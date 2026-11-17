// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! CMS / PKCS#7 SignedData verification for DDS-Security governance and
//! permissions documents.
//!
//! DDS-Security v1.1 9.4.1.2 and 9.4.1.3 require both documents to be signed by
//! the Permissions CA, and 9.4.3 says `validate_local_permissions` "shall verify
//! the signature of the Signed Domain Governance and Signed Permissions document
//! by the configured Permissions CA [...] Otherwise the operation shall return
//! an error". This module is that check.
//!
//! # Trust model
//!
//! The ONLY trust anchor is the configured Permissions CA certificate. A CMS
//! blob may carry a `certificates` field; those certificates are never used as
//! anchors and never used to build a chain, so a document that ships its own
//! self-signed CA is refused exactly like any other foreign signature. A signer
//! is accepted only when its `SignerIdentifier` names the configured CA -- by
//! issuer and serial number, or by subject key identifier.
//!
//! Chained signers (a permissions-signing certificate issued BY the Permissions
//! CA rather than the CA key itself) are out of scope for this release and are
//! refused; every vendor document in reach signs with the CA key directly.
//!
//! # What is checked, in order
//!
//! 1. the envelope really is a CMS `SignedData` over `id-data`;
//! 2. the Permissions CA certificate parses and is inside its validity window;
//! 3. at least one `SignerInfo` passes ALL of:
//!    a. `signedAttrs` is present (RFC 5652 5.3 then makes contentType and
//!       messageDigest mandatory, and the signature covers the attributes);
//!    b. the `messageDigest` attribute equals the digest of the signed content;
//!    c. the `contentType` attribute equals the encapsulated content type;
//!    d. the `SignerIdentifier` names the configured Permissions CA;
//!    e. the signature over the re-tagged `signedAttrs` verifies with the
//!       Permissions CA public key, under an algorithm named by an OID this
//!       module knows. There is no "try every algorithm until one works" loop.
//!
//! Anything else -- zero signers, an unknown OID, a BER-only encoding, a
//! truncated field -- is an error. The caller turns that into a refusal to
//! build the participant.

use crate::security::SecurityError;
use ring::digest::{digest, Algorithm as DigestAlgorithm, SHA256, SHA384};
use ring::signature::{self, UnparsedPublicKey, VerificationAlgorithm};
use x509_parser::der_parser::asn1_rs::{Any, Class, FromDer, Tag};
use x509_parser::prelude::*;

// Object identifiers, content bytes only (no tag, no length).
const OID_SIGNED_DATA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02];
const OID_DATA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01];
const OID_ATTR_CONTENT_TYPE: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x03];
const OID_ATTR_MESSAGE_DIGEST: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04];
const OID_SHA256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
const OID_SHA384: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02];
const OID_RSA_ENCRYPTION: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
const OID_SHA256_WITH_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];
const OID_SHA384_WITH_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c];
const OID_ECDSA_WITH_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
const OID_ECDSA_WITH_SHA384: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03];

/// The configured Permissions CA, in owned form.
///
/// `x509_parser` types borrow the buffer they were parsed from, so everything
/// this struct needs is copied out inside one borrowing scope rather than
/// keeping a self-referential certificate around (which is what forced the
/// `Box::leak` in `authentication::x509::cert`).
#[derive(Debug, Clone)]
pub(crate) struct PermissionsCa {
    /// Subject DN in RFC 4514 form, for messages and the SPDP PermissionsToken.
    pub(crate) subject_dn: String,
    /// DER of the certificate's own `issuer` Name, for `IssuerAndSerialNumber`.
    issuer_der: Vec<u8>,
    /// Serial number content octets, leading zero padding removed.
    serial: Vec<u8>,
    /// SubjectKeyIdentifier extension value, when the certificate carries one.
    ski: Option<Vec<u8>>,
    /// `subjectPublicKey` BIT STRING contents: the uncompressed EC point, or
    /// the `RSAPublicKey` DER. Both are what `ring` expects.
    public_key: Vec<u8>,
    not_before: i64,
    not_after: i64,
}

impl PermissionsCa {
    /// Parse the Permissions CA from a PEM certificate.
    ///
    /// Only the FIRST certificate in the file is read. The Permissions CA is
    /// one anchor, not a bundle: a file holding several certificates would make
    /// "which key signed this document" ambiguous, which is the question this
    /// whole module exists to answer.
    ///
    /// # Errors
    ///
    /// Returns `SecurityError::CertificateInvalid` if the PEM or the
    /// certificate inside it cannot be parsed.
    pub(crate) fn from_pem(pem_bytes: &[u8]) -> Result<Self, SecurityError> {
        let (_, pem) = parse_x509_pem(pem_bytes).map_err(|e| {
            SecurityError::CertificateInvalid(format!(
                "permissions CA is not a PEM certificate: {:?}",
                e
            ))
        })?;
        let (_, cert) = X509Certificate::from_der(&pem.contents).map_err(|e| {
            SecurityError::CertificateInvalid(format!(
                "permissions CA certificate does not parse: {:?}",
                e
            ))
        })?;

        let ski = cert
            .get_extension_unique(&oid_registry::OID_X509_EXT_SUBJECT_KEY_IDENTIFIER)
            .ok()
            .flatten()
            .and_then(|ext| match ext.parsed_extension() {
                x509_parser::extensions::ParsedExtension::SubjectKeyIdentifier(id) => {
                    Some(id.0.to_vec())
                }
                _ => None,
            });

        Ok(Self {
            subject_dn: cert.subject().to_string(),
            issuer_der: cert.issuer().as_raw().to_vec(),
            serial: strip_leading_zeros(cert.raw_serial()).to_vec(),
            ski,
            public_key: cert.public_key().subject_public_key.data.to_vec(),
            not_before: cert.validity().not_before.timestamp(),
            not_after: cert.validity().not_after.timestamp(),
        })
    }
}

/// Verify a CMS `SignedData` blob over `signed_content` with the Permissions CA.
///
/// `now_unix` is the instant the CA validity window is checked against; callers
/// pass the wall clock, tests pass a fixed value so a fixture cannot expire a
/// test suite.
///
/// # Errors
///
/// Returns `SecurityError::ConfigError` for a malformed or unacceptable
/// envelope, and `SecurityError::CertificateExpired` when the Permissions CA
/// itself is outside its validity window. It never returns `Ok` on a signature
/// it could not check.
pub(crate) fn verify_signed_data(
    cms_der: &[u8],
    signed_content: &[u8],
    ca: &PermissionsCa,
    now_unix: i64,
) -> Result<(), SecurityError> {
    if now_unix < ca.not_before {
        return Err(SecurityError::CertificateInvalid(format!(
            "permissions CA '{}' is not valid yet",
            ca.subject_dn
        )));
    }
    if now_unix > ca.not_after {
        return Err(SecurityError::CertificateExpired);
    }

    let signed_data = SignedData::parse(cms_der)?;

    if signed_data.signer_infos.is_empty() {
        return Err(cfg_err("CMS SignedData carries no signerInfos"));
    }

    let mut last_error = None;
    for signer_der in &signed_data.signer_infos {
        match verify_one_signer(signer_der, &signed_data, signed_content, ca) {
            Ok(()) => return Ok(()),
            Err(e) => last_error = Some(e),
        }
    }

    Err(last_error.unwrap_or_else(|| cfg_err("CMS SignedData carries no acceptable signer")))
}

fn cfg_err(msg: impl Into<String>) -> SecurityError {
    SecurityError::ConfigError(msg.into())
}

// ---------------------------------------------------------------------------
// SignedData
// ---------------------------------------------------------------------------

struct SignedData<'a> {
    /// `encapContentInfo.eContentType`, content octets of the OID.
    e_content_type: &'a [u8],
    /// Raw DER of each `SignerInfo`.
    signer_infos: Vec<&'a [u8]>,
}

impl<'a> SignedData<'a> {
    fn parse(cms_der: &'a [u8]) -> Result<Self, SecurityError> {
        let (content_info, _) = der_next(cms_der, "ContentInfo")?;
        expect(
            &content_info,
            Class::Universal,
            Tag::Sequence,
            "ContentInfo",
        )?;

        let (content_type, rest) = der_next(content_info.data, "contentType")?;
        expect(&content_type, Class::Universal, Tag::Oid, "contentType")?;
        if content_type.data != OID_SIGNED_DATA {
            return Err(cfg_err("CMS contentType is not id-signedData"));
        }

        let (content, _) = der_next(rest, "content [0]")?;
        expect(&content, Class::ContextSpecific, Tag(0), "content [0]")?;

        let (signed_data, _) = der_next(content.data, "SignedData")?;
        expect(&signed_data, Class::Universal, Tag::Sequence, "SignedData")?;

        let (version, rest) = der_next(signed_data.data, "SignedData.version")?;
        expect(
            &version,
            Class::Universal,
            Tag::Integer,
            "SignedData.version",
        )?;

        let (digest_algorithms, rest) = der_next(rest, "digestAlgorithms")?;
        expect(
            &digest_algorithms,
            Class::Universal,
            Tag::Set,
            "digestAlgorithms",
        )?;

        let (encap, mut rest) = der_next(rest, "encapContentInfo")?;
        expect(&encap, Class::Universal, Tag::Sequence, "encapContentInfo")?;
        let (e_content_type, _) = der_next(encap.data, "eContentType")?;
        expect(&e_content_type, Class::Universal, Tag::Oid, "eContentType")?;
        if e_content_type.data != OID_DATA {
            return Err(cfg_err(
                "CMS encapContentInfo is not id-data; a governance or permissions \
                 document is always id-data",
            ));
        }

        // certificates [0] IMPLICIT and crls [1] IMPLICIT are optional and are
        // deliberately skipped: neither is a trust anchor here.
        let mut signer_infos_der = None;
        while !rest.is_empty() {
            let (item, next) = der_next(rest, "SignedData member")?;
            if item.class() == Class::Universal && item.tag() == Tag::Set {
                signer_infos_der = Some(item.data);
                break;
            }
            rest = next;
        }
        let signer_infos_der =
            signer_infos_der.ok_or_else(|| cfg_err("CMS SignedData has no signerInfos SET"))?;

        let mut signer_infos = Vec::new();
        let mut cursor = signer_infos_der;
        while !cursor.is_empty() {
            let before = cursor.len();
            let (signer, next) = der_next(cursor, "SignerInfo")?;
            expect(&signer, Class::Universal, Tag::Sequence, "SignerInfo")?;
            signer_infos.push(&cursor[..before - next.len()]);
            cursor = next;
        }

        Ok(Self {
            e_content_type: e_content_type.data,
            signer_infos,
        })
    }
}

// ---------------------------------------------------------------------------
// SignerInfo
// ---------------------------------------------------------------------------

fn verify_one_signer(
    signer_der: &[u8],
    signed_data: &SignedData<'_>,
    signed_content: &[u8],
    ca: &PermissionsCa,
) -> Result<(), SecurityError> {
    let (signer, _) = der_next(signer_der, "SignerInfo")?;
    let mut cursor = signer.data;

    let (version, next) = der_next(cursor, "SignerInfo.version")?;
    expect(
        &version,
        Class::Universal,
        Tag::Integer,
        "SignerInfo.version",
    )?;
    cursor = next;

    let (sid, next) = der_next(cursor, "SignerIdentifier")?;
    signer_is_the_permissions_ca(&sid, ca)?;
    cursor = next;

    let (digest_algorithm, next) = der_next(cursor, "digestAlgorithm")?;
    expect(
        &digest_algorithm,
        Class::Universal,
        Tag::Sequence,
        "digestAlgorithm",
    )?;
    let (digest_oid, _) = der_next(digest_algorithm.data, "digestAlgorithm.algorithm")?;
    expect(
        &digest_oid,
        Class::Universal,
        Tag::Oid,
        "digestAlgorithm.algorithm",
    )?;
    let digest_alg = digest_algorithm_from_oid(digest_oid.data)?;
    cursor = next;

    // signedAttrs [0] IMPLICIT is optional in RFC 5652 and mandatory here: a
    // signature taken over the bare content carries no contentType binding, so
    // the same signature would stay valid for a document of another type.
    let attrs_input = cursor;
    let (signed_attrs, next) = der_next(cursor, "signedAttrs")?;
    if signed_attrs.class() != Class::ContextSpecific || signed_attrs.tag() != Tag(0) {
        return Err(cfg_err(
            "CMS SignerInfo has no signedAttrs; HDDS requires the contentType and \
             messageDigest attributes to be signed",
        ));
    }
    let signed_attrs_tlv = &attrs_input[..attrs_input.len() - next.len()];
    cursor = next;

    let (signature_algorithm, next) = der_next(cursor, "signatureAlgorithm")?;
    expect(
        &signature_algorithm,
        Class::Universal,
        Tag::Sequence,
        "signatureAlgorithm",
    )?;
    let (signature_oid, _) = der_next(signature_algorithm.data, "signatureAlgorithm.algorithm")?;
    expect(
        &signature_oid,
        Class::Universal,
        Tag::Oid,
        "signatureAlgorithm.algorithm",
    )?;
    cursor = next;

    let (signature, _) = der_next(cursor, "signature")?;
    expect(&signature, Class::Universal, Tag::OctetString, "signature")?;

    check_signed_attributes(
        signed_attrs.data,
        signed_data.e_content_type,
        signed_content,
        digest_alg,
    )?;

    // RFC 5652 5.4: the signature covers the DER SET OF encoding of the signed
    // attributes, that is the same octets with the IMPLICIT [0] identifier
    // replaced by the universal SET identifier. Tag number 0 in the
    // context-specific constructed class is one octet, 0xa0.
    if signed_attrs_tlv.first() != Some(&0xa0) {
        return Err(cfg_err(
            "CMS signedAttrs has an unexpected identifier octet",
        ));
    }
    let mut to_verify = signed_attrs_tlv.to_vec();
    to_verify[0] = 0x31;

    let algorithm = signature_algorithm_from_oid(signature_oid.data, digest_alg)?;
    UnparsedPublicKey::new(algorithm, &ca.public_key)
        .verify(&to_verify, signature.data)
        .map_err(|_| {
            cfg_err(format!(
                "CMS signature does not verify with the configured permissions CA '{}'",
                ca.subject_dn
            ))
        })
}

fn check_signed_attributes(
    signed_attrs: &[u8],
    e_content_type: &[u8],
    signed_content: &[u8],
    digest_alg: &'static DigestAlgorithm,
) -> Result<(), SecurityError> {
    let mut seen_content_type = false;
    let mut seen_message_digest = false;

    let mut cursor = signed_attrs;
    while !cursor.is_empty() {
        let (attribute, next) = der_next(cursor, "signed attribute")?;
        expect(
            &attribute,
            Class::Universal,
            Tag::Sequence,
            "signed attribute",
        )?;
        cursor = next;

        let (attr_type, attr_rest) = der_next(attribute.data, "attribute type")?;
        expect(&attr_type, Class::Universal, Tag::Oid, "attribute type")?;
        let (attr_values, _) = der_next(attr_rest, "attribute values")?;
        expect(&attr_values, Class::Universal, Tag::Set, "attribute values")?;

        if attr_type.data == OID_ATTR_CONTENT_TYPE {
            let (value, _) = der_next(attr_values.data, "contentType attribute value")?;
            expect(
                &value,
                Class::Universal,
                Tag::Oid,
                "contentType attribute value",
            )?;
            if value.data != e_content_type {
                return Err(cfg_err(
                    "CMS contentType attribute does not match encapContentInfo",
                ));
            }
            seen_content_type = true;
        } else if attr_type.data == OID_ATTR_MESSAGE_DIGEST {
            let (value, _) = der_next(attr_values.data, "messageDigest attribute value")?;
            expect(
                &value,
                Class::Universal,
                Tag::OctetString,
                "messageDigest attribute value",
            )?;
            let computed = digest(digest_alg, signed_content);
            if value.data != computed.as_ref() {
                return Err(cfg_err(
                    "CMS messageDigest does not match the document: the document was \
                     modified after it was signed",
                ));
            }
            seen_message_digest = true;
        }
    }

    if !seen_content_type {
        return Err(cfg_err("CMS signedAttrs has no contentType attribute"));
    }
    if !seen_message_digest {
        return Err(cfg_err("CMS signedAttrs has no messageDigest attribute"));
    }
    Ok(())
}

/// The signer must BE the configured Permissions CA.
fn signer_is_the_permissions_ca(sid: &Any<'_>, ca: &PermissionsCa) -> Result<(), SecurityError> {
    match (sid.class(), sid.tag()) {
        // IssuerAndSerialNumber ::= SEQUENCE { issuer Name, serialNumber INTEGER }
        (Class::Universal, Tag::Sequence) => {
            let before = sid.data;
            let (issuer, rest) = der_next(before, "sid.issuer")?;
            let issuer_der = &before[..before.len() - rest.len()];
            let (serial, _) = der_next(rest, "sid.serialNumber")?;
            expect(&serial, Class::Universal, Tag::Integer, "sid.serialNumber")?;
            let _ = issuer;

            if issuer_der != ca.issuer_der {
                return Err(cfg_err(format!(
                    "CMS signer is not the configured permissions CA '{}' (issuer mismatch)",
                    ca.subject_dn
                )));
            }
            if strip_leading_zeros(serial.data) != ca.serial.as_slice() {
                return Err(cfg_err(format!(
                    "CMS signer is not the configured permissions CA '{}' (serial mismatch)",
                    ca.subject_dn
                )));
            }
            Ok(())
        }
        // subjectKeyIdentifier [0] IMPLICIT OCTET STRING contents
        (Class::ContextSpecific, Tag(0)) => match &ca.ski {
            Some(ski) if sid.data == ski.as_slice() => Ok(()),
            Some(_) => Err(cfg_err(format!(
                "CMS signer key identifier does not match the configured permissions CA '{}'",
                ca.subject_dn
            ))),
            None => Err(cfg_err(format!(
                "CMS signer is named by key identifier but the configured permissions CA \
                 '{}' has no subjectKeyIdentifier extension",
                ca.subject_dn
            ))),
        },
        _ => Err(cfg_err("CMS SignerIdentifier has an unexpected shape")),
    }
}

fn digest_algorithm_from_oid(oid: &[u8]) -> Result<&'static DigestAlgorithm, SecurityError> {
    match oid {
        OID_SHA256 => Ok(&SHA256),
        OID_SHA384 => Ok(&SHA384),
        _ => Err(cfg_err(
            "CMS digestAlgorithm is neither SHA-256 nor SHA-384",
        )),
    }
}

fn signature_algorithm_from_oid(
    oid: &[u8],
    digest_alg: &'static DigestAlgorithm,
) -> Result<&'static dyn VerificationAlgorithm, SecurityError> {
    let sha256 = core::ptr::eq(digest_alg, &SHA256);
    match oid {
        OID_SHA256_WITH_RSA => Ok(&signature::RSA_PKCS1_2048_8192_SHA256),
        OID_SHA384_WITH_RSA => Ok(&signature::RSA_PKCS1_2048_8192_SHA384),
        // Some encoders name the key algorithm and leave the digest to the
        // digestAlgorithm field.
        OID_RSA_ENCRYPTION => {
            if sha256 {
                Ok(&signature::RSA_PKCS1_2048_8192_SHA256)
            } else {
                Ok(&signature::RSA_PKCS1_2048_8192_SHA384)
            }
        }
        OID_ECDSA_WITH_SHA256 => Ok(&signature::ECDSA_P256_SHA256_ASN1),
        OID_ECDSA_WITH_SHA384 => Ok(&signature::ECDSA_P384_SHA384_ASN1),
        _ => Err(cfg_err(
            "CMS signatureAlgorithm OID is not one HDDS accepts (RSA PKCS#1 v1.5 or \
             ECDSA with SHA-256 / SHA-384)",
        )),
    }
}

fn strip_leading_zeros(bytes: &[u8]) -> &[u8] {
    let mut start = 0;
    while start + 1 < bytes.len() && bytes[start] == 0 {
        start += 1;
    }
    &bytes[start..]
}

fn der_next<'a>(input: &'a [u8], what: &str) -> Result<(Any<'a>, &'a [u8]), SecurityError> {
    Any::from_der(input)
        .map(|(rest, any)| (any, rest))
        .map_err(|e| cfg_err(format!("CMS: cannot read {}: {:?}", what, e)))
}

fn expect(any: &Any<'_>, class: Class, tag: Tag, what: &str) -> Result<(), SecurityError> {
    if any.class() != class || any.tag() != tag {
        return Err(cfg_err(format!(
            "CMS: {} has unexpected tag {:?}/{:?}",
            what,
            any.class(),
            any.tag()
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::p7s::parse_envelope;
    use crate::security::test_pki::{
        EXPIRED_PERM_CA_PEM, FASTDDS_MAIN_CA_PEM, FASTDDS_OTHER_CA_PEM,
        FASTDDS_PERMISSIONS_OTHER_CA_SMIME, FASTDDS_PERMISSIONS_SMIME, FIXTURE_NOW_UNIX,
        GOVERNANCE_EC_SMIME, OTHER_PERM_CA_KEYID_PEM, OTHER_PERM_CA_PEM,
        PERMISSIONS_EC_ATTACHED_DER, PERMISSIONS_EC_NO_SUBHEADERS_SMIME, PERMISSIONS_EC_SMIME,
        PERMISSIONS_EXPIRED_CA_SMIME, PERMISSIONS_KEYID_SMIME, PERMISSIONS_NOATTR_SMIME,
        PERMISSIONS_OTHER_CA_KEYID_SMIME, PERMISSIONS_OTHER_CA_SMIME, PERMISSIONS_RSA_SMIME,
        PERMISSIONS_TAMPERED_SMIME, PERM_CA_EC_PEM, PERM_CA_KEYID_PEM, PERM_CA_RSA_PEM,
    };

    fn verify(document: &[u8], ca_pem: &[u8]) -> Result<(), SecurityError> {
        let envelope = parse_envelope(document).expect("fixture must parse as an envelope");
        let ca = PermissionsCa::from_pem(ca_pem).expect("fixture CA must parse");
        verify_signed_data(
            &envelope.cms_der,
            &envelope.signed_content,
            &ca,
            FIXTURE_NOW_UNIX,
        )
    }

    /// An EC P-256 signed S/MIME permissions document verifies.
    #[test]
    fn verify_ec_p256_smime_permissions_ok() {
        verify(PERMISSIONS_EC_SMIME, PERM_CA_EC_PEM).expect("EC P-256 signature must verify");
    }

    /// Governance is the same path as permissions.
    #[test]
    fn verify_ec_p256_smime_governance_ok() {
        verify(GOVERNANCE_EC_SMIME, PERM_CA_EC_PEM).expect("governance signature must verify");
    }

    /// An RSA-2048 signed S/MIME permissions document verifies.
    #[test]
    fn verify_rsa2048_smime_permissions_ok() {
        verify(PERMISSIONS_RSA_SMIME, PERM_CA_RSA_PEM).expect("RSA-2048 signature must verify");
    }

    /// A part with no MIME sub-headers is canonicalised the same way.
    #[test]
    fn verify_smime_without_subheaders_ok() {
        verify(PERMISSIONS_EC_NO_SUBHEADERS_SMIME, PERM_CA_EC_PEM)
            .expect("header-less S/MIME must verify");
    }

    /// The second shape the spec allows: DER PKCS#7 with the document attached.
    #[test]
    fn verify_der_attached_permissions_ok() {
        verify(PERMISSIONS_EC_ATTACHED_DER, PERM_CA_EC_PEM)
            .expect("attached DER PKCS#7 must verify");
    }

    /// A document produced by another vendor's toolchain, verified against that
    /// vendor's CA. Nothing in this fixture was made by HDDS.
    #[test]
    fn verify_fastdds_oracle_against_maincacert_ok() {
        verify(FASTDDS_PERMISSIONS_SMIME, FASTDDS_MAIN_CA_PEM)
            .expect("the eProsima oracle document must verify against its own CA");
    }

    /// The vendor's own wrong-CA fixture: right shape, wrong signer.
    #[test]
    fn verify_rejects_fastdds_document_signed_by_other_ca() {
        let err = verify(FASTDDS_PERMISSIONS_OTHER_CA_SMIME, FASTDDS_MAIN_CA_PEM)
            .expect_err("a document signed by another CA must be refused");
        assert!(
            err.to_string().contains("permissions CA"),
            "message must name the trust anchor: {}",
            err
        );
        // The same bytes verify against the CA that really signed them, so the
        // refusal above is about the signer, not about a parse failure.
        verify(FASTDDS_PERMISSIONS_OTHER_CA_SMIME, FASTDDS_OTHER_CA_PEM)
            .expect("the document is well formed and verifies with its own CA");
    }

    /// One byte of the document changed after signing is refused.
    #[test]
    fn verify_rejects_tampered_content_byte() {
        let err = verify(PERMISSIONS_TAMPERED_SMIME, PERM_CA_EC_PEM)
            .expect_err("an edited document must be refused");
        assert!(
            err.to_string().contains("messageDigest"),
            "the digest check must be the one that fires: {}",
            err
        );
    }

    /// A document signed by an unconfigured CA is refused.
    #[test]
    fn verify_rejects_other_ca_signer() {
        let err = verify(PERMISSIONS_OTHER_CA_SMIME, PERM_CA_EC_PEM)
            .expect_err("a foreign signer must be refused");
        assert!(
            err.to_string().contains("permissions CA"),
            "message must name the trust anchor: {}",
            err
        );
    }

    /// A signer that names itself by subjectKeyIdentifier verifies.
    ///
    /// RFC 5652 5.3 allows both SignerIdentifier shapes and both are accept
    /// paths in the trust check; openssl writes issuer+serial unless asked for
    /// the other one, so without this fixture the key-identifier branch is
    /// untested code inside a trust decision.
    #[test]
    fn verify_ec_p256_signer_by_key_identifier_ok() {
        verify(PERMISSIONS_KEYID_SMIME, PERM_CA_KEYID_PEM)
            .expect("a signer named by key identifier must verify against its own CA");
    }

    /// A key identifier that is not the configured CA's is refused, and the
    /// refusal comes from the key-identifier branch rather than from the
    /// signature check behind it.
    #[test]
    fn verify_rejects_key_identifier_of_another_ca() {
        let err = verify(PERMISSIONS_OTHER_CA_KEYID_SMIME, PERM_CA_KEYID_PEM)
            .expect_err("a foreign key identifier must be refused");
        assert!(
            err.to_string().contains("key identifier does not match"),
            "the key-identifier branch must be the one that fires: {}",
            err
        );
        verify(PERMISSIONS_OTHER_CA_KEYID_SMIME, OTHER_PERM_CA_KEYID_PEM)
            .expect("the same document verifies once its signer is the configured CA");
    }

    /// The certificate the envelope carries is never a trust anchor.
    ///
    /// `permissions_other_ca.smime` embeds the certificate that signed it. If
    /// embedded certificates were treated as anchors this document would
    /// verify against any configuration at all.
    #[test]
    fn verify_rejects_embedded_cert_as_anchor() {
        verify(PERMISSIONS_OTHER_CA_SMIME, PERM_CA_EC_PEM)
            .expect_err("an embedded certificate must not become a trust anchor");
        verify(PERMISSIONS_OTHER_CA_SMIME, PERM_CA_RSA_PEM)
            .expect_err("an embedded certificate must not become a trust anchor");
        verify(PERMISSIONS_OTHER_CA_SMIME, OTHER_PERM_CA_PEM)
            .expect("the document does verify once its signer is the configured CA");
    }

    /// A signature taken without signedAttrs is refused.
    #[test]
    fn verify_rejects_missing_signed_attrs() {
        let err = verify(PERMISSIONS_NOATTR_SMIME, PERM_CA_EC_PEM)
            .expect_err("a signature without signedAttrs must be refused");
        assert!(
            err.to_string().contains("signedAttrs"),
            "message must name the missing attributes: {}",
            err
        );
    }

    /// A valid signature made by a CA that has expired is refused.
    #[test]
    fn verify_rejects_expired_permissions_ca() {
        let err = verify(PERMISSIONS_EXPIRED_CA_SMIME, EXPIRED_PERM_CA_PEM)
            .expect_err("an expired permissions CA must be refused");
        assert!(
            matches!(err, SecurityError::CertificateExpired),
            "expected CertificateExpired, got {}",
            err
        );
    }

    /// An algorithm OID the module does not know is refused rather than guessed.
    #[test]
    fn verify_rejects_unknown_signature_oid() {
        let envelope = parse_envelope(PERMISSIONS_EC_SMIME).expect("fixture parses");
        let mut cms = envelope.cms_der.clone();
        // ecdsa-with-SHA256 is 1.2.840.10045.4.3.2; rewrite the last arc so the
        // OID stays the same length but names nothing this module accepts.
        let needle = [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
        let position = cms
            .windows(needle.len())
            .rposition(|window| window == needle)
            .expect("the signatureAlgorithm OID must be present");
        cms[position + needle.len() - 1] = 0x09;

        let ca = PermissionsCa::from_pem(PERM_CA_EC_PEM).expect("CA parses");
        let err = verify_signed_data(&cms, &envelope.signed_content, &ca, FIXTURE_NOW_UNIX)
            .expect_err("an unknown algorithm OID must be refused");
        assert!(
            err.to_string().contains("signatureAlgorithm"),
            "message must name the algorithm: {}",
            err
        );
    }

    /// A signature value with one byte changed is refused by `ring`, not by an
    /// earlier structural check.
    #[test]
    fn verify_rejects_corrupted_signature_value() {
        let envelope = parse_envelope(PERMISSIONS_EC_SMIME).expect("fixture parses");
        let mut cms = envelope.cms_der.clone();
        // The signature OCTET STRING is the last field of the last SignerInfo,
        // so the final byte of the blob belongs to it.
        let last = cms.len() - 1;
        cms[last] ^= 0x01;

        let ca = PermissionsCa::from_pem(PERM_CA_EC_PEM).expect("CA parses");
        let err = verify_signed_data(&cms, &envelope.signed_content, &ca, FIXTURE_NOW_UNIX)
            .expect_err("a corrupted signature must be refused");
        assert!(
            err.to_string().contains("does not verify"),
            "the signature check must be the one that fires: {}",
            err
        );
    }

    /// A truncated CMS blob is refused by the parser.
    #[test]
    fn verify_rejects_a_truncated_cms_blob() {
        let envelope = parse_envelope(PERMISSIONS_EC_SMIME).expect("fixture parses");
        let ca = PermissionsCa::from_pem(PERM_CA_EC_PEM).expect("CA parses");
        let truncated = &envelope.cms_der[..envelope.cms_der.len() / 2];
        verify_signed_data(truncated, &envelope.signed_content, &ca, FIXTURE_NOW_UNIX)
            .expect_err("a truncated CMS blob must be refused");
    }

    /// A well-formed CMS blob whose signerInfos SET is EMPTY is refused.
    ///
    /// Nothing to check is not the same as nothing wrong: an empty SET parses
    /// cleanly, so only the explicit guard stands between it and `Ok`.
    #[test]
    fn verify_rejects_zero_signers() {
        let envelope = parse_envelope(PERMISSIONS_EC_SMIME).expect("fixture parses");
        let ca = PermissionsCa::from_pem(PERM_CA_EC_PEM).expect("CA parses");
        let emptied = empty_the_signer_infos(&envelope.cms_der);

        // The doctored blob still parses: same eContentType, no signers.
        let parsed = SignedData::parse(&emptied).expect("the doctored blob must still parse");
        assert!(parsed.signer_infos.is_empty());

        let err = verify_signed_data(&emptied, &envelope.signed_content, &ca, FIXTURE_NOW_UNIX)
            .expect_err("a SignedData with no signers must be refused");
        assert!(
            err.to_string().contains("no signerInfos"),
            "the empty-signers guard must be the one that fires: {}",
            err
        );
    }

    /// Rebuild `cms_der` with its `signerInfos` SET replaced by an empty one.
    ///
    /// Every enclosing length shrinks by the bytes removed, which is why this
    /// walks the structure instead of patching bytes in place.
    fn empty_the_signer_infos(cms_der: &[u8]) -> Vec<u8> {
        /// Split one DER TLV into (header, contents, tail).
        fn tlv(der: &[u8]) -> (usize, usize) {
            // Returns (header length, contents length).
            let first_length_byte = der[1];
            if first_length_byte & 0x80 == 0 {
                (2, first_length_byte as usize)
            } else {
                let count = (first_length_byte & 0x7f) as usize;
                let mut length = 0usize;
                for byte in &der[2..2 + count] {
                    length = length * 256 + *byte as usize;
                }
                (2 + count, length)
            }
        }

        /// Wrap `contents` in a definite-length TLV with identifier `tag`.
        fn wrap(tag: u8, contents: &[u8]) -> Vec<u8> {
            let mut out = vec![tag];
            if contents.len() < 128 {
                out.push(contents.len() as u8);
            } else {
                let be = contents.len().to_be_bytes();
                let significant: Vec<u8> = be.iter().copied().skip_while(|b| *b == 0).collect();
                out.push(0x80 | significant.len() as u8);
                out.extend_from_slice(&significant);
            }
            out.extend_from_slice(contents);
            out
        }

        // ContentInfo ::= SEQUENCE { contentType OID, content [0] SignedData }
        let (ci_header, ci_len) = tlv(cms_der);
        let ci_contents = &cms_der[ci_header..ci_header + ci_len];
        let (oid_header, oid_len) = tlv(ci_contents);
        let oid = &ci_contents[..oid_header + oid_len];
        let explicit = &ci_contents[oid_header + oid_len..];
        let (exp_header, exp_len) = tlv(explicit);
        let signed_data = &explicit[exp_header..exp_header + exp_len];
        let (sd_header, sd_len) = tlv(signed_data);
        let sd_contents = &signed_data[sd_header..sd_header + sd_len];

        // Keep everything up to the signerInfos SET. The first three members
        // are version, digestAlgorithms (also a SET) and encapContentInfo;
        // signerInfos is the first Universal SET after them, the optional
        // certificates [0] and crls [1] slots being context-specific.
        let mut cut = 0usize;
        let mut offset = 0usize;
        let mut member = 0usize;
        while offset < sd_contents.len() {
            let (header, len) = tlv(&sd_contents[offset..]);
            if member >= 3 && sd_contents[offset] == 0x31 {
                cut = offset;
                break;
            }
            offset += header + len;
            member += 1;
        }
        assert!(cut > 0, "signerInfos SET not found");

        let mut new_sd_contents = sd_contents[..cut].to_vec();
        new_sd_contents.extend_from_slice(&[0x31, 0x00]); // SET {}
        let new_sd = wrap(0x30, &new_sd_contents);
        let new_explicit = wrap(0xa0, &new_sd);
        let mut new_ci_contents = oid.to_vec();
        new_ci_contents.extend_from_slice(&new_explicit);
        wrap(0x30, &new_ci_contents)
    }

    /// A valid signature checked before the CA's own notBefore is refused.
    #[test]
    fn verify_rejects_permissions_ca_not_yet_valid() {
        let envelope = parse_envelope(PERMISSIONS_EC_SMIME).expect("fixture parses");
        let ca = PermissionsCa::from_pem(PERM_CA_EC_PEM).expect("CA parses");
        // 2010-01-01T00:00:00Z, before any fixture was minted.
        let err = verify_signed_data(
            &envelope.cms_der,
            &envelope.signed_content,
            &ca,
            1_262_304_000,
        )
        .expect_err("a CA that is not valid yet must be refused");
        assert!(
            err.to_string().contains("not valid yet"),
            "message must say why: {}",
            err
        );
    }

    /// The plain-XML shape carries no CMS blob, so it can never verify.
    #[test]
    fn verify_rejects_an_empty_cms_blob() {
        let ca = PermissionsCa::from_pem(PERM_CA_EC_PEM).expect("CA parses");
        verify_signed_data(&[], b"<dds/>", &ca, FIXTURE_NOW_UNIX)
            .expect_err("an empty CMS blob must be refused");
    }
}
