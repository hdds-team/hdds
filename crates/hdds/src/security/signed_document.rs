// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Fail-closed loading of the two signed DDS-Security documents.
//!
//! DDS-Security v1.1 9.4.1.2 (governance) and 9.4.1.3 (permissions) both say
//! the document "shall be signed by the Permissions CA", and 9.4.3 makes the
//! verification a precondition of `validate_local_permissions`. This module is
//! the policy layer over [`crate::security::p7s`] (which splits the envelope)
//! and [`crate::security::cms`] (which checks the signature):
//!
//! - a signed document is accepted only when its signature verifies against the
//!   configured Permissions CA;
//! - a signed document with no Permissions CA configured is an error, never a
//!   silent pass;
//! - a plain, unsigned document is an error unless the caller explicitly turned
//!   on `insecure_allow_unsigned_documents`, in which case it is accepted with
//!   a warning and an audit record.
//!
//! Every failure surfaces as an error from `SecurityPluginSuite::new`, which
//! participant bootstrap propagates, so a participant never starts on a
//! document it could not verify.

use crate::security::audit::{AccessOutcome, AuditChain, SecurityEvent};
use crate::security::cms::{self, PermissionsCa};
use crate::security::p7s::{self, EnvelopeKind};
use crate::security::SecurityError;

/// Which of the two documents is being loaded, for error and audit messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DocumentKind {
    /// The domain governance document (DDS-Security v1.1 9.4.1.2).
    Governance,
    /// The participant permissions document (DDS-Security v1.1 9.4.1.3).
    Permissions,
}

impl DocumentKind {
    fn as_str(self) -> &'static str {
        match self {
            DocumentKind::Governance => "governance",
            DocumentKind::Permissions => "permissions",
        }
    }

    /// Element names only this kind of document carries.
    ///
    /// Both spellings in reach are covered: the OMG shape nests
    /// `<domain_access_rules><domain_rule>` under `<dds>`, and the shorter
    /// vendor shape uses `<governance>` or a bare `<permissions>` root.
    fn markers(self) -> &'static [&'static str] {
        match self {
            DocumentKind::Governance => &["domain_access_rules", "domain_rule", "governance"],
            DocumentKind::Permissions => &["permissions", "grant"],
        }
    }

    fn is_declared_by(self, xml: &str) -> bool {
        self.markers()
            .iter()
            .any(|marker| declares_element(xml, marker))
    }
}

/// True when `xml` opens an element named `name`, with or without a namespace
/// prefix.
///
/// Deliberately a scan rather than a parse: this module must keep working with
/// the `qos-loaders` feature off, where no XML parser is compiled in, and a
/// name that appears only in text or in an attribute value must not count.
fn declares_element(xml: &str, name: &str) -> bool {
    let bytes = xml.as_bytes();
    let name_bytes = name.as_bytes();
    let mut from = 0usize;
    while let Some(offset) = xml[from..].find('<') {
        let start = from + offset + 1;
        from = start;
        // Skip the closing-tag marker; an element that closes also opened.
        let start = match bytes.get(start) {
            Some(b'/') => start + 1,
            Some(_) => start,
            None => return false,
        };
        // Step over an optional namespace prefix.
        let rest = &xml[start..];
        let local = match rest.find(|c: char| c == ':' || c == '>' || c == '/' || c.is_whitespace())
        {
            Some(cut) if rest.as_bytes()[cut] == b':' => &rest[cut + 1..],
            _ => rest,
        };
        let local_bytes = local.as_bytes();
        if local_bytes.starts_with(name_bytes) {
            match local_bytes.get(name_bytes.len()) {
                None => return true,
                Some(next) if next.is_ascii_whitespace() || *next == b'>' || *next == b'/' => {
                    return true
                }
                Some(_) => {}
            }
        }
    }
    false
}

/// Everything the loader needs to decide about a document.
pub(crate) struct DocumentPolicy<'a> {
    /// The one trust anchor, when one is configured.
    pub(crate) permissions_ca: Option<&'a PermissionsCa>,
    /// Development escape hatch for plain XML.
    pub(crate) allow_unsigned: bool,
    /// The instant certificate validity is judged against.
    pub(crate) now_unix: i64,
    /// Audit sink, when audit logging is enabled.
    pub(crate) audit: Option<&'a AuditChain>,
}

/// Load one document, verifying its signature, and return its XML.
///
/// `origin` names the file in errors and audit records.
///
/// # Errors
///
/// Returns `SecurityError` when the envelope is malformed, when the signature
/// does not verify against the configured Permissions CA, when a signed
/// document arrives with no Permissions CA configured, when an unsigned
/// document arrives and the escape hatch is off, or when the document is not
/// valid UTF-8.
pub(crate) fn load_verified(
    bytes: &[u8],
    origin: &str,
    kind: DocumentKind,
    policy: &DocumentPolicy<'_>,
) -> Result<String, SecurityError> {
    let envelope = p7s::parse_envelope(bytes).map_err(|e| {
        SecurityError::ConfigError(format!(
            "{} document at {} is not a readable envelope: {}",
            kind.as_str(),
            origin,
            e
        ))
    })?;

    match envelope.kind {
        EnvelopeKind::Plain => {
            if !policy.allow_unsigned {
                return Err(SecurityError::ConfigError(format!(
                    "{} document at {} is not signed. DDS-Security v1.1 9.4.1.2 and 9.4.1.3 \
                     require both documents to be signed by the Permissions CA; sign it with \
                     `openssl smime -sign -text -signer permissions_ca.pem -inkey \
                     permissions_ca.key -outform SMIME`, or set \
                     insecure_allow_unsigned_documents(true) for local development only",
                    kind.as_str(),
                    origin
                )));
            }
            log::warn!(
                "SECURITY: accepting UNSIGNED {} document at {} because \
                 insecure_allow_unsigned_documents is set; anyone who can write this file can \
                 rewrite the domain's access rules",
                kind.as_str(),
                origin
            );
            if let Some(audit) = policy.audit {
                // A refusal to check a signature is an access-control decision,
                // and it belongs in the chain next to the decisions it enables.
                let _ = audit.record(&SecurityEvent::AccessControl {
                    participant_guid: [0u8; 16],
                    action: "load_unsigned_document".to_string(),
                    resource: format!("{}:{}", kind.as_str(), origin),
                    outcome: AccessOutcome::Allowed,
                    timestamp: crate::security::audit::timestamp_ns(),
                });
            }
        }
        EnvelopeKind::SMime | EnvelopeKind::DerAttached => {
            let ca = policy.permissions_ca.ok_or_else(|| {
                SecurityError::ConfigError(format!(
                    "{} document at {} carries a signature but no permissions CA is \
                     configured to check it against; set permissions_ca",
                    kind.as_str(),
                    origin
                ))
            })?;
            cms::verify_signed_data(
                &envelope.cms_der,
                &envelope.signed_content,
                ca,
                policy.now_unix,
            )
            .map_err(|e| match e {
                SecurityError::CertificateExpired => e,
                other => SecurityError::ConfigError(format!(
                    "{} document at {} failed signature verification: {}",
                    kind.as_str(),
                    origin,
                    other
                )),
            })?;
        }
    }

    let xml = String::from_utf8(envelope.xml).map_err(|_| {
        SecurityError::ConfigError(format!(
            "{} document at {} is not valid UTF-8",
            kind.as_str(),
            origin
        ))
    })?;

    // A verified signature says who wrote the document, not WHICH document it
    // is: the CMS contentType is id-data for both of them, so a permissions
    // file signed by the right CA is a perfectly valid signature to present in
    // the governance slot.
    //
    // This check is the ONLY thing that refuses the swap. An earlier version
    // of this comment said the swap was caught further down anyway, because
    // "an unrecognised governance file yields zero domain rules and an
    // unrecognised permissions file yields zero grants, and both of those are
    // errors". Half of that was never true: `GovernanceConfig::parse` returned
    // `Ok` with an empty rule list and nobody looked at the length, and
    // `PermissionsConfig::parse` still does exactly that for grants
    // (`permissions.rs`, `Ok(Self { grants })`). Nothing downstream would have
    // caught a permissions file presented as governance. A comment asserting a
    // second line of defence that does not exist is worse than no comment: it
    // invites the next reader to relax the first one.
    if !kind.is_declared_by(&xml) {
        return Err(SecurityError::ConfigError(format!(
            "{} document at {} declares none of {}: it does not look like a {} document \
             (a document signed by the permissions CA is still only valid in the slot it \
             was written for)",
            kind.as_str(),
            origin,
            kind.markers().join(", "),
            kind.as_str()
        )));
    }

    Ok(xml)
}

/// Seconds since the Unix epoch, for certificate validity checks.
pub(crate) fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::test_pki::{
        FIXTURE_NOW_UNIX, GOVERNANCE_EC_SMIME, PERMISSIONS_EC_SMIME, PERMISSIONS_PLAIN_XML,
        PERMISSIONS_TAMPERED_SMIME, PERM_CA_EC_PEM,
    };

    fn policy<'a>(ca: Option<&'a PermissionsCa>, allow_unsigned: bool) -> DocumentPolicy<'a> {
        DocumentPolicy {
            permissions_ca: ca,
            allow_unsigned,
            now_unix: FIXTURE_NOW_UNIX,
            audit: None,
        }
    }

    /// Plain XML is refused, and the message says how to sign it.
    #[test]
    fn plain_xml_rejected_by_default() {
        let ca = PermissionsCa::from_pem(PERM_CA_EC_PEM).expect("CA parses");
        let err = load_verified(
            PERMISSIONS_PLAIN_XML,
            "permissions.xml",
            DocumentKind::Permissions,
            &policy(Some(&ca), false),
        )
        .expect_err("unsigned documents must be refused by default");
        let text = err.to_string();
        assert!(text.contains("is not signed"), "got: {}", text);
        assert!(text.contains("openssl smime -sign"), "got: {}", text);
    }

    /// The escape hatch accepts plain XML and returns it unchanged.
    #[test]
    fn plain_xml_accepted_with_explicit_opt_in() {
        let xml = load_verified(
            PERMISSIONS_PLAIN_XML,
            "permissions.xml",
            DocumentKind::Permissions,
            &policy(None, true),
        )
        .expect("the opt-in must accept plain XML");
        assert!(xml.contains("<permissions>"), "got: {}", xml);
    }

    /// The escape hatch does NOT disable verification of a signed document.
    #[test]
    fn opt_in_does_not_excuse_a_broken_signature() {
        let ca = PermissionsCa::from_pem(PERM_CA_EC_PEM).expect("CA parses");
        load_verified(
            PERMISSIONS_TAMPERED_SMIME,
            "permissions.p7s",
            DocumentKind::Permissions,
            &policy(Some(&ca), true),
        )
        .expect_err("a signed document is always verified, opt-in or not");
    }

    /// A signed document with no CA configured is an error, not a pass.
    #[test]
    fn signed_document_without_permissions_ca_is_error() {
        let err = load_verified(
            PERMISSIONS_EC_SMIME,
            "permissions.p7s",
            DocumentKind::Permissions,
            &policy(None, true),
        )
        .expect_err("nothing verifies a signature when no CA is configured");
        assert!(
            err.to_string().contains("no permissions CA is configured"),
            "got: {}",
            err
        );
    }

    /// A correctly signed document is returned as XML.
    #[test]
    fn signed_document_is_accepted_and_returned_as_xml() {
        let ca = PermissionsCa::from_pem(PERM_CA_EC_PEM).expect("CA parses");
        let xml = load_verified(
            PERMISSIONS_EC_SMIME,
            "permissions.p7s",
            DocumentKind::Permissions,
            &policy(Some(&ca), false),
        )
        .expect("a correctly signed document must be accepted");
        assert!(xml.starts_with("<?xml"), "got: {}", xml);
        assert!(xml.contains("HddsTestGrant"), "got: {}", xml);
    }

    /// A signed permissions document is not a governance document, and a
    /// verified signature does not make it one.
    #[test]
    fn a_permissions_document_is_refused_in_the_governance_slot() {
        let ca = PermissionsCa::from_pem(PERM_CA_EC_PEM).expect("CA parses");
        let err = load_verified(
            PERMISSIONS_EC_SMIME,
            "governance.p7s",
            DocumentKind::Governance,
            &policy(Some(&ca), false),
        )
        .expect_err("a permissions document must not pass as governance");
        let text = err.to_string();
        assert!(text.contains("domain_access_rules"), "got: {}", text);
        assert!(
            text.contains("does not look like a governance"),
            "got: {}",
            text
        );
    }

    /// And the same the other way round.
    #[test]
    fn a_governance_document_is_refused_in_the_permissions_slot() {
        let ca = PermissionsCa::from_pem(PERM_CA_EC_PEM).expect("CA parses");
        let err = load_verified(
            GOVERNANCE_EC_SMIME,
            "permissions.p7s",
            DocumentKind::Permissions,
            &policy(Some(&ca), false),
        )
        .expect_err("a governance document must not pass as permissions");
        assert!(
            err.to_string().contains("does not look like a permissions"),
            "got: {}",
            err
        );
    }

    /// The scan reads element names, not text and not attribute values.
    #[test]
    fn element_scan_ignores_text_and_attributes() {
        assert!(declares_element("<dds><permissions/></dds>", "permissions"));
        assert!(declares_element(
            "<dds:permissions xmlns:dds=\"x\"/>",
            "permissions"
        ));
        assert!(declares_element("</permissions>", "permissions"));
        assert!(!declares_element(
            "<dds><topic name=\"permissions\">permissions</topic></dds>",
            "permissions"
        ));
        assert!(!declares_element(
            "<dds><permissions_x/></dds>",
            "permissions"
        ));
    }

    /// The error message names which of the two documents failed.
    #[test]
    fn errors_name_the_document_kind() {
        let ca = PermissionsCa::from_pem(PERM_CA_EC_PEM).expect("CA parses");
        let err = load_verified(
            PERMISSIONS_TAMPERED_SMIME,
            "/etc/dds/governance.p7s",
            DocumentKind::Governance,
            &policy(Some(&ca), false),
        )
        .expect_err("a tampered document must be refused");
        let text = err.to_string();
        assert!(text.contains("governance"), "got: {}", text);
        assert!(text.contains("/etc/dds/governance.p7s"), "got: {}", text);
    }
}
