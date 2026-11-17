// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Access control applied to a REMOTE participant's endpoints.
//!
//! `AccessControlPlugin` answers "may I do this?" from the documents this
//! participant was configured with. This module answers the other half of
//! DDS-Security v1.1 9.4.3, the one the local documents cannot settle alone:
//! "may that peer do this?", from the signed permissions document the peer
//! itself presented during the PKI-DH handshake as the `c.perm` binary
//! property (`handshake::tokens`).
//!
//! Two documents meet here and they are not interchangeable:
//!
//! - OUR governance, already verified when the suite was built. It says which
//!   domains are protected and whether a peer's permissions are checked before
//!   it is let in (`enable_join_access_control`). It is the operator's
//!   declaration, signed, and it is the ONLY thing consulted when a peer
//!   presents nothing.
//! - THE PEER's permissions, freshly arrived and verified here against the
//!   same permissions CA we verified our own documents with. It says what that
//!   peer may publish and subscribe.
//!
//! # A peer cannot downgrade itself
//!
//! "The peer sent no document" and "the peer sent a document that does not
//! verify" are deliberately kept apart. The first is a configuration the
//! operator may legitimately have chosen to admit; the second is a document
//! that failed a signature check, and it is always a refusal. Collapsing the
//! second into the first would hand any peer a way onto the domain: send
//! garbage in `c.perm`, fail verification, and land in the no-document path
//! that an operator running with `enable_join_access_control` false lets
//! through.
//!
//! # No document is no grant
//!
//! A peer without a document is let in only as far as join access control
//! goes (Sec.9.4.1.2.5.3). It holds no permission, so on a topic whose
//! governance rule enables read or write access control the matching check
//! (`check_remote_datareader` / `check_remote_datawriter`, Table 63) has
//! nothing to grant it from and refuses: only a topic whose rule leaves that
//! access control off "shall succeed" without one. Admitting it there would
//! let a peer whose valid document denies a topic simply stop sending it.

use crate::core::discovery::GUID;
use crate::security::access::permissions::DomainRule;
use crate::security::access::{AccessControlPlugin, GovernanceConfig, TopicScope};
use crate::security::cms::PermissionsCa;
use crate::security::signed_document::{self, DocumentKind, DocumentPolicy};
use crate::security::SecurityError;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, Ordering};

/// The material a [`RemoteAccessControl`] needs, captured while the suite was
/// verifying its own documents.
///
/// Kept as a separate value because the two halves are produced at different
/// times: the governance content and the permissions CA are known when
/// `SecurityPluginSuite::new` runs, the domain id only when the participant's
/// discovery is set up.
#[derive(Clone)]
pub(crate) struct RemoteAccessInputs {
    /// OUR governance document, as `signed_document::load_verified` returned
    /// it. Already verified: it is never re-checked here.
    pub(crate) governance_xml: String,
    /// The one trust anchor for a peer's permissions document. `None` only
    /// when the participant was configured with no permissions CA, in which
    /// case a peer that presents a signed document is refused by
    /// `load_verified` rather than trusted blind.
    pub(crate) permissions_ca: Option<PermissionsCa>,
    /// Read a peer's unsigned permissions document, for the fixtures that
    /// have no permissions CA key to sign one with. Test builds only.
    #[cfg(test)]
    pub(crate) accept_unsigned_for_tests: bool,
    /// Whether a peer's allowed partitions conditions are read with the
    /// "legacy matching" (`SecurityConfig::legacy_partition_matching`), as
    /// the local document's are.
    pub(crate) legacy_partition_matching: bool,
}

/// What we concluded about one peer, once.
enum PeerVerdict {
    /// The peer presented no permissions document and our governance rule for
    /// the local domain, held here, does not require join access control. It
    /// holds no grant: it may own an endpoint only on a topic whose rule
    /// leaves that endpoint's access control off (`no_document_admits`).
    NoDocument(DomainRule),
    /// The peer's document verified. These are its grants, already narrowed to
    /// its own subject name per DDS-Security v1.1 9.4.3.
    Grants(AccessControlPlugin),
    /// The peer is refused, for this reason.
    Refused(SecurityError),
}

/// A verdict and the credentials it was reached from.
struct CachedVerdict {
    /// The identity certificate the peer authenticated with.
    peer_cert: Vec<u8>,
    /// The permissions document it presented, if any.
    peer_permissions: Option<Vec<u8>>,
    verdict: PeerVerdict,
}

impl CachedVerdict {
    /// Whether this verdict was reached from these credentials.
    fn reached_from(&self, peer_cert: &[u8], peer_permissions: Option<&[u8]>) -> bool {
        self.peer_cert == peer_cert && self.peer_permissions.as_deref() == peer_permissions
    }
}

/// Decides whether a remote participant's endpoints may be surfaced.
///
/// One instance per participant, shared by `Arc` with the discovery FSM.
pub(crate) struct RemoteAccessControl {
    /// OUR verified governance XML (see [`RemoteAccessInputs::governance_xml`]).
    governance_xml: String,
    /// Trust anchor for a peer's permissions document.
    permissions_ca: Option<PermissionsCa>,
    /// Whether unsigned XML is accepted from a peer: never outside tests.
    /// `insecure_allow_unsigned_documents` is a local development switch for
    /// the documents this participant reads from its own disk; a peer's
    /// permissions document is what grants it rights here, and an unsigned
    /// one is a claim anyone can write.
    #[cfg(test)]
    accept_unsigned_for_tests: bool,
    /// Whether a peer's allowed partitions conditions are read with the
    /// "legacy matching" (`RemoteAccessInputs::legacy_partition_matching`).
    legacy_partition_matching: bool,
    /// The domain this participant joined. Selects the governance rule whose
    /// `enable_join_access_control` decides the no-document case.
    domain_id: u32,
    /// Fixed evaluation instant, or `None` to read the clock on each miss.
    ///
    /// Production leaves this `None`: a permissions CA or a grant that expires
    /// while the participant runs must stop admitting NEW peers, which an
    /// instant pinned at construction could never do. Tests pin it, because
    /// the signed fixtures have a validity window and a test suite must not
    /// start failing on a calendar date, and may move it.
    now_unix: Option<AtomicI64>,
    /// One verdict per peer.
    ///
    /// This cache exists because a CMS signature verification is expensive and
    /// the question it answers does not change between endpoints: a peer is
    /// discovered once but announces one endpoint per reader and writer it
    /// owns, and without this every one of them would re-verify the same
    /// signature and re-parse the same XML. The verdict is pinned to the
    /// instant it was first reached; it lives as long as the handshake session
    /// that produced the credentials: `forget_peer` drops it when that session
    /// goes away and when another one completes (a re-authentication is
    /// judged at its own instant, a grant may have expired since).
    ///
    /// It answers only for the credentials it was reached from
    /// (`CachedVerdict::reached_from`): a check that arrives with the
    /// certificate and document of a session that replaced the one the
    /// verdict was reached for is evaluated again, whatever the order in
    /// which a re-authentication and a check in flight reach this map.
    verdicts: RwLock<HashMap<GUID, CachedVerdict>>,
}

impl RemoteAccessControl {
    /// Build the evaluator for `domain_id` from the suite's verified material.
    pub(crate) fn new(inputs: RemoteAccessInputs, domain_id: u32) -> Self {
        Self {
            governance_xml: inputs.governance_xml,
            permissions_ca: inputs.permissions_ca,
            #[cfg(test)]
            accept_unsigned_for_tests: inputs.accept_unsigned_for_tests,
            legacy_partition_matching: inputs.legacy_partition_matching,
            domain_id,
            now_unix: None,
            verdicts: RwLock::new(HashMap::new()),
        }
    }

    /// Pin the instant every document is judged against.
    ///
    /// Test-only: see [`Self::now_unix`].
    #[cfg(test)]
    pub(crate) fn with_fixed_now(mut self, now_unix: i64) -> Self {
        self.now_unix = Some(AtomicI64::new(now_unix));
        self
    }

    /// Whether a peer's unsigned permissions document is read: never in a
    /// build, whatever `insecure_allow_unsigned_documents` says.
    fn accepts_unsigned(&self) -> bool {
        #[cfg(test)]
        {
            self.accept_unsigned_for_tests
        }
        #[cfg(not(test))]
        {
            false
        }
    }

    /// Move the pinned instant (`with_fixed_now`).
    #[cfg(test)]
    pub(crate) fn set_fixed_now(&self, now_unix: i64) {
        if let Some(ref pinned) = self.now_unix {
            pinned.store(now_unix, Ordering::Relaxed);
        }
    }

    /// Drop the cached verdict for a peer that has gone away, or whose
    /// handshake has just completed.
    ///
    /// A recycled GUID prefix would otherwise inherit the verdict reached for
    /// its predecessor, which is the same class of defect as the recycled
    /// participant id that silently lost SEDP announcements; and a session
    /// that completes is judged at its own instant, not at the instant an
    /// earlier session of the same peer was.
    pub(crate) fn forget_peer(&self, remote_guid: &GUID) {
        self.verdicts.write().remove(remote_guid);
    }

    /// May `remote_guid` own an endpoint on `topic`, before the endpoint's
    /// partitions and data tags are known?
    ///
    /// `peer_cert` and `peer_permissions` are what
    /// `HandshakeMachine::peer_credentials` returned for this peer, in one
    /// piece. `is_writer` selects publish rules over subscribe rules.
    ///
    /// `Ok(TopicScope::Any)`: whatever its partitions and data tags (our
    /// governance leaves the topic's access control off, the one case a peer
    /// without a document is admitted, or no rule names the topic and its
    /// grant's default is ALLOW). `Ok(TopicScope::PerEndpoint)`: the endpoint's partitions and
    /// data tags decide ([`check_remote_endpoint_qualified`](Self::check_remote_endpoint_qualified)).
    ///
    /// # Errors
    ///
    /// Returns `SecurityError::PermissionsDenied` naming the peer, the topic
    /// and the reason. Every refusal path goes through this one variant so a
    /// caller can log them uniformly; the message is what distinguishes a
    /// missing document from one that failed verification.
    pub(crate) fn check_remote_endpoint(
        &self,
        remote_guid: &GUID,
        peer_cert: &[u8],
        peer_permissions: Option<&[u8]>,
        topic: &str,
        is_writer: bool,
    ) -> Result<TopicScope, SecurityError> {
        self.with_verdict(
            remote_guid,
            peer_cert,
            peer_permissions,
            |verdict| match verdict {
                PeerVerdict::NoDocument(rule) => {
                    Self::no_document_admits(rule, remote_guid, topic, is_writer)
                        .map(|()| TopicScope::Any)
                }
                PeerVerdict::Refused(reason) => Err(reason.clone()),
                PeerVerdict::Grants(plugin) => plugin
                    .topic_scope(topic, is_writer)
                    .map_err(|inner| Self::denied(remote_guid, topic, is_writer, &inner)),
            },
        )
    }

    /// `check_remote_datawriter` / `check_remote_datareader` (DDS-Security
    /// v1.1 Sec.8.4.2.9.10, 8.4.2.9.11) for an endpoint of `topic` whose
    /// announcement names `partitions` and `data_tags`: the peer's grant,
    /// rules in document order (`RulesEngine::check_endpoint`).
    ///
    /// # Errors
    ///
    /// As [`check_remote_endpoint`](Self::check_remote_endpoint).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn check_remote_endpoint_qualified(
        &self,
        remote_guid: &GUID,
        peer_cert: &[u8],
        peer_permissions: Option<&[u8]>,
        topic: &str,
        is_writer: bool,
        partitions: &[String],
        data_tags: &[crate::qos::data_tags::DataTag],
    ) -> Result<(), SecurityError> {
        self.with_verdict(
            remote_guid,
            peer_cert,
            peer_permissions,
            |verdict| match verdict {
                PeerVerdict::NoDocument(rule) => {
                    Self::no_document_admits(rule, remote_guid, topic, is_writer)
                }
                PeerVerdict::Refused(reason) => Err(reason.clone()),
                PeerVerdict::Grants(plugin) => plugin
                    .check_endpoint(topic, is_writer, partitions, data_tags)
                    .map_err(|inner| Self::denied(remote_guid, topic, is_writer, &inner)),
            },
        )
    }

    /// Apply `answer` to the verdict reached for `remote_guid` from these
    /// credentials, reached now when none is cached (`verdicts`).
    fn with_verdict<R>(
        &self,
        remote_guid: &GUID,
        peer_cert: &[u8],
        peer_permissions: Option<&[u8]>,
        answer: impl Fn(&PeerVerdict) -> R,
    ) -> R {
        if let Some(cached) = self.verdicts.read().get(remote_guid) {
            if cached.reached_from(peer_cert, peer_permissions) {
                return answer(&cached.verdict);
            }
        }

        // Evaluated off-lock: verification reads no shared state, and holding
        // the map exclusively across a CMS check would serialise discovery of
        // unrelated peers behind it.
        let verdict = self.evaluate(remote_guid, peer_cert, peer_permissions);

        let mut cache = self.verdicts.write();
        // Another thread may have reached the same conclusion meanwhile, from
        // the same credentials: its entry is as good as ours, keep it. An
        // entry reached from other credentials (another session's) is
        // replaced: one verdict per peer, and each answer is the one its own
        // credentials give - a check that replaces the newer session's entry
        // only makes the next check of that session evaluate again.
        match cache.get(remote_guid) {
            Some(cached) if cached.reached_from(peer_cert, peer_permissions) => {
                answer(&cached.verdict)
            }
            _ => {
                let reply = answer(&verdict);
                cache.insert(
                    *remote_guid,
                    CachedVerdict {
                        peer_cert: peer_cert.to_vec(),
                        peer_permissions: peer_permissions.map(<[u8]>::to_vec),
                        verdict,
                    },
                );
                reply
            }
        }
    }

    /// The refusal of a valid document that does not grant `topic`.
    fn denied(
        remote_guid: &GUID,
        topic: &str,
        is_writer: bool,
        inner: &SecurityError,
    ) -> SecurityError {
        SecurityError::PermissionsDenied(format!(
            "remote participant {:?} presented a valid permissions document that does not let \
             it {} topic '{}': {}",
            remote_guid,
            if is_writer { "publish" } else { "subscribe to" },
            topic,
            inner
        ))
    }

    /// May a peer that presented no permissions document own an endpoint of
    /// `topic`? Only when OUR governance `rule` leaves the endpoint's access
    /// control off for the topic (DDS-Security v1.1 Table 63,
    /// check_remote_datawriter / check_remote_datareader): with no document
    /// there is no grant to consult, so an access-controlled topic is
    /// refused, whatever the endpoint's partitions and data tags. A topic no
    /// topic rule matches is refused (Sec.9.4.1.2.7), as for a peer with a
    /// document.
    fn no_document_admits(
        rule: &DomainRule,
        remote_guid: &GUID,
        topic: &str,
        is_writer: bool,
    ) -> Result<(), SecurityError> {
        let Some(topic_rule) = rule.topic_rule_for(topic) else {
            return Err(SecurityError::PermissionsDenied(format!(
                "remote participant {:?} presented no permissions document, and our governance \
                 has no <topic_rule> whose <topic_expression> matches topic '{}' \
                 (DDS-Security v1.1 9.4.1.2.7)",
                remote_guid, topic
            )));
        };
        let (controlled, element) = if is_writer {
            (
                topic_rule.enable_write_access_control,
                "enable_write_access_control",
            )
        } else {
            (
                topic_rule.enable_read_access_control,
                "enable_read_access_control",
            )
        };
        if !controlled {
            return Ok(());
        }
        Err(SecurityError::PermissionsDenied(format!(
            "remote participant {:?} presented no permissions document, so it holds no grant to \
             {} topic '{}', on which our governance sets {} (DDS-Security v1.1 Table 63)",
            remote_guid,
            if is_writer { "publish" } else { "subscribe to" },
            topic,
            element
        )))
    }

    /// Reach a verdict for a peer we have not seen before.
    fn evaluate(
        &self,
        remote_guid: &GUID,
        peer_cert: &[u8],
        peer_permissions: Option<&[u8]>,
    ) -> PeerVerdict {
        let Some(document) = peer_permissions else {
            return self.verdict_without_document(remote_guid);
        };
        match self.verdict_from_document(remote_guid, peer_cert, document) {
            Ok(verdict) => verdict,
            Err(reason) => PeerVerdict::Refused(reason),
        }
    }

    /// The peer presented nothing. OUR governance decides, and nothing else.
    ///
    /// The operator already stated the policy in a signed document, so there
    /// is no configuration flag here and no silent default: a domain the
    /// governance does not describe admits nobody, and a domain it describes
    /// with `enable_join_access_control` admits nobody who cannot show a
    /// document. Otherwise the peer is in, with no grant: each topic's rule
    /// decides (`no_document_admits`).
    fn verdict_without_document(&self, remote_guid: &GUID) -> PeerVerdict {
        let governance = match GovernanceConfig::parse(&self.governance_xml) {
            Ok(governance) => governance,
            // Unreachable in production - the same text parsed when the suite
            // was built - but a parse that fails here must not widen access.
            Err(err) => {
                return PeerVerdict::Refused(SecurityError::PermissionsDenied(format!(
                    "our own governance document no longer parses, so no remote participant \
                     can be judged against it: {}",
                    err
                )))
            }
        };

        let Some(rule) = governance
            .domain_rules
            .iter()
            .find(|rule| rule.covers(self.domain_id))
        else {
            return PeerVerdict::Refused(SecurityError::PermissionsDenied(format!(
                "remote participant {:?} presented no permissions document, and our \
                 governance document carries no domain rule covering domain {}: a domain \
                 our own governance does not describe is not one we admit peers on",
                remote_guid, self.domain_id
            )));
        };

        if rule.enable_join_access_control {
            PeerVerdict::Refused(SecurityError::PermissionsDenied(format!(
                "remote participant {:?} presented no permissions document, and our \
                 governance sets enable_join_access_control for domain {}",
                remote_guid, self.domain_id
            )))
        } else {
            PeerVerdict::NoDocument(rule.clone())
        }
    }

    /// The peer presented a document. Verify it, then read it.
    fn verdict_from_document(
        &self,
        remote_guid: &GUID,
        peer_cert: &[u8],
        document: &[u8],
    ) -> Result<PeerVerdict, SecurityError> {
        let now_unix = self
            .now_unix
            .as_ref()
            .map_or_else(signed_document::now_unix, |pinned| {
                pinned.load(Ordering::Relaxed)
            });
        let policy = DocumentPolicy {
            permissions_ca: self.permissions_ca.as_ref(),
            allow_unsigned: self.accepts_unsigned(),
            now_unix,
            // The peer's document is not one of ours, and recording every
            // remote document in the local chain would let a peer drive our
            // audit volume. Its refusals surface as a warn log at the gate.
            audit: None,
        };

        let origin = format!("c.perm from {:?}", remote_guid);
        let permissions_xml =
            signed_document::load_verified(document, &origin, DocumentKind::Permissions, &policy)
                .map_err(|inner| {
                SecurityError::PermissionsDenied(format!(
                    "remote participant {:?} presented a permissions document that did not verify \
                 against our permissions CA: {}",
                    remote_guid, inner
                ))
            })?;

        let subject = super::subject::certificate_subject(peer_cert).map_err(|inner| {
            SecurityError::PermissionsDenied(format!(
                "remote participant {:?} presented a permissions document but its identity \
                 certificate has no readable subject: {}",
                remote_guid, inner
            ))
        })?;

        // OUR governance, THEIR permissions, THEIR subject. The governance is
        // the domain's, so it is the same document for every peer; the grants
        // are the peer's own, and 9.4.3 keeps only those issued to the subject
        // named in the certificate we just authenticated it with.
        let plugin = AccessControlPlugin::from_documents_for_name(
            &self.governance_xml,
            &permissions_xml,
            &subject,
            now_unix,
            self.domain_id,
        )
        .map_err(|inner| {
            SecurityError::PermissionsDenied(format!(
                "remote participant {:?} presented a permissions document that grants '{}' \
                 nothing in force: {}",
                remote_guid, subject, inner
            ))
        })?
        .with_legacy_partition_matching(self.legacy_partition_matching);

        Ok(PeerVerdict::Grants(plugin))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::rtps_constants::RTPS_ENTITYID_PARTICIPANT;
    use crate::security::test_pki::{
        AUDIT_PERMISSIONS_SMIME, FIXTURE_NOW_UNIX, PERMISSIONS_OTHER_SUBJECT_SMIME,
        PERMISSIONS_TAMPERED_SMIME, PERM_CA_EC_PEM, TEST_IDENTITY_CERT_PEM,
    };

    /// The domain `audit_permissions.smime` writes its grant for.
    const GRANTED_DOMAIN: u32 = 229;

    fn peer_guid() -> GUID {
        GUID::new([0x7A; 12], RTPS_ENTITYID_PARTICIPANT)
    }

    fn governance_with_join_access_control(enabled: bool) -> String {
        format!(
            r#"<?xml version="1.0"?>
<governance>
  <domain_rule>
    <domains>{}</domains>
    <allow_unauthenticated_participants>false</allow_unauthenticated_participants>
    <enable_join_access_control>{}</enable_join_access_control>
    <discovery_protection_kind>NONE</discovery_protection_kind>
    <data_protection_kind>NONE</data_protection_kind>
  </domain_rule>
</governance>"#,
            GRANTED_DOMAIN, enabled
        )
    }

    /// A governance whose one topic rule names `expression`, with the given
    /// join, read and write access control.
    fn governance_with_topic_rule(
        join_access_control: bool,
        expression: &str,
        read_access_control: bool,
        write_access_control: bool,
    ) -> String {
        format!(
            r#"<dds><domain_access_rules><domain_rule>
  <domains>{}</domains>
  <allow_unauthenticated_participants>false</allow_unauthenticated_participants>
  <enable_join_access_control>{}</enable_join_access_control>
  <discovery_protection_kind>NONE</discovery_protection_kind>
  <liveliness_protection_kind>NONE</liveliness_protection_kind>
  <rtps_protection_kind>NONE</rtps_protection_kind>
  <topic_access_rules><topic_rule>
    <topic_expression>{}</topic_expression>
    <enable_discovery_protection>false</enable_discovery_protection>
    <enable_liveliness_protection>false</enable_liveliness_protection>
    <enable_read_access_control>{}</enable_read_access_control>
    <enable_write_access_control>{}</enable_write_access_control>
    <metadata_protection_kind>NONE</metadata_protection_kind>
    <data_protection_kind>ENCRYPT</data_protection_kind>
  </topic_rule></topic_access_rules>
</domain_rule></domain_access_rules></dds>"#,
            GRANTED_DOMAIN,
            join_access_control,
            expression,
            read_access_control,
            write_access_control
        )
    }

    fn evaluator(governance_xml: String, domain_id: u32) -> RemoteAccessControl {
        let ca = PermissionsCa::from_pem(PERM_CA_EC_PEM).expect("fixture permissions CA parses");
        RemoteAccessControl::new(
            RemoteAccessInputs {
                governance_xml,
                permissions_ca: Some(ca),
                accept_unsigned_for_tests: false,
                legacy_partition_matching: false,
            },
            domain_id,
        )
        .with_fixed_now(FIXTURE_NOW_UNIX)
    }

    /// No document, and the operator asked for join access control: refused.
    ///
    /// Goes red if the no-document path ever defaults to "allow", which is the
    /// shape this gate exists to forbid.
    #[test]
    fn peer_without_a_document_is_refused_when_governance_requires_one() {
        let control = evaluator(governance_with_join_access_control(true), GRANTED_DOMAIN);
        let err = control
            .check_remote_endpoint(
                &peer_guid(),
                TEST_IDENTITY_CERT_PEM,
                None,
                "sensor/temperature",
                true,
            )
            .expect_err("a peer with no document must not pass join access control");
        let text = err.to_string();
        assert!(
            text.contains("presented no permissions document"),
            "{}",
            text
        );
        assert!(text.contains("enable_join_access_control"), "{}", text);
    }

    /// Same peer, same absence of a document, opposite governance: admitted,
    /// on a topic whose access control our governance leaves off.
    ///
    /// The pair is the point: it proves the verdict is read from the signed
    /// governance and not from a constant.
    #[test]
    fn peer_without_a_document_is_admitted_when_governance_does_not_require_one() {
        let control = evaluator(
            governance_with_topic_rule(false, "sensor/*", false, false),
            GRANTED_DOMAIN,
        );
        for is_writer in [true, false] {
            let scope = control
                .check_remote_endpoint(
                    &peer_guid(),
                    TEST_IDENTITY_CERT_PEM,
                    None,
                    "sensor/temperature",
                    is_writer,
                )
                .expect(
                    "governance with join and topic access control off must admit a peer \
                     with no document",
                );
            assert_eq!(scope, TopicScope::Any, "unconstrained: every partition");
            control
                .check_remote_endpoint_qualified(
                    &peer_guid(),
                    TEST_IDENTITY_CERT_PEM,
                    None,
                    "sensor/temperature",
                    is_writer,
                    &["B".to_string()],
                    &[],
                )
                .expect("any partition");
        }
    }

    /// DDS-Security v1.1 Table 63, check_remote_datawriter: only a topic
    /// whose governance rule sets enable_write_access_control FALSE succeeds
    /// without a grant; otherwise the permissions of the remote participant
    /// decide, and a peer that presented no document holds no permission.
    /// Join access control off (Sec.9.4.1.2.5.3) only lets the participant
    /// in; "no document" must not open a topic a document could have denied.
    #[test]
    fn v2_omitting_c_perm_does_not_open_a_protected_topic() {
        let governance = governance_with_topic_rule(false, "admin/*", true, true);
        let control = evaluator(governance.clone(), GRANTED_DOMAIN);
        control
            .check_remote_endpoint(
                &peer_guid(),
                TEST_IDENTITY_CERT_PEM,
                Some(AUDIT_PERMISSIONS_SMIME),
                "admin/shutdown",
                true,
            )
            .expect_err("control: the document denies admin/*");
        let control = evaluator(governance, GRANTED_DOMAIN);
        let other = GUID::new([0x7B; 12], RTPS_ENTITYID_PARTICIPANT);
        for is_writer in [true, false] {
            let verdict = control.check_remote_endpoint(
                &other,
                TEST_IDENTITY_CERT_PEM,
                None,
                "admin/shutdown",
                is_writer,
            );
            let err = verdict.expect_err(
                "a peer that omits c.perm owns an endpoint on an access-controlled topic",
            );
            let text = err.to_string();
            assert!(
                text.contains("presented no permissions document"),
                "{}",
                text
            );
            assert!(text.contains("admin/shutdown"), "{}", text);
            control
                .check_remote_endpoint_qualified(
                    &other,
                    TEST_IDENTITY_CERT_PEM,
                    None,
                    "admin/shutdown",
                    is_writer,
                    &[],
                    &[],
                )
                .expect_err("the per-endpoint check refuses it too");
        }
    }

    /// The peer whose valid document denies a topic, then the same peer
    /// presenting nothing (a new session without `c.perm`): it gains nothing.
    #[test]
    fn a_peer_that_stops_sending_its_denying_document_gains_nothing() {
        let control = evaluator(
            governance_with_topic_rule(false, "admin/*", true, true),
            GRANTED_DOMAIN,
        );
        let guid = peer_guid();
        control
            .check_remote_endpoint(
                &guid,
                TEST_IDENTITY_CERT_PEM,
                Some(AUDIT_PERMISSIONS_SMIME),
                "admin/shutdown",
                true,
            )
            .expect_err("the document denies admin/*");
        control
            .check_remote_endpoint(&guid, TEST_IDENTITY_CERT_PEM, None, "admin/shutdown", true)
            .expect_err("dropping the denying document opened the topic");
    }

    /// Access control enabled on one direction only: a peer without a
    /// document may own the open side, never the controlled one.
    #[test]
    fn without_a_document_each_direction_follows_its_own_access_control() {
        let control = evaluator(
            governance_with_topic_rule(false, "admin/*", true, false),
            GRANTED_DOMAIN,
        );
        let check = |is_writer| {
            control.check_remote_endpoint(
                &peer_guid(),
                TEST_IDENTITY_CERT_PEM,
                None,
                "admin/shutdown",
                is_writer,
            )
        };
        assert_eq!(check(true).expect("writes are open"), TopicScope::Any);
        let err = check(false).expect_err("reads are access-controlled");
        assert!(err.to_string().contains("subscribe to"), "{}", err);
    }

    /// The shorthand governance (no topic rules) controls every topic
    /// (`TopicRule::shorthand`), and a topic no rule matches is refused
    /// (Sec.9.4.1.2.7): neither is open to a peer without a document.
    #[test]
    fn without_a_document_shorthand_and_unmatched_topics_are_refused() {
        let shorthand = evaluator(governance_with_join_access_control(false), GRANTED_DOMAIN);
        shorthand
            .check_remote_endpoint(
                &peer_guid(),
                TEST_IDENTITY_CERT_PEM,
                None,
                "sensor/temperature",
                true,
            )
            .expect_err("the shorthand rule controls every topic");
        let narrow = evaluator(
            governance_with_topic_rule(false, "sensor/*", false, false),
            GRANTED_DOMAIN,
        );
        let err = narrow
            .check_remote_endpoint(&peer_guid(), TEST_IDENTITY_CERT_PEM, None, "other", true)
            .expect_err("no topic rule matches 'other'");
        assert!(err.to_string().contains("no <topic_rule>"), "{}", err);
    }

    /// A domain our own governance says nothing about admits nobody.
    #[test]
    fn peer_on_a_domain_no_governance_rule_covers_is_refused() {
        let uncovered = GRANTED_DOMAIN + 1;
        let control = evaluator(governance_with_join_access_control(false), uncovered);
        let err = control
            .check_remote_endpoint(
                &peer_guid(),
                TEST_IDENTITY_CERT_PEM,
                None,
                "sensor/temperature",
                true,
            )
            .expect_err("an undescribed domain must not admit peers");
        assert!(
            err.to_string().contains("no domain rule covering domain"),
            "{}",
            err
        );
    }

    /// The peer's own document grants `sensor/*`, so a writer on it passes,
    /// in the default partition only: the grant names no partition
    /// (DDS-Security v1.1 Sec.9.4.1.3.2.3.1.4), so the endpoint's partitions
    /// decide.
    #[test]
    fn peer_whose_document_grants_the_topic_is_admitted() {
        let control = evaluator(governance_with_join_access_control(true), GRANTED_DOMAIN);
        let scope = control
            .check_remote_endpoint(
                &peer_guid(),
                TEST_IDENTITY_CERT_PEM,
                Some(AUDIT_PERMISSIONS_SMIME),
                "sensor/temperature",
                true,
            )
            .expect("sensor/* is granted to this subject by the fixture");
        assert_eq!(scope, TopicScope::PerEndpoint);
        let qualified = |partitions: &[&str]| {
            control.check_remote_endpoint_qualified(
                &peer_guid(),
                TEST_IDENTITY_CERT_PEM,
                Some(AUDIT_PERMISSIONS_SMIME),
                "sensor/temperature",
                true,
                &partitions
                    .iter()
                    .map(|name| (*name).to_string())
                    .collect::<Vec<_>>(),
                &[],
            )
        };
        assert!(qualified(&[]).is_ok(), "the default partition");
        assert!(qualified(&[""]).is_ok(), "the default partition, named");
        assert!(qualified(&["B"]).is_err(), "not granted in partition B");
    }

    /// The same document denies `admin/*`, and the refusal names the topic.
    #[test]
    fn peer_whose_document_does_not_grant_the_topic_is_refused() {
        let control = evaluator(governance_with_join_access_control(true), GRANTED_DOMAIN);
        let err = control
            .check_remote_endpoint(
                &peer_guid(),
                TEST_IDENTITY_CERT_PEM,
                Some(AUDIT_PERMISSIONS_SMIME),
                "admin/shutdown",
                true,
            )
            .expect_err("admin/* is denied to this subject by the fixture");
        let text = err.to_string();
        assert!(text.contains("admin/shutdown"), "{}", text);
        assert!(text.contains("does not let it publish"), "{}", text);
    }

    /// DDS-Security v1.1 Table 63, check_remote_datawriter: "If the
    /// Governance specifies a topic or topic-expression ... matching the
    /// remote DataWriter topic with enable_write_access_control set to FALSE,
    /// then the operation shall succeed". The same document that denies
    /// `admin/*` lets the peer publish `admin/shutdown` when our governance
    /// leaves that topic's writes open, and not its reads.
    #[test]
    fn a_topic_our_governance_leaves_open_needs_no_grant_from_a_peer() {
        let governance = format!(
            r#"<dds><domain_access_rules><domain_rule>
  <domains>{}</domains>
  <allow_unauthenticated_participants>false</allow_unauthenticated_participants>
  <enable_join_access_control>true</enable_join_access_control>
  <discovery_protection_kind>NONE</discovery_protection_kind>
  <liveliness_protection_kind>NONE</liveliness_protection_kind>
  <rtps_protection_kind>NONE</rtps_protection_kind>
  <topic_access_rules><topic_rule>
    <topic_expression>admin/*</topic_expression>
    <enable_discovery_protection>false</enable_discovery_protection>
    <enable_liveliness_protection>false</enable_liveliness_protection>
    <enable_read_access_control>true</enable_read_access_control>
    <enable_write_access_control>false</enable_write_access_control>
    <metadata_protection_kind>NONE</metadata_protection_kind>
    <data_protection_kind>NONE</data_protection_kind>
  </topic_rule></topic_access_rules>
</domain_rule></domain_access_rules></dds>"#,
            GRANTED_DOMAIN
        );
        let control = evaluator(governance, GRANTED_DOMAIN);
        control
            .check_remote_endpoint(
                &peer_guid(),
                TEST_IDENTITY_CERT_PEM,
                Some(AUDIT_PERMISSIONS_SMIME),
                "admin/shutdown",
                true,
            )
            .expect("writes to admin/* are open in our governance");
        control
            .check_remote_endpoint(
                &peer_guid(),
                TEST_IDENTITY_CERT_PEM,
                Some(AUDIT_PERMISSIONS_SMIME),
                "admin/shutdown",
                false,
            )
            .expect_err("reads of admin/* are not, and the document denies them");
    }

    /// A reader is judged by the subscribe rules, not the publish ones.
    #[test]
    fn a_reader_is_judged_by_the_subscribe_rules() {
        let control = evaluator(governance_with_join_access_control(true), GRANTED_DOMAIN);
        control
            .check_remote_endpoint(
                &peer_guid(),
                TEST_IDENTITY_CERT_PEM,
                Some(AUDIT_PERMISSIONS_SMIME),
                "sensor/temperature",
                false,
            )
            .expect("sensor/* is granted for subscribe too");
        let err = control
            .check_remote_endpoint(
                &peer_guid(),
                TEST_IDENTITY_CERT_PEM,
                Some(AUDIT_PERMISSIONS_SMIME),
                "admin/shutdown",
                false,
            )
            .expect_err("admin/* is denied for subscribe too");
        assert!(
            err.to_string().contains("does not let it subscribe to"),
            "{}",
            err
        );
    }

    /// A document that fails verification is refused, and NOT treated as the
    /// absence of a document.
    ///
    /// This is the downgrade the module exists to forbid: the governance here
    /// has `enable_join_access_control` FALSE and leaves the topic's access
    /// control off, so a peer sending nothing would be admitted. Sending
    /// garbage must still be refused, and the message must say which of the
    /// two happened.
    #[test]
    fn a_document_that_fails_verification_is_refused_and_says_so() {
        let control = evaluator(
            governance_with_topic_rule(false, "sensor/*", false, false),
            GRANTED_DOMAIN,
        );
        let err = control
            .check_remote_endpoint(
                &peer_guid(),
                TEST_IDENTITY_CERT_PEM,
                Some(PERMISSIONS_TAMPERED_SMIME),
                "sensor/temperature",
                true,
            )
            .expect_err("a tampered document must never fall back to the no-document path");
        let text = err.to_string();
        assert!(text.contains("did not verify"), "{}", text);
        assert!(
            !text.contains("presented no permissions document"),
            "the refusal must not be confusable with the no-document case: {}",
            text
        );
    }

    /// A perfectly signed document issued to somebody else grants nothing.
    #[test]
    fn a_document_issued_to_another_subject_is_refused() {
        let control = evaluator(governance_with_join_access_control(true), GRANTED_DOMAIN);
        let err = control
            .check_remote_endpoint(
                &peer_guid(),
                TEST_IDENTITY_CERT_PEM,
                Some(PERMISSIONS_OTHER_SUBJECT_SMIME),
                "sensor/temperature",
                true,
            )
            .expect_err("a valid document issued to another subject must grant nothing");
        assert!(err.to_string().contains("nothing in force"), "{}", err);
    }

    /// The second endpoint of the same peer reuses the first verdict.
    ///
    /// Asserted through `forget_peer`: after the entry is dropped the same
    /// call must be evaluated again, which is only observable if it was cached
    /// in the first place.
    #[test]
    fn the_verdict_is_cached_per_peer_and_dropped_with_the_peer() {
        let control = evaluator(governance_with_join_access_control(true), GRANTED_DOMAIN);
        let guid = peer_guid();
        control
            .check_remote_endpoint(
                &guid,
                TEST_IDENTITY_CERT_PEM,
                Some(AUDIT_PERMISSIONS_SMIME),
                "sensor/a",
                true,
            )
            .expect("first endpoint admitted");
        assert_eq!(control.verdicts.read().len(), 1, "one verdict per peer");

        control
            .check_remote_endpoint(
                &guid,
                TEST_IDENTITY_CERT_PEM,
                Some(AUDIT_PERMISSIONS_SMIME),
                "sensor/b",
                true,
            )
            .expect("second endpoint of the same peer admitted from the cache");
        assert_eq!(
            control.verdicts.read().len(),
            1,
            "a second endpoint must not add a second verdict"
        );

        control.forget_peer(&guid);
        assert!(
            control.verdicts.read().is_empty(),
            "a departed peer must not leave its verdict behind for a recycled prefix"
        );
    }

    /// A verdict answers only for the credentials it was reached from.
    ///
    /// The same peer presents another permissions document (a session that
    /// replaced its old one): the cached verdict must not answer for it, in
    /// either direction - a refusal must not outlive the renewed document,
    /// nor an admission the expired one.
    #[test]
    fn a_cached_verdict_answers_only_for_the_credentials_it_was_reached_from() {
        use crate::security::test_pki::PERMISSIONS_EXPIRED_GRANT_SMIME;
        let control = evaluator(governance_with_join_access_control(true), GRANTED_DOMAIN);
        let guid = peer_guid();
        let check = |document: &[u8]| {
            control.check_remote_endpoint(
                &guid,
                TEST_IDENTITY_CERT_PEM,
                Some(document),
                "sensor/temperature",
                true,
            )
        };
        check(PERMISSIONS_EXPIRED_GRANT_SMIME).expect_err("the expired grant refuses");
        check(AUDIT_PERMISSIONS_SMIME)
            .expect("the renewed document was answered by the refusal cached for the expired one");
        check(PERMISSIONS_EXPIRED_GRANT_SMIME).expect_err(
            "the expired document was answered by the admission cached for the renewed one",
        );
        assert_eq!(control.verdicts.read().len(), 1, "one verdict per peer");
    }

    /// The subject reader accepts the PEM the handshake actually carries.
    ///
    /// Pinned separately because the field is named `identity_cert_der` and is
    /// not DER; if that is ever corrected, this test keeps the DER branch
    /// honest too.
    #[test]
    fn the_subject_is_read_from_pem_and_from_der() {
        use crate::security::access::subject::certificate_subject;
        let from_pem = certificate_subject(TEST_IDENTITY_CERT_PEM).expect("PEM is readable");
        let (_, pem) = x509_parser::pem::parse_x509_pem(TEST_IDENTITY_CERT_PEM)
            .expect("fixture is a PEM certificate");
        let from_der = certificate_subject(&pem.contents).expect("DER is readable");
        assert_eq!(from_pem, from_der);
        let named =
            crate::security::access::DistinguishedName::parse("CN=DDS Test Identity, O=HDDS Test")
                .expect("dn");
        assert!(from_pem.matches(&named), "{}", from_pem);
    }
    // Adversarial cases of the decision: every governance x document x
    // endpoint kind, a re-authentication that drops its document, rule order,
    // a document holder on an open or unmatched topic, builtin-like names.
    fn two_rule_gov(
        first_expr: &str,
        first_ac: bool,
        second_expr: &str,
        second_ac: bool,
    ) -> String {
        format!(
            r#"<dds><domain_access_rules><domain_rule>
  <domains>{d}</domains>
  <allow_unauthenticated_participants>false</allow_unauthenticated_participants>
  <enable_join_access_control>false</enable_join_access_control>
  <discovery_protection_kind>NONE</discovery_protection_kind>
  <liveliness_protection_kind>NONE</liveliness_protection_kind>
  <rtps_protection_kind>NONE</rtps_protection_kind>
  <topic_access_rules><topic_rule>
    <topic_expression>{a}</topic_expression>
    <enable_discovery_protection>false</enable_discovery_protection>
    <enable_liveliness_protection>false</enable_liveliness_protection>
    <enable_read_access_control>{aa}</enable_read_access_control>
    <enable_write_access_control>{aa}</enable_write_access_control>
    <metadata_protection_kind>NONE</metadata_protection_kind>
    <data_protection_kind>NONE</data_protection_kind>
  </topic_rule><topic_rule>
    <topic_expression>{b}</topic_expression>
    <enable_discovery_protection>false</enable_discovery_protection>
    <enable_liveliness_protection>false</enable_liveliness_protection>
    <enable_read_access_control>{bb}</enable_read_access_control>
    <enable_write_access_control>{bb}</enable_write_access_control>
    <metadata_protection_kind>NONE</metadata_protection_kind>
    <data_protection_kind>NONE</data_protection_kind>
  </topic_rule></topic_access_rules>
</domain_rule></domain_access_rules></dds>"#,
            d = GRANTED_DOMAIN,
            a = first_expr,
            aa = first_ac,
            b = second_expr,
            bb = second_ac
        )
    }

    #[test]
    fn atk_matrix_join_x_rw_x_document_kind() {
        let garbage: &[u8] = b"not a document";
        let ws: &[u8] = b"   ";
        for join in [false, true] {
            for (r, w) in [(false, false), (true, true), (true, false), (false, true)] {
                for (label, doc) in [
                    ("absent", None),
                    ("tampered", Some(PERMISSIONS_TAMPERED_SMIME)),
                    ("garbage", Some(garbage)),
                    ("whitespace", Some(ws)),
                ] {
                    for is_writer in [true, false] {
                        let c =
                            evaluator(governance_with_topic_rule(join, "*", r, w), GRANTED_DOMAIN);
                        let got = c
                            .check_remote_endpoint(
                                &peer_guid(),
                                TEST_IDENTITY_CERT_PEM,
                                doc,
                                "sensor/x",
                                is_writer,
                            )
                            .is_ok();
                        let gotq = c
                            .check_remote_endpoint_qualified(
                                &peer_guid(),
                                TEST_IDENTITY_CERT_PEM,
                                doc,
                                "sensor/x",
                                is_writer,
                                &["P".to_string(), "*".to_string()],
                                &[],
                            )
                            .is_ok();
                        let controlled = if is_writer { w } else { r };
                        let expect = label == "absent" && !join && !controlled;
                        assert_eq!(
                            got, expect,
                            "join={join} r={r} w={w} doc={label} writer={is_writer}"
                        );
                        assert_eq!(
                            gotq, expect,
                            "qualified join={join} r={r} w={w} doc={label} writer={is_writer}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn atk_reauth_none_then_doc_then_none() {
        let c = evaluator(
            governance_with_topic_rule(false, "*", true, true),
            GRANTED_DOMAIN,
        );
        let g = peer_guid();
        assert!(c
            .check_remote_endpoint(&g, TEST_IDENTITY_CERT_PEM, None, "sensor/x", true)
            .is_err());
        assert_eq!(
            c.check_remote_endpoint(
                &g,
                TEST_IDENTITY_CERT_PEM,
                Some(AUDIT_PERMISSIONS_SMIME),
                "sensor/x",
                true
            )
            .expect("doc grants sensor/*"),
            TopicScope::PerEndpoint
        );
        assert!(c
            .check_remote_endpoint(
                &g,
                TEST_IDENTITY_CERT_PEM,
                Some(AUDIT_PERMISSIONS_SMIME),
                "admin/x",
                true
            )
            .is_err());
        assert!(
            c.check_remote_endpoint(&g, TEST_IDENTITY_CERT_PEM, None, "sensor/x", true)
                .is_err(),
            "back to no doc"
        );
        assert!(c
            .check_remote_endpoint(&g, TEST_IDENTITY_CERT_PEM, None, "admin/x", false)
            .is_err());
    }

    #[test]
    fn atk_first_match_order() {
        let c = evaluator(two_rule_gov("admin/*", false, "*", true), GRANTED_DOMAIN);
        assert!(c
            .check_remote_endpoint(&peer_guid(), TEST_IDENTITY_CERT_PEM, None, "admin/x", true)
            .is_ok());
        assert!(c
            .check_remote_endpoint(&peer_guid(), TEST_IDENTITY_CERT_PEM, None, "sensor/x", true)
            .is_err());
        let c = evaluator(two_rule_gov("*", true, "admin/*", false), GRANTED_DOMAIN);
        assert!(
            c.check_remote_endpoint(&peer_guid(), TEST_IDENTITY_CERT_PEM, None, "admin/x", true)
                .is_err(),
            "first match wins: * controlled"
        );
    }

    /// Table 63: an open topic "shall succeed" for a document holder too, even one whose doc denies it.
    #[test]
    fn atk_doc_holder_on_open_topic_denied_by_doc() {
        let c = evaluator(
            governance_with_topic_rule(false, "*", false, false),
            GRANTED_DOMAIN,
        );
        let r = c.check_remote_endpoint(
            &peer_guid(),
            TEST_IDENTITY_CERT_PEM,
            Some(AUDIT_PERMISSIONS_SMIME),
            "admin/x",
            true,
        );
        let rn = c.check_remote_endpoint(
            &GUID::new([0x55; 12], RTPS_ENTITYID_PARTICIPANT),
            TEST_IDENTITY_CERT_PEM,
            None,
            "admin/x",
            true,
        );
        assert_eq!(
            r.is_ok(),
            rn.is_ok(),
            "doc-holder {:?} vs no-doc {:?}",
            r,
            rn
        );
    }

    /// 9.4.1.2.7: unmatched topic refused for a doc holder too.
    #[test]
    fn atk_doc_holder_on_unmatched_topic() {
        let c = evaluator(
            governance_with_topic_rule(false, "other/*", true, true),
            GRANTED_DOMAIN,
        );
        let r = c.check_remote_endpoint(
            &peer_guid(),
            TEST_IDENTITY_CERT_PEM,
            Some(AUDIT_PERMISSIONS_SMIME),
            "sensor/x",
            true,
        );
        assert!(r.is_err(), "{:?}", r);
        let rq = c.check_remote_endpoint_qualified(
            &peer_guid(),
            TEST_IDENTITY_CERT_PEM,
            Some(AUDIT_PERMISSIONS_SMIME),
            "sensor/x",
            true,
            &[],
            &[],
        );
        assert!(rq.is_err(), "{:?}", rq);
    }

    #[test]
    fn atk_builtin_like_names_and_data_tags() {
        let c = evaluator(
            governance_with_topic_rule(false, "*", true, true),
            GRANTED_DOMAIN,
        );
        for t in [
            "DCPSParticipantsSecure",
            "DCPSPublicationsSecure",
            "DCPSParticipantMessageSecure",
            "DCPSParticipantVolatileMessageSecure",
            "TypeLookup",
            "",
            "*",
        ] {
            assert!(
                c.check_remote_endpoint(&peer_guid(), TEST_IDENTITY_CERT_PEM, None, t, true)
                    .is_err(),
                "{t}"
            );
        }
        let tags = vec![crate::qos::data_tags::DataTag {
            name: "a".into(),
            value: "b".into(),
        }];
        assert!(c
            .check_remote_endpoint_qualified(
                &peer_guid(),
                TEST_IDENTITY_CERT_PEM,
                None,
                "sensor/x",
                false,
                &[],
                &tags
            )
            .is_err());
    }
}
