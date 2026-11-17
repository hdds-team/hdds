// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Access Control Plugin for DDS Security v1.1
//!
//! Implements topic/partition authorization per DDS Security spec Sec.8.4-8.5.
//!
//! # XML Configuration
//!
//! - **governance.xml** -- Domain-wide security policies
//! - **permissions.xml** -- Per-participant topic allow/deny rules
//!
//! # Example
//!
//! ```ignore
//! use hdds::security::access::AccessControlPlugin;
//!
//! let plugin = AccessControlPlugin::from_xml(
//!     "governance.xml",
//!     "permissions.xml"
//! )?;
//!
//! // Check if participant can create writer on topic
//! plugin.check_create_writer("sensor/temperature", None)?;
//! ```

use crate::security::SecurityError;

pub mod attributes;
/// POSIX fnmatch, as the governance topic expressions are matched.
pub(crate) mod fnmatch;
pub mod permissions;
/// Access control applied to a REMOTE participant, from the signed permissions
/// document it presented during the handshake.
pub(crate) mod remote;
pub mod rules;
pub mod subject;

/// The published governance examples, parsed from the files that publish them.
#[cfg(test)]
mod doc_examples_tests;

/// A governance that requests a protection this release does not apply is
/// refused when the participant is created.
#[cfg(all(test, feature = "qos-loaders"))]
mod protection_refusal_tests;

pub use attributes::{
    BasicProtectionKind, EndpointSecurityAttributes, ParticipantSecurityAttributes,
    PluginEndpointSecurityAttributes, PluginParticipantSecurityAttributes, ProtectionKind,
    TopicSecurityAttributes,
};
pub use permissions::{
    Criterion, DomainRule, GovernanceConfig, Grant, PermissionsConfig, Rule, RuleKind, TopicRule,
    Validity,
};
pub(crate) use remote::{RemoteAccessControl, RemoteAccessInputs};
pub use rules::RulesEngine;
pub(crate) use rules::TopicScope;
pub use subject::{parse_xs_datetime, DistinguishedName};

/// What discovery reads of the governance document: the domain rule applied
/// to this participant (DDS-Security v1.1 Sec.9.4.1.2.5).
///
/// The participant's `discovery_protection_kind` (Sec.9.4.1.2.5.4) protects
/// its secure discovery writers, and each topic's `enable_discovery_protection`
/// (Sec.9.4.1.2.6.2, Table 29) decides whether an endpoint of it is announced
/// on them.
#[derive(Debug, Clone)]
pub(crate) struct DiscoveryGovernance {
    rule: DomainRule,
}

impl DiscoveryGovernance {
    /// The policy of `rule`.
    pub(crate) fn new(rule: DomainRule) -> Self {
        Self { rule }
    }

    /// The protection kind of the secure discovery writers and readers.
    pub(crate) fn discovery_protection_kind(&self) -> ProtectionKind {
        self.rule.discovery_protection_kind
    }

    /// `<liveliness_protection_kind>` (Sec.9.4.1.2.5.5): the protection
    /// kind of the ParticipantMessageSecure builtin endpoints
    /// (`DiscoveryFsm::register_builtin_reader_keys`/`_writer_keys`), a
    /// DIFFERENT field than `discovery_protection_kind` even though both
    /// live on the same `DomainRule` -- liveliness assertions are not
    /// discovery traffic.
    pub(crate) fn liveliness_protection_kind(&self) -> ProtectionKind {
        self.rule.liveliness_protection_kind
    }

    /// `is_discovery_protected` of `topic`, `None` when no topic rule
    /// matches it (Sec.9.4.1.2.7: the entity is then refused).
    pub(crate) fn topic_is_discovery_protected(&self, topic: &str) -> Option<bool> {
        self.rule
            .topic_rule_for(topic)
            .map(|rule| rule.enable_discovery_protection)
    }

    /// `allow_unauthenticated_participants` (Sec.9.4.1.2.5.2).
    pub(crate) fn allows_unauthenticated(&self) -> bool {
        self.rule.allow_unauthenticated
    }

    /// Whether `topic` is `is_read_protected` or `is_write_protected`
    /// (`enable_read_access_control`, `enable_write_access_control`,
    /// Sec.9.4.1.2.6.4, 9.4.1.2.6.5). A topic no rule matches is refused
    /// (Sec.9.4.1.2.7), and reads as protected.
    pub(crate) fn topic_is_access_protected(&self, topic: &str) -> bool {
        self.rule
            .topic_rule_for(topic)
            .is_none_or(|rule| rule.enable_read_access_control || rule.enable_write_access_control)
    }

    /// `ParticipantSecurityAttributes` of this participant (Sec.9.4.1.2.5.2
    /// to 9.4.1.2.5.6): the rule already matched its domain.
    pub(crate) fn participant_attributes(&self) -> ParticipantSecurityAttributes {
        self.rule.participant_attributes()
    }

    /// `EndpointSecurityAttributes` of an endpoint of `topic` under this
    /// participant's domain rule (Sec.9.4.1.2.6.6, 9.4.1.2.6.7), consulted
    /// to compare against a remote endpoint's own announced
    /// `PID_ENDPOINT_SECURITY_INFO`.
    ///
    /// `None` when no topic rule matches `topic` (Sec.9.4.1.2.7: the entity
    /// is refused by `check_create_writer`/`check_create_reader` before it
    /// ever reaches discovery; this method reports nothing to compare
    /// against rather than guess one).
    pub(crate) fn topic_endpoint_attributes(
        &self,
        topic: &str,
    ) -> Option<EndpointSecurityAttributes> {
        self.rule
            .topic_rule_for(topic)
            .map(TopicRule::endpoint_attributes)
    }
}

/// Access Control Plugin implementing DDS Security v1.1 Sec.8.4-8.5
pub struct AccessControlPlugin {
    /// Rules engine (governance + permissions)
    rules: RulesEngine,
}

impl AccessControlPlugin {
    /// Create access control plugin from XML files.
    ///
    /// This constructor applies EVERY grant in the document, whoever it was
    /// issued to. It is kept for tools and for tests that write their own
    /// documents inline; a participant goes through
    /// [`from_documents_for_subject`], which applies DDS-Security v1.1 9.4.3.
    ///
    /// [`from_documents_for_subject`]: AccessControlPlugin::from_documents_for_subject
    pub fn from_xml(
        governance_xml: &str,
        permissions_xml: &str,
        domain_id: u32,
    ) -> Result<Self, SecurityError> {
        let governance = GovernanceConfig::parse(governance_xml)?;
        let permissions = PermissionsConfig::parse(permissions_xml)?;

        Ok(Self {
            rules: RulesEngine::new(governance, permissions, domain_id),
        })
    }

    /// Create the plugin from two verified documents, keeping only the grants
    /// that belong to this participant.
    ///
    /// DDS-Security v1.1 9.4.3: `validate_local_permissions` checks that the
    /// subject name in the identity certificate matches the one in the signed
    /// permissions document. A grant issued to another subject, or one whose
    /// `<validity>` window does not contain `now_unix`, is dropped. If nothing
    /// survives, this is an error rather than a silently empty rule set: a
    /// correctly signed document that grants this participant nothing is a
    /// misconfiguration, not a policy.
    ///
    /// # Errors
    ///
    /// Returns `SecurityError::ConfigError` if either document fails to parse,
    /// if the identity DN is unreadable, if a grant carries an unreadable
    /// validity, or if no grant is in force for this subject.
    pub fn from_documents_for_subject(
        governance_xml: &str,
        permissions_xml: &str,
        identity_subject_dn: &str,
        now_unix: i64,
        domain_id: u32,
    ) -> Result<Self, SecurityError> {
        let governance = GovernanceConfig::parse(governance_xml)?;
        let permissions = PermissionsConfig::parse(permissions_xml)?;
        let grants =
            subject::select_grants_for_subject(permissions.grants, identity_subject_dn, now_unix)?;

        Ok(Self {
            rules: RulesEngine::new(governance, PermissionsConfig { grants }, domain_id),
        })
    }

    /// [`Self::from_documents_for_subject`] for the subject name of a
    /// certificate, read from its DER (`subject::certificate_subject`).
    pub(crate) fn from_documents_for_name(
        governance_xml: &str,
        permissions_xml: &str,
        identity: &DistinguishedName,
        now_unix: i64,
        domain_id: u32,
    ) -> Result<Self, SecurityError> {
        let governance = GovernanceConfig::parse(governance_xml)?;
        let permissions = PermissionsConfig::parse(permissions_xml)?;
        let grants = subject::select_grants_for_name(permissions.grants, identity, now_unix)?;

        Ok(Self {
            rules: RulesEngine::new(governance, PermissionsConfig { grants }, domain_id),
        })
    }

    /// Select the "legacy matching" of the permissions' allowed partitions
    /// conditions (DDS-Security v1.1 Sec.9.4.1.3.2.3.1.4,
    /// [`RulesEngine::with_legacy_partition_matching`]); off by default.
    #[must_use]
    pub fn with_legacy_partition_matching(mut self, legacy: bool) -> Self {
        self.rules = self.rules.with_legacy_partition_matching(legacy);
        self
    }

    /// `get_participant_sec_attributes` (DDS-Security v1.1 Sec.8.4.2.9,
    /// Sec.9.4.1.2.5) for the domain this plugin was built for.
    ///
    /// # Errors
    ///
    /// No governance rule covers the domain.
    pub fn participant_attributes(&self) -> Result<ParticipantSecurityAttributes, SecurityError> {
        self.rules.participant_attributes()
    }

    /// `get_datawriter_sec_attributes` / `get_datareader_sec_attributes`
    /// (Sec.8.4.2.9, Sec.9.4.1.2.6) for an endpoint of `topic`.
    ///
    /// # Errors
    ///
    /// No governance rule covers the domain, or no topic rule matches
    /// `topic` (Sec.9.4.1.2.7).
    pub fn endpoint_attributes(
        &self,
        topic: &str,
    ) -> Result<EndpointSecurityAttributes, SecurityError> {
        self.rules.endpoint_attributes(topic)
    }

    /// The discovery policy of the domain rule applied to this participant,
    /// `None` when none covers its domain.
    pub(crate) fn discovery_governance(&self) -> Option<DiscoveryGovernance> {
        self.rules
            .domain_rule()
            .cloned()
            .map(DiscoveryGovernance::new)
    }

    /// Check if participant can join domain
    pub fn check_create_participant(&self, domain_id: u32) -> Result<(), SecurityError> {
        self.rules.check_domain_access(domain_id)
    }

    /// Check if participant can create writer on topic, in `partition`
    /// (`None`: the default partition), without data tags
    /// ([`check_create_datawriter`](Self::check_create_datawriter)).
    pub fn check_create_writer(
        &self,
        topic: &str,
        partition: Option<&str>,
    ) -> Result<(), SecurityError> {
        self.rules.check_topic_publish(topic, partition)
    }

    /// `check_create_datawriter` (DDS-Security v1.1 Sec.8.4.2.9.4): a writer
    /// of `topic` whose PARTITION names `partitions` (empty: the default
    /// partition) and whose DataTagQosPolicy holds `data_tags`
    /// ([`RulesEngine::check_publish`]).
    pub fn check_create_datawriter(
        &self,
        topic: &str,
        partitions: &[String],
        data_tags: &[crate::qos::data_tags::DataTag],
    ) -> Result<(), SecurityError> {
        self.rules.check_publish(topic, partitions, data_tags)
    }

    /// `check_create_datareader` (Sec.8.4.2.9.5), as
    /// [`check_create_datawriter`](Self::check_create_datawriter).
    pub fn check_create_datareader(
        &self,
        topic: &str,
        partitions: &[String],
        data_tags: &[crate::qos::data_tags::DataTag],
    ) -> Result<(), SecurityError> {
        self.rules.check_subscribe(topic, partitions, data_tags)
    }

    /// What the documents say of an endpoint of `topic` (`write`: a
    /// writer) before its partitions and data tags are known
    /// (`RulesEngine::topic_scope`).
    pub(crate) fn topic_scope(
        &self,
        topic: &str,
        write: bool,
    ) -> Result<rules::TopicScope, SecurityError> {
        self.rules.topic_scope(topic, write)
    }

    /// The decision for an endpoint of `topic` in `partitions` with
    /// `data_tags` (`RulesEngine::check_endpoint`).
    pub(crate) fn check_endpoint(
        &self,
        topic: &str,
        write: bool,
        partitions: &[String],
        data_tags: &[crate::qos::data_tags::DataTag],
    ) -> Result<(), SecurityError> {
        self.rules
            .check_endpoint(topic, write, partitions, data_tags)
    }

    /// Check if participant can create reader on topic, in `partition`,
    /// without data tags
    /// ([`check_create_datareader`](Self::check_create_datareader)).
    pub fn check_create_reader(
        &self,
        topic: &str,
        partition: Option<&str>,
    ) -> Result<(), SecurityError> {
        self.rules.check_topic_subscribe(topic, partition)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_access_control_allow() {
        let governance = r#"<?xml version="1.0"?>
<governance>
  <domain_rule>
    <domains>0</domains>
    <allow_unauthenticated_participants>false</allow_unauthenticated_participants>
    <enable_join_access_control>true</enable_join_access_control>
    <discovery_protection_kind>NONE</discovery_protection_kind>
    <data_protection_kind>NONE</data_protection_kind>
  </domain_rule>
</governance>"#;

        let permissions = r#"<?xml version="1.0"?>
<permissions>
  <grant>
    <subject_name>CN=TestParticipant</subject_name>
    <validity>
      <not_before>2024-01-01T00:00:00</not_before>
      <not_after>2036-01-01T00:00:00</not_after>
    </validity>
    <allow_rule>
      <domains>0</domains>
      <publish>
        <topics>sensor/*</topics>
      </publish>
      <subscribe>
        <topics>*</topics>
      </subscribe>
    </allow_rule>
  </grant>
</permissions>"#;

        let plugin = AccessControlPlugin::from_xml(governance, permissions, 0).unwrap();

        // Should allow
        assert!(plugin
            .check_create_writer("sensor/temperature", None)
            .is_ok());
        assert!(plugin.check_create_reader("any/topic", None).is_ok());
    }

    #[test]
    fn test_access_control_deny() {
        let governance = r#"<?xml version="1.0"?>
<governance>
  <domain_rule>
    <domains>0</domains>
    <allow_unauthenticated_participants>false</allow_unauthenticated_participants>
    <enable_join_access_control>true</enable_join_access_control>
    <discovery_protection_kind>NONE</discovery_protection_kind>
    <data_protection_kind>NONE</data_protection_kind>
  </domain_rule>
</governance>"#;

        let permissions = r#"<?xml version="1.0"?>
<permissions>
  <grant>
    <subject_name>CN=TestParticipant</subject_name>
    <validity>
      <not_before>2024-01-01T00:00:00</not_before>
      <not_after>2036-01-01T00:00:00</not_after>
    </validity>
    <allow_rule>
      <domains>0</domains>
      <publish>
        <topics>sensor/*</topics>
      </publish>
    </allow_rule>
    <deny_rule>
      <domains>0</domains>
      <publish>
        <topics>admin/*</topics>
      </publish>
    </deny_rule>
  </grant>
</permissions>"#;

        let plugin = AccessControlPlugin::from_xml(governance, permissions, 0).unwrap();

        // Should deny
        assert!(plugin.check_create_writer("admin/shutdown", None).is_err());
    }
}
