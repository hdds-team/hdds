// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Rules engine for access control (allow/deny logic, fnmatch topic and
//! partition expressions, data tags)
//!
//! # Rule Evaluation Order
//!
//! 1. The governance: no topic rule for the topic refuses; access control
//!    off for it allows, whatever the endpoint's partitions and data tags.
//! 2. The grant's rules, in document order, allow and deny alike: "The rules
//!    are applied in the same order that appear in the document. If the
//!    criteria for the rule matches ... then the allow or deny decision is
//!    applied" (DDS-Security v1.1 Sec.9.4.1.3.2.3). A rule matches when one
//!    of its criteria for the action matches the topic AND the endpoint's
//!    partitions AND its data tags (Sec.9.4.1.3.2.3.1.2).
//! 3. If no rule matches, the grant's `<default>` decides; absent, DENIED.
//!
//! See [`RulesEngine::check_publish`].

use crate::qos::data_tags::DataTag;
use crate::security::access::{Criterion, GovernanceConfig, PermissionsConfig, Rule, RuleKind};
use crate::security::SecurityError;

/// What the documents say of a topic before an endpoint's partitions and
/// data tags are known ([`RulesEngine::topic_scope`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TopicScope {
    /// Every endpoint of the topic is allowed, whatever its partitions and
    /// data tags: the governance leaves the topic's access control off, or
    /// no rule names the topic and the grant's default is ALLOW.
    Any,
    /// A rule names the topic with a condition on partitions or data tags:
    /// the endpoint's own decide ([`RulesEngine::check_endpoint`]).
    PerEndpoint,
}

/// Rules engine for access control
///
/// Implements **deny-by-default** semantics per DDS Security v1.1 Sec.8.4.
/// See module documentation for detailed security model explanation.
pub struct RulesEngine {
    governance: GovernanceConfig,
    permissions: PermissionsConfig,
    /// The domain every decision this engine makes is scoped to.
    ///
    /// DDS-Security v1.1 section 9.4.1.3 scopes each allow_rule and deny_rule
    /// to the domains it names: a grant written for one domain must not be
    /// applied on whatever domain the participant happened to join. An engine cannot answer "may this peer
    /// publish here" without knowing where "here" is, so the domain is a
    /// construction parameter and not an argument - there is then no call site
    /// that can forget to pass it.
    domain_id: u32,
    /// The "legacy matching" of an allow rule's partitions condition
    /// (DDS-Security v1.1 Sec.9.4.1.3.2.3.1.4): met when ONE partition of the
    /// endpoint matches, instead of all of them. Off by default
    /// (`with_legacy_partition_matching`).
    legacy_partition_matching: bool,
}

impl RulesEngine {
    /// Create new rules engine for one domain.
    pub fn new(
        governance: GovernanceConfig,
        permissions: PermissionsConfig,
        domain_id: u32,
    ) -> Self {
        Self {
            governance,
            permissions,
            domain_id,
            legacy_partition_matching: false,
        }
    }

    /// Select the "legacy matching" of an allow rule's partitions condition
    /// (`legacy`) or the specification's own (default). DDS-Security v1.1
    /// Sec.9.4.1.3.2.3.1.4: "For legacy reasons DDS-Security implementations
    /// shall provide a way to select an alternative "legacy matching"
    /// behavior", under which the condition is met "as long as one or more
    /// of the Partitions associated with DDS Entity ... matches one of the
    /// partitions in the allowed partitions condition" - an allow rule for
    /// {A, B} then covers a writer in {A, B, C}. Deny rules, which already
    /// apply when one partition matches (Sec.9.4.1.3.2.3.2.4), read the same
    /// in both.
    #[must_use]
    pub fn with_legacy_partition_matching(mut self, legacy: bool) -> Self {
        self.legacy_partition_matching = legacy;
        self
    }

    /// `get_participant_sec_attributes` for this engine's domain
    /// (DDS-Security v1.1 Sec.9.4.1.2.5).
    ///
    /// # Errors
    ///
    /// No governance rule covers the domain (Sec.9.4.1.2.7).
    pub fn participant_attributes(
        &self,
    ) -> Result<crate::security::access::ParticipantSecurityAttributes, SecurityError> {
        self.governance.participant_attributes(self.domain_id)
    }

    /// `get_datawriter_sec_attributes` / `get_datareader_sec_attributes`
    /// for an endpoint of `topic` on this engine's domain (Sec.9.4.1.2.6).
    ///
    /// # Errors
    ///
    /// No governance rule covers the domain, or none of its topic rules
    /// matches `topic` (Sec.9.4.1.2.7).
    pub fn endpoint_attributes(
        &self,
        topic: &str,
    ) -> Result<crate::security::access::EndpointSecurityAttributes, SecurityError> {
        self.governance.endpoint_attributes(self.domain_id, topic)
    }

    /// The governance domain rule applied to this engine's domain: the first
    /// that covers it (Sec.9.4.1.2.5).
    pub(crate) fn domain_rule(&self) -> Option<&crate::security::access::DomainRule> {
        self.governance.domain_rule_for(self.domain_id)
    }

    /// Check if domain access is allowed
    pub fn check_domain_access(&self, domain_id: u32) -> Result<(), SecurityError> {
        // Check governance rules. `covers` consults the listed ids AND the
        // stored id ranges; a rule written as <id_range> used to be expanded
        // into `domains` at parse time, which is where the 17 GB allocation
        // lived.
        for rule in &self.governance.domain_rules {
            if rule.covers(domain_id) {
                return Ok(());
            }
        }

        Err(SecurityError::PermissionsDenied(format!(
            "Domain {} not allowed by governance",
            domain_id
        )))
    }

    /// Whether the governance takes `topic`'s writes (`write`) or reads out of
    /// the permissions document's hands: DDS-Security v1.1 Table 63,
    /// check_create_datawriter, "If the Governance specifies a topic or
    /// topic-expression on the DomainParticipant domain_id matching the
    /// DataWriter topic with enable_write_access_control set to FALSE, then the
    /// operation shall succeed and return TRUE" (Sec.9.4.1.2.6.5; the same for
    /// readers and enable_read_access_control, Sec.9.4.1.2.6.4, and for the
    /// remote checks, check_remote_datawriter / check_remote_datareader).
    ///
    /// # Errors
    ///
    /// No topic rule matches `topic` (Sec.9.4.1.2.7): the operation fails.
    fn governance_waives(&self, topic: &str, write: bool) -> Result<bool, SecurityError> {
        let rule = self.governance.topic_rule_for(self.domain_id, topic)?;
        Ok(if write {
            !rule.enable_write_access_control
        } else {
            !rule.enable_read_access_control
        })
    }

    /// Check if topic publish is allowed for a writer whose PARTITION is
    /// `partition` (`None` or the empty string: the default partition) and
    /// which has no data tag ([`check_publish`](Self::check_publish)).
    pub fn check_topic_publish(
        &self,
        topic: &str,
        partition: Option<&str>,
    ) -> Result<(), SecurityError> {
        self.check_endpoint(topic, true, &Self::one_partition(partition), &[])
    }

    /// Check if topic subscribe is allowed for a reader whose PARTITION is
    /// `partition` and which has no data tag
    /// ([`check_subscribe`](Self::check_subscribe)).
    pub fn check_topic_subscribe(
        &self,
        topic: &str,
        partition: Option<&str>,
    ) -> Result<(), SecurityError> {
        self.check_endpoint(topic, false, &Self::one_partition(partition), &[])
    }

    /// `check_create_datawriter` and `check_remote_datawriter`
    /// (DDS-Security v1.1 Sec.8.4.2.9.4, 8.4.2.9.10): may a writer of
    /// `topic` whose PARTITION QoS names `partitions` (empty: the default
    /// partition) and whose DataTagQosPolicy holds `data_tags` publish?
    ///
    /// The governance first: a topic no topic rule matches is refused
    /// (Sec.9.4.1.2.7), and one whose rule has `enable_write_access_control`
    /// FALSE is allowed without the permissions document (Table 63). Then
    /// the grant's rules, in document order, the first whose criterion
    /// matches deciding ([`check_endpoint`](Self::check_endpoint)).
    pub fn check_publish(
        &self,
        topic: &str,
        partitions: &[String],
        data_tags: &[DataTag],
    ) -> Result<(), SecurityError> {
        self.check_endpoint(topic, true, partitions, data_tags)
    }

    /// `check_create_datareader` and `check_remote_datareader`
    /// (Sec.8.4.2.9.5, 8.4.2.9.11), as [`check_publish`](Self::check_publish)
    /// for readers.
    pub fn check_subscribe(
        &self,
        topic: &str,
        partitions: &[String],
        data_tags: &[DataTag],
    ) -> Result<(), SecurityError> {
        self.check_endpoint(topic, false, partitions, data_tags)
    }

    fn one_partition(partition: Option<&str>) -> Vec<String> {
        partition
            .map(|name| vec![name.to_string()])
            .unwrap_or_default()
    }

    /// The decision for an endpoint of `topic` (`write`: a writer, else a
    /// reader) in `partitions` with `data_tags`:
    ///
    /// 1. The governance: a topic no topic rule matches is refused
    ///    (Sec.9.4.1.2.7); one whose rule leaves its access control off is
    ///    allowed without the document (Table 63).
    /// 2. The rules of the grant(s), in document order, allow and deny
    ///    alike, each on this engine's domain only: the first with a
    ///    `<publish>` (writer) or `<subscribe>` (reader) criterion that
    ///    matches decides (Sec.9.4.1.3.2.3). A criterion matches when its
    ///    topic, partition and data tag conditions all do
    ///    ([`criterion_matches`](Self::criterion_matches)).
    /// 3. "If all rules have been examined without a match, then the
    ///    decision specified by the "default" rule is applied ... If the
    ///    default rule is not present, the implied default decision is
    ///    DENY." With several grants (a document applied whole, without a
    ///    subject), their rules are read one grant after the other, and the
    ///    default allows only when every grant's does.
    ///
    /// # Errors
    ///
    /// `PermissionsDenied` naming the rule, or the absence of one; the
    /// governance's error when no topic rule matches.
    pub(crate) fn check_endpoint(
        &self,
        topic: &str,
        write: bool,
        partitions: &[String],
        data_tags: &[DataTag],
    ) -> Result<(), SecurityError> {
        if self.governance_waives(topic, write)? {
            return Ok(());
        }
        for (index, rule) in self.rules_in_order() {
            let direction = if write {
                &rule.publish
            } else {
                &rule.subscribe
            };
            if direction
                .iter()
                .any(|c| self.criterion_matches(rule.kind, c, topic, partitions, data_tags))
            {
                return match rule.kind {
                    RuleKind::Allow => Ok(()),
                    RuleKind::Deny => Err(SecurityError::PermissionsDenied(format!(
                        "{} on topic '{}' in partitions {:?} with data tags {:?} denied by \
                         deny_rule #{} (first matching rule, DDS-Security v1.1 \
                         Sec.9.4.1.3.2.3)",
                        Self::action(write),
                        topic,
                        partitions,
                        data_tags,
                        index + 1
                    ))),
                };
            }
            // No direction-specific (publish/subscribe) criterion of this
            // rule matched; a `<relay>` criterion of the SAME rule might
            // (Sec.9.4.1.3.2.3.1.2, 9.4.1.3.2.3.2.2) - but ONLY on the
            // subscribe side. check_remote_datawriter (Sec.8.4.2.9.10,
            // "the operation returns a Boolean value") has no relay
            // concept at all: relay_only is an output of
            // check_remote_datareader alone (Sec.8.4.2.9.11, "...and also
            // sets the relay_only output parameter"). On the publish/write
            // side a relay criterion must therefore have NO effect, exactly
            // as if it were absent: fall through to the next rule, or the
            // default.
            if write {
                continue;
            }
            // A relay DENY denies like any other deny. A relay ALLOW would
            // normally admit, but check_remote_datareader would then set
            // allow_relay_only (Sec.8.4.2.9.11), which needs reduced
            // cryptographic material (Sec.9.5.3.3.4) this release cannot
            // produce: failing closed here is safer than granting full
            // access to an endpoint the document meant to restrict to relay.
            if rule
                .relay
                .iter()
                .any(|c| self.criterion_matches(rule.kind, c, topic, partitions, data_tags))
            {
                return match rule.kind {
                    RuleKind::Allow => Err(SecurityError::PermissionsDenied(format!(
                        "{} on topic '{}' in partitions {:?} with data tags {:?} matches only \
                         a <relay> allow_rule #{} (DDS-Security v1.1 Sec.9.4.1.3.2.3.1.2): this \
                         release has no routing-service role and cannot produce the reduced \
                         relay_only cryptographic material check_remote_datareader would set \
                         (Sec.8.4.2.9.11, Sec.9.5.3.3.4) - refusing rather than admitting with \
                         full access",
                        Self::action(write),
                        topic,
                        partitions,
                        data_tags,
                        index + 1
                    ))),
                    RuleKind::Deny => Err(SecurityError::PermissionsDenied(format!(
                        "{} on topic '{}' in partitions {:?} with data tags {:?} denied by \
                         relay deny_rule #{} (first matching rule, DDS-Security v1.1 \
                         Sec.9.4.1.3.2.3)",
                        Self::action(write),
                        topic,
                        partitions,
                        data_tags,
                        index + 1
                    ))),
                };
            }
        }
        if self.default_allows() {
            return Ok(());
        }
        Err(SecurityError::PermissionsDenied(format!(
            "{} on topic '{}' in partitions {:?} with data tags {:?}: no rule matches and the \
             grant's default is DENY (DDS-Security v1.1 Sec.9.4.1.3.2.3.1.4: an allow rule \
             without <partitions> grants the default partition only, Sec.9.4.1.3.2.3.1.5: \
             without <data_tags>, endpoints without data tags only)",
            Self::action(write),
            topic,
            partitions,
            data_tags
        )))
    }

    /// What the documents say of an endpoint of `topic` before its
    /// partitions and data tags are known: allowed whatever they are
    /// (`TopicScope::Any`), refused whatever they are (`Err`), or decided by
    /// them (`TopicScope::PerEndpoint`, [`check_endpoint`](Self::check_endpoint)).
    /// The same walk as `check_endpoint`: the first rule with a criterion
    /// naming the topic settles it when that criterion matches every
    /// endpoint (a deny criterion, or a `<relay>` ALLOW criterion - fails
    /// closed the same as a deny, see below - with neither `<partitions>`
    /// nor `<data_tags>`), else the endpoint decides; no criterion naming
    /// the topic leaves the default.
    ///
    /// A `<relay>` criterion is checked like `check_endpoint` checks it, and
    /// ONLY on the subscribe side (`write == false`): check_remote_datawriter
    /// (Sec.8.4.2.9.10) has no relay concept, relay_only is an output of
    /// check_remote_datareader alone (Sec.8.4.2.9.11). There, it never
    /// grants `TopicScope::Any` by itself (Sec.9.5.3.3.4 -- this release
    /// cannot produce the reduced crypto material it implies), so a relay
    /// ALLOW unconditional on partitions and data tags is refused outright
    /// here, the same way an unconditional deny is, rather than reported as
    /// `Any`; a conditional one defers to `TopicScope::PerEndpoint`, where
    /// `check_endpoint` judges it against the endpoint's own partitions and
    /// data tags.
    ///
    /// # Errors
    ///
    /// As `check_endpoint`, for a topic refused whatever the endpoint.
    pub(crate) fn topic_scope(
        &self,
        topic: &str,
        write: bool,
    ) -> Result<TopicScope, SecurityError> {
        if self.governance_waives(topic, write)? {
            return Ok(TopicScope::Any);
        }
        for (index, rule) in self.rules_in_order() {
            let direction = if write {
                &rule.publish
            } else {
                &rule.subscribe
            };
            let (names_it, unconditional) = Self::names_topic(direction, topic);
            if names_it {
                if rule.kind == RuleKind::Deny && unconditional {
                    return Err(SecurityError::PermissionsDenied(format!(
                        "{} on topic '{}' denied by deny_rule #{} in every partition \
                         (DDS-Security v1.1 Sec.9.4.1.3.2.3.2.4)",
                        Self::action(write),
                        topic,
                        index + 1
                    )));
                }
                return Ok(TopicScope::PerEndpoint);
            }
            // No direction-specific criterion of this rule names the
            // topic. A `<relay>` criterion of the same rule might
            // (Sec.9.4.1.3.2.3.1.2, Sec.9.4.1.3.2.3.2.2) - but ONLY on the
            // subscribe side: check_remote_datawriter (Sec.8.4.2.9.10) has
            // no relay concept, so on the publish/write side a relay
            // criterion has no effect, exactly as if it were absent.
            if write {
                continue;
            }
            // Same asymmetry as the direction case above: a deny criterion
            // with no `<partitions>` applies to every partition
            // (Sec.9.4.1.3.2.3.2.4), so an unconditional relay DENY refuses
            // the topic outright here. An allow criterion with no
            // `<partitions>` grants the DEFAULT partition only
            // (Sec.9.4.1.3.2.3.1.4) -- "unconditional" does not mean
            // "every partition" -- so a relay ALLOW, conditional or not,
            // always defers to `PerEndpoint`, where `check_endpoint`
            // judges it (and fails closed on a match: this release cannot
            // produce the reduced relay_only crypto material
            // check_remote_datareader would set, Sec.8.4.2.9.11,
            // Sec.9.5.3.3.4) against the endpoint's own, possibly
            // non-default, partition.
            let (relay_names_it, relay_unconditional) = Self::names_topic(&rule.relay, topic);
            if relay_names_it {
                if rule.kind == RuleKind::Deny && relay_unconditional {
                    return Err(SecurityError::PermissionsDenied(format!(
                        "{} on topic '{}' denied by relay deny_rule #{} in every partition \
                         (DDS-Security v1.1 Sec.9.4.1.3.2.3.2.4)",
                        Self::action(write),
                        topic,
                        index + 1
                    )));
                }
                return Ok(TopicScope::PerEndpoint);
            }
        }
        if self.default_allows() {
            return Ok(TopicScope::Any);
        }
        Err(SecurityError::PermissionsDenied(format!(
            "Topic '{}' not allowed for {} (no matching allow_rule)",
            topic,
            Self::action(write)
        )))
    }

    fn action(write: bool) -> &'static str {
        if write {
            "publish"
        } else {
            "subscribe"
        }
    }

    /// Every rule covering this engine's domain, in document order, across
    /// every grant, with its position among its own grant's rules.
    /// `check_endpoint` and `topic_scope` need `publish`, `subscribe` AND
    /// `relay` of the SAME rule together (a rule's criteria are evaluated
    /// against each other in document order, DDS-Security v1.1
    /// Sec.9.4.1.3.2.3), which a flattened per-criterion iterator (as this
    /// used to be) cannot give them without losing which `<relay>`
    /// criterion belongs next to which `<publish>`/`<subscribe>` one.
    fn rules_in_order(&self) -> impl Iterator<Item = (usize, &Rule)> {
        self.permissions.grants.iter().flat_map(move |grant| {
            grant
                .rules
                .iter()
                .enumerate()
                .filter(move |(_, rule)| rule.covers(self.domain_id))
        })
    }

    /// Whether any criterion in `criteria` (a rule's `publish`, `subscribe`
    /// or `relay` list) names `topic` at all, and whether at least one that
    /// does is UNCONDITIONAL (no `<partitions>`, no `<data_tags>`) --
    /// `check_endpoint`'s partition/data-tag match still decides whether it
    /// actually applies to a given endpoint; this is `topic_scope`'s
    /// topic-only pre-check.
    fn names_topic(criteria: &[Criterion], topic: &str) -> (bool, bool) {
        let mut names_it = false;
        let mut unconditional = false;
        for criterion in criteria {
            if criterion
                .topics
                .iter()
                .any(|pattern| Self::wildcard_match(pattern, topic))
            {
                names_it = true;
                if criterion.partitions.is_none() && criterion.data_tags.is_none() {
                    unconditional = true;
                }
            }
        }
        (names_it, unconditional)
    }

    /// Whether the grants' default allows what no rule matched: every grant
    /// says ALLOW (one grant in a document applied to its subject).
    fn default_allows(&self) -> bool {
        !self.permissions.grants.is_empty()
            && self
                .permissions
                .grants
                .iter()
                .all(|grant| grant.default_allow)
    }

    /// Whether `criterion` of a rule of `kind` matches an endpoint of
    /// `topic` in `partitions` (none: the default, empty-string, partition)
    /// with `data_tags` - its three conditions, each read as the
    /// specification reads it for that kind of rule:
    ///
    /// - topics, either kind: one expression matches the topic
    ///   (Sec.9.4.1.3.2.3.1.3, 9.4.1.3.2.3.2.3);
    /// - partitions, allow: "the set of the Partitions associated with the
    ///   DDS entity ... must be contained in the set of partitions defined by
    ///   the allowed partitions condition", each partition matched by one
    ///   expression; absent, "the default "empty string" partition is
    ///   assumed" (Sec.9.4.1.3.2.3.1.4). Under the "legacy matching" the
    ///   same section asks implementations to offer as an option
    ///   (`with_legacy_partition_matching`), ONE partition of the endpoint
    ///   matched is enough;
    /// - partitions, deny: "one of more of the partition names associated
    ///   with the DDS Entity ... must match one the partitions or partition
    ///   expressions"; absent, "*" (Sec.9.4.1.3.2.3.2.4);
    /// - data tags, allow: the endpoint's tags "must be contained in the set
    ///   of data tags defined by the allowed data tags condition"; absent,
    ///   "the default empty set is assumed" (Sec.9.4.1.3.2.3.1.5);
    /// - data tags, deny: the endpoint has "a data tag name and value pair
    ///   ... that matches one the data tags"; absent, "the set of all
    ///   possible tags" (Sec.9.4.1.3.2.3.2.5).
    fn criterion_matches(
        &self,
        kind: RuleKind,
        criterion: &Criterion,
        topic: &str,
        partitions: &[String],
        data_tags: &[DataTag],
    ) -> bool {
        if !criterion
            .topics
            .iter()
            .any(|pattern| Self::wildcard_match(pattern, topic))
        {
            return false;
        }
        // DDS 1.4 Sec.2.2.3.13: an endpoint naming no partition is in the
        // default partition, the empty string.
        let default_partition = [String::new()];
        let endpoint_partitions = if partitions.is_empty() {
            &default_partition[..]
        } else {
            partitions
        };
        let matched = |partition: &String, expressions: &[String]| {
            expressions
                .iter()
                .any(|expression| Self::wildcard_match(expression, partition))
        };
        match kind {
            RuleKind::Allow => {
                let partitions_met = match (&criterion.partitions, self.legacy_partition_matching) {
                    (None, false) => endpoint_partitions.iter().all(String::is_empty),
                    (None, true) => endpoint_partitions.iter().any(String::is_empty),
                    (Some(expressions), false) => endpoint_partitions
                        .iter()
                        .all(|partition| matched(partition, expressions)),
                    (Some(expressions), true) => endpoint_partitions
                        .iter()
                        .any(|partition| matched(partition, expressions)),
                };
                let tags_met = match &criterion.data_tags {
                    None => data_tags.is_empty(),
                    Some(allowed) => data_tags.iter().all(|tag| allowed.contains(tag)),
                };
                partitions_met && tags_met
            }
            RuleKind::Deny => {
                let partitions_met = criterion.partitions.as_ref().is_none_or(|expressions| {
                    endpoint_partitions
                        .iter()
                        .any(|partition| matched(partition, expressions))
                });
                let tags_met = criterion
                    .data_tags
                    .as_ref()
                    .is_none_or(|denied| data_tags.iter().any(|tag| denied.contains(tag)));
                partitions_met && tags_met
            }
        }
    }

    /// Whether a permissions topic expression matches `topic`.
    ///
    /// DDS-Security v1.1 Sec.9.4.1.3.2.3.1.3: "The Topic name expression
    /// syntax and matching shall use the syntax and rules of the POSIX
    /// fnmatch() function as specified in POSIX 1003.2-1992, Section B.6."
    /// The same words as the governance topic expressions (Sec.9.4.1.2.6.1),
    /// so the same matcher: `fnmatch(pattern, topic, 0)`. `*` matches any
    /// string, `/` included; `?` one character; brackets a set.
    ///
    /// This is full fnmatch matching, not a restricted matcher knowing only
    /// `*`, `prefix/*`, `*/suffix` and `*middle*`: a deny rule on `Secret*`
    /// must deny `SecretPlans` even after `allow *`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use hdds::security::access::rules::RulesEngine;
    /// assert!(RulesEngine::wildcard_match("sensor/*", "sensor/temperature"));
    /// assert!(RulesEngine::wildcard_match("*", "any/topic"));
    /// assert!(RulesEngine::wildcard_match("Secret*", "SecretPlans"));
    /// assert!(!RulesEngine::wildcard_match("sensor/*", "actuator/motor"));
    /// // The separator is a character of the pattern like any other.
    /// assert!(!RulesEngine::wildcard_match("sensor/*", "sensorAdmin"));
    /// assert!(!RulesEngine::wildcard_match("*/temperature", "footemperature"));
    /// ```
    #[must_use]
    pub fn wildcard_match(pattern: &str, topic: &str) -> bool {
        super::fnmatch::fnmatch(pattern, topic)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A grant is a boundary, and the separator is what draws it.
    ///
    /// `prefix/*` must keep the `/` in the pattern: matching only
    /// `topic.starts_with(prefix)` would let a permissions grant on
    /// `sensor/*` silently also cover `sensorAdmin` - a different topic that
    /// an attacker chooses the name of. `*/suffix` has the mirror hazard.
    /// These cases are asserted before anything else in this module.
    #[test]
    fn a_wildcard_grant_stops_at_the_separator() {
        // What the grant is meant to cover.
        assert!(RulesEngine::wildcard_match(
            "sensor/*",
            "sensor/temperature"
        ));
        assert!(RulesEngine::wildcard_match("sensor/*", "sensor/a/b/c"));
        assert!(RulesEngine::wildcard_match(
            "*/temperature",
            "sensor/temperature"
        ));
        assert!(RulesEngine::wildcard_match(
            "*/temperature",
            "a/b/temperature"
        ));

        // What it must NOT cover: a sibling whose name merely shares the letters.
        assert!(
            !RulesEngine::wildcard_match("sensor/*", "sensorAdmin"),
            "a grant on sensor/* must not reach sensorAdmin"
        );
        assert!(
            !RulesEngine::wildcard_match("sensor/*", "sensors/temperature"),
            "a grant on sensor/* must not reach a different branch"
        );
        assert!(
            !RulesEngine::wildcard_match("*/temperature", "footemperature"),
            "a grant on */temperature must not reach footemperature"
        );

        // The prefix alone is not below itself.
        assert!(!RulesEngine::wildcard_match("sensor/*", "sensor"));

        // Unchanged behaviour, asserted so the fix is not over-broad.
        assert!(RulesEngine::wildcard_match("*", "any/topic"));
        assert!(RulesEngine::wildcard_match(
            "sensor/temperature",
            "sensor/temperature"
        ));
        assert!(!RulesEngine::wildcard_match("sensor/*", "actuator/motor"));
        assert!(RulesEngine::wildcard_match("*temp*", "sensor/temperature"));
    }

    /// `?` is fnmatch's single-character wildcard (Sec.9.4.1.3.2.3.1.3).
    #[test]
    fn a_question_mark_matches_one_character() {
        assert!(RulesEngine::wildcard_match("sensor/temp?", "sensor/tempX"));
        assert!(!RulesEngine::wildcard_match("sensor/temp?", "sensor/temp"));
    }

    use crate::security::access::{
        BasicProtectionKind, Criterion, DomainRule, Grant, ProtectionKind, Rule, RuleKind,
        TopicRule, Validity,
    };

    /// Table 63: a topic rule with `enable_write_access_control` /
    /// `enable_read_access_control` FALSE allows writers / readers without
    /// consulting the permissions document at all - a grant is not needed and
    /// a deny rule does not apply - and a topic no rule matches is refused
    /// (Sec.9.4.1.2.7).
    #[test]
    #[cfg(feature = "qos-loaders")]
    fn the_governance_waives_access_control_where_its_topic_rule_says() {
        let rule = |expression: &str, read: bool, write: bool| {
            format!(
                "<topic_rule><topic_expression>{}</topic_expression>\
                 <enable_discovery_protection>false</enable_discovery_protection>\
                 <enable_liveliness_protection>false</enable_liveliness_protection>\
                 <enable_read_access_control>{}</enable_read_access_control>\
                 <enable_write_access_control>{}</enable_write_access_control>\
                 <metadata_protection_kind>NONE</metadata_protection_kind>\
                 <data_protection_kind>NONE</data_protection_kind></topic_rule>",
                expression, read, write
            )
        };
        let governance = GovernanceConfig::parse(&format!(
            "<dds><domain_access_rules><domain_rule><domains><id>0</id></domains>\
             <allow_unauthenticated_participants>false</allow_unauthenticated_participants>\
             <enable_join_access_control>true</enable_join_access_control>\
             <discovery_protection_kind>NONE</discovery_protection_kind>\
             <liveliness_protection_kind>NONE</liveliness_protection_kind>\
             <rtps_protection_kind>NONE</rtps_protection_kind>\
             <topic_access_rules>{}{}{}{}{}</topic_access_rules>\
             </domain_rule></domain_access_rules></dds>",
            rule("admin/open", false, false),
            rule("public/*", false, false),
            rule("readable/*", false, true),
            rule("sensor/*", true, true),
            rule("admin/*", true, true),
        ))
        .expect("governance");
        let engine = RulesEngine::new(governance, create_test_engine().permissions, 0);

        // Not granted: allowed by the governance alone.
        assert!(engine.check_topic_publish("public/news", None).is_ok());
        assert!(engine.check_topic_subscribe("public/news", None).is_ok());
        // Denied by a deny rule, and the deny rule is not consulted.
        assert!(engine.check_topic_publish("admin/open", None).is_ok());
        // Reads waived, writes not.
        assert!(engine.check_topic_subscribe("readable/x", None).is_ok());
        assert!(engine.check_topic_publish("readable/x", None).is_err());
        // Protected: the permissions document decides, as before.
        assert!(engine
            .check_topic_publish("sensor/temperature", None)
            .is_ok());
        assert!(engine.check_topic_publish("admin/secret", None).is_err());
        // No rule.
        let err = engine
            .check_topic_publish("elsewhere", None)
            .expect_err("no topic rule matches");
        assert!(err.to_string().contains("topic_rule"), "{}", err);
        assert!(engine.check_topic_subscribe("elsewhere", None).is_err());
    }

    fn create_test_engine() -> RulesEngine {
        let governance = GovernanceConfig {
            domain_rules: vec![DomainRule {
                domains: vec![0, 1],
                domain_ranges: Vec::new(),
                allow_unauthenticated: false,
                enable_join_access_control: true,
                discovery_protection_kind: ProtectionKind::None,
                liveliness_protection_kind: ProtectionKind::None,
                rtps_protection_kind: ProtectionKind::None,
                topic_rules: vec![TopicRule::shorthand(
                    ProtectionKind::None,
                    BasicProtectionKind::None,
                )],
            }],
        };

        let permissions = PermissionsConfig {
            grants: vec![Grant {
                subject_name: "CN=Test".to_string(),
                validity: Validity {
                    not_before: "2024-01-01T00:00:00".to_string(),
                    not_after: "2030-01-01T00:00:00".to_string(),
                },
                rules: vec![
                    Rule {
                        kind: RuleKind::Allow,
                        domains: vec![0],
                        domain_ranges: Vec::new(),
                        publish: vec![Criterion {
                            topics: vec!["sensor/*".to_string(), "data/raw".to_string()],
                            ..Criterion::default()
                        }],
                        subscribe: vec![Criterion {
                            topics: vec!["*".to_string()],
                            ..Criterion::default()
                        }],
                        relay: Vec::new(),
                    },
                    Rule {
                        kind: RuleKind::Deny,
                        domains: vec![0],
                        domain_ranges: Vec::new(),
                        publish: vec![Criterion {
                            topics: vec!["admin/*".to_string()],
                            ..Criterion::default()
                        }],
                        subscribe: Vec::new(),
                        relay: Vec::new(),
                    },
                ],
                default_allow: false,
            }],
        };

        // The fixture's grants name domain 0, so the engine judges for 0.
        RulesEngine::new(governance, permissions, 0)
    }

    #[test]
    fn test_domain_access_allowed() {
        let engine = create_test_engine();
        assert!(engine.check_domain_access(0).is_ok());
        assert!(engine.check_domain_access(1).is_ok());
    }

    #[test]
    fn test_domain_access_denied() {
        let engine = create_test_engine();
        assert!(engine.check_domain_access(99).is_err());
    }

    #[test]
    fn test_publish_allowed_wildcard() {
        let engine = create_test_engine();
        assert!(engine
            .check_topic_publish("sensor/temperature", None)
            .is_ok());
        assert!(engine.check_topic_publish("sensor/pressure", None).is_ok());
    }

    #[test]
    fn test_publish_allowed_exact() {
        let engine = create_test_engine();
        assert!(engine.check_topic_publish("data/raw", None).is_ok());
    }

    #[test]
    fn test_publish_denied_by_deny_rule() {
        let engine = create_test_engine();
        assert!(engine.check_topic_publish("admin/shutdown", None).is_err());
        assert!(engine.check_topic_publish("admin/config", None).is_err());
    }

    #[test]
    fn test_publish_denied_not_in_allow() {
        let engine = create_test_engine();
        assert!(engine.check_topic_publish("other/topic", None).is_err());
    }

    #[test]
    fn test_subscribe_allowed_wildcard() {
        let engine = create_test_engine();
        assert!(engine.check_topic_subscribe("any/topic", None).is_ok());
        assert!(engine
            .check_topic_subscribe("sensor/temperature", None)
            .is_ok());
    }

    #[test]
    fn test_wildcard_match_star() {
        assert!(RulesEngine::wildcard_match("*", "any/topic"));
        assert!(RulesEngine::wildcard_match("*", "sensor/temperature"));
    }

    #[test]
    fn test_wildcard_match_exact() {
        assert!(RulesEngine::wildcard_match(
            "sensor/temperature",
            "sensor/temperature"
        ));
        assert!(!RulesEngine::wildcard_match(
            "sensor/temperature",
            "sensor/pressure"
        ));
    }

    #[test]
    fn test_wildcard_match_prefix() {
        assert!(RulesEngine::wildcard_match(
            "sensor/*",
            "sensor/temperature"
        ));
        assert!(RulesEngine::wildcard_match("sensor/*", "sensor/pressure"));
        assert!(!RulesEngine::wildcard_match("sensor/*", "actuator/motor"));
    }

    #[test]
    fn test_wildcard_match_suffix() {
        assert!(RulesEngine::wildcard_match(
            "*/temperature",
            "sensor/temperature"
        ));
        assert!(!RulesEngine::wildcard_match(
            "*/temperature",
            "sensor/pressure"
        ));
    }

    #[test]
    fn test_wildcard_match_contains() {
        assert!(RulesEngine::wildcard_match("*temp*", "sensor/temperature"));
        assert!(RulesEngine::wildcard_match("*temp*", "temperature_data"));
        assert!(!RulesEngine::wildcard_match("*temp*", "sensor/pressure"));
    }

    /// The fixture's allow rule does not name `admin/*`, its deny rule
    /// does: refused.
    #[test]
    fn test_publish_denied_by_a_later_deny_rule() {
        let engine = create_test_engine();
        assert!(engine.check_topic_publish("admin/test", None).is_err());
    }

    fn engine_from_xml(perm: &str) -> RulesEngine {
        let governance = create_test_engine().governance;
        let permissions = PermissionsConfig::parse(perm).expect("permissions parse");
        RulesEngine::new(governance, permissions, 0)
    }

    /// DDS-Security v1.1 Sec.9.4.1.3.2.3.1.3: permissions topic expressions
    /// are POSIX fnmatch. A deny rule `Secret*` written before `allow *`
    /// denies `SecretPlans`. Written after `allow *`, it is never reached:
    /// the first rule that matches decides (Sec.9.4.1.3.2.3).
    #[test]
    #[cfg(feature = "qos-loaders")]
    fn a_deny_rule_is_matched_as_fnmatch() {
        let allow_all = "<allow_rule><domains><id>0</id></domains><publish><topics>\
                         <topic>*</topic></topics></publish></allow_rule>";
        let deny_secret = "<deny_rule><domains><id>0</id></domains><publish><topics>\
                           <topic>Secret*</topic></topics></publish></deny_rule>";
        let deny_first = engine_from_xml(&grant_of(&format!(
            "{}{}<default>DENY</default>",
            deny_secret, allow_all
        )));
        assert!(
            deny_first.check_topic_publish("SecretPlans", None).is_err(),
            "deny Secret* did not deny SecretPlans: allow * granted it"
        );
        assert!(deny_first.check_topic_publish("OpenPlans", None).is_ok());
        let allow_first = engine_from_xml(&grant_of(&format!(
            "{}{}<default>DENY</default>",
            allow_all, deny_secret
        )));
        assert!(
            allow_first.check_topic_publish("SecretPlans", None).is_ok(),
            "allow * comes first in the document"
        );
    }

    /// A grant around `body`, the rules and the default of one grant.
    #[cfg(feature = "qos-loaders")]
    fn grant_of(body: &str) -> String {
        format!(
            "<dds><permissions><grant name=\"g\"><subject_name>CN=Test</subject_name>\
             <validity><not_before>2020-01-01T00:00:00</not_before>\
             <not_after>2036-01-01T00:00:00</not_after></validity>{}</grant></permissions>\
             </dds>",
            body
        )
    }

    /// The endpoint partitions `names`, as a PARTITION QoS holds them.
    fn parts(names: &[&str]) -> Vec<String> {
        names.iter().map(|name| (*name).to_string()).collect()
    }

    /// The data tags `pairs`, as a DataTagQosPolicy holds them.
    fn tags(pairs: &[(&str, &str)]) -> Vec<DataTag> {
        pairs
            .iter()
            .map(|(name, value)| DataTag {
                name: (*name).to_string(),
                value: (*value).to_string(),
            })
            .collect()
    }

    /// DDS-Security v1.1 Sec.9.4.1.3.2.3: "The rules are applied in the same
    /// order that appear in the document. If the criteria for the rule
    /// matches ... then the allow or deny decision is applied." An allow
    /// rule written before a deny rule that also matches allows; written
    /// after it, it does not. Deny rules are not consulted
    /// first: the document order decides.
    #[test]
    #[cfg(feature = "qos-loaders")]
    fn rules_apply_in_document_order_first_match_wins() {
        let allow_t = "<allow_rule><domains><id>0</id></domains><publish><topics>\
                       <topic>T</topic></topics></publish></allow_rule>";
        let deny_all = "<deny_rule><domains><id>0</id></domains><publish><topics>\
                        <topic>*</topic></topics></publish></deny_rule>";
        let allow_first = engine_from_xml(&grant_of(&format!(
            "{}{}<default>DENY</default>",
            allow_t, deny_all
        )));
        assert!(allow_first.check_topic_publish("T", None).is_ok());
        assert!(allow_first.check_topic_publish("U", None).is_err());
        let deny_first = engine_from_xml(&grant_of(&format!(
            "{}{}<default>ALLOW</default>",
            deny_all, allow_t
        )));
        assert!(deny_first.check_topic_publish("T", None).is_err());
        // A rule of another domain is skipped, not applied.
        let other_domain = engine_from_xml(&grant_of(
            "<deny_rule><domains><id>7</id></domains><publish><topics><topic>*</topic>\
             </topics></publish></deny_rule><default>ALLOW</default>",
        ));
        assert!(other_domain.check_topic_publish("T", None).is_ok());
    }

    /// Sec.9.4.1.3.2.3.1.4: an allow rule's partition condition is met when
    /// every partition of the endpoint is in the set its expressions
    /// (fnmatch) define: "OK to publish in partition A, in B, or in {A, B}
    /// but not in {A, B, C}". Absent, only the empty-string partition.
    /// Sec.9.4.1.3.2.3.2.4: a deny rule's is met when one partition of the
    /// endpoint is: "OK to publish in C, but not in {A}, {A, B}, or {A, B,
    /// C}"; absent, every partition.
    #[test]
    #[cfg(feature = "qos-loaders")]
    fn partition_conditions_read_as_the_specification_reads_them() {
        let allow = engine_from_xml(&grant_of(
            "<allow_rule><domains><id>0</id></domains><publish><topics><topic>T</topic>\
             </topics><partitions><partition>A</partition><partition>B</partition>\
             </partitions></publish><publish><topics><topic>W</topic></topics><partitions>\
             <partition>*</partition></partitions></publish></allow_rule>\
             <default>DENY</default>",
        ));
        for (endpoint, allowed) in [
            (&["A"][..], true),
            (&["B"][..], true),
            (&["A", "B"][..], true),
            (&["A", "B", "C"][..], false),
            (&["C"][..], false),
            (&[][..], false),
            (&[""][..], false),
        ] {
            assert_eq!(
                allow.check_publish("T", &parts(endpoint), &[]).is_ok(),
                allowed,
                "allow {{A, B}}, endpoint in {:?}",
                endpoint
            );
        }
        // "*" matches every name, the empty one included.
        assert!(allow.check_publish("W", &parts(&[]), &[]).is_ok());
        assert!(allow.check_publish("W", &parts(&["x", "y"]), &[]).is_ok());

        let deny = engine_from_xml(&grant_of(
            "<deny_rule><domains><id>0</id></domains><publish><topics><topic>T</topic>\
             </topics><partitions><partition>A</partition><partition>B</partition>\
             </partitions></publish></deny_rule><default>ALLOW</default>",
        ));
        for (endpoint, allowed) in [
            (&["C"][..], true),
            (&[][..], true),
            (&["A"][..], false),
            (&["A", "B"][..], false),
            (&["A", "B", "C"][..], false),
            (&["C", "B"][..], false),
        ] {
            assert_eq!(
                deny.check_publish("T", &parts(endpoint), &[]).is_ok(),
                allowed,
                "deny {{A, B}}, endpoint in {:?}",
                endpoint
            );
        }
    }

    /// Sec.9.4.1.3.2.3.1.4, "legacy matching" (the option the section asks
    /// for): an allow rule's partition condition is met when ONE partition
    /// of the endpoint matches: "OK to publish in A, in B, or in {A, B} and
    /// also in {A, B, C}". Absent, the default partition is one of them.
    /// Deny rules read the same in both modes. And the default is the
    /// specification's matching.
    #[test]
    #[cfg(feature = "qos-loaders")]
    fn legacy_partition_matching_is_an_option_and_reads_one_partition() {
        let allow = grant_of(
            "<allow_rule><domains><id>0</id></domains><publish><topics><topic>T</topic>\
             </topics><partitions><partition>A</partition><partition>B</partition>\
             </partitions></publish><publish><topics><topic>U</topic></topics></publish>\
             </allow_rule><default>DENY</default>",
        );
        let deny = grant_of(
            "<deny_rule><domains><id>0</id></domains><publish><topics><topic>V</topic>\
             </topics><partitions><partition>A</partition></partitions></publish>\
             </deny_rule><default>ALLOW</default>",
        );
        for (document, topic, endpoint, by_spec, by_legacy) in [
            (&allow, "T", &["A"][..], true, true),
            (&allow, "T", &["A", "B"][..], true, true),
            (&allow, "T", &["A", "B", "C"][..], false, true),
            (&allow, "T", &["C", "B"][..], false, true),
            (&allow, "T", &["C"][..], false, false),
            (&allow, "T", &[][..], false, false),
            (&allow, "U", &[][..], true, true),
            (&allow, "U", &["", "X"][..], false, true),
            (&allow, "U", &["X"][..], false, false),
            // Deny: one partition matching denies, in both modes.
            (&deny, "V", &["C"][..], true, true),
            (&deny, "V", &["C", "A"][..], false, false),
        ] {
            let strict = engine_from_xml(document);
            let off = engine_from_xml(document).with_legacy_partition_matching(false);
            let legacy = engine_from_xml(document).with_legacy_partition_matching(true);
            let partitions = parts(endpoint);
            assert_eq!(
                strict.check_publish(topic, &partitions, &[]).is_ok(),
                by_spec,
                "strict, {topic} in {endpoint:?}"
            );
            assert_eq!(
                off.check_publish(topic, &partitions, &[]).is_ok(),
                by_spec,
                "explicitly off, {topic} in {endpoint:?}"
            );
            assert_eq!(
                legacy.check_publish(topic, &partitions, &[]).is_ok(),
                by_legacy,
                "legacy, {topic} in {endpoint:?}"
            );
        }
    }

    /// Sec.9.4.1.3.2.3.1.5: an allow rule's data tag condition is met when
    /// the endpoint's tags are a subset of the rule's; absent, only an
    /// endpoint without tags. Sec.9.4.1.3.2.3.2.5: a deny rule's is met when
    /// the endpoint has one of the rule's tags; absent, whatever its tags.
    #[test]
    #[cfg(feature = "qos-loaders")]
    fn data_tag_conditions_read_as_the_specification_reads_them() {
        let allow = engine_from_xml(&grant_of(
            "<allow_rule><domains><id>0</id></domains><publish><topics><topic>T</topic>\
             </topics><data_tags><tag><name>aTagName1</name><value>aTagValue1</value></tag>\
             </data_tags></publish><publish><topics><topic>U</topic></topics></publish>\
             </allow_rule><default>DENY</default>",
        ));
        let t1 = ("aTagName1", "aTagValue1");
        assert!(allow.check_publish("T", &[], &[]).is_ok(), "no tag");
        assert!(allow.check_publish("T", &[], &tags(&[t1])).is_ok());
        assert!(allow
            .check_publish("T", &[], &tags(&[("aTagName1", "aTagValue2")]))
            .is_err());
        assert!(allow
            .check_publish("T", &[], &tags(&[t1, ("aTagName2", "aTagValue2")]))
            .is_err());
        assert!(allow.check_publish("U", &[], &[]).is_ok());
        assert!(
            allow.check_publish("U", &[], &tags(&[t1])).is_err(),
            "no <data_tags>: endpoints without tags only"
        );

        let deny = engine_from_xml(&grant_of(
            "<deny_rule><domains><id>0</id></domains><publish><topics><topic>T</topic>\
             </topics><data_tags><tag><name>aTagName1</name><value>aTagValue1</value></tag>\
             </data_tags></publish><publish><topics><topic>U</topic></topics></publish>\
             </deny_rule><default>ALLOW</default>",
        ));
        assert!(deny.check_publish("T", &[], &[]).is_ok());
        assert!(deny
            .check_publish("T", &[], &tags(&[("aTagName2", "x")]))
            .is_ok());
        assert!(deny
            .check_publish("T", &[], &tags(&[("aTagName1", "aTagValue2")]))
            .is_ok());
        assert!(deny
            .check_publish("T", &[], &tags(&[t1, ("aTagName2", "aTagValue2")]))
            .is_err());
        assert!(deny.check_publish("U", &[], &tags(&[t1])).is_err());
        assert!(deny.check_publish("U", &[], &[]).is_err());
    }

    /// Each criterion is evaluated on its own (Sec.9.4.1.3.2.3.1.2): the
    /// partitions of one never condition the topics of another, as a
    /// flattened cross-product of a rule's topics and partitions would.
    #[test]
    #[cfg(feature = "qos-loaders")]
    fn each_criterion_is_evaluated_on_its_own() {
        let engine = engine_from_xml(&grant_of(
            "<allow_rule><domains><id>0</id></domains>\
             <publish><topics><topic>T1</topic></topics><partitions><partition>A</partition>\
             </partitions></publish>\
             <publish><topics><topic>T2</topic></topics><partitions><partition>B</partition>\
             </partitions></publish></allow_rule><default>DENY</default>",
        ));
        assert!(engine.check_publish("T1", &parts(&["A"]), &[]).is_ok());
        assert!(engine.check_publish("T2", &parts(&["B"]), &[]).is_ok());
        assert!(engine.check_publish("T1", &parts(&["B"]), &[]).is_err());
        assert!(engine.check_publish("T2", &parts(&["A"]), &[]).is_err());
        assert!(
            engine.check_subscribe("T1", &parts(&["A"]), &[]).is_err(),
            "a publish criterion grants no subscription"
        );
    }

    /// `topic_scope` settles a topic before the endpoint is known only when
    /// the endpoint cannot change the answer, and agrees with
    /// `check_endpoint` when it does.
    #[test]
    #[cfg(feature = "qos-loaders")]
    fn the_topic_scope_agrees_with_the_endpoint_decision() {
        let engine = engine_from_xml(&grant_of(
            "<deny_rule><domains><id>0</id></domains><publish><topics><topic>D</topic>\
             </topics></publish><publish><topics><topic>P</topic></topics><partitions>\
             <partition>X</partition></partitions></publish></deny_rule>\
             <allow_rule><domains><id>0</id></domains><publish><topics><topic>A</topic>\
             </topics></publish></allow_rule><default>ALLOW</default>",
        ));
        assert!(engine.topic_scope("D", true).is_err(), "denied whatever");
        assert_eq!(
            engine.topic_scope("P", true).expect("scope"),
            TopicScope::PerEndpoint
        );
        assert_eq!(
            engine.topic_scope("A", true).expect("scope"),
            TopicScope::PerEndpoint
        );
        assert_eq!(
            engine.topic_scope("Other", true).expect("scope"),
            TopicScope::Any,
            "no rule names it, default ALLOW"
        );
        // P in X denied; P elsewhere falls to the default ALLOW. A in B
        // is not met by the allow rule and falls to the default too.
        assert!(engine.check_publish("P", &parts(&["X"]), &[]).is_err());
        assert!(engine.check_publish("P", &parts(&["Y"]), &[]).is_ok());
        assert!(engine.check_publish("A", &parts(&["B"]), &[]).is_ok());
    }

    /// The allow rule example of Sec.9.4.1.3.2.3.1.6 (the same text as
    /// 9.4.1.3.2.3.2.6), copied from the specification, behaves as the
    /// specification describes its three criteria.
    #[test]
    #[cfg(feature = "qos-loaders")]
    fn the_specification_allow_rule_example() {
        let engine = engine_from_xml(&grant_of(&format!(
            "{}<default>DENY</default>",
            SPEC_ALLOW_RULE_EXAMPLE
        )));
        let t1 = ("aTagName1", "aTagValue1");
        let t2 = ("aTagName2", "aTagValue2");
        // <publish> Cir* with {t1}.
        assert!(engine.check_publish("Circle", &[], &[]).is_ok());
        assert!(engine.check_publish("Circle", &[], &tags(&[t1])).is_ok());
        assert!(engine.check_publish("Circle", &[], &tags(&[t2])).is_err());
        assert!(engine.check_publish("Circle", &parts(&["P"]), &[]).is_err());
        assert!(engine.check_publish("Square", &[], &[]).is_err());
        // <subscribe> Sq* with {t1, t2}.
        assert!(engine
            .check_subscribe("Square", &[], &tags(&[t1, t2]))
            .is_ok());
        assert!(engine.check_subscribe("Square", &[], &tags(&[t2])).is_ok());
        assert!(engine
            .check_subscribe("Square", &[], &tags(&[("aTagName3", "v")]))
            .is_err());
        // <subscribe> Triangle in P*.
        assert!(engine
            .check_subscribe("Triangle", &parts(&["P1"]), &[])
            .is_ok());
        assert!(engine
            .check_subscribe("Triangle", &parts(&["P1", "P2"]), &[])
            .is_ok());
        assert!(engine
            .check_subscribe("Triangle", &parts(&["P1", "Q"]), &[])
            .is_err());
        assert!(
            engine.check_subscribe("Triangle", &[], &[]).is_err(),
            "P* does not name the default partition"
        );
        assert!(engine
            .check_publish("Triangle", &parts(&["P1"]), &[])
            .is_err());
    }

    /// The deny rule example of Sec.9.4.1.3.2.3.2.7, copied from the
    /// specification, under a default of ALLOW.
    #[test]
    #[cfg(feature = "qos-loaders")]
    fn the_specification_deny_rule_example() {
        let engine = engine_from_xml(&grant_of(&format!(
            "{}<default>ALLOW</default>",
            SPEC_DENY_RULE_EXAMPLE
        )));
        let t1 = ("aTagName1", "aTagValue1");
        let t2 = ("aTagName2", "aTagValue2");
        assert!(engine.check_publish("Circle1", &[], &[]).is_err());
        assert!(engine
            .check_publish("Circle1", &parts(&["Z"]), &[])
            .is_err());
        assert!(engine.check_publish("Circle2", &[], &[]).is_ok());
        assert!(engine
            .check_publish("Square", &parts(&["A_partition"]), &[])
            .is_err());
        assert!(engine.check_publish("Square", &parts(&["B"]), &[]).is_ok());
        assert!(engine.check_publish("Square", &[], &[]).is_ok());
        assert!(engine.check_subscribe("Square1", &[], &[]).is_err());
        assert!(engine.check_subscribe("Square", &[], &[]).is_ok());
        // Tr* in P1* with a tag of {t1, t2}: all three conditions.
        assert!(engine
            .check_subscribe("Triangle", &parts(&["P1a"]), &tags(&[t1]))
            .is_err());
        assert!(engine
            .check_subscribe("Triangle", &parts(&["P1a"]), &tags(&[t2]))
            .is_err());
        assert!(engine
            .check_subscribe("Triangle", &parts(&["P1a"]), &[])
            .is_ok());
        assert!(engine
            .check_subscribe("Triangle", &parts(&["Q"]), &tags(&[t1]))
            .is_ok());
    }

    /// The example permissions document of Sec.9.4.1.4, copied verbatim
    /// from the specification (grant, subject, validity and its `<relay>`
    /// action all included, `SPEC_PERMISSIONS_EXAMPLE`), loads, and its
    /// rules apply in their order: the deny rule written before the second
    /// allow rule wins where both match. The `<relay>` action's own
    /// partition (`aPartitionName`) is never probed here -- it is covered
    /// on its own by the `relay_*` tests below.
    #[test]
    #[cfg(feature = "qos-loaders")]
    fn the_specification_example_permissions_document() {
        let engine = engine_from_xml(SPEC_PERMISSIONS_EXAMPLE);
        let t1 = ("aTagName1", "aTagValue1");
        assert!(
            engine.check_publish("Circle1", &[], &[]).is_err(),
            "denied first"
        );
        assert!(engine.check_publish("Circle2", &[], &[]).is_ok());
        assert!(engine.check_publish("Circle2", &[], &tags(&[t1])).is_ok());
        assert!(engine
            .check_publish("Square", &parts(&["A_partition"]), &[])
            .is_err());
        assert!(
            engine.check_publish("Square", &[], &[]).is_err(),
            "no allow rule names Square for publish: default DENY"
        );
        assert!(engine.check_subscribe("Square1", &[], &[]).is_err());
        assert!(engine.check_subscribe("Square2", &[], &tags(&[t1])).is_ok());
        assert!(
            engine
                .check_subscribe("Triangle", &parts(&["P1x"]), &tags(&[t1]))
                .is_err(),
            "deny Tr* in P1* comes before allow Triangle in P*"
        );
        assert!(engine
            .check_subscribe("Triangle", &parts(&["P2"]), &tags(&[t1]))
            .is_ok());
        assert!(engine
            .check_subscribe("Triangle", &parts(&["P2"]), &[])
            .is_ok());
        assert!(engine
            .check_subscribe("Triangle", &parts(&["Q"]), &[])
            .is_err());
    }

    /// `<relay>` is kept in the model, but Sec.8.4.2.9.11 makes it an
    /// OUTPUT of check_remote_datareader alone (`allow_relay_only`), not a
    /// third way to grant publish or subscribe. A grant with ONLY a
    /// `<relay>` allow criterion for a topic must deny publish AND
    /// subscribe on it, exactly as if the document said nothing about that
    /// topic.
    ///
    /// Mutant: make `parse_rule` push relay criteria into `publish` (or
    /// `subscribe`) instead of `relay`, and both assertions below flip to
    /// `is_ok()`.
    #[test]
    #[cfg(feature = "qos-loaders")]
    fn relay_never_grants_publish_or_subscribe() {
        let engine = engine_from_xml(&grant_of(
            "<allow_rule><domains><id>0</id></domains><relay><topics><topic>Classified</topic>\
             </topics></relay></allow_rule><default>DENY</default>",
        ));
        assert!(
            engine.check_publish("Classified", &[], &[]).is_err(),
            "a relay allow_rule must not grant publish"
        );
        assert!(
            engine.check_subscribe("Classified", &[], &[]).is_err(),
            "a relay allow_rule must not grant subscribe"
        );
    }

    /// check_remote_datawriter (Sec.8.4.2.9.10, "the operation returns a
    /// Boolean value") has NO relay concept at all; only
    /// check_remote_datareader (Sec.8.4.2.9.11, "...and also sets the
    /// relay_only output parameter") does. On the publish/write side a
    /// `<relay>` criterion must therefore have NO effect: the evaluation
    /// falls through to the next rule, or the default, exactly as if the
    /// `<relay>` element were absent. Proved against a grant whose
    /// `<default>` is ALLOW so the admission can only come from that
    /// fall-through, never from an accidental relay grant.
    ///
    /// Mutant: delete the `if write { continue; }` guard in
    /// `check_endpoint` and this flips to `is_err()` (the relay allow
    /// criterion would fail closed on the publish side too).
    #[test]
    #[cfg(feature = "qos-loaders")]
    fn a_relay_allow_has_no_effect_on_the_publish_side() {
        let engine = engine_from_xml(&grant_of(
            "<allow_rule><domains><id>0</id></domains><relay><topics><topic>Classified</topic>\
             </topics></relay></allow_rule><default>ALLOW</default>",
        ));
        assert!(
            engine.check_publish("Classified", &[], &[]).is_ok(),
            "a relay criterion has no concept on the write side (Sec.8.4.2.9.10): ignored, \
             the default ALLOW applies"
        );
    }

    /// The subscribe-side mirror of
    /// `a_relay_allow_has_no_effect_on_the_publish_side`: a remote reader
    /// whose ONLY matching permission for a topic is `<relay>` must be
    /// REFUSED, not admitted with full access. HDDS has no routing-service
    /// role and cannot produce the `relay_only` cryptographic material
    /// check_remote_datareader would set (Sec.8.4.2.9.11, Sec.9.5.3.3.4).
    /// Proved against a grant whose `<default>` is ALLOW, so the refusal
    /// can only come from the relay match itself, never from the ordinary
    /// default-deny path.
    ///
    /// Mutant: delete the relay branch in `check_endpoint` (the
    /// `if rule.relay...` block) and `check_subscribe("Classified", ...)`
    /// flips to `is_ok()` (the walk falls through to `default_allows()`,
    /// which is `true` here).
    #[test]
    #[cfg(feature = "qos-loaders")]
    fn a_relay_allow_fails_closed_on_the_subscribe_side() {
        let engine = engine_from_xml(&grant_of(
            "<allow_rule><domains><id>0</id></domains><relay><topics><topic>Classified</topic>\
             </topics></relay></allow_rule><default>ALLOW</default>",
        ));
        let err = engine
            .check_subscribe("Classified", &[], &[])
            .expect_err("relay-only must fail closed on subscribe, even under a default ALLOW");
        assert!(
            err.to_string().contains("relay"),
            "the refusal must name why: {}",
            err
        );
        // A topic the relay criterion does not name is unaffected: the
        // default ALLOW still applies to it.
        assert!(engine.check_subscribe("Unrelated", &[], &[]).is_ok());
    }

    /// A `<relay>` DENY, like the allow case, has no concept on the
    /// publish side (Sec.8.4.2.9.10): ignored, exactly as if absent.
    ///
    /// Mutant: same as `a_relay_allow_has_no_effect_on_the_publish_side`.
    #[test]
    #[cfg(feature = "qos-loaders")]
    fn a_relay_deny_has_no_effect_on_the_publish_side() {
        let engine = engine_from_xml(&grant_of(
            "<deny_rule><domains><id>0</id></domains><relay><topics><topic>Classified</topic>\
             </topics></relay></deny_rule><default>ALLOW</default>",
        ));
        assert!(
            engine.check_publish("Classified", &[], &[]).is_ok(),
            "a relay criterion has no concept on the write side: ignored"
        );
    }

    /// A `<relay>` DENY on the subscribe side is a denial like any other,
    /// no special casing needed: `RulesEngine` must still refuse it (as
    /// opposed to silently treating relay criteria as inert in the deny
    /// direction too).
    ///
    /// Mutant: deleting the relay branch in `check_endpoint` makes this
    /// fall through to `default_allows()` (`true` here) and flip to
    /// `is_ok()`.
    #[test]
    #[cfg(feature = "qos-loaders")]
    fn a_relay_deny_denies_on_the_subscribe_side() {
        let engine = engine_from_xml(&grant_of(
            "<deny_rule><domains><id>0</id></domains><relay><topics><topic>Classified</topic>\
             </topics></relay></deny_rule><default>ALLOW</default>",
        ));
        assert!(engine.check_subscribe("Classified", &[], &[]).is_err());
    }

    /// `topic_scope` must not report `TopicScope::Any` for a topic a relay
    /// criterion alone names ON THE SUBSCRIBE SIDE: that would skip
    /// `check_endpoint` entirely at the caller
    /// (`DiscoveryFsm::judge_admission`), admitting the peer before the
    /// fail-closed relay-only check ever runs. A CONDITIONAL relay allow
    /// (scoped to one partition) defers to `PerEndpoint`, where
    /// `check_endpoint` judges the real endpoint: refused in the named
    /// partition, admitted (by the default) in another. On the publish
    /// side the same relay criterion has no concept at all
    /// (Sec.8.4.2.9.10) and `topic_scope` reports `Any` outright, from the
    /// default.
    ///
    /// Mutant: in `topic_scope`, return `Ok(TopicScope::Any)` instead of
    /// `Ok(TopicScope::PerEndpoint)` for the relay-names-it branch: the
    /// first assertion fails. Mutant: delete the `if write { continue; }`
    /// guard: the last assertion fails (`Any` becomes `PerEndpoint` on the
    /// publish side too).
    #[test]
    #[cfg(feature = "qos-loaders")]
    fn relay_topic_scope_defers_to_the_endpoint_on_subscribe_only() {
        let engine = engine_from_xml(&grant_of(
            "<allow_rule><domains><id>0</id></domains><relay><topics><topic>Classified</topic>\
             </topics><partitions><partition>Secret</partition></partitions></relay>\
             </allow_rule><default>ALLOW</default>",
        ));
        assert_eq!(
            engine.topic_scope("Classified", false).unwrap(),
            TopicScope::PerEndpoint,
            "a relay criterion must never report Any on subscribe, whatever its partitions"
        );
        assert!(
            engine
                .check_subscribe("Classified", &parts(&["Secret"]), &[])
                .is_err(),
            "the endpoint actually in the relay-named partition must be refused"
        );
        assert!(
            engine
                .check_subscribe("Classified", &parts(&["Other"]), &[])
                .is_ok(),
            "an endpoint in a DIFFERENT partition falls through to the default ALLOW"
        );
        assert_eq!(
            engine.topic_scope("Classified", true).unwrap(),
            TopicScope::Any,
            "the same relay criterion has no concept on the publish side (Sec.8.4.2.9.10)"
        );
    }

    /// An UNCONDITIONAL relay DENY (no `<partitions>`, no `<data_tags>`)
    /// applies to every partition (Sec.9.4.1.3.2.3.2.4, the same rule a
    /// plain deny criterion follows) ON THE SUBSCRIBE SIDE: `topic_scope`
    /// can and must refuse the topic outright, without waiting for an
    /// endpoint's partitions.
    ///
    /// Mutant: delete the `rule.kind == RuleKind::Deny && relay_unconditional`
    /// branch (always returning `PerEndpoint` for a relay match): this test
    /// still passes (`check_endpoint` denies it too, through `PerEndpoint`),
    /// but `the_specification_example_permissions_document`-style tests that
    /// rely on `topic_scope` alone (e.g. `DiscoveryFsm::judge_admission`'s
    /// topic-level pass with no endpoint partitions to fall back on) would
    /// start reporting `PerEndpoint` where a flat `Admitted`/`Refused` used
    /// to be decidable; verified directly here instead of through that
    /// integration path.
    #[test]
    #[cfg(feature = "qos-loaders")]
    fn an_unconditional_relay_deny_refuses_the_topic_outright_on_subscribe() {
        let engine = engine_from_xml(&grant_of(
            "<deny_rule><domains><id>0</id></domains><relay><topics><topic>Classified</topic>\
             </topics></relay></deny_rule><default>ALLOW</default>",
        ));
        let err = engine
            .topic_scope("Classified", false)
            .expect_err("an unconditional relay deny must refuse the topic outright");
        assert!(err.to_string().contains("relay"), "{}", err);
    }

    /// Pins that, WITHIN one rule, the direction-specific criterion
    /// (`<publish>`/`<subscribe>`) is checked before `<relay>`. The other
    /// relay tests never put both kinds of criterion, matching, in the SAME
    /// rule, so swapping the precedence would leave them green. This
    /// one does: an allow_rule with both a `<subscribe>` criterion naming
    /// `Classified` and a `<relay>` criterion naming it too. The direction
    /// criterion must win and grant subscribe normally; if relay were
    /// checked first, the fail-closed relay path would refuse it instead.
    ///
    /// Mutant: in `check_endpoint`, check the `rule.relay` branch before
    /// the direction branch (swap the two `if` blocks): the assertion
    /// flips from `is_ok()` to `is_err()`.
    #[test]
    #[cfg(feature = "qos-loaders")]
    fn direction_criteria_are_checked_before_relay_within_one_rule() {
        let engine = engine_from_xml(&grant_of(
            "<allow_rule><domains><id>0</id></domains><subscribe><topics>\
             <topic>Classified</topic></topics></subscribe><relay><topics>\
             <topic>Classified</topic></topics></relay></allow_rule><default>DENY</default>",
        ));
        assert!(
            engine.check_subscribe("Classified", &[], &[]).is_ok(),
            "the rule's own <subscribe> criterion must decide before its <relay> one is ever \
             consulted"
        );
    }

    /// Spec-legal documents with `<partitions>` and `<data_tags>` load, and what the schema requires is still required.
    #[test]
    #[cfg(feature = "qos-loaders")]
    fn criteria_conditions_load_and_malformed_ones_are_refused() {
        for body in [
            SPEC_ALLOW_RULE_EXAMPLE,
            SPEC_DENY_RULE_EXAMPLE,
            "<allow_rule><domains><id>0</id></domains><publish><topics><topic>Square</topic>\
             </topics><partitions><partition>A_partition</partition></partitions></publish>\
             </allow_rule>",
        ] {
            let parsed = PermissionsConfig::parse(&grant_of(body));
            assert!(parsed.is_ok(), "{}: {:?}", body, parsed.err());
        }
        let refused = |body: &str, names: &str| {
            let err = PermissionsConfig::parse(&grant_of(body)).expect_err(body);
            assert!(err.to_string().contains(names), "{}: {}", body, err);
        };
        let rule = |criterion: &str| {
            format!(
                "<allow_rule><domains><id>0</id></domains>{}</allow_rule>",
                criterion
            )
        };
        refused(
            &rule("<publish><partitions><partition>A</partition></partitions></publish>"),
            "without a <topics>",
        );
        refused(
            &rule("<publish><topics><topic>T</topic></topics><partitions></partitions></publish>"),
            "names no <partition>",
        );
        refused(
            &rule(
                "<publish><topics><topic>T</topic></topics><data_tags><tag><name>n</name>\
                 </tag></data_tags></publish>",
            ),
            "one <name> and one <value>",
        );
        refused(
            &rule(
                "<subscribe><topics><topic>T</topic></topics><data_tags></data_tags></subscribe>",
            ),
            "holds no <tag>",
        );
        refused(
            &rule(
                "<publish><topics><topic>T</topic></topics><partitions><partition>A\
                 </partition></partitions><partitions><partition>B</partition></partitions>\
                 </publish>",
            ),
            "<partitions> twice",
        );
        refused(
            &rule(
                "<publish><topics><topic>T</topic></topics><partitions><partition>[[:uper:]]\
                 </partition></partitions></publish>",
            ),
            "ill-formed bracket",
        );
        refused(
            "<allow_rule><domains><id>0</id></domains><publish><topics><topic>T</topic>\
             </topics></publish><partitions>A</partitions></allow_rule>",
            "<partitions> directly inside a rule",
        );
    }

    /// A POSIX bracket class in a topic expression loads and matches
    /// (fnmatch, Sec.9.4.1.3.2.3.1.3).
    #[test]
    #[cfg(feature = "qos-loaders")]
    fn a_posix_character_class_in_a_topic_expression_is_matched() {
        let engine = engine_from_xml(&grant_of(
            "<allow_rule><domains><id>0</id></domains><publish><topics>\
             <topic>[[:upper:]]quare</topic></topics></publish></allow_rule>\
             <default>DENY</default>",
        ));
        assert!(engine.check_topic_publish("Square", None).is_ok());
        assert!(engine.check_topic_publish("square", None).is_err());
    }

    /// A document applied whole (no subject selection, `from_xml`) with
    /// several grants: their rules are read one grant after the other, and
    /// the default allows what none matches only when every grant's default
    /// is ALLOW - the narrower reading of grants the specification gives one
    /// subject each.
    #[test]
    #[cfg(feature = "qos-loaders")]
    fn several_grants_allow_by_default_only_when_every_default_allows() {
        let grant = |name: &str, default: &str| {
            format!(
                "<grant name=\"{}\"><subject_name>CN={}</subject_name><validity>\
                 <not_before>2020-01-01T00:00:00</not_before>\
                 <not_after>2036-01-01T00:00:00</not_after></validity>\
                 <default>{}</default></grant>",
                name, name, default
            )
        };
        let document = |defaults: [&str; 2]| {
            format!(
                "<dds><permissions>{}{}</permissions></dds>",
                grant("a", defaults[0]),
                grant("b", defaults[1])
            )
        };
        assert!(engine_from_xml(&document(["ALLOW", "ALLOW"]))
            .check_topic_publish("T", None)
            .is_ok());
        for defaults in [["ALLOW", "DENY"], ["DENY", "ALLOW"]] {
            assert!(
                engine_from_xml(&document(defaults))
                    .check_topic_publish("T", None)
                    .is_err(),
                "{:?}",
                defaults
            );
        }
    }

    /// A default of ALLOW decides what no rule matches, whatever the
    /// partition: a deny rule on X leaves T allowed in B.
    #[test]
    #[cfg(feature = "qos-loaders")]
    fn a_default_allow_covers_every_partition() {
        let engine = engine_from_xml(&grant_of(
            "<deny_rule><domains><id>0</id></domains><publish><topics><topic>X</topic>\
             </topics></publish></deny_rule><default>ALLOW</default>",
        ));
        assert!(engine.check_topic_publish("X", None).is_err());
        assert!(engine.check_topic_publish("T", Some("B")).is_ok());
    }

    /// Sec.9.4.1.3.2.3.1.6, copied (indentation aside).
    #[cfg(feature = "qos-loaders")]
    const SPEC_ALLOW_RULE_EXAMPLE: &str = "<allow_rule>
<domains>
<id>0</id>
</domains>
<publish>
<topics>
<topic>Cir*</topic>
</topics>
<data_tags>
<tag>
<name>aTagName1</name>
<value>aTagValue1</value>
</tag>
</data_tags>
</publish>
<subscribe>
<topics>
<topic>Sq*</topic>
</topics>
<data_tags>
<tag>
<name>aTagName1</name>
<value>aTagValue1</value>
</tag>
<tag>
<name>aTagName2</name>
<value>aTagValue2</value>
</tag>
</data_tags>
</subscribe>
<subscribe>
<topics>
<topic>Triangle</topic>
</topics>
<partitions>
<partition>P*</partition>
</partitions>
</subscribe>
</allow_rule>";

    /// Sec.9.4.1.3.2.3.2.7, copied.
    #[cfg(feature = "qos-loaders")]
    const SPEC_DENY_RULE_EXAMPLE: &str = "<deny_rule>
<domains>
<id>0</id>
</domains>
<publish>
<topics>
<topic>Circle1</topic>
</topics>
</publish>
<publish>
<topics>
<topic>Square</topic>
</topics>
<partitions>
<partition>A_partition</partition>
</partitions>
</publish>
<subscribe>
<topics>
<topic>Square1</topic>
</topics>
</subscribe>
<subscribe>
<topics>
<topic>Tr*</topic>
</topics>
<partitions>
<partition>P1*</partition>
</partitions>
<data_tags>
<tag>
<name>aTagName1</name>
<value>aTagValue1</value>
</tag>
<tag>
<name>aTagName2</name>
<value>aTagValue2</value>
</tag>
</data_tags>
</subscribe>
</deny_rule>";

    /// Sec.9.4.1.4, copied: the example permissions document, its validity
    /// window the specification's own (2013-10-26 to 2018-10-26, elapsed),
    /// not extended. The grant applies all the same: a RulesEngine applies
    /// every grant it is given and reads no validity - choosing the grants
    /// of a subject that are in force is `select_grants_for_subject`'s, not
    /// exercised here.
    #[cfg(feature = "qos-loaders")]
    const SPEC_PERMISSIONS_EXAMPLE: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<dds xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
xsi:noNamespaceSchemaLocation="http://www.omg.org/spec/DDSSecurity/20170801/omg_shared_ca_permissions.xsd">
<permissions>
<grant name="ShapesPermission">
<subject_name>emailAddress=cto@acme.com, CN=DDS Shapes Demo, OU=CTO
Office, O=ACME Inc., L=Sunnyvale, ST=CA, C=US</subject_name>
<validity>
<!-- Format is CCYY-MM-DDThh:mm:ss[Z|(+|-)hh:mm] The time zone may
be specified as Z (UTC) or (+|-)hh:mm. Time zones that aren't
specified are considered UTC.
-->
<not_before>2013-10-26T00:00:00</not_before>
<not_after>2018-10-26T22:45:30</not_after>
</validity>
<allow_rule>
<domains>
<id>0</id>
</domains>
<!-- DDSSEC11-56 - deleted invalid elements -->
</allow_rule>
<deny_rule>
<domains>
<id>0</id>
</domains>
<publish>
<topics>
<topic>Circle1</topic>
</topics>
</publish>
<publish>
<topics>
<topic>Square</topic>
</topics>
<partitions>
<partition>A_partition</partition>
</partitions>
</publish>
<subscribe>
<topics>
<topic>Square1</topic>
</topics>
</subscribe>
<subscribe>
<topics>
<topic>Tr*</topic>
</topics>
<partitions>
<partition>P1*</partition>
</partitions>
</subscribe>
</deny_rule>
<allow_rule>
<domains>
<id>0</id>
</domains>
<publish>
<topics>
<topic>Cir*</topic>
</topics>
<data_tags>
<tag>
<name>aTagName1</name>
<value>aTagValue1</value>
</tag>
</data_tags>
</publish>
<subscribe>
<topics>
<topic>Sq*</topic>
</topics>
<data_tags>
<tag>
<name>aTagName1</name>
<value>aTagValue1</value>
</tag>
<tag>
<name>aTagName2</name>
<value>aTagValue2</value>
</tag>
</data_tags>
</subscribe>
<subscribe>
<topics>
<topic>Triangle</topic>
</topics>
<partitions>
<partition>P*</partition>
</partitions>
<data_tags>
<tag>
<name>aTagName1</name>
<value>aTagValue1</value>
</tag>
</data_tags>
</subscribe>
<relay>
<topics>
<topic>*</topic>
</topics>
<partitions>
<partition>aPartitionName</partition>
</partitions>
</relay>
</allow_rule>
<default>DENY</default>
</grant>
</permissions>
</dds>"#;

    /// Sec.9.4.1.3.2.3.1.4: "If there is no <partitions> Section within an
    /// allow rule, then the default "empty string" partition is assumed ...
    /// the allow rule (e.g., publish) would only allow a DataWriter to
    /// publish on the "empty string" partition." Sec.9.4.1.3.2.3.2.4: a deny
    /// rule without one applies "independent of the partition".
    #[test]
    #[cfg(feature = "qos-loaders")]
    fn an_allow_rule_grants_the_default_partition_only() {
        let engine = engine_from_xml(&grant_of(
            "<allow_rule><domains><id>0</id></domains><publish><topics><topic>T*</topic>\
             </topics></publish><subscribe><topics><topic>T*</topic></topics></subscribe>\
             </allow_rule><deny_rule><domains><id>0</id></domains><publish><topics>\
             <topic>Tx</topic></topics></publish></deny_rule><default>DENY</default>",
        ));
        assert!(engine.check_topic_publish("T", None).is_ok());
        assert!(engine.check_topic_publish("T", Some("")).is_ok());
        let err = engine
            .check_topic_publish("T", Some("B"))
            .expect_err("partition B is not granted");
        assert!(
            err.to_string().contains("default partition only"),
            "{}",
            err
        );
        assert!(engine.check_topic_subscribe("T", Some("B")).is_err());
        assert!(engine.check_topic_subscribe("T", None).is_ok());
        // Tx in the default partition is allowed by the allow rule, which
        // comes first; in B the allow rule does not match, and the deny
        // rule, which names no partition, refuses in every partition.
        assert!(engine.check_topic_publish("Tx", None).is_ok());
        assert!(engine.check_topic_publish("Tx", Some("B")).is_err());
    }

    /// Sec.9.4.1.3.2.3: "If all rules have been examined without a match,
    /// then the decision specified by the "default" rule is applied. The
    /// default rule, if present, must appear after all allow and deny rules.
    /// If the default rule is not present, the implied default decision is
    /// DENY."
    #[test]
    #[cfg(feature = "qos-loaders")]
    fn the_default_decides_what_no_rule_matches() {
        let deny_x = "<deny_rule><domains><id>0</id></domains><publish><topics>\
                      <topic>X</topic></topics></publish></deny_rule>";
        let allowing = engine_from_xml(&grant_of(&format!("{}<default>ALLOW</default>", deny_x)));
        assert!(allowing.check_topic_publish("Other", None).is_ok());
        assert!(allowing.check_topic_publish("Other", Some("B")).is_ok());
        assert!(allowing.check_topic_subscribe("Other", None).is_ok());
        assert!(
            allowing.check_topic_publish("X", None).is_err(),
            "a deny rule matched"
        );
        let lower = engine_from_xml(&grant_of(&format!("{}<default>allow</default>", deny_x)));
        assert!(lower.check_topic_publish("Other", None).is_ok());

        let denying = engine_from_xml(&grant_of(&format!("{}<default>DENY</default>", deny_x)));
        assert!(denying.check_topic_publish("Other", None).is_err());
        let absent = engine_from_xml(&grant_of(deny_x));
        assert!(
            absent.check_topic_publish("Other", None).is_err(),
            "implied DENY"
        );

        for (body, names) in [
            (
                format!("{}<default>MAYBE</default>", deny_x),
                "write ALLOW or DENY",
            ),
            (
                format!("<default>ALLOW</default>{}", deny_x),
                "after <default>",
            ),
            (
                format!("{}<default>DENY</default><default>ALLOW</default>", deny_x),
                "<default> twice",
            ),
        ] {
            let err = PermissionsConfig::parse(&grant_of(&body)).expect_err(&body);
            assert!(err.to_string().contains(names), "{}: {}", body, err);
        }
    }

    fn verify2_doc(rules: &str, default: &str) -> String {
        format!(
            "<dds><permissions><grant name=\"g\"><subject_name>CN=Test</subject_name>\
             <validity><not_before>2020-01-01T00:00:00</not_before>\
             <not_after>2036-01-01T00:00:00</not_after></validity>{}<default>{}</default>\
             </grant></permissions></dds>",
            rules, default
        )
    }

    /// Written `allow *` BEFORE `deny Secret*`, the allow decides: the rule
    /// is not deny-first. Sec.9.4.1.3.2.3, "The rules are applied in
    /// the same order that appear in the document", so `allow *` decides
    /// `SecretPlans` (allowed). This tests the fnmatch prefix deny applied
    /// when it comes first, and the document order both ways.
    #[test]
    #[cfg(feature = "qos-loaders")]
    fn verify2_deny_rule_with_fnmatch_prefix_pattern_is_applied() {
        let allow_all = "<allow_rule><domains><id>0</id></domains><publish><topics>\
                         <topic>*</topic></topics></publish></allow_rule>";
        let deny_secret = "<deny_rule><domains><id>0</id></domains><publish><topics>\
                           <topic>Secret*</topic></topics></publish></deny_rule>";
        let deny_first =
            engine_from_xml(&verify2_doc(&format!("{deny_secret}{allow_all}"), "DENY"));
        assert!(deny_first.check_topic_publish("SecretPlans", None).is_err());
        assert!(deny_first.check_topic_publish("Open", None).is_ok());
        let allow_first =
            engine_from_xml(&verify2_doc(&format!("{allow_all}{deny_secret}"), "DENY"));
        assert!(
            allow_first.check_topic_publish("SecretPlans", None).is_ok(),
            "document order: allow * comes first"
        );
    }

    /// Sec.9.4.1.3.2.3: "The rules are applied in the same order that appear
    /// in the document." allow T, then deny *: T is allowed by the spec.
    #[test]
    #[cfg(feature = "qos-loaders")]
    fn verify2_rule_order_allow_before_catch_all_deny_follows_document_order() {
        let engine = engine_from_xml(&verify2_doc(
            "<allow_rule><domains><id>0</id></domains><publish><topics><topic>T</topic>\
             </topics></publish></allow_rule>\
             <deny_rule><domains><id>0</id></domains><publish><topics><topic>*</topic>\
             </topics></publish></deny_rule>",
            "DENY",
        ));
        assert!(
            engine.check_topic_publish("U", None).is_err(),
            "U denied by deny *"
        );
        assert!(
            engine.check_topic_publish("T", None).is_ok(),
            "allow T written BEFORE deny * : the spec applies the first match (allow)"
        );
    }

    /// A spec-legal allow rule with <partitions> inside <publish> (the spec's
    /// own example shape, Sec.9.4.1.3.2.3.1.2) is refused at load.
    #[test]
    #[cfg(feature = "qos-loaders")]
    fn verify2_spec_example_allow_with_partitions_loads() {
        let r = PermissionsConfig::parse(&verify2_doc(
            "<allow_rule><domains><id>0</id></domains><publish><topics><topic>Square</topic>\
             </topics><partitions><partition>A_partition</partition></partitions></publish>\
             </allow_rule>",
            "DENY",
        ));
        assert!(r.is_ok(), "spec-legal document refused: {:?}", r.err());
    }

    /// POSIX fnmatch character class in a permissions topic expression.
    #[test]
    #[cfg(feature = "qos-loaders")]
    fn verify2_posix_character_class_loads() {
        let r = PermissionsConfig::parse(&verify2_doc(
            "<allow_rule><domains><id>0</id></domains><publish><topics>\
             <topic>[[:upper:]]quare</topic></topics></publish></allow_rule>",
            "DENY",
        ));
        assert!(r.is_ok(), "POSIX class refused: {:?}", r.err());
    }

    /// default ALLOW + allow rule matching T: T allowed in any partition
    /// (default applies when the allow rule's partition criterion fails).
    #[test]
    #[cfg(feature = "qos-loaders")]
    fn verify2_default_allow_scope() {
        let engine = engine_from_xml(&verify2_doc(
            "<deny_rule><domains><id>0</id></domains><publish><topics><topic>X</topic>\
             </topics></publish></deny_rule>",
            "ALLOW",
        ));
        assert!(engine.check_topic_publish("X", None).is_err());
        assert!(engine.check_topic_publish("T", Some("B")).is_ok());
    }

    /// DDS-Security v1.1 Sec.9.4.1.3.2.3: permissions topic expressions are
    /// POSIX fnmatch. A deny rule `Secret*` must deny `SecretPlans`.
    ///
    /// The deny comes first, where it is the rule that decides: the
    /// specification is not deny-first ("The rules are applied in the same
    /// order that appear in the document", Sec.9.4.1.3.2.3).
    #[test]
    #[cfg(feature = "qos-loaders")]
    fn verify_deny_rule_with_fnmatch_prefix_pattern_is_applied() {
        let engine = engine_from_xml(
            "<dds><permissions><grant name=\"g\"><subject_name>CN=Test</subject_name>\
             <validity><not_before>2020-01-01T00:00:00</not_before>\
             <not_after>2036-01-01T00:00:00</not_after></validity>\
             <deny_rule><domains><id>0</id></domains><publish><topics><topic>Secret*</topic>\
             </topics></publish></deny_rule>\
             <allow_rule><domains><id>0</id></domains><publish><topics><topic>*</topic>\
             </topics></publish></allow_rule><default>DENY</default></grant></permissions></dds>",
        );
        assert!(
            engine.check_topic_publish("SecretPlans", None).is_err(),
            "deny Secret* did not deny SecretPlans"
        );
        assert!(engine.check_topic_publish("OpenPlans", None).is_ok());
    }

    /// Partitions inside <publish> (the spec's schema) are not read, and the
    /// engine ignores the partition argument: a grant for partition A covers B.
    #[test]
    #[cfg(feature = "qos-loaders")]
    fn verify_allow_rule_partition_limits_the_grant() {
        let engine = engine_from_xml(
            "<dds><permissions><grant name=\"g\"><subject_name>CN=Test</subject_name>\
             <validity><not_before>2020-01-01T00:00:00</not_before>\
             <not_after>2036-01-01T00:00:00</not_after></validity>\
             <allow_rule><domains><id>0</id></domains><publish><topics><topic>T</topic>\
             </topics><partitions><partition>A</partition></partitions></publish></allow_rule>\
             <default>DENY</default></grant></permissions></dds>",
        );
        assert!(
            engine.check_topic_publish("T", Some("B")).is_err(),
            "a grant limited to partition A allowed partition B"
        );
    }
}
