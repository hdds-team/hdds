// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Governance and Permissions XML parsing for DDS Security v1.1

use crate::security::access::attributes::{
    BasicProtectionKind, EndpointSecurityAttributes, ParticipantSecurityAttributes, ProtectionKind,
    TopicSecurityAttributes,
};
use crate::security::SecurityError;

/// Governance configuration (domain-wide security policies)
#[derive(Debug, Clone)]
pub struct GovernanceConfig {
    pub domain_rules: Vec<DomainRule>,
}

/// One `<domain_rule>` (DDS-Security v1.1 Sec.9.4.1.2.5).
#[derive(Debug, Clone)]
pub struct DomainRule {
    /// Domain ids listed one by one.
    pub domains: Vec<u32>,
    /// Inclusive id ranges, stored as bounds and NEVER expanded.
    ///
    /// A signed document may legitimately carry `<min>0</min>` with
    /// `<max>4294967295</max>`. Expanding that into `domains` would allocate
    /// four billion `u32`, about 17 GB, before any rule was evaluated - a
    /// memory exhaustion reachable from a document the operator considers
    /// trusted. The previous parser avoided it only by clamping the upper
    /// bound to 255, which silently discarded every legitimate id above 255.
    /// Storing the bounds costs nothing and is exact.
    pub domain_ranges: Vec<(u32, u32)>,
    /// `<allow_unauthenticated_participants>` (Sec.9.4.1.2.5.2).
    pub allow_unauthenticated: bool,
    /// DDS-Security `enable_join_access_control` (Sec.9.4.1.2.5.3): whether a
    /// participant's permissions are checked before it is allowed into the
    /// domain.
    pub enable_join_access_control: bool,
    /// `<discovery_protection_kind>` (Sec.9.4.1.2.5.4).
    pub discovery_protection_kind: ProtectionKind,
    /// `<liveliness_protection_kind>` (Sec.9.4.1.2.5.5).
    pub liveliness_protection_kind: ProtectionKind,
    /// `<rtps_protection_kind>` (Sec.9.4.1.2.5.6).
    pub rtps_protection_kind: ProtectionKind,
    /// `<topic_access_rules>` (Sec.9.4.1.2.5.7), in document order: the
    /// first whose expression matches a topic is the one applied to it
    /// (Sec.9.4.1.2.6, 9.4.1.2.7).
    ///
    /// A rule written in this project's shorthand - a domain-level
    /// `<data_protection_kind>` and no `<topic_access_rules>` - holds the one
    /// topic rule that shorthand has always meant: see [`TopicRule::shorthand`].
    pub topic_rules: Vec<TopicRule>,
}

/// One `<topic_rule>` (DDS-Security v1.1 Sec.9.4.1.2.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopicRule {
    /// `<topic_expression>`, an fnmatch pattern (Sec.9.4.1.2.6.1).
    pub topic_expression: String,
    /// `<enable_discovery_protection>` (Sec.9.4.1.2.6.2).
    pub enable_discovery_protection: bool,
    /// `<enable_liveliness_protection>` (Sec.9.4.1.2.6.3).
    pub enable_liveliness_protection: bool,
    /// `<enable_read_access_control>` (Sec.9.4.1.2.6.4).
    pub enable_read_access_control: bool,
    /// `<enable_write_access_control>` (Sec.9.4.1.2.6.5).
    pub enable_write_access_control: bool,
    /// `<metadata_protection_kind>` (Sec.9.4.1.2.6.6).
    pub metadata_protection_kind: ProtectionKind,
    /// `<data_protection_kind>` (Sec.9.4.1.2.6.7).
    pub data_protection_kind: BasicProtectionKind,
}

impl TopicRule {
    /// The topic rule a `<domain_rule>` written in this project's shorthand
    /// stands for: no `<topic_access_rules>`, a domain-level
    /// `<data_protection_kind>` (or the older `<encrypt_topics>`).
    ///
    /// That shorthand predates per-topic rules here and has always meant one
    /// policy for every topic, so it reads as a single `*` rule:
    ///
    /// - discovery protection as the domain's `discovery_protection_kind`
    ///   says: every endpoint on the secure discovery topics when the kind
    ///   protects anything, none otherwise. That is what the shorthand has
    ///   always asked for, and before this rule existed nothing applied it;
    /// - read and write access control ON: the permissions document was
    ///   consulted for every endpoint, and it still is;
    /// - no liveliness protection and no submessage protection, which the
    ///   shorthand never could ask for;
    /// - the data protection it names.
    #[must_use]
    pub fn shorthand(discovery: ProtectionKind, data: BasicProtectionKind) -> Self {
        Self {
            topic_expression: "*".to_string(),
            enable_discovery_protection: discovery.is_protected(),
            enable_liveliness_protection: false,
            enable_read_access_control: true,
            enable_write_access_control: true,
            metadata_protection_kind: ProtectionKind::None,
            data_protection_kind: data,
        }
    }

    /// `TopicSecurityAttributes` of a topic this rule applies to
    /// (Sec.9.4.1.2.6.2 to 9.4.1.2.6.5).
    #[must_use]
    pub fn topic_attributes(&self) -> TopicSecurityAttributes {
        TopicSecurityAttributes {
            is_read_protected: self.enable_read_access_control,
            is_write_protected: self.enable_write_access_control,
            is_discovery_protected: self.enable_discovery_protection,
            is_liveliness_protected: self.enable_liveliness_protection,
        }
    }

    /// `EndpointSecurityAttributes` of an endpoint of a topic this rule
    /// applies to (Sec.9.4.1.2.6.6, 9.4.1.2.6.7).
    #[must_use]
    pub fn endpoint_attributes(&self) -> EndpointSecurityAttributes {
        EndpointSecurityAttributes::from_rule(
            self.topic_attributes(),
            self.metadata_protection_kind,
            self.data_protection_kind,
        )
    }
}

impl DomainRule {
    /// Whether this rule applies to `domain_id`.
    #[must_use]
    pub fn covers(&self, domain_id: u32) -> bool {
        self.domains.contains(&domain_id)
            || self
                .domain_ranges
                .iter()
                .any(|(lo, hi)| domain_id >= *lo && domain_id <= *hi)
    }

    /// `ParticipantSecurityAttributes` of a participant this rule applies to
    /// (Sec.9.4.1.2.5.2 to 9.4.1.2.5.6).
    #[must_use]
    pub fn participant_attributes(&self) -> ParticipantSecurityAttributes {
        ParticipantSecurityAttributes::from_kinds(
            self.allow_unauthenticated,
            self.enable_join_access_control,
            self.discovery_protection_kind,
            self.liveliness_protection_kind,
            self.rtps_protection_kind,
        )
    }

    /// The topic rule applied to `topic`: the FIRST whose expression matches
    /// (Sec.9.4.1.2.6: "If multiple rules match the first rule that matches
    /// is the only one that applies").
    #[must_use]
    pub fn topic_rule_for(&self, topic: &str) -> Option<&TopicRule> {
        self.topic_rules
            .iter()
            .find(|rule| super::fnmatch::fnmatch(&rule.topic_expression, topic))
    }
}

impl GovernanceConfig {
    /// The domain rule applied to a participant of `domain_id`: the FIRST
    /// that covers it (Sec.9.4.1.2.5, 9.4.1.2.7).
    #[must_use]
    pub fn domain_rule_for(&self, domain_id: u32) -> Option<&DomainRule> {
        self.domain_rules.iter().find(|rule| rule.covers(domain_id))
    }

    /// The topic rules of `domain_id` whose access control rests on nothing
    /// authenticated: read or write access control on, while discovery is
    /// not protected (Sec.9.4.1.2.6.2) and neither the submessages nor the
    /// payload are (Sec.9.4.1.2.6.6, 9.4.1.2.6.7).
    ///
    /// Access control judges an endpoint by the permissions of the
    /// participant its GUID prefix names. With discovery on the plain SEDP
    /// topics, anyone can announce an endpoint under the prefix of an
    /// authenticated participant and be judged by ITS permissions; with no
    /// data or metadata protection, nothing in the traffic tells the forged
    /// endpoint from the real one. The configuration is legal, so it is not
    /// refused: one message per rule, for the operator's log.
    #[must_use]
    pub fn unauthenticated_access_control_warnings(&self, domain_id: u32) -> Vec<String> {
        let Some(rule) = self.domain_rule_for(domain_id) else {
            return Vec::new();
        };
        rule.topic_rules
            .iter()
            .filter(|topic| {
                (topic.enable_read_access_control || topic.enable_write_access_control)
                    && !topic.enable_discovery_protection
                    && topic.metadata_protection_kind == ProtectionKind::None
                    && topic.data_protection_kind == BasicProtectionKind::None
            })
            .map(|topic| {
                format!(
                    "governance topic rule '{}' on domain {} enables access control with \
                     discovery, metadata and data protection all off: an endpoint announced \
                     in the clear under an authenticated participant's prefix is judged by \
                     that participant's permissions, and nothing authenticates it; enable \
                     discovery protection or a protection kind for this rule",
                    topic.topic_expression, domain_id
                )
            })
            .collect()
    }

    /// `get_participant_sec_attributes` for a participant of `domain_id`.
    ///
    /// # Errors
    ///
    /// No rule covers the domain: Sec.9.4.1.2.7, "If no Domain Rule matches
    /// the DomainParticipant domain_id the operation under consideration
    /// shall fail with a suitable permissions error".
    pub fn participant_attributes(
        &self,
        domain_id: u32,
    ) -> Result<ParticipantSecurityAttributes, SecurityError> {
        self.domain_rule_for(domain_id)
            .map(DomainRule::participant_attributes)
            .ok_or_else(|| no_domain_rule(domain_id))
    }

    /// The topic rule applied to `topic` on `domain_id`.
    ///
    /// # Errors
    ///
    /// No domain rule covers the domain, or no topic rule of the one that
    /// does matches the topic: Sec.9.4.1.2.7, "If no Topic Rule matches the
    /// Entity topic name the operation under consideration shall fail with a
    /// suitable permissions error".
    pub fn topic_rule_for(&self, domain_id: u32, topic: &str) -> Result<&TopicRule, SecurityError> {
        let domain = self
            .domain_rule_for(domain_id)
            .ok_or_else(|| no_domain_rule(domain_id))?;
        domain.topic_rule_for(topic).ok_or_else(|| {
            SecurityError::PermissionsDenied(format!(
                "governance has no <topic_rule> whose <topic_expression> matches topic '{}' on \
                 domain {} (DDS-Security v1.1 9.4.1.2.7: an entity whose topic no rule matches \
                 is refused; a final <topic_expression>*</topic_expression> rule is the \
                 specification's default)",
                topic, domain_id
            ))
        })
    }

    /// `get_topic_sec_attributes` for `topic` on `domain_id`.
    ///
    /// # Errors
    ///
    /// See [`Self::topic_rule_for`].
    pub fn topic_attributes(
        &self,
        domain_id: u32,
        topic: &str,
    ) -> Result<TopicSecurityAttributes, SecurityError> {
        self.topic_rule_for(domain_id, topic)
            .map(TopicRule::topic_attributes)
    }

    /// `get_datawriter_sec_attributes` / `get_datareader_sec_attributes`
    /// for an endpoint of `topic` on `domain_id`.
    ///
    /// # Errors
    ///
    /// See [`Self::topic_rule_for`].
    pub fn endpoint_attributes(
        &self,
        domain_id: u32,
        topic: &str,
    ) -> Result<EndpointSecurityAttributes, SecurityError> {
        self.topic_rule_for(domain_id, topic)
            .map(TopicRule::endpoint_attributes)
    }
}

fn no_domain_rule(domain_id: u32) -> SecurityError {
    SecurityError::PermissionsDenied(format!(
        "governance has no <domain_rule> covering domain {} (DDS-Security v1.1 9.4.1.2.7)",
        domain_id
    ))
}

/// Read a governance boolean, with no silent default.
///
/// The governance XSD types these elements `xs:boolean` (Sec.9.4.1.2.3),
/// whose lexical space is `true`, `false`, `1` and `0`. The prose of the same
/// specification says they "may take the binary values TRUE or FALSE"
/// (Sec.9.4.1.2.5.2, 9.4.1.2.6.2 and the others), and its own example
/// document writes `TRUE` (Sec.9.4.1.2.8). Both spellings are therefore
/// read, case-insensitively, as the open implementations of the builtin
/// plugin read them. Anything else - `yes`, `on`, an empty element - is an
/// error naming the element: the previous parser read every one of them as
/// `false` through `text.trim() == "true"`, and for an element that ENABLES
/// a protection that is the worst possible reading.
#[cfg(feature = "qos-loaders")]
fn governance_bool(element: &str, text: Option<&str>) -> Result<bool, SecurityError> {
    let value = text.map(str::trim);
    match value {
        Some(v) if v.eq_ignore_ascii_case("true") || v == "1" => Ok(true),
        Some(v) if v.eq_ignore_ascii_case("false") || v == "0" => Ok(false),
        Some("") | None => Err(SecurityError::ConfigError(format!(
            "governance <{}> is empty: a security setting has no default here, \
             write TRUE or FALSE",
            element
        ))),
        Some(other) => Err(SecurityError::ConfigError(format!(
            "governance <{}> is \"{}\", which is not a boolean: write TRUE or FALSE",
            element, other
        ))),
    }
}

/// Read a `ProtectionKind` (Sec.9.4.1.2.1, 9.4.1.2.2).
#[cfg(feature = "qos-loaders")]
fn protection_kind(element: &str, text: Option<&str>) -> Result<ProtectionKind, SecurityError> {
    let value = text.map(str::trim).unwrap_or("");
    if value.is_empty() {
        return Err(SecurityError::ConfigError(format!(
            "governance <{}> is empty: a protection setting has no default here",
            element
        )));
    }
    ProtectionKind::from_xml(value).ok_or_else(|| {
        SecurityError::ConfigError(format!(
            "governance <{}> is \"{}\", which is not a ProtectionKind: write NONE, SIGN, \
             ENCRYPT, SIGN_WITH_ORIGIN_AUTHENTICATION or ENCRYPT_WITH_ORIGIN_AUTHENTICATION",
            element, value
        ))
    })
}

/// Read a `BasicProtectionKind` (Sec.9.4.1.2.1, DDSSEC11-11).
#[cfg(feature = "qos-loaders")]
fn basic_protection_kind(
    element: &str,
    text: Option<&str>,
) -> Result<BasicProtectionKind, SecurityError> {
    let value = text.map(str::trim).unwrap_or("");
    if value.is_empty() {
        return Err(SecurityError::ConfigError(format!(
            "governance <{}> is empty: a protection setting has no default here",
            element
        )));
    }
    BasicProtectionKind::from_xml(value).ok_or_else(|| {
        SecurityError::ConfigError(format!(
            "governance <{}> is \"{}\", which is not a BasicProtectionKind: write NONE, SIGN \
             or ENCRYPT",
            element, value
        ))
    })
}

/// Refuse a protection this release does not apply, by name.
///
/// The document is the operator's statement of what protects their traffic.
/// Accepting a protection that nothing applies is how an operator ends up
/// believing in it, so every kind below is refused where it is read, with
/// the element and the kind named, until the transformation that provides
/// it exists:
///
/// - `rtps_protection_kind` other than NONE: `encode_rtps_message` is not
///   implemented;
/// - `liveliness_protection_kind` other than NONE, and a topic's
///   `enable_liveliness_protection` TRUE: liveliness is not sent on
///   BuiltinParticipantMessageSecure;
/// - a topic's `metadata_protection_kind` other than NONE: user-data
///   submessages are not protected (only their payload is);
/// - a topic's `data_protection_kind` SIGN: the payload is encrypted or
///   left alone, never only authenticated;
/// - `discovery_protection_kind` SIGN_WITH_ORIGIN_AUTHENTICATION or
///   ENCRYPT_WITH_ORIGIN_AUTHENTICATION: origin authentication needs a
///   receiver-specific key per matched remote reader, created by
///   `register_matched_remote_datareader` and "shared only with that one
///   specific remote DataReader" (Table 70), so a DatawriterCryptoTokens
///   message per reader; the secure discovery writers announce one token per
///   writer to every peer.
#[cfg(feature = "qos-loaders")]
fn refuse_unapplied(rule: &DomainRule) -> Result<(), SecurityError> {
    let refuse = |element: &str, value: &str, why: &str| {
        Err(SecurityError::ConfigError(format!(
            "governance <{}> asks for {}, which this release does not apply: {}. It is \
             refused rather than accepted, because a document that requests a protection \
             nobody applies is worse than one that does not request it",
            element, value, why
        )))
    };
    if rule.rtps_protection_kind.is_protected() {
        return refuse(
            "rtps_protection_kind",
            rule.rtps_protection_kind.as_xml(),
            "whole-message protection (encode_rtps_message) is not implemented",
        );
    }
    if rule.discovery_protection_kind.is_origin_authenticated() {
        return refuse(
            "discovery_protection_kind",
            rule.discovery_protection_kind.as_xml(),
            "origin authentication needs a receiver-specific key for each matched remote \
             DataReader (DDS Security v1.1 Table 70, register_matched_remote_datareader), and \
             the secure discovery writers announce one key material per writer to every \
             authenticated participant; use SIGN or ENCRYPT",
        );
    }
    if rule.liveliness_protection_kind.is_protected() {
        return refuse(
            "liveliness_protection_kind",
            rule.liveliness_protection_kind.as_xml(),
            "liveliness is not sent on BuiltinParticipantMessageSecure",
        );
    }
    for topic in &rule.topic_rules {
        if topic.enable_liveliness_protection {
            return refuse(
                "enable_liveliness_protection",
                &format!("TRUE (topic expression \"{}\")", topic.topic_expression),
                "liveliness is not sent on BuiltinParticipantMessageSecure",
            );
        }
        if topic.metadata_protection_kind.is_protected() {
            return refuse(
                "metadata_protection_kind",
                &format!(
                    "{} (topic expression \"{}\")",
                    topic.metadata_protection_kind.as_xml(),
                    topic.topic_expression
                ),
                "the submessages of user DataWriters and DataReaders are not protected, only \
                 their payload",
            );
        }
        if topic.data_protection_kind == BasicProtectionKind::Sign {
            return refuse(
                "data_protection_kind",
                &format!("SIGN (topic expression \"{}\")", topic.topic_expression),
                "a payload is encrypted or left alone, never only authenticated",
            );
        }
    }
    Ok(())
}

/// The deepest element nesting read in a governance or permissions document.
///
/// The parser recurses once per level: ten thousand levels overflowed an
/// 8 MiB stack and aborted the process, which `catch_unwind` cannot stop.
/// The schemas nest seven levels deep (`dds/permissions/grant/allow_rule/
/// publish/topics/topic`). 64 leaves a wide margin and parses on a 512 KiB
/// thread stack in a debug build (`the_nesting_bound_is_exact`), where 256
/// levels did not: a bound must hold on the smallest stack that parses, not
/// only on the main thread's.
pub(crate) const MAX_XML_DEPTH: usize = 64;

/// Refuse `xml` before it reaches the parser when its elements nest deeper
/// than [`MAX_XML_DEPTH`], or when it carries a DTD (which the parser refuses
/// as well: a DTD is where entity expansion lives).
///
/// A linear scan of the markup. Comments, CDATA sections, processing
/// instructions and quoted attribute values are stepped over whole, so a
/// closing tag written inside one of them does not lower the count. Where the
/// scan and the parser could disagree on malformed input, the scan counts an
/// element open: it can refuse a document the parser would also refuse, never
/// hand it a deeper one.
#[cfg(feature = "qos-loaders")]
fn refuse_deep_nesting(xml: &str, document: &str) -> Result<(), SecurityError> {
    let bytes = xml.as_bytes();
    // The index just past the first `needle` at or after `from`, or the end.
    let past = |from: usize, needle: &[u8]| -> usize {
        bytes
            .get(from..)
            .and_then(|rest| rest.windows(needle.len()).position(|w| w == needle))
            .map_or(bytes.len(), |at| from + at + needle.len())
    };
    let mut depth = 0usize;
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] != b'<' {
            i += 1;
            continue;
        }
        let rest = &bytes[i..];
        if rest.starts_with(b"<!--") {
            i = past(i + 4, b"-->");
        } else if rest.starts_with(b"<![CDATA[") {
            i = past(i + 9, b"]]>");
        } else if rest.starts_with(b"<?") {
            i = past(i + 2, b"?>");
        } else if rest.starts_with(b"<!") {
            return Err(SecurityError::ConfigError(format!(
                "{} document carries a DTD (<!DOCTYPE>): refused, a security document has \
                 no use for entity declarations",
                document
            )));
        } else if rest.starts_with(b"</") {
            depth = depth.saturating_sub(1);
            i = past(i + 2, b">");
        } else {
            // A start tag: up to its '>', stepping over quoted values.
            let mut j = i + 1;
            let mut quote = None;
            let mut self_closing = false;
            while let Some(&b) = bytes.get(j) {
                match quote {
                    Some(q) if b == q => quote = None,
                    Some(_) => {}
                    None if b == b'"' || b == b'\'' => quote = Some(b),
                    None if b == b'>' => {
                        self_closing = bytes[j - 1] == b'/';
                        break;
                    }
                    None => {}
                }
                j += 1;
            }
            if !self_closing {
                depth += 1;
                if depth > MAX_XML_DEPTH {
                    return Err(SecurityError::ConfigError(format!(
                        "{} document nests elements more than {} levels deep: refused before \
                         parsing (the schema nests seven)",
                        document, MAX_XML_DEPTH
                    )));
                }
            }
            i = j + 1;
        }
    }
    Ok(())
}

/// The text of a value element: its character data, which must be one run.
///
/// roxmltree's `Node::text` is the FIRST text child only. A comment or a
/// processing instruction inside a value splits it, so `Open<!-- x -->Secret`
/// read as `Open` and `*<!-- -->Secret` as `*`: a rule wider than the one
/// written. Joining the parts would be the XML reading, but a signed security
/// document is read by more than one tool, and a value whose parts some
/// reader may not join is refused here rather than read one way among
/// several. An element inside a value is refused for the same reason. CDATA
/// is character data and reads as part of the run.
#[cfg(feature = "qos-loaders")]
fn leaf_text<'a>(node: &roxmltree::Node<'a, '_>) -> Result<Option<&'a str>, SecurityError> {
    if let Some(inner) = node.children().find(|child| !child.is_text()) {
        let what = if inner.is_comment() {
            "a comment".to_string()
        } else if inner.is_pi() {
            "a processing instruction".to_string()
        } else {
            format!("the element <{}>", inner.tag_name().name())
        };
        return Err(SecurityError::ConfigError(format!(
            "security document element <{}> carries {} inside its value: a value is one run \
             of character data, and one split in parts is refused rather than read as one \
             of them",
            node.tag_name().name(),
            what
        )));
    }
    Ok(node.text())
}

/// Set an element read once: a second occurrence is an error naming it.
///
/// The previous parser let the last occurrence win, and two of its names
/// wrote the same variable, so `<enable_discovery_protection>` and
/// `<discovery_protection_kind>` silently overrode each other in document
/// order.
#[cfg(feature = "qos-loaders")]
fn set_once<T>(slot: &mut Option<T>, value: T, element: &str) -> Result<(), SecurityError> {
    if slot.is_some() {
        return Err(SecurityError::ConfigError(format!(
            "governance carries <{}> twice in one rule: which one applies would be a guess",
            element
        )));
    }
    *slot = Some(value);
    Ok(())
}

/// Read one `<topic_rule>` (Sec.9.4.1.2.6). Every element is required
/// (Sec.9.4.1.2.3, `TopicRule` is a sequence of seven elements, each
/// minOccurs 1) and none may appear twice.
#[cfg(feature = "qos-loaders")]
fn parse_topic_rule(node: &roxmltree::Node) -> Result<TopicRule, SecurityError> {
    let mut expression = None;
    let mut discovery = None;
    let mut liveliness = None;
    let mut read = None;
    let mut write = None;
    let mut metadata = None;
    let mut data = None;

    for child in node.children().filter(roxmltree::Node::is_element) {
        let name = child.tag_name().name();
        let text = || leaf_text(&child);
        match name {
            "topic_expression" => {
                let value = text()?.map(str::trim).unwrap_or("").to_string();
                if value.is_empty() {
                    return Err(SecurityError::ConfigError(
                        "governance <topic_expression> is empty: it would match no topic"
                            .to_string(),
                    ));
                }
                super::fnmatch::check_pattern(&value).map_err(SecurityError::ConfigError)?;
                set_once(&mut expression, value, name)?;
            }
            "enable_discovery_protection" => {
                set_once(&mut discovery, governance_bool(name, text()?)?, name)?;
            }
            "enable_liveliness_protection" => {
                set_once(&mut liveliness, governance_bool(name, text()?)?, name)?;
            }
            "enable_read_access_control" => {
                set_once(&mut read, governance_bool(name, text()?)?, name)?;
            }
            "enable_write_access_control" => {
                set_once(&mut write, governance_bool(name, text()?)?, name)?;
            }
            "metadata_protection_kind" => {
                set_once(&mut metadata, protection_kind(name, text()?)?, name)?;
            }
            "data_protection_kind" => {
                set_once(&mut data, basic_protection_kind(name, text()?)?, name)?;
            }
            other => {
                return Err(SecurityError::ConfigError(format!(
                    "governance <topic_rule> carries an element this release does not \
                     recognise: <{}>. It is refused rather than ignored - an unread security \
                     setting is indistinguishable from an absent one, and only one of those \
                     is safe",
                    other
                )));
            }
        }
    }

    let which = expression
        .as_deref()
        .map(|e| format!(" for \"{}\"", e))
        .unwrap_or_default();
    let missing = |element: &str| {
        SecurityError::ConfigError(format!(
            "governance <topic_rule>{} does not say <{}>: every element of a topic rule is \
             required (DDS-Security v1.1 9.4.1.2.3), and this release will not choose a \
             security setting on the operator's behalf",
            which, element
        ))
    };
    Ok(TopicRule {
        enable_discovery_protection: discovery
            .ok_or_else(|| missing("enable_discovery_protection"))?,
        enable_liveliness_protection: liveliness
            .ok_or_else(|| missing("enable_liveliness_protection"))?,
        enable_read_access_control: read.ok_or_else(|| missing("enable_read_access_control"))?,
        enable_write_access_control: write.ok_or_else(|| missing("enable_write_access_control"))?,
        metadata_protection_kind: metadata.ok_or_else(|| missing("metadata_protection_kind"))?,
        data_protection_kind: data.ok_or_else(|| missing("data_protection_kind"))?,
        topic_expression: expression.ok_or_else(|| missing("topic_expression"))?,
    })
}

/// Read one `<domain_rule>` (Sec.9.4.1.2.5).
#[cfg(feature = "qos-loaders")]
fn parse_domain_rule(node: &roxmltree::Node) -> Result<DomainRule, SecurityError> {
    let mut saw_domains = false;
    let mut domains = Vec::new();
    let mut domain_ranges = Vec::new();
    let mut allow_unauthenticated = None;
    let mut enable_join_access_control = None;
    let mut discovery = None;
    let mut liveliness = None;
    let mut rtps = None;
    let mut topic_rules: Option<Vec<TopicRule>> = None;
    // The shorthand's data protection, from <data_protection_kind> or the
    // older <encrypt_topics>.
    let mut shorthand_data = None;

    for child in node.children().filter(roxmltree::Node::is_element) {
        let name = child.tag_name().name();
        let text = || leaf_text(&child);
        match name {
            "domains" => {
                if saw_domains {
                    return Err(SecurityError::ConfigError(
                        "governance carries <domains> twice in one rule: which one applies \
                         would be a guess"
                            .to_string(),
                    ));
                }
                saw_domains = true;
                parse_domains(&child, &mut domains, &mut domain_ranges)?;
            }
            // `allow_unauthenticated` and `encrypt_discovery` / `encrypt_topics`
            // below are the names this project's security guide documented
            // before it documented the specification's, and stay readable.
            "allow_unauthenticated_participants" | "allow_unauthenticated" => {
                set_once(
                    &mut allow_unauthenticated,
                    governance_bool(name, text()?)?,
                    "allow_unauthenticated_participants",
                )?;
            }
            "enable_join_access_control" => {
                set_once(
                    &mut enable_join_access_control,
                    governance_bool(name, text()?)?,
                    name,
                )?;
            }
            "discovery_protection_kind" => {
                set_once(
                    &mut discovery,
                    protection_kind(name, text()?)?,
                    "discovery_protection_kind",
                )?;
            }
            "encrypt_discovery" => {
                let kind = if governance_bool(name, text()?)? {
                    ProtectionKind::Encrypt
                } else {
                    ProtectionKind::None
                };
                set_once(&mut discovery, kind, "discovery_protection_kind")?;
            }
            "liveliness_protection_kind" => {
                set_once(&mut liveliness, protection_kind(name, text()?)?, name)?;
            }
            "rtps_protection_kind" => {
                set_once(&mut rtps, protection_kind(name, text()?)?, name)?;
            }
            "topic_access_rules" => {
                let mut rules = Vec::new();
                for rule in child.children().filter(roxmltree::Node::is_element) {
                    if rule.tag_name().name() != "topic_rule" {
                        return Err(SecurityError::ConfigError(format!(
                            "governance <topic_access_rules> carries <{}>, which is not a \
                             <topic_rule>",
                            rule.tag_name().name()
                        )));
                    }
                    rules.push(parse_topic_rule(&rule)?);
                }
                if rules.is_empty() {
                    return Err(SecurityError::ConfigError(
                        "governance <topic_access_rules> holds no <topic_rule>: every topic \
                         of the domain would be refused (DDS-Security v1.1 9.4.1.2.7)"
                            .to_string(),
                    ));
                }
                set_once(&mut topic_rules, rules, name)?;
            }
            "data_protection_kind" => {
                set_once(
                    &mut shorthand_data,
                    basic_protection_kind(name, text()?)?,
                    "data_protection_kind",
                )?;
            }
            "encrypt_topics" => {
                let kind = if governance_bool(name, text()?)? {
                    BasicProtectionKind::Encrypt
                } else {
                    BasicProtectionKind::None
                };
                set_once(&mut shorthand_data, kind, "data_protection_kind")?;
            }
            "metadata_protection_kind"
            | "enable_discovery_protection"
            | "enable_liveliness_protection"
            | "enable_read_access_control"
            | "enable_write_access_control"
            | "topic_expression"
            | "topic_rule" => {
                return Err(SecurityError::ConfigError(format!(
                    "governance <{}> is an element of a <topic_rule> (DDS-Security v1.1 \
                     9.4.1.2.6), not of a <domain_rule>: write it inside \
                     <topic_access_rules><topic_rule>",
                    name
                )));
            }
            other => {
                return Err(SecurityError::ConfigError(format!(
                    "governance <domain_rule> carries an element this release does not \
                     recognise: <{}>. It is refused rather than ignored - an unread security \
                     setting is indistinguishable from an absent one, and only one of those \
                     is safe",
                    other
                )));
            }
        }
    }

    if domains.is_empty() && domain_ranges.is_empty() {
        return Err(SecurityError::ConfigError(
            "governance <domain_rule> names no domain: a rule that applies to nothing \
             protects nothing"
                .to_string(),
        ));
    }

    // No silent default on anything that decides a protection. An absent
    // element is an operator who has not made the decision, and this is not
    // the place to make it for them.
    let require = |present: bool, element: &str| {
        if present {
            Ok(())
        } else {
            Err(SecurityError::ConfigError(format!(
                "governance <domain_rule> does not say <{}>: this release will not choose a \
                 security setting on the operator's behalf",
                element
            )))
        }
    };
    require(
        allow_unauthenticated.is_some(),
        "allow_unauthenticated_participants",
    )?;
    require(
        enable_join_access_control.is_some(),
        "enable_join_access_control",
    )?;
    require(discovery.is_some(), "discovery_protection_kind")?;
    let discovery = discovery.unwrap_or(ProtectionKind::None);

    let (liveliness, rtps, topic_rules) =
        match (topic_rules, shorthand_data) {
            // The specification's form: every element of the XSD sequence is
            // required (Sec.9.4.1.2.3).
            (Some(rules), None) => {
                require(liveliness.is_some(), "liveliness_protection_kind")?;
                require(rtps.is_some(), "rtps_protection_kind")?;
                (
                    liveliness.unwrap_or(ProtectionKind::None),
                    rtps.unwrap_or(ProtectionKind::None),
                    rules,
                )
            }
            // The shorthand: one policy for every topic. Its liveliness and RTPS
            // kinds were always optional and read as NONE when absent.
            (None, Some(data)) => (
                liveliness.unwrap_or(ProtectionKind::None),
                rtps.unwrap_or(ProtectionKind::None),
                vec![TopicRule::shorthand(discovery, data)],
            ),
            (Some(_), Some(_)) => return Err(SecurityError::ConfigError(
                "governance <domain_rule> carries both <topic_access_rules> and a domain-level \
                 <data_protection_kind>: the per-topic rules say what protects each topic, and \
                 a second answer beside them is ambiguous. Put the data protection in each \
                 <topic_rule>"
                    .to_string(),
            )),
            (None, None) => {
                return Err(SecurityError::ConfigError(
                    "governance <domain_rule> says nothing about its topics: it carries neither \
                 <topic_access_rules> (DDS-Security v1.1 9.4.1.2.5.7) nor this release's \
                 domain-level <data_protection_kind> shorthand, and every topic would be \
                 refused"
                        .to_string(),
                ))
            }
        };

    let allow_unauthenticated = allow_unauthenticated.unwrap_or(false);
    // Table 27, is_rtps_protected: "If is_rtps_protected is TRUE then: (1)
    // allow_unauthenticated_participants must be FALSE."
    if allow_unauthenticated && rtps.is_protected() {
        return Err(SecurityError::ConfigError(
            "governance <allow_unauthenticated_participants> is TRUE while \
             <rtps_protection_kind> protects the RTPS messages: DDS-Security v1.1 Table 27 \
             requires it FALSE in that case"
                .to_string(),
        ));
    }

    Ok(DomainRule {
        domains,
        domain_ranges,
        allow_unauthenticated,
        enable_join_access_control: enable_join_access_control.unwrap_or(true),
        discovery_protection_kind: discovery,
        liveliness_protection_kind: liveliness,
        rtps_protection_kind: rtps,
        topic_rules,
    })
}

impl GovernanceConfig {
    /// Parse a DDS-Security governance document.
    ///
    /// Element names and structure are the specification's (DDS-Security v1.1
    /// section 9.4.1.2): domain rules evaluated in document order, the first
    /// one covering a domain applied to it, and within it the topic rules in
    /// document order, the first one matching a topic applied to it.
    ///
    /// Also read, because documents written against this project's own
    /// security guide exist: the shorthand `<domain_rule>` that carries a
    /// domain-level `<data_protection_kind>` and no `<topic_access_rules>`
    /// (see [`TopicRule::shorthand`]), and the older names
    /// `allow_unauthenticated`, `encrypt_discovery` and `encrypt_topics`.
    ///
    /// An element that is neither is an ERROR naming the element. The previous
    /// parser ended its match with `_ => {}`, so a governance file written to
    /// the specification parsed into a rule with every protection off and no
    /// diagnostic of any kind. "I did not understand that" and "that did not
    /// apply" are indistinguishable to an operator, and the difference between
    /// them is whether their traffic is protected.
    ///
    /// A document that asks for a protection this release does not apply is
    /// refused, naming the element and the kind (`refuse_unapplied`): see
    /// [`Self::parse_document`] for the document read without that check.
    pub fn parse(xml: &str) -> Result<Self, SecurityError> {
        let config = Self::parse_document(xml)?;
        #[cfg(feature = "qos-loaders")]
        for rule in &config.domain_rules {
            refuse_unapplied(rule)?;
        }
        Ok(config)
    }

    /// The governance document as the specification reads it, without asking
    /// whether this release applies what it requests. Used to check the
    /// reading itself against documents that ask for more than is applied,
    /// the specification's own example among them.
    pub(crate) fn parse_document(xml: &str) -> Result<Self, SecurityError> {
        #[cfg(feature = "qos-loaders")]
        {
            refuse_deep_nesting(xml, "governance")?;
            let doc = roxmltree::Document::parse(xml).map_err(|e| {
                SecurityError::ConfigError(format!("Failed to parse governance XML: {}", e))
            })?;

            let mut domain_rules = Vec::new();
            for node in doc.descendants() {
                if node.tag_name().name() == "domain_rule" {
                    domain_rules.push(parse_domain_rule(&node)?);
                }
            }

            if domain_rules.is_empty() {
                return Err(SecurityError::ConfigError(
                    "governance document carries no <domain_rule>: it grants nothing and \
                     protects nothing, which is never what an operator meant to write"
                        .to_string(),
                ));
            }

            Ok(Self { domain_rules })
        }

        #[cfg(not(feature = "qos-loaders"))]
        {
            let _ = xml;
            Err(SecurityError::ConfigError(
                "Governance XML parsing requires 'qos-loaders' feature".to_string(),
            ))
        }
    }
}

/// Read `<domains>`, in either of the two shapes the specification allows.
///
/// Inline text (`<domains>0</domains>`) or nested `<id>` / `<id_range>`.
/// Ranges are stored, never expanded - see `DomainRule::domain_ranges`.
#[cfg(feature = "qos-loaders")]
fn parse_domains(
    node: &roxmltree::Node,
    domains: &mut Vec<u32>,
    ranges: &mut Vec<(u32, u32)>,
) -> Result<(), SecurityError> {
    let mut saw_child = false;

    for child in node.children() {
        if !child.is_element() {
            continue;
        }
        saw_child = true;
        match child.tag_name().name() {
            "id" => {
                domains.push(parse_domain_id("id", leaf_text(&child)?)?);
            }
            "id_range" => {
                let mut lo = None;
                let mut hi = None;
                for bound in child.children() {
                    if !bound.is_element() {
                        continue;
                    }
                    match bound.tag_name().name() {
                        "min" => lo = Some(parse_domain_id("min", leaf_text(&bound)?)?),
                        "max" => hi = Some(parse_domain_id("max", leaf_text(&bound)?)?),
                        other => {
                            return Err(SecurityError::ConfigError(format!(
                                "governance <id_range> carries <{}>, which is not a bound",
                                other
                            )))
                        }
                    }
                }
                // The specification allows an open-ended range: <min> with no
                // <max> means "from min upwards". Storing bounds makes that
                // free to represent; expanding it never could.
                let lo = lo.ok_or_else(|| {
                    SecurityError::ConfigError("governance <id_range> has no <min>".to_string())
                })?;
                let hi = hi.unwrap_or(u32::MAX);
                if hi < lo {
                    return Err(SecurityError::ConfigError(format!(
                        "governance <id_range> runs backwards: min {} is above max {}",
                        lo, hi
                    )));
                }
                ranges.push((lo, hi));
            }
            other => {
                return Err(SecurityError::ConfigError(format!(
                    "governance <domains> carries <{}>, which is neither <id> nor <id_range>",
                    other
                )))
            }
        }
    }

    if !saw_child {
        domains.push(parse_domain_id("domains", leaf_text(node)?)?);
    }
    Ok(())
}

#[cfg(feature = "qos-loaders")]
fn parse_domain_id(element: &str, text: Option<&str>) -> Result<u32, SecurityError> {
    let raw = text.map(str::trim).unwrap_or("");
    raw.parse::<u32>().map_err(|_| {
        SecurityError::ConfigError(format!(
            "governance <{}> is \"{}\", which is not a domain id. \
             A domain that cannot be read is not a domain that can be protected",
            element, raw
        ))
    })
}

/// Permissions configuration (per-participant access rules)
#[derive(Debug, Clone)]
pub struct PermissionsConfig {
    pub grants: Vec<Grant>,
}

#[derive(Debug, Clone)]
pub struct Grant {
    pub subject_name: String,
    pub validity: Validity,
    /// The grant's `<allow_rule>` and `<deny_rule>` elements, in document
    /// order: "The rules are applied in the same order that appear in the
    /// document" (DDS-Security v1.1 Sec.9.4.1.3.2.3).
    pub rules: Vec<Rule>,
    /// The grant's `<default>` (DDS-Security v1.1 Sec.9.4.1.3.2.3): the
    /// decision when no rule matches, `true` for ALLOW. "If the default rule
    /// is not present, the implied default decision is DENY."
    pub default_allow: bool,
}

#[derive(Debug, Clone)]
pub struct Validity {
    pub not_before: String,
    pub not_after: String,
}

/// Whether a rule allows or denies what its criteria match
/// (Sec.9.4.1.3.2.3.1, 9.4.1.3.2.3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleKind {
    /// An `<allow_rule>`.
    Allow,
    /// A `<deny_rule>`.
    Deny,
}

/// One `<allow_rule>` or `<deny_rule>`.
#[derive(Debug, Clone)]
pub struct Rule {
    /// Allow or deny.
    pub kind: RuleKind,
    pub domains: Vec<u32>,
    /// Inclusive id ranges, stored as bounds and NEVER expanded.
    ///
    /// Same reasoning, and the same trap, as `DomainRule::domain_ranges`. This
    /// copy of the expansion survived the governance fix by a full day, which
    /// is the argument for both halves now going through `parse_domains`
    /// instead of each carrying its own reading of the same schema.
    pub domain_ranges: Vec<(u32, u32)>,
    /// The `<publish>` criteria, each evaluated on its own.
    pub publish: Vec<Criterion>,
    /// The `<subscribe>` criteria, each evaluated on its own.
    pub subscribe: Vec<Criterion>,
    /// The `<relay>` criteria, each evaluated on its own (Sec.9.4.1.3.2.3.1.2,
    /// 9.4.1.3.2.3.2.2). Never grants publish or subscribe by itself, and
    /// has an effect on the SUBSCRIBE side only: check_remote_datawriter
    /// (Sec.8.4.2.9.10, "the operation returns a Boolean value") has no
    /// relay concept, while check_remote_datareader alone sets
    /// `allow_relay_only` (Sec.8.4.2.9.11) on a match. That needs reduced,
    /// relay-only cryptographic material (Sec.9.5.3.3.4) this release
    /// cannot produce -- `RulesEngine` fails closed on a subscribe-side
    /// match instead, and ignores a publish-side one entirely, as if it
    /// were absent ([`RulesEngine::check_endpoint`]).
    pub relay: Vec<Criterion>,
}

/// One `<publish>`, `<subscribe>` (or `<relay>`) criterion: a topic
/// condition, a partition condition and a data tag condition, "All these
/// conditions must be met for the allowed action to apply"
/// (Sec.9.4.1.3.2.3.1.2). Evaluated on its own, never merged with another
/// criterion of the same rule.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Criterion {
    /// The `<topic>` expressions, POSIX fnmatch (Sec.9.4.1.3.2.3.1.3); one
    /// matching is enough.
    pub topics: Vec<String>,
    /// The `<partition>` expressions, POSIX fnmatch (Sec.9.4.1.3.2.3.1.4);
    /// `None` when the criterion has no `<partitions>` section: an allow
    /// rule then assumes the empty-string partition, a deny rule `*`
    /// (Sec.9.4.1.3.2.3.2.4).
    pub partitions: Option<Vec<String>>,
    /// The `<tag>` name/value pairs (Sec.9.4.1.3.2.3.1.5); `None` when the
    /// criterion has no `<data_tags>` section: an allow rule then assumes
    /// the empty set, a deny rule "the set of all possible tags"
    /// (Sec.9.4.1.3.2.3.2.5).
    pub data_tags: Option<Vec<crate::qos::data_tags::DataTag>>,
}

impl Rule {
    /// Whether this grant rule applies on `domain_id`.
    ///
    /// DDS-Security v1.1 section 9.4.1.3 scopes every allow_rule and deny_rule
    /// to the domains it names: a grant written for one domain must not be
    /// applied on every domain a participant happens to join, which is the
    /// opposite of what an operator writes a per-domain grant to express.
    #[must_use]
    pub fn covers(&self, domain_id: u32) -> bool {
        self.domains.contains(&domain_id)
            || self
                .domain_ranges
                .iter()
                .any(|(lo, hi)| domain_id >= *lo && domain_id <= *hi)
    }
}

impl PermissionsConfig {
    /// Parse permissions.xml
    pub fn parse(xml: &str) -> Result<Self, SecurityError> {
        #[cfg(feature = "qos-loaders")]
        {
            refuse_deep_nesting(xml, "permissions")?;
            let doc = roxmltree::Document::parse(xml).map_err(|e| {
                SecurityError::ConfigError(format!("Failed to parse permissions XML: {}", e))
            })?;

            let mut grants = Vec::new();

            for grant_node in doc.descendants() {
                if grant_node.tag_name().name() == "grant" {
                    let mut subject_name = String::new();
                    let mut validity = Validity {
                        not_before: String::new(),
                        not_after: String::new(),
                    };
                    let mut rules = Vec::new();
                    let mut default_allow: Option<bool> = None;

                    for child in grant_node.children() {
                        // Sec.9.4.1.3.2.3: "The default rule, if present,
                        // must appear after all allow and deny rules."
                        if default_allow.is_some()
                            && matches!(child.tag_name().name(), "allow_rule" | "deny_rule")
                        {
                            return Err(SecurityError::ConfigError(format!(
                                "permissions <{}> after <default>: the default rule must \
                                 appear after all allow and deny rules (DDS-Security v1.1 \
                                 Sec.9.4.1.3.2.3)",
                                child.tag_name().name()
                            )));
                        }
                        match child.tag_name().name() {
                            "subject_name" => {
                                if let Some(text) = leaf_text(&child)? {
                                    subject_name = text.trim().to_string();
                                }
                            }
                            "validity" => {
                                for v_child in child.children() {
                                    match v_child.tag_name().name() {
                                        "not_before" => {
                                            if let Some(text) = leaf_text(&v_child)? {
                                                validity.not_before = text.trim().to_string();
                                            }
                                        }
                                        "not_after" => {
                                            if let Some(text) = leaf_text(&v_child)? {
                                                validity.not_after = text.trim().to_string();
                                            }
                                        }
                                        _ => {}
                                    }
                                }
                            }
                            // A rule that does not read is an error, not a rule
                            // left out: a deny rule left out widens the grant.
                            "allow_rule" => rules.push(Self::parse_rule(&child, RuleKind::Allow)?),
                            "deny_rule" => rules.push(Self::parse_rule(&child, RuleKind::Deny)?),
                            "default" => {
                                if default_allow.is_some() {
                                    return Err(SecurityError::ConfigError(
                                        "permissions grant carries <default> twice: which one \
                                         applies would be a guess"
                                            .to_string(),
                                    ));
                                }
                                default_allow = Some(default_action(leaf_text(&child)?)?);
                            }
                            _ => {}
                        }
                    }

                    grants.push(Grant {
                        subject_name,
                        validity,
                        rules,
                        // "If the default rule is not present, the implied
                        // default decision is DENY."
                        default_allow: default_allow.unwrap_or(false),
                    });
                }
            }

            Ok(Self { grants })
        }

        #[cfg(not(feature = "qos-loaders"))]
        {
            Err(SecurityError::ConfigError(
                "Permissions XML parsing requires 'qos-loaders' feature".to_string(),
            ))
        }
    }

    #[cfg(feature = "qos-loaders")]
    fn parse_rule(node: &roxmltree::Node, kind: RuleKind) -> Result<Rule, SecurityError> {
        let mut domains = Vec::new();
        let mut domain_ranges = Vec::new();
        let mut publish = Vec::new();
        let mut subscribe = Vec::new();
        let mut relay = Vec::new();

        for child in node.children() {
            match child.tag_name().name() {
                "domains" => {
                    // The SAME reader the governance half uses. These were two
                    // copies of one schema, and only one of them was fixed
                    // when the expansion trap was found - this one still
                    // expanded `<id_range>` into a Vec clamped at 255, so a
                    // signed document could allocate about 17 GB and every
                    // legitimate domain id above 255 was silently dropped.
                    // Two copies of a parser are rarely symmetric; one cannot
                    // be.
                    parse_domains(&child, &mut domains, &mut domain_ranges)?;
                }
                // Each criterion is topics AND partitions AND data tags, and
                // is kept apart from the others (Sec.9.4.1.3.2.3.1.2): one
                // criterion's partitions never condition another's topics.
                "publish" => publish.push(parse_criterion(&child, "publish")?),
                "subscribe" => subscribe.push(parse_criterion(&child, "subscribe")?),
                // `<relay>` grants or denies the Allow/Deny Relay Action
                // (Sec.9.4.1.3.2.3.1.2, 9.4.1.3.2.3.2.2): kept in the model
                // like any other criterion - refusing the WHOLE document
                // over one grant's `<relay>` action broke shared,
                // multi-subject permission files, the specification's own
                // 9.4.1.4 example included. Per Sec.8.4.2.9.11, relay is an
                // OUTPUT of check_remote_datareader alone (`allow_relay_only`),
                // not a load-time validity gate; check_remote_datawriter
                // (Sec.8.4.2.9.10) has no relay concept at all. A relay
                // grant never grants publish or subscribe by itself
                // (`RulesEngine::criteria` never reads it); on the
                // subscribe side, a remote endpoint whose only matching
                // permission for the topic is relay is refused rather than
                // admitted with full access - HDDS has no routing-service
                // role and mints no relay_only cryptographic material
                // (Sec.9.5.3.3.4), so it fails closed instead of a silent
                // over-grant; on the publish side it has no effect at all,
                // exactly as if absent (`RulesEngine::check_endpoint`,
                // `RulesEngine::topic_scope`).
                "relay" => relay.push(parse_criterion(&child, "relay")?),
                // Not an element of the schema's Rule (Sec.9.4.1.3): the
                // schema puts it inside a criterion.
                "partitions" | "data_tags" => {
                    return Err(SecurityError::ConfigError(format!(
                        "permissions <{}> directly inside a rule: the schema puts it inside \
                         <publish>, <subscribe> or <relay> (DDS-Security v1.1 Sec.9.4.1.3)",
                        child.tag_name().name()
                    )));
                }
                _ => {}
            }
        }

        Ok(Rule {
            kind,
            domains,
            domain_ranges,
            publish,
            subscribe,
            relay,
        })
    }
}

/// Read one `<publish>`, `<subscribe>` or `<relay>` criterion
/// (Sec.9.4.1.3.2.3.1.2): exactly one `<topics>` holding at least one
/// expression, at most one `<partitions>` and one `<data_tags>` (the
/// schema's `Criteria`, an `xs:all`).
#[cfg(feature = "qos-loaders")]
fn parse_criterion(node: &roxmltree::Node, action: &str) -> Result<Criterion, SecurityError> {
    let mut topics: Option<Vec<String>> = None;
    let mut partitions: Option<Vec<String>> = None;
    let mut data_tags: Option<Vec<crate::qos::data_tags::DataTag>> = None;
    let twice = |name: &str| {
        SecurityError::ConfigError(format!(
            "permissions <{}> carries <{}> twice: which one applies would be a guess",
            action, name
        ))
    };
    for child in node.children().filter(roxmltree::Node::is_element) {
        match child.tag_name().name() {
            "topics" => {
                let mut list = Vec::new();
                // Two schema variants per DDS-Security spec:
                //   - Inline text:   <topics>Square</topics>
                //   - Nested elements: <topics><topic>*</topic></topics>
                collect_topics(&child, &mut list)?;
                set_once(&mut topics, list, "topics").map_err(|_| twice("topics"))?;
            }
            "partitions" => {
                let list = collect_partitions(&child, action)?;
                set_once(&mut partitions, list, "partitions").map_err(|_| twice("partitions"))?;
            }
            "data_tags" => {
                let list = collect_data_tags(&child, action)?;
                set_once(&mut data_tags, list, "data_tags").map_err(|_| twice("data_tags"))?;
            }
            _ => {}
        }
    }
    let topics = topics.filter(|list| !list.is_empty()).ok_or_else(|| {
        SecurityError::ConfigError(format!(
            "permissions <{}> without a <topics> expression: \"The topic condition section \
             must always be present\" (DDS-Security v1.1 Sec.9.4.1.3.2.3.1.3)",
            action
        ))
    })?;
    Ok(Criterion {
        topics,
        partitions,
        data_tags,
    })
}

/// The `<partition>` expressions of a `<partitions>` section
/// (Sec.9.4.1.3.2.3.1.4), POSIX fnmatch like the topic expressions, an
/// empty one being the default (empty string) partition. At least one.
#[cfg(feature = "qos-loaders")]
fn collect_partitions(node: &roxmltree::Node, action: &str) -> Result<Vec<String>, SecurityError> {
    let mut out = Vec::new();
    for child in node.children().filter(roxmltree::Node::is_element) {
        if child.tag_name().name() == "partition" {
            let expression = leaf_text(&child)?.unwrap_or("").trim().to_string();
            super::fnmatch::check_pattern(&expression).map_err(SecurityError::ConfigError)?;
            out.push(expression);
        }
    }
    if out.is_empty() {
        return Err(SecurityError::ConfigError(format!(
            "permissions <partitions> in <{}> names no <partition> (DDS-Security v1.1 \
             Sec.9.4.1.3.2.3.1.4)",
            action
        )));
    }
    Ok(out)
}

/// The `<tag>` name/value pairs of a `<data_tags>` section
/// (Sec.9.4.1.3.2.3.1.5): each `<tag>` one `<name>` and one `<value>`, at
/// least one tag.
#[cfg(feature = "qos-loaders")]
fn collect_data_tags(
    node: &roxmltree::Node,
    action: &str,
) -> Result<Vec<crate::qos::data_tags::DataTag>, SecurityError> {
    let mut out = Vec::new();
    for tag in node.children().filter(roxmltree::Node::is_element) {
        if tag.tag_name().name() != "tag" {
            continue;
        }
        let mut name: Option<String> = None;
        let mut value: Option<String> = None;
        for part in tag.children().filter(roxmltree::Node::is_element) {
            let text = leaf_text(&part)?.unwrap_or("").trim().to_string();
            let slot = match part.tag_name().name() {
                "name" => &mut name,
                "value" => &mut value,
                _ => continue,
            };
            if slot.replace(text).is_some() {
                return Err(SecurityError::ConfigError(format!(
                    "permissions <tag> in <{}> carries <{}> twice: which one applies would                      be a guess",
                    action,
                    part.tag_name().name()
                )));
            }
        }
        let (Some(name), Some(value)) = (name, value) else {
            return Err(SecurityError::ConfigError(format!(
                "permissions <tag> in <{}> without one <name> and one <value> (DDS-Security \
                 v1.1 Sec.9.4.1.3.2.3.1.5)",
                action
            )));
        };
        out.push(crate::qos::data_tags::DataTag { name, value });
    }
    if out.is_empty() {
        return Err(SecurityError::ConfigError(format!(
            "permissions <data_tags> in <{}> holds no <tag> (DDS-Security v1.1 \
             Sec.9.4.1.3.2.3.1.5)",
            action
        )));
    }
    Ok(out)
}

/// Read a grant's `<default>` (Sec.9.4.1.3.2.3, `DefaultAction`): `true` for
/// ALLOW, `false` for DENY, read case-insensitively as the governance
/// booleans are. Anything else is an error naming the value.
#[cfg(feature = "qos-loaders")]
fn default_action(text: Option<&str>) -> Result<bool, SecurityError> {
    match text.map(str::trim) {
        Some(v) if v.eq_ignore_ascii_case("ALLOW") => Ok(true),
        Some(v) if v.eq_ignore_ascii_case("DENY") => Ok(false),
        other => Err(SecurityError::ConfigError(format!(
            "permissions <default> is \"{}\": write ALLOW or DENY",
            other.unwrap_or("")
        ))),
    }
}

/// Collect topic strings from a `<topics>` node.
///
/// Handles two XML variants per the DDS-Security permissions schema:
///   - Inline text:      `<topics>Square</topics>` -> pushes `"Square"`
///   - Nested elements:  `<topics><topic>*</topic></topics>` -> pushes `"*"`
///
/// The inline-text form is common in handcrafted files; the nested-element form
/// is used by the OMG interop repository.
#[cfg(feature = "qos-loaders")]
fn collect_topics(
    topics_node: &roxmltree::Node,
    out: &mut Vec<String>,
) -> Result<(), SecurityError> {
    // Check for nested <topic> children first.
    let mut found_child = false;
    for child in topics_node.children() {
        if child.tag_name().name() == "topic" {
            if let Some(text) = leaf_text(&child)? {
                let t = text.trim().to_string();
                if !t.is_empty() {
                    // Matched as fnmatch (Sec.9.4.1.3.2.3.1.3), refused at load
                    // where this matcher would read it otherwise than POSIX.
                    super::fnmatch::check_pattern(&t).map_err(SecurityError::ConfigError)?;
                    out.push(t);
                    found_child = true;
                }
            }
        }
    }

    // Fall back to inline text if no <topic> children were found: only for a
    // <topics> holding no element, whose content is then a value.
    if !found_child && !topics_node.children().any(|child| child.is_element()) {
        if let Some(text) = leaf_text(topics_node)? {
            let t = text.trim().to_string();
            if !t.is_empty() {
                super::fnmatch::check_pattern(&t).map_err(SecurityError::ConfigError)?;
                out.push(t);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The topic expressions of `criteria`, in order.
    fn topics_of(criteria: &[Criterion]) -> Vec<String> {
        criteria
            .iter()
            .flat_map(|criterion| criterion.topics.iter().cloned())
            .collect()
    }

    /// Access control is only as good as the identity of the endpoint it
    /// judges: a topic rule that checks permissions while discovery, metadata
    /// and data all travel unprotected (Sec.9.4.1.2.6.2, .6.6, .6.7) is
    /// named, and a rule with any one of the three protections is not.
    #[test]
    #[cfg(feature = "qos-loaders")]
    fn access_control_with_nothing_authenticated_is_named() {
        let rule = |expression: &str, read: bool, write: bool, discovery: bool, meta, data| {
            format!(
                "<topic_rule><topic_expression>{}</topic_expression>\
                 <enable_discovery_protection>{}</enable_discovery_protection>\
                 <enable_liveliness_protection>false</enable_liveliness_protection>\
                 <enable_read_access_control>{}</enable_read_access_control>\
                 <enable_write_access_control>{}</enable_write_access_control>\
                 <metadata_protection_kind>{}</metadata_protection_kind>\
                 <data_protection_kind>{}</data_protection_kind></topic_rule>",
                expression, discovery, read, write, meta, data
            )
        };
        let xml = format!(
            "<dds><domain_access_rules><domain_rule><domains>7</domains>\
             <allow_unauthenticated_participants>false</allow_unauthenticated_participants>\
             <enable_join_access_control>true</enable_join_access_control>\
             <discovery_protection_kind>NONE</discovery_protection_kind>\
             <liveliness_protection_kind>NONE</liveliness_protection_kind>\
             <rtps_protection_kind>NONE</rtps_protection_kind>\
             <topic_access_rules>{}{}{}{}{}</topic_access_rules>\
             </domain_rule></domain_access_rules></dds>",
            rule("read/*", true, false, false, "NONE", "NONE"),
            rule("write/*", false, true, false, "NONE", "NONE"),
            rule("discovered/*", true, true, true, "NONE", "NONE"),
            rule("sealed/*", true, true, false, "NONE", "ENCRYPT"),
            rule("open/*", false, false, false, "NONE", "NONE"),
        );
        let config = GovernanceConfig::parse(&xml).expect("governance parses");
        let warnings = config.unauthenticated_access_control_warnings(7);
        assert_eq!(warnings.len(), 2, "{:?}", warnings);
        assert!(warnings[0].contains("'read/*'"), "{}", warnings[0]);
        assert!(warnings[1].contains("'write/*'"), "{}", warnings[1]);
        assert!(config.unauthenticated_access_control_warnings(8).is_empty());
    }

    /// The names this project's own security guide documents still work.
    #[test]
    #[cfg(feature = "qos-loaders")]
    fn test_parse_governance_xml() {
        let xml = r#"<?xml version="1.0"?>
<governance>
  <domain_rule>
    <domains>0</domains>
    <allow_unauthenticated>false</allow_unauthenticated>
    <enable_join_access_control>true</enable_join_access_control>
    <encrypt_discovery>true</encrypt_discovery>
    <encrypt_topics>true</encrypt_topics>
  </domain_rule>
</governance>"#;

        let config = GovernanceConfig::parse(xml).unwrap();
        assert_eq!(config.domain_rules.len(), 1);
        assert_eq!(config.domain_rules[0].domains, vec![0]);
        assert!(!config.domain_rules[0].allow_unauthenticated);
        assert_eq!(
            config.domain_rules[0].discovery_protection_kind,
            ProtectionKind::Encrypt
        );
        assert_eq!(
            config.domain_rules[0].topic_rules,
            vec![TopicRule::shorthand(
                ProtectionKind::Encrypt,
                BasicProtectionKind::Encrypt
            )]
        );
        assert!(config.domain_rules[0].enable_join_access_control);
    }

    /// The specification's names produce the same rule. Before this release
    /// they produced a rule with every protection off, silently: none of the
    /// four names the parser knew appears in a spec-shaped document, so each
    /// one fell through `_ => {}`.
    #[test]
    #[cfg(feature = "qos-loaders")]
    fn a_spec_shaped_governance_document_is_read_the_same_way() {
        let xml = r#"<?xml version="1.0" encoding="utf-8"?>
<dds>
  <domain_access_rules>
    <domain_rule>
      <domains>0</domains>
      <allow_unauthenticated_participants>false</allow_unauthenticated_participants>
      <enable_join_access_control>true</enable_join_access_control>
      <discovery_protection_kind>ENCRYPT</discovery_protection_kind>
      <liveliness_protection_kind>NONE</liveliness_protection_kind>
      <rtps_protection_kind>NONE</rtps_protection_kind>
      <data_protection_kind>ENCRYPT</data_protection_kind>
    </domain_rule>
  </domain_access_rules>
</dds>"#;

        let config = GovernanceConfig::parse(xml).expect("a spec document must parse");
        assert_eq!(config.domain_rules.len(), 1);
        let rule = &config.domain_rules[0];
        assert!(!rule.allow_unauthenticated);
        assert!(rule.enable_join_access_control);
        assert_eq!(
            rule.discovery_protection_kind,
            ProtectionKind::Encrypt,
            "ENCRYPT must not read as off"
        );
        assert_eq!(
            rule.topic_rules[0].data_protection_kind,
            BasicProtectionKind::Encrypt,
            "ENCRYPT must not read as off"
        );
    }

    /// An element a `<topic_rule>` does not define is refused by name, as at
    /// the domain level.
    ///
    /// The previous release refused `<topic_access_rules>` whole, because it
    /// enforced none of it; before that it looked at the element's TEXT, and
    /// an element carrying children has none, so a block full of real rules
    /// was waved through as asking for nothing. Per-topic rules are read now,
    /// and what is unknown inside them is still refused, never skipped.
    #[test]
    #[cfg(feature = "qos-loaders")]
    fn an_unknown_topic_rule_element_is_refused_by_name() {
        let xml = r#"<?xml version="1.0"?>
<governance>
  <domain_rule>
    <domains>0</domains>
    <allow_unauthenticated_participants>false</allow_unauthenticated_participants>
    <enable_join_access_control>true</enable_join_access_control>
    <discovery_protection_kind>NONE</discovery_protection_kind>
    <liveliness_protection_kind>NONE</liveliness_protection_kind>
    <rtps_protection_kind>NONE</rtps_protection_kind>
    <topic_access_rules>
      <topic_rule>
        <topic_expression>*</topic_expression>
        <enable_data_protection>true</enable_data_protection>
      </topic_rule>
    </topic_access_rules>
  </domain_rule>
</governance>"#;

        let err = GovernanceConfig::parse(xml).expect_err("an unknown element must be refused");
        assert!(
            format!("{}", err).contains("enable_data_protection"),
            "the error must name the element, got: {}",
            err
        );
    }

    /// The example `docs/security-guide.md` tells an operator to write, parsed
    /// verbatim.
    ///
    /// The guide taught a dialect with three element names that appear in no
    /// DDS-Security document, for as long as the parser only understood those.
    /// Someone following it got a participant with every protection off and no
    /// diagnostic. A documentation example is a promise; this test is what
    /// makes it one that cannot rot silently.
    #[test]
    #[cfg(feature = "qos-loaders")]
    fn the_security_guide_example_parses() {
        let xml = r#"<?xml version="1.0"?>
<governance>
  <domain_rule>
    <domains>0</domains>
    <allow_unauthenticated_participants>false</allow_unauthenticated_participants>
    <enable_join_access_control>true</enable_join_access_control>
    <discovery_protection_kind>ENCRYPT</discovery_protection_kind>
    <data_protection_kind>ENCRYPT</data_protection_kind>
  </domain_rule>
</governance>"#;

        let config = GovernanceConfig::parse(xml).expect("the documented example must parse");
        let rule = &config.domain_rules[0];
        assert!(rule.covers(0));
        assert!(!rule.allow_unauthenticated);
        assert!(rule.enable_join_access_control);
        assert_eq!(rule.discovery_protection_kind, ProtectionKind::Encrypt);
        assert_eq!(
            rule.topic_rules[0].data_protection_kind,
            BasicProtectionKind::Encrypt
        );
    }

    /// The domain-range example from the same guide, including the claim that
    /// a single id and a range can sit side by side.
    #[test]
    #[cfg(feature = "qos-loaders")]
    fn the_security_guide_domain_range_example_parses() {
        let xml = r#"<?xml version="1.0"?>
<governance>
  <domain_rule>
    <domains>
      <id>0</id>
      <id_range><min>10</min><max>20</max></id_range>
    </domains>
    <allow_unauthenticated_participants>false</allow_unauthenticated_participants>
    <enable_join_access_control>true</enable_join_access_control>
    <discovery_protection_kind>NONE</discovery_protection_kind>
    <data_protection_kind>NONE</data_protection_kind>
  </domain_rule>
</governance>"#;

        let config = GovernanceConfig::parse(xml).expect("the documented range example must parse");
        let rule = &config.domain_rules[0];
        assert_eq!(rule.domains, vec![0]);
        assert_eq!(rule.domain_ranges, vec![(10, 20)]);
        assert!(rule.covers(0));
        assert!(rule.covers(10));
        assert!(rule.covers(15));
        assert!(rule.covers(20));
        assert!(!rule.covers(9));
        assert!(!rule.covers(21));
        assert!(!rule.covers(1));
    }

    /// And the guide's claim that `<max>` may be omitted.
    #[test]
    #[cfg(feature = "qos-loaders")]
    fn an_open_ended_domain_range_runs_to_the_top() {
        let xml = r#"<?xml version="1.0"?>
<governance>
  <domain_rule>
    <domains><id_range><min>100</min></id_range></domains>
    <allow_unauthenticated_participants>false</allow_unauthenticated_participants>
    <enable_join_access_control>true</enable_join_access_control>
    <discovery_protection_kind>NONE</discovery_protection_kind>
    <data_protection_kind>NONE</data_protection_kind>
  </domain_rule>
</governance>"#;

        let config = GovernanceConfig::parse(xml).expect("an open-ended range must parse");
        let rule = &config.domain_rules[0];
        assert_eq!(rule.domain_ranges, vec![(100, u32::MAX)]);
        assert!(!rule.covers(99));
        assert!(rule.covers(100));
        assert!(rule.covers(u32::MAX));
    }

    /// An element nobody reads is refused by name. This is the whole policy in
    /// one assertion: "I did not understand that" and "that did not apply"
    /// look identical to an operator, and only one of them leaves them
    /// protected.
    #[test]
    #[cfg(feature = "qos-loaders")]
    fn an_unrecognised_governance_element_is_an_error_that_names_it() {
        let xml = r#"<?xml version="1.0"?>
<governance>
  <domain_rule>
    <domains>0</domains>
    <allow_unauthenticated_participants>false</allow_unauthenticated_participants>
    <enable_join_access_control>true</enable_join_access_control>
    <discovery_protection_kind>NONE</discovery_protection_kind>
    <data_protection_kind>NONE</data_protection_kind>
    <enable_topic_teleportation>true</enable_topic_teleportation>
  </domain_rule>
</governance>"#;

        let err = GovernanceConfig::parse(xml).expect_err("an unknown element must be refused");
        assert!(
            format!("{}", err).contains("enable_topic_teleportation"),
            "the error must name the element, got: {}",
            err
        );
    }

    /// Every discovery protection kind without origin authentication is
    /// read and applied: SIGN is not rounded to anything, it is AES-GMAC on
    /// the secure discovery writers (DDS-Security v1.1 9.4.1.2.1,
    /// 9.5.3.3.4.5).
    #[test]
    #[cfg(feature = "qos-loaders")]
    fn every_discovery_protection_kind_is_read() {
        for kind in [
            ProtectionKind::None,
            ProtectionKind::Sign,
            ProtectionKind::Encrypt,
        ] {
            let xml = format!(
                r#"<?xml version="1.0"?>
<governance>
  <domain_rule>
    <domains>0</domains>
    <allow_unauthenticated_participants>false</allow_unauthenticated_participants>
    <enable_join_access_control>true</enable_join_access_control>
    <discovery_protection_kind>{}</discovery_protection_kind>
    <data_protection_kind>NONE</data_protection_kind>
  </domain_rule>
</governance>"#,
                kind.as_xml()
            );
            let config = GovernanceConfig::parse(&xml).expect("applied");
            assert_eq!(config.domain_rules[0].discovery_protection_kind, kind);
            assert_eq!(
                config.domain_rules[0].topic_rules[0].enable_discovery_protection,
                kind != ProtectionKind::None,
                "the shorthand protects discovery whenever the kind does"
            );
        }
    }

    /// A discovery protection kind with origin authentication is refused at
    /// load, naming Table 70: its receiver-specific keys are per matched
    /// remote reader, and the secure discovery writers announce one key
    /// material per writer.
    ///
    /// Mutant: the `is_origin_authenticated` check removed from
    /// `refuse_unapplied` fails both rows.
    #[test]
    #[cfg(feature = "qos-loaders")]
    fn discovery_origin_authentication_is_refused_at_load() {
        for kind in [
            ProtectionKind::SignWithOriginAuthentication,
            ProtectionKind::EncryptWithOriginAuthentication,
        ] {
            let xml = format!(
                r#"<?xml version="1.0"?>
<governance>
  <domain_rule>
    <domains>0</domains>
    <allow_unauthenticated_participants>false</allow_unauthenticated_participants>
    <enable_join_access_control>true</enable_join_access_control>
    <discovery_protection_kind>{}</discovery_protection_kind>
    <data_protection_kind>NONE</data_protection_kind>
  </domain_rule>
</governance>"#,
                kind.as_xml()
            );
            GovernanceConfig::parse_document(&xml).expect("the document itself is valid");
            let err = GovernanceConfig::parse(&xml).expect_err("refused");
            let text = err.to_string();
            assert!(text.contains("discovery_protection_kind"), "{}", text);
            assert!(text.contains(kind.as_xml()), "{}", text);
            assert!(text.contains("Table 70"), "{}", text);
            assert!(
                text.contains("register_matched_remote_datareader"),
                "{}",
                text
            );
        }
    }

    /// `rtps_protection_kind` is not enforced here. Asking for nothing is
    /// accepted; asking for something is refused, because ignoring it would
    /// leave an operator believing in a protection nobody applies.
    #[test]
    #[cfg(feature = "qos-loaders")]
    fn an_unenforced_element_passes_at_none_and_is_refused_otherwise() {
        let doc = |rtps: &str| {
            format!(
                r#"<?xml version="1.0"?>
<governance>
  <domain_rule>
    <domains>0</domains>
    <allow_unauthenticated_participants>false</allow_unauthenticated_participants>
    <enable_join_access_control>true</enable_join_access_control>
    <discovery_protection_kind>NONE</discovery_protection_kind>
    <data_protection_kind>NONE</data_protection_kind>
    <rtps_protection_kind>{}</rtps_protection_kind>
  </domain_rule>
</governance>"#,
                rtps
            )
        };

        GovernanceConfig::parse(&doc("NONE")).expect("NONE asks for nothing and must be accepted");
        let err = GovernanceConfig::parse(&doc("ENCRYPT"))
            .expect_err("a protection we do not apply must not be accepted");
        assert!(format!("{}", err).contains("rtps_protection_kind"));
    }

    /// A signed document may carry
    /// <max>4294967295</max>; a parser must not expand it (about 17 GB
    /// of u32) nor clamp it to 255, silently discarding every legitimate id
    /// above 255. Bounds are stored, so neither happens.
    #[test]
    #[cfg(feature = "qos-loaders")]
    fn a_full_domain_range_is_stored_not_expanded() {
        let xml = r#"<?xml version="1.0"?>
<governance>
  <domain_rule>
    <domains>
      <id_range><min>0</min><max>4294967295</max></id_range>
    </domains>
    <allow_unauthenticated_participants>false</allow_unauthenticated_participants>
    <enable_join_access_control>true</enable_join_access_control>
    <discovery_protection_kind>NONE</discovery_protection_kind>
    <data_protection_kind>NONE</data_protection_kind>
  </domain_rule>
</governance>"#;

        let config = GovernanceConfig::parse(xml).expect("a full range must parse");
        let rule = &config.domain_rules[0];
        assert!(rule.domains.is_empty(), "nothing may be expanded");
        assert_eq!(rule.domain_ranges, vec![(0, u32::MAX)]);
        // And an id above the old 255 clamp is covered, which it was not.
        assert!(rule.covers(0));
        assert!(rule.covers(229));
        assert!(rule.covers(1000));
        assert!(rule.covers(u32::MAX));
    }

    /// A boolean that is not a boolean is an error, not a silent false. The
    /// previous parser read `TRUE` through `text.trim() == "true"` and turned
    /// a protection ON into a protection OFF with no diagnostic.
    ///
    /// `TRUE` itself is a boolean: the specification's prose says these
    /// elements "may take the binary values TRUE or FALSE" (Sec.9.4.1.2.5.2)
    /// and its example document writes `TRUE`. `yes` is not.
    #[test]
    #[cfg(feature = "qos-loaders")]
    fn a_misspelled_boolean_is_refused_rather_than_read_as_false() {
        let doc = |value: &str| {
            format!(
                r#"<?xml version="1.0"?>
<governance>
  <domain_rule>
    <domains>0</domains>
    <allow_unauthenticated_participants>{}</allow_unauthenticated_participants>
    <enable_join_access_control>true</enable_join_access_control>
    <discovery_protection_kind>NONE</discovery_protection_kind>
    <data_protection_kind>NONE</data_protection_kind>
  </domain_rule>
</governance>"#,
                value
            )
        };

        for no in ["yes", "on", "", "truee"] {
            let err = GovernanceConfig::parse(&doc(no)).expect_err("not an xs:boolean");
            assert!(
                format!("{}", err).contains("allow_unauthenticated_participants"),
                "{:?}: {}",
                no,
                err
            );
        }
        for (text, value) in [
            ("TRUE", true),
            ("true", true),
            ("1", true),
            ("FALSE", false),
            ("false", false),
            ("0", false),
            ("\n   TRUE\n", true),
        ] {
            let config = GovernanceConfig::parse(&doc(text)).expect("a boolean");
            assert_eq!(
                config.domain_rules[0].allow_unauthenticated, value,
                "{:?}",
                text
            );
        }
    }

    /// The governance document the `access_control` sample prints, verbatim.
    ///
    /// One document, four files: `sdk/samples/05_security/rust/src/bin/
    /// access_control.rs`, `c/access_control.c`, `cpp/access_control.cpp` and
    /// `python/access_control.py` all print exactly these lines, so one test
    /// covers all four.
    ///
    /// Every one of them used to print a `<topic_access_rules>` block with a
    /// `<topic_rule>` inside and omit elements the parser requires. The C
    /// version additionally abbreviated its closing tags to `</..>`, so what it
    /// printed was not well-formed XML at all. A sample that prints a document
    /// the library refuses is a defect that only shows up on the reader.
    #[test]
    #[cfg(feature = "qos-loaders")]
    fn the_access_control_sample_governance_parses() {
        let xml = r#"  <domain_access_rules>
    <domain_rule>
      <domains><id>0</id></domains>
      <allow_unauthenticated_participants>false</allow_unauthenticated_participants>
      <enable_join_access_control>true</enable_join_access_control>
      <discovery_protection_kind>ENCRYPT</discovery_protection_kind>
      <data_protection_kind>ENCRYPT</data_protection_kind>
    </domain_rule>
  </domain_access_rules>"#;

        let config = GovernanceConfig::parse(xml).expect("the sample's own document must parse");
        let rule = &config.domain_rules[0];
        assert!(rule.covers(0));
        assert!(!rule.allow_unauthenticated);
        assert!(rule.enable_join_access_control);
        assert_eq!(rule.discovery_protection_kind, ProtectionKind::Encrypt);
        assert_eq!(
            rule.topic_rules[0].data_protection_kind,
            BasicProtectionKind::Encrypt
        );
    }

    /// The "Governance Document Example" of `sdk/samples/05_security/README.md`.
    ///
    /// It carried `<liveliness_protection_kind>SIGN</...>` and a
    /// `<topic_access_rules>` block, and stated its data protection only inside
    /// the topic rule - so the `<domain_rule>` itself never said what it
    /// protected. Three separate refusals in one example.
    #[test]
    #[cfg(feature = "qos-loaders")]
    fn the_security_sample_readme_example_parses() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<dds xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <domain_access_rules>
    <domain_rule>
      <domains><id>0</id></domains>
      <allow_unauthenticated_participants>false</allow_unauthenticated_participants>
      <enable_join_access_control>true</enable_join_access_control>
      <discovery_protection_kind>ENCRYPT</discovery_protection_kind>
      <data_protection_kind>ENCRYPT</data_protection_kind>
    </domain_rule>
  </domain_access_rules>
</dds>"#;

        let config = GovernanceConfig::parse(xml).expect("the README example must parse");
        let rule = &config.domain_rules[0];
        assert!(rule.covers(0));
        assert!(!rule.allow_unauthenticated);
        assert!(rule.enable_join_access_control);
        assert_eq!(rule.discovery_protection_kind, ProtectionKind::Encrypt);
        assert_eq!(
            rule.topic_rules[0].data_protection_kind,
            BasicProtectionKind::Encrypt
        );
    }

    /// The governance rule the `secure_discovery` sample documents and prints.
    ///
    /// One document, four files again: the module doc comment and the printed
    /// output of `sdk/samples/05_security/rust/src/bin/secure_discovery.rs`,
    /// plus `c/secure_discovery.c`, `cpp/secure_discovery.cpp` and
    /// `python/secure_discovery.py`.
    ///
    /// What they printed was three elements, two of which are not among the
    /// five a `<domain_rule>` requires, including
    /// `<enable_liveliness_protection>true</...>` - an element this release
    /// does not enforce, asking for something. The sample about protecting
    /// discovery was teaching a document that could not be loaded.
    #[test]
    #[cfg(feature = "qos-loaders")]
    fn the_secure_discovery_sample_governance_parses() {
        let xml = r#"<domain_rule>
  <domains><id>0</id></domains>
  <allow_unauthenticated_participants>false</allow_unauthenticated_participants>
  <enable_join_access_control>true</enable_join_access_control>
  <discovery_protection_kind>ENCRYPT</discovery_protection_kind>
  <data_protection_kind>ENCRYPT</data_protection_kind>
</domain_rule>"#;

        let config = GovernanceConfig::parse(xml).expect("the secure_discovery rule must parse");
        let rule = &config.domain_rules[0];
        assert!(rule.covers(0));
        assert!(!rule.allow_unauthenticated);
        assert!(rule.enable_join_access_control);
        assert_eq!(rule.discovery_protection_kind, ProtectionKind::Encrypt);
        assert_eq!(
            rule.topic_rules[0].data_protection_kind,
            BasicProtectionKind::Encrypt
        );
    }

    /// The governance document `sdk/samples/05_security/certs/generate_certs.sh`
    /// writes and signs, verbatim.
    ///
    /// This is the one that mattered most. The script did not merely document a
    /// shape - it produced `governance.xml`, signed it into `governance.p7s`
    /// with the permissions CA, and verified the signature, all successfully,
    /// while the document itself named three of the five required elements. The
    /// artefact an operator would hand to HDDS was generated, signed and
    /// refused. A signature over a document the parser rejects proves only that
    /// nothing ever parsed it.
    #[test]
    #[cfg(feature = "qos-loaders")]
    fn the_sample_certificate_generator_governance_parses() {
        let xml = r#"<?xml version="1.0" encoding="utf-8"?>
<dds>
  <domain_access_rules>
    <domain_rule>
      <domains>0</domains>
      <allow_unauthenticated_participants>false</allow_unauthenticated_participants>
      <enable_join_access_control>true</enable_join_access_control>
      <discovery_protection_kind>ENCRYPT</discovery_protection_kind>
      <data_protection_kind>ENCRYPT</data_protection_kind>
    </domain_rule>
  </domain_access_rules>
</dds>"#;

        let config = GovernanceConfig::parse(xml).expect("the generated document must parse");
        let rule = &config.domain_rules[0];
        assert_eq!(rule.domains, vec![0]);
        assert!(rule.covers(0));
        assert!(
            !rule.covers(1),
            "the script pins domain 0 and only domain 0"
        );
        assert!(!rule.allow_unauthenticated);
        assert!(rule.enable_join_access_control);
        assert_eq!(rule.discovery_protection_kind, ProtectionKind::Encrypt);
        assert_eq!(
            rule.topic_rules[0].data_protection_kind,
            BasicProtectionKind::Encrypt
        );
    }

    /// The governance example of `docs/guides/security/access-control.md`.
    ///
    /// It nested a `<topic_rule>` directly in the `<domain_rule>`, which is not
    /// where the specification puts one and is not an element this parser
    /// knows; it asked for `<enable_liveliness_protection>`, which this release
    /// does not enforce; and it named neither `<enable_join_access_control>`
    /// nor any data protection. The guide's own subject is access control, and
    /// the element that turns access control on was the one it left out.
    #[test]
    #[cfg(feature = "qos-loaders")]
    fn the_access_control_guide_example_parses() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<governance>
    <domain_rule>
        <domains><id>0</id></domains>
        <allow_unauthenticated_participants>false</allow_unauthenticated_participants>
        <enable_join_access_control>true</enable_join_access_control>
        <discovery_protection_kind>ENCRYPT</discovery_protection_kind>
        <data_protection_kind>ENCRYPT</data_protection_kind>
    </domain_rule>
</governance>"#;

        let config = GovernanceConfig::parse(xml).expect("the guide example must parse");
        let rule = &config.domain_rules[0];
        assert!(rule.covers(0));
        assert!(!rule.allow_unauthenticated);
        assert!(
            rule.enable_join_access_control,
            "an access-control guide must turn access control on"
        );
        assert_eq!(rule.discovery_protection_kind, ProtectionKind::Encrypt);
        assert_eq!(
            rule.topic_rules[0].data_protection_kind,
            BasicProtectionKind::Encrypt
        );
    }

    // ---- DDS-Security v1.1 Sec.9.4.1.2: topic rules and attributes ----

    use crate::security::access::attributes::{
        EndpointSecurityAttributes, ParticipantSecurityAttributes,
    };

    /// The example document of Sec.9.4.1.2.8 (see the fixture's header for
    /// its two repairs).
    const SPEC_EXAMPLE: &str = include_str!("../fixtures/governance_spec_example.xml");

    /// A spec-form `<domain_rule>` for domain 7 around `topics`, with the
    /// participant kinds given.
    fn spec_rule(discovery: &str, liveliness: &str, rtps: &str, topics: &str) -> String {
        format!(
            r#"<dds><domain_access_rules><domain_rule>
  <domains><id>7</id></domains>
  <allow_unauthenticated_participants>FALSE</allow_unauthenticated_participants>
  <enable_join_access_control>TRUE</enable_join_access_control>
  <discovery_protection_kind>{}</discovery_protection_kind>
  <liveliness_protection_kind>{}</liveliness_protection_kind>
  <rtps_protection_kind>{}</rtps_protection_kind>
  <topic_access_rules>{}</topic_access_rules>
</domain_rule></domain_access_rules></dds>"#,
            discovery, liveliness, rtps, topics
        )
    }

    fn topic_rule(
        expression: &str,
        discovery: bool,
        liveliness: bool,
        read: bool,
        write: bool,
        metadata: &str,
        data: &str,
    ) -> String {
        format!(
            r#"<topic_rule>
  <topic_expression>{}</topic_expression>
  <enable_discovery_protection>{}</enable_discovery_protection>
  <enable_liveliness_protection>{}</enable_liveliness_protection>
  <enable_read_access_control>{}</enable_read_access_control>
  <enable_write_access_control>{}</enable_write_access_control>
  <metadata_protection_kind>{}</metadata_protection_kind>
  <data_protection_kind>{}</data_protection_kind>
</topic_rule>"#,
            expression, discovery, liveliness, read, write, metadata, data
        )
    }

    /// The specification's own example, read as the specification says:
    /// participant attributes from the domain rule (Sec.9.4.1.2.5.2 to
    /// 9.4.1.2.5.6), topic and endpoint attributes from the FIRST topic rule
    /// whose expression matches (Sec.9.4.1.2.6, 9.4.1.2.6.2 to 9.4.1.2.6.7),
    /// and the masks of Tables 28, 31, 60 and 62.
    #[test]
    #[cfg(feature = "qos-loaders")]
    fn the_specification_example_is_read_as_the_specification_says() {
        let config =
            GovernanceConfig::parse_document(SPEC_EXAMPLE).expect("the example must be read");
        assert_eq!(config.domain_rules.len(), 1);
        let rule = &config.domain_rules[0];
        assert_eq!(rule.domains, vec![0]);
        assert_eq!(rule.domain_ranges, vec![(10, 20)]);
        assert!(config.domain_rule_for(15).is_some());
        assert!(config.domain_rule_for(21).is_none());

        let participant: ParticipantSecurityAttributes = config
            .participant_attributes(0)
            .expect("domain 0 is covered");
        assert!(!participant.allow_unauthenticated_participants);
        assert!(participant.is_access_protected);
        assert!(participant.is_rtps_protected, "rtps SIGN");
        assert!(participant.is_discovery_protected, "discovery ENCRYPT");
        assert!(participant.is_liveliness_protected, "liveliness SIGN");
        assert!(!participant.plugin.is_rtps_encrypted);
        assert!(participant.plugin.is_discovery_encrypted);
        assert!(!participant.plugin.is_liveliness_encrypted);
        assert_eq!(participant.mask(), 0x8000_0007);
        assert_eq!(participant.plugin.mask(), 0x8000_0002);
        assert!(config.participant_attributes(21).is_err());

        let endpoint = |topic: &str| -> EndpointSecurityAttributes {
            config.endpoint_attributes(0, topic).expect(topic)
        };
        // Square*: everything on, metadata and data ENCRYPT.
        for topic in ["Square", "SquareRoot"] {
            let e = endpoint(topic);
            assert_eq!(e.mask(), 0x8000_003f, "{}", topic);
            assert_eq!(e.plugin.mask(), 0x8000_0003, "{}", topic);
        }
        // Circle: read access control off.
        assert_eq!(endpoint("Circle").mask(), 0x8000_003e);
        assert!(
            !config
                .topic_attributes(0, "Circle")
                .expect("Circle")
                .is_read_protected
        );
        // Triangle (its expression has a trailing newline in the example):
        // discovery and every protection off, write access control on.
        let triangle = endpoint("Triangle");
        assert_eq!(triangle.mask(), 0x8000_0002);
        assert_eq!(triangle.plugin.mask(), 0x8000_0000);
        assert!(!triangle.topic.is_discovery_protected);
        // "Circles" is not "Circle": the first rule that MATCHES is the `*`.
        assert_eq!(endpoint("Circles").mask(), 0x8000_003f);
        assert_eq!(endpoint("Pentagon").mask(), 0x8000_003f);
    }

    /// And `parse` refuses it, naming the first protection this release does
    /// not apply rather than loading a document that asks for it.
    #[test]
    #[cfg(feature = "qos-loaders")]
    fn the_specification_example_is_refused_for_what_is_not_applied() {
        let err = GovernanceConfig::parse(SPEC_EXAMPLE).expect_err("rtps SIGN is not applied");
        let text = err.to_string();
        assert!(text.contains("rtps_protection_kind"), "{}", text);
        assert!(text.contains("SIGN"), "{}", text);
    }

    /// Sec.9.4.1.2.5: "If multiple rules match, the first rule that matches
    /// is the only one that applies."
    #[test]
    #[cfg(feature = "qos-loaders")]
    fn the_first_domain_rule_that_covers_a_domain_is_the_one_applied() {
        let rule = |domains: &str, discovery: &str| {
            format!(
                r#"<domain_rule>
  <domains>{}</domains>
  <allow_unauthenticated_participants>false</allow_unauthenticated_participants>
  <enable_join_access_control>true</enable_join_access_control>
  <discovery_protection_kind>{}</discovery_protection_kind>
  <data_protection_kind>NONE</data_protection_kind>
</domain_rule>"#,
                domains, discovery
            )
        };
        let xml = format!(
            "<dds><domain_access_rules>{}{}</domain_access_rules></dds>",
            rule("<id>5</id>", "NONE"),
            rule("<id_range><min>0</min></id_range>", "ENCRYPT")
        );
        let config = GovernanceConfig::parse(&xml).expect("parses");
        assert!(
            !config
                .participant_attributes(5)
                .expect("5")
                .is_discovery_protected
        );
        assert!(
            config
                .participant_attributes(6)
                .expect("6")
                .is_discovery_protected
        );
    }

    /// Sec.9.4.1.2.6 and 9.4.1.2.7: the first matching topic rule applies,
    /// and a topic no rule matches is a permissions error.
    #[test]
    #[cfg(feature = "qos-loaders")]
    fn the_first_topic_rule_that_matches_applies_and_no_match_is_refused() {
        let xml = spec_rule(
            "ENCRYPT",
            "NONE",
            "NONE",
            &format!(
                "{}{}",
                topic_rule("Open*", false, false, false, false, "NONE", "NONE"),
                topic_rule("O*", true, false, true, true, "NONE", "ENCRYPT")
            ),
        );
        let config = GovernanceConfig::parse(&xml).expect("parses");
        let open = config.topic_attributes(7, "OpenData").expect("OpenData");
        assert!(!open.is_discovery_protected && !open.is_read_protected);
        let other = config.topic_attributes(7, "Other").expect("Other");
        assert!(other.is_discovery_protected && other.is_read_protected);
        let err = config
            .topic_attributes(7, "Unmatched")
            .expect_err("no rule matches");
        assert!(
            matches!(err, SecurityError::PermissionsDenied(_)),
            "{:?}",
            err
        );
        assert!(err.to_string().contains("Unmatched"), "{}", err);
        assert!(
            config.topic_attributes(8, "Other").is_err(),
            "no domain rule"
        );
    }

    /// The shorthand this project documented - a domain-level
    /// `<data_protection_kind>`, no topic rules - is one `*` rule with access
    /// control on and discovery protection as the domain's kind says.
    #[test]
    #[cfg(feature = "qos-loaders")]
    fn the_shorthand_is_one_rule_for_every_topic() {
        let doc = |discovery: &str, data: &str| {
            format!(
                r#"<domain_rule>
  <domains>3</domains>
  <allow_unauthenticated_participants>false</allow_unauthenticated_participants>
  <enable_join_access_control>true</enable_join_access_control>
  <discovery_protection_kind>{}</discovery_protection_kind>
  <data_protection_kind>{}</data_protection_kind>
</domain_rule>"#,
                discovery, data
            )
        };
        let config = GovernanceConfig::parse(&doc("ENCRYPT", "ENCRYPT")).expect("parses");
        for topic in ["a", "rt/chatter", ""] {
            let e = config.endpoint_attributes(3, topic).expect("every topic");
            // read, write, discovery, payload, key.
            assert_eq!(e.mask(), 0x8000_0037, "{:?}", topic);
            assert_eq!(e.plugin.mask(), 0x8000_0002, "{:?}", topic);
        }
        let config = GovernanceConfig::parse(&doc("NONE", "NONE")).expect("parses");
        let e = config.endpoint_attributes(3, "a").expect("a");
        assert_eq!(e.mask(), 0x8000_0003, "access control stays on");
        assert!(!e.topic.is_discovery_protected);
    }

    /// Two answers to one question are refused, whichever form asks it.
    #[test]
    #[cfg(feature = "qos-loaders")]
    fn ambiguous_rules_are_refused_by_name() {
        // Shorthand and topic rules together.
        let mixed = spec_rule(
            "NONE",
            "NONE",
            "NONE",
            &topic_rule("*", false, false, true, true, "NONE", "NONE"),
        )
        .replace(
            "<topic_access_rules>",
            "<data_protection_kind>NONE</data_protection_kind><topic_access_rules>",
        );
        let err = GovernanceConfig::parse(&mixed).expect_err("two answers");
        assert!(err.to_string().contains("data_protection_kind"), "{}", err);

        // One element twice, under its two names.
        let twice = r#"<domain_rule>
  <domains>0</domains>
  <allow_unauthenticated_participants>false</allow_unauthenticated_participants>
  <enable_join_access_control>true</enable_join_access_control>
  <discovery_protection_kind>ENCRYPT</discovery_protection_kind>
  <encrypt_discovery>false</encrypt_discovery>
  <data_protection_kind>NONE</data_protection_kind>
</domain_rule>"#;
        let err = GovernanceConfig::parse(twice).expect_err("twice");
        assert!(
            err.to_string().contains("discovery_protection_kind"),
            "{}",
            err
        );

        // A topic rule element twice.
        let rule = topic_rule("*", false, false, true, true, "NONE", "NONE").replace(
            "</topic_rule>",
            "<enable_read_access_control>false</enable_read_access_control></topic_rule>",
        );
        let err =
            GovernanceConfig::parse(&spec_rule("NONE", "NONE", "NONE", &rule)).expect_err("twice");
        assert!(
            err.to_string().contains("enable_read_access_control"),
            "{}",
            err
        );
    }

    /// Every element of a topic rule is required, and the spec form needs
    /// all seven domain-rule elements (Sec.9.4.1.2.3).
    #[test]
    #[cfg(feature = "qos-loaders")]
    fn a_missing_element_is_named() {
        let full = topic_rule("*", true, false, true, true, "NONE", "ENCRYPT");
        for element in [
            "topic_expression",
            "enable_discovery_protection",
            "enable_liveliness_protection",
            "enable_read_access_control",
            "enable_write_access_control",
            "metadata_protection_kind",
            "data_protection_kind",
        ] {
            let without: String = full
                .lines()
                .filter(|line| !line.contains(&format!("<{}>", element)))
                .collect::<Vec<_>>()
                .join("\n");
            let err = GovernanceConfig::parse(&spec_rule("ENCRYPT", "NONE", "NONE", &without))
                .expect_err(element);
            assert!(err.to_string().contains(element), "{}: {}", element, err);
        }
        for element in ["liveliness_protection_kind", "rtps_protection_kind"] {
            let xml: String = spec_rule("ENCRYPT", "NONE", "NONE", &full)
                .lines()
                .filter(|line| !line.contains(&format!("<{}>", element)))
                .collect::<Vec<_>>()
                .join("\n");
            let err = GovernanceConfig::parse(&xml).expect_err(element);
            assert!(err.to_string().contains(element), "{}: {}", element, err);
        }
        let err = GovernanceConfig::parse(&spec_rule("ENCRYPT", "NONE", "NONE", ""))
            .expect_err("no topic rule");
        assert!(err.to_string().contains("topic_rule"), "{}", err);
    }

    /// A topic-rule element written at the domain level is refused with
    /// where it belongs.
    #[test]
    #[cfg(feature = "qos-loaders")]
    fn a_topic_element_at_the_domain_level_says_where_it_belongs() {
        for element in ["enable_discovery_protection", "metadata_protection_kind"] {
            let xml = format!(
                r#"<domain_rule>
  <domains>0</domains>
  <allow_unauthenticated_participants>false</allow_unauthenticated_participants>
  <enable_join_access_control>true</enable_join_access_control>
  <discovery_protection_kind>NONE</discovery_protection_kind>
  <data_protection_kind>NONE</data_protection_kind>
  <{0}>NONE</{0}>
</domain_rule>"#,
                element
            );
            let err = GovernanceConfig::parse(&xml).expect_err(element);
            let text = err.to_string();
            assert!(
                text.contains(element) && text.contains("topic_rule"),
                "{}",
                text
            );
        }
    }

    /// Each protection this release does not apply is refused by `parse`,
    /// naming the element; what it applies is accepted. One row per rule of
    /// `refuse_unapplied`, so a row that stops refusing fails by name.
    #[test]
    #[cfg(feature = "qos-loaders")]
    fn every_protection_not_applied_is_refused_by_name() {
        let applied = topic_rule("*", true, false, true, true, "NONE", "ENCRYPT");
        let refused: [(String, &str); 5] = [
            (
                spec_rule("NONE", "NONE", "SIGN", &applied),
                "rtps_protection_kind",
            ),
            (
                spec_rule("NONE", "ENCRYPT", "NONE", &applied),
                "liveliness_protection_kind",
            ),
            (
                spec_rule(
                    "ENCRYPT",
                    "NONE",
                    "NONE",
                    &topic_rule("*", true, true, true, true, "NONE", "NONE"),
                ),
                "enable_liveliness_protection",
            ),
            (
                spec_rule(
                    "ENCRYPT",
                    "NONE",
                    "NONE",
                    &topic_rule("*", true, false, true, true, "SIGN", "NONE"),
                ),
                "metadata_protection_kind",
            ),
            (
                spec_rule(
                    "ENCRYPT",
                    "NONE",
                    "NONE",
                    &topic_rule("*", true, false, true, true, "NONE", "SIGN"),
                ),
                "data_protection_kind",
            ),
        ];
        for (xml, element) in &refused {
            GovernanceConfig::parse_document(xml).expect("the document itself is valid");
            let err = GovernanceConfig::parse(xml).expect_err(element);
            assert!(err.to_string().contains(element), "{}: {}", element, err);
        }
        // Every discovery protection kind without origin authentication is
        // applied (secure_sedp).
        for discovery in ["NONE", "SIGN", "ENCRYPT"] {
            for data in ["NONE", "ENCRYPT"] {
                let xml = spec_rule(
                    discovery,
                    "NONE",
                    "NONE",
                    &topic_rule("*", true, false, false, true, "NONE", data),
                );
                GovernanceConfig::parse(&xml).expect("applied");
            }
        }
    }

    /// Table 27: is_rtps_protected requires allow_unauthenticated_participants
    /// FALSE. Read without the applied-check so the rule itself is what
    /// refuses.
    #[test]
    #[cfg(feature = "qos-loaders")]
    fn rtps_protection_with_unauthenticated_participants_is_refused() {
        let xml = spec_rule(
            "NONE",
            "NONE",
            "SIGN",
            &topic_rule("*", false, false, false, false, "NONE", "NONE"),
        )
        .replace(
            "<allow_unauthenticated_participants>FALSE",
            "<allow_unauthenticated_participants>TRUE",
        );
        let err = GovernanceConfig::parse_document(&xml).expect_err("Table 27");
        assert!(err.to_string().contains("Table 27"), "{}", err);
    }

    #[test]
    #[cfg(feature = "qos-loaders")]
    fn test_parse_permissions_xml() {
        let xml = r#"<?xml version="1.0"?>
<permissions>
  <grant>
    <subject_name>CN=TestParticipant</subject_name>
    <validity>
      <not_before>2024-01-01T00:00:00</not_before>
      <not_after>2030-01-01T00:00:00</not_after>
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

        let config = PermissionsConfig::parse(xml).unwrap();
        assert_eq!(config.grants.len(), 1);
        assert_eq!(config.grants[0].subject_name, "CN=TestParticipant");
        assert_eq!(config.grants[0].rules.len(), 1);
        let rule = &config.grants[0].rules[0];
        assert_eq!(rule.kind, RuleKind::Allow);
        assert_eq!(topics_of(&rule.publish), vec!["sensor/*"]);
        assert_eq!(topics_of(&rule.subscribe), vec!["*"]);
    }

    /// OMG-format permissions XML using nested <topic> and <id> elements.
    /// This is the format used by the OMG interop repository.
    #[test]
    #[cfg(feature = "qos-loaders")]
    fn test_parse_permissions_omg_nested_format() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<dds xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <permissions>
    <grant name="hdds_allowall">
      <subject_name>CN=TestNode</subject_name>
      <validity>
        <not_before>2024-01-01T00:00:00</not_before>
        <not_after>2034-01-01T00:00:00</not_after>
      </validity>
      <allow_rule>
        <domains>
          <id>0</id>
        </domains>
        <publish>
          <topics>
            <topic>*</topic>
          </topics>
        </publish>
        <subscribe>
          <topics>
            <topic>Square</topic>
            <topic>Triangle</topic>
          </topics>
        </subscribe>
      </allow_rule>
      <default>DENY</default>
    </grant>
  </permissions>
</dds>"#;

        let config = PermissionsConfig::parse(xml).unwrap();
        assert_eq!(config.grants.len(), 1);
        assert_eq!(config.grants[0].rules.len(), 1);
        let rule = &config.grants[0].rules[0];
        // Nested <topic> elements must be collected.
        assert_eq!(topics_of(&rule.publish), vec!["*"]);
        assert_eq!(topics_of(&rule.subscribe), vec!["Square", "Triangle"]);
        // Nested <id> domain must be collected.
        assert_eq!(rule.domains, vec![0]);
    }

    /// id_range expansion: <id_range><min>10</min><max>12</max></id_range> -> [10, 11, 12]
    #[test]
    #[cfg(feature = "qos-loaders")]
    fn test_parse_permissions_id_range() {
        let xml = r#"<?xml version="1.0"?>
<permissions>
  <grant>
    <subject_name>CN=RangeTest</subject_name>
    <validity>
      <not_before>2024-01-01T00:00:00</not_before>
      <not_after>2034-01-01T00:00:00</not_after>
    </validity>
    <allow_rule>
      <domains>
        <id_range>
          <min>10</min>
          <max>12</max>
        </id_range>
      </domains>
      <publish>
        <topics><topic>*</topic></topics>
      </publish>
      <subscribe>
        <topics><topic>*</topic></topics>
      </subscribe>
    </allow_rule>
  </grant>
</permissions>"#;

        let config = PermissionsConfig::parse(xml).unwrap();
        let rule = &config.grants[0].rules[0];
        // Stored, not expanded - the same treatment the governance half got,
        // and the reason to ask through `covers` rather than reach into the
        // list. This test used to assert `domains.contains(&10)`, which was
        // only ever true because the parser expanded the range into a Vec
        // clamped at 255.
        assert!(rule.domains.is_empty(), "nothing may be expanded");
        assert_eq!(rule.domain_ranges, vec![(10, 12)]);
        assert!(rule.covers(10));
        assert!(rule.covers(11));
        assert!(rule.covers(12));
        assert!(!rule.covers(9));
        assert!(!rule.covers(13));
    }

    /// A grant is scoped to the domains it names, and nothing else.
    ///
    /// `Rule::domains` must be read: a grant written for one domain must not
    /// be applied on every domain a participant joins. That is the opposite
    /// of what an operator writes a per-domain grant to express, and it is
    /// invisible in any test that runs on a single domain - which is why this
    /// one runs the same rules on two.
    #[test]
    #[cfg(feature = "qos-loaders")]
    fn a_grant_does_not_reach_a_domain_it_does_not_name() {
        use crate::security::access::rules::RulesEngine;

        let governance = GovernanceConfig::parse(
            r#"<?xml version="1.0"?>
<governance>
  <domain_rule>
    <domains><id_range><min>0</min><max>50</max></id_range></domains>
    <allow_unauthenticated_participants>false</allow_unauthenticated_participants>
    <enable_join_access_control>true</enable_join_access_control>
    <discovery_protection_kind>NONE</discovery_protection_kind>
    <data_protection_kind>NONE</data_protection_kind>
  </domain_rule>
</governance>"#,
        )
        .expect("governance");

        let permissions = PermissionsConfig::parse(
            r#"<?xml version="1.0"?>
<permissions>
  <grant>
    <subject_name>CN=RangeTest</subject_name>
    <validity>
      <not_before>2024-01-01T00:00:00</not_before>
      <not_after>2034-01-01T00:00:00</not_after>
    </validity>
    <allow_rule>
      <domains><id>7</id></domains>
      <publish><topics><topic>sensor/*</topic></topics></publish>
    </allow_rule>
  </grant>
</permissions>"#,
        )
        .expect("permissions");

        let here = RulesEngine::new(governance.clone(), permissions.clone(), 7);
        assert!(
            here.check_topic_publish("sensor/temperature", None).is_ok(),
            "the grant names domain 7, so it applies on domain 7"
        );

        let elsewhere = RulesEngine::new(governance, permissions, 8);
        assert!(
            elsewhere
                .check_topic_publish("sensor/temperature", None)
                .is_err(),
            "the grant names domain 7 and nothing else: on domain 8 it grants nothing"
        );
    }

    /// A governance rule whose topic expression is `expression`.
    #[cfg(feature = "qos-loaders")]
    fn rule_with_expression(expression: &str) -> String {
        format!(
            "<dds><domain_access_rules><domain_rule><domains><id>0</id></domains>\
             <allow_unauthenticated_participants>false</allow_unauthenticated_participants>\
             <enable_join_access_control>true</enable_join_access_control>\
             <discovery_protection_kind>NONE</discovery_protection_kind>\
             <liveliness_protection_kind>NONE</liveliness_protection_kind>\
             <rtps_protection_kind>NONE</rtps_protection_kind>\
             <topic_access_rules><topic_rule><topic_expression>{}</topic_expression>\
             <enable_discovery_protection>false</enable_discovery_protection>\
             <enable_liveliness_protection>false</enable_liveliness_protection>\
             <enable_read_access_control>true</enable_read_access_control>\
             <enable_write_access_control>true</enable_write_access_control>\
             <metadata_protection_kind>NONE</metadata_protection_kind>\
             <data_protection_kind>NONE</data_protection_kind></topic_rule>\
             </topic_access_rules></domain_rule></domain_access_rules></dds>",
            expression
        )
    }

    /// A comment splits the text of an element into two text nodes. Read as
    /// its first node, `Open<!-- x -->Secret` was the expression `Open` and
    /// `*<!-- -->Secret` the expression `*`: a rule wider than written. A
    /// value that is not one run of character data is refused, naming it.
    #[test]
    #[cfg(feature = "qos-loaders")]
    fn a_governance_value_split_by_a_comment_is_refused() {
        for expression in [
            "Open<!-- x -->Secret",
            "*<!-- -->Secret",
            "<!-- -->Secret",
            "Secret<?pi x?>Open",
        ] {
            let err =
                GovernanceConfig::parse(&rule_with_expression(expression)).expect_err(expression);
            assert!(
                err.to_string().contains("topic_expression"),
                "{}: the error names the element: {}",
                expression,
                err
            );
        }
        // A boolean or a kind split the same way.
        let doc = rule_with_expression("Open").replace(
            "<enable_read_access_control>true",
            "<enable_read_access_control>tr<!-- -->ue",
        );
        assert!(GovernanceConfig::parse(&doc).is_err(), "split boolean");
        let doc = rule_with_expression("Open")
            .replace("<domains><id>0</id>", "<domains><id>1<!-- -->0</id>");
        assert!(GovernanceConfig::parse(&doc).is_err(), "split domain id");
        // Character data alone, CDATA included, still reads.
        let rule = GovernanceConfig::parse(&rule_with_expression("<![CDATA[Open]]>Secret"))
            .expect("one run of character data");
        assert_eq!(
            rule.domain_rules[0].topic_rules[0].topic_expression,
            "OpenSecret"
        );
        // A comment between elements is not inside a value.
        let rule = GovernanceConfig::parse(
            &rule_with_expression("Open")
                .replace("<topic_rule>", "<topic_rule><!-- the open topics -->"),
        )
        .expect("a comment between elements");
        assert_eq!(rule.domain_rules[0].topic_rules[0].topic_expression, "Open");
    }

    /// The same split in a permissions document: a subject, a validity bound
    /// or a topic read as its first text node names another subject, another
    /// date or a wider topic. Each is refused, and a refused deny rule is not
    /// dropped (dropping it would widen the grant).
    #[test]
    #[cfg(feature = "qos-loaders")]
    fn a_permissions_value_split_by_a_comment_is_refused() {
        let doc = |subject: &str, topic: &str, deny_domains: &str| {
            format!(
                "<dds><permissions><grant name=\"g\"><subject_name>{}</subject_name>\
                 <validity><not_before>2020-01-01T00:00:00</not_before>\
                 <not_after>2036-01-01T00:00:00</not_after></validity>\
                 <allow_rule><domains><id>0</id></domains><publish><topics><topic>{}</topic>\
                 </topics></publish></allow_rule>\
                 <deny_rule><domains>{}</domains><publish><topics><topic>Secret</topic>\
                 </topics></publish></deny_rule>\
                 <default>DENY</default></grant></permissions></dds>",
                subject, topic, deny_domains
            )
        };
        let parsed = PermissionsConfig::parse(&doc("CN=Alice", "Open", "<id>0</id>"))
            .expect("the plain document");
        assert_eq!(parsed.grants[0].subject_name, "CN=Alice");
        assert_eq!(
            parsed.grants[0]
                .rules
                .iter()
                .filter(|rule| rule.kind == RuleKind::Deny)
                .count(),
            1
        );
        for (what, bad) in [
            (
                "subject",
                doc("CN=Alice<!-- -->, O=Other", "Open", "<id>0</id>"),
            ),
            ("topic", doc("CN=Alice", "*<!-- -->Secret", "<id>0</id>")),
            (
                "deny domains",
                doc("CN=Alice", "Open", "<id>0<!-- -->1</id>"),
            ),
            (
                "inline topics",
                doc("CN=Alice", "Open", "<id>0</id>").replace(
                    "<topics><topic>Open</topic></topics>",
                    "<topics>*<!-- -->Open</topics>",
                ),
            ),
        ] {
            assert!(
                PermissionsConfig::parse(&bad).is_err(),
                "{}: a split value is refused, not read as its first half",
                what
            );
        }
    }

    /// Run `f` on a thread with `stack` bytes of stack: a parse that
    /// overflowed it would abort the whole test binary, not fail one test.
    #[cfg(feature = "qos-loaders")]
    fn on_stack<T: Send + 'static>(stack: usize, f: impl FnOnce() -> T + Send + 'static) -> T {
        std::thread::Builder::new()
            .stack_size(stack)
            .spawn(f)
            .expect("spawn")
            .join()
            .expect("the parse panicked")
    }

    /// roxmltree recurses once per nesting level, so ten thousand nested
    /// elements overflowed an 8 MiB stack and aborted the process, a remote
    /// participant's `c.perm` included (parsed before any grant is read).
    /// Both documents are refused past `MAX_XML_DEPTH`, before parsing.
    #[test]
    #[cfg(feature = "qos-loaders")]
    fn deep_nesting_is_refused_before_parsing() {
        for depth in [10_000usize, 200_000] {
            let deep = "<a>".repeat(depth) + &"</a>".repeat(depth);
            let nested = format!(
                "<dds><domain_access_rules><domain_rule>{}</domain_rule>\
                 </domain_access_rules></dds>",
                deep
            );
            let (governance, permissions, nested) = on_stack(8 << 20, move || {
                (
                    GovernanceConfig::parse(&deep).map(|_| ()),
                    PermissionsConfig::parse(&deep).map(|_| ()),
                    GovernanceConfig::parse(&nested).map(|_| ()),
                )
            });
            for (what, result) in [
                ("governance", governance),
                ("permissions", permissions),
                ("nested governance", nested),
            ] {
                let err = result.expect_err(what);
                assert!(
                    err.to_string().contains("nest"),
                    "{} at depth {}: refused for its depth: {}",
                    what,
                    depth,
                    err
                );
            }
        }
    }

    /// The bound from both sides: `MAX_XML_DEPTH` levels are handed to the
    /// parser (and parse on a small stack), one more is refused.
    #[test]
    #[cfg(feature = "qos-loaders")]
    fn the_nesting_bound_is_exact() {
        let doc = |depth: usize| "<a>".repeat(depth) + &"</a>".repeat(depth);
        let at = on_stack(512 << 10, move || {
            PermissionsConfig::parse(&doc(MAX_XML_DEPTH)).map(|_| ())
        });
        assert!(at.is_ok(), "{} levels are parsed: {:?}", MAX_XML_DEPTH, at);
        let over = PermissionsConfig::parse(&doc(MAX_XML_DEPTH + 1)).expect_err("one more");
        assert!(over.to_string().contains("nest"), "{}", over);
        // Self-closing elements, closing tags and character data do not nest.
        let flat = format!(
            "<dds>{}{}</dds>",
            "<a/>".repeat(10_000),
            "<b>x</b>".repeat(10_000)
        );
        assert!(PermissionsConfig::parse(&flat).is_ok());
    }

    /// What is not markup does not close an element: a closing tag written
    /// in a comment, a CDATA section, a processing instruction or an
    /// attribute value leaves the count of open elements as it was.
    #[test]
    #[cfg(feature = "qos-loaders")]
    fn markup_inside_comments_and_attributes_does_not_hide_depth() {
        let depth = MAX_XML_DEPTH + 1;
        for decoy in ["<!-- </a> -->", "<![CDATA[</a>]]>", "<?pi </a> ?>"] {
            let doc = format!("<a>{}", decoy).repeat(depth) + &"</a>".repeat(depth);
            let err = PermissionsConfig::parse(&doc).expect_err(decoy);
            assert!(err.to_string().contains("nest"), "{}: {}", decoy, err);
        }
        let doc = "<a x=\"/>\" y='</a>'>".repeat(depth) + &"</a>".repeat(depth);
        let err = PermissionsConfig::parse(&doc).expect_err("attribute values");
        assert!(err.to_string().contains("nest"), "{}", err);
    }

    /// Hostile input in general: refused, never a panic.
    #[test]
    #[cfg(feature = "qos-loaders")]
    fn hostile_governance_never_panics() {
        for junk in [
            "",
            "<",
            "<dds>",
            "\u{0}",
            "<a x=\"",
            "<!--",
            "<![CDATA[",
            "<?",
            "<dds><domain_access_rules><domain_rule><domains><id_range><min>5</min></id_range>\
             </domains></domain_rule></domain_access_rules></dds>",
            "<dds><domain_access_rules><domain_rule><domains><id>-1</id></domains>\
             </domain_rule></domain_access_rules></dds>",
            "<dds><domain_access_rules><domain_rule><domains><id>99999999999</id></domains>\
             </domain_rule></domain_access_rules></dds>",
        ] {
            let result = std::panic::catch_unwind(|| GovernanceConfig::parse(junk))
                .unwrap_or_else(|_| panic!("panic on {:?}", junk));
            assert!(result.is_err(), "{:?}", junk);
        }
    }

    #[test]
    #[cfg(feature = "qos-loaders")]
    fn verify_hostile_xml_never_panics_and_deep_is_refused() {
        let deep = |n: usize, open: &str, close: &str| {
            format!("<dds>{}{}</dds>", open.repeat(n), close.repeat(n))
        };
        // Deep nesting hidden from the scan in various ways must still be refused or parsed safely.
        let mut cases: Vec<String> = vec![
            deep(100_000, "<a>", "</a>"),
            deep(100_000, "<a x='>'>", "</a>"),
            deep(100_000, "<a x=\"</a>\">", "</a>"),
            format!("\u{feff}{}", deep(100_000, "<a>", "</a>")),
            // a fake closing tag inside a comment/PI/CDATA must not lower the count
            format!("<dds>{}</dds>", "<a><!-- </a> -->".repeat(100_000)),
            format!("<dds>{}</dds>", "<a><?pi </a> ?>".repeat(100_000)),
            format!("<dds>{}</dds>", "<a><![CDATA[</a>]]>".repeat(100_000)),
            // `</a>` inside an attribute value of a start tag
            format!("<dds>{}</dds>", "<a b='</a>'>".repeat(100_000)),
            // unterminated constructs
            "<dds><!--".to_string(),
            "<dds><![CDATA[".to_string(),
            "<dds><?x".to_string(),
            "<dds><a b='".to_string(),
            "<".to_string(),
            "".to_string(),
            "<<<<".to_string(),
            "<!DOCTYPE dds [<!ENTITY a 'x'>]><dds>&a;</dds>".to_string(),
            "<dds><!-- --><!DOCTYPE x></dds>".to_string(),
            // whitespace / odd closers: `</a  >` and `< a>`
            format!("<dds>{}</dds>", "<a\n>".repeat(100_000)),
            format!(
                "<dds>{}{}</dds>",
                "<a>".repeat(100_000),
                "</a\n>".repeat(100_000)
            ),
            // namespace-prefixed tags
            deep(100_000, "<p:a xmlns:p='u'>", "</p:a>"),
            // huge single line, no markup
            "x".repeat(20_000_000),
            format!("<dds>{}</dds>", "<".repeat(5_000_000)),
        ];
        // random-ish bytes
        let mut x: u64 = 0x9E3779B97F4A7C15;
        let alphabet = b"<>/!?-[]'\"= aCDT\n";
        for _ in 0..3000 {
            let mut v = String::new();
            for _ in 0..200 {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                v.push(alphabet[(x % alphabet.len() as u64) as usize] as char);
            }
            cases.push(v);
        }
        for c in &cases {
            let a = std::panic::catch_unwind(|| GovernanceConfig::parse(c));
            let b = std::panic::catch_unwind(|| PermissionsConfig::parse(c));
            assert!(
                a.is_ok() && b.is_ok(),
                "panic on input prefix {:?}",
                &c[..c.len().min(80)]
            );
        }
    }

    /// Hostile XML: deep nesting hidden from the pre-scan in every
    /// way tried, unterminated
    /// constructs, and random markup. Neither parser may panic.
    #[test]
    #[cfg(feature = "qos-loaders")]
    fn hostile_xml_never_panics_either_parser() {
        let deep = |n: usize, open: &str, close: &str| {
            format!("<dds>{}{}</dds>", open.repeat(n), close.repeat(n))
        };
        // Deep nesting hidden from the scan in various ways must still be refused or parsed safely.
        let mut cases: Vec<String> = vec![
            deep(100_000, "<a>", "</a>"),
            deep(100_000, "<a x='>'>", "</a>"),
            deep(100_000, "<a x=\"</a>\">", "</a>"),
            format!("\u{feff}{}", deep(100_000, "<a>", "</a>")),
            // a fake closing tag inside a comment/PI/CDATA must not lower the count
            format!("<dds>{}</dds>", "<a><!-- </a> -->".repeat(100_000)),
            format!("<dds>{}</dds>", "<a><?pi </a> ?>".repeat(100_000)),
            format!("<dds>{}</dds>", "<a><![CDATA[</a>]]>".repeat(100_000)),
            // `</a>` inside an attribute value of a start tag
            format!("<dds>{}</dds>", "<a b='</a>'>".repeat(100_000)),
            // unterminated constructs
            "<dds><!--".to_string(),
            "<dds><![CDATA[".to_string(),
            "<dds><?x".to_string(),
            "<dds><a b='".to_string(),
            "<".to_string(),
            "".to_string(),
            "<<<<".to_string(),
            "<!DOCTYPE dds [<!ENTITY a 'x'>]><dds>&a;</dds>".to_string(),
            "<dds><!-- --><!DOCTYPE x></dds>".to_string(),
            // whitespace / odd closers: `</a  >` and `< a>`
            format!("<dds>{}</dds>", "<a\n>".repeat(100_000)),
            format!(
                "<dds>{}{}</dds>",
                "<a>".repeat(100_000),
                "</a\n>".repeat(100_000)
            ),
            // namespace-prefixed tags
            deep(100_000, "<p:a xmlns:p='u'>", "</p:a>"),
            // huge single line, no markup
            "x".repeat(20_000_000),
            format!("<dds>{}</dds>", "<".repeat(5_000_000)),
        ];
        // random-ish bytes
        let mut x: u64 = 0x9E3779B97F4A7C15;
        let alphabet = b"<>/!?-[]'\"= aCDT\n";
        for _ in 0..3000 {
            let mut v = String::new();
            for _ in 0..200 {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                v.push(alphabet[(x % alphabet.len() as u64) as usize] as char);
            }
            cases.push(v);
        }
        for c in &cases {
            let a = std::panic::catch_unwind(|| GovernanceConfig::parse(c));
            let b = std::panic::catch_unwind(|| PermissionsConfig::parse(c));
            assert!(
                a.is_ok() && b.is_ok(),
                "panic on input prefix {:?}",
                &c[..c.len().min(80)]
            );
        }
    }

    /// A permissions topic expression is matched as fnmatch
    /// (Sec.9.4.1.3.2.3.1.3), POSIX bracket classes included: a document
    /// using `[[:upper:]]` loads, and one
    /// naming a class fnmatch does not know is refused at load, as the
    /// governance's are (`fnmatch::check_pattern`).
    #[test]
    #[cfg(feature = "qos-loaders")]
    fn a_permissions_topic_with_a_character_class_loads() {
        let document = |topic: &str| {
            format!(
                "<dds><permissions><grant name=\"g\"><subject_name>CN=Test</subject_name>\
                 <validity><not_before>2020-01-01T00:00:00</not_before>\
                 <not_after>2036-01-01T00:00:00</not_after></validity>\
                 <allow_rule><domains><id>0</id></domains><publish><topics><topic>{}</topic>\
                 </topics></publish></allow_rule><default>DENY</default></grant></permissions>\
                 </dds>",
                topic
            )
        };
        assert!(PermissionsConfig::parse(&document("Square*")).is_ok());
        assert!(PermissionsConfig::parse(&document("[[:upper:]]quare")).is_ok());
        assert!(PermissionsConfig::parse(&document("[[:alpha:]]*")).is_ok());
        let err = PermissionsConfig::parse(&document("[[:uper:]]quare")).expect_err("refused");
        assert!(err.to_string().contains("ill-formed bracket"), "{}", err);
    }
}
