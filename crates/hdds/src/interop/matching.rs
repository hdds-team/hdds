// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

// hdds/crates/hdds/src/interop/matching.rs
// Etape 0.5 - Matching Rules & Diagnostics
//
// For now we keep this module self-contained to avoid rippling type
// changes across the core. TopicName/TypeName are simple String
// aliases and QoS policies are represented as an opaque unit type.
// This is sufficient for diagnostics (we log names, not structures)
// and can be refined later when full WireProfile integration lands.

use crate::reliability::GuidPrefix;

pub type TopicName = String;
pub type TypeName = String;
pub type QosPolicy = ();

/// Matching flexibility levels
#[derive(Debug, Clone, Copy, PartialEq)]
#[allow(dead_code)] // All variants are part of the API for future type matching strategies
pub enum TypeNameMatch {
    Exact,            // "Temperature" == "Temperature"
    NamespaceRelaxed, // "ns::Temperature" ~= "Temperature"
    Suffix,           // "Foo::Bar::Temperature" ~= "Temperature"
    Any,              // Always match (danger mode)
}

#[derive(Debug, Clone, Copy, PartialEq)]
#[allow(dead_code)] // All variants are part of the API for future QoS compatibility checking
pub enum QosCompatMode {
    Strict,  // All QoS must match exactly
    Relaxed, // RELIABLE ~= BEST_EFFORT OK
    Legacy,  // FastDDS quirks (TRANSIENT_LOCAL ignored, etc.)
    Bypass,  // Skip QoS checks (debug only)
}

/// Core matching rules for a wire profile
#[derive(Debug, Clone)]
pub struct MatchingRules {
    pub require_type_object: bool,
    pub type_name_match: TypeNameMatch,
    #[allow(dead_code)] // Part of matching rules API for future QoS compatibility checking
    pub qos_compat: QosCompatMode,
    #[allow(dead_code)] // Part of matching rules API for future XCDR1/XCDR2 checking
    pub data_representation_check: bool, // XCDR1 vs XCDR2
    #[allow(dead_code)] // Part of matching rules API for future keyed topic checking
    pub keyed_topic_check: bool, // NO_KEY vs WITH_KEY
}

impl MatchingRules {
    /// Legacy CDR1 profile (Temperature SENSOR/STATE/EVENT)
    pub fn legacy_cdr1() -> Self {
        Self {
            require_type_object: false,
            type_name_match: TypeNameMatch::Suffix, // FastDDS adds namespaces
            qos_compat: QosCompatMode::Legacy,
            data_representation_check: false, // Don't care
            keyed_topic_check: false,         // Temperature is NO_KEY
        }
    }

    /// XCDR2 profile (Poly3D)
    pub fn xcdr2_strict() -> Self {
        Self {
            require_type_object: true,
            type_name_match: TypeNameMatch::Exact,
            qos_compat: QosCompatMode::Strict,
            data_representation_check: true,
            keyed_topic_check: true,
        }
    }
}

/// Diagnostic severity (for HDDS Viewer)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[allow(dead_code)] // All severity levels are part of the diagnostic API
pub enum MismatchSeverity {
    Ignorable,  // TypeObject v1.2 vs v1.3, can proceed
    Negotiable, // QoS mismatch but might work
    Fatal,      // XCDR1 vs XCDR2, will NOT work
}

/// Detailed mismatch report
#[derive(Debug, Clone)]
pub struct MismatchReport {
    pub local_topic: TopicName,
    #[allow(dead_code)] // Part of diagnostic report API for identifying remote endpoint
    pub remote_guid: GuidPrefix,
    pub severity: MismatchSeverity,
    #[allow(dead_code)] // Part of diagnostic report API for categorizing mismatches
    pub category: MismatchCategory,
    pub details: String,
    pub suggestion: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
#[allow(dead_code)] // All mismatch categories are part of the diagnostic API
pub enum MismatchCategory {
    TypeName {
        local: TypeName,
        remote: TypeName,
    },
    TypeObject {
        reason: String,
    },
    DataRepresentation {
        local: String,
        remote: String,
    },
    QosPolicy {
        policy: String,
        local: String,
        remote: String,
    },
    KeyedMismatch {
        local_keyed: bool,
        remote_keyed: bool,
    },
}

impl MismatchReport {
    pub fn type_name_mismatch(
        local_topic: TopicName,
        remote_guid: GuidPrefix,
        local: TypeName,
        remote: TypeName,
    ) -> Self {
        Self {
            local_topic,
            remote_guid,
            severity: MismatchSeverity::Fatal,
            category: MismatchCategory::TypeName {
                local: local.clone(),
                remote: remote.clone(),
            },
            details: format!("Type name mismatch: '{}' vs '{}'", local, remote),
            suggestion: Some("Check IDL namespaces or set HDDS_FORCE_TYPE_NAME".into()),
        }
    }

    #[allow(dead_code)] // Factory method for XCDR mismatch reports, part of diagnostic API
    pub fn xcdr_mismatch(local_topic: TopicName, remote_guid: GuidPrefix) -> Self {
        Self {
            local_topic,
            remote_guid,
            severity: MismatchSeverity::Fatal,
            category: MismatchCategory::DataRepresentation {
                local: "XCDR2".into(),
                remote: "XCDR1".into(),
            },
            details: "Data representation incompatible: XCDR2 vs XCDR1".into(),
            suggestion: Some("Use consistent IDL code generation across peers".into()),
        }
    }
}

/// Matcher with diagnostic collection
pub struct DiagnosticMatcher {
    rules: MatchingRules,
    reports: Vec<MismatchReport>,
}

impl DiagnosticMatcher {
    pub fn new(rules: MatchingRules) -> Self {
        Self {
            rules,
            reports: Vec::new(),
        }
    }

    /// Check if endpoints match, collecting diagnostics
    pub fn check_match(
        &mut self,
        local: &EndpointInfo,
        remote: &RemoteEndpointInfo,
    ) -> MatchResult {
        // Type name check
        if !self.check_type_name(&local.type_name, &remote.type_name) {
            let report = MismatchReport::type_name_mismatch(
                local.topic_name.clone(),
                remote.guid_prefix,
                local.type_name.clone(),
                remote.type_name.clone(),
            );
            self.reports.push(report);
            return MatchResult::Failed;
        }

        // Type object check
        if self.rules.require_type_object && remote.type_object.is_none() {
            let report = MismatchReport {
                local_topic: local.topic_name.clone(),
                remote_guid: remote.guid_prefix,
                severity: MismatchSeverity::Negotiable,
                category: MismatchCategory::TypeObject {
                    reason: "Remote peer missing TypeObject".into(),
                },
                details: "TypeObject required but not provided by remote".into(),
                suggestion: Some("Update remote to send TypeObject or relax rules".into()),
            };
            self.reports.push(report);
            // Continue for now if Negotiable
        }

        // QoS compatibility
        if let Some(qos_issue) = self.check_qos_compat(&local.qos, &remote.qos) {
            // Keep a copy in the local matcher while inspecting severity.
            self.reports.push(qos_issue.clone());
            if qos_issue.severity == MismatchSeverity::Fatal {
                return MatchResult::Failed;
            }
        }

        MatchResult::Success
    }

    fn check_type_name(&self, local: &TypeName, remote: &TypeName) -> bool {
        match self.rules.type_name_match {
            TypeNameMatch::Exact => local == remote,
            TypeNameMatch::Suffix => {
                // "Foo::Bar::Temperature" matches "Temperature"
                local.ends_with(&remote.as_str()) || remote.ends_with(&local.as_str())
            }
            TypeNameMatch::NamespaceRelaxed => {
                // Strip namespace and compare
                let local_base = local.split("::").last().unwrap_or(local);
                let remote_base = remote.split("::").last().unwrap_or(remote);
                local_base == remote_base
            }
            TypeNameMatch::Any => true,
        }
    }

    fn check_qos_compat(
        &self,
        _local: &[QosPolicy],
        _remote: &[QosPolicy],
    ) -> Option<MismatchReport> {
        // QoS compatibility: currently a no-op for diagnostics-only phase.
        // Future work: inspect `self.rules.qos_compat` and populate a
        // `MismatchCategory::QosPolicy` when needed.
        None
    }

    /// Get all collected diagnostics
    pub fn drain_reports(&mut self) -> Vec<MismatchReport> {
        std::mem::take(&mut self.reports)
    }
}

#[derive(Debug, PartialEq)]
#[allow(dead_code)] // All match results are part of the matching API
pub enum MatchResult {
    Success,
    Failed,
    Pending, // Need more info
}

// Placeholder types - replace with real ones
pub struct EndpointInfo {
    pub topic_name: TopicName,
    pub type_name: TypeName,
    #[allow(dead_code)] // Part of endpoint info for future type object validation
    pub type_object: Option<Vec<u8>>,
    pub qos: Vec<QosPolicy>,
}

pub struct RemoteEndpointInfo {
    pub guid_prefix: GuidPrefix,
    #[allow(dead_code)] // Part of remote endpoint info for future topic name matching
    pub topic_name: TopicName,
    pub type_name: TypeName,
    pub type_object: Option<Vec<u8>>,
    pub qos: Vec<QosPolicy>,
}

// ========================================================================
// Tests
// ========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_guid() -> GuidPrefix {
        [0; crate::reliability::GUID_PREFIX_LEN]
    }

    #[test]
    fn exact_type_name_match_succeeds_without_reports() {
        let rules = MatchingRules::xcdr2_strict();
        let mut matcher = DiagnosticMatcher::new(rules);

        let local = EndpointInfo {
            topic_name: "TemperatureTopic".to_string(),
            type_name: "Temperature".to_string(),
            type_object: Some(Vec::new()),
            qos: Vec::new(),
        };

        let remote = RemoteEndpointInfo {
            guid_prefix: dummy_guid(),
            topic_name: "TemperatureTopic".to_string(),
            type_name: "Temperature".to_string(),
            type_object: Some(Vec::new()),
            qos: Vec::new(),
        };

        let result = matcher.check_match(&local, &remote);
        assert_eq!(result, MatchResult::Success);
        assert!(matcher.drain_reports().is_empty());
    }

    #[test]
    fn suffix_type_name_match_allows_namespace_prefixes() {
        let rules = MatchingRules::legacy_cdr1();
        let mut matcher = DiagnosticMatcher::new(rules);

        let local = EndpointInfo {
            topic_name: "TemperatureTopic".to_string(),
            type_name: "Temperature".to_string(),
            type_object: None,
            qos: Vec::new(),
        };

        let remote = RemoteEndpointInfo {
            guid_prefix: dummy_guid(),
            topic_name: "TemperatureTopic".to_string(),
            type_name: "Sensor::Temperature".to_string(),
            type_object: None,
            qos: Vec::new(),
        };

        let result = matcher.check_match(&local, &remote);
        assert_eq!(result, MatchResult::Success);
        assert!(matcher.drain_reports().is_empty());
    }

    #[test]
    fn namespace_relaxed_matches_different_prefixes() {
        let mut rules = MatchingRules::legacy_cdr1();
        rules.type_name_match = TypeNameMatch::NamespaceRelaxed;

        let mut matcher = DiagnosticMatcher::new(rules);

        let local = EndpointInfo {
            topic_name: "TemperatureTopic".to_string(),
            type_name: "ns1::Temperature".to_string(),
            type_object: None,
            qos: Vec::new(),
        };

        let remote = RemoteEndpointInfo {
            guid_prefix: dummy_guid(),
            topic_name: "TemperatureTopic".to_string(),
            type_name: "ns2::Temperature".to_string(),
            type_object: None,
            qos: Vec::new(),
        };

        let result = matcher.check_match(&local, &remote);
        assert_eq!(result, MatchResult::Success);
        assert!(matcher.drain_reports().is_empty());
    }

    #[test]
    fn exact_type_name_mismatch_produces_fatal_report() {
        let rules = MatchingRules::xcdr2_strict();
        let mut matcher = DiagnosticMatcher::new(rules);

        let local = EndpointInfo {
            topic_name: "TemperatureTopic".to_string(),
            type_name: "Temperature".to_string(),
            type_object: None,
            qos: Vec::new(),
        };

        let remote = RemoteEndpointInfo {
            guid_prefix: dummy_guid(),
            topic_name: "TemperatureTopic".to_string(),
            type_name: "OtherType".to_string(),
            type_object: None,
            qos: Vec::new(),
        };

        let result = matcher.check_match(&local, &remote);
        assert_eq!(result, MatchResult::Failed);

        let reports = matcher.drain_reports();
        assert_eq!(reports.len(), 1);

        let report = &reports[0];
        assert_eq!(report.severity, MismatchSeverity::Fatal);

        if let MismatchCategory::TypeName { local, remote } = &report.category {
            assert_eq!(local, "Temperature");
            assert_eq!(remote, "OtherType");
        } else {
            // In tests we prefer an explicit failure instead of panicking from
            // production code paths.
            assert!(
                matches!(report.category, MismatchCategory::TypeName { .. }),
                "unexpected mismatch category: {:?}",
                report.category
            );
        }
    }
}
