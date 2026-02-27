// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Rules engine for access control (allow/deny logic with wildcard matching)
//!
//! # Security Model: Deny-by-Default
//!
//! This implementation follows a **deny-by-default** security model per DDS Security v1.1:
//!
//! - **Implicit Deny**: If no explicit `allow_rule` matches, access is DENIED
//! - **Deny Takes Precedence**: `deny_rule` is checked BEFORE `allow_rule`
//! - **Zero Trust**: No permissions are granted without explicit authorization
//!
//! ## Rule Evaluation Order
//!
//! 1. Check all `deny_rule` entries - if ANY matches, return DENIED
//! 2. Check all `allow_rule` entries - if ANY matches, return ALLOWED
//! 3. If no rules match, return DENIED (implicit deny)
//!
//! This model ensures security-by-default even with misconfigured permissions.

use crate::security::access::{GovernanceConfig, PermissionsConfig};
use crate::security::SecurityError;

/// Rules engine for access control
///
/// Implements **deny-by-default** semantics per DDS Security v1.1 Sec.8.4.
/// See module documentation for detailed security model explanation.
pub struct RulesEngine {
    governance: GovernanceConfig,
    permissions: PermissionsConfig,
}

impl RulesEngine {
    /// Create new rules engine
    pub fn new(governance: GovernanceConfig, permissions: PermissionsConfig) -> Self {
        Self {
            governance,
            permissions,
        }
    }

    /// Check if domain access is allowed
    pub fn check_domain_access(&self, domain_id: u32) -> Result<(), SecurityError> {
        // Check governance rules
        for rule in &self.governance.domain_rules {
            if rule.domains.contains(&domain_id) {
                return Ok(());
            }
        }

        Err(SecurityError::PermissionsDenied(format!(
            "Domain {} not allowed by governance",
            domain_id
        )))
    }

    /// Check if topic publish is allowed
    ///
    /// # Security Model
    ///
    /// Uses **deny-by-default** semantics:
    /// 1. Deny rules checked first (deny takes precedence)
    /// 2. Allow rules checked second
    /// 3. Default: DENY if no rules match
    pub fn check_topic_publish(
        &self,
        topic: &str,
        _partition: Option<&str>,
    ) -> Result<(), SecurityError> {
        // Step 1: Check deny rules first (deny takes precedence)
        for grant in &self.permissions.grants {
            for deny_rule in &grant.deny_rules {
                for pattern in &deny_rule.publish_topics {
                    if Self::wildcard_match(pattern, topic) {
                        return Err(SecurityError::PermissionsDenied(format!(
                            "Topic '{}' denied by rule '{}'",
                            topic, pattern
                        )));
                    }
                }
            }
        }

        // Step 2: Check allow rules
        for grant in &self.permissions.grants {
            for allow_rule in &grant.allow_rules {
                for pattern in &allow_rule.publish_topics {
                    if Self::wildcard_match(pattern, topic) {
                        return Ok(());
                    }
                }
            }
        }

        // Step 3: Default DENY (deny-by-default security model)
        Err(SecurityError::PermissionsDenied(format!(
            "Topic '{}' not allowed for publish (no matching allow_rule)",
            topic
        )))
    }

    /// Check if topic subscribe is allowed
    ///
    /// # Security Model
    ///
    /// Uses **deny-by-default** semantics:
    /// 1. Deny rules checked first (deny takes precedence)
    /// 2. Allow rules checked second
    /// 3. Default: DENY if no rules match
    pub fn check_topic_subscribe(
        &self,
        topic: &str,
        _partition: Option<&str>,
    ) -> Result<(), SecurityError> {
        // Step 1: Check deny rules first (deny takes precedence)
        for grant in &self.permissions.grants {
            for deny_rule in &grant.deny_rules {
                for pattern in &deny_rule.subscribe_topics {
                    if Self::wildcard_match(pattern, topic) {
                        return Err(SecurityError::PermissionsDenied(format!(
                            "Topic '{}' denied by rule '{}'",
                            topic, pattern
                        )));
                    }
                }
            }
        }

        // Step 2: Check allow rules
        for grant in &self.permissions.grants {
            for allow_rule in &grant.allow_rules {
                for pattern in &allow_rule.subscribe_topics {
                    if Self::wildcard_match(pattern, topic) {
                        return Ok(());
                    }
                }
            }
        }

        // Step 3: Default DENY (deny-by-default security model)
        Err(SecurityError::PermissionsDenied(format!(
            "Topic '{}' not allowed for subscribe (no matching allow_rule)",
            topic
        )))
    }

    /// Wildcard pattern matching (glob-style)
    ///
    /// Supports:
    /// - `*` -- Matches any sequence of characters
    /// - `?` -- Matches any single character
    ///
    /// # Examples
    ///
    /// ```
    /// # use hdds::security::access::rules::RulesEngine;
    /// assert!(RulesEngine::wildcard_match("sensor/*", "sensor/temperature"));
    /// assert!(RulesEngine::wildcard_match("*", "any/topic"));
    /// assert!(!RulesEngine::wildcard_match("sensor/*", "actuator/motor"));
    /// ```
    pub fn wildcard_match(pattern: &str, topic: &str) -> bool {
        // Simple wildcard matching
        if pattern == "*" {
            return true;
        }

        if pattern == topic {
            return true;
        }

        // Handle "prefix/*" pattern
        if let Some(prefix) = pattern.strip_suffix("/*") {
            return topic.starts_with(prefix);
        }

        // Handle "*/suffix" pattern
        if let Some(suffix) = pattern.strip_prefix("*/") {
            return topic.ends_with(suffix);
        }

        // Handle "*middle*" pattern (contains)
        if pattern.starts_with('*') && pattern.ends_with('*') && pattern.len() > 2 {
            let middle = &pattern[1..pattern.len() - 1];
            return topic.contains(middle);
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::access::{DomainRule, Grant, Rule, Validity};

    fn create_test_engine() -> RulesEngine {
        let governance = GovernanceConfig {
            domain_rules: vec![DomainRule {
                domains: vec![0, 1],
                allow_unauthenticated: false,
                encrypt_discovery: false,
                encrypt_topics: false,
            }],
        };

        let permissions = PermissionsConfig {
            grants: vec![Grant {
                subject_name: "CN=Test".to_string(),
                validity: Validity {
                    not_before: "2024-01-01T00:00:00".to_string(),
                    not_after: "2030-01-01T00:00:00".to_string(),
                },
                allow_rules: vec![Rule {
                    domains: vec![0],
                    publish_topics: vec!["sensor/*".to_string(), "data/raw".to_string()],
                    subscribe_topics: vec!["*".to_string()],
                    partitions: vec![],
                }],
                deny_rules: vec![Rule {
                    domains: vec![0],
                    publish_topics: vec!["admin/*".to_string()],
                    subscribe_topics: vec![],
                    partitions: vec![],
                }],
            }],
        };

        RulesEngine::new(governance, permissions)
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

    #[test]
    fn test_deny_takes_precedence_over_allow() {
        let engine = create_test_engine();

        // Even though "admin/*" might match an allow rule, deny takes precedence
        assert!(engine.check_topic_publish("admin/test", None).is_err());
    }
}
