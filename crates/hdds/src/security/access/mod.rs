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

pub mod permissions;
pub mod rules;

pub use permissions::{DomainRule, GovernanceConfig, Grant, PermissionsConfig, Rule, Validity};
pub use rules::RulesEngine;

/// Access Control Plugin implementing DDS Security v1.1 Sec.8.4-8.5
pub struct AccessControlPlugin {
    /// Rules engine (governance + permissions)
    rules: RulesEngine,
}

impl AccessControlPlugin {
    /// Create access control plugin from XML files
    pub fn from_xml(governance_xml: &str, permissions_xml: &str) -> Result<Self, SecurityError> {
        let governance = GovernanceConfig::parse(governance_xml)?;
        let permissions = PermissionsConfig::parse(permissions_xml)?;

        Ok(Self {
            rules: RulesEngine::new(governance, permissions),
        })
    }

    /// Check if participant can join domain
    pub fn check_create_participant(&self, domain_id: u32) -> Result<(), SecurityError> {
        self.rules.check_domain_access(domain_id)
    }

    /// Check if participant can create writer on topic
    pub fn check_create_writer(
        &self,
        topic: &str,
        partition: Option<&str>,
    ) -> Result<(), SecurityError> {
        self.rules.check_topic_publish(topic, partition)
    }

    /// Check if participant can create reader on topic
    pub fn check_create_reader(
        &self,
        topic: &str,
        partition: Option<&str>,
    ) -> Result<(), SecurityError> {
        self.rules.check_topic_subscribe(topic, partition)
    }

    /// Check if remote writer is allowed
    pub fn check_remote_writer(&self, topic: &str) -> Result<(), SecurityError> {
        self.rules.check_topic_publish(topic, None)
    }

    /// Check if remote reader is allowed
    pub fn check_remote_reader(&self, topic: &str) -> Result<(), SecurityError> {
        self.rules.check_topic_subscribe(topic, None)
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
    <allow_unauthenticated>false</allow_unauthenticated>
  </domain_rule>
</governance>"#;

        let permissions = r#"<?xml version="1.0"?>
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

        let plugin = AccessControlPlugin::from_xml(governance, permissions).unwrap();

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
  </domain_rule>
</governance>"#;

        let permissions = r#"<?xml version="1.0"?>
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
    </allow_rule>
    <deny_rule>
      <domains>0</domains>
      <publish>
        <topics>admin/*</topics>
      </publish>
    </deny_rule>
  </grant>
</permissions>"#;

        let plugin = AccessControlPlugin::from_xml(governance, permissions).unwrap();

        // Should deny
        assert!(plugin.check_create_writer("admin/shutdown", None).is_err());
    }
}
