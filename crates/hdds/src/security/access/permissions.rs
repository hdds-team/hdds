// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Governance and Permissions XML parsing for DDS Security v1.1

use crate::security::SecurityError;

/// Governance configuration (domain-wide security policies)
#[derive(Debug, Clone)]
pub struct GovernanceConfig {
    pub domain_rules: Vec<DomainRule>,
}

#[derive(Debug, Clone)]
pub struct DomainRule {
    pub domains: Vec<u32>,
    pub allow_unauthenticated: bool,
    pub encrypt_discovery: bool,
    pub encrypt_topics: bool,
}

impl GovernanceConfig {
    /// Parse governance.xml
    pub fn parse(xml: &str) -> Result<Self, SecurityError> {
        #[cfg(feature = "qos-loaders")]
        {
            let doc = roxmltree::Document::parse(xml).map_err(|e| {
                SecurityError::ConfigError(format!("Failed to parse governance XML: {}", e))
            })?;

            let mut domain_rules = Vec::new();

            for node in doc.descendants() {
                if node.tag_name().name() == "domain_rule" {
                    let mut domains = Vec::new();
                    let mut allow_unauthenticated = false;
                    let mut encrypt_discovery = false;
                    let mut encrypt_topics = false;

                    for child in node.children() {
                        match child.tag_name().name() {
                            "domains" => {
                                if let Some(text) = child.text() {
                                    if let Ok(domain_id) = text.trim().parse::<u32>() {
                                        domains.push(domain_id);
                                    }
                                }
                            }
                            "allow_unauthenticated" => {
                                if let Some(text) = child.text() {
                                    allow_unauthenticated = text.trim() == "true";
                                }
                            }
                            "encrypt_discovery" => {
                                if let Some(text) = child.text() {
                                    encrypt_discovery = text.trim() == "true";
                                }
                            }
                            "encrypt_topics" => {
                                if let Some(text) = child.text() {
                                    encrypt_topics = text.trim() == "true";
                                }
                            }
                            _ => {}
                        }
                    }

                    domain_rules.push(DomainRule {
                        domains,
                        allow_unauthenticated,
                        encrypt_discovery,
                        encrypt_topics,
                    });
                }
            }

            Ok(Self { domain_rules })
        }

        #[cfg(not(feature = "qos-loaders"))]
        {
            Err(SecurityError::ConfigError(
                "Governance XML parsing requires 'qos-loaders' feature".to_string(),
            ))
        }
    }
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
    pub allow_rules: Vec<Rule>,
    pub deny_rules: Vec<Rule>,
}

#[derive(Debug, Clone)]
pub struct Validity {
    pub not_before: String,
    pub not_after: String,
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub domains: Vec<u32>,
    pub publish_topics: Vec<String>,
    pub subscribe_topics: Vec<String>,
    pub partitions: Vec<String>,
}

impl PermissionsConfig {
    /// Parse permissions.xml
    pub fn parse(xml: &str) -> Result<Self, SecurityError> {
        #[cfg(feature = "qos-loaders")]
        {
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
                    let mut allow_rules = Vec::new();
                    let mut deny_rules = Vec::new();

                    for child in grant_node.children() {
                        match child.tag_name().name() {
                            "subject_name" => {
                                if let Some(text) = child.text() {
                                    subject_name = text.trim().to_string();
                                }
                            }
                            "validity" => {
                                for v_child in child.children() {
                                    match v_child.tag_name().name() {
                                        "not_before" => {
                                            if let Some(text) = v_child.text() {
                                                validity.not_before = text.trim().to_string();
                                            }
                                        }
                                        "not_after" => {
                                            if let Some(text) = v_child.text() {
                                                validity.not_after = text.trim().to_string();
                                            }
                                        }
                                        _ => {}
                                    }
                                }
                            }
                            "allow_rule" => {
                                if let Some(rule) = Self::parse_rule(&child) {
                                    allow_rules.push(rule);
                                }
                            }
                            "deny_rule" => {
                                if let Some(rule) = Self::parse_rule(&child) {
                                    deny_rules.push(rule);
                                }
                            }
                            _ => {}
                        }
                    }

                    grants.push(Grant {
                        subject_name,
                        validity,
                        allow_rules,
                        deny_rules,
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
    fn parse_rule(node: &roxmltree::Node) -> Option<Rule> {
        let mut domains = Vec::new();
        let mut publish_topics = Vec::new();
        let mut subscribe_topics = Vec::new();
        let mut partitions = Vec::new();

        for child in node.children() {
            match child.tag_name().name() {
                "domains" => {
                    if let Some(text) = child.text() {
                        if let Ok(domain_id) = text.trim().parse::<u32>() {
                            domains.push(domain_id);
                        }
                    }
                }
                "publish" => {
                    for pub_child in child.children() {
                        if pub_child.tag_name().name() == "topics" {
                            if let Some(text) = pub_child.text() {
                                publish_topics.push(text.trim().to_string());
                            }
                        }
                    }
                }
                "subscribe" => {
                    for sub_child in child.children() {
                        if sub_child.tag_name().name() == "topics" {
                            if let Some(text) = sub_child.text() {
                                subscribe_topics.push(text.trim().to_string());
                            }
                        }
                    }
                }
                "partitions" => {
                    if let Some(text) = child.text() {
                        partitions.push(text.trim().to_string());
                    }
                }
                _ => {}
            }
        }

        Some(Rule {
            domains,
            publish_topics,
            subscribe_topics,
            partitions,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "qos-loaders")]
    fn test_parse_governance_xml() {
        let xml = r#"<?xml version="1.0"?>
<governance>
  <domain_rule>
    <domains>0</domains>
    <allow_unauthenticated>false</allow_unauthenticated>
    <encrypt_discovery>true</encrypt_discovery>
    <encrypt_topics>true</encrypt_topics>
  </domain_rule>
</governance>"#;

        let config = GovernanceConfig::parse(xml).unwrap();
        assert_eq!(config.domain_rules.len(), 1);
        assert_eq!(config.domain_rules[0].domains, vec![0]);
        assert!(!config.domain_rules[0].allow_unauthenticated);
        assert!(config.domain_rules[0].encrypt_discovery);
        assert!(config.domain_rules[0].encrypt_topics);
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
        assert_eq!(config.grants[0].allow_rules.len(), 1);
        assert_eq!(
            config.grants[0].allow_rules[0].publish_topics,
            vec!["sensor/*"]
        );
        assert_eq!(config.grants[0].allow_rules[0].subscribe_topics, vec!["*"]);
    }
}
