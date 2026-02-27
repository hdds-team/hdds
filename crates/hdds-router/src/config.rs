// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Router configuration.
//!
//! Supports both programmatic and file-based configuration.

use serde::{Deserialize, Serialize};
use std::path::Path;
use thiserror::Error;

/// Configuration errors.
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("TOML parse error: {0}")]
    Toml(#[from] toml::de::Error),

    #[error("Invalid configuration: {0}")]
    Invalid(String),
}

/// Router configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouterConfig {
    /// Router name (for identification).
    #[serde(default = "default_router_name")]
    pub name: String,

    /// Routes to configure.
    #[serde(default)]
    pub routes: Vec<RouteConfig>,

    /// Enable statistics collection.
    #[serde(default = "default_true")]
    pub enable_stats: bool,

    /// Statistics reporting interval (seconds).
    #[serde(default = "default_stats_interval")]
    pub stats_interval_secs: u64,

    /// Log level.
    #[serde(default = "default_log_level")]
    pub log_level: String,
}

fn default_router_name() -> String {
    "hdds-router".to_string()
}

fn default_true() -> bool {
    true
}

fn default_stats_interval() -> u64 {
    10
}

fn default_log_level() -> String {
    "info".to_string()
}

impl Default for RouterConfig {
    fn default() -> Self {
        Self {
            name: default_router_name(),
            routes: Vec::new(),
            enable_stats: true,
            stats_interval_secs: 10,
            log_level: "info".to_string(),
        }
    }
}

impl RouterConfig {
    /// Load configuration from a TOML file.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path)?;
        let config: Self = toml::from_str(&content)?;
        config.validate()?;
        Ok(config)
    }

    /// Create a simple bridge between two domains.
    pub fn bridge(from_domain: u32, to_domain: u32) -> Self {
        Self {
            routes: vec![RouteConfig {
                from_domain,
                to_domain,
                bidirectional: false,
                topics: TopicSelection::All,
                remaps: Vec::new(),
                qos_transform: None,
            }],
            ..Default::default()
        }
    }

    /// Create a bidirectional bridge between two domains.
    pub fn bidirectional_bridge(domain_a: u32, domain_b: u32) -> Self {
        Self {
            routes: vec![RouteConfig {
                from_domain: domain_a,
                to_domain: domain_b,
                bidirectional: true,
                topics: TopicSelection::All,
                remaps: Vec::new(),
                qos_transform: None,
            }],
            ..Default::default()
        }
    }

    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.routes.is_empty() {
            return Err(ConfigError::Invalid("No routes configured".into()));
        }

        for (i, route) in self.routes.iter().enumerate() {
            if route.from_domain == route.to_domain {
                return Err(ConfigError::Invalid(format!(
                    "Route {} has same source and destination domain ({})",
                    i, route.from_domain
                )));
            }

            // Validate remaps
            for remap in &route.remaps {
                if remap.from.is_empty() {
                    return Err(ConfigError::Invalid(format!(
                        "Route {} has empty remap source",
                        i
                    )));
                }
                if remap.to.is_empty() {
                    return Err(ConfigError::Invalid(format!(
                        "Route {} has empty remap destination",
                        i
                    )));
                }
            }
        }

        Ok(())
    }

    /// Add a route.
    pub fn add_route(&mut self, route: RouteConfig) {
        self.routes.push(route);
    }
}

/// Configuration for a single route.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteConfig {
    /// Source domain ID.
    pub from_domain: u32,

    /// Destination domain ID.
    pub to_domain: u32,

    /// Enable bidirectional routing.
    #[serde(default)]
    pub bidirectional: bool,

    /// Topics to route.
    #[serde(default)]
    pub topics: TopicSelection,

    /// Topic remappings.
    #[serde(default)]
    pub remaps: Vec<TopicRemap>,

    /// QoS transformation.
    #[serde(default)]
    pub qos_transform: Option<QosTransformConfig>,
}

impl RouteConfig {
    /// Create a new route.
    pub fn new(from_domain: u32, to_domain: u32) -> Self {
        Self {
            from_domain,
            to_domain,
            bidirectional: false,
            topics: TopicSelection::All,
            remaps: Vec::new(),
            qos_transform: None,
        }
    }

    /// Set bidirectional mode.
    pub fn bidirectional(mut self, enabled: bool) -> Self {
        self.bidirectional = enabled;
        self
    }

    /// Set topic selection.
    pub fn topics(mut self, selection: TopicSelection) -> Self {
        self.topics = selection;
        self
    }

    /// Add a topic remap.
    pub fn remap(mut self, from: impl Into<String>, to: impl Into<String>) -> Self {
        self.remaps.push(TopicRemap {
            from: from.into(),
            to: to.into(),
        });
        self
    }

    /// Set QoS transformation.
    pub fn qos(mut self, transform: QosTransformConfig) -> Self {
        self.qos_transform = Some(transform);
        self
    }
}

/// Topic selection for routing.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(tag = "type", content = "value")]
pub enum TopicSelection {
    /// Route all topics.
    #[default]
    All,

    /// Route only specified topics.
    Include(Vec<String>),

    /// Route all topics except specified.
    Exclude(Vec<String>),

    /// Route topics matching pattern (glob).
    Pattern(String),
}

impl TopicSelection {
    /// Check if a topic matches this selection.
    pub fn matches(&self, topic: &str) -> bool {
        match self {
            Self::All => true,
            Self::Include(topics) => topics
                .iter()
                .any(|t| t == topic || Self::glob_match(t, topic)),
            Self::Exclude(topics) => !topics
                .iter()
                .any(|t| t == topic || Self::glob_match(t, topic)),
            Self::Pattern(pattern) => Self::glob_match(pattern, topic),
        }
    }

    /// Simple glob matching (supports * and ?).
    fn glob_match(pattern: &str, text: &str) -> bool {
        let pattern_chars: Vec<char> = pattern.chars().collect();
        let text_chars: Vec<char> = text.chars().collect();
        Self::glob_match_recursive(&pattern_chars, &text_chars, 0, 0)
    }

    fn glob_match_recursive(pattern: &[char], text: &[char], pi: usize, ti: usize) -> bool {
        if pi == pattern.len() {
            return ti == text.len();
        }

        match pattern[pi] {
            '*' => {
                // Try matching zero or more characters
                for i in ti..=text.len() {
                    if Self::glob_match_recursive(pattern, text, pi + 1, i) {
                        return true;
                    }
                }
                false
            }
            '?' => {
                // Match exactly one character
                if ti < text.len() {
                    Self::glob_match_recursive(pattern, text, pi + 1, ti + 1)
                } else {
                    false
                }
            }
            c => {
                // Match literal character
                if ti < text.len() && text[ti] == c {
                    Self::glob_match_recursive(pattern, text, pi + 1, ti + 1)
                } else {
                    false
                }
            }
        }
    }
}

/// Topic remapping configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopicRemap {
    /// Source topic name (or pattern).
    pub from: String,

    /// Destination topic name (or template).
    pub to: String,
}

impl TopicRemap {
    /// Create a new remap.
    pub fn new(from: impl Into<String>, to: impl Into<String>) -> Self {
        Self {
            from: from.into(),
            to: to.into(),
        }
    }

    /// Apply this remap to a topic name.
    pub fn apply(&self, topic: &str) -> Option<String> {
        if self.from.contains('*') {
            // Pattern-based remap
            if TopicSelection::glob_match(&self.from, topic) {
                // Simple substitution: replace * in 'to' with matched portion
                if let Some(pos) = self.from.find('*') {
                    let prefix = &self.from[..pos];
                    let suffix = &self.from[pos + 1..];

                    if topic.starts_with(prefix) && topic.ends_with(suffix) {
                        let matched = &topic[prefix.len()..topic.len() - suffix.len()];
                        return Some(self.to.replace('*', matched));
                    }
                }
                // Fallback: just use 'to' directly
                Some(self.to.clone())
            } else {
                None
            }
        } else if self.from == topic {
            // Exact match
            Some(self.to.clone())
        } else {
            None
        }
    }
}

/// QoS transformation configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct QosTransformConfig {
    /// Override reliability (reliable/best_effort).
    pub reliability: Option<String>,

    /// Override durability (volatile/transient_local/transient/persistent).
    pub durability: Option<String>,

    /// Override history depth.
    pub history_depth: Option<u32>,

    /// Override deadline (microseconds).
    pub deadline_us: Option<u64>,

    /// Override lifespan (microseconds).
    pub lifespan_us: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_topic_selection_all() {
        let sel = TopicSelection::All;
        assert!(sel.matches("Temperature"));
        assert!(sel.matches("anything"));
    }

    #[test]
    fn test_topic_selection_include() {
        let sel = TopicSelection::Include(vec!["Temperature".into(), "Pressure".into()]);
        assert!(sel.matches("Temperature"));
        assert!(sel.matches("Pressure"));
        assert!(!sel.matches("Humidity"));
    }

    #[test]
    fn test_topic_selection_exclude() {
        let sel = TopicSelection::Exclude(vec!["Internal/*".into()]);
        assert!(sel.matches("Temperature"));
        assert!(!sel.matches("Internal/Debug"));
    }

    #[test]
    fn test_topic_selection_pattern() {
        let sel = TopicSelection::Pattern("Sensor/*".into());
        assert!(sel.matches("Sensor/Temperature"));
        assert!(sel.matches("Sensor/Pressure"));
        assert!(!sel.matches("Vehicle/Speed"));
    }

    #[test]
    fn test_glob_match() {
        assert!(TopicSelection::glob_match("*", "anything"));
        assert!(TopicSelection::glob_match("Sensor/*", "Sensor/Temperature"));
        assert!(TopicSelection::glob_match(
            "*/Temperature",
            "Sensor/Temperature"
        ));
        assert!(TopicSelection::glob_match("?est", "Test"));
        assert!(!TopicSelection::glob_match("?est", "Quest"));
    }

    #[test]
    fn test_topic_remap_exact() {
        let remap = TopicRemap::new("Temperature", "Vehicle/Temperature");
        assert_eq!(
            remap.apply("Temperature"),
            Some("Vehicle/Temperature".into())
        );
        assert_eq!(remap.apply("Pressure"), None);
    }

    #[test]
    fn test_topic_remap_pattern() {
        let remap = TopicRemap::new("Sensor/*", "Vehicle/*");
        assert_eq!(
            remap.apply("Sensor/Temperature"),
            Some("Vehicle/Temperature".into())
        );
        assert_eq!(remap.apply("Other/Temperature"), None);
    }

    #[test]
    fn test_router_config_bridge() {
        let config = RouterConfig::bridge(0, 1);
        assert_eq!(config.routes.len(), 1);
        assert_eq!(config.routes[0].from_domain, 0);
        assert_eq!(config.routes[0].to_domain, 1);
    }

    #[test]
    fn test_router_config_validation() {
        let mut config = RouterConfig::default();
        assert!(config.validate().is_err()); // No routes

        config.add_route(RouteConfig::new(0, 0)); // Same domain
        assert!(config.validate().is_err());

        config.routes.clear();
        config.add_route(RouteConfig::new(0, 1));
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_route_config_builder() {
        let route = RouteConfig::new(0, 1)
            .bidirectional(true)
            .topics(TopicSelection::Include(vec!["Temperature".into()]))
            .remap("Temperature", "Vehicle/Engine/Temperature");

        assert!(route.bidirectional);
        assert_eq!(route.remaps.len(), 1);
    }

    #[test]
    fn test_config_serialization() {
        let config = RouterConfig::bridge(0, 1);
        let toml_str = toml::to_string_pretty(&config).expect("serialize");
        assert!(toml_str.contains("from_domain = 0"));
        assert!(toml_str.contains("to_domain = 1"));
    }
}
