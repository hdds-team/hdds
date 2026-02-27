// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Persistence service configuration

use serde::{Deserialize, Serialize};

/// Persistence service configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Topic filter (supports wildcards: "State/*", "*")
    pub topic_filter: String,

    /// Retention policy: maximum number of samples to keep per topic
    pub retention_count: usize,

    /// Retention policy: maximum age of samples in seconds (0 = infinite)
    pub retention_time_secs: u64,

    /// Retention policy: maximum total storage size in bytes (0 = infinite)
    pub retention_size_bytes: u64,

    /// Domain ID to join
    pub domain_id: u32,

    /// Participant name
    pub participant_name: String,

    /// Subscribe to volatile writers (default: false, only TRANSIENT_LOCAL)
    pub subscribe_volatile: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            topic_filter: "*".to_string(),
            retention_count: 10000,
            retention_time_secs: 0,
            retention_size_bytes: 0,
            domain_id: 0,
            participant_name: "PersistenceService".to_string(),
            subscribe_volatile: false,
        }
    }
}

impl Config {
    /// Create a new config builder
    pub fn builder() -> ConfigBuilder {
        ConfigBuilder::default()
    }
}

/// Config builder for fluent API
#[derive(Debug, Default)]
pub struct ConfigBuilder {
    topic_filter: Option<String>,
    retention_count: Option<usize>,
    retention_time_secs: Option<u64>,
    retention_size_bytes: Option<u64>,
    domain_id: Option<u32>,
    participant_name: Option<String>,
    subscribe_volatile: Option<bool>,
}

impl ConfigBuilder {
    /// Set topic filter (supports wildcards: "State/*", "*")
    pub fn topic_filter(mut self, filter: impl Into<String>) -> Self {
        self.topic_filter = Some(filter.into());
        self
    }

    /// Set retention count (maximum samples per topic)
    pub fn retention_count(mut self, count: usize) -> Self {
        self.retention_count = Some(count);
        self
    }

    /// Set retention time in seconds (0 = infinite)
    pub fn retention_time_secs(mut self, secs: u64) -> Self {
        self.retention_time_secs = Some(secs);
        self
    }

    /// Set retention size in bytes (0 = infinite)
    pub fn retention_size_bytes(mut self, bytes: u64) -> Self {
        self.retention_size_bytes = Some(bytes);
        self
    }

    /// Set domain ID
    pub fn domain_id(mut self, id: u32) -> Self {
        self.domain_id = Some(id);
        self
    }

    /// Set participant name
    pub fn participant_name(mut self, name: impl Into<String>) -> Self {
        self.participant_name = Some(name.into());
        self
    }

    /// Subscribe to volatile writers (default: false)
    pub fn subscribe_volatile(mut self, subscribe: bool) -> Self {
        self.subscribe_volatile = Some(subscribe);
        self
    }

    /// Build the configuration
    pub fn build(self) -> Config {
        let defaults = Config::default();

        Config {
            topic_filter: self.topic_filter.unwrap_or(defaults.topic_filter),
            retention_count: self.retention_count.unwrap_or(defaults.retention_count),
            retention_time_secs: self
                .retention_time_secs
                .unwrap_or(defaults.retention_time_secs),
            retention_size_bytes: self
                .retention_size_bytes
                .unwrap_or(defaults.retention_size_bytes),
            domain_id: self.domain_id.unwrap_or(defaults.domain_id),
            participant_name: self.participant_name.unwrap_or(defaults.participant_name),
            subscribe_volatile: self
                .subscribe_volatile
                .unwrap_or(defaults.subscribe_volatile),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_builder() {
        let config = Config::builder()
            .topic_filter("State/*")
            .retention_count(500)
            .retention_time_secs(3600)
            .domain_id(42)
            .participant_name("TestPersistence")
            .build();

        assert_eq!(config.topic_filter, "State/*");
        assert_eq!(config.retention_count, 500);
        assert_eq!(config.retention_time_secs, 3600);
        assert_eq!(config.domain_id, 42);
        assert_eq!(config.participant_name, "TestPersistence");
    }

    #[test]
    fn test_config_defaults() {
        let config = Config::default();

        assert_eq!(config.topic_filter, "*");
        assert_eq!(config.retention_count, 10000);
        assert_eq!(config.retention_time_secs, 0);
        assert_eq!(config.domain_id, 0);
    }
}
