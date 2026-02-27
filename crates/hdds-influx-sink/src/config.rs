// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! YAML configuration for the InfluxDB sink.

use serde::Deserialize;
use std::fmt;
use std::path::Path;

/// Top-level sink configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct SinkConfig {
    /// Per-topic sink configurations.
    pub sinks: Vec<TopicSinkConfig>,
    /// InfluxDB connection settings.
    pub influxdb: InfluxDbConfig,
}

/// Configuration for a single DDS topic sink.
#[derive(Debug, Clone, Deserialize)]
pub struct TopicSinkConfig {
    /// DDS topic name to subscribe to.
    pub topic: String,
    /// InfluxDB measurement name.
    pub measurement: String,
    /// Fields from the DDS sample to use as InfluxDB tags.
    pub tags: Vec<String>,
    /// Fields from the DDS sample to use as InfluxDB fields.
    pub fields: Vec<String>,
    /// Maximum samples per second (downsample). None = no limit.
    pub sample_rate: Option<u32>,
    /// Number of lines to batch before flush. None = default (1000).
    pub batch_size: Option<usize>,
    /// Flush interval in milliseconds. None = default (1000).
    pub flush_interval_ms: Option<u64>,
}

/// InfluxDB v2 connection configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct InfluxDbConfig {
    /// InfluxDB URL (e.g., "http://localhost:8086").
    pub url: String,
    /// InfluxDB organization.
    pub org: String,
    /// InfluxDB bucket.
    pub bucket: String,
    /// Authentication token.
    pub token: String,
}

/// Configuration parsing errors.
#[derive(Debug)]
pub enum ConfigError {
    /// YAML parsing failed.
    Yaml(serde_yaml::Error),
    /// File I/O failed.
    Io(std::io::Error),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::Yaml(e) => write!(f, "YAML parse error: {}", e),
            ConfigError::Io(e) => write!(f, "I/O error: {}", e),
        }
    }
}

impl std::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ConfigError::Yaml(e) => Some(e),
            ConfigError::Io(e) => Some(e),
        }
    }
}

impl From<serde_yaml::Error> for ConfigError {
    fn from(e: serde_yaml::Error) -> Self {
        ConfigError::Yaml(e)
    }
}

impl From<std::io::Error> for ConfigError {
    fn from(e: std::io::Error) -> Self {
        ConfigError::Io(e)
    }
}

impl SinkConfig {
    /// Parse configuration from a YAML string.
    pub fn from_yaml(yaml: &str) -> Result<Self, ConfigError> {
        let config: SinkConfig = serde_yaml::from_str(yaml)?;
        Ok(config)
    }

    /// Parse configuration from a YAML file.
    pub fn from_file(path: &Path) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path)?;
        Self::from_yaml(&content)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL_YAML: &str = r#"
influxdb:
  url: "http://localhost:8086"
  org: "myorg"
  bucket: "mybucket"
  token: "mytoken"
sinks:
  - topic: "Temperature"
    measurement: "temperature"
    tags:
      - sensor_id
    fields:
      - value
"#;

    const FULL_YAML: &str = r#"
influxdb:
  url: "http://influx.example.com:8086"
  org: "example-org"
  bucket: "telemetry"
  token: "test-token-placeholder"
sinks:
  - topic: "Temperature"
    measurement: "temperature"
    tags:
      - sensor_id
      - location
    fields:
      - value
      - unit
    sample_rate: 10
    batch_size: 500
    flush_interval_ms: 2000
  - topic: "Pressure"
    measurement: "pressure"
    tags:
      - sensor_id
    fields:
      - value
      - altitude
    sample_rate: 5
    batch_size: 200
    flush_interval_ms: 5000
"#;

    #[test]
    fn test_config_parse_minimal() {
        let config = SinkConfig::from_yaml(MINIMAL_YAML).expect("parse minimal yaml");

        assert_eq!(config.influxdb.url, "http://localhost:8086");
        assert_eq!(config.influxdb.org, "myorg");
        assert_eq!(config.influxdb.bucket, "mybucket");
        assert_eq!(config.influxdb.token, "mytoken");

        assert_eq!(config.sinks.len(), 1);
        assert_eq!(config.sinks[0].topic, "Temperature");
        assert_eq!(config.sinks[0].measurement, "temperature");
        assert_eq!(config.sinks[0].tags, vec!["sensor_id"]);
        assert_eq!(config.sinks[0].fields, vec!["value"]);
        assert!(config.sinks[0].sample_rate.is_none());
        assert!(config.sinks[0].batch_size.is_none());
        assert!(config.sinks[0].flush_interval_ms.is_none());
    }

    #[test]
    fn test_config_parse_all_fields() {
        let config = SinkConfig::from_yaml(FULL_YAML).expect("parse full yaml");

        assert_eq!(config.influxdb.url, "http://influx.example.com:8086");
        assert_eq!(config.influxdb.org, "prod-org");
        assert_eq!(config.influxdb.bucket, "telemetry");
        assert_eq!(config.influxdb.token, "test-token-placeholder");

        assert_eq!(config.sinks.len(), 2);

        let temp = &config.sinks[0];
        assert_eq!(temp.topic, "Temperature");
        assert_eq!(temp.measurement, "temperature");
        assert_eq!(temp.tags, vec!["sensor_id", "location"]);
        assert_eq!(temp.fields, vec!["value", "unit"]);
        assert_eq!(temp.sample_rate, Some(10));
        assert_eq!(temp.batch_size, Some(500));
        assert_eq!(temp.flush_interval_ms, Some(2000));

        let press = &config.sinks[1];
        assert_eq!(press.topic, "Pressure");
        assert_eq!(press.measurement, "pressure");
        assert_eq!(press.tags, vec!["sensor_id"]);
        assert_eq!(press.fields, vec!["value", "altitude"]);
        assert_eq!(press.sample_rate, Some(5));
        assert_eq!(press.batch_size, Some(200));
        assert_eq!(press.flush_interval_ms, Some(5000));
    }
}
