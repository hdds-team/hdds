// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Discovery Server configuration.

use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::path::Path;
use std::time::Duration;

/// Discovery Server configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Address to bind to (default: 0.0.0.0)
    #[serde(default = "default_bind_address")]
    pub bind_address: IpAddr,

    /// TCP port to listen on (default: 7400)
    #[serde(default = "default_port")]
    pub port: u16,

    /// Domain ID to serve (0 = all domains)
    #[serde(default)]
    pub domain_id: u32,

    /// Participant lease duration in seconds
    #[serde(default = "default_lease_duration")]
    pub lease_duration_secs: u64,

    /// Enable relay mode (forward DATA between participants)
    #[serde(default)]
    pub relay_enabled: bool,

    /// Maximum number of connected participants
    #[serde(default = "default_max_participants")]
    pub max_participants: usize,

    /// Maximum number of endpoints per participant
    #[serde(default = "default_max_endpoints")]
    pub max_endpoints_per_participant: usize,

    /// Heartbeat interval for lease checking (seconds)
    #[serde(default = "default_heartbeat_interval")]
    pub heartbeat_interval_secs: u64,

    /// Enable TCP keepalive on client connections
    #[serde(default = "default_true")]
    pub tcp_keepalive: bool,

    /// TCP keepalive interval in seconds
    #[serde(default = "default_keepalive_interval")]
    pub tcp_keepalive_interval_secs: u64,

    /// Maximum message size (bytes)
    #[serde(default = "default_max_message_size")]
    pub max_message_size: usize,

    /// Enable TLS (requires certificate configuration)
    #[serde(default)]
    pub tls_enabled: bool,

    /// TLS certificate file path (PEM)
    #[serde(default)]
    pub tls_cert_path: Option<String>,

    /// TLS private key file path (PEM)
    #[serde(default)]
    pub tls_key_path: Option<String>,
}

fn default_bind_address() -> IpAddr {
    "0.0.0.0".parse().unwrap()
}

fn default_port() -> u16 {
    7400
}

fn default_lease_duration() -> u64 {
    30
}

fn default_max_participants() -> usize {
    1000
}

fn default_max_endpoints() -> usize {
    10000
}

fn default_heartbeat_interval() -> u64 {
    5
}

fn default_true() -> bool {
    true
}

fn default_keepalive_interval() -> u64 {
    15
}

fn default_max_message_size() -> usize {
    16 * 1024 * 1024 // 16 MB
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind_address: default_bind_address(),
            port: default_port(),
            domain_id: 0,
            lease_duration_secs: default_lease_duration(),
            relay_enabled: false,
            max_participants: default_max_participants(),
            max_endpoints_per_participant: default_max_endpoints(),
            heartbeat_interval_secs: default_heartbeat_interval(),
            tcp_keepalive: true,
            tcp_keepalive_interval_secs: default_keepalive_interval(),
            max_message_size: default_max_message_size(),
            tls_enabled: false,
            tls_cert_path: None,
            tls_key_path: None,
        }
    }
}

impl ServerConfig {
    /// Load configuration from a JSON file.
    pub fn from_file(path: &Path) -> Result<Self, ConfigError> {
        let content =
            std::fs::read_to_string(path).map_err(|e| ConfigError::IoError(e.to_string()))?;

        serde_json::from_str(&content).map_err(|e| ConfigError::ParseError(e.to_string()))
    }

    /// Save configuration to a JSON file.
    pub fn to_file(&self, path: &Path) -> Result<(), ConfigError> {
        let content = serde_json::to_string_pretty(self)
            .map_err(|e| ConfigError::SerializeError(e.to_string()))?;

        std::fs::write(path, content).map_err(|e| ConfigError::IoError(e.to_string()))
    }

    /// Get lease duration as Duration.
    pub fn lease_duration(&self) -> Duration {
        Duration::from_secs(self.lease_duration_secs)
    }

    /// Get heartbeat interval as Duration.
    pub fn heartbeat_interval(&self) -> Duration {
        Duration::from_secs(self.heartbeat_interval_secs)
    }

    /// Validate configuration.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.port == 0 {
            return Err(ConfigError::InvalidValue("port cannot be 0".into()));
        }
        if self.lease_duration_secs == 0 {
            return Err(ConfigError::InvalidValue(
                "lease_duration_secs cannot be 0".into(),
            ));
        }
        if self.max_participants == 0 {
            return Err(ConfigError::InvalidValue(
                "max_participants cannot be 0".into(),
            ));
        }
        if self.tls_enabled {
            if self.tls_cert_path.is_none() {
                return Err(ConfigError::InvalidValue(
                    "tls_cert_path required when TLS enabled".into(),
                ));
            }
            if self.tls_key_path.is_none() {
                return Err(ConfigError::InvalidValue(
                    "tls_key_path required when TLS enabled".into(),
                ));
            }
        }
        Ok(())
    }
}

/// Configuration error types.
#[derive(Debug, Clone)]
pub enum ConfigError {
    IoError(String),
    ParseError(String),
    SerializeError(String),
    InvalidValue(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IoError(s) => write!(f, "I/O error: {}", s),
            Self::ParseError(s) => write!(f, "Parse error: {}", s),
            Self::SerializeError(s) => write!(f, "Serialize error: {}", s),
            Self::InvalidValue(s) => write!(f, "Invalid value: {}", s),
        }
    }
}

impl std::error::Error for ConfigError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ServerConfig::default();
        assert_eq!(config.port, 7400);
        assert_eq!(config.domain_id, 0);
        assert!(!config.relay_enabled);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_serialization() {
        let config = ServerConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let parsed: ServerConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config.port, parsed.port);
    }

    #[test]
    fn test_validation_port_zero() {
        let config = ServerConfig {
            port: 0,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validation_tls_without_cert() {
        let config = ServerConfig {
            tls_enabled: true,
            tls_cert_path: None,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_lease_duration() {
        let config = ServerConfig {
            lease_duration_secs: 60,
            ..Default::default()
        };
        assert_eq!(config.lease_duration(), Duration::from_secs(60));
    }
}
