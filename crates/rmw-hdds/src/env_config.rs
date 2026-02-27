// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Environment variable configuration for rmw_hdds.
//!
//! Reads runtime configuration from environment variables:
//!
//! ## Core Configuration
//! - `HDDS_DOMAIN_ID`: DDS domain ID (default: 0, or ROS_DOMAIN_ID if set)
//! - `HDDS_PARTICIPANT_ID`: Participant ID within domain (0-119)
//! - `HDDS_INTERFACE`: Network interface for multicast (default: system default)
//! - `HDDS_MULTICAST_ADDRESS`: Custom multicast address (e.g., "239.255.0.1")
//! - `HDDS_LOG_LEVEL`: Logging level (default: "info")
//! - `HDDS_QOS_PROFILE_PATH`: Path to QoS profile XML/YAML file
//!
//! ## Discovery Configuration
//! - `HDDS_DISCOVERY_PEERS`: Comma-separated list of static peers ("host:port,...")
//! - `HDDS_INITIAL_PEERS`: Alias for HDDS_DISCOVERY_PEERS
//!
//! ## Security Configuration (DDS Security v1.1)
//! - `HDDS_SECURITY_ENABLE`: Enable security ("1" or "true")
//! - `HDDS_SECURITY_IDENTITY_CERT`: Path to identity certificate (PEM)
//! - `HDDS_SECURITY_IDENTITY_KEY`: Path to identity private key (PEM)
//! - `HDDS_SECURITY_CA_CERT`: Path to CA certificate (PEM)
//! - `HDDS_SECURITY_PERMISSIONS`: Path to permissions XML
//! - `HDDS_SECURITY_GOVERNANCE`: Path to governance XML
//!
//! ## ROS 2 Compatibility
//! - `ROS_DOMAIN_ID`: Fallback for HDDS_DOMAIN_ID
//! - `ROS_SECURITY_ENABLE`: Fallback for HDDS_SECURITY_ENABLE
//! - `ROS_SECURITY_ENCLAVE`: Security enclave path (SROS2 compatibility)
//!
//! # Example
//!
//! ```bash
//! # Basic configuration
//! export HDDS_DOMAIN_ID=42
//! export HDDS_INTERFACE=eth0
//! export HDDS_LOG_LEVEL=debug
//!
//! # Static peer discovery
//! export HDDS_DISCOVERY_PEERS="192.168.1.10:7400,192.168.1.11:7400"
//!
//! # Security configuration
//! export HDDS_SECURITY_ENABLE=true
//! export HDDS_SECURITY_IDENTITY_CERT=/certs/identity.pem
//! export HDDS_SECURITY_IDENTITY_KEY=/certs/identity_key.pem
//! export HDDS_SECURITY_CA_CERT=/certs/ca.pem
//! ```

use std::env;

/// Environment variable names
pub const ENV_DOMAIN_ID: &str = "HDDS_DOMAIN_ID";
pub const ENV_INTERFACE: &str = "HDDS_INTERFACE";
pub const ENV_LOG_LEVEL: &str = "HDDS_LOG_LEVEL";
pub const ENV_QOS_PROFILE_PATH: &str = "HDDS_QOS_PROFILE_PATH";
pub const ENV_CONFIG_FILE: &str = "HDDS_CONFIG_FILE";
pub const ENV_PARTICIPANT_ID: &str = "HDDS_PARTICIPANT_ID";
pub const ENV_MULTICAST_ADDRESS: &str = "HDDS_MULTICAST_ADDRESS";
pub const ENV_MULTICAST_DISABLE: &str = "HDDS_MULTICAST_DISABLE";
pub const ENV_SHM_DISABLE: &str = "HDDS_SHM_DISABLE";
pub const ENV_DISCOVERY_PEERS: &str = "HDDS_DISCOVERY_PEERS";
pub const ENV_DISCOVERY_PORT: &str = "HDDS_DISCOVERY_PORT";
pub const ENV_INITIAL_PEERS: &str = "HDDS_INITIAL_PEERS";

/// Security environment variables (DDS Security v1.1)
pub const ENV_SECURITY_ENABLE: &str = "HDDS_SECURITY_ENABLE";
pub const ENV_SECURITY_IDENTITY_CERT: &str = "HDDS_SECURITY_IDENTITY_CERT";
pub const ENV_SECURITY_IDENTITY_KEY: &str = "HDDS_SECURITY_IDENTITY_KEY";
pub const ENV_SECURITY_CA_CERT: &str = "HDDS_SECURITY_CA_CERT";
pub const ENV_SECURITY_PERMISSIONS: &str = "HDDS_SECURITY_PERMISSIONS";
pub const ENV_SECURITY_GOVERNANCE: &str = "HDDS_SECURITY_GOVERNANCE";

/// ROS 2 environment variable for domain ID (fallback)
pub const ENV_ROS_DOMAIN_ID: &str = "ROS_DOMAIN_ID";
/// ROS 2 security enclave (compatibility)
pub const ENV_ROS_SECURITY_ENCLAVE: &str = "ROS_SECURITY_ENCLAVE";
/// ROS 2 security enable (compatibility)
pub const ENV_ROS_SECURITY_ENABLE: &str = "ROS_SECURITY_ENABLE";

/// Runtime configuration from environment variables
#[derive(Debug, Clone)]
pub struct EnvConfig {
    /// DDS domain ID (0-232)
    pub domain_id: u32,

    /// Participant ID within the domain (0-119)
    pub participant_id: Option<u8>,

    /// Network interface name (e.g., "eth0", "lo")
    pub interface: Option<String>,

    /// Custom multicast address (e.g., "239.255.0.1")
    pub multicast_address: Option<String>,

    /// Disable multicast discovery (use unicast only)
    pub multicast_disable: bool,

    /// Disable shared memory transport
    pub shm_disable: bool,

    /// Static discovery peers (comma-separated list of "host:port")
    pub discovery_peers: Vec<String>,

    /// Custom discovery port (default: 7400)
    pub discovery_port: Option<u16>,

    /// Logging level (trace, debug, info, warn, error)
    pub log_level: String,

    /// Path to QoS profile file
    pub qos_profile_path: Option<String>,

    /// Path to general config file
    pub config_file: Option<String>,

    /// Security configuration
    pub security: Option<SecurityEnvConfig>,
}

/// Security configuration from environment variables
#[derive(Debug, Clone)]
pub struct SecurityEnvConfig {
    /// Path to identity certificate (PEM format)
    pub identity_cert_path: Option<String>,

    /// Path to identity private key (PEM format)
    pub identity_key_path: Option<String>,

    /// Path to CA certificate (PEM format)
    pub ca_cert_path: Option<String>,

    /// Path to permissions XML file
    pub permissions_path: Option<String>,

    /// Path to governance XML file
    pub governance_path: Option<String>,

    /// ROS 2 security enclave (for SROS2 compatibility)
    pub ros_enclave: Option<String>,
}

impl Default for EnvConfig {
    fn default() -> Self {
        Self {
            domain_id: 0,
            participant_id: None,
            interface: None,
            multicast_address: None,
            multicast_disable: false,
            shm_disable: false,
            discovery_peers: Vec::new(),
            discovery_port: None,
            log_level: "info".to_string(),
            qos_profile_path: None,
            config_file: None,
            security: None,
        }
    }
}

impl EnvConfig {
    /// Load configuration from environment variables
    ///
    /// Priority for domain ID:
    /// 1. HDDS_DOMAIN_ID
    /// 2. ROS_DOMAIN_ID
    /// 3. Default (0)
    #[must_use]
    pub fn from_env() -> Self {
        let domain_id = env::var(ENV_DOMAIN_ID)
            .ok()
            .and_then(|s| s.parse::<u32>().ok())
            .or_else(|| {
                env::var(ENV_ROS_DOMAIN_ID)
                    .ok()
                    .and_then(|s| s.parse::<u32>().ok())
            })
            .unwrap_or(0);

        let participant_id = env::var(ENV_PARTICIPANT_ID)
            .ok()
            .and_then(|s| s.parse::<u8>().ok());

        let interface = env::var(ENV_INTERFACE).ok().filter(|s| !s.is_empty());

        let multicast_address = env::var(ENV_MULTICAST_ADDRESS)
            .ok()
            .filter(|s| !s.is_empty());

        // Check if multicast is disabled
        let multicast_disable = env::var(ENV_MULTICAST_DISABLE)
            .ok()
            .map(|s| s == "1" || s.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        // Check if shared memory is disabled
        let shm_disable = env::var(ENV_SHM_DISABLE)
            .ok()
            .map(|s| s == "1" || s.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        // Custom discovery port
        let discovery_port = env::var(ENV_DISCOVERY_PORT)
            .ok()
            .and_then(|s| s.parse::<u16>().ok());

        // Parse discovery peers from comma-separated list
        let discovery_peers = env::var(ENV_DISCOVERY_PEERS)
            .or_else(|_| env::var(ENV_INITIAL_PEERS))
            .ok()
            .map(|s| {
                s.split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(String::from)
                    .collect()
            })
            .unwrap_or_default();

        let log_level = env::var(ENV_LOG_LEVEL)
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "info".to_string());

        let qos_profile_path = env::var(ENV_QOS_PROFILE_PATH)
            .ok()
            .filter(|s| !s.is_empty());

        let config_file = env::var(ENV_CONFIG_FILE).ok().filter(|s| !s.is_empty());

        // Load security configuration
        let security = Self::load_security_config();

        Self {
            domain_id,
            participant_id,
            interface,
            multicast_address,
            multicast_disable,
            shm_disable,
            discovery_peers,
            discovery_port,
            log_level,
            qos_profile_path,
            config_file,
            security,
        }
    }

    /// Load security configuration from environment variables
    fn load_security_config() -> Option<SecurityEnvConfig> {
        // Check if security is enabled via either HDDS or ROS 2 env vars
        let hdds_enabled = env::var(ENV_SECURITY_ENABLE)
            .ok()
            .map(|s| s == "1" || s.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        let ros_enabled = env::var(ENV_ROS_SECURITY_ENABLE)
            .ok()
            .map(|s| s.eq_ignore_ascii_case("true") || s.eq_ignore_ascii_case("enforce"))
            .unwrap_or(false);

        if !hdds_enabled && !ros_enabled {
            return None;
        }

        Some(SecurityEnvConfig {
            identity_cert_path: env::var(ENV_SECURITY_IDENTITY_CERT)
                .ok()
                .filter(|s| !s.is_empty()),
            identity_key_path: env::var(ENV_SECURITY_IDENTITY_KEY)
                .ok()
                .filter(|s| !s.is_empty()),
            ca_cert_path: env::var(ENV_SECURITY_CA_CERT)
                .ok()
                .filter(|s| !s.is_empty()),
            permissions_path: env::var(ENV_SECURITY_PERMISSIONS)
                .ok()
                .filter(|s| !s.is_empty()),
            governance_path: env::var(ENV_SECURITY_GOVERNANCE)
                .ok()
                .filter(|s| !s.is_empty()),
            ros_enclave: env::var(ENV_ROS_SECURITY_ENCLAVE)
                .ok()
                .filter(|s| !s.is_empty()),
        })
    }

    /// Check if any custom configuration was provided
    #[must_use]
    pub fn is_custom(&self) -> bool {
        self.domain_id != 0
            || self.participant_id.is_some()
            || self.interface.is_some()
            || self.multicast_address.is_some()
            || self.multicast_disable
            || self.shm_disable
            || !self.discovery_peers.is_empty()
            || self.discovery_port.is_some()
            || self.log_level != "info"
            || self.qos_profile_path.is_some()
            || self.config_file.is_some()
            || self.security.is_some()
    }

    /// Check if multicast is disabled
    #[must_use]
    pub fn is_multicast_disabled(&self) -> bool {
        self.multicast_disable
    }

    /// Check if shared memory is disabled
    #[must_use]
    pub fn is_shm_disabled(&self) -> bool {
        self.shm_disable
    }

    /// Check if security is configured
    #[must_use]
    pub fn is_security_enabled(&self) -> bool {
        self.security.is_some()
    }

    /// Check if static discovery peers are configured
    #[must_use]
    pub fn has_discovery_peers(&self) -> bool {
        !self.discovery_peers.is_empty()
    }

    /// Apply log level to the logging subsystem
    pub fn apply_log_level(&self) {
        if let Err(e) = env::var("RUST_LOG") {
            // Only set if RUST_LOG is not already set
            if e == env::VarError::NotPresent {
                env::set_var("RUST_LOG", &self.log_level);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = EnvConfig::default();
        assert_eq!(config.domain_id, 0);
        assert!(config.interface.is_none());
        assert_eq!(config.log_level, "info");
        assert!(config.qos_profile_path.is_none());
        assert!(!config.is_custom());
    }

    #[test]
    fn test_from_env_with_hdds_domain_id() {
        // Save and clear existing env vars
        let prev_hdds = env::var(ENV_DOMAIN_ID).ok();
        let prev_ros = env::var(ENV_ROS_DOMAIN_ID).ok();

        env::set_var(ENV_DOMAIN_ID, "42");
        env::set_var(ENV_ROS_DOMAIN_ID, "99");

        let config = EnvConfig::from_env();
        assert_eq!(config.domain_id, 42); // HDDS_DOMAIN_ID takes priority

        // Restore
        if let Some(v) = prev_hdds {
            env::set_var(ENV_DOMAIN_ID, v);
        } else {
            env::remove_var(ENV_DOMAIN_ID);
        }
        if let Some(v) = prev_ros {
            env::set_var(ENV_ROS_DOMAIN_ID, v);
        } else {
            env::remove_var(ENV_ROS_DOMAIN_ID);
        }
    }

    #[test]
    fn test_from_env_fallback_to_ros_domain_id() {
        // Save and clear existing env vars
        let prev_hdds = env::var(ENV_DOMAIN_ID).ok();
        let prev_ros = env::var(ENV_ROS_DOMAIN_ID).ok();

        env::remove_var(ENV_DOMAIN_ID);
        env::set_var(ENV_ROS_DOMAIN_ID, "77");

        let config = EnvConfig::from_env();
        assert_eq!(config.domain_id, 77);

        // Restore
        if let Some(v) = prev_hdds {
            env::set_var(ENV_DOMAIN_ID, v);
        }
        if let Some(v) = prev_ros {
            env::set_var(ENV_ROS_DOMAIN_ID, v);
        } else {
            env::remove_var(ENV_ROS_DOMAIN_ID);
        }
    }

    #[test]
    fn test_from_env_with_interface() {
        let prev = env::var(ENV_INTERFACE).ok();

        env::set_var(ENV_INTERFACE, "eth0");

        let config = EnvConfig::from_env();
        assert_eq!(config.interface, Some("eth0".to_string()));

        // Restore
        if let Some(v) = prev {
            env::set_var(ENV_INTERFACE, v);
        } else {
            env::remove_var(ENV_INTERFACE);
        }
    }

    #[test]
    fn test_from_env_empty_interface_is_none() {
        let prev = env::var(ENV_INTERFACE).ok();

        env::set_var(ENV_INTERFACE, "");

        let config = EnvConfig::from_env();
        assert!(config.interface.is_none());

        // Restore
        if let Some(v) = prev {
            env::set_var(ENV_INTERFACE, v);
        } else {
            env::remove_var(ENV_INTERFACE);
        }
    }

    #[test]
    fn test_is_custom() {
        let mut config = EnvConfig::default();
        assert!(!config.is_custom());

        config.domain_id = 1;
        assert!(config.is_custom());

        config.domain_id = 0;
        config.interface = Some("lo".to_string());
        assert!(config.is_custom());
    }
}
