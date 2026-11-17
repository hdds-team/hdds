// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Environment variable configuration for rmw_hdds.
//!
//! Reads runtime configuration from environment variables.
//!
//! # What actually reaches the engine
//!
//! This module PARSES more than the adapter APPLIES.
//! The table below is the honest split. Adding a variable to the parser does
//! not make it do anything - wire it, and name the test that proves it.
//!
//! | Variable | Applied? | Where, and what proves it |
//! |---|---|---|
//! | `HDDS_LOG_LEVEL` | yes | sets `RUST_LOG`; `hdds_c`'s `rmw_init_logger` brings `env_logger` up on the rmw entry path |
//! | `HDDS_DOMAIN_ID` | yes | `rmw_init.c` through `rmw_hdds_env_domain_id`, ahead of `ROS_DOMAIN_ID`, only when rcl passed no explicit domain |
//! | `HDDS_DISCOVERY_PEERS` | yes | `hdds::rmw::context::with_rmw_discovery_env` -> `ParticipantBuilder::with_seed_peers` |
//! | `HDDS_INITIAL_PEERS` | yes | same, as the documented alias (`both_documented_peer_spellings_reach_the_participant`) |
//! | `HDDS_MULTICAST_DISABLE` | yes | same, as `MulticastMode::Disabled` (`multicast_can_be_turned_off_for_a_ros_node`) |
//! | `HDDS_TRANSPORT` | yes | `RmwContext::create_with_domain` (`intra`/`intra_process`, `udp`/`udp_multicast`; anything else is refused by name) |
//! | `ROS_DOMAIN_ID` | yes | `rmw_init.c` |
//! | `ROS_SECURITY_STRATEGY` | yes | `rmw_init.c` REFUSES to start on `Enforce` |
//! | `HDDS_PARTICIPANT_ID` | yes, by the engine | the adapter sets no participant id, so `ParticipantBuilder` reads it itself (`builder/bootstrap.rs`, priority 2.5) |
//! | `HDDS_INTERFACE` | yes, by the engine | read by the UDP transport and socket setup for every participant (`transport/udp.rs`, `builder/sockets.rs`); the allowlist variant is `HDDS_INTERFACE_ALLOW` |
//! | `HDDS_MULTICAST_ADDRESS` | NO | parsed only |
//! | `HDDS_QOS_PROFILE_PATH` | NO | parsed only |
//! | `HDDS_CONFIG_FILE` | NO | parsed only |
//! | `HDDS_DISCOVERY_PORT` | NO | parsed only |
//! | `HDDS_SHM_DISABLE` | NO | parsed only |
//! | `HDDS_SECURITY_*` | NO | parsed only; no participant this adapter creates enables DDS-Security |
//! | `ROS_SECURITY_ENABLE`, `ROS_SECURITY_ENCLAVE` | NO | parsed only |
//!
//! ## Core Configuration
//! - `HDDS_DOMAIN_ID`: DDS domain ID. Wins over `ROS_DOMAIN_ID`, and only
//!   when rcl passed no explicit domain (`RMW_DEFAULT_DOMAIN_ID`): a domain a
//!   caller set programmatically is the caller's, not the environment's.
//!   A value that is not a decimal id in `0..=232` is an error, not domain 0
//!   (see [`env_domain_id`]).
//! - `HDDS_PARTICIPANT_ID`: Participant ID within domain (0-119) - PARSED ONLY
//! - `HDDS_INTERFACE`: Network interface for multicast - PARSED ONLY
//! - `HDDS_MULTICAST_ADDRESS`: Custom multicast address - PARSED ONLY
//! - `HDDS_LOG_LEVEL`: Logging level (default: "info")
//! - `HDDS_QOS_PROFILE_PATH`: Path to QoS profile XML/YAML file - PARSED ONLY
//!
//! ## Discovery Configuration
//! - `HDDS_DISCOVERY_PEERS`: Comma-separated list of static peers ("host:port,...")
//! - `HDDS_INITIAL_PEERS`: Alias for HDDS_DISCOVERY_PEERS
//! - `HDDS_MULTICAST_DISABLE`: "1"/"true" = unicast-only discovery. This is
//!   the mode the peer list exists for: a container network or a WAN segment
//!   where SPDP multicast reaches nobody.
//!
//! ## Security Configuration (DDS Security v1.1)
//!
//! PARSED ONLY. Nothing in `rmw_hdds/src` reads a keystore and no participant
//! this adapter creates enables DDS-Security, which is why `rmw_init` REFUSES
//! `ROS_SECURITY_STRATEGY=Enforce` instead of coming up unsecured.
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

/// The DDS domain the environment picks for an rcl init that passed no
/// explicit domain: `HDDS_DOMAIN_ID`, else `ROS_DOMAIN_ID`, else 0.
///
/// Both variables go through the core rule (`hdds::config::domain_id_from_env`),
/// so a malformed or out-of-range value is an error here too. Before, this
/// parsed with `.ok()` and fell back to 0 without a word.
pub fn env_domain_id() -> hdds::dds::Result<u32> {
    if let Some(id) = hdds::config::domain_id_from_env(ENV_DOMAIN_ID)? {
        return Ok(id);
    }
    Ok(hdds::config::domain_id_from_env(ENV_ROS_DOMAIN_ID)?.unwrap_or(0))
}

/// Runtime configuration from environment variables
#[derive(Debug, Clone)]
pub struct EnvConfig {
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
    /// Load configuration from environment variables.
    ///
    /// The domain is not part of this: see [`env_domain_id`].
    #[must_use]
    pub fn from_env() -> Self {
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
        self.participant_id.is_some()
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

    /// Set only in the re-executed child process, see `with_env`.
    const CHILD_MARK: &str = "HDDS_TEST_ENV_CHILD";

    #[test]
    fn test_default_config() {
        let config = EnvConfig::default();
        assert!(config.interface.is_none());
        assert_eq!(config.log_level, "info");
        assert!(config.qos_profile_path.is_none());
        assert!(!config.is_custom());
    }

    /// Runs `body` with each `(name, value)` set (`None` = unset).
    ///
    /// No test in this module touches the process environment. In the test
    /// process this re-executes the test binary on `test_path` (the full
    /// libtest path) with the variables in the child's environment, and fails
    /// unless that child ran exactly one test and it passed. In the child it
    /// runs `body` directly, so a mistyped path cannot pass silently.
    fn with_env(test_path: &str, vars: &[(&str, Option<&str>)], body: impl FnOnce()) {
        if std::env::var_os(CHILD_MARK).is_some() {
            body();
            return;
        }
        let exe = std::env::current_exe().expect("test binary path");
        let mut child = std::process::Command::new(exe);
        child
            .args([test_path, "--exact", "--test-threads=1", "--nocapture"])
            .env(CHILD_MARK, "1");
        for &(name, value) in vars {
            if let Some(v) = value {
                child.env(name, v);
            } else {
                child.env_remove(name);
            }
        }
        let out = child.output().expect("spawn the env test child");
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            out.status.success(),
            "{test_path} failed in its child process:\n{stdout}{stderr}"
        );
        assert!(
            stdout.contains("test result: ok. 1 passed; 0 failed"),
            "the child did not run exactly {test_path}:\n{stdout}"
        );
    }

    #[test]
    fn env_domain_hdds_wins_over_ros() {
        with_env(
            "env_config::tests::env_domain_hdds_wins_over_ros",
            &[
                (ENV_DOMAIN_ID, Some("211")),
                (ENV_ROS_DOMAIN_ID, Some("212")),
            ],
            || assert_eq!(env_domain_id().unwrap(), 211),
        );
    }

    #[test]
    fn env_domain_ros_is_the_fallback() {
        with_env(
            "env_config::tests::env_domain_ros_is_the_fallback",
            &[(ENV_DOMAIN_ID, None), (ENV_ROS_DOMAIN_ID, Some("213"))],
            || assert_eq!(env_domain_id().unwrap(), 213),
        );
    }

    #[test]
    fn env_domain_empty_hdds_counts_as_unset() {
        with_env(
            "env_config::tests::env_domain_empty_hdds_counts_as_unset",
            &[(ENV_DOMAIN_ID, Some("")), (ENV_ROS_DOMAIN_ID, Some("214"))],
            || assert_eq!(env_domain_id().unwrap(), 214),
        );
    }

    #[test]
    fn env_domain_neither_set_is_zero() {
        with_env(
            "env_config::tests::env_domain_neither_set_is_zero",
            &[(ENV_DOMAIN_ID, None), (ENV_ROS_DOMAIN_ID, None)],
            || assert_eq!(env_domain_id().unwrap(), 0),
        );
    }

    #[test]
    fn env_domain_malformed_hdds_is_an_error_not_zero() {
        with_env(
            "env_config::tests::env_domain_malformed_hdds_is_an_error_not_zero",
            &[
                (ENV_DOMAIN_ID, Some("2x1")),
                (ENV_ROS_DOMAIN_ID, Some("215")),
            ],
            || {
                assert!(
                    env_domain_id().is_err(),
                    "malformed HDDS_DOMAIN_ID must be refused"
                )
            },
        );
    }

    #[test]
    fn env_domain_out_of_range_hdds_is_an_error() {
        with_env(
            "env_config::tests::env_domain_out_of_range_hdds_is_an_error",
            &[(ENV_DOMAIN_ID, Some("233")), (ENV_ROS_DOMAIN_ID, None)],
            || {
                assert!(
                    env_domain_id().is_err(),
                    "HDDS_DOMAIN_ID above 232 must be refused"
                )
            },
        );
    }

    #[test]
    fn env_domain_malformed_ros_is_an_error_too() {
        with_env(
            "env_config::tests::env_domain_malformed_ros_is_an_error_too",
            &[(ENV_DOMAIN_ID, None), (ENV_ROS_DOMAIN_ID, Some("abc"))],
            || {
                assert!(
                    env_domain_id().is_err(),
                    "malformed ROS_DOMAIN_ID must be refused"
                )
            },
        );
    }

    #[test]
    fn ffi_env_domain_writes_the_resolved_value() {
        with_env(
            "env_config::tests::ffi_env_domain_writes_the_resolved_value",
            &[(ENV_DOMAIN_ID, Some("217")), (ENV_ROS_DOMAIN_ID, None)],
            || {
                let mut out = u32::MAX;
                let ok = unsafe { crate::ffi::rmw_hdds_env_domain_id(&mut out) };
                assert!(ok);
                assert_eq!(out, 217);
            },
        );
    }

    #[test]
    fn ffi_env_domain_refuses_a_malformed_value_without_writing() {
        with_env(
            "env_config::tests::ffi_env_domain_refuses_a_malformed_value_without_writing",
            &[(ENV_DOMAIN_ID, Some("2x1")), (ENV_ROS_DOMAIN_ID, None)],
            || {
                let mut out = u32::MAX;
                let ok = unsafe { crate::ffi::rmw_hdds_env_domain_id(&mut out) };
                assert!(!ok);
                assert_eq!(out, u32::MAX, "a refused domain must not be written back");
            },
        );
    }

    #[test]
    fn test_from_env_with_interface() {
        with_env(
            "env_config::tests::test_from_env_with_interface",
            &[(ENV_INTERFACE, Some("eth0"))],
            || {
                let config = EnvConfig::from_env();
                assert_eq!(config.interface, Some("eth0".to_string()));
            },
        );
    }

    #[test]
    fn test_from_env_empty_interface_is_none() {
        with_env(
            "env_config::tests::test_from_env_empty_interface_is_none",
            &[(ENV_INTERFACE, Some(""))],
            || {
                let config = EnvConfig::from_env();
                assert!(config.interface.is_none());
            },
        );
    }

    #[test]
    fn test_is_custom() {
        let mut config = EnvConfig::default();
        assert!(!config.is_custom());

        config.interface = Some("lo".to_string());
        assert!(config.is_custom());
    }
}
