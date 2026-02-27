// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! NAT traversal support for HDDS via STUN (RFC 5389).
//!
//! This module provides automatic discovery of the public (reflexive) transport
//! address for DDS participants behind a NAT gateway:
//!
//! - **STUN client**: Sends Binding Requests to a STUN server and parses
//!   XOR-MAPPED-ADDRESS responses to learn the external IP:port mapping.
//! - **Keepalive**: Periodically refreshes the STUN binding to prevent the
//!   NAT mapping from expiring (typical timeout: 30-120s).
//! - **NatTraversal facade**: High-level API that combines STUN discovery
//!   and keepalive into a single start/stop lifecycle.
//!
//! # Architecture
//!
//! ```text
//! +--------------------------------------------------------------+
//! |                      NatTraversal                             |
//! |  +--------------------------------------------------------+  |
//! |  |                    NatKeepalive                         |  |
//! |  |  +--------------------------------------------------+  |  |
//! |  |  |                  StunClient                       |  |  |
//! |  |  |  - build_binding_request()                        |  |  |
//! |  |  |  - parse_binding_response()                       |  |  |
//! |  |  |  - discover_reflexive_address()                   |  |  |
//! |  |  +--------------------------------------------------+  |  |
//! |  |                                                        |  |
//! |  |  Background thread: periodic STUN refresh              |  |
//! |  +--------------------------------------------------------+  |
//! +--------------------------------------------------------------+
//! ```
//!
//! # Example
//!
//! ```rust,ignore
//! use hdds::transport::nat::{NatConfig, NatTraversal};
//! use std::time::Duration;
//!
//! let config = NatConfig {
//!     stun_server: "stun.l.google.com:19302".to_string(),
//!     enabled: true,
//!     keepalive_interval: Duration::from_secs(25),
//!     stun_timeout: Duration::from_secs(3),
//!     max_retries: 3,
//! };
//!
//! let mut nat = NatTraversal::new(config).unwrap();
//! let public_addr = nat.start().unwrap();
//! println!("Public address: {}:{}", public_addr.ip, public_addr.port);
//!
//! // ... later ...
//! nat.stop();
//! ```
//!
//! # Limitations
//!
//! - Only STUN Binding is implemented (not TURN relay or ICE).
//! - Symmetric NATs cannot be traversed with STUN alone; TURN support
//!   is planned as a separate feature.

pub mod keepalive;
pub mod stun;

use std::fmt;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::time::{Duration, Instant};

use keepalive::NatKeepalive;

// ============================================================================
// Configuration
// ============================================================================

/// NAT traversal configuration.
#[derive(Debug, Clone)]
pub struct NatConfig {
    /// STUN server address (hostname:port or IP:port).
    ///
    /// Default: `"stun.l.google.com:19302"` (Google public STUN server).
    pub stun_server: String,

    /// Whether NAT traversal is enabled.
    pub enabled: bool,

    /// Interval between keepalive STUN refreshes.
    ///
    /// Should be less than the NAT binding timeout (typically 30-120s).
    /// Default: 25 seconds.
    pub keepalive_interval: Duration,

    /// Timeout for a single STUN request/response exchange.
    ///
    /// Default: 3 seconds.
    pub stun_timeout: Duration,

    /// Maximum number of retransmissions per STUN discovery attempt.
    ///
    /// Default: 3.
    pub max_retries: u32,
}

impl Default for NatConfig {
    fn default() -> Self {
        Self {
            stun_server: "stun.l.google.com:19302".to_string(),
            enabled: false,
            keepalive_interval: Duration::from_secs(25),
            stun_timeout: Duration::from_secs(3),
            max_retries: 3,
        }
    }
}

// ============================================================================
// Discovered address
// ============================================================================

/// A reflexive (server-reflexive) transport address discovered via STUN.
///
/// This is the public IP:port as observed by the STUN server, which is
/// the address that remote peers should use to reach this participant.
#[derive(Debug, Clone, PartialEq)]
pub struct ReflexiveAddress {
    /// Public IP address as seen by the STUN server.
    pub ip: IpAddr,
    /// Public port as seen by the STUN server.
    pub port: u16,
    /// The STUN server that was used for discovery.
    pub server_used: SocketAddr,
    /// When this address was discovered (monotonic clock).
    pub discovered_at: Instant,
}

impl fmt::Display for ReflexiveAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{} (via {})", self.ip, self.port, self.server_used)
    }
}

// ============================================================================
// NAT type classification
// ============================================================================

/// NAT type detected via STUN probing.
///
/// Determines what traversal strategies are available:
/// - `NoNat` / `FullCone`: Direct connectivity, STUN sufficient.
/// - `RestrictedCone` / `PortRestricted`: STUN hole-punching works.
/// - `Symmetric`: STUN alone is insufficient; TURN relay is needed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatType {
    /// No NAT detected -- direct public connectivity.
    NoNat,
    /// Full cone NAT -- any external host can send to the mapped address.
    FullCone,
    /// Restricted cone NAT -- only hosts we've sent to can respond.
    RestrictedCone,
    /// Port-restricted cone NAT -- only the exact host:port we sent to can respond.
    PortRestricted,
    /// Symmetric NAT -- each destination gets a different mapping. TURN required.
    Symmetric,
    /// NAT type could not be determined.
    Unknown,
}

impl fmt::Display for NatType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoNat => write!(f, "No NAT"),
            Self::FullCone => write!(f, "Full Cone"),
            Self::RestrictedCone => write!(f, "Restricted Cone"),
            Self::PortRestricted => write!(f, "Port Restricted"),
            Self::Symmetric => write!(f, "Symmetric"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

// ============================================================================
// Errors
// ============================================================================

/// Errors from NAT traversal operations.
#[derive(Debug, Clone)]
pub enum NatError {
    /// NAT traversal is disabled in configuration.
    Disabled,
    /// DNS resolution or network I/O error.
    NetworkError(String),
    /// STUN server did not respond within the timeout.
    Timeout(String),
    /// STUN response was malformed or invalid.
    MalformedResponse(String),
    /// STUN server returned an error response.
    ServerError(String),
    /// Internal error (lock poisoning, thread spawn failure, etc.).
    InternalError(String),
}

impl fmt::Display for NatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Disabled => write!(f, "NAT traversal is disabled"),
            Self::NetworkError(msg) => write!(f, "NAT network error: {}", msg),
            Self::Timeout(msg) => write!(f, "NAT timeout: {}", msg),
            Self::MalformedResponse(msg) => write!(f, "NAT malformed response: {}", msg),
            Self::ServerError(msg) => write!(f, "NAT server error: {}", msg),
            Self::InternalError(msg) => write!(f, "NAT internal error: {}", msg),
        }
    }
}

impl std::error::Error for NatError {}

// ============================================================================
// NatTraversal facade
// ============================================================================

/// High-level NAT traversal manager.
///
/// Combines STUN discovery and keepalive into a single lifecycle:
///
/// 1. `new()` -- validate config, resolve STUN server address
/// 2. `start()` -- perform initial STUN discovery + start keepalive thread
/// 3. `reflexive_address()` -- query the current public address
/// 4. `stop()` -- shut down the keepalive thread
pub struct NatTraversal {
    config: NatConfig,
    keepalive: Option<NatKeepalive>,
    resolved_server: Option<SocketAddr>,
}

impl NatTraversal {
    /// Create a new NAT traversal manager.
    ///
    /// If NAT is disabled in the config, this still succeeds but `start()`
    /// will return `Err(NatError::Disabled)`.
    pub fn new(config: NatConfig) -> Result<Self, NatError> {
        let resolved = if config.enabled {
            Some(resolve_stun_server(&config.stun_server)?)
        } else {
            None
        };

        Ok(Self {
            config,
            keepalive: None,
            resolved_server: resolved,
        })
    }

    /// Start NAT traversal: discover the reflexive address and begin keepalive.
    ///
    /// Returns the initially discovered public address.
    pub fn start(&mut self) -> Result<ReflexiveAddress, NatError> {
        if !self.config.enabled {
            return Err(NatError::Disabled);
        }

        let server = self
            .resolved_server
            .ok_or_else(|| NatError::InternalError("STUN server not resolved".into()))?;

        let keepalive = NatKeepalive::new(&self.config, server);
        let addr = keepalive.start()?;
        self.keepalive = Some(keepalive);

        log::info!("[NAT] discovered reflexive address: {}", addr);
        Ok(addr)
    }

    /// Get the current reflexive address, if available.
    #[must_use]
    pub fn reflexive_address(&self) -> Option<ReflexiveAddress> {
        self.keepalive.as_ref().and_then(|k| k.current_address())
    }

    /// Stop NAT traversal and shut down the keepalive thread.
    pub fn stop(&mut self) {
        if let Some(ref keepalive) = self.keepalive {
            keepalive.stop();
        }
        self.keepalive = None;
    }

    /// Check whether NAT traversal is enabled.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Check whether the keepalive thread is running.
    #[must_use]
    pub fn is_running(&self) -> bool {
        self.keepalive
            .as_ref()
            .is_some_and(|k| k.is_running())
    }

    /// Get the NAT configuration.
    #[must_use]
    pub fn config(&self) -> &NatConfig {
        &self.config
    }
}

impl Drop for NatTraversal {
    fn drop(&mut self) {
        self.stop();
    }
}

// ============================================================================
// Helper functions
// ============================================================================

/// Resolve a STUN server string ("host:port") to a `SocketAddr`.
fn resolve_stun_server(server: &str) -> Result<SocketAddr, NatError> {
    server
        .to_socket_addrs()
        .map_err(|e| NatError::NetworkError(format!("failed to resolve '{}': {}", server, e)))?
        .next()
        .ok_or_else(|| {
            NatError::NetworkError(format!("no addresses resolved for '{}'", server))
        })
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nat_config_default() {
        let config = NatConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.keepalive_interval, Duration::from_secs(25));
        assert_eq!(config.stun_timeout, Duration::from_secs(3));
        assert_eq!(config.max_retries, 3);
        assert_eq!(config.stun_server, "stun.l.google.com:19302");
    }

    #[test]
    fn test_reflexive_address_equality() {
        let addr1 = ReflexiveAddress {
            ip: IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 1)),
            port: 54321,
            server_used: "198.51.100.1:3478".parse().unwrap(),
            discovered_at: Instant::now(),
        };

        // Same IP/port/server but different discovered_at
        // PartialEq checks all fields, so this tests that Instant equality works
        let addr2 = addr1.clone();
        assert_eq!(addr1, addr2);

        // Different IP
        let addr3 = ReflexiveAddress {
            ip: IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 2)),
            ..addr1.clone()
        };
        assert_ne!(addr1, addr3);

        // Different port
        let addr4 = ReflexiveAddress {
            port: 12345,
            ..addr1.clone()
        };
        assert_ne!(addr1, addr4);
    }

    #[test]
    fn test_nat_type_variants() {
        // Ensure all variants exist and Display works
        let types = [
            (NatType::NoNat, "No NAT"),
            (NatType::FullCone, "Full Cone"),
            (NatType::RestrictedCone, "Restricted Cone"),
            (NatType::PortRestricted, "Port Restricted"),
            (NatType::Symmetric, "Symmetric"),
            (NatType::Unknown, "Unknown"),
        ];

        for (nat_type, expected_display) in &types {
            assert_eq!(format!("{}", nat_type), *expected_display);
        }

        // Test equality
        assert_eq!(NatType::FullCone, NatType::FullCone);
        assert_ne!(NatType::FullCone, NatType::Symmetric);
    }

    #[test]
    fn test_nat_error_display() {
        let errors = [
            (NatError::Disabled, "NAT traversal is disabled"),
            (
                NatError::NetworkError("test".into()),
                "NAT network error: test",
            ),
            (NatError::Timeout("test".into()), "NAT timeout: test"),
            (
                NatError::MalformedResponse("test".into()),
                "NAT malformed response: test",
            ),
            (
                NatError::ServerError("test".into()),
                "NAT server error: test",
            ),
            (
                NatError::InternalError("test".into()),
                "NAT internal error: test",
            ),
        ];

        for (error, expected) in &errors {
            assert_eq!(format!("{}", error), *expected);
        }
    }

    #[test]
    fn test_nat_traversal_disabled() {
        let config = NatConfig::default(); // enabled: false
        let mut nat = NatTraversal::new(config).unwrap();

        assert!(!nat.is_enabled());
        assert!(!nat.is_running());
        assert!(nat.reflexive_address().is_none());

        let result = nat.start();
        assert!(result.is_err());
        match result.unwrap_err() {
            NatError::Disabled => {}
            other => panic!("expected Disabled, got: {:?}", other),
        }
    }

    #[test]
    fn test_nat_traversal_creation_with_local_server() {
        // Create with a valid local address (won't connect, just tests resolution)
        let config = NatConfig {
            stun_server: "127.0.0.1:3478".to_string(),
            enabled: true,
            ..NatConfig::default()
        };

        let nat = NatTraversal::new(config);
        assert!(nat.is_ok());
        let nat = nat.unwrap();
        assert!(nat.is_enabled());
        assert!(!nat.is_running());
    }

    #[test]
    fn test_reflexive_address_display() {
        let addr = ReflexiveAddress {
            ip: IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 42)),
            port: 54321,
            server_used: "198.51.100.1:3478".parse().unwrap(),
            discovered_at: Instant::now(),
        };

        let display = format!("{}", addr);
        assert!(display.contains("203.0.113.42"));
        assert!(display.contains("54321"));
        assert!(display.contains("198.51.100.1:3478"));
    }

    #[test]
    fn test_resolve_stun_server_valid() {
        let result = resolve_stun_server("127.0.0.1:3478");
        assert!(result.is_ok());
        let addr = result.unwrap();
        assert_eq!(addr, "127.0.0.1:3478".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn test_resolve_stun_server_invalid() {
        let result = resolve_stun_server("this-does-not-exist.invalid:3478");
        assert!(result.is_err());
    }
}
