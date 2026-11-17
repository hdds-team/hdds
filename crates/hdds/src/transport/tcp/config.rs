// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! TCP transport configuration.
//!
//! Provides configuration types for the TCP transport layer:
//! - [`TcpConfig`] - Main configuration struct
//! - [`TcpRole`] - Server/client/auto role selection
//! - [`TransportPreference`] - Transport selection policy
//!
//! # Example
//!
//! ```
//! use hdds::transport::tcp::{TcpConfig, TcpRole, TransportPreference};
//! use std::time::Duration;
//!
//! let config = TcpConfig {
//!     enabled: true,
//!     listen_port: 7410,
//!     nodelay: true,
//!     ..Default::default()
//! };
//! ```

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

/// TCP transport configuration.
///
/// Controls all aspects of TCP transport behavior including:
/// - Listening and connection parameters
/// - Buffer sizes and framing limits
/// - Keep-alive and reconnection policy
/// - Bootstrap peers for TCP-only mode
#[derive(Clone, Debug)]
pub struct TcpConfig {
    // === Enable/Disable ===
    /// Enable TCP transport (opt-in, disabled by default)
    pub enabled: bool,

    // === Listener ===
    /// TCP listen port (0 = ephemeral port assigned by OS)
    pub listen_port: u16,

    /// Address to bind for listening (None = all interfaces)
    pub listen_address: Option<IpAddr>,

    /// TCP listen backlog (pending connection queue size)
    pub listen_backlog: u32,

    // === Connection ===
    /// Connection timeout for outbound connections
    pub connect_timeout: Duration,

    /// Delay before retry after connection failure
    pub reconnect_delay: Duration,

    /// Maximum number of reconnection attempts (0 = infinite)
    pub max_reconnect_attempts: u32,

    /// TCP role (Auto, ServerOnly, ClientOnly)
    pub role: TcpRole,

    // === Framing ===
    /// Maximum message size in bytes (anti-OOM protection)
    ///
    /// Messages larger than this will be rejected.
    /// Default: 16 MB (DDS can have large messages with big arrays/sequences)
    pub max_message_size: usize,

    /// Enable TCP_NODELAY (disable Nagle's algorithm)
    ///
    /// Recommended: true for low-latency DDS applications
    pub nodelay: bool,

    // === Buffers ===
    /// Application-level send buffer size
    pub send_buffer_size: usize,

    /// Application-level receive buffer size
    pub recv_buffer_size: usize,

    /// SO_SNDBUF socket option (0 = OS default)
    pub socket_send_buffer: usize,

    /// SO_RCVBUF socket option (0 = OS default)
    pub socket_recv_buffer: usize,

    // === Keep-alive ===
    /// Enable TCP keep-alive probes
    pub keepalive: bool,

    /// Keep-alive probe interval
    pub keepalive_interval: Duration,

    // === Bootstrap ===
    /// Initial peers for TCP-only mode (no UDP discovery)
    ///
    /// When UDP discovery is disabled, these peers are contacted
    /// directly via TCP to bootstrap the mesh.
    pub initial_peers: Vec<SocketAddr>,

    // === TLS (Phase 6) ===
    /// Enable TLS encryption for TCP connections.
    ///
    /// Requires the `tcp-tls` feature flag to be enabled.
    /// When enabled, all TCP connections use TLS 1.2/1.3.
    pub tls_enabled: bool,

    /// TLS configuration (certificates, keys, verification).
    ///
    /// Required when `tls_enabled` is true. The configuration must cover every
    /// direction the role uses: `TcpRole::Auto` (default) needs
    /// `TlsConfig::peer(server, client)`, `ServerOnly` a `TlsConfig::server()`,
    /// `ClientOnly` a `TlsConfig::client()`; `validate()` refuses anything else.
    #[cfg(feature = "tcp-tls")]
    pub tls_config: Option<super::tls::TlsConfig>,
}

impl Default for TcpConfig {
    fn default() -> Self {
        Self {
            enabled: false, // Opt-in

            listen_port: 0,       // Ephemeral
            listen_address: None, // All interfaces
            listen_backlog: 128,

            connect_timeout: Duration::from_secs(5),
            reconnect_delay: Duration::from_secs(1),
            max_reconnect_attempts: 10,
            role: TcpRole::Auto,

            max_message_size: 16 * 1024 * 1024, // 16 MB
            nodelay: true,                      // Low latency

            send_buffer_size: 256 * 1024, // 256 KB
            recv_buffer_size: 256 * 1024, // 256 KB
            socket_send_buffer: 0,        // OS default
            socket_recv_buffer: 0,        // OS default

            keepalive: true,
            keepalive_interval: Duration::from_secs(30),

            initial_peers: Vec::new(),

            tls_enabled: false,
            #[cfg(feature = "tcp-tls")]
            tls_config: None,
        }
    }
}

impl TcpConfig {
    /// Create a new TCP config with TCP enabled.
    pub fn enabled() -> Self {
        Self {
            enabled: true,
            ..Default::default()
        }
    }

    /// Create a TCP endpoint config with initial peers.
    ///
    /// The historical name does not disable the participant's UDP writer path;
    /// `DataWriter::write` is not routed through this transport yet.
    pub fn tcp_only(initial_peers: Vec<SocketAddr>) -> Self {
        Self {
            enabled: true,
            initial_peers,
            ..Default::default()
        }
    }

    /// Create a server-only config (listen but don't initiate).
    pub fn server_only(port: u16) -> Self {
        Self {
            enabled: true,
            listen_port: port,
            role: TcpRole::ServerOnly,
            ..Default::default()
        }
    }

    /// Create a client-only config (connect but don't listen).
    pub fn client_only(peers: Vec<SocketAddr>) -> Self {
        Self {
            enabled: true,
            role: TcpRole::ClientOnly,
            initial_peers: peers,
            ..Default::default()
        }
    }

    /// Builder: set listen port
    pub fn with_port(mut self, port: u16) -> Self {
        self.listen_port = port;
        self
    }

    /// Builder: set role
    pub fn with_role(mut self, role: TcpRole) -> Self {
        self.role = role;
        self
    }

    /// Builder: set max message size
    pub fn with_max_message_size(mut self, size: usize) -> Self {
        self.max_message_size = size;
        self
    }

    /// Builder: add initial peers
    pub fn with_peers(mut self, peers: Vec<SocketAddr>) -> Self {
        self.initial_peers = peers;
        self
    }

    /// Builder: set TCP_NODELAY
    pub fn with_nodelay(mut self, nodelay: bool) -> Self {
        self.nodelay = nodelay;
        self
    }

    /// Builder: set connect timeout
    pub fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Builder: set keepalive
    pub fn with_keepalive(mut self, enabled: bool, interval: Duration) -> Self {
        self.keepalive = enabled;
        self.keepalive_interval = interval;
        self
    }

    /// Builder: enable TLS (requires tcp-tls feature and tls_config)
    pub fn with_tls(mut self, enabled: bool) -> Self {
        self.tls_enabled = enabled;
        self
    }

    /// Builder: set TLS configuration
    #[cfg(feature = "tcp-tls")]
    pub fn with_tls_config(mut self, config: super::tls::TlsConfig) -> Self {
        self.tls_enabled = true;
        self.tls_config = Some(config);
        self
    }

    /// Check if TLS is properly configured.
    pub fn is_tls_ready(&self) -> bool {
        #[cfg(feature = "tcp-tls")]
        {
            self.tls_enabled && self.tls_config.is_some()
        }
        #[cfg(not(feature = "tcp-tls"))]
        {
            false
        }
    }

    /// Validate configuration, returning error message if invalid.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.max_message_size == 0 {
            return Err("max_message_size must be > 0");
        }
        if self.max_message_size > 1024 * 1024 * 1024 {
            return Err("max_message_size too large (> 1 GB)");
        }
        if self.send_buffer_size == 0 {
            return Err("send_buffer_size must be > 0");
        }
        if self.recv_buffer_size == 0 {
            return Err("recv_buffer_size must be > 0");
        }
        if self.connect_timeout.is_zero() {
            return Err("connect_timeout must be > 0");
        }
        if self.role == TcpRole::ClientOnly && self.initial_peers.is_empty() {
            return Err("ClientOnly role requires initial_peers");
        }

        // TLS validation: the role must be able to run TLS in every direction
        // it uses, otherwise the I/O thread would have to fall back to plaintext.
        #[cfg(feature = "tcp-tls")]
        {
            if self.tls_enabled {
                let tls = match &self.tls_config {
                    Some(tls) => tls,
                    None => return Err("tls_enabled requires tls_config to be set"),
                };
                if self.role.can_listen() && !tls.can_accept() {
                    return Err(
                        "tls_enabled with a listening role (Auto/ServerOnly) requires a server \
                         TlsConfig: use TlsConfig::server() or TlsConfig::peer()",
                    );
                }
                if self.role.can_connect() && !tls.can_initiate() {
                    return Err(
                        "tls_enabled with a connecting role (Auto/ClientOnly) requires a client \
                         TlsConfig: use TlsConfig::client() or TlsConfig::peer()",
                    );
                }
            }
        }
        #[cfg(not(feature = "tcp-tls"))]
        {
            if self.tls_enabled {
                return Err("TLS requires the 'tcp-tls' feature flag");
            }
        }

        Ok(())
    }
}

/// TCP role for connection establishment.
///
/// Controls whether this participant initiates connections, accepts them, or both.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum TcpRole {
    /// Auto-negotiation via GUID tie-breaker.
    ///
    /// The participant with the "larger" GUID initiates the connection.
    /// This ensures exactly one connection between any two participants.
    #[default]
    Auto,

    /// Server only: listen for connections but never initiate.
    ///
    /// Useful for:
    /// - Edge devices behind NAT
    /// - Corporate firewall policies
    /// - Known server topology
    ServerOnly,

    /// Client only: initiate connections but never listen.
    ///
    /// Useful for:
    /// - Mobile/embedded clients
    /// - NAT traversal scenarios
    /// - When firewall blocks inbound
    ClientOnly,
}

impl TcpRole {
    /// Check if this role allows listening for connections.
    pub fn can_listen(&self) -> bool {
        matches!(self, TcpRole::Auto | TcpRole::ServerOnly)
    }

    /// Check if this role allows initiating connections.
    pub fn can_connect(&self) -> bool {
        matches!(self, TcpRole::Auto | TcpRole::ClientOnly)
    }
}

/// Transport selection preference for the participant.
///
/// Records the intended transport policy. The DDS writer path does not consume
/// this value yet; only `TcpOnly` construction failure is enforced.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum TransportPreference {
    /// UDP only (default RTPS behavior).
    ///
    /// Standard DDS operation over UDP multicast/unicast.
    #[default]
    UdpOnly,

    /// Requested TCP-only policy (not yet enforced for DDS writes).
    TcpOnly,

    /// Requested UDP-discovery/TCP-data policy (not yet routed).
    UdpDiscoveryTcpData,

    /// Shared memory preferred (local IPC).
    ///
    /// Use SHM for local participants, UDP for remote.
    ShmPreferred,

    /// Requested SHM-local/TCP-remote policy (not yet routed).
    ShmLocalTcpRemote,
}

impl TransportPreference {
    /// Check if UDP discovery is used.
    pub fn uses_udp_discovery(&self) -> bool {
        matches!(
            self,
            TransportPreference::UdpOnly
                | TransportPreference::UdpDiscoveryTcpData
                | TransportPreference::ShmPreferred
        )
    }

    /// Check whether this preference requests TCP data.
    ///
    /// This is a configuration query, not proof that the writer path is routed.
    pub fn uses_tcp_data(&self) -> bool {
        matches!(
            self,
            TransportPreference::TcpOnly
                | TransportPreference::UdpDiscoveryTcpData
                | TransportPreference::ShmLocalTcpRemote
        )
    }

    /// Check if SHM is preferred for local communication.
    pub fn prefers_shm(&self) -> bool {
        matches!(
            self,
            TransportPreference::ShmPreferred | TransportPreference::ShmLocalTcpRemote
        )
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = TcpConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.listen_port, 0);
        assert_eq!(config.role, TcpRole::Auto);
        assert_eq!(config.max_message_size, 16 * 1024 * 1024);
        assert!(config.nodelay);
        assert!(config.keepalive);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_enabled_config() {
        let config = TcpConfig::enabled();
        assert!(config.enabled);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_tcp_only_config() {
        let peers = vec!["192.168.1.1:7410".parse().unwrap()];
        let config = TcpConfig::tcp_only(peers.clone());
        assert!(config.enabled);
        assert_eq!(config.initial_peers, peers);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_server_only_config() {
        let config = TcpConfig::server_only(7410);
        assert!(config.enabled);
        assert_eq!(config.listen_port, 7410);
        assert_eq!(config.role, TcpRole::ServerOnly);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_client_only_config() {
        let peers = vec!["192.168.1.1:7410".parse().unwrap()];
        let config = TcpConfig::client_only(peers.clone());
        assert!(config.enabled);
        assert_eq!(config.role, TcpRole::ClientOnly);
        assert_eq!(config.initial_peers, peers);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_client_only_requires_peers() {
        let config = TcpConfig {
            enabled: true,
            role: TcpRole::ClientOnly,
            initial_peers: vec![],
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_builder_methods() {
        let config = TcpConfig::enabled()
            .with_port(8080)
            .with_role(TcpRole::ServerOnly)
            .with_max_message_size(1024 * 1024)
            .with_nodelay(false)
            .with_connect_timeout(Duration::from_secs(10))
            .with_keepalive(false, Duration::from_secs(60));

        assert_eq!(config.listen_port, 8080);
        assert_eq!(config.role, TcpRole::ServerOnly);
        assert_eq!(config.max_message_size, 1024 * 1024);
        assert!(!config.nodelay);
        assert_eq!(config.connect_timeout, Duration::from_secs(10));
        assert!(!config.keepalive);
    }

    #[test]
    fn test_validation_errors() {
        // Zero max message size
        let config = TcpConfig {
            max_message_size: 0,
            ..TcpConfig::enabled()
        };
        assert!(config.validate().is_err());

        // Too large max message size
        let config = TcpConfig {
            max_message_size: 2 * 1024 * 1024 * 1024,
            ..TcpConfig::enabled()
        };
        assert!(config.validate().is_err());

        // Zero send buffer
        let config = TcpConfig {
            send_buffer_size: 0,
            ..TcpConfig::enabled()
        };
        assert!(config.validate().is_err());

        // Zero connect timeout
        let config = TcpConfig {
            connect_timeout: Duration::ZERO,
            ..TcpConfig::enabled()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_tcp_role_capabilities() {
        assert!(TcpRole::Auto.can_listen());
        assert!(TcpRole::Auto.can_connect());

        assert!(TcpRole::ServerOnly.can_listen());
        assert!(!TcpRole::ServerOnly.can_connect());

        assert!(!TcpRole::ClientOnly.can_listen());
        assert!(TcpRole::ClientOnly.can_connect());
    }

    #[test]
    fn test_transport_preference_queries() {
        assert!(TransportPreference::UdpOnly.uses_udp_discovery());
        assert!(!TransportPreference::UdpOnly.uses_tcp_data());

        assert!(!TransportPreference::TcpOnly.uses_udp_discovery());
        assert!(TransportPreference::TcpOnly.uses_tcp_data());

        assert!(TransportPreference::UdpDiscoveryTcpData.uses_udp_discovery());
        assert!(TransportPreference::UdpDiscoveryTcpData.uses_tcp_data());

        assert!(TransportPreference::ShmPreferred.prefers_shm());
        assert!(!TransportPreference::TcpOnly.prefers_shm());

        assert!(TransportPreference::ShmLocalTcpRemote.prefers_shm());
        assert!(TransportPreference::ShmLocalTcpRemote.uses_tcp_data());
    }

    #[test]
    fn test_tls_not_ready_by_default() {
        let config = TcpConfig::default();
        assert!(!config.tls_enabled);
        assert!(!config.is_tls_ready());
    }

    #[test]
    fn test_with_tls_flag() {
        let config = TcpConfig::enabled().with_tls(true);
        assert!(config.tls_enabled);
        // Still not ready without tls_config
        assert!(!config.is_tls_ready());
    }

    #[cfg(not(feature = "tcp-tls"))]
    #[test]
    fn test_tls_validation_without_feature() {
        let config = TcpConfig {
            tls_enabled: true,
            ..TcpConfig::enabled()
        };
        assert!(config.validate().is_err());
        assert!(config.validate().unwrap_err().contains("feature"));
    }

    #[cfg(feature = "tcp-tls")]
    #[test]
    fn test_tls_validation_with_feature() {
        // TLS enabled but no config
        let config = TcpConfig {
            tls_enabled: true,
            tls_config: None,
            ..TcpConfig::enabled()
        };
        assert!(config.validate().is_err());
    }

    #[cfg(feature = "tcp-tls")]
    #[test]
    fn test_with_tls_config() {
        use crate::transport::tcp::tls::TlsConfig;

        let tls_config = TlsConfig::client().with_system_roots().build().unwrap();

        let peers = vec!["192.168.1.1:7410".parse().unwrap()];
        let config = TcpConfig::client_only(peers).with_tls_config(tls_config);

        assert!(config.tls_enabled);
        assert!(config.is_tls_ready());
        assert!(config.validate().is_ok());
    }

    #[cfg(feature = "tcp-tls")]
    #[test]
    fn tcp_config_validate_refuses_tls_role_without_matching_config() {
        use crate::transport::tcp::tls::TlsConfig;
        use crate::transport::tcp::tls_test_pki::TestPki;

        let pki = TestPki::shared();
        let server = || {
            TlsConfig::server()
                .with_cert_pem(pki.server_a_cert.clone())
                .with_key_pem(pki.server_a_key.clone())
                .build()
                .unwrap()
        };
        let client = || {
            TlsConfig::client()
                .with_root_cert_pem(pki.ca_a_cert.clone())
                .build()
                .unwrap()
        };
        let peers = vec!["192.168.1.1:7410".parse().unwrap()];

        // Auto listens and dials: a single-role config would leave one
        // direction in plaintext.
        let err = TcpConfig::enabled()
            .with_tls_config(client())
            .validate()
            .unwrap_err();
        assert!(err.contains("server TlsConfig"), "{err}");
        let err = TcpConfig::enabled()
            .with_tls_config(server())
            .validate()
            .unwrap_err();
        assert!(err.contains("client TlsConfig"), "{err}");

        // Cross-role mismatches.
        let err = TcpConfig::server_only(0)
            .with_tls_config(client())
            .validate()
            .unwrap_err();
        assert!(err.contains("server TlsConfig"), "{err}");
        let err = TcpConfig::client_only(peers.clone())
            .with_tls_config(server())
            .validate()
            .unwrap_err();
        assert!(err.contains("client TlsConfig"), "{err}");

        // Matching roles pass; a peer config satisfies every role.
        assert!(TcpConfig::server_only(0)
            .with_tls_config(server())
            .validate()
            .is_ok());
        assert!(TcpConfig::client_only(peers)
            .with_tls_config(client())
            .validate()
            .is_ok());
        let peer = TlsConfig::peer(server(), client()).unwrap();
        assert!(TcpConfig::enabled()
            .with_tls_config(peer)
            .validate()
            .is_ok());
    }
}
