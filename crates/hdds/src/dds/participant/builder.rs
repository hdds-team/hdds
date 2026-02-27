// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Participant builder pattern implementation.
//!
//! This module provides the `ParticipantBuilder` for configuring and creating
//! DDS participants. The builder pattern allows fluent configuration of:
//! - Domain ID and participant ID
//! - Transport mode (intra-process vs UDP multicast)
//! - XTypes configuration (type cache, ROS distro)
//! - Seed peers and configuration files

mod bootstrap; // build() implementation (orchestration)
mod discovery_setup; // Discovery FSM, listeners, demux router (now a module with handlers)
mod entity_registry; // SEDP cache and GUID generation
mod sockets; // Socket creation utilities
mod telemetry_setup; // Telemetry and metrics initialization
mod threads; // Background thread spawning (SPDP, lease tracker)
pub(in crate::dds::participant) mod unicast_routing; // Sprint 7: TCP/QUIC → TopicRegistry routing thread

use super::runtime::{Participant, TransportMode};
use crate::discovery_server::DiscoveryServerConfig;
use crate::transport::lowbw::LowBwConfig;
use crate::transport::shm::ShmPolicy;
use crate::transport::tcp::{TcpConfig, TransportPreference};
use crate::transport::CustomPortMapping;

#[cfg(feature = "xtypes")]
use crate::core::types::{Distro, TypeObjectHandle};
#[cfg(feature = "k8s")]
use crate::discovery::k8s::K8sDiscoveryConfig;
#[cfg(feature = "security")]
use crate::security::SecurityConfig;
#[cfg(feature = "quic")]
use crate::transport::quic::QuicConfig;
#[cfg(feature = "xtypes")]
use parking_lot::RwLock;
#[cfg(feature = "xtypes")]
use std::collections::HashMap;
#[cfg(feature = "xtypes")]
use std::sync::Arc;

/// Builder for configuring and creating a [`Participant`].
pub struct ParticipantBuilder {
    pub(super) name: String,
    pub(super) transport_mode: TransportMode,
    pub(super) domain_id: u32,
    pub(super) participant_id: Option<u8>,
    pub(super) seed_peers: Option<String>,
    pub(super) config_path: Option<String>,
    pub(super) custom_ports: Option<CustomPortMapping>,
    /// Static peers for unicast communication without discovery
    pub(super) static_peers: Vec<std::net::SocketAddr>,
    #[cfg(feature = "xtypes")]
    pub(super) type_cache_capacity: usize,
    #[cfg(feature = "xtypes")]
    pub(super) distro: Distro,
    #[cfg(feature = "xtypes")]
    pub(super) registered_types: Arc<RwLock<HashMap<String, Arc<TypeObjectHandle>>>>,
    #[cfg(feature = "xtypes")]
    pub(super) topic_types: Arc<RwLock<HashMap<String, Arc<TypeObjectHandle>>>>,
    /// Security configuration for DDS Security v1.1
    #[cfg(feature = "security")]
    pub(super) security_config: Option<SecurityConfig>,
    /// Kubernetes DNS discovery configuration
    #[cfg(feature = "k8s")]
    pub(super) k8s_discovery_config: Option<K8sDiscoveryConfig>,
    /// TCP transport configuration for WAN/Internet communication
    pub(super) tcp_config: Option<TcpConfig>,
    /// Transport preference (UDP only, TCP only, hybrid)
    pub(super) transport_preference: TransportPreference,
    /// QUIC transport configuration for NAT traversal
    #[cfg(feature = "quic")]
    pub(super) quic_config: Option<QuicConfig>,
    /// Low Bandwidth transport configuration (for constrained links like HC-12)
    pub(super) lowbw_config: Option<LowBwConfig>,
    /// Discovery Server configuration (for environments without multicast)
    pub(super) discovery_server_config: Option<DiscoveryServerConfig>,
    /// Cloud discovery provider name (consul, aws, azure)
    #[cfg(feature = "cloud-discovery")]
    pub(super) cloud_discovery_provider: Option<String>,
    /// Consul discovery endpoint
    #[cfg(feature = "cloud-discovery")]
    pub(super) consul_addr: Option<String>,
    /// Shared Memory transport policy (Prefer, Require, Disable)
    pub(super) shm_policy: ShmPolicy,
}

impl Participant {
    /// Create a new participant with default settings.
    ///
    /// This is a convenience method equivalent to:
    /// ```ignore
    /// Participant::builder(name).build()
    /// ```
    ///
    /// Uses IntraProcess transport mode and domain ID 0 by default.
    /// For more configuration options, use [`Participant::builder`].
    ///
    /// # Example
    /// ```no_run
    /// use hdds::Participant;
    /// let participant = Participant::new("my_app")?;
    /// # Ok::<(), hdds::Error>(())
    /// ```
    pub fn new(name: &str) -> crate::dds::Result<std::sync::Arc<Self>> {
        Self::builder(name).build()
    }

    /// Create a new participant builder.
    ///
    /// # Example
    /// ```no_run
    /// use hdds::Participant;
    /// let participant = Participant::builder("my_app")
    ///     .domain_id(0)
    ///     .build()
    ///     .unwrap();
    /// ```
    pub fn builder(name: &str) -> ParticipantBuilder {
        ParticipantBuilder::new(name)
    }
}

impl ParticipantBuilder {
    pub(super) fn new(name: &str) -> Self {
        ParticipantBuilder {
            name: name.to_string(),
            transport_mode: TransportMode::IntraProcess,
            domain_id: 0,
            participant_id: None,
            seed_peers: None,
            config_path: None,
            custom_ports: None,
            static_peers: Vec::new(),
            #[cfg(feature = "xtypes")]
            type_cache_capacity: 256,
            #[cfg(feature = "xtypes")]
            distro: Distro::Humble,
            #[cfg(feature = "xtypes")]
            registered_types: Arc::new(RwLock::new(HashMap::new())),
            #[cfg(feature = "xtypes")]
            topic_types: Arc::new(RwLock::new(HashMap::new())),
            #[cfg(feature = "security")]
            security_config: None,
            #[cfg(feature = "k8s")]
            k8s_discovery_config: None,
            tcp_config: None,
            transport_preference: TransportPreference::UdpOnly,
            #[cfg(feature = "quic")]
            quic_config: None,
            lowbw_config: None,
            discovery_server_config: None,
            #[cfg(feature = "cloud-discovery")]
            cloud_discovery_provider: None,
            #[cfg(feature = "cloud-discovery")]
            consul_addr: None,
            shm_policy: ShmPolicy::Prefer,
        }
    }

    /// Set the transport mode (intra-process or UDP multicast).
    pub fn with_transport(mut self, mode: TransportMode) -> Self {
        self.transport_mode = mode;
        self
    }

    /// Set the DDS domain ID (default: 0).
    pub fn domain_id(mut self, domain_id: u32) -> Self {
        self.domain_id = domain_id;
        self
    }

    /// Set the participant ID (default: auto-assigned).
    pub fn participant_id(mut self, participant_id: Option<u8>) -> Self {
        self.participant_id = participant_id;
        self
    }

    /// Set seed peers for discovery.
    ///
    /// [!] **LIMITATION**: Currently only stores the list, does NOT implement discovery from peers.
    ///
    /// **Status**: Planned for v0.6.0
    ///
    /// For now, all participants must be on the same multicast network for automatic discovery.
    pub fn with_seed_peers(mut self, list: &str) -> Self {
        self.seed_peers = Some(list.to_string());
        self
    }

    /// Set configuration file path.
    ///
    /// [!] **LIMITATION**: Currently only stores the path, does NOT parse participant configuration.
    ///
    /// **What works**: For QoS configuration from FastDDS XML, use `QoS::load_fastdds(path)` instead.
    ///
    /// **What doesn't work**: Participant-level config (ports, discovery servers, locators) is NOT loaded.
    ///
    /// **Workaround**: Use `with_discovery_ports()` to override ports manually.
    ///
    /// **Status**: Full FastDDS XML participant config parsing planned for v0.6.0
    ///
    /// # Example
    /// ```no_run
    /// use hdds::{Participant, QoS};
    ///
    /// // Load QoS from XML (works [OK])
    /// let qos = QoS::load_fastdds("fastdds_profile.xml").unwrap();
    ///
    /// // Custom ports (use this for now)
    /// let participant = Participant::builder("app")
    ///     .with_discovery_ports(7400, 7410, 7411)
    ///     .build()
    ///     .unwrap();
    /// ```
    pub fn with_config(mut self, path: &str) -> Self {
        self.config_path = Some(path.to_string());
        self
    }

    /// Set custom discovery ports (override RTPS v2.5 formula).
    ///
    /// Use this when you need non-standard ports for:
    /// - Firewall restrictions (ports 7400-7499 blocked)
    /// - FastDDS XML configs with custom `<metatrafficUnicastLocatorList>`
    /// - Multi-tenancy (multiple DDS domains on same host with isolation)
    /// - Testing (parallel test runs with port isolation)
    ///
    /// **Important**: All participants must use the **same** custom ports to discover each other!
    ///
    /// # Arguments
    /// * `spdp_multicast` - Multicast port for SPDP discovery (default: 7400)
    /// * `sedp_unicast` - Unicast port for SEDP/control (default: 7410)
    /// * `user_unicast` - Unicast port for user data (default: 7411)
    ///
    /// # Example
    /// ```no_run
    /// use hdds::Participant;
    ///
    /// // Custom ports for firewall compatibility
    /// let participant = Participant::builder("app")
    ///     .domain_id(0)
    ///     .with_discovery_ports(9400, 9410, 9411)  // Override defaults
    ///     .build()
    ///     .unwrap();
    /// ```
    ///
    /// # FastDDS XML Compatibility
    /// If your FastDDS XML has:
    /// ```xml
    /// <metatrafficUnicastLocatorList>
    ///     <locator><udpv4><port>9410</port></udpv4></locator>
    /// </metatrafficUnicastLocatorList>
    /// ```
    /// Use: `.with_discovery_ports(9400, 9410, 9411)`
    pub fn with_discovery_ports(
        mut self,
        spdp_multicast: u16,
        sedp_unicast: u16,
        user_unicast: u16,
    ) -> Self {
        self.custom_ports = Some(CustomPortMapping {
            spdp_multicast,
            sedp_unicast,
            user_unicast,
        });
        self
    }

    /// Add a static peer for UDP unicast communication without multicast discovery.
    ///
    /// **Important**: This method is for **UDP SPDP discovery** and requires
    /// `TransportMode::UdpMulticast`. For TCP-only mode, use
    /// [`TcpConfig::initial_peers`](crate::TcpConfig) instead.
    ///
    /// Use this when communicating with peers that don't participate in SPDP discovery,
    /// such as hdds-micro embedded devices or manually configured endpoints.
    ///
    /// The peer address should be the user data port (typically 7411 for domain 0).
    ///
    /// # Arguments
    /// * `addr` - Socket address string (e.g., "192.168.1.100:7411")
    ///
    /// # Example (UDP with static peers)
    /// ```no_run
    /// use hdds::{Participant, TransportMode};
    ///
    /// let participant = Participant::builder("my_app")
    ///     .with_transport(TransportMode::UdpMulticast)  // Required for add_static_peer
    ///     .domain_id(0)
    ///     .add_static_peer("192.168.1.100:7411")  // Pi Zero running hdds-micro
    ///     .add_static_peer("192.168.1.101:7411")  // ESP32 running hdds-micro
    ///     .build()
    ///     .unwrap();
    /// ```
    ///
    /// # Example (TCP-only with initial peers)
    /// ```no_run
    /// use hdds::{Participant, TransportMode, TcpConfig};
    ///
    /// // For TCP-only mode, use tcp_config() with a TcpConfig:
    /// let participant = Participant::builder("my_app")
    ///     .with_transport(TransportMode::IntraProcess)
    ///     .tcp_config(TcpConfig::tcp_only(vec![
    ///         "192.168.1.100:9999".parse().unwrap(),
    ///     ]))
    ///     .build()
    ///     .unwrap();
    /// ```
    ///
    /// Invalid addresses are logged and ignored (no panic).
    pub fn add_static_peer(mut self, addr: &str) -> Self {
        match addr.parse::<std::net::SocketAddr>() {
            Ok(socket_addr) => {
                self.static_peers.push(socket_addr);
            }
            Err(e) => {
                log::error!("Invalid static peer address '{}': {}", addr, e);
            }
        }
        self
    }

    /// Set type cache capacity (XTypes feature only).
    #[cfg(feature = "xtypes")]
    pub fn with_type_cache_capacity(mut self, capacity: usize) -> Self {
        self.type_cache_capacity = capacity.max(1);
        self
    }

    /// Set ROS distro for type compatibility (XTypes feature only).
    #[cfg(feature = "xtypes")]
    pub fn with_distro(mut self, distro: Distro) -> Self {
        self.distro = distro;
        self
    }

    /// Enable DDS Security with the given configuration.
    ///
    /// # Arguments
    /// * `config` - Security configuration with certificate paths and permissions
    ///
    /// # Example
    /// ```no_run
    /// use hdds::{Participant, TransportMode};
    /// use hdds::security::SecurityConfig;
    ///
    /// let config = SecurityConfig::builder()
    ///     .identity_certificate("/path/to/identity.pem")
    ///     .private_key("/path/to/identity_key.pem")
    ///     .ca_certificates("/path/to/ca.pem")
    ///     .permissions_xml("/path/to/permissions.xml")
    ///     .build()
    ///     .unwrap();
    ///
    /// let participant = Participant::builder("secure_app")
    ///     .with_transport(TransportMode::UdpMulticast)
    ///     .with_security(config)
    ///     .build()
    ///     .unwrap();
    /// ```
    #[cfg(feature = "security")]
    pub fn with_security(mut self, config: SecurityConfig) -> Self {
        self.security_config = Some(config);
        self
    }

    /// Enable Kubernetes DNS-based discovery.
    ///
    /// Uses Kubernetes Headless Services for peer discovery. Zero external dependencies -
    /// just DNS resolution via `std::net::ToSocketAddrs`.
    ///
    /// # How It Works
    ///
    /// 1. Query DNS for headless service: `{service}.{namespace}.svc.cluster.local`
    /// 2. Get list of pod IPs (A/AAAA records)
    /// 3. Each pod IP + DDS port = potential DDS participant
    /// 4. Register discovered peers with the discovery system
    ///
    /// # Kubernetes Setup
    ///
    /// Create a Headless Service (clusterIP: None) that selects your DDS pods:
    ///
    /// ```yaml
    /// apiVersion: v1
    /// kind: Service
    /// metadata:
    ///   name: hdds-discovery
    ///   namespace: default
    /// spec:
    ///   clusterIP: None  # Headless service
    ///   selector:
    ///     app: my-dds-app
    ///   ports:
    ///   - name: dds-user
    ///     port: 7411
    ///     protocol: UDP
    /// ```
    ///
    /// # Arguments
    /// * `service` - Kubernetes service name (e.g., "hdds-discovery")
    /// * `namespace` - Kubernetes namespace (e.g., "default")
    ///
    /// # Example
    /// ```no_run
    /// use hdds::{Participant, TransportMode};
    ///
    /// let participant = Participant::builder("my_app")
    ///     .with_transport(TransportMode::UdpMulticast)
    ///     .with_k8s_discovery("hdds-discovery", "default")
    ///     .build()
    ///     .unwrap();
    /// ```
    ///
    /// # Environment Variables
    ///
    /// Can also be configured via environment:
    /// - `HDDS_K8S_SERVICE`: Service name
    /// - `HDDS_K8S_NAMESPACE`: Namespace
    /// - `HDDS_K8S_PORT`: DDS port (default: 7411)
    /// - `HDDS_K8S_POLL_INTERVAL_MS`: Poll interval (default: 5000)
    #[cfg(feature = "k8s")]
    pub fn with_k8s_discovery(mut self, service: &str, namespace: &str) -> Self {
        self.k8s_discovery_config = Some(K8sDiscoveryConfig::new(service, namespace));
        self
    }

    /// Enable Kubernetes DNS-based discovery with custom configuration.
    ///
    /// For advanced configuration (custom port, poll interval, cluster domain).
    ///
    /// # Example
    /// ```no_run
    /// use hdds::{Participant, TransportMode};
    /// use hdds::discovery::K8sDiscoveryConfig;
    /// use std::time::Duration;
    ///
    /// let config = K8sDiscoveryConfig::new("hdds", "production")
    ///     .with_port(8411)
    ///     .with_poll_interval(Duration::from_secs(10));
    ///
    /// let participant = Participant::builder("my_app")
    ///     .with_transport(TransportMode::UdpMulticast)
    ///     .with_k8s_discovery_config(config)
    ///     .build()
    ///     .unwrap();
    /// ```
    #[cfg(feature = "k8s")]
    pub fn with_k8s_discovery_config(mut self, config: K8sDiscoveryConfig) -> Self {
        self.k8s_discovery_config = Some(config);
        self
    }

    // =========================================================================
    // TCP Transport (for WAN/Internet communication)
    // =========================================================================

    /// Enable TCP transport with a specific listen port.
    ///
    /// This is a convenience method for simple TCP setups. For advanced
    /// configuration, use [`tcp_config()`](Self::tcp_config) instead.
    ///
    /// TCP transport is useful when:
    /// - UDP is blocked by firewalls
    /// - Operating across NAT without multicast
    /// - WAN/Internet communication is needed
    ///
    /// # Arguments
    /// * `listen_port` - TCP port to listen on (0 = OS assigns ephemeral port)
    ///
    /// # Example
    /// ```no_run
    /// use hdds::{Participant, TransportMode};
    ///
    /// // Gateway participant: listen on port 7410 for WAN connections
    /// let participant = Participant::builder("gateway")
    ///     .with_transport(TransportMode::UdpMulticast)
    ///     .domain_id(0)
    ///     .with_tcp(7410)
    ///     .build()
    ///     .unwrap();
    /// ```
    pub fn with_tcp(mut self, listen_port: u16) -> Self {
        let mut config = TcpConfig::enabled();
        config.listen_port = listen_port;
        self.tcp_config = Some(config);
        self.transport_preference = TransportPreference::UdpDiscoveryTcpData;
        self
    }

    /// Set full TCP transport configuration.
    ///
    /// Use this for advanced TCP configuration including:
    /// - TLS encryption
    /// - Client/Server role selection
    /// - Initial peers for TCP-only mode
    /// - Buffer sizes and timeouts
    ///
    /// # Example
    /// ```no_run
    /// use hdds::{Participant, TransportMode};
    /// use hdds::transport::tcp::{TcpConfig, TcpRole};
    ///
    /// // Server participant: listen-only with TLS
    /// let tcp = TcpConfig::server_only(7410)
    ///     .with_tls(true);
    ///
    /// let participant = Participant::builder("server")
    ///     .with_transport(TransportMode::UdpMulticast)
    ///     .tcp_config(tcp)
    ///     .build()
    ///     .unwrap();
    /// ```
    ///
    /// # TCP-Only Mode (no UDP)
    /// ```no_run
    /// use hdds::{Participant, TransportMode};
    /// use hdds::transport::tcp::TcpConfig;
    ///
    /// // Client connecting to a known server (no UDP discovery)
    /// let tcp = TcpConfig::client_only(vec![
    ///     "server.example.com:7410".parse().unwrap(),
    /// ]);
    ///
    /// let participant = Participant::builder("client")
    ///     .with_transport(TransportMode::UdpMulticast)
    ///     .tcp_config(tcp)
    ///     .tcp_only()  // Disable UDP, TCP-only mode
    ///     .build()
    ///     .unwrap();
    /// ```
    pub fn tcp_config(mut self, config: TcpConfig) -> Self {
        self.tcp_config = Some(config);
        // Default to hybrid mode unless already set to TCP-only
        if self.transport_preference == TransportPreference::UdpOnly {
            self.transport_preference = TransportPreference::UdpDiscoveryTcpData;
        }
        self
    }

    /// Set transport to TCP-only mode (no UDP).
    ///
    /// In this mode, UDP is completely disabled. Requires either:
    /// - Initial peers configured in [`TcpConfig::initial_peers`]
    /// - A discovery server (planned feature)
    ///
    /// This is useful for:
    /// - Environments where UDP is blocked
    /// - Cloud/Kubernetes without multicast
    /// - Strict firewall policies
    ///
    /// # Example
    /// ```no_run
    /// use hdds::{Participant, TransportMode};
    /// use hdds::transport::tcp::TcpConfig;
    ///
    /// let tcp = TcpConfig::tcp_only(vec![
    ///     "10.0.0.1:7410".parse().unwrap(),
    ///     "10.0.0.2:7410".parse().unwrap(),
    /// ]);
    ///
    /// let participant = Participant::builder("node")
    ///     .tcp_config(tcp)
    ///     .tcp_only()
    ///     .build()
    ///     .unwrap();
    /// ```
    pub fn tcp_only(mut self) -> Self {
        self.transport_preference = TransportPreference::TcpOnly;
        self
    }

    /// Set transport preference (UDP only, TCP only, hybrid, etc.).
    ///
    /// For most cases, use the convenience methods:
    /// - [`with_tcp()`](Self::with_tcp) - Enables hybrid mode (UDP discovery + TCP data)
    /// - [`tcp_only()`](Self::tcp_only) - TCP-only, no UDP
    ///
    /// This method provides full control over transport selection.
    pub fn with_transport_preference(mut self, preference: TransportPreference) -> Self {
        self.transport_preference = preference;
        self
    }

    // =========================================================================
    // QUIC Transport (for NAT traversal and connection migration)
    // =========================================================================

    /// Enable QUIC transport for advanced WAN communication.
    ///
    /// QUIC provides modern transport features:
    /// - **NAT Traversal**: UDP-based, works better through NAT than TCP
    /// - **0-RTT**: Near-instant reconnection to known peers
    /// - **Connection Migration**: Survives IP changes (WiFi roaming, mobile)
    /// - **Built-in TLS 1.3**: Encrypted by default
    ///
    /// # Feature Flag
    /// Requires the `quic` feature:
    /// ```toml
    /// hdds = { version = "0.8", features = ["quic"] }
    /// ```
    ///
    /// # Example
    /// ```ignore
    /// use hdds::{Participant, TransportMode};
    /// use hdds::transport::quic::QuicConfig;
    ///
    /// let quic = QuicConfig::builder()
    ///     .bind_addr("0.0.0.0:7400".parse().unwrap())
    ///     .enable_migration(true)  // Handle IP changes
    ///     .build();
    ///
    /// let participant = Participant::builder("mobile_robot")
    ///     .with_transport(TransportMode::UdpMulticast)
    ///     .with_quic(quic)
    ///     .build()
    ///     .unwrap();
    /// ```
    #[cfg(feature = "quic")]
    pub fn with_quic(mut self, config: QuicConfig) -> Self {
        self.quic_config = Some(config);
        self
    }

    // =========================================================================
    // Low Bandwidth Transport (for constrained links: HC-12, LoRa, satellite)
    // =========================================================================

    /// Enable Low Bandwidth transport for constrained links.
    ///
    /// LowBw transport is optimized for:
    /// - **Throughput**: 9.6 kbps -> 2 Mbps
    /// - **Latency**: 100 ms -> 2 s RTT
    /// - **Loss**: 10-30% packet loss tolerance
    ///
    /// Use presets for common scenarios:
    /// - `LowBwConfig::slow_serial()` - 9600 bps (HC-12, RS-485)
    /// - `LowBwConfig::satellite()` - 128 kbps, high latency
    /// - `LowBwConfig::tactical_radio()` - 32 kbps, lossy
    /// - `LowBwConfig::iot_lora()` - LoRa/LPWAN (<10 kbps)
    ///
    /// # Example: HC-12 Radio Link (ESP32 ↔ Pi Gateway)
    /// ```ignore
    /// use hdds::{Participant, TransportMode};
    /// use hdds::transport::lowbw::LowBwConfig;
    ///
    /// let participant = Participant::builder("gateway")
    ///     .with_transport(TransportMode::UdpMulticast)
    ///     .with_lowbw(LowBwConfig::slow_serial())
    ///     .build()?;
    ///
    /// // Create transport with your link implementation
    /// let link = Arc::new(MySerialLink::new("/dev/ttyUSB0", 9600)?);
    /// let lowbw = participant.create_lowbw_transport(link)?;
    ///
    /// // Register streams and send data
    /// lowbw.register_tx_stream(StreamHandle(1), config)?;
    /// lowbw.send(StreamHandle(1), &sensor_data, Priority::P1)?;
    /// ```
    ///
    /// # Priority Levels
    ///
    /// - **P0**: Critical (commands, state sync) - reliable, immediate flush
    /// - **P1**: Important (sensor data) - batched, no retransmit
    /// - **P2**: Telemetry (droppable) - batched, dropped on congestion
    pub fn with_lowbw(mut self, config: LowBwConfig) -> Self {
        self.lowbw_config = Some(config);
        self
    }

    /// Configure Low Bandwidth transport with a preset.
    ///
    /// Convenience method using preset names.
    ///
    /// # Presets
    /// - `"serial"` / `"hc12"` - 9600 bps serial link
    /// - `"satellite"` - 128 kbps high-latency link
    /// - `"radio"` / `"tactical"` - 32 kbps lossy link
    /// - `"lora"` / `"iot"` - <10 kbps IoT link
    /// - `"test"` / `"local"` - Fast local testing
    pub fn lowbw_preset(mut self, preset: &str) -> Self {
        let config = match preset.to_lowercase().as_str() {
            "serial" | "hc12" | "slow" => LowBwConfig::slow_serial(),
            "satellite" | "sat" => LowBwConfig::satellite(),
            "radio" | "tactical" | "uhf" | "vhf" => LowBwConfig::tactical_radio(),
            "lora" | "iot" | "lpwan" => LowBwConfig::iot_lora(),
            "test" | "local" | "fast" => LowBwConfig::local_test(),
            _ => {
                log::warn!("[LowBw] Unknown preset '{}', using default", preset);
                LowBwConfig::default()
            }
        };
        self.lowbw_config = Some(config);
        self
    }

    // =========================================================================
    // Discovery Server (for environments without multicast)
    // =========================================================================

    /// Use a Discovery Server instead of multicast discovery.
    ///
    /// A Discovery Server acts as a central rendezvous point for participants
    /// that cannot use multicast (cloud, Kubernetes, corporate networks, NAT).
    ///
    /// # When to Use
    ///
    /// - AWS/Azure/GCP without multicast
    /// - Kubernetes clusters
    /// - Corporate networks with multicast disabled
    /// - WAN deployments across sites
    ///
    /// # Example
    /// ```ignore
    /// use hdds::{Participant, TransportMode};
    /// use hdds::discovery_server::DiscoveryServerConfig;
    ///
    /// // Connect to a discovery server
    /// let config = DiscoveryServerConfig::new("discovery.example.com:7400".parse()?);
    ///
    /// let participant = Participant::builder("cloud_node")
    ///     .with_transport(TransportMode::UdpMulticast)
    ///     .with_discovery_server(config)
    ///     .build()?;
    /// ```
    pub fn with_discovery_server(mut self, config: DiscoveryServerConfig) -> Self {
        self.discovery_server_config = Some(config);
        self
    }

    /// Use a Discovery Server at the specified address.
    ///
    /// Convenience method that creates a default config with the given address.
    ///
    /// # Example
    /// ```ignore
    /// let participant = Participant::builder("node")
    ///     .discovery_server_addr("discovery.example.com:7400".parse()?)
    ///     .build()?;
    /// ```
    pub fn discovery_server_addr(mut self, addr: std::net::SocketAddr) -> Self {
        self.discovery_server_config = Some(DiscoveryServerConfig::new(addr));
        self
    }

    // =========================================================================
    // Cloud Discovery (AWS, Azure, Consul)
    // =========================================================================

    /// Use Consul for service discovery.
    ///
    /// Consul is ideal for:
    /// - Kubernetes (via Consul Connect)
    /// - Hybrid cloud deployments
    /// - On-premise data centers
    ///
    /// # Feature Flag
    /// Requires the `cloud-discovery` feature:
    /// ```toml
    /// hdds = { version = "1.0", features = ["cloud-discovery"] }
    /// ```
    ///
    /// # Example
    /// ```ignore
    /// let participant = Participant::builder("k8s_node")
    ///     .with_consul("http://consul.service.consul:8500")
    ///     .build()?;
    ///
    /// // Consul discovery is async - create when needed
    /// let consul = participant.create_consul_discovery().await?;
    /// consul.register_participant(&info).await?;
    /// let peers = consul.discover_participants().await?;
    /// ```
    #[cfg(feature = "cloud-discovery")]
    pub fn with_consul(mut self, consul_addr: &str) -> Self {
        self.cloud_discovery_provider = Some("consul".to_string());
        self.consul_addr = Some(consul_addr.to_string());
        self
    }

    /// Use AWS Cloud Map for service discovery.
    ///
    /// AWS Cloud Map is ideal for:
    /// - Amazon ECS services
    /// - Amazon EKS clusters
    /// - EC2 instances in VPCs
    ///
    /// # Feature Flag
    /// Requires the `cloud-discovery` feature.
    ///
    /// # Example
    /// ```ignore
    /// let participant = Participant::builder("ecs_task")
    ///     .with_aws_cloud_map("hdds-namespace", "hdds-service", "us-east-1")
    ///     .build()?;
    /// ```
    #[cfg(feature = "cloud-discovery")]
    pub fn with_aws_cloud_map(mut self, namespace: &str, service: &str, region: &str) -> Self {
        self.cloud_discovery_provider = Some("aws".to_string());
        // Store as JSON for simplicity
        self.consul_addr = Some(format!(
            r#"{{"namespace":"{}","service":"{}","region":"{}"}}"#,
            namespace, service, region
        ));
        self
    }

    /// Use Azure Service Discovery.
    ///
    /// Azure integration is ideal for:
    /// - Azure Kubernetes Service (AKS)
    /// - Azure Container Instances
    /// - Azure VMs in VNets
    ///
    /// # Feature Flag
    /// Requires the `cloud-discovery` feature.
    #[cfg(feature = "cloud-discovery")]
    pub fn with_azure_discovery(mut self, config_json: &str) -> Self {
        self.cloud_discovery_provider = Some("azure".to_string());
        self.consul_addr = Some(config_json.to_string());
        self
    }

    // =========================================================================
    // SHM (Shared Memory) Transport Configuration
    // =========================================================================

    /// Set the Shared Memory transport policy.
    ///
    /// SHM provides ultra-low latency zero-copy communication between processes
    /// on the same host.
    ///
    /// # Policies
    ///
    /// - `ShmPolicy::Prefer` (default) -- Use SHM when available, fallback to UDP
    /// - `ShmPolicy::Require` -- Force SHM, fail if not available
    /// - `ShmPolicy::Disable` -- Always use UDP, even when SHM is available
    ///
    /// # Requirements for SHM
    ///
    /// - Same host (matching `host_id`)
    /// - Both endpoints use `BestEffort` QoS (SHM doesn't support retransmission)
    /// - Remote endpoint advertises SHM capability
    ///
    /// # Performance
    ///
    /// - Writer push: < 200 ns
    /// - Reader poll: < 100 ns
    /// - End-to-end: < 1 μs
    ///
    /// # Example
    ///
    /// ```ignore
    /// use hdds::{Participant, TransportMode};
    /// use hdds::transport::shm::ShmPolicy;
    ///
    /// // Prefer SHM when available (default)
    /// let participant = Participant::builder("shm_app")
    ///     .shm_policy(ShmPolicy::Prefer)
    ///     .build()?;
    ///
    /// // Force SHM (fails if not same-host)
    /// let participant = Participant::builder("local_only")
    ///     .shm_policy(ShmPolicy::Require)
    ///     .build()?;
    /// ```
    pub fn shm_policy(mut self, policy: ShmPolicy) -> Self {
        self.shm_policy = policy;
        self
    }

    /// Prefer SHM transport when available (default behavior).
    ///
    /// Shorthand for `.shm_policy(ShmPolicy::Prefer)`.
    pub fn shm_prefer(mut self) -> Self {
        self.shm_policy = ShmPolicy::Prefer;
        self
    }

    /// Require SHM transport (fail if not available).
    ///
    /// Shorthand for `.shm_policy(ShmPolicy::Require)`.
    ///
    /// Use this when you need guaranteed zero-copy performance and
    /// know that all participants are on the same host.
    pub fn shm_require(mut self) -> Self {
        self.shm_policy = ShmPolicy::Require;
        self
    }

    /// Disable SHM transport (always use UDP).
    ///
    /// Shorthand for `.shm_policy(ShmPolicy::Disable)`.
    ///
    /// Use this for debugging or when SHM overhead isn't worth it.
    pub fn shm_disable(mut self) -> Self {
        self.shm_policy = ShmPolicy::Disable;
        self
    }

    // build() is implemented in bootstrap.rs
}
