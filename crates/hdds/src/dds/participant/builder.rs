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
#[cfg(feature = "cloud-discovery")]
pub(in crate::dds::participant) mod cloud_discovery_runtime;
pub(in crate::dds::participant) mod discovery_server_runtime;
pub(super) mod discovery_setup; // Discovery FSM, listeners, demux router (now a module with handlers)
pub(in crate::dds::participant) use discovery_setup::forget_local_participant;
#[cfg(feature = "dns-sd")]
pub(in crate::dds::participant) mod dnssd_runtime;
mod entity_registry; // SEDP cache and GUID generation
mod relay_channel; // Discovery Server relay: the queue between sender and session
mod sockets; // Socket creation utilities
pub(super) mod telemetry_setup; // Telemetry and metrics initialization
mod threads; // Background thread spawning (SPDP, lease tracker)
mod timing; // Participant lease and SPDP announcement timing
pub(in crate::dds::participant) mod unicast_routing; // TCP/QUIC -> TopicRegistry routing thread

use super::runtime::{Participant, TransportMode};
use crate::discovery_server::DiscoveryServerConfig;
use crate::transport::lowbw::LowBwConfig;
use crate::transport::shm::ShmPolicy;
use crate::transport::socket_buffer::SocketBufferOptions;
use crate::transport::tcp::{TcpConfig, TransportPreference};
use crate::transport::{CustomPortMapping, TransportOptions};
use timing::ParticipantDiscoveryTiming;

#[cfg(feature = "xtypes")]
use crate::core::types::{Distro, TypeObjectHandle};
#[cfg(feature = "dns-sd")]
use crate::discovery::dnssd::DnsSdConfig;
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
use std::num::NonZeroUsize;
#[cfg(feature = "xtypes")]
use std::sync::Arc;
use std::time::Duration;

/// Builder for configuring and creating a [`Participant`].
pub struct ParticipantBuilder {
    #[cfg(test)]
    pub(crate) liveliness_clock:
        Option<std::sync::Arc<dyn crate::dds::liveliness::LivelinessClock>>,
    pub(super) name: String,
    pub(super) transport_mode: TransportMode,
    /// `None` until `domain_id()` is called; `build()` then reads
    /// `HDDS_DOMAIN_ID` (see `config::domain_id_from_env`), else uses 0.
    pub(super) domain_id: Option<u32>,
    pub(super) participant_id: Option<u8>,
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
    /// Types this participant can SERVE to a peer that asks, via either
    /// TypeLookup responder. Never consulted by the SEDP announcement path
    /// (`resolve_type_info` reads `registered_types` only), so a native
    /// typed endpoint's TypeObject can be made servable without changing a
    /// single announced byte. See `Participant::register_served_type`.
    #[cfg(feature = "xtypes")]
    pub(super) served_types: Arc<RwLock<HashMap<String, Arc<TypeObjectHandle>>>>,
    #[cfg(feature = "xtypes")]
    pub(super) topic_types: Arc<RwLock<HashMap<String, Arc<TypeObjectHandle>>>>,
    /// Security configuration for DDS Security v1.1
    #[cfg(feature = "security")]
    pub(super) security_config: Option<SecurityConfig>,
    /// Kubernetes DNS discovery configuration
    #[cfg(feature = "k8s")]
    pub(super) k8s_discovery_config: Option<K8sDiscoveryConfig>,
    /// DNS-SD discovery configuration (SRV + A/AAAA peer resolution)
    #[cfg(feature = "dns-sd")]
    pub(super) dns_sd_config: Option<DnsSdConfig>,
    /// DNS-SD lowers the transport's multicast default to `Disabled`
    /// (same switch as Discovery Server and cloud registry mode) unless
    /// told not to.
    #[cfg(feature = "dns-sd")]
    pub(super) dns_sd_disable_multicast: bool,
    /// Manual HDDS-to-HDDS TCP endpoint configuration.
    pub(super) tcp_config: Option<TcpConfig>,
    /// Requested transport preference; not yet an outbound routing policy.
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

    /// Consul-specific options (service name, datacenter, ACL token,
    /// health policy). Only read when the provider is Consul.
    #[cfg(feature = "cloud-discovery")]
    pub(super) consul_options: Option<crate::discovery::cloud::ConsulOptions>,
    /// Cloud discovery lowers the transport's multicast default to
    /// `Disabled` (same switch as Discovery Server mode) unless told not to.
    #[cfg(feature = "cloud-discovery")]
    pub(super) cloud_disable_multicast: bool,
    /// Registry poll interval.
    #[cfg(feature = "cloud-discovery")]
    pub(super) cloud_poll_interval: Duration,
    /// Typed AWS Cloud Map configuration, when the user built one.
    ///
    /// Separate from `consul_addr` on purpose: an AWS configuration can
    /// carry static credentials, and `consul_addr` is echoed back by the
    /// public `Participant::cloud_discovery_config()`.
    #[cfg(feature = "cloud-discovery")]
    pub(super) cloud_aws_config: Option<Box<crate::discovery::cloud::AwsCloudMapConfig>>,
    /// Shared Memory transport policy (Prefer, Require, Disable)
    pub(super) shm_policy: ShmPolicy,
    /// Participant-level transport options (TTL, DSCP, interface allowlist,
    /// multicast mode). Defaults replicate historical behavior.
    pub(super) transport_options: TransportOptions,
    /// UDP kernel socket buffer requests, kept outside TransportOptions to
    /// preserve that public struct's source-compatible shape.
    pub(super) socket_buffer_options: SocketBufferOptions,
    /// Advertised participant lease and steady-state SPDP cadence.
    discovery_timing: ParticipantDiscoveryTiming,
    /// Allocation strategy for the process-wide slab pool. See
    /// [`memory_policy`](Self::memory_policy) for why only the first
    /// participant built in a process can make this take effect.
    pub(super) memory_policy: crate::qos::MemoryPolicy,
    /// Tests only: the HDDS capabilities this participant announces and
    /// speaks, in place of `protocol::group::LOCAL_CAPABILITIES` (a peer
    /// of an older wire, in one process).
    #[cfg(test)]
    pub(super) hdds_capabilities: Option<u32>,
}

impl Participant {
    /// Create a new participant with default settings.
    ///
    /// This is a convenience method equivalent to:
    /// ```ignore
    /// Participant::builder(name).build()
    /// ```
    ///
    /// Uses UdpMulticast transport mode. The domain is `HDDS_DOMAIN_ID` when
    /// set and valid, else 0.
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
    /// Build under a GUID prefix the test chooses, the way a peer that
    /// reuses its prefix comes back (a foreign stack deriving it from host
    /// and process id, or an HDDS release before prefixes were unique). An
    /// HDDS participant otherwise never takes a prefix twice
    /// (`entity_registry::generate_guid`).
    #[cfg(all(test, feature = "security"))]
    pub(crate) fn build_with_guid_prefix_for_test(
        self,
        prefix: [u8; 12],
    ) -> crate::dds::Result<Arc<Participant>> {
        entity_registry::set_next_prefix_for_test(prefix);
        self.build()
    }

    pub(super) fn new(name: &str) -> Self {
        ParticipantBuilder {
            #[cfg(test)]
            liveliness_clock: None,
            name: name.to_string(),
            transport_mode: TransportMode::UdpMulticast,
            domain_id: None,
            participant_id: None,
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
            served_types: Arc::new(RwLock::new(HashMap::new())),
            #[cfg(feature = "xtypes")]
            topic_types: Arc::new(RwLock::new(HashMap::new())),
            #[cfg(feature = "security")]
            security_config: None,
            #[cfg(feature = "k8s")]
            k8s_discovery_config: None,
            #[cfg(feature = "dns-sd")]
            dns_sd_config: None,
            #[cfg(feature = "dns-sd")]
            dns_sd_disable_multicast: true,
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
            #[cfg(feature = "cloud-discovery")]
            consul_options: None,
            #[cfg(feature = "cloud-discovery")]
            cloud_disable_multicast: true,
            #[cfg(feature = "cloud-discovery")]
            cloud_poll_interval: bootstrap::CLOUD_DEFAULT_POLL_INTERVAL,
            #[cfg(feature = "cloud-discovery")]
            cloud_aws_config: None,
            shm_policy: ShmPolicy::Prefer,
            transport_options: TransportOptions::default(),
            socket_buffer_options: SocketBufferOptions::default(),
            discovery_timing: ParticipantDiscoveryTiming::default(),
            memory_policy: crate::qos::MemoryPolicy::default(),
            #[cfg(test)]
            hdds_capabilities: None,
        }
    }

    /// Tests only: announce and speak the HDDS capabilities `caps`
    /// (`PID_HDDS_CAPABILITIES`) instead of this build's: 0 is a participant
    /// of the HDDS 1.4.x GROUP wire.
    #[cfg(test)]
    pub(crate) fn hdds_capabilities_for_test(mut self, caps: u32) -> Self {
        self.hdds_capabilities = Some(caps);
        self
    }

    /// Set the transport mode (intra-process or UDP multicast).
    pub fn with_transport(mut self, mode: TransportMode) -> Self {
        self.transport_mode = mode;
        self
    }

    /// Set participant-level transport options for constrained networks:
    /// IP TTL, per-class DSCP marking, interface allowlist, and multicast
    /// on/off (unicast-only discovery).
    ///
    /// # Precedence
    ///
    /// Explicit options win over environment variables; env vars
    /// (`HDDS_TTL`, `HDDS_MULTICAST_TTL`, `HDDS_UNICAST_TTL`, `HDDS_DSCP`,
    /// `HDDS_INTERFACE_ALLOW`) remain the fallback for fields left at
    /// `None`. The default [`TransportOptions`] replicates the behavior
    /// without this call exactly. See [`crate::transport::TransportOptions`]
    /// for the full resolution table.
    ///
    /// # Example: tactical-radio gateway (unicast-only, marked traffic)
    /// ```no_run
    /// use hdds::transport::{DscpConfig, InterfaceFilter, TtlConfig};
    /// use hdds::{Participant, TransportOptions};
    ///
    /// let options = TransportOptions::default()
    ///     .with_ttl(TtlConfig::custom(8, 64))
    ///     .with_dscp(DscpConfig::high_priority())
    ///     .with_interface_allowlist(InterfaceFilter::only_names(&["eth1"]))
    ///     .unicast_only();
    ///
    /// let participant = Participant::builder("gateway")
    ///     .domain_id(0)
    ///     .with_transport_options(options)
    ///     .add_static_peer("192.168.1.100:7410") // peer metatraffic port
    ///     .build()
    ///     .unwrap();
    /// ```
    ///
    /// Static peers added via [`Self::add_static_peer`] always receive the
    /// periodic SPDP announcements (merged with `HDDS_SPDP_UNICAST_PEERS`),
    /// whatever the [`crate::MulticastMode`]. In `ReceiveOnly` and
    /// `Disabled` no multicast locators are advertised and every
    /// participant discovered by any means is announced to over unicast as
    /// well. Point static peers at the peer's metatraffic unicast port
    /// (7410 for domain 0 participant 0).
    pub fn with_transport_options(mut self, options: TransportOptions) -> Self {
        self.transport_options = options;
        self
    }

    /// Request a receive buffer size for participant-owned UDP sockets.
    ///
    /// This overrides `HDDS_RCVBUF_BYTES`. The kernel may cap the requested
    /// value; HDDS reads the effective value back and logs any explicit clamp.
    pub fn with_socket_receive_buffer_size(mut self, bytes: NonZeroUsize) -> Self {
        self.socket_buffer_options = self.socket_buffer_options.with_receive_buffer_size(bytes);
        self
    }

    /// Request a send buffer size for participant-owned UDP sockets.
    ///
    /// This overrides `HDDS_SNDBUF_BYTES`. The kernel may cap the requested
    /// value; HDDS reads the effective value back and logs any clamp.
    pub fn with_socket_send_buffer_size(mut self, bytes: NonZeroUsize) -> Self {
        self.socket_buffer_options = self.socket_buffer_options.with_send_buffer_size(bytes);
        self
    }

    /// Set the participant lease advertised in every SPDP announcement.
    ///
    /// The duration must be positive, exactly representable in milliseconds,
    /// and greater than the configured SPDP announcement period. Validation
    /// occurs in [`Self::build`].
    pub fn with_participant_lease_duration(mut self, duration: Duration) -> Self {
        self.discovery_timing.lease_duration = duration;
        self
    }

    /// Set the steady-state SPDP announcement period.
    ///
    /// The five-second startup burst remains enabled for interoperability.
    /// The duration must be positive and exactly representable in
    /// milliseconds. Validation occurs in [`Self::build`].
    pub fn with_spdp_announcement_period(mut self, period: Duration) -> Self {
        self.discovery_timing.announcement_period = period;
        self
    }

    /// Set the DDS domain ID. A domain set here always wins over
    /// `HDDS_DOMAIN_ID`.
    ///
    /// Left unset, `build()` reads `HDDS_DOMAIN_ID`: a value that is not a
    /// decimal integer, or is above 232, makes `build()` fail with
    /// `Error::Config`, and an empty value counts as unset. With neither, the
    /// domain is 0.
    pub fn domain_id(mut self, domain_id: u32) -> Self {
        self.domain_id = Some(domain_id);
        self
    }

    /// Set the participant ID (default: auto-assigned).
    ///
    /// The id selects the participant's unicast ports (DDSI-RTPS 2.5
    /// 9.6.1.1), which are exclusive on the host: `build()` fails with
    /// `AddrInUse` when another participant on this domain, in this process
    /// or another one, already uses the id. Left unset, the first free id
    /// is taken.
    pub fn participant_id(mut self, participant_id: Option<u8>) -> Self {
        self.participant_id = participant_id;
        self
    }

    /// Add comma-separated unicast SPDP seed peers.
    ///
    /// Each non-empty `IP:port` entry is treated like
    /// [`add_static_peer`](Self::add_static_peer). Invalid entries are logged
    /// and ignored.
    ///
    /// ```ignore
    /// let participant = Participant::builder("node")
    ///     .with_seed_peers("192.168.1.10:7410,192.168.1.11:7410")
    ///     .build()?;
    /// ```
    pub fn with_seed_peers(mut self, list: &str) -> Self {
        for peer in list
            .split(',')
            .map(str::trim)
            .filter(|peer| !peer.is_empty())
        {
            self = self.add_static_peer(peer);
        }
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
    ///
    /// # Participant id
    /// Custom ports do not depend on the participant id, but the GUID prefix
    /// does. Participants built on custom ports without
    /// [`Self::participant_id`] get a process-unique id so two of them in one
    /// process never share a GUID prefix (which would make them drop each
    /// other's SPDP as their own loopback). The unicast ports are exclusive
    /// (DDSI-RTPS 2.5 9.6.1.1): a second participant on the SAME
    /// `sedp_unicast` / `user_unicast` pair, in this process or another one,
    /// fails to build with `AddrInUse`; give each its own pair. Only
    /// `spdp_multicast` is shared.
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
    /// `TransportMode::UdpMulticast`. For the manual TCP endpoint, configure
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

    /// Discover peers through DNS-SD (RFC 6763 `SRV` + `A`/`AAAA`).
    ///
    /// This is the DNS half of the announced AWS Cloud Map integration and
    /// works against any zone that publishes the records: Cloud Map private
    /// DNS, Route 53, CoreDNS, Consul's DNS interface, a zone file.
    ///
    /// # Feature flag
    /// Requires the `dns-sd` feature (zero dependencies; implied by
    /// `cloud-discovery`).
    ///
    /// # Behaviour
    /// `build()` starts a thread that resolves `_hdds._udp.<domain>` every
    /// [`DnsSdConfig::poll_interval`](crate::discovery::dnssd::DnsSdConfig)
    /// and feeds every resolved `ip:port` into the SPDP unicast
    /// destinations, so discovery completes without multicast. Multicast
    /// is therefore disabled by default for such a participant; see
    /// [`Self::dns_sd_disable_multicast`].
    ///
    /// HDDS RESOLVES the zone, it does not publish into it: the `SRV` and
    /// address records are the deployment's (or Cloud Map's) job.
    ///
    /// # Errors at `build()`
    /// The configuration is validated up front and
    /// [`crate::dds::Error::Config`] is returned for a service label that
    /// is not RFC 6763 shaped, an empty domain, a name that cannot be
    /// encoded, a poll interval below 100 ms, and for having no nameserver
    /// at all (neither configured nor in `/etc/resolv.conf`). A cloud
    /// registry provider and DNS-SD on the same participant is also
    /// refused: they own the same leased peer origin.
    ///
    /// # Example
    /// ```no_run
    /// use hdds::discovery::dnssd::DnsSdConfig;
    /// use hdds::{Participant, TransportMode};
    ///
    /// let participant = Participant::builder("dns_sd_node")
    ///     .with_transport(TransportMode::UdpMulticast)
    ///     .with_dns_sd(DnsSdConfig::new("hdds.example.internal"))
    ///     .build()
    ///     .unwrap();
    ///
    /// let status = participant.dns_sd_status().unwrap();
    /// println!("peers={}", status.resolved_peers);
    /// ```
    #[cfg(feature = "dns-sd")]
    pub fn with_dns_sd(mut self, config: DnsSdConfig) -> Self {
        self.dns_sd_config = Some(config);
        self
    }

    /// Whether [`Self::with_dns_sd`] lowers the transport's multicast
    /// default to [`crate::transport::MulticastMode::Disabled`].
    ///
    /// Default `true`, the same rule as Discovery Server and cloud
    /// registry mode: a deployment that publishes its peers in DNS is a
    /// deployment where multicast does not route. It only lowers the
    /// DEFAULT; an explicit `with_transport_options(..)` multicast mode is
    /// kept as configured. Pass `false` to keep multicast next to DNS-SD.
    #[cfg(feature = "dns-sd")]
    pub fn dns_sd_disable_multicast(mut self, disable: bool) -> Self {
        self.dns_sd_disable_multicast = disable;
        self
    }

    // =========================================================================
    // TCP transport building block
    // =========================================================================

    /// Enable TCP transport with a specific listen port.
    ///
    /// This is a convenience method for simple TCP setups. For advanced
    /// configuration, use [`tcp_config()`](Self::tcp_config) instead.
    ///
    /// This creates an HDDS-specific TCP endpoint and enables inbound RTPS
    /// routing. It does not route [`DataWriter::write`](crate::dds::DataWriter::write)
    /// over TCP; outbound TCP requires [`Participant::tcp_connect`](crate::dds::Participant::tcp_connect)
    /// and [`Participant::tcp_send`](crate::dds::Participant::tcp_send).
    ///
    /// # Arguments
    /// * `listen_port` - TCP port to listen on (0 = OS assigns ephemeral port)
    ///
    /// # Example
    /// ```no_run
    /// use hdds::{Participant, TransportMode};
    ///
    /// // Create a participant with a manual TCP endpoint.
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
    /// This configures the manual TCP endpoint. It does not change the UDP
    /// transport used by `DataWriter::write`.
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
    pub fn tcp_config(mut self, config: TcpConfig) -> Self {
        self.tcp_config = Some(config);
        // Default to hybrid mode unless already set to TCP-only
        if self.transport_preference == TransportPreference::UdpOnly {
            self.transport_preference = TransportPreference::UdpDiscoveryTcpData;
        }
        self
    }

    /// Record a TCP-only transport preference.
    ///
    /// This preference currently makes TCP construction failure fatal, but it
    /// does not disable the UDP writer path or route `DataWriter::write` over
    /// TCP. Do not use it as proof of UDP-free operation.
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

    /// Record the requested transport preference.
    ///
    /// The value is currently exposed as participant metadata and used to make
    /// TCP setup failure fatal for `TcpOnly`. It is not consulted by the DDS
    /// writer send path.
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
    /// The low-bandwidth transport is a separate API: `DataWriter::write` does
    /// not use it. Its session handshake is not started in this release.
    ///
    /// Design targets (not measured):
    /// - **Throughput**: 9.6 kbps -> 2 Mbps
    /// - **Latency**: 100 ms -> 2 s RTT
    /// - **Loss**: 10-30% packet loss
    ///
    /// Use presets for common scenarios:
    /// - `LowBwConfig::slow_serial()` - 9600 bps (HC-12, RS-485)
    /// - `LowBwConfig::satellite()` - 128 kbps, high latency
    /// - `LowBwConfig::tactical_radio()` - 32 kbps, lossy
    /// - `LowBwConfig::iot_lora()` - LoRa/LPWAN (<10 kbps)
    ///
    /// # Example: HC-12 Radio Link (ESP32 <-> Pi Gateway)
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
    /// - **P2**: Telemetry (droppable) - batched, first to be dropped
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
    // Discovery Server client configuration
    // =========================================================================

    /// Configure automatic Discovery Server rendezvous.
    ///
    /// The participant owns the TCP client lifecycle, reconnects when configured,
    /// and uses server-provided participant locators as unicast SPDP seeds. SEDP,
    /// QoS matching, security, and user data remain peer-to-peer DDS traffic.
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

    /// Configure an automatic Discovery Server client address.
    ///
    /// Convenience method that creates a default client config for
    /// [`with_discovery_server`](Self::with_discovery_server).
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
    /// # Behaviour
    /// `build()` starts a poller thread that registers this participant's
    /// metatraffic locators in Consul (retried with backoff), polls the
    /// catalog every [`Self::with_cloud_poll_interval`] and feeds every
    /// peer of this domain into the SPDP unicast destinations, so
    /// discovery completes without multicast. Multicast is disabled by
    /// default for such a participant (cloud networks do not route it);
    /// see [`Self::cloud_discovery_disable_multicast`].
    ///
    /// # Endpoint transport
    /// `consul_addr` must carry an explicit scheme. `https://` is accepted
    /// anywhere; plaintext `http://` is accepted only when the host is a
    /// loopback literal (`127.0.0.0/8`, `::1`, `localhost`), which is the
    /// local-agent case. Anything else fails `build()` with
    /// [`crate::dds::Error::Config`]: the registry traffic carries this
    /// participant's GUID and locators, and no flag re-opens it.
    ///
    /// # Example
    /// ```ignore
    /// let participant = Participant::builder("k8s_node")
    ///     .with_consul("https://consul.service.consul:8500")
    ///     .build()?;
    ///
    /// // Optional: observe the registry from sync code.
    /// let status = participant.cloud_discovery_status().unwrap();
    /// println!("registered={} peers={}", status.registered, status.registry_peers);
    /// ```
    #[cfg(feature = "cloud-discovery")]
    pub fn with_consul(mut self, consul_addr: &str) -> Self {
        self.cloud_discovery_provider = Some("consul".to_string());
        self.consul_addr = Some(consul_addr.to_string());
        self
    }

    /// Configure Consul with everything that is not the endpoint: service
    /// name, datacenter, ACL token, health policy and the KV mirror.
    ///
    /// Equivalent to [`Self::with_consul`] plus the options; the defaults
    /// are the ones [`crate::discovery::cloud::ConsulOptions::default`]
    /// documents (TTL health check ON, KV mirror ON, no token).
    ///
    /// An ACL-enabled Consul answers `403 Permission denied` to an
    /// unauthenticated agent call, so a deployment with ACLs needs the
    /// token here; it is never rendered by any `Debug` output.
    ///
    /// Requires the `cloud-discovery` feature.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use hdds::discovery::cloud::ConsulOptions;
    ///
    /// let participant = Participant::builder("node")
    ///     .with_consul_options(
    ///         "https://consul.service.consul:8500",
    ///         ConsulOptions::default()
    ///             .with_token(std::env::var("CONSUL_HTTP_TOKEN")?)
    ///             .with_datacenter("dc1"),
    ///     )
    ///     .build()?;
    /// ```
    #[cfg(feature = "cloud-discovery")]
    pub fn with_consul_options(
        mut self,
        consul_addr: &str,
        options: crate::discovery::cloud::ConsulOptions,
    ) -> Self {
        self.cloud_discovery_provider = Some("consul".to_string());
        self.consul_addr = Some(consul_addr.to_string());
        self.consul_options = Some(options);
        self
    }

    /// Whether configuring a cloud registry (`with_consul`,
    /// `with_aws_cloud_map`, `with_azure_discovery`) lowers the transport's
    /// multicast default to [`crate::transport::MulticastMode::Disabled`].
    ///
    /// Default `true`: cloud users are the no-multicast users, and the
    /// registry is what replaces multicast SPDP. It only lowers the
    /// DEFAULT: an explicit `with_transport_options(..)` multicast mode is
    /// kept as configured, exactly like Discovery Server mode. Pass
    /// `false` to keep multicast enabled next to the registry.
    #[cfg(feature = "cloud-discovery")]
    pub fn cloud_discovery_disable_multicast(mut self, disable: bool) -> Self {
        self.cloud_disable_multicast = disable;
        self
    }

    /// How often the cloud registry is polled for peers (default 5 s).
    /// The first poll happens right after the poller starts.
    ///
    /// An interval below 100 ms (the poller loop's own tick) fails
    /// `build()` with [`crate::dds::Error::Config`]: it would poll the
    /// registry on every tick and shrink the cloud peer lease onto its
    /// one-second floor.
    #[cfg(feature = "cloud-discovery")]
    pub fn with_cloud_poll_interval(mut self, interval: Duration) -> Self {
        self.cloud_poll_interval = interval;
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
    /// # Behaviour
    /// Every other Cloud Map setting takes its default: the standard
    /// credential chain (environment, EKS IRSA web identity, ECS container
    /// role, IMDSv2), `HealthStatus` `ALL`, and the regional AWS
    /// endpoints. Use [`Self::with_aws_cloud_map_config`] to change any of
    /// them.
    ///
    /// `service` may be a `srv-...` id, a service ARN, or a service NAME.
    /// Cloud Map needs BOTH identities - the control plane takes the id,
    /// `DiscoverInstances` takes the name - so whichever one is given, the
    /// other is resolved once at startup: an id or an ARN costs one
    /// `servicediscovery:GetService`, a NAME costs one `ListNamespaces`
    /// plus `ListServices` walk. Supplying both, with
    /// [`AwsCloudMapConfig::with_service_name`](crate::discovery::cloud::AwsCloudMapConfig::with_service_name)
    /// through [`Self::with_aws_cloud_map_config`], is the only form that
    /// needs no lookup and therefore only the `RegisterInstance`,
    /// `DeregisterInstance` and `DiscoverInstances` IAM actions.
    ///
    /// # Validation status
    /// Proven against an in-process fake Cloud Map endpoint that verifies
    /// the SigV4 signature of every request. NOT validated against a live
    /// AWS account.
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
        self.cloud_aws_config = None;
        // Stored as JSON, built by serde_json so a namespace, service or
        // region containing a quote or a backslash escapes correctly:
        // `build()` parses this string back, and a hand-formatted one
        // would surface as an opaque JSON error from a call that looks
        // nothing like JSON. (A typed config is the batch-2 API.)
        self.consul_addr = Some(
            serde_json::json!({
                "namespace": namespace,
                "service": service,
                "region": region,
            })
            .to_string(),
        );
        self
    }

    /// Use AWS Cloud Map with a full configuration.
    ///
    /// The typed form of [`Self::with_aws_cloud_map`]: it carries the
    /// credential source, the `DiscoverInstances` health filter, an
    /// endpoint override (a VPC endpoint, or a test fake) and the ECS task
    /// metadata endpoint.
    ///
    /// The configuration is held in a dedicated field, NOT serialised into
    /// the string `Participant::cloud_discovery_config()` returns: a
    /// static secret must never travel through a public accessor. That
    /// accessor reports
    /// [`AwsCloudMapConfig::redacted_json`](crate::discovery::cloud::AwsCloudMapConfig::redacted_json)
    /// instead.
    ///
    /// # Feature Flag
    /// Requires the `cloud-discovery` feature.
    ///
    /// # Example
    /// ```ignore
    /// use hdds::discovery::cloud::{AwsCloudMapConfig, AwsHealthStatus};
    ///
    /// let participant = Participant::builder("eks_pod")
    ///     .with_aws_cloud_map_config(
    ///         AwsCloudMapConfig::new("hdds-namespace", "srv-0123456789abcdef", "eu-west-3")
    ///             .with_health_status(AwsHealthStatus::HealthyOrElseAll),
    ///     )
    ///     .build()?;
    /// ```
    #[cfg(feature = "cloud-discovery")]
    pub fn with_aws_cloud_map_config(
        mut self,
        config: crate::discovery::cloud::AwsCloudMapConfig,
    ) -> Self {
        self.cloud_discovery_provider = Some("aws".to_string());
        self.consul_addr = Some(config.redacted_json());
        self.cloud_aws_config = Some(Box::new(config));
        self
    }

    /// Use Azure Table Storage as the participant registry.
    ///
    /// Azure integration is for:
    /// - Azure Kubernetes Service (AKS)
    /// - Azure Container Instances
    /// - Azure VMs and scale sets in VNets
    ///
    /// # Feature Flag
    /// Requires the `cloud-discovery` feature.
    ///
    /// # Behaviour
    /// `build()` starts a poller that writes this participant's
    /// metatraffic locators as one row of an Azure Storage table
    /// (`PartitionKey` = its domain, `RowKey` = its GUID), refreshes that
    /// row before its lease expires, queries the domain's partition every
    /// [`Self::with_cloud_poll_interval`], and feeds every live peer into
    /// the SPDP unicast destinations, so discovery completes without
    /// multicast. See ADR 0002.
    ///
    /// # Configuration
    /// `config_json` is an [`crate::discovery::cloud::AzureDiscoveryConfig`],
    /// for example:
    /// ```json
    /// {"account":"hddsacct","auth":{"kind":"managed_identity"}}
    /// ```
    /// `auth` is `managed_identity` (VM, VMSS, AKS node; optional
    /// `client_id` for a user-assigned identity), `workload_identity`
    /// (AKS pod; defaults to the `AZURE_*` variables the webhook
    /// projects) or `sas` (`token`, or `token_env` naming the variable
    /// that holds the signature). Shared Key / account key / connection
    /// string is refused: it is a long-lived shared secret with full
    /// data-plane rights.
    ///
    /// The identity needs the `Storage Table Data Contributor` role on
    /// the account. Table creation is best effort: a credential that may
    /// not create tables (a table-scoped SAS) works against a table that
    /// already exists.
    ///
    /// # Errors at build time
    /// An unparsable config, an unknown field, a refused auth mode, a
    /// plaintext `http://` table endpoint on a non-loopback host, or a
    /// credential that cannot be resolved -- the Workload Identity token
    /// FILE is read here, not only at mint time -- fails `build()` with
    /// [`crate::dds::Error::Config`] -- never a participant whose poller
    /// dies with multicast already lowered.
    ///
    /// # Example
    /// ```ignore
    /// let participant = Participant::builder("aks_pod")
    ///     .with_azure_discovery(r#"{"account":"hddsacct","auth":{"kind":"workload_identity"}}"#)
    ///     .build()?;
    /// ```
    #[cfg(feature = "cloud-discovery")]
    pub fn with_azure_discovery(mut self, config_json: &str) -> Self {
        self.cloud_discovery_provider = Some("azure".to_string());
        self.consul_addr = Some(config_json.to_string());
        self
    }

    /// Same as [`Self::with_azure_discovery`], typed.
    ///
    /// The config is serialised into the one string the builder carries,
    /// so both forms take exactly the same path afterwards.
    ///
    /// A `sas` credential given as a literal `token` ends up in that
    /// string, which [`crate::Participant::cloud_discovery_config`]
    /// returns verbatim; `token_env` keeps the secret out of it.
    #[cfg(feature = "cloud-discovery")]
    pub fn with_azure_discovery_config(
        self,
        config: &crate::discovery::cloud::AzureDiscoveryConfig,
    ) -> Self {
        // Serialisation of this type cannot fail (plain strings, one
        // enum, two integers); the fallback keeps the call infallible and
        // the empty string then fails `build()` loudly.
        let json = serde_json::to_string(config).unwrap_or_default();
        self.with_azure_discovery(&json)
    }

    // =========================================================================
    // SHM (Shared Memory) Transport Configuration
    // =========================================================================

    /// Set the Shared Memory transport policy.
    ///
    /// # Current status
    ///
    /// The SHM transport (`transport/shm`) is implemented and unit-tested,
    /// but is **not wired to any writer or reader**: no sample is
    /// transported over SHM today, regardless of policy. See
    /// `transport::shm::ShmPolicy` for the full picture. Concretely:
    ///
    /// - `ShmPolicy::Prefer` (the participant default) -- advertise SHM
    ///   capability over SEDP AND carry DATA over shared memory whenever the
    ///   pairing qualifies: same shared-memory realm, both sides BEST_EFFORT.
    ///   A pairing that does not qualify uses UDP, decided once at pairing.
    /// - `ShmPolicy::Require` -- **`build()` returns
    ///   `Err(Error::Config(..))`**. `Require` means "never move a sample over
    ///   UDP behind my back", and one gap remains that no build-time check can
    ///   close: samples past `DEFAULT_MAX_UNFRAGMENTED_SIZE` go out as
    ///   DATA_FRAG, which is not wired to shared memory. Whether a given
    ///   participant will write one is a property of the SAMPLE, not of the
    ///   configuration, so the request is refused rather than honoured
    ///   partially.
    /// - `ShmPolicy::Disable` -- neither advertise nor use shared memory.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use hdds::{Participant, TransportMode};
    /// use hdds::transport::shm::ShmPolicy;
    ///
    /// // The participant default: advertises SHM and uses it for qualifying
    /// // pairings.
    /// let participant = Participant::builder("shm_app")
    ///     .shm_policy(ShmPolicy::Prefer)
    ///     .build()?;
    ///
    /// // Require still fails at build(): the large-DATA leg is not wired.
    /// let err = Participant::builder("local_only")
    ///     .shm_policy(ShmPolicy::Require)
    ///     .build()
    ///     .unwrap_err();
    /// ```
    pub fn shm_policy(mut self, policy: ShmPolicy) -> Self {
        self.shm_policy = policy;
        self
    }

    /// Advertise SHM capability over SEDP and use shared memory for DATA on
    /// qualifying pairings (the participant default; see `shm_policy`).
    ///
    /// Shorthand for `.shm_policy(ShmPolicy::Prefer)`.
    pub fn shm_prefer(mut self) -> Self {
        self.shm_policy = ShmPolicy::Prefer;
        self
    }

    /// Request SHM transport. `build()` still fails with this policy, but not
    /// because the data path is missing - it is wired for ordinary DATA. What
    /// is missing is the large-DATA leg: a sample past
    /// `DEFAULT_MAX_UNFRAGMENTED_SIZE` goes out as DATA_FRAG over UDP, and
    /// `Require` is a promise never to do that behind the caller's back.
    /// Whether a participant will write such a sample cannot be known at
    /// build time, so the request is refused rather than half-kept (see
    /// `shm_policy` and `transport::shm::ShmPolicy::Require`).
    ///
    /// Shorthand for `.shm_policy(ShmPolicy::Require)`.
    pub fn shm_require(mut self) -> Self {
        self.shm_policy = ShmPolicy::Require;
        self
    }

    /// Disable SHM: do not advertise SHM capability over SEDP.
    ///
    /// Shorthand for `.shm_policy(ShmPolicy::Disable)`.
    ///
    /// Use this for debugging, cross-machine deployments, or when you do
    /// not want to advertise the capability to peers.
    pub fn shm_disable(mut self) -> Self {
        self.shm_policy = ShmPolicy::Disable;
        self
    }

    /// Allocation strategy for the slab pool backing every writer/reader
    /// payload (intra-process and wire alike): which secondary size
    /// classes exist for large payloads, and the heap fallback's byte
    /// ceiling. See [`crate::qos::MemoryPolicy`].
    ///
    /// The pool itself is process-wide, not per-participant: `build()`
    /// hands this policy to [`crate::core::rt::init_slab_pool_with_policy`],
    /// which builds the pool from the FIRST participant's policy in the
    /// process and logs (rather than silently ignoring) any later
    /// participant asking for a different one. Set it once, on whichever
    /// participant your process creates first, if you need it to matter.
    pub fn memory_policy(mut self, policy: crate::qos::MemoryPolicy) -> Self {
        self.memory_policy = policy;
        self
    }

    // build() is implemented in bootstrap.rs
}
