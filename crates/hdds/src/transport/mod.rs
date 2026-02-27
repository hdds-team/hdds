// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Transport layer for RTPS communication.
//!
//! Manages UDP sockets, multicast groups, port mapping, and shared memory
//! according to RTPS v2.5 specification (OMG DDS-RTPS Sec.9.6).
//!
//! # Modules
//!
//! - `udp` - UDP socket management and send/receive operations
//! - `multicast` - Multicast group joining and interface discovery
//! - `ports` - RTPS v2.5 port number calculation
//! - `shm` - Shared memory transport for inter-process zero-copy communication
//!
//! # Example
//!
//! ```no_run
//! use hdds::transport::{PortMapping, UdpTransport};
//!
//! // Calculate RTPS ports for domain 0, participant 0
//! let mapping = PortMapping::calculate(0, 0).unwrap();
//! let transport = UdpTransport::new(0, 0, mapping).unwrap();
//!
//! // Send RTPS packet
//! transport.send(b"RTPS...").unwrap();
//! ```

/// DSCP (Differentiated Services Code Point) for network QoS.
pub mod dscp;
/// IP-based network filtering (whitelist/blacklist).
pub mod filter;
/// Low Bandwidth Transport for constrained links (9.6 kbps - 2 Mbps).
pub mod lowbw;
/// IP mobility detection and locator tracking.
pub mod mobility;
/// Multicast group management and interface discovery.
pub mod multicast;
/// RTPS v2.5 port number calculation and mapping.
pub mod ports;
/// Shared memory transport for inter-process zero-copy communication.
#[cfg(target_os = "linux")]
pub mod shm;

/// SHM stub for non-Linux platforms (provides public types, no-op implementation).
#[cfg(not(target_os = "linux"))]
pub mod shm {
    //! Stub module -- SHM is only available on Linux.
    //! This provides the public types so downstream code compiles unchanged.

    /// SHM transport selection policy (stub -- always resolves to UDP on this platform).
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
    pub enum ShmPolicy {
        #[default]
        Prefer,
        Require,
        Disable,
    }

    /// Selected transport type
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum TransportSelection {
        Udp,
        Shm,
    }

    /// Transport selection error
    #[derive(Clone, Debug)]
    pub struct TransportSelectionError(pub String);

    impl std::fmt::Display for TransportSelectionError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.0)
        }
    }

    impl std::error::Error for TransportSelectionError {}

    /// Always selects UDP on non-Linux platforms.
    pub fn select_transport(
        _policy: ShmPolicy,
        _remote_user_data: Option<&str>,
        _local_best_effort: bool,
        _remote_best_effort: bool,
    ) -> std::result::Result<TransportSelection, TransportSelectionError> {
        Ok(TransportSelection::Udp)
    }

    /// SHM metrics (stub)
    #[derive(Clone, Debug, Default)]
    pub struct ShmMetrics;

    /// SHM metrics snapshot (stub)
    #[derive(Clone, Debug, Default)]
    pub struct ShmMetricsSnapshot;

    /// Get global SHM metrics (stub -- returns empty metrics)
    pub fn global_metrics() -> ShmMetricsSnapshot {
        ShmMetricsSnapshot
    }

    /// Generate host ID from machine identifier.
    #[must_use]
    pub fn host_id() -> u32 {
        if let Ok(hostname) = std::env::var("COMPUTERNAME") {
            return hash_string(&hostname);
        }
        if let Ok(hostname) = std::env::var("HOSTNAME") {
            return hash_string(&hostname);
        }
        0xDEAD_BEEF
    }

    fn hash_string(s: &str) -> u32 {
        let mut hash: u32 = 2_166_136_261;
        for byte in s.bytes() {
            hash ^= u32::from(byte);
            hash = hash.wrapping_mul(16_777_619);
        }
        hash
    }

    /// Format SHM capability for user_data (stub -- advertises no SHM).
    #[must_use]
    pub fn format_shm_user_data() -> String {
        // Do not advertise SHM on non-Linux
        String::new()
    }

    /// Parse SHM capability from user_data string (stub -- always returns None).
    #[must_use]
    pub fn parse_shm_user_data(_user_data: &str) -> Option<(u32, u32)> {
        None
    }

    /// Check if SHM transport can be used (stub -- always returns None).
    #[must_use]
    pub fn can_use_shm_transport(
        _remote_user_data: Option<&str>,
        _local_best_effort: bool,
        _remote_best_effort: bool,
    ) -> Option<u32> {
        None
    }
}
/// QUIC transport for NAT traversal and connection migration.
#[cfg(feature = "quic")]
pub mod quic;
/// TCP transport for environments where UDP is blocked or unreliable.
pub mod tcp;
/// Time-Sensitive Networking (TSN) support for deterministic Ethernet.
pub mod tsn;
/// TTL (Time To Live) configuration for IP packet hop limit.
pub mod ttl;
/// UDP socket management for RTPS communication.
pub mod udp;

// Re-export main types
pub use dscp::{DscpClass, DscpConfig};
pub use filter::{
    InterfaceFilter, InterfaceMatcher, Ipv4Network, NetworkFilter, NetworkFilterBuilder,
    NetworkParseError, SourceFilter,
};
pub use ports::{CustomPortMapping, PortMapping};
pub use tsn::{
    default_backend as tsn_default_backend, DropPolicy, SupportLevel, TrafficPolicy, TsnBackend,
    TsnCapabilities, TsnClockId, TsnConfig, TsnEnforcement, TsnErrorStats, TsnMetrics, TsnProbe,
    TsnTxtime, TxTimePolicy,
};
pub use ttl::{get_multicast_ttl, get_unicast_ttl, set_multicast_ttl, set_unicast_ttl, TtlConfig};
pub use udp::UdpTransport;

// Re-export SHM types (full implementation on Linux, stubs elsewhere)
pub use shm::{
    global_metrics as shm_global_metrics, select_transport, ShmMetrics, ShmMetricsSnapshot,
    ShmPolicy, TransportSelection, TransportSelectionError,
};

// Re-export Linux-only SHM implementation types
#[cfg(target_os = "linux")]
pub use shm::{ShmRingReader, ShmRingWriter, ShmSegment};

// Re-export QUIC types when feature is enabled
#[cfg(feature = "quic")]
pub use quic::{
    QuicConfig, QuicConfigBuilder, QuicConnection, QuicConnectionState, QuicError, QuicResult,
    QuicTransport, QuicTransportHandle,
};
