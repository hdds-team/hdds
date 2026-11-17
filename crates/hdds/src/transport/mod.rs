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
/// Announced addresses that are not bound locally (NAT / relay endpoints).
pub mod external_locator;
/// IP-based network filtering (whitelist/blacklist).
pub mod filter;
/// Local interface enumeration snapshot (getifaddrs on Unix). Public only so
/// the `ifaces_ab` example can A/B the real code path; not a stable API.
#[doc(hidden)]
pub mod ifaddrs;
/// Low Bandwidth Transport for constrained links (9.6 kbps - 2 Mbps).
pub mod lowbw;
/// IP mobility detection and locator tracking.
pub mod mobility;
/// Multicast group management and interface discovery.
pub mod multicast;
/// Participant-level transport options (TTL, DSCP, allowlist, multicast mode).
pub mod options;
/// RTPS v2.5 port number calculation and mapping.
pub mod ports;
pub(crate) mod relay;
pub(crate) mod relay_locator;
/// Shared memory transport for inter-process zero-copy communication.
#[cfg(target_os = "linux")]
pub mod shm;
pub(crate) mod socket_buffer;

/// SHM stub for non-Linux platforms (provides public types, no-op implementation).
///
/// SHM is only available on Linux. This stub provides the public types so
/// downstream code compiles unchanged on every other platform.
#[cfg(not(target_os = "linux"))]
pub mod shm {

    /// SHM transport selection policy (stub -- always resolves to UDP on this platform).
    ///
    /// The default is `Disable`, in lockstep with the Linux enum, so
    /// `ShmPolicy::default()` answers the same on every target. This stub
    /// resolves every selection to UDP and advertises no capability, which
    /// would hide any divergence until the stub gained a real implementation;
    /// keeping the defaults identical avoids a non-Linux build advertising a
    /// transport its author never opted into.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
    pub enum ShmPolicy {
        Prefer,
        Require,
        #[default]
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

    /// There is no SHM data path on this platform, so a participant built
    /// with `ShmPolicy::Require` is refused by `build()` (see
    /// `builder/bootstrap.rs`) rather than silently running over UDP.
    /// Mirrors `shm::policy::shm_require_is_honourable` on Linux.
    pub(crate) const fn shm_require_is_honourable() -> bool {
        false
    }

    impl ShmPolicy {
        /// Which policy an ENDPOINT runs under, given its own setting and its
        /// participant's. Mirrors `shm::policy::ShmPolicy::resolve` on Linux
        /// exactly (same signature, same precedence): the more specific
        /// setting wins, and absence of everything means no shared memory.
        ///
        /// Kept in lockstep with the Linux implementation on purpose -- the
        /// call sites in `dds/reader/builder.rs` and `dds/writer/builder.rs`
        /// are NOT `#[cfg]`-gated, so this stub must expose the identical
        /// associated function or every non-Linux target fails to compile
        /// (a missing `resolve` on the stub breaks the non-Linux build).
        #[must_use]
        pub fn resolve(endpoint: Option<Self>, participant: Option<Self>) -> Self {
            endpoint.or(participant).unwrap_or(Self::Disable)
        }
    }

    /// Co-location can never be proven on a platform with no shared-memory
    /// transport. Mirrors `shm::colocation_is_provable` on Linux.
    #[must_use]
    pub fn colocation_is_provable() -> bool {
        false
    }

    /// Selects UDP on non-Linux platforms. `ShmPolicy::Require` is refused:
    /// there is no SHM transport here, and a policy whose point is to fail
    /// loudly must not fall back to UDP silently (the Linux implementation
    /// refuses too when the peer cannot do SHM).
    pub fn select_transport(
        policy: ShmPolicy,
        _remote_user_data: Option<&str>,
        _local_best_effort: bool,
        _remote_best_effort: bool,
    ) -> std::result::Result<TransportSelection, TransportSelectionError> {
        if policy == ShmPolicy::Require {
            return Err(TransportSelectionError(
                "SHM transport required but not available on this platform".to_string(),
            ));
        }
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

    /// No ring segment can exist on this platform, so none is left behind.
    /// Mirrors `shm::reclaim_dead_ring_segments` on Linux, which
    /// `builder/bootstrap.rs` calls without a `#[cfg]` gate.
    #[must_use]
    pub fn reclaim_dead_ring_segments(_domain_id: u32) -> usize {
        0
    }

    /// No notify segment can exist on this platform, so none is released.
    /// Mirrors `shm::reclaim_dead_notify_segments` on Linux.
    #[must_use]
    pub fn reclaim_dead_notify_segments(_domain_id: u32) -> usize {
        0
    }

    /// Mirrors `transport::shm::policy::endpoint_policy_tests` on Linux
    /// (same three cases, same assertions) so the stub's `resolve` is
    /// proven to have the identical precedence, not just the identical
    /// signature. This module only compiles on a non-Linux target
    /// (`cfg(not(target_os = "linux"))` on the enclosing `mod shm`), so it
    /// cannot run from a Linux CI host -- it is exercised by the
    /// `x86_64-pc-windows-gnu` / `*-apple-darwin` cross-compile checks
    /// compiling it, and by an actual test run on one of those platforms.
    #[cfg(test)]
    mod endpoint_policy_tests {
        use super::ShmPolicy;

        #[test]
        fn an_endpoints_own_policy_overrides_its_participants() {
            assert_eq!(
                ShmPolicy::resolve(Some(ShmPolicy::Disable), Some(ShmPolicy::Prefer)),
                ShmPolicy::Disable,
                "a writer that asked for Disable must not inherit Prefer"
            );
            assert_eq!(
                ShmPolicy::resolve(Some(ShmPolicy::Prefer), Some(ShmPolicy::Disable)),
                ShmPolicy::Prefer
            );
        }

        #[test]
        fn an_endpoint_that_asked_for_nothing_follows_its_participant() {
            assert_eq!(
                ShmPolicy::resolve(None, Some(ShmPolicy::Prefer)),
                ShmPolicy::Prefer
            );
            assert_eq!(
                ShmPolicy::resolve(None, Some(ShmPolicy::Disable)),
                ShmPolicy::Disable
            );
        }

        #[test]
        fn no_participant_means_no_shared_memory() {
            assert_eq!(ShmPolicy::resolve(None, None), ShmPolicy::Disable);
            assert_eq!(
                ShmPolicy::resolve(Some(ShmPolicy::Prefer), None),
                ShmPolicy::Prefer,
                "an explicit ask still stands on its own"
            );
        }

        /// The honest half of this stub: `Require` is refused, never
        /// silently downgraded to UDP. Mirrors
        /// `participant::builder::bootstrap::shm_require_refuses_at_build`,
        /// which already runs cross-platform through this same
        /// `select_transport`; this test pins the lower-level function
        /// directly so a future edit to `select_transport` alone (without
        /// touching the builder) still gets caught here.
        #[test]
        fn select_transport_refuses_require_instead_of_downgrading_to_udp() {
            let err = super::select_transport(ShmPolicy::Require, None, true, true)
                .expect_err("Require must be refused on a platform with no SHM data path");
            assert!(
                err.to_string().to_ascii_lowercase().contains("shm"),
                "the refusal must mention SHM: {err}"
            );
        }

        #[test]
        fn select_transport_allows_prefer_and_disable() {
            // `TransportSelectionError` has no `PartialEq`, so compare the
            // unwrapped selection rather than the `Result`.
            assert_eq!(
                super::select_transport(ShmPolicy::Prefer, None, true, true)
                    .expect("Prefer must not be refused"),
                super::TransportSelection::Udp
            );
            assert_eq!(
                super::select_transport(ShmPolicy::Disable, None, true, true)
                    .expect("Disable must not be refused"),
                super::TransportSelection::Udp
            );
        }
    }
}
/// QUIC transport for NAT traversal and connection migration.
#[cfg(feature = "quic")]
pub mod quic;
/// Manual HDDS-to-HDDS TCP endpoint; DDS writers remain UDP-backed.
pub mod tcp;
/// Time-Sensitive Networking (TSN) support for deterministic Ethernet.
pub mod tsn;
/// TTL (Time To Live) configuration for IP packet hop limit.
pub mod ttl;
/// UDP socket management for RTPS communication.
pub mod udp;

// Re-export main types
pub use dscp::{DscpClass, DscpConfig};
pub use external_locator::{ExternalLocator, ExternalLocatorError};
pub use filter::{
    InterfaceFilter, InterfaceMatcher, Ipv4Network, NetworkFilter, NetworkFilterBuilder,
    NetworkParseError, SourceFilter,
};
pub use options::{MulticastMode, ResolvedTransportOptions, TransportOptions};
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
