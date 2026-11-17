// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Transport and participant configuration C FFI bindings.
//!
//! Provides a builder-style API for C/C++ users to configure participants
//! with TCP, TLS, SHM, and transport settings before creation.
//!
//! # Design
//!
//! We store configuration in our own `ParticipantConfigInner` struct (all pub fields)
//! rather than wrapping `ParticipantBuilder` directly, because `ParticipantBuilder`
//! fields are `pub(super)` and its methods consume `self`. At build time we translate
//! our config into chained builder calls.
//!
//! # Usage from C
//!
//! ```c
//! HddsParticipantConfig* cfg = hdds_config_create("my_app");
//! hdds_config_set_domain_id(cfg, 42);
//! hdds_config_enable_tcp(cfg, 7410);
//! hdds_config_set_shm_policy(cfg, HDDS_SHM_PREFER);
//! HddsParticipant* p = hdds_config_build(cfg);
//! // cfg is consumed by build, do NOT destroy it
//! ```

use std::ffi::CStr;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::os::raw::c_char;
use std::path::PathBuf;
use std::ptr;
use std::time::Duration;

use hdds::transport::dscp::{DscpClass, DscpConfig};
use hdds::transport::filter::{InterfaceFilter, InterfaceMatcher};
use hdds::transport::ttl::TtlConfig;
use hdds::MulticastMode;
use hdds::Participant;
use hdds::ShmPolicy;
use hdds::TcpConfig;
use hdds::TcpRole;
use hdds::TransportMode;
use hdds::TransportOptions;
use hdds::TransportPreference;

use crate::{HddsError, HddsParticipant};

// =============================================================================
// Internal config struct (owns all settings, translated to builder at build time)
// =============================================================================

struct ParticipantConfigInner {
    name: String,
    /// `None` unless `hdds_config_set_domain_id` was called: the core then applies
    /// the domain rule (HDDS_DOMAIN_ID, else 0) at build time.
    domain_id: Option<u32>,
    participant_id: Option<u8>,
    transport_mode: TransportMode,
    shm_policy: ShmPolicy,
    tcp_config: Option<TcpConfig>,
    /// TLS material (paths only; materialised into a `TlsConfig` at build time).
    tls_cert_file: Option<PathBuf>,
    tls_key_file: Option<PathBuf>,
    tls_ca_file: Option<PathBuf>,
    tls_crl_file: Option<PathBuf>,
    tls_require_client_cert: bool,
    transport_preference: TransportPreference,
    transport_options: TransportOptions,
    socket_receive_buffer_size: Option<NonZeroUsize>,
    socket_send_buffer_size: Option<NonZeroUsize>,
    participant_lease_duration: Option<Duration>,
    spdp_announcement_period: Option<Duration>,
    discovery_ports: Option<(u16, u16, u16)>,
    static_peers: Vec<SocketAddr>,
    #[cfg(feature = "security")]
    security_config: Option<crate::security_config::SecurityConfigInner>,
}

impl ParticipantConfigInner {
    fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            domain_id: None,
            participant_id: None,
            transport_mode: TransportMode::UdpMulticast,
            shm_policy: ShmPolicy::Prefer,
            tcp_config: None,
            tls_cert_file: None,
            tls_key_file: None,
            tls_ca_file: None,
            tls_crl_file: None,
            tls_require_client_cert: false,
            transport_preference: TransportPreference::UdpOnly,
            transport_options: TransportOptions::default(),
            socket_receive_buffer_size: None,
            socket_send_buffer_size: None,
            participant_lease_duration: None,
            spdp_announcement_period: None,
            discovery_ports: None,
            static_peers: Vec::new(),
            #[cfg(feature = "security")]
            security_config: None,
        }
    }
}

/// Opaque handle to a participant configuration (builder).
pub struct HddsParticipantConfig {
    _private: [u8; 0],
}

// =============================================================================
// SHM Policy
// =============================================================================

/// Shared memory policy for C FFI.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code, clippy::enum_variant_names)]
pub enum HddsShmPolicy {
    /// Prefer SHM when available, fallback to UDP (default).
    HddsShmPrefer = 0,
    /// Require SHM, fail if conditions not met.
    HddsShmRequire = 1,
    /// Disable SHM, always use network transport.
    HddsShmDisable = 2,
}

// =============================================================================
// Transport Preference
// =============================================================================

/// Transport preference for C FFI.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code, clippy::enum_variant_names)]
pub enum HddsTransportPreference {
    /// UDP only (default).
    HddsTransportPrefUdpOnly = 0,
    /// TCP only (requires initial peers).
    HddsTransportPrefTcpOnly = 1,
    /// UDP for discovery, TCP for data.
    HddsTransportPrefUdpDiscoveryTcpData = 2,
    /// Prefer SHM for local, UDP for remote.
    HddsTransportPrefShmPreferred = 3,
    /// SHM for local, TCP for remote.
    HddsTransportPrefShmLocalTcpRemote = 4,
}

// =============================================================================
// DSCP Configuration
// =============================================================================

/// Named DSCP values accepted by `hdds_config_set_dscp`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code, clippy::enum_variant_names)]
pub enum HddsDscpClass {
    /// Best effort / CS0.
    HddsDscpBestEffort = 0,
    /// Assured Forwarding 11.
    HddsDscpAf11 = 10,
    /// Assured Forwarding 21.
    HddsDscpAf21 = 18,
    /// Assured Forwarding 31.
    HddsDscpAf31 = 26,
    /// Assured Forwarding 41.
    HddsDscpAf41 = 34,
    /// Expedited Forwarding.
    HddsDscpEf = 46,
    /// Class Selector 6.
    HddsDscpCs6 = 48,
    /// Class Selector 7.
    HddsDscpCs7 = 56,
}

/// Participant-level DSCP values, expressed as the raw six-bit code points.
///
/// Use the `HDDS_DSCP_*` constants above. Discovery currently shares the
/// metatraffic multicast socket, so its value is retained for forward
/// compatibility but metatraffic wins on that shared socket today.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HddsDscpConfig {
    /// SPDP discovery code point; currently blurred with metatraffic multicast.
    pub discovery: u8,
    /// User DATA and user-data HEARTBEAT/GAP code point.
    pub user_data: u8,
    /// SEDP, ACKNACK, HEARTBEAT, and repair code point.
    pub metatraffic: u8,
}

// =============================================================================
// TCP Role
// =============================================================================

/// TCP role for C FFI.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code, clippy::enum_variant_names)]
pub enum HddsTcpRole {
    /// Auto-negotiation via GUID tie-breaker (default).
    HddsTcpRoleAuto = 0,
    /// Server only: listen but never initiate.
    HddsTcpRoleServerOnly = 1,
    /// Client only: initiate but never listen.
    HddsTcpRoleClientOnly = 2,
}

// =============================================================================
// Config Creation / Destruction
// =============================================================================

/// Create a new participant configuration (builder).
///
/// The returned handle must be passed to `hdds_config_build` (which consumes it)
/// or freed with `hdds_config_destroy` if not used.
///
/// # Safety
/// - `name` must be a valid null-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn hdds_config_create(name: *const c_char) -> *mut HddsParticipantConfig {
    if name.is_null() {
        return ptr::null_mut();
    }
    let Ok(name_str) = CStr::from_ptr(name).to_str() else {
        return ptr::null_mut();
    };

    let inner = ParticipantConfigInner::new(name_str);
    Box::into_raw(Box::new(inner)).cast::<HddsParticipantConfig>()
}

/// Destroy a participant configuration without building.
///
/// Only call this if you do NOT call `hdds_config_build`.
///
/// # Safety
/// - `config` must be a valid pointer from `hdds_config_create`, or NULL.
#[no_mangle]
pub unsafe extern "C" fn hdds_config_destroy(config: *mut HddsParticipantConfig) {
    if !config.is_null() {
        let _ = Box::from_raw(config.cast::<ParticipantConfigInner>());
    }
}

// =============================================================================
// Basic Configuration
// =============================================================================

/// Set the DDS domain ID. A domain set here always wins over `HDDS_DOMAIN_ID`.
/// Without this call, `hdds_config_build` reads `HDDS_DOMAIN_ID` (a malformed or
/// out-of-range value makes the build fail), else uses domain 0.
///
/// # Safety
/// - `config` must be a valid pointer from `hdds_config_create`.
#[no_mangle]
pub unsafe extern "C" fn hdds_config_set_domain_id(
    config: *mut HddsParticipantConfig,
    domain_id: u32,
) -> HddsError {
    if config.is_null() {
        return HddsError::HddsInvalidArgument;
    }
    let inner = &mut *config.cast::<ParticipantConfigInner>();
    inner.domain_id = Some(domain_id);
    HddsError::HddsOk
}

/// Set the participant ID (for port assignment).
///
/// Each participant on the same host should have a unique ID (0-119).
/// If not set, ports are auto-probed.
///
/// # Safety
/// - `config` must be a valid pointer from `hdds_config_create`.
#[no_mangle]
pub unsafe extern "C" fn hdds_config_set_participant_id(
    config: *mut HddsParticipantConfig,
    participant_id: u8,
) -> HddsError {
    if config.is_null() {
        return HddsError::HddsInvalidArgument;
    }
    let inner = &mut *config.cast::<ParticipantConfigInner>();
    inner.participant_id = Some(participant_id);
    HddsError::HddsOk
}

/// Set the transport mode (IntraProcess or UdpMulticast).
///
/// # Safety
/// - `config` must be a valid pointer from `hdds_config_create`.
#[no_mangle]
pub unsafe extern "C" fn hdds_config_set_transport_mode(
    config: *mut HddsParticipantConfig,
    mode: crate::HddsTransportMode,
) -> HddsError {
    if config.is_null() {
        return HddsError::HddsInvalidArgument;
    }
    let inner = &mut *config.cast::<ParticipantConfigInner>();
    inner.transport_mode = match mode {
        crate::HddsTransportMode::HddsTransportIntraProcess => TransportMode::IntraProcess,
        crate::HddsTransportMode::HddsTransportUdpMulticast => TransportMode::UdpMulticast,
    };
    HddsError::HddsOk
}

/// Set custom discovery ports (override RTPS default port formula).
///
/// # Safety
/// - `config` must be a valid pointer from `hdds_config_create`.
#[no_mangle]
pub unsafe extern "C" fn hdds_config_set_discovery_ports(
    config: *mut HddsParticipantConfig,
    spdp_multicast: u16,
    sedp_unicast: u16,
    user_unicast: u16,
) -> HddsError {
    if config.is_null() {
        return HddsError::HddsInvalidArgument;
    }
    let inner = &mut *config.cast::<ParticipantConfigInner>();
    inner.discovery_ports = Some((spdp_multicast, sedp_unicast, user_unicast));
    HddsError::HddsOk
}

/// Add a static UDP peer for unicast discovery (e.g. embedded devices).
///
/// Can be called multiple times.
///
/// # Safety
/// - `config` must be a valid pointer from `hdds_config_create`.
/// - `addr` must be a valid null-terminated C string in "host:port" format.
#[no_mangle]
pub unsafe extern "C" fn hdds_config_add_static_peer(
    config: *mut HddsParticipantConfig,
    addr: *const c_char,
) -> HddsError {
    if config.is_null() || addr.is_null() {
        return HddsError::HddsInvalidArgument;
    }
    let Ok(addr_str) = CStr::from_ptr(addr).to_str() else {
        return HddsError::HddsInvalidArgument;
    };
    let Ok(socket_addr) = addr_str.parse::<SocketAddr>() else {
        return HddsError::HddsInvalidArgument;
    };
    let inner = &mut *config.cast::<ParticipantConfigInner>();
    inner.static_peers.push(socket_addr);
    HddsError::HddsOk
}

/// Set the unicast IP TTL (hop limit) for UDP sockets.
///
/// Valid values are 1-255. Setting either TTL explicitly makes the other TTL
/// use its historical default until explicitly changed (multicast 1, unicast 64).
///
/// # Safety
/// - `config` must be a valid pointer from `hdds_config_create`.
#[no_mangle]
pub unsafe extern "C" fn hdds_config_set_unicast_ttl(
    config: *mut HddsParticipantConfig,
    ttl: u8,
) -> HddsError {
    if config.is_null() || ttl == 0 {
        return HddsError::HddsInvalidArgument;
    }
    let inner = &mut *config.cast::<ParticipantConfigInner>();
    inner
        .transport_options
        .ttl
        .get_or_insert_with(TtlConfig::default)
        .unicast = ttl;
    HddsError::HddsOk
}

/// Set the multicast IP TTL (hop limit) for UDP sockets.
///
/// Valid values are 1-255. Setting either TTL explicitly makes the other TTL
/// use its historical default until explicitly changed (multicast 1, unicast 64).
///
/// # Safety
/// - `config` must be a valid pointer from `hdds_config_create`.
#[no_mangle]
pub unsafe extern "C" fn hdds_config_set_multicast_ttl(
    config: *mut HddsParticipantConfig,
    ttl: u8,
) -> HddsError {
    if config.is_null() || ttl == 0 {
        return HddsError::HddsInvalidArgument;
    }
    let inner = &mut *config.cast::<ParticipantConfigInner>();
    inner
        .transport_options
        .ttl
        .get_or_insert_with(TtlConfig::default)
        .multicast = ttl;
    HddsError::HddsOk
}

/// Request a receive buffer size for participant-owned UDP sockets.
///
/// Overrides `HDDS_RCVBUF_BYTES`. The kernel may cap the requested value;
/// HDDS logs the effective size when the participant opens its sockets.
///
/// # Safety
/// - `config` must be a valid pointer from `hdds_config_create`.
#[no_mangle]
pub unsafe extern "C" fn hdds_config_set_socket_receive_buffer_size(
    config: *mut HddsParticipantConfig,
    bytes: u32,
) -> HddsError {
    let Some(bytes) = usize::try_from(bytes).ok().and_then(NonZeroUsize::new) else {
        return HddsError::HddsInvalidArgument;
    };
    if config.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    let inner = &mut *config.cast::<ParticipantConfigInner>();
    inner.socket_receive_buffer_size = Some(bytes);
    HddsError::HddsOk
}

/// Request a send buffer size for participant-owned UDP sockets.
///
/// Overrides `HDDS_SNDBUF_BYTES`. The kernel may cap the requested value;
/// HDDS logs the effective size when the participant opens its sockets.
///
/// # Safety
/// - `config` must be a valid pointer from `hdds_config_create`.
#[no_mangle]
pub unsafe extern "C" fn hdds_config_set_socket_send_buffer_size(
    config: *mut HddsParticipantConfig,
    bytes: u32,
) -> HddsError {
    let Some(bytes) = usize::try_from(bytes).ok().and_then(NonZeroUsize::new) else {
        return HddsError::HddsInvalidArgument;
    };
    if config.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    let inner = &mut *config.cast::<ParticipantConfigInner>();
    inner.socket_send_buffer_size = Some(bytes);
    HddsError::HddsOk
}

/// Set the participant lease advertised in every SPDP announcement.
///
/// The value must be positive and greater than the configured SPDP
/// announcement period. Cross-field validation occurs in `hdds_config_build`.
///
/// # Safety
/// - `config` must be a valid pointer from `hdds_config_create`.
#[no_mangle]
pub unsafe extern "C" fn hdds_config_set_participant_lease_duration_ms(
    config: *mut HddsParticipantConfig,
    milliseconds: u64,
) -> HddsError {
    if config.is_null() || milliseconds == 0 {
        return HddsError::HddsInvalidArgument;
    }

    let inner = &mut *config.cast::<ParticipantConfigInner>();
    inner.participant_lease_duration = Some(Duration::from_millis(milliseconds));
    HddsError::HddsOk
}

/// Set the steady-state SPDP announcement period.
///
/// The five-second startup burst remains enabled. The value must be positive
/// and shorter than the participant lease. Cross-field validation occurs in
/// `hdds_config_build`.
///
/// # Safety
/// - `config` must be a valid pointer from `hdds_config_create`.
#[no_mangle]
pub unsafe extern "C" fn hdds_config_set_spdp_announcement_period_ms(
    config: *mut HddsParticipantConfig,
    milliseconds: u64,
) -> HddsError {
    if config.is_null() || milliseconds == 0 {
        return HddsError::HddsInvalidArgument;
    }

    let inner = &mut *config.cast::<ParticipantConfigInner>();
    inner.spdp_announcement_period = Some(Duration::from_millis(milliseconds));
    HddsError::HddsOk
}

/// Set participant-level DSCP markings for discovery, user data, and metatraffic.
///
/// Each field must be one of the named `HDDS_DSCP_*` values. The configuration
/// is applied when `hdds_config_build` opens the UDP sockets. Discovery and
/// metatraffic currently share one multicast socket, so `METATRAFFIC` is the
/// effective value for multicast SPDP/SEDP; unicast metatraffic and user data
/// are marked independently.
///
/// # Safety
/// - `config` must be a valid pointer from `hdds_config_create`.
/// - `dscp` must point to a valid `HddsDscpConfig`.
#[no_mangle]
pub unsafe extern "C" fn hdds_config_set_dscp(
    config: *mut HddsParticipantConfig,
    dscp: *const HddsDscpConfig,
) -> HddsError {
    if config.is_null() || dscp.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    let dscp = *dscp;
    let Some(discovery) = DscpClass::from_raw(dscp.discovery) else {
        return HddsError::HddsInvalidArgument;
    };
    let Some(user_data) = DscpClass::from_raw(dscp.user_data) else {
        return HddsError::HddsInvalidArgument;
    };
    let Some(metatraffic) = DscpClass::from_raw(dscp.metatraffic) else {
        return HddsError::HddsInvalidArgument;
    };

    let inner = &mut *config.cast::<ParticipantConfigInner>();
    inner.transport_options.dscp = Some(DscpConfig {
        discovery,
        user_data,
        metatraffic,
    });
    HddsError::HddsOk
}

/// Add an interface name to the UDP transport allowlist.
///
/// Can be called multiple times. Once the first interface is added, only the
/// named interfaces are eligible for multicast joins and locator advertising.
///
/// # Safety
/// - `config` must be a valid pointer from `hdds_config_create`.
/// - `interface_name` must be a valid, non-empty null-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn hdds_config_add_allowed_interface(
    config: *mut HddsParticipantConfig,
    interface_name: *const c_char,
) -> HddsError {
    if config.is_null() || interface_name.is_null() {
        return HddsError::HddsInvalidArgument;
    }
    let Ok(interface_name) = CStr::from_ptr(interface_name).to_str() else {
        return HddsError::HddsInvalidArgument;
    };
    let interface_name = interface_name.trim();
    if interface_name.is_empty() {
        return HddsError::HddsInvalidArgument;
    }

    let inner = &mut *config.cast::<ParticipantConfigInner>();
    inner
        .transport_options
        .interface_allowlist
        .get_or_insert_with(InterfaceFilter::allow_all)
        .allow
        .push(InterfaceMatcher::Name(interface_name.to_string()));
    HddsError::HddsOk
}

/// Enable or disable UDP multicast emission and locator advertising.
///
/// Disabling multicast keeps reception active for mixed deployments
/// (`HDDS_MULTICAST_RECEIVE_ONLY`): the participant still joins the group
/// and listens, never emits multicast, advertises no multicast locators, and
/// announces itself over unicast to its static peers and to every
/// participant it discovers. Use `hdds_config_set_multicast_mode` with
/// `HDDS_MULTICAST_DISABLED` for links where multicast does not exist at all.
///
/// # Safety
/// - `config` must be a valid pointer from `hdds_config_create`.
#[no_mangle]
pub unsafe extern "C" fn hdds_config_set_multicast_enabled(
    config: *mut HddsParticipantConfig,
    enabled: bool,
) -> HddsError {
    if config.is_null() {
        return HddsError::HddsInvalidArgument;
    }
    let inner = &mut *config.cast::<ParticipantConfigInner>();
    inner.transport_options.multicast = if enabled {
        MulticastMode::Enabled
    } else {
        MulticastMode::ReceiveOnly
    };
    HddsError::HddsOk
}

/// Multicast usage policy of the participant's UDP transport.
///
/// | mode | multicast TX | group join + listeners | multicast locators advertised |
/// |---|---|---|---|
/// | `HDDS_MULTICAST_ENABLED` | yes | yes | yes |
/// | `HDDS_MULTICAST_RECEIVE_ONLY` | no | yes | no |
/// | `HDDS_MULTICAST_DISABLED` | no | no | no |
///
/// In the last two modes static peers and every discovered participant
/// receive periodic unicast SPDP for the duration of their lease.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code, clippy::enum_variant_names)] // constructed by C callers; C naming convention
pub enum HddsMulticastMode {
    /// Full multicast (default).
    HddsMulticastEnabled = 0,
    /// Listen to multicast, never emit it (asymmetric / tactical links).
    HddsMulticastReceiveOnly = 1,
    /// No multicast at all (containers, WAN, Discovery Server deployments).
    HddsMulticastDisabled = 2,
}

/// Set the multicast usage policy (see `HddsMulticastMode`).
///
/// # Safety
/// - `config` must be a valid pointer from `hdds_config_create`.
#[no_mangle]
pub unsafe extern "C" fn hdds_config_set_multicast_mode(
    config: *mut HddsParticipantConfig,
    mode: HddsMulticastMode,
) -> HddsError {
    if config.is_null() {
        return HddsError::HddsInvalidArgument;
    }
    let inner = &mut *config.cast::<ParticipantConfigInner>();
    inner.transport_options.multicast = match mode {
        HddsMulticastMode::HddsMulticastEnabled => MulticastMode::Enabled,
        HddsMulticastMode::HddsMulticastReceiveOnly => MulticastMode::ReceiveOnly,
        HddsMulticastMode::HddsMulticastDisabled => MulticastMode::Disabled,
    };
    HddsError::HddsOk
}

// =============================================================================
// SHM Configuration
// =============================================================================

/// Set shared memory policy.
///
/// # Safety
/// - `config` must be a valid pointer from `hdds_config_create`.
#[no_mangle]
pub unsafe extern "C" fn hdds_config_set_shm_policy(
    config: *mut HddsParticipantConfig,
    policy: HddsShmPolicy,
) -> HddsError {
    if config.is_null() {
        return HddsError::HddsInvalidArgument;
    }
    let inner = &mut *config.cast::<ParticipantConfigInner>();
    inner.shm_policy = match policy {
        HddsShmPolicy::HddsShmPrefer => ShmPolicy::Prefer,
        HddsShmPolicy::HddsShmRequire => ShmPolicy::Require,
        HddsShmPolicy::HddsShmDisable => ShmPolicy::Disable,
    };
    HddsError::HddsOk
}

// =============================================================================
// TCP Configuration
// =============================================================================

/// Ensure tcp_config exists, creating default if needed.
fn ensure_tcp(inner: &mut ParticipantConfigInner) -> &mut TcpConfig {
    if inner.tcp_config.is_none() {
        inner.tcp_config = Some(TcpConfig::enabled());
    }
    inner.tcp_config.as_mut().unwrap()
}

/// Enable TCP transport with a listen port.
///
/// This enables hybrid mode (UDP discovery + TCP data) by default.
///
/// # Safety
/// - `config` must be a valid pointer from `hdds_config_create`.
#[no_mangle]
pub unsafe extern "C" fn hdds_config_enable_tcp(
    config: *mut HddsParticipantConfig,
    listen_port: u16,
) -> HddsError {
    if config.is_null() {
        return HddsError::HddsInvalidArgument;
    }
    let inner = &mut *config.cast::<ParticipantConfigInner>();
    let tcp = ensure_tcp(inner);
    tcp.listen_port = listen_port;
    tcp.enabled = true;
    inner.transport_preference = TransportPreference::UdpDiscoveryTcpData;
    HddsError::HddsOk
}

/// Set TCP role (Auto, ServerOnly, ClientOnly).
///
/// # Safety
/// - `config` must be a valid pointer from `hdds_config_create`.
#[no_mangle]
pub unsafe extern "C" fn hdds_config_set_tcp_role(
    config: *mut HddsParticipantConfig,
    role: HddsTcpRole,
) -> HddsError {
    if config.is_null() {
        return HddsError::HddsInvalidArgument;
    }
    let inner = &mut *config.cast::<ParticipantConfigInner>();
    let tcp = ensure_tcp(inner);
    tcp.role = match role {
        HddsTcpRole::HddsTcpRoleAuto => TcpRole::Auto,
        HddsTcpRole::HddsTcpRoleServerOnly => TcpRole::ServerOnly,
        HddsTcpRole::HddsTcpRoleClientOnly => TcpRole::ClientOnly,
    };
    HddsError::HddsOk
}

/// Add a TCP initial peer address (for TCP-only or client mode).
///
/// Can be called multiple times to add multiple peers.
///
/// # Safety
/// - `config` must be a valid pointer from `hdds_config_create`.
/// - `addr` must be a valid null-terminated C string in "host:port" format.
#[no_mangle]
pub unsafe extern "C" fn hdds_config_add_tcp_peer(
    config: *mut HddsParticipantConfig,
    addr: *const c_char,
) -> HddsError {
    if config.is_null() || addr.is_null() {
        return HddsError::HddsInvalidArgument;
    }
    let Ok(addr_str) = CStr::from_ptr(addr).to_str() else {
        return HddsError::HddsInvalidArgument;
    };
    let Ok(socket_addr) = addr_str.parse::<SocketAddr>() else {
        return HddsError::HddsInvalidArgument;
    };
    let inner = &mut *config.cast::<ParticipantConfigInner>();
    let tcp = ensure_tcp(inner);
    tcp.initial_peers.push(socket_addr);
    HddsError::HddsOk
}

/// Set TCP nodelay option (disable Nagle's algorithm).
///
/// # Safety
/// - `config` must be a valid pointer from `hdds_config_create`.
#[no_mangle]
pub unsafe extern "C" fn hdds_config_set_tcp_nodelay(
    config: *mut HddsParticipantConfig,
    nodelay: bool,
) -> HddsError {
    if config.is_null() {
        return HddsError::HddsInvalidArgument;
    }
    let inner = &mut *config.cast::<ParticipantConfigInner>();
    let tcp = ensure_tcp(inner);
    tcp.nodelay = nodelay;
    HddsError::HddsOk
}

// =============================================================================
// TLS Configuration
// =============================================================================

/// Enable TLS on TCP transport.
///
/// Call this before or after the material setters, but always call it: TLS
/// material set on a configuration that never enables TLS makes
/// `hdds_config_build` fail rather than run TCP in cleartext.
///
/// The certificate, private key and CA files are set with
/// `hdds_config_set_tls_certificate_file`, `hdds_config_set_tls_private_key_file`
/// and `hdds_config_set_tls_ca_file`; `hdds_config_build` materialises them
/// according to the TCP role (Auto: both accept and dial, ServerOnly, ClientOnly)
/// and fails (returns NULL) when the material is incomplete or the library was
/// built without the `tcp-tls` feature. TLS never falls back to plaintext.
///
/// # Safety
/// - `config` must be a valid pointer from `hdds_config_create`.
#[no_mangle]
pub unsafe extern "C" fn hdds_config_enable_tls(config: *mut HddsParticipantConfig) -> HddsError {
    if config.is_null() {
        return HddsError::HddsInvalidArgument;
    }
    let inner = &mut *config.cast::<ParticipantConfigInner>();
    let tcp = ensure_tcp(inner);
    tcp.tls_enabled = true;
    HddsError::HddsOk
}

/// Convert a C path argument; NULL, non-UTF-8 and empty paths are rejected.
unsafe fn path_arg(path: *const c_char) -> Option<PathBuf> {
    if path.is_null() {
        return None;
    }
    CStr::from_ptr(path)
        .to_str()
        .ok()
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
}

/// Set the TLS certificate chain file (PEM).
///
/// Presented as the server certificate when accepting connections and as the
/// client certificate when dialing a peer that requires client certificates.
/// HDDS-to-HDDS peers dial by IP address, so the certificate needs an IP
/// subject alternative name. On the Auto role (the default) the same
/// certificate serves both directions, so it must carry both the serverAuth
/// and the clientAuth extended key usage; a serverAuth-only certificate fails
/// the dial side of a mutual-TLS handshake.
///
/// # Safety
/// - `config` must be a valid pointer from `hdds_config_create`.
/// - `path` must be a valid NUL-terminated UTF-8 string.
#[no_mangle]
pub unsafe extern "C" fn hdds_config_set_tls_certificate_file(
    config: *mut HddsParticipantConfig,
    path: *const c_char,
) -> HddsError {
    if config.is_null() {
        return HddsError::HddsInvalidArgument;
    }
    let Some(path) = path_arg(path) else {
        return HddsError::HddsInvalidArgument;
    };
    let inner = &mut *config.cast::<ParticipantConfigInner>();
    inner.tls_cert_file = Some(path);
    HddsError::HddsOk
}

/// Set the TLS private key file (PEM, PKCS#8 / SEC1 / PKCS#1).
///
/// # Safety
/// - `config` must be a valid pointer from `hdds_config_create`.
/// - `path` must be a valid NUL-terminated UTF-8 string.
#[no_mangle]
pub unsafe extern "C" fn hdds_config_set_tls_private_key_file(
    config: *mut HddsParticipantConfig,
    path: *const c_char,
) -> HddsError {
    if config.is_null() {
        return HddsError::HddsInvalidArgument;
    }
    let Some(path) = path_arg(path) else {
        return HddsError::HddsInvalidArgument;
    };
    let inner = &mut *config.cast::<ParticipantConfigInner>();
    inner.tls_key_file = Some(path);
    HddsError::HddsOk
}

/// Set the TLS trust anchor file (PEM, one or more CA certificates).
///
/// Used to verify the peer's server certificate when dialing, and as the client
/// CA when `hdds_config_set_tls_require_client_cert` is set. Required for every
/// role that dials (Auto, ClientOnly).
///
/// # Safety
/// - `config` must be a valid pointer from `hdds_config_create`.
/// - `path` must be a valid NUL-terminated UTF-8 string.
#[no_mangle]
pub unsafe extern "C" fn hdds_config_set_tls_ca_file(
    config: *mut HddsParticipantConfig,
    path: *const c_char,
) -> HddsError {
    if config.is_null() {
        return HddsError::HddsInvalidArgument;
    }
    let Some(path) = path_arg(path) else {
        return HddsError::HddsInvalidArgument;
    };
    let inner = &mut *config.cast::<ParticipantConfigInner>();
    inner.tls_ca_file = Some(path);
    HddsError::HddsOk
}

/// Set a certificate revocation list file (PEM) for client-certificate checks.
///
/// Requires `hdds_config_set_tls_require_client_cert(config, true)`. Revocation
/// is fail closed: unknown status and a CRL past its nextUpdate refuse the
/// client. OCSP is not supported.
///
/// # Safety
/// - `config` must be a valid pointer from `hdds_config_create`.
/// - `path` must be a valid NUL-terminated UTF-8 string.
#[no_mangle]
pub unsafe extern "C" fn hdds_config_set_tls_crl_file(
    config: *mut HddsParticipantConfig,
    path: *const c_char,
) -> HddsError {
    if config.is_null() {
        return HddsError::HddsInvalidArgument;
    }
    let Some(path) = path_arg(path) else {
        return HddsError::HddsInvalidArgument;
    };
    let inner = &mut *config.cast::<ParticipantConfigInner>();
    inner.tls_crl_file = Some(path);
    HddsError::HddsOk
}

/// Require and verify client certificates on accepted TLS connections (mutual TLS).
///
/// Clients without a certificate, or with a certificate not issued by the CA set
/// with `hdds_config_set_tls_ca_file`, are refused during the handshake.
///
/// # Safety
/// - `config` must be a valid pointer from `hdds_config_create`.
#[no_mangle]
pub unsafe extern "C" fn hdds_config_set_tls_require_client_cert(
    config: *mut HddsParticipantConfig,
    required: bool,
) -> HddsError {
    if config.is_null() {
        return HddsError::HddsInvalidArgument;
    }
    let inner = &mut *config.cast::<ParticipantConfigInner>();
    inner.tls_require_client_cert = required;
    HddsError::HddsOk
}

// =============================================================================
// TLS materialisation (paths -> TlsConfig at build time)
// =============================================================================

/// What `hdds_config_build` materialises for TLS, resolved before any file is read.
#[derive(Debug, Clone, PartialEq, Eq)]
struct TlsPlan {
    role: TcpRole,
    cert: PathBuf,
    key: PathBuf,
    ca: Option<PathBuf>,
    crl: Option<PathBuf>,
    require_client_cert: bool,
}

/// Whether the caller set any TLS material at all.
fn tls_material_present(inner: &ParticipantConfigInner) -> bool {
    inner.tls_cert_file.is_some()
        || inner.tls_key_file.is_some()
        || inner.tls_ca_file.is_some()
        || inner.tls_crl_file.is_some()
        || inner.tls_require_client_cert
}

/// Resolve the TLS plan, or `Ok(None)` when TLS is not enabled.
///
/// Fail closed on ordering mistakes: a caller who sets certificate, key, CA,
/// CRL or `require_client_cert` but never calls `hdds_config_enable_tls`
/// would otherwise get a participant running TCP in cleartext with no error.
fn tls_plan(inner: &ParticipantConfigInner) -> Result<Option<TlsPlan>, String> {
    let tls_enabled = inner.tcp_config.as_ref().is_some_and(|tcp| tcp.tls_enabled);
    if !tls_enabled && tls_material_present(inner) {
        return Err(
            "TLS material set but TLS is not enabled (hdds_config_enable_tcp + hdds_config_enable_tls): refusing to run TCP in cleartext"
                .to_string(),
        );
    }
    let Some(tcp) = &inner.tcp_config else {
        return Ok(None);
    };
    if !tcp.tls_enabled {
        return Ok(None);
    }
    let cert = inner.tls_cert_file.clone().ok_or_else(|| {
        "TLS enabled but no certificate file (hdds_config_set_tls_certificate_file)".to_string()
    })?;
    let key = inner.tls_key_file.clone().ok_or_else(|| {
        "TLS enabled but no private key file (hdds_config_set_tls_private_key_file)".to_string()
    })?;
    let role = tcp.role;
    if inner.tls_require_client_cert && inner.tls_ca_file.is_none() {
        return Err(
            "require_client_cert set but no CA file (hdds_config_set_tls_ca_file)".to_string(),
        );
    }
    if role.can_connect() && inner.tls_ca_file.is_none() {
        return Err(format!(
            "TLS role {:?} dials peers and needs a CA file to verify them (hdds_config_set_tls_ca_file)",
            role
        ));
    }
    if inner.tls_crl_file.is_some() && !inner.tls_require_client_cert {
        return Err(
            "CRL file set but require_client_cert not set (hdds_config_set_tls_require_client_cert)"
                .to_string(),
        );
    }
    Ok(Some(TlsPlan {
        role,
        cert,
        key,
        ca: inner.tls_ca_file.clone(),
        crl: inner.tls_crl_file.clone(),
        require_client_cert: inner.tls_require_client_cert,
    }))
}

/// Build the `TlsConfig` for the plan: server half for accepting roles, client
/// half for dialing roles, `TlsConfig::peer` for Auto.
#[cfg(feature = "tcp-tls")]
fn materialise_tls(plan: &TlsPlan) -> Result<hdds::transport::tcp::TlsConfig, String> {
    use hdds::transport::tcp::TlsConfig;

    fn io(what: &'static str) -> impl Fn(std::io::Error) -> String {
        move |e| format!("TLS {what}: {e}")
    }

    let server = || -> Result<TlsConfig, String> {
        let mut builder = TlsConfig::server()
            .with_cert_file(&plan.cert)
            .map_err(io("certificate file"))?
            .with_key_file(&plan.key)
            .map_err(io("private key file"))?;
        if plan.require_client_cert {
            let ca = plan
                .ca
                .as_ref()
                .ok_or_else(|| "require_client_cert set but no CA file".to_string())?;
            builder = builder
                .require_client_cert()
                .with_root_certs_file(ca)
                .map_err(io("CA file"))?;
            if let Some(crl) = &plan.crl {
                builder = builder.with_crl_file(crl).map_err(io("CRL file"))?;
            }
        }
        builder.build().map_err(io("server config"))
    };

    let client = || -> Result<TlsConfig, String> {
        let ca = plan
            .ca
            .as_ref()
            .ok_or_else(|| "dialing role needs a CA file".to_string())?;
        TlsConfig::client()
            .with_root_certs_file(ca)
            .map_err(io("CA file"))?
            .with_cert_file(&plan.cert)
            .map_err(io("certificate file"))?
            .with_key_file(&plan.key)
            .map_err(io("private key file"))?
            .build()
            .map_err(io("client config"))
    };

    match plan.role {
        TcpRole::Auto => TlsConfig::peer(server()?, client()?).map_err(|e| e.to_string()),
        TcpRole::ServerOnly => server(),
        TcpRole::ClientOnly => client(),
    }
}

/// Without the `tcp-tls` feature TLS cannot be provided: refuse, never downgrade.
#[cfg(not(feature = "tcp-tls"))]
fn materialise_tls(_plan: &TlsPlan) -> Result<hdds::transport::tcp::TlsConfig, String> {
    Err(
        "hdds-c was built without the tcp-tls feature; TLS refused (no plaintext fallback)"
            .to_string(),
    )
}

// =============================================================================
// Transport Preference
// =============================================================================

/// Set transport preference (UDP-only, TCP-only, hybrid, SHM+TCP, etc.).
///
/// # Safety
/// - `config` must be a valid pointer from `hdds_config_create`.
#[no_mangle]
pub unsafe extern "C" fn hdds_config_set_transport_preference(
    config: *mut HddsParticipantConfig,
    pref: HddsTransportPreference,
) -> HddsError {
    if config.is_null() {
        return HddsError::HddsInvalidArgument;
    }
    let inner = &mut *config.cast::<ParticipantConfigInner>();
    inner.transport_preference = match pref {
        HddsTransportPreference::HddsTransportPrefUdpOnly => TransportPreference::UdpOnly,
        HddsTransportPreference::HddsTransportPrefTcpOnly => TransportPreference::TcpOnly,
        HddsTransportPreference::HddsTransportPrefUdpDiscoveryTcpData => {
            TransportPreference::UdpDiscoveryTcpData
        }
        HddsTransportPreference::HddsTransportPrefShmPreferred => TransportPreference::ShmPreferred,
        HddsTransportPreference::HddsTransportPrefShmLocalTcpRemote => {
            TransportPreference::ShmLocalTcpRemote
        }
    };
    HddsError::HddsOk
}

// =============================================================================
// Security Configuration
// =============================================================================

/// Attach a security configuration to this participant config.
///
/// **This consumes the security config handle.** Do NOT call
/// `hdds_security_config_destroy` after this.
///
/// Requires the `security` feature to be enabled at compile time.
///
/// # Safety
/// - `config` must be a valid pointer from `hdds_config_create`.
/// - `security` must be a valid pointer from `hdds_security_config_create`.
#[cfg(feature = "security")]
#[no_mangle]
pub unsafe extern "C" fn hdds_config_set_security(
    config: *mut HddsParticipantConfig,
    security: *mut crate::security_config::HddsSecurityConfig,
) -> HddsError {
    if config.is_null() || security.is_null() {
        return HddsError::HddsInvalidArgument;
    }
    let sec_inner = *Box::from_raw(security.cast::<crate::security_config::SecurityConfigInner>());
    let inner = &mut *config.cast::<ParticipantConfigInner>();
    inner.security_config = Some(sec_inner);
    HddsError::HddsOk
}

// =============================================================================
// Build
// =============================================================================

/// Build a Participant from the configuration.
///
/// **This consumes the config handle.** Do NOT call `hdds_config_destroy`
/// after this. If build fails, the config is still consumed and NULL is returned.
///
/// # Safety
/// - `config` must be a valid pointer from `hdds_config_create`.
/// - After this call, `config` is invalid (consumed).
#[no_mangle]
pub unsafe extern "C" fn hdds_config_build(
    config: *mut HddsParticipantConfig,
) -> *mut HddsParticipant {
    if config.is_null() {
        return ptr::null_mut();
    }

    // Initialize logger (only once)
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = env_logger::try_init();
    });

    let inner = *Box::from_raw(config.cast::<ParticipantConfigInner>());

    // Resolve TLS material before anything is built (fail closed).
    let tls_plan = match tls_plan(&inner) {
        Ok(plan) => plan,
        Err(e) => {
            log::error!("hdds_config_build: invalid TLS config: {}", e);
            return ptr::null_mut();
        }
    };

    // Translate our config into ParticipantBuilder calls
    let mut builder = Participant::builder(&inner.name)
        .participant_id(inner.participant_id)
        .with_transport(inner.transport_mode)
        .shm_policy(inner.shm_policy)
        .with_transport_preference(inner.transport_preference)
        .with_transport_options(inner.transport_options);
    // Unset means the core applies the domain rule (HDDS_DOMAIN_ID, else 0).
    if let Some(domain_id) = inner.domain_id {
        builder = builder.domain_id(domain_id);
    }

    if let Some(tcp) = inner.tcp_config {
        #[allow(unused_mut)] // reassigned only with the tcp-tls feature
        let mut tcp = tcp;
        if let Some(plan) = &tls_plan {
            match materialise_tls(plan) {
                Ok(tls) => {
                    #[cfg(feature = "tcp-tls")]
                    {
                        tcp = tcp.with_tls_config(tls);
                    }
                    #[cfg(not(feature = "tcp-tls"))]
                    {
                        let _ = tls;
                    }
                }
                Err(e) => {
                    log::error!("hdds_config_build: TLS config refused: {}", e);
                    return ptr::null_mut();
                }
            }
        }
        builder = builder.tcp_config(tcp);
        // Re-apply preference since tcp_config() may override it
        builder = builder.with_transport_preference(inner.transport_preference);
    }

    if let Some((spdp, sedp, user)) = inner.discovery_ports {
        builder = builder.with_discovery_ports(spdp, sedp, user);
    }

    if let Some(bytes) = inner.socket_receive_buffer_size {
        builder = builder.with_socket_receive_buffer_size(bytes);
    }
    if let Some(bytes) = inner.socket_send_buffer_size {
        builder = builder.with_socket_send_buffer_size(bytes);
    }
    if let Some(duration) = inner.participant_lease_duration {
        builder = builder.with_participant_lease_duration(duration);
    }
    if let Some(period) = inner.spdp_announcement_period {
        builder = builder.with_spdp_announcement_period(period);
    }

    for peer in &inner.static_peers {
        builder = builder.add_static_peer(&peer.to_string());
    }

    // Apply security configuration if provided
    #[cfg(feature = "security")]
    if let Some(sec) = inner.security_config {
        let sec_builder = hdds::SecurityConfig::builder();
        let mut sec_builder = sec_builder;
        if let Some(p) = sec.identity_certificate {
            sec_builder = sec_builder.identity_certificate(p);
        }
        if let Some(p) = sec.private_key {
            sec_builder = sec_builder.private_key(p);
        }
        if let Some(p) = sec.ca_certificates {
            sec_builder = sec_builder.ca_certificates(p);
        }
        if let Some(p) = sec.governance_xml {
            sec_builder = sec_builder.governance_xml(p);
        }
        if let Some(p) = sec.permissions_xml {
            sec_builder = sec_builder.permissions_xml(p);
        }
        if let Some(p) = sec.permissions_ca {
            sec_builder = sec_builder.permissions_ca(p);
        }
        sec_builder = sec_builder.enable_encryption(sec.enable_encryption);
        sec_builder = sec_builder.enable_audit_log(sec.enable_audit_log);
        if let Some(p) = sec.audit_log_path {
            sec_builder = sec_builder.audit_log_path(p);
        }
        sec_builder = sec_builder.require_authentication(sec.require_authentication);
        sec_builder = sec_builder.check_certificate_revocation(sec.check_certificate_revocation);
        if let Some(p) = sec.certificate_revocation_list {
            sec_builder = sec_builder.certificate_revocation_list(p);
        }
        if let Some(p) = sec.permissions_overlay {
            sec_builder = sec_builder.permissions_overlay(p);
        }
        if sec.permissions_overlay_poll_ms > 0 {
            sec_builder = sec_builder.permissions_overlay_poll(std::time::Duration::from_millis(
                sec.permissions_overlay_poll_ms,
            ));
        }

        match sec_builder.build() {
            Ok(security_config) => {
                builder = builder.with_security(security_config);
            }
            Err(e) => {
                log::error!("hdds_config_build: invalid security config: {:?}", e);
                return ptr::null_mut();
            }
        }
    }

    match builder.build() {
        Ok(participant) => Box::into_raw(Box::new(participant)).cast::<HddsParticipant>(),
        Err(e) => {
            log::error!("hdds_config_build: failed to create participant: {:?}", e);
            ptr::null_mut()
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    #[test]
    fn test_config_create_and_destroy() {
        unsafe {
            let name = CString::new("test_app").unwrap();
            let config = hdds_config_create(name.as_ptr());
            assert!(!config.is_null());
            hdds_config_destroy(config);
        }
    }

    #[test]
    fn test_config_null_safety() {
        unsafe {
            assert!(hdds_config_create(ptr::null()).is_null());
            hdds_config_destroy(ptr::null_mut()); // should not crash

            assert_eq!(
                hdds_config_set_domain_id(ptr::null_mut(), 0),
                HddsError::HddsInvalidArgument,
            );
            assert_eq!(
                hdds_config_set_participant_id(ptr::null_mut(), 0),
                HddsError::HddsInvalidArgument,
            );
            assert_eq!(
                hdds_config_enable_tcp(ptr::null_mut(), 7410),
                HddsError::HddsInvalidArgument,
            );
            assert_eq!(
                hdds_config_set_shm_policy(ptr::null_mut(), HddsShmPolicy::HddsShmPrefer),
                HddsError::HddsInvalidArgument,
            );
            assert_eq!(
                hdds_config_set_unicast_ttl(ptr::null_mut(), 64),
                HddsError::HddsInvalidArgument,
            );
            assert_eq!(
                hdds_config_set_multicast_ttl(ptr::null_mut(), 1),
                HddsError::HddsInvalidArgument,
            );
            assert_eq!(
                hdds_config_set_dscp(ptr::null_mut(), ptr::null()),
                HddsError::HddsInvalidArgument,
            );
            assert_eq!(
                hdds_config_add_allowed_interface(ptr::null_mut(), ptr::null()),
                HddsError::HddsInvalidArgument,
            );
            assert_eq!(
                hdds_config_set_multicast_enabled(ptr::null_mut(), false),
                HddsError::HddsInvalidArgument,
            );
            assert!(hdds_config_build(ptr::null_mut()).is_null());
        }
    }

    #[test]
    fn test_config_setters() {
        unsafe {
            let name = CString::new("test_setters").unwrap();
            let config = hdds_config_create(name.as_ptr());
            assert!(!config.is_null());

            // All setters should return HddsOk
            assert_eq!(hdds_config_set_domain_id(config, 42), HddsError::HddsOk);
            assert_eq!(hdds_config_set_participant_id(config, 5), HddsError::HddsOk);
            assert_eq!(
                hdds_config_set_shm_policy(config, HddsShmPolicy::HddsShmDisable),
                HddsError::HddsOk,
            );
            assert_eq!(hdds_config_enable_tcp(config, 7410), HddsError::HddsOk);
            assert_eq!(
                hdds_config_set_tcp_role(config, HddsTcpRole::HddsTcpRoleServerOnly),
                HddsError::HddsOk,
            );
            assert_eq!(hdds_config_set_tcp_nodelay(config, true), HddsError::HddsOk);
            assert_eq!(hdds_config_enable_tls(config), HddsError::HddsOk);
            assert_eq!(
                hdds_config_set_transport_preference(
                    config,
                    HddsTransportPreference::HddsTransportPrefTcpOnly,
                ),
                HddsError::HddsOk,
            );
            assert_eq!(
                hdds_config_set_discovery_ports(config, 9400, 9410, 9411),
                HddsError::HddsOk,
            );
            assert_eq!(hdds_config_set_unicast_ttl(config, 32), HddsError::HddsOk);
            assert_eq!(hdds_config_set_multicast_ttl(config, 4), HddsError::HddsOk);
            let dscp = HddsDscpConfig {
                discovery: HddsDscpClass::HddsDscpAf21 as u8,
                user_data: HddsDscpClass::HddsDscpAf41 as u8,
                metatraffic: HddsDscpClass::HddsDscpAf31 as u8,
            };
            assert_eq!(hdds_config_set_dscp(config, &dscp), HddsError::HddsOk);
            let interface = CString::new("eth0").unwrap();
            assert_eq!(
                hdds_config_add_allowed_interface(config, interface.as_ptr()),
                HddsError::HddsOk,
            );
            assert_eq!(
                hdds_config_set_multicast_enabled(config, false),
                HddsError::HddsOk,
            );

            let peer = CString::new("127.0.0.1:7412").unwrap();
            assert_eq!(
                hdds_config_add_tcp_peer(config, peer.as_ptr()),
                HddsError::HddsOk
            );

            let static_peer = CString::new("192.168.1.100:7411").unwrap();
            assert_eq!(
                hdds_config_add_static_peer(config, static_peer.as_ptr()),
                HddsError::HddsOk,
            );

            // Verify internal state
            let inner = &*config.cast::<ParticipantConfigInner>();
            assert_eq!(inner.domain_id, Some(42));
            assert_eq!(inner.participant_id, Some(5));
            assert_eq!(inner.shm_policy, ShmPolicy::Disable);
            assert_eq!(inner.transport_preference, TransportPreference::TcpOnly);
            assert!(inner.tcp_config.is_some());
            let tcp = inner.tcp_config.as_ref().unwrap();
            assert_eq!(tcp.listen_port, 7410);
            assert!(tcp.nodelay);
            assert!(tcp.tls_enabled);
            assert_eq!(tcp.initial_peers.len(), 1);
            assert_eq!(inner.discovery_ports, Some((9400, 9410, 9411)));
            assert_eq!(inner.static_peers.len(), 1);
            assert_eq!(inner.transport_options.ttl, Some(TtlConfig::custom(4, 32)));
            let dscp = inner
                .transport_options
                .dscp
                .expect("explicit DSCP configuration");
            assert_eq!(dscp.discovery, DscpClass::Af21);
            assert_eq!(dscp.user_data, DscpClass::Af41);
            assert_eq!(dscp.metatraffic, DscpClass::Af31);
            let interface_filter = inner
                .transport_options
                .interface_allowlist
                .as_ref()
                .expect("explicit interface allowlist");
            assert!(interface_filter.allows_name("eth0"));
            assert!(!interface_filter.allows_name("wlan0"));
            // set_multicast_enabled(false) = the documented "reception stays
            // active" contract = ReceiveOnly, not Disabled.
            assert_eq!(
                inner.transport_options.multicast,
                MulticastMode::ReceiveOnly
            );

            hdds_config_destroy(config);
        }
    }

    #[test]
    fn multicast_mode_setter_covers_the_three_states() {
        unsafe {
            let config = hdds_config_create(c"mode-test".as_ptr());
            assert!(!config.is_null());
            for (mode, expected) in [
                (
                    HddsMulticastMode::HddsMulticastDisabled,
                    MulticastMode::Disabled,
                ),
                (
                    HddsMulticastMode::HddsMulticastReceiveOnly,
                    MulticastMode::ReceiveOnly,
                ),
                (
                    HddsMulticastMode::HddsMulticastEnabled,
                    MulticastMode::Enabled,
                ),
            ] {
                assert_eq!(
                    hdds_config_set_multicast_mode(config, mode),
                    HddsError::HddsOk
                );
                let inner = &*config.cast::<ParticipantConfigInner>();
                assert_eq!(inner.transport_options.multicast, expected);
            }
            assert_eq!(
                hdds_config_set_multicast_mode(
                    std::ptr::null_mut(),
                    HddsMulticastMode::HddsMulticastEnabled
                ),
                HddsError::HddsInvalidArgument
            );
            hdds_config_destroy(config);
        }
    }

    #[test]
    fn test_config_bad_peer_address() {
        unsafe {
            let name = CString::new("test_bad_peer").unwrap();
            let config = hdds_config_create(name.as_ptr());

            let bad_addr = CString::new("not_a_valid_address").unwrap();
            assert_eq!(
                hdds_config_add_tcp_peer(config, bad_addr.as_ptr()),
                HddsError::HddsInvalidArgument,
            );
            assert_eq!(
                hdds_config_add_static_peer(config, bad_addr.as_ptr()),
                HddsError::HddsInvalidArgument,
            );

            hdds_config_destroy(config);
        }
    }

    #[test]
    fn test_transport_option_validation_and_ttl_defaults() {
        unsafe {
            let name = CString::new("test_transport_options").unwrap();
            let config = hdds_config_create(name.as_ptr());

            assert_eq!(
                hdds_config_set_unicast_ttl(config, 0),
                HddsError::HddsInvalidArgument,
            );
            assert_eq!(
                hdds_config_set_multicast_ttl(config, 0),
                HddsError::HddsInvalidArgument,
            );
            assert_eq!(
                hdds_config_set_socket_receive_buffer_size(config, 0),
                HddsError::HddsInvalidArgument,
            );
            assert_eq!(
                hdds_config_set_socket_send_buffer_size(config, 0),
                HddsError::HddsInvalidArgument,
            );
            assert_eq!(
                hdds_config_set_participant_lease_duration_ms(config, 0),
                HddsError::HddsInvalidArgument,
            );
            assert_eq!(
                hdds_config_set_spdp_announcement_period_ms(config, 0),
                HddsError::HddsInvalidArgument,
            );
            assert_eq!(
                hdds_config_add_allowed_interface(config, ptr::null()),
                HddsError::HddsInvalidArgument,
            );
            let empty = CString::new("   ").unwrap();
            assert_eq!(
                hdds_config_add_allowed_interface(config, empty.as_ptr()),
                HddsError::HddsInvalidArgument,
            );

            assert_eq!(hdds_config_set_unicast_ttl(config, 96), HddsError::HddsOk);
            assert_eq!(
                hdds_config_set_socket_receive_buffer_size(config, 131_072),
                HddsError::HddsOk,
            );
            assert_eq!(
                hdds_config_set_socket_send_buffer_size(config, 65_536),
                HddsError::HddsOk,
            );
            assert_eq!(
                hdds_config_set_participant_lease_duration_ms(config, 600_000),
                HddsError::HddsOk,
            );
            assert_eq!(
                hdds_config_set_spdp_announcement_period_ms(config, 60_000),
                HddsError::HddsOk,
            );
            assert_eq!(
                (&*config.cast::<ParticipantConfigInner>())
                    .transport_options
                    .ttl,
                Some(TtlConfig::custom(1, 96)),
            );
            assert_eq!(
                (&*config.cast::<ParticipantConfigInner>())
                    .socket_receive_buffer_size
                    .map(NonZeroUsize::get),
                Some(131_072),
            );
            assert_eq!(
                (&*config.cast::<ParticipantConfigInner>())
                    .socket_send_buffer_size
                    .map(NonZeroUsize::get),
                Some(65_536),
            );
            assert_eq!(
                (&*config.cast::<ParticipantConfigInner>()).participant_lease_duration,
                Some(Duration::from_secs(600)),
            );
            assert_eq!(
                (&*config.cast::<ParticipantConfigInner>()).spdp_announcement_period,
                Some(Duration::from_secs(60)),
            );

            let invalid = HddsDscpConfig {
                discovery: HddsDscpClass::HddsDscpAf21 as u8,
                user_data: 63,
                metatraffic: HddsDscpClass::HddsDscpAf31 as u8,
            };
            assert_eq!(
                hdds_config_set_dscp(config, &invalid),
                HddsError::HddsInvalidArgument,
            );
            assert!((&*config.cast::<ParticipantConfigInner>())
                .transport_options
                .dscp
                .is_none());

            hdds_config_destroy(config);
        }
    }

    #[test]
    fn test_spdp_timing_relation_is_rejected_at_build() {
        unsafe {
            let name = CString::new("test_invalid_spdp_timing").unwrap();
            let config = hdds_config_create(name.as_ptr());
            assert_eq!(
                hdds_config_set_participant_lease_duration_ms(config, 1_000),
                HddsError::HddsOk,
            );
            assert_eq!(
                hdds_config_set_spdp_announcement_period_ms(config, 1_000),
                HddsError::HddsOk,
            );

            assert!(hdds_config_build(config).is_null());
        }
    }

    // -------------------------------------------------------------------
    // TLS setters and materialisation plan
    // -------------------------------------------------------------------

    #[test]
    fn tls_setters_store_paths_and_require_flag() {
        unsafe {
            let name = CString::new("tls_setters").unwrap();
            let config = hdds_config_create(name.as_ptr());
            assert!(!config.is_null());
            assert_eq!(hdds_config_enable_tcp(config, 7420), HddsError::HddsOk);
            assert_eq!(hdds_config_enable_tls(config), HddsError::HddsOk);

            let cert = CString::new("/etc/hdds/certs/participant.crt").unwrap();
            let key = CString::new("/etc/hdds/certs/participant.key").unwrap();
            let ca = CString::new("/etc/hdds/certs/ca.crt").unwrap();
            let crl = CString::new("/etc/hdds/certs/ca.crl").unwrap();
            assert_eq!(
                hdds_config_set_tls_certificate_file(config, cert.as_ptr()),
                HddsError::HddsOk
            );
            assert_eq!(
                hdds_config_set_tls_private_key_file(config, key.as_ptr()),
                HddsError::HddsOk
            );
            assert_eq!(
                hdds_config_set_tls_ca_file(config, ca.as_ptr()),
                HddsError::HddsOk
            );
            assert_eq!(
                hdds_config_set_tls_crl_file(config, crl.as_ptr()),
                HddsError::HddsOk
            );
            assert_eq!(
                hdds_config_set_tls_require_client_cert(config, true),
                HddsError::HddsOk
            );

            let inner = &*config.cast::<ParticipantConfigInner>();
            assert_eq!(
                inner.tls_cert_file.as_deref(),
                Some(std::path::Path::new("/etc/hdds/certs/participant.crt"))
            );
            assert_eq!(
                inner.tls_key_file.as_deref(),
                Some(std::path::Path::new("/etc/hdds/certs/participant.key"))
            );
            assert_eq!(
                inner.tls_ca_file.as_deref(),
                Some(std::path::Path::new("/etc/hdds/certs/ca.crt"))
            );
            assert_eq!(
                inner.tls_crl_file.as_deref(),
                Some(std::path::Path::new("/etc/hdds/certs/ca.crl"))
            );
            assert!(inner.tls_require_client_cert);
            assert!(inner.tcp_config.as_ref().unwrap().tls_enabled);

            let plan = tls_plan(inner)
                .expect("plan resolves")
                .expect("TLS enabled");
            assert_eq!(plan.role, TcpRole::Auto);
            assert!(plan.require_client_cert);
            assert_eq!(
                plan.crl.as_deref(),
                Some(std::path::Path::new("/etc/hdds/certs/ca.crl"))
            );

            hdds_config_destroy(config);
        }
    }

    #[test]
    fn tls_setters_reject_null_and_empty_arguments() {
        unsafe {
            let path = CString::new("/tmp/x.pem").unwrap();
            let empty = CString::new("").unwrap();
            assert_eq!(
                hdds_config_set_tls_certificate_file(ptr::null_mut(), path.as_ptr()),
                HddsError::HddsInvalidArgument
            );
            assert_eq!(
                hdds_config_set_tls_require_client_cert(ptr::null_mut(), true),
                HddsError::HddsInvalidArgument
            );

            let name = CString::new("tls_null").unwrap();
            let config = hdds_config_create(name.as_ptr());
            assert_eq!(
                hdds_config_set_tls_certificate_file(config, ptr::null()),
                HddsError::HddsInvalidArgument
            );
            assert_eq!(
                hdds_config_set_tls_private_key_file(config, empty.as_ptr()),
                HddsError::HddsInvalidArgument
            );
            assert_eq!(
                hdds_config_set_tls_ca_file(config, ptr::null()),
                HddsError::HddsInvalidArgument
            );
            assert_eq!(
                hdds_config_set_tls_crl_file(config, ptr::null()),
                HddsError::HddsInvalidArgument
            );
            let inner = &*config.cast::<ParticipantConfigInner>();
            assert!(inner.tls_cert_file.is_none());
            assert!(inner.tls_key_file.is_none());
            assert!(inner.tls_ca_file.is_none());
            assert!(inner.tls_crl_file.is_none());
            hdds_config_destroy(config);
        }
    }

    fn tls_inner(role: TcpRole) -> ParticipantConfigInner {
        let mut inner = ParticipantConfigInner::new("tls_plan");
        let mut tcp = TcpConfig::enabled();
        tcp.role = role;
        tcp.tls_enabled = true;
        if role == TcpRole::ClientOnly {
            tcp.initial_peers.push("127.0.0.1:7410".parse().unwrap());
        }
        inner.tcp_config = Some(tcp);
        inner
    }

    #[test]
    fn tls_plan_absent_when_tls_disabled() {
        let inner = ParticipantConfigInner::new("no_tls");
        assert_eq!(tls_plan(&inner).unwrap(), None);
        let mut inner = ParticipantConfigInner::new("tcp_no_tls");
        inner.tcp_config = Some(TcpConfig::enabled());
        assert_eq!(tls_plan(&inner).unwrap(), None);
    }

    #[test]
    fn tls_plan_refuses_material_without_enable_tls() {
        // Certificate material but hdds_config_enable_tls was never called:
        // the build must fail rather than run TCP in cleartext.
        for setup in [
            |i: &mut ParticipantConfigInner| i.tls_cert_file = Some(PathBuf::from("id.crt")),
            |i: &mut ParticipantConfigInner| i.tls_key_file = Some(PathBuf::from("id.key")),
            |i: &mut ParticipantConfigInner| i.tls_ca_file = Some(PathBuf::from("ca.crt")),
            |i: &mut ParticipantConfigInner| i.tls_crl_file = Some(PathBuf::from("ca.crl")),
            |i: &mut ParticipantConfigInner| i.tls_require_client_cert = true,
        ] {
            // TCP enabled, TLS not enabled.
            let mut inner = ParticipantConfigInner::new("tcp_no_tls");
            inner.tcp_config = Some(TcpConfig::enabled());
            setup(&mut inner);
            let err = tls_plan(&inner).unwrap_err();
            assert!(err.contains("TLS is not enabled"), "{err}");

            // No TCP transport at all.
            let mut inner = ParticipantConfigInner::new("no_tcp");
            setup(&mut inner);
            let err = tls_plan(&inner).unwrap_err();
            assert!(err.contains("TLS is not enabled"), "{err}");
        }
    }

    #[test]
    fn tls_plan_requires_identity_and_ca_for_dialing_roles() {
        // No identity at all.
        let inner = tls_inner(TcpRole::Auto);
        let err = tls_plan(&inner).unwrap_err();
        assert!(err.contains("certificate file"), "{err}");

        // Certificate without key.
        let mut inner = tls_inner(TcpRole::Auto);
        inner.tls_cert_file = Some(PathBuf::from("id.crt"));
        let err = tls_plan(&inner).unwrap_err();
        assert!(err.contains("private key file"), "{err}");

        // Auto dials: a CA is mandatory to verify the peer.
        let mut inner = tls_inner(TcpRole::Auto);
        inner.tls_cert_file = Some(PathBuf::from("id.crt"));
        inner.tls_key_file = Some(PathBuf::from("id.key"));
        let err = tls_plan(&inner).unwrap_err();
        assert!(err.contains("CA file"), "{err}");

        // ClientOnly dials too.
        let mut inner = tls_inner(TcpRole::ClientOnly);
        inner.tls_cert_file = Some(PathBuf::from("id.crt"));
        inner.tls_key_file = Some(PathBuf::from("id.key"));
        assert!(tls_plan(&inner).unwrap_err().contains("CA file"));

        // ServerOnly without client-cert requirement needs no CA.
        let mut inner = tls_inner(TcpRole::ServerOnly);
        inner.tls_cert_file = Some(PathBuf::from("id.crt"));
        inner.tls_key_file = Some(PathBuf::from("id.key"));
        let plan = tls_plan(&inner).unwrap().unwrap();
        assert_eq!(plan.role, TcpRole::ServerOnly);
        assert!(plan.ca.is_none());
        assert!(!plan.require_client_cert);

        // require_client_cert without a CA is refused.
        inner.tls_require_client_cert = true;
        let err = tls_plan(&inner).unwrap_err();
        assert!(err.contains("require_client_cert"), "{err}");

        // CRL without require_client_cert is refused (nothing silently ignored).
        let mut inner = tls_inner(TcpRole::ServerOnly);
        inner.tls_cert_file = Some(PathBuf::from("id.crt"));
        inner.tls_key_file = Some(PathBuf::from("id.key"));
        inner.tls_ca_file = Some(PathBuf::from("ca.crt"));
        inner.tls_crl_file = Some(PathBuf::from("ca.crl"));
        let err = tls_plan(&inner).unwrap_err();
        assert!(err.contains("CRL file"), "{err}");

        // Complete mTLS peer plan.
        let mut inner = tls_inner(TcpRole::Auto);
        inner.tls_cert_file = Some(PathBuf::from("id.crt"));
        inner.tls_key_file = Some(PathBuf::from("id.key"));
        inner.tls_ca_file = Some(PathBuf::from("ca.crt"));
        inner.tls_crl_file = Some(PathBuf::from("ca.crl"));
        inner.tls_require_client_cert = true;
        let plan = tls_plan(&inner).unwrap().unwrap();
        assert_eq!(
            plan,
            TlsPlan {
                role: TcpRole::Auto,
                cert: PathBuf::from("id.crt"),
                key: PathBuf::from("id.key"),
                ca: Some(PathBuf::from("ca.crt")),
                crl: Some(PathBuf::from("ca.crl")),
                require_client_cert: true,
            }
        );
    }

    #[cfg(not(feature = "tcp-tls"))]
    #[test]
    fn materialise_tls_refuses_without_feature() {
        let plan = TlsPlan {
            role: TcpRole::ServerOnly,
            cert: PathBuf::from("id.crt"),
            key: PathBuf::from("id.key"),
            ca: None,
            crl: None,
            require_client_cert: false,
        };
        let err = materialise_tls(&plan).unwrap_err();
        assert!(err.contains("tcp-tls"), "{err}");
    }

    #[cfg(feature = "tcp-tls")]
    mod materialise {
        use super::*;
        use rcgen::{
            BasicConstraints, CertificateParams, DistinguishedName, DnType,
            ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
        };
        use std::path::Path;

        /// Write a CA and an identity (IP SAN 127.0.0.1, serverAuth + clientAuth)
        /// into a fresh temp directory; returns (dir, ca.crt, id.crt, id.key).
        fn write_pki() -> (PathBuf, PathBuf, PathBuf, PathBuf) {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let dir =
                std::env::temp_dir().join(format!("hdds-c-tls-{}-{}", std::process::id(), nanos));
            std::fs::create_dir_all(&dir).unwrap();

            let ca_key = KeyPair::generate().unwrap();
            let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
            let mut dn = DistinguishedName::new();
            dn.push(DnType::CommonName, "hdds-c test CA");
            ca_params.distinguished_name = dn;
            ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            ca_params.key_usages = vec![
                KeyUsagePurpose::KeyCertSign,
                KeyUsagePurpose::DigitalSignature,
                KeyUsagePurpose::CrlSign,
            ];
            let ca = ca_params.self_signed(&ca_key).unwrap();

            let id_key = KeyPair::generate().unwrap();
            let mut id_params = CertificateParams::new(vec!["127.0.0.1".to_string()]).unwrap();
            let mut dn = DistinguishedName::new();
            dn.push(DnType::CommonName, "hdds-c participant");
            id_params.distinguished_name = dn;
            id_params.extended_key_usages = vec![
                ExtendedKeyUsagePurpose::ServerAuth,
                ExtendedKeyUsagePurpose::ClientAuth,
            ];
            id_params.use_authority_key_identifier_extension = true;
            let id = id_params.signed_by(&id_key, &ca, &ca_key).unwrap();

            let ca_path = dir.join("ca.crt");
            let cert_path = dir.join("id.crt");
            let key_path = dir.join("id.key");
            std::fs::write(&ca_path, ca.pem()).unwrap();
            std::fs::write(&cert_path, id.pem()).unwrap();
            std::fs::write(&key_path, id_key.serialize_pem()).unwrap();
            (dir, ca_path, cert_path, key_path)
        }

        fn plan(
            role: TcpRole,
            ca: Option<&Path>,
            cert: &Path,
            key: &Path,
            require: bool,
        ) -> TlsPlan {
            TlsPlan {
                role,
                cert: cert.to_path_buf(),
                key: key.to_path_buf(),
                ca: ca.map(Path::to_path_buf),
                crl: None,
                require_client_cert: require,
            }
        }

        #[test]
        fn materialise_tls_builds_role_configs_from_files() {
            let (dir, ca, cert, key) = write_pki();

            // Auto + require_client_cert -> peer config with both halves.
            let peer = materialise_tls(&plan(TcpRole::Auto, Some(&ca), &cert, &key, true))
                .expect("peer config");
            assert!(peer.is_peer());
            assert!(peer.can_accept() && peer.can_initiate());
            assert!(peer.require_client_cert());
            assert_eq!(peer.client_ca_count(), 1);

            // ServerOnly without client-cert requirement: plain TLS server.
            let server = materialise_tls(&plan(TcpRole::ServerOnly, None, &cert, &key, false))
                .expect("server config");
            assert!(server.is_server() && !server.is_peer());
            assert!(!server.require_client_cert());

            // ClientOnly: client identity + private CA trust anchor.
            let client = materialise_tls(&plan(TcpRole::ClientOnly, Some(&ca), &cert, &key, false))
                .expect("client config");
            assert!(client.is_client() && !client.is_server());
            assert_eq!(client.trust_anchor_count(), 1);

            let _ = std::fs::remove_dir_all(dir);
        }

        #[test]
        fn materialise_tls_fails_closed_on_missing_or_bad_files() {
            let (dir, _ca, cert, key) = write_pki();
            let missing = dir.join("missing.pem");

            let err = materialise_tls(&plan(TcpRole::ServerOnly, None, &missing, &key, false))
                .unwrap_err();
            assert!(err.contains("certificate file"), "{err}");

            let err = materialise_tls(&plan(TcpRole::Auto, Some(&missing), &cert, &key, true))
                .unwrap_err();
            assert!(err.contains("CA file"), "{err}");

            // A CA file with no certificate inside: mTLS server refuses to build.
            let empty_ca = dir.join("empty.crt");
            std::fs::write(&empty_ca, "").unwrap();
            let err = materialise_tls(&plan(
                TcpRole::ServerOnly,
                Some(&empty_ca),
                &cert,
                &key,
                true,
            ))
            .unwrap_err();
            assert!(err.contains("no client CA"), "{err}");

            let _ = std::fs::remove_dir_all(dir);
        }
    }
}
