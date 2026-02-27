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
use std::os::raw::c_char;
use std::ptr;

use hdds::Participant;
use hdds::ShmPolicy;
use hdds::TcpConfig;
use hdds::TcpRole;
use hdds::TransportMode;
use hdds::TransportPreference;

use crate::{HddsError, HddsParticipant};

// =============================================================================
// Internal config struct (owns all settings, translated to builder at build time)
// =============================================================================

struct ParticipantConfigInner {
    name: String,
    domain_id: u32,
    participant_id: Option<u8>,
    transport_mode: TransportMode,
    shm_policy: ShmPolicy,
    tcp_config: Option<TcpConfig>,
    transport_preference: TransportPreference,
    discovery_ports: Option<(u16, u16, u16)>,
    static_peers: Vec<SocketAddr>,
    #[cfg(feature = "security")]
    security_config: Option<crate::security_config::SecurityConfigInner>,
}

impl ParticipantConfigInner {
    fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            domain_id: 0,
            participant_id: None,
            transport_mode: TransportMode::UdpMulticast,
            shm_policy: ShmPolicy::Prefer,
            tcp_config: None,
            transport_preference: TransportPreference::UdpOnly,
            discovery_ports: None,
            static_peers: Vec::new(),
            #[cfg(feature = "security")]
            security_config: None,
        }
    }
}

/// Opaque handle to a participant configuration (builder).
#[repr(C)]
pub struct HddsParticipantConfig {
    _private: [u8; 0],
}

// =============================================================================
// SHM Policy
// =============================================================================

/// Shared memory policy for C FFI.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
// TCP Role
// =============================================================================

/// TCP role for C FFI.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

/// Set the DDS domain ID.
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
    inner.domain_id = domain_id;
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
/// # Safety
/// - `config` must be a valid pointer from `hdds_config_create`.
#[no_mangle]
pub unsafe extern "C" fn hdds_config_enable_tls(
    config: *mut HddsParticipantConfig,
) -> HddsError {
    if config.is_null() {
        return HddsError::HddsInvalidArgument;
    }
    let inner = &mut *config.cast::<ParticipantConfigInner>();
    let tcp = ensure_tcp(inner);
    tcp.tls_enabled = true;
    HddsError::HddsOk
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
        HddsTransportPreference::HddsTransportPrefShmPreferred => {
            TransportPreference::ShmPreferred
        }
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
    let sec_inner = *Box::from_raw(
        security.cast::<crate::security_config::SecurityConfigInner>(),
    );
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

    // Translate our config into ParticipantBuilder calls
    let mut builder = Participant::builder(&inner.name)
        .domain_id(inner.domain_id)
        .participant_id(inner.participant_id)
        .with_transport(inner.transport_mode)
        .shm_policy(inner.shm_policy)
        .with_transport_preference(inner.transport_preference);

    if let Some(tcp) = inner.tcp_config {
        builder = builder.tcp_config(tcp);
        // Re-apply preference since tcp_config() may override it
        builder = builder.with_transport_preference(inner.transport_preference);
    }

    if let Some((spdp, sedp, user)) = inner.discovery_ports {
        builder = builder.with_discovery_ports(spdp, sedp, user);
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
        sec_builder = sec_builder.enable_encryption(sec.enable_encryption);
        sec_builder = sec_builder.enable_audit_log(sec.enable_audit_log);
        if let Some(p) = sec.audit_log_path {
            sec_builder = sec_builder.audit_log_path(p);
        }
        sec_builder = sec_builder.require_authentication(sec.require_authentication);
        sec_builder = sec_builder.check_certificate_revocation(sec.check_certificate_revocation);

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

            let peer = CString::new("127.0.0.1:7412").unwrap();
            assert_eq!(hdds_config_add_tcp_peer(config, peer.as_ptr()), HddsError::HddsOk);

            let static_peer = CString::new("192.168.1.100:7411").unwrap();
            assert_eq!(
                hdds_config_add_static_peer(config, static_peer.as_ptr()),
                HddsError::HddsOk,
            );

            // Verify internal state
            let inner = &*config.cast::<ParticipantConfigInner>();
            assert_eq!(inner.domain_id, 42);
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
}
