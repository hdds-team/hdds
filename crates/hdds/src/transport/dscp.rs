// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! DSCP (Differentiated Services Code Point) configuration for QoS network prioritization.
//!
//! DSCP is used to mark IP packets for traffic classification by routers/switches.
//! This enables network-level QoS for real-time DDS traffic.
//!
//! # DSCP Values (RFC 2474, RFC 4594)
//!
//! | Class | DSCP | Binary | Decimal | Use Case |
//! |-------|------|--------|---------|----------|
//! | EF (Expedited Forwarding) | 101110 | 46 | Real-time voice/video |
//! | AF41 (Assured Forwarding) | 100010 | 34 | Video streaming |
//! | AF31 | 011010 | 26 | Streaming media |
//! | AF21 | 010010 | 18 | Low-latency data |
//! | AF11 | 001010 | 10 | High-throughput data |
//! | CS0 (Best Effort) | 000000 | 0 | Default traffic |
//!
//! # DDS QoS Mapping (recommended)
//!
//! | DDS Priority | DSCP | Use Case |
//! |--------------|------|----------|
//! | REALTIME | EF (46) | Safety-critical, low-latency |
//! | HIGH | AF41 (34) | Important telemetry |
//! | NORMAL | AF21 (18) | Standard data |
//! | LOW | CS0 (0) | Best-effort, bulk |

use socket2::Socket;
use std::io;
use std::net::UdpSocket;
#[cfg(unix)]
use std::os::unix::io::AsRawFd;

/// DSCP traffic class values per RFC 4594.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[derive(Default)]
pub enum DscpClass {
    /// Best Effort (CS0) - Default traffic, no priority
    #[default]
    BestEffort = 0,

    /// AF11 - High-throughput data (bulk transfers)
    Af11 = 10,

    /// AF21 - Low-latency data (standard DDS)
    Af21 = 18,

    /// AF31 - Streaming media
    Af31 = 26,

    /// AF41 - Video streaming, important telemetry
    Af41 = 34,

    /// EF (Expedited Forwarding) - Real-time, safety-critical
    /// Lowest latency, highest priority
    Ef = 46,

    /// CS6 - Network control (routing protocols)
    Cs6 = 48,

    /// CS7 - Network control (highest)
    Cs7 = 56,
}

impl DscpClass {
    /// Convert DSCP class to TOS byte value.
    ///
    /// TOS field layout: `DSCP (6 bits) | ECN (2 bits)`
    /// So DSCP value must be shifted left by 2.
    #[inline]
    #[must_use]
    pub const fn to_tos(self) -> u8 {
        (self as u8) << 2
    }

    /// Create from raw DSCP value (0-63).
    #[must_use]
    pub const fn from_raw(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::BestEffort),
            10 => Some(Self::Af11),
            18 => Some(Self::Af21),
            26 => Some(Self::Af31),
            34 => Some(Self::Af41),
            46 => Some(Self::Ef),
            48 => Some(Self::Cs6),
            56 => Some(Self::Cs7),
            _ => None,
        }
    }

    /// Get human-readable name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::BestEffort => "Best Effort (CS0)",
            Self::Af11 => "AF11 (High Throughput)",
            Self::Af21 => "AF21 (Low Latency Data)",
            Self::Af31 => "AF31 (Streaming)",
            Self::Af41 => "AF41 (Video/Telemetry)",
            Self::Ef => "EF (Expedited Forwarding)",
            Self::Cs6 => "CS6 (Network Control)",
            Self::Cs7 => "CS7 (Network Control High)",
        }
    }
}

/// DSCP configuration for a socket.
#[derive(Debug, Clone, Copy)]
pub struct DscpConfig {
    /// DSCP class for discovery traffic (SPDP/SEDP)
    pub discovery: DscpClass,
    /// DSCP class for user data traffic
    pub user_data: DscpClass,
    /// DSCP class for metatraffic (ACKNACK, HEARTBEAT)
    pub metatraffic: DscpClass,
}

impl Default for DscpConfig {
    fn default() -> Self {
        Self {
            // Discovery: medium priority (important but not real-time)
            discovery: DscpClass::Af21,
            // User data: configurable per-writer (default: standard)
            user_data: DscpClass::Af21,
            // Metatraffic: higher priority (reliability depends on it)
            metatraffic: DscpClass::Af31,
        }
    }
}

impl DscpConfig {
    /// Create configuration for real-time/safety-critical traffic.
    #[must_use]
    pub const fn realtime() -> Self {
        Self {
            discovery: DscpClass::Af41,
            user_data: DscpClass::Ef,
            metatraffic: DscpClass::Ef,
        }
    }

    /// Create configuration for high-priority traffic.
    #[must_use]
    pub const fn high_priority() -> Self {
        Self {
            discovery: DscpClass::Af31,
            user_data: DscpClass::Af41,
            metatraffic: DscpClass::Af41,
        }
    }

    /// Create configuration for best-effort traffic (no prioritization).
    #[must_use]
    pub const fn best_effort() -> Self {
        Self {
            discovery: DscpClass::BestEffort,
            user_data: DscpClass::BestEffort,
            metatraffic: DscpClass::BestEffort,
        }
    }

    /// Create from environment variable HDDS_DSCP.
    ///
    /// Format: `HDDS_DSCP=<discovery>,<user_data>,<metatraffic>`
    /// Example: `HDDS_DSCP=18,46,26` (AF21, EF, AF31)
    /// Or single value: `HDDS_DSCP=46` (EF for all)
    #[must_use]
    pub fn from_env() -> Self {
        match std::env::var("HDDS_DSCP") {
            Ok(val) => Self::parse_env(&val).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    // @audit-ok: Simple pattern matching (cyclo 12, cogni 1) - parse 1 or 3 comma-separated DSCP values
    fn parse_env(val: &str) -> Option<Self> {
        let parts: Vec<&str> = val.split(',').collect();
        match parts.len() {
            1 => {
                // Single value: apply to all
                let dscp = parts[0].trim().parse::<u8>().ok()?;
                let class = DscpClass::from_raw(dscp)?;
                Some(Self {
                    discovery: class,
                    user_data: class,
                    metatraffic: class,
                })
            }
            3 => {
                // Three values: discovery, user_data, metatraffic
                let discovery = DscpClass::from_raw(parts[0].trim().parse().ok()?)?;
                let user_data = DscpClass::from_raw(parts[1].trim().parse().ok()?)?;
                let metatraffic = DscpClass::from_raw(parts[2].trim().parse().ok()?)?;
                Some(Self {
                    discovery,
                    user_data,
                    metatraffic,
                })
            }
            _ => None,
        }
    }
}

/// Set DSCP/TOS value on a socket.
///
/// This sets the IP_TOS socket option which marks outgoing packets
/// with the specified DSCP value for QoS routing.
///
/// # Arguments
/// * `socket` - The socket to configure
/// * `dscp` - The DSCP class to apply
///
/// # Returns
/// * `Ok(())` on success
/// * `Err` if setsockopt fails (usually requires CAP_NET_ADMIN on some systems)
///
/// # Platform Notes
/// - Linux: Works without privileges for most DSCP values
/// - Some values (CS6, CS7) may require CAP_NET_ADMIN
/// - Routers must be configured to honor DSCP markings
#[cfg(unix)]
pub fn set_socket_dscp(socket: &UdpSocket, dscp: DscpClass) -> io::Result<()> {
    let tos = dscp.to_tos();
    set_socket_tos_raw(socket, tos)
}

/// Set DSCP on a socket2::Socket.
#[cfg(unix)]
pub fn set_socket2_dscp(socket: &Socket, dscp: DscpClass) -> io::Result<()> {
    let tos = dscp.to_tos();
    set_socket2_tos_raw(socket, tos)
}

/// Set raw TOS value on a UdpSocket.
#[cfg(unix)]
fn set_socket_tos_raw(socket: &UdpSocket, tos: u8) -> io::Result<()> {
    let fd = socket.as_raw_fd();
    set_tos_fd(fd, tos)
}

/// Set raw TOS value on a socket2::Socket.
#[cfg(unix)]
fn set_socket2_tos_raw(socket: &Socket, tos: u8) -> io::Result<()> {
    let fd = socket.as_raw_fd();
    set_tos_fd(fd, tos)
}

/// Set TOS on a raw file descriptor.
#[cfg(unix)]
fn set_tos_fd(fd: i32, tos: u8) -> io::Result<()> {
    // IP_TOS = 1 on Linux
    const IP_TOS: i32 = 1;
    // IPPROTO_IP = 0
    const IPPROTO_IP: i32 = 0;

    let tos_val = i32::from(tos);
    // SAFETY:
    // - fd is a valid socket descriptor (caller responsibility, obtained from UdpSocket::as_raw_fd())
    // - IPPROTO_IP (0) and IP_TOS (1) are valid socket option constants
    // - tos_val is a stack-allocated i32, properly aligned
    // - size_of::<i32>() correctly represents the option value size
    // - setsockopt only modifies kernel socket state, no memory corruption possible
    let result = unsafe {
        libc::setsockopt(
            fd,
            IPPROTO_IP,
            IP_TOS,
            &tos_val as *const i32 as *const libc::c_void,
            std::mem::size_of::<i32>() as libc::socklen_t,
        )
    };

    if result == 0 {
        log::debug!("[DSCP] Set TOS={} (DSCP={}) on fd={}", tos, tos >> 2, fd);
        Ok(())
    } else {
        let err = io::Error::last_os_error();
        log::warn!("[DSCP] Failed to set TOS={} on fd={}: {}", tos, fd, err);
        Err(err)
    }
}

/// Get current TOS value from a socket.
#[must_use]
#[cfg(unix)]
pub fn get_socket_dscp(socket: &UdpSocket) -> Option<DscpClass> {
    let fd = socket.as_raw_fd();
    get_tos_fd(fd).and_then(|tos| DscpClass::from_raw(tos >> 2))
}

/// Get TOS from a raw file descriptor.
#[cfg(unix)]
fn get_tos_fd(fd: i32) -> Option<u8> {
    const IP_TOS: i32 = 1;
    const IPPROTO_IP: i32 = 0;

    let mut tos_val: i32 = 0;
    let mut len: libc::socklen_t = std::mem::size_of::<i32>() as libc::socklen_t;

    // SAFETY:
    // - fd is a valid socket descriptor (caller responsibility)
    // - IPPROTO_IP (0) and IP_TOS (1) are valid socket option constants
    // - tos_val is a mutable stack-allocated i32, properly aligned
    // - len is initialized to size_of::<i32>() and passed by mutable reference
    // - getsockopt writes at most len bytes to tos_val, which has sufficient space
    let result = unsafe {
        libc::getsockopt(
            fd,
            IPPROTO_IP,
            IP_TOS,
            &mut tos_val as *mut i32 as *mut libc::c_void,
            &mut len,
        )
    };

    if result == 0 {
        Some(tos_val as u8)
    } else {
        None
    }
}

// --- Windows alternatives using socket2 cross-platform API ---

/// Set DSCP/TOS value on a UdpSocket (Windows).
#[cfg(windows)]
pub fn set_socket_dscp(socket: &UdpSocket, dscp: DscpClass) -> io::Result<()> {
    let sock_ref = socket2::SockRef::from(socket);
    sock_ref.set_tos(u32::from(dscp.to_tos()))?;
    Ok(())
}

/// Set DSCP on a socket2::Socket (Windows).
#[cfg(windows)]
pub fn set_socket2_dscp(socket: &Socket, dscp: DscpClass) -> io::Result<()> {
    socket.set_tos(u32::from(dscp.to_tos()))?;
    Ok(())
}

/// Get current DSCP value from a socket (Windows).
#[must_use]
#[cfg(windows)]
pub fn get_socket_dscp(socket: &UdpSocket) -> Option<DscpClass> {
    let sock_ref = socket2::SockRef::from(socket);
    // TOS is 8-bit per IP spec, but clamp defensively against buggy OS/driver
    sock_ref
        .tos()
        .ok()
        .and_then(|tos| DscpClass::from_raw((tos.min(255) as u8) >> 2))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket;

    #[test]
    fn test_dscp_to_tos() {
        assert_eq!(DscpClass::BestEffort.to_tos(), 0);
        assert_eq!(DscpClass::Af11.to_tos(), 40); // 10 << 2
        assert_eq!(DscpClass::Af21.to_tos(), 72); // 18 << 2
        assert_eq!(DscpClass::Ef.to_tos(), 184); // 46 << 2
    }

    #[test]
    fn test_dscp_from_raw() {
        assert_eq!(DscpClass::from_raw(0), Some(DscpClass::BestEffort));
        assert_eq!(DscpClass::from_raw(46), Some(DscpClass::Ef));
        assert_eq!(DscpClass::from_raw(99), None);
    }

    #[test]
    fn test_dscp_config_parse_env() {
        // Single value
        let cfg = DscpConfig::parse_env("46").expect("valid single DSCP value");
        assert_eq!(cfg.discovery, DscpClass::Ef);
        assert_eq!(cfg.user_data, DscpClass::Ef);

        // Three values
        let cfg = DscpConfig::parse_env("18,46,26").expect("valid triple DSCP values");
        assert_eq!(cfg.discovery, DscpClass::Af21);
        assert_eq!(cfg.user_data, DscpClass::Ef);
        assert_eq!(cfg.metatraffic, DscpClass::Af31);

        // Invalid
        assert!(DscpConfig::parse_env("invalid").is_none());
        assert!(DscpConfig::parse_env("1,2").is_none()); // Wrong count
    }

    #[test]
    #[cfg(unix)]
    fn test_set_socket_dscp() {
        let socket = UdpSocket::bind("0.0.0.0:0").expect("bind failed");

        // Set DSCP
        let result = set_socket_dscp(&socket, DscpClass::Af21);
        // May fail on some systems without permissions, but shouldn't panic
        if result.is_ok() {
            // Verify it was set
            let dscp = get_socket_dscp(&socket);
            assert_eq!(dscp, Some(DscpClass::Af21));
        }
    }

    #[test]
    fn test_dscp_presets() {
        let rt = DscpConfig::realtime();
        assert_eq!(rt.user_data, DscpClass::Ef);

        let hp = DscpConfig::high_priority();
        assert_eq!(hp.user_data, DscpClass::Af41);

        let be = DscpConfig::best_effort();
        assert_eq!(be.user_data, DscpClass::BestEffort);
    }
}
