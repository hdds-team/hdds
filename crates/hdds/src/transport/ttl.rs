// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! TTL (Time To Live) configuration for IP packet hop limit.
//!
//! TTL controls how many network hops a packet can traverse before being discarded.
//! This is essential for multicast routing and network topology control.
//!
//! # TTL Values
//!
//! | TTL | Scope | Use Case |
//! |-----|-------|----------|
//! | 1 | Link-local | Same subnet only (default for multicast) |
//! | 16 | Site-local | Within organization/site |
//! | 64 | Regional | Typical internet default |
//! | 128 | Global | Extended reach |
//! | 255 | Maximum | No hop limit |
//!
//! # DDS/RTPS Recommendations
//!
//! - **Discovery (SPDP/SEDP)**: TTL=1 for link-local, TTL=16+ for routed multicast
//! - **User Data**: Depends on deployment topology
//! - **Same subnet**: TTL=1 (prevents multicast leakage)
//! - **Routed multicast**: TTL=16 or higher
//!
//! # Environment Variable
//!
//! `HDDS_TTL=<value>` - Set TTL for all sockets (1-255)
//! `HDDS_MULTICAST_TTL=<value>` - Set multicast TTL specifically

use socket2::Socket;
use std::io;
use std::net::UdpSocket;
#[cfg(unix)]
use std::os::unix::io::AsRawFd;

/// Default multicast TTL (link-local only).
pub const DEFAULT_MULTICAST_TTL: u8 = 1;

/// Default unicast TTL (standard internet default).
pub const DEFAULT_UNICAST_TTL: u8 = 64;

/// TTL configuration for sockets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TtlConfig {
    /// TTL for multicast packets
    pub multicast: u8,
    /// TTL for unicast packets
    pub unicast: u8,
}

impl Default for TtlConfig {
    fn default() -> Self {
        Self {
            multicast: DEFAULT_MULTICAST_TTL,
            unicast: DEFAULT_UNICAST_TTL,
        }
    }
}

impl TtlConfig {
    /// Create configuration for link-local only (same subnet).
    ///
    /// Multicast packets will not traverse routers.
    #[must_use]
    pub const fn link_local() -> Self {
        Self {
            multicast: 1,
            unicast: 64,
        }
    }

    /// Create configuration for site-local (within organization).
    ///
    /// Multicast packets can traverse up to 16 hops.
    #[must_use]
    pub const fn site_local() -> Self {
        Self {
            multicast: 16,
            unicast: 64,
        }
    }

    /// Create configuration for regional/internet scope.
    ///
    /// Multicast packets can traverse up to 64 hops.
    #[must_use]
    pub const fn regional() -> Self {
        Self {
            multicast: 64,
            unicast: 64,
        }
    }

    /// Create configuration with maximum TTL.
    ///
    /// No hop limit - use with caution.
    #[must_use]
    pub const fn global() -> Self {
        Self {
            multicast: 128,
            unicast: 128,
        }
    }

    /// Create configuration with custom values.
    #[must_use]
    pub const fn custom(multicast: u8, unicast: u8) -> Self {
        Self { multicast, unicast }
    }

    /// Create from environment variables.
    ///
    /// Checks:
    /// - `HDDS_TTL` - Sets both multicast and unicast TTL
    /// - `HDDS_MULTICAST_TTL` - Sets multicast TTL only (overrides HDDS_TTL for multicast)
    /// - `HDDS_UNICAST_TTL` - Sets unicast TTL only (overrides HDDS_TTL for unicast)
    #[must_use]
    pub fn from_env() -> Self {
        let mut config = Self::default();

        // HDDS_TTL sets both
        if let Ok(val) = std::env::var("HDDS_TTL") {
            if let Ok(ttl) = val.parse::<u8>() {
                config.multicast = ttl;
                config.unicast = ttl;
            }
        }

        // HDDS_MULTICAST_TTL overrides multicast
        if let Ok(val) = std::env::var("HDDS_MULTICAST_TTL") {
            if let Ok(ttl) = val.parse::<u8>() {
                config.multicast = ttl;
            }
        }

        // HDDS_UNICAST_TTL overrides unicast
        if let Ok(val) = std::env::var("HDDS_UNICAST_TTL") {
            if let Ok(ttl) = val.parse::<u8>() {
                config.unicast = ttl;
            }
        }

        config
    }
}

/// Set multicast TTL on a UDP socket.
///
/// This controls how many hops multicast packets can traverse.
/// A TTL of 1 means link-local only (same subnet).
///
/// # Arguments
/// * `socket` - The UDP socket to configure
/// * `ttl` - TTL value (1-255)
///
/// # Returns
/// * `Ok(())` on success
/// * `Err` if setsockopt fails
#[cfg(unix)]
pub fn set_multicast_ttl(socket: &UdpSocket, ttl: u8) -> io::Result<()> {
    let fd = socket.as_raw_fd();
    set_multicast_ttl_fd(fd, ttl)
}

/// Set multicast TTL on a socket2::Socket.
#[cfg(unix)]
pub fn set_socket2_multicast_ttl(socket: &Socket, ttl: u8) -> io::Result<()> {
    let fd = socket.as_raw_fd();
    set_multicast_ttl_fd(fd, ttl)
}

/// Set multicast TTL on a raw file descriptor.
#[cfg(unix)]
fn set_multicast_ttl_fd(fd: i32, ttl: u8) -> io::Result<()> {
    // IP_MULTICAST_TTL = 33 on Linux
    const IP_MULTICAST_TTL: i32 = 33;
    const IPPROTO_IP: i32 = 0;

    let ttl_val = i32::from(ttl);
    // SAFETY:
    // - fd is a valid socket descriptor (obtained from UdpSocket::as_raw_fd())
    // - IPPROTO_IP (0) and IP_MULTICAST_TTL (33) are valid socket option constants
    // - ttl_val is a stack-allocated i32, properly aligned
    // - size_of::<i32>() correctly represents the option value size
    // - setsockopt only modifies kernel socket state, no memory corruption possible
    let result = unsafe {
        libc::setsockopt(
            fd,
            IPPROTO_IP,
            IP_MULTICAST_TTL,
            &ttl_val as *const i32 as *const libc::c_void,
            std::mem::size_of::<i32>() as libc::socklen_t,
        )
    };

    if result == 0 {
        log::debug!("[TTL] Set multicast TTL={} on fd={}", ttl, fd);
        Ok(())
    } else {
        let err = io::Error::last_os_error();
        log::warn!(
            "[TTL] Failed to set multicast TTL={} on fd={}: {}",
            ttl,
            fd,
            err
        );
        Err(err)
    }
}

/// Set unicast TTL on a UDP socket.
///
/// This controls the IP TTL field for unicast packets.
///
/// # Arguments
/// * `socket` - The UDP socket to configure
/// * `ttl` - TTL value (1-255)
#[cfg(unix)]
pub fn set_unicast_ttl(socket: &UdpSocket, ttl: u8) -> io::Result<()> {
    let fd = socket.as_raw_fd();
    set_unicast_ttl_fd(fd, ttl)
}

/// Set unicast TTL on a socket2::Socket.
#[cfg(unix)]
pub fn set_socket2_unicast_ttl(socket: &Socket, ttl: u8) -> io::Result<()> {
    let fd = socket.as_raw_fd();
    set_unicast_ttl_fd(fd, ttl)
}

/// Set unicast TTL on a raw file descriptor.
#[cfg(unix)]
fn set_unicast_ttl_fd(fd: i32, ttl: u8) -> io::Result<()> {
    // IP_TTL = 2 on Linux
    const IP_TTL: i32 = 2;
    const IPPROTO_IP: i32 = 0;

    let ttl_val = i32::from(ttl);
    // SAFETY:
    // - fd is a valid socket descriptor (obtained from UdpSocket::as_raw_fd())
    // - IPPROTO_IP (0) and IP_TTL (2) are valid socket option constants
    // - ttl_val is a stack-allocated i32, properly aligned
    // - size_of::<i32>() correctly represents the option value size
    // - setsockopt only modifies kernel socket state, no memory corruption possible
    let result = unsafe {
        libc::setsockopt(
            fd,
            IPPROTO_IP,
            IP_TTL,
            &ttl_val as *const i32 as *const libc::c_void,
            std::mem::size_of::<i32>() as libc::socklen_t,
        )
    };

    if result == 0 {
        log::debug!("[TTL] Set unicast TTL={} on fd={}", ttl, fd);
        Ok(())
    } else {
        let err = io::Error::last_os_error();
        log::warn!(
            "[TTL] Failed to set unicast TTL={} on fd={}: {}",
            ttl,
            fd,
            err
        );
        Err(err)
    }
}

/// Get current multicast TTL from a socket.
#[cfg(unix)]
#[must_use]
pub fn get_multicast_ttl(socket: &UdpSocket) -> Option<u8> {
    let fd = socket.as_raw_fd();
    get_multicast_ttl_fd(fd)
}

/// Get multicast TTL from a raw file descriptor.
#[cfg(unix)]
fn get_multicast_ttl_fd(fd: i32) -> Option<u8> {
    const IP_MULTICAST_TTL: i32 = 33;
    const IPPROTO_IP: i32 = 0;

    let mut ttl_val: i32 = 0;
    let mut len: libc::socklen_t = std::mem::size_of::<i32>() as libc::socklen_t;

    // SAFETY:
    // - fd is a valid socket descriptor (caller responsibility)
    // - IPPROTO_IP (0) and IP_MULTICAST_TTL (33) are valid socket option constants
    // - ttl_val is a mutable stack-allocated i32, properly aligned
    // - len is initialized to size_of::<i32>() and passed by mutable reference
    // - getsockopt writes at most len bytes to ttl_val, which has sufficient space
    let result = unsafe {
        libc::getsockopt(
            fd,
            IPPROTO_IP,
            IP_MULTICAST_TTL,
            &mut ttl_val as *mut i32 as *mut libc::c_void,
            &mut len,
        )
    };

    if result == 0 {
        Some(ttl_val as u8)
    } else {
        None
    }
}

/// Get current unicast TTL from a socket.
#[cfg(unix)]
#[must_use]
pub fn get_unicast_ttl(socket: &UdpSocket) -> Option<u8> {
    let fd = socket.as_raw_fd();
    get_unicast_ttl_fd(fd)
}

/// Get unicast TTL from a raw file descriptor.
#[cfg(unix)]
fn get_unicast_ttl_fd(fd: i32) -> Option<u8> {
    const IP_TTL: i32 = 2;
    const IPPROTO_IP: i32 = 0;

    let mut ttl_val: i32 = 0;
    let mut len: libc::socklen_t = std::mem::size_of::<i32>() as libc::socklen_t;

    // SAFETY:
    // - fd is a valid socket descriptor (caller responsibility)
    // - IPPROTO_IP (0) and IP_TTL (2) are valid socket option constants
    // - ttl_val is a mutable stack-allocated i32, properly aligned
    // - len is initialized to size_of::<i32>() and passed by mutable reference
    // - getsockopt writes at most len bytes to ttl_val, which has sufficient space
    let result = unsafe {
        libc::getsockopt(
            fd,
            IPPROTO_IP,
            IP_TTL,
            &mut ttl_val as *mut i32 as *mut libc::c_void,
            &mut len,
        )
    };

    if result == 0 {
        Some(ttl_val as u8)
    } else {
        None
    }
}

/// Apply TTL configuration to a UDP socket.
///
/// Sets both multicast and unicast TTL values.
#[cfg(unix)]
pub fn apply_ttl_config(socket: &UdpSocket, config: &TtlConfig) -> io::Result<()> {
    set_multicast_ttl(socket, config.multicast)?;
    set_unicast_ttl(socket, config.unicast)?;
    Ok(())
}

/// Apply TTL configuration to a socket2::Socket.
#[cfg(unix)]
pub fn apply_socket2_ttl_config(socket: &Socket, config: &TtlConfig) -> io::Result<()> {
    set_socket2_multicast_ttl(socket, config.multicast)?;
    set_socket2_unicast_ttl(socket, config.unicast)?;
    Ok(())
}

#[cfg(windows)]
pub fn set_multicast_ttl(socket: &UdpSocket, ttl: u8) -> io::Result<()> {
    let sock_ref = socket2::SockRef::from(socket);
    sock_ref.set_multicast_ttl_v4(u32::from(ttl))
}

#[cfg(windows)]
pub fn set_socket2_multicast_ttl(socket: &Socket, ttl: u8) -> io::Result<()> {
    socket.set_multicast_ttl_v4(u32::from(ttl))
}

#[cfg(windows)]
pub fn set_unicast_ttl(socket: &UdpSocket, ttl: u8) -> io::Result<()> {
    let sock_ref = socket2::SockRef::from(socket);
    sock_ref.set_ttl(u32::from(ttl))
}

#[cfg(windows)]
pub fn set_socket2_unicast_ttl(socket: &Socket, ttl: u8) -> io::Result<()> {
    socket.set_ttl(u32::from(ttl))
}

#[cfg(windows)]
pub fn get_multicast_ttl(socket: &UdpSocket) -> Option<u8> {
    let sock_ref = socket2::SockRef::from(socket);
    // TTL is 8-bit per IP spec, but clamp defensively against buggy OS/driver
    sock_ref.multicast_ttl_v4().ok().map(|v| v.min(255) as u8)
}

#[cfg(windows)]
pub fn get_unicast_ttl(socket: &UdpSocket) -> Option<u8> {
    let sock_ref = socket2::SockRef::from(socket);
    // TTL is 8-bit per IP spec, but clamp defensively against buggy OS/driver
    sock_ref.ttl().ok().map(|v| v.min(255) as u8)
}

#[cfg(windows)]
pub fn apply_ttl_config(socket: &UdpSocket, config: &TtlConfig) -> io::Result<()> {
    set_multicast_ttl(socket, config.multicast)?;
    set_unicast_ttl(socket, config.unicast)?;
    Ok(())
}

#[cfg(windows)]
pub fn apply_socket2_ttl_config(socket: &Socket, config: &TtlConfig) -> io::Result<()> {
    set_socket2_multicast_ttl(socket, config.multicast)?;
    set_socket2_unicast_ttl(socket, config.unicast)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket;

    #[test]
    fn test_ttl_config_default() {
        let cfg = TtlConfig::default();
        assert_eq!(cfg.multicast, 1);
        assert_eq!(cfg.unicast, 64);
    }

    #[test]
    fn test_ttl_config_presets() {
        let ll = TtlConfig::link_local();
        assert_eq!(ll.multicast, 1);

        let sl = TtlConfig::site_local();
        assert_eq!(sl.multicast, 16);

        let reg = TtlConfig::regional();
        assert_eq!(reg.multicast, 64);

        let glob = TtlConfig::global();
        assert_eq!(glob.multicast, 128);
    }

    #[test]
    fn test_ttl_config_custom() {
        let cfg = TtlConfig::custom(32, 128);
        assert_eq!(cfg.multicast, 32);
        assert_eq!(cfg.unicast, 128);
    }

    #[cfg(unix)]
    #[test]
    fn test_set_multicast_ttl() {
        let socket = UdpSocket::bind("0.0.0.0:0").expect("bind failed");

        // Set TTL
        let result = set_multicast_ttl(&socket, 16);
        assert!(result.is_ok(), "set_multicast_ttl should succeed");

        // Verify it was set
        let ttl = get_multicast_ttl(&socket);
        assert_eq!(ttl, Some(16));
    }

    #[cfg(unix)]
    #[test]
    fn test_set_unicast_ttl() {
        let socket = UdpSocket::bind("0.0.0.0:0").expect("bind failed");

        // Set TTL
        let result = set_unicast_ttl(&socket, 128);
        assert!(result.is_ok(), "set_unicast_ttl should succeed");

        // Verify it was set
        let ttl = get_unicast_ttl(&socket);
        assert_eq!(ttl, Some(128));
    }

    #[cfg(unix)]
    #[test]
    fn test_apply_ttl_config() {
        let socket = UdpSocket::bind("0.0.0.0:0").expect("bind failed");
        let config = TtlConfig::site_local();

        let result = apply_ttl_config(&socket, &config);
        assert!(result.is_ok(), "apply_ttl_config should succeed");

        assert_eq!(get_multicast_ttl(&socket), Some(16));
        assert_eq!(get_unicast_ttl(&socket), Some(64));
    }

    #[cfg(unix)]
    #[test]
    fn test_ttl_boundary_values() {
        let socket = UdpSocket::bind("0.0.0.0:0").expect("bind failed");

        // Minimum TTL
        assert!(set_multicast_ttl(&socket, 1).is_ok());
        assert_eq!(get_multicast_ttl(&socket), Some(1));

        // Maximum TTL
        assert!(set_multicast_ttl(&socket, 255).is_ok());
        assert_eq!(get_multicast_ttl(&socket), Some(255));
    }
}
