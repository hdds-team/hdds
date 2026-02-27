// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Multicast group management and interface discovery.
//!
//! Handles joining multicast groups, discovering network interfaces,
//! and configuring multicast settings for RTPS communication.

use std::io;
use std::net::{Ipv4Addr, UdpSocket};

/// Join RTPS multicast groups (SPDP and SEDP) on all available interfaces.
///
/// RTPS v2.5: SPDP uses 239.255.0.1, SEDP uses 239.255.0.2 (Sec.9.6.1.4.1).
/// Following RTI Connext behavior: join on ALL non-loopback interfaces.
pub fn join_multicast_group(socket: &UdpSocket) -> io::Result<Ipv4Addr> {
    let multicast_groups = [
        Ipv4Addr::new(239, 255, 0, 1), // SPDP (common practice)
        Ipv4Addr::new(239, 255, 0, 2), // SEDP (spec-compliant)
    ];

    // RTI strategy: Join multicast on ALL available interfaces (not just one).
    // strace shows RTI calls IP_ADD_MEMBERSHIP multiple times for each interface.
    let interfaces = get_multicast_interfaces()?;

    if interfaces.is_empty() {
        log::debug!("[UDP] WARNING: No suitable interfaces found for multicast, using UNSPECIFIED");
        for group in &multicast_groups {
            socket.join_multicast_v4(group, &Ipv4Addr::UNSPECIFIED)?;
            log::debug!("[UDP] join_multicast_v4({}) on UNSPECIFIED", group);
        }
    } else {
        for iface in &interfaces {
            for group in &multicast_groups {
                match socket.join_multicast_v4(group, iface) {
                    Ok(()) => {
                        log::debug!("[UDP] join_multicast_v4({}) on interface {}", group, iface);
                    }
                    Err(e) if e.raw_os_error() == Some(98) => {
                        // EADDRINUSE (98) Linux: already joined on same physical NIC
                        log::debug!(
                            "[UDP] join_multicast_v4({}) on {} - already joined, skipping",
                            group,
                            iface
                        );
                    }
                    Err(e) => {
                        // Non-fatal: skip interfaces that can't join multicast
                        // Windows 10049 (WSAEADDRNOTAVAIL): adapter doesn't support multicast
                        // Windows 10065 (WSAEHOSTUNREACH): no route to multicast group
                        log::debug!(
                            "[UDP] join_multicast_v4({}) on {} failed (non-fatal): {}",
                            group,
                            iface,
                            e
                        );
                    }
                }
            }
        }
    }

    socket.set_multicast_loop_v4(true)?;
    log::debug!("[UDP] multicast loop enabled");
    let _ = socket.set_multicast_ttl_v4(1);

    // Return first interface for sending (or UNSPECIFIED if none)
    Ok(interfaces.first().copied().unwrap_or(Ipv4Addr::UNSPECIFIED))
}

/// Get all non-loopback IPv4 interfaces suitable for multicast.
///
/// Mimics RTI Connext behavior of joining multicast on multiple interfaces.
/// - Linux: parses `ip -4 addr show` output
/// - Windows/other: uses `local_ip_address` crate
pub fn get_multicast_interfaces() -> io::Result<Vec<Ipv4Addr>> {
    // Try env var override first (for testing/debugging)
    if let Ok(var) = std::env::var("HDDS_MULTICAST_IF") {
        if let Ok(addr) = var.parse::<Ipv4Addr>() {
            log::debug!("[UDP] Using HDDS_MULTICAST_IF override: {}", addr);
            return Ok(vec![addr]);
        }
    }

    get_multicast_interfaces_platform()
}

/// Linux: parse `ip -4 addr show` to discover interfaces.
/// Falls back to `local_ip_address` crate if `ip` command is unavailable (e.g. Docker).
#[cfg(target_os = "linux")]
fn get_multicast_interfaces_platform() -> io::Result<Vec<Ipv4Addr>> {
    use std::process::Command;

    let output = match Command::new("ip").args(["-4", "addr", "show"]).output() {
        Ok(o) => o,
        Err(_) => {
            log::debug!("[UDP] 'ip' command not found, using local_ip_address crate");
            return get_multicast_interfaces_crate();
        }
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut interfaces = Vec::new();

    for line in stdout.lines() {
        if line.contains("127.0.0.1") || line.contains("host lo") {
            continue;
        }
        if let Some(inet_part) = line.trim().strip_prefix("inet ") {
            if let Some(addr_str) = inet_part.split('/').next() {
                if let Ok(addr) = addr_str.trim().parse::<Ipv4Addr>() {
                    interfaces.push(addr);
                }
            }
        }
    }

    Ok(interfaces)
}

/// Windows/other: use `local_ip_address` crate for interface discovery.
#[cfg(not(target_os = "linux"))]
fn get_multicast_interfaces_platform() -> io::Result<Vec<Ipv4Addr>> {
    get_multicast_interfaces_crate()
}

/// Portable interface discovery via `local_ip_address` crate.
fn get_multicast_interfaces_crate() -> io::Result<Vec<Ipv4Addr>> {
    use std::net::IpAddr;

    let interfaces = match local_ip_address::list_afinet_netifas() {
        Ok(ifs) => ifs,
        Err(e) => {
            log::debug!("[UDP] Failed to list network interfaces: {}", e);
            return Ok(vec![]);
        }
    };

    let mut addrs = Vec::new();
    for (_name, ip) in interfaces {
        if let IpAddr::V4(ipv4) = ip {
            if !ipv4.is_loopback() {
                addrs.push(ipv4);
            }
        }
    }

    log::debug!(
        "[UDP] Discovered {} non-loopback interfaces (portable)",
        addrs.len()
    );
    Ok(addrs)
}

/// Get primary interface IP address (the one used for default route).
///
/// Returns the IP to bind unicast sockets to, avoiding 0.0.0.0 binding issues
/// on multi-interface machines (e.g., with docker0 interface).
pub fn get_primary_interface_ip() -> io::Result<Ipv4Addr> {
    // Try to get interfaces that can be used for multicast
    let interfaces = get_multicast_interfaces()?;

    if let Some(&ip) = interfaces.first() {
        log::debug!("[UDP] Using primary interface IP: {}", ip);
        return Ok(ip);
    }

    // Fallback: use 0.0.0.0 (but this causes send issues on multi-interface machines)
    log::debug!(
        "[UDP] WARNING: No suitable interface found, using UNSPECIFIED (may cause send issues!)"
    );
    Ok(Ipv4Addr::UNSPECIFIED)
}

/// Get locators for a given port on all non-loopback interfaces.
///
/// Used to generate unicast locator lists for SPDP/SEDP announcements.
/// Honors HDDS_UNICAST_IF environment variable to force a specific interface.
pub fn get_unicast_locators(primary_iface: Ipv4Addr, port: u16) -> Vec<std::net::SocketAddr> {
    use std::net::IpAddr;

    // Allow forcing a specific IPv4 address for unicast locators (avoids docker0, etc.)
    if let Ok(addr_str) = std::env::var("HDDS_UNICAST_IF") {
        if let Ok(ipv4) = addr_str.parse::<std::net::Ipv4Addr>() {
            let sock = std::net::SocketAddr::new(IpAddr::V4(ipv4), port);
            log::debug!("[UDP] Using HDDS_UNICAST_IF={} -> locator {}", ipv4, sock);
            return vec![sock];
        } else {
            log::debug!(
                "[UDP] [!]  Invalid HDDS_UNICAST_IF='{}' -- falling back to auto-detect",
                addr_str
            );
        }
    }

    // v98: FIX - Use primary interface only (not all interfaces)
    // This prevents announcing localhost IP when running on remote nodes
    // which caused FastDDS to respond to wrong IP (ICMP unreachable)
    if !primary_iface.is_unspecified() {
        let addr = std::net::SocketAddr::new(IpAddr::V4(primary_iface), port);
        log::debug!("[UDP] v98: Using primary interface for locator: {}", addr);
        return vec![addr];
    }

    // Fallback: enumerate all interfaces (only if primary not available)
    log::debug!("[UDP] v98: WARNING - Primary interface not available, enumerating all interfaces");
    let interfaces = match local_ip_address::list_afinet_netifas() {
        Ok(ifs) => ifs,
        Err(e) => {
            log::debug!("[UDP] Failed to list network interfaces: {}", e);
            return vec![];
        }
    };

    let mut locators = Vec::new();

    for (name, ip) in interfaces {
        // Only use IPv4 addresses, skip loopback for interop
        if let IpAddr::V4(ipv4) = ip {
            if ipv4.is_loopback() {
                continue;
            }

            let addr = std::net::SocketAddr::new(IpAddr::V4(ipv4), port);
            log::debug!(
                "[UDP] Found unicast locator: {} (interface: {})",
                addr,
                name
            );
            locators.push(addr);
        }
    }

    if locators.is_empty() {
        log::debug!(
            "[UDP] [!]  No unicast locators found! Remote peers won't be able to send us data."
        );
    }

    locators
}
