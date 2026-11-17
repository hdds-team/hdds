// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Multicast group management and interface discovery.
//!
//! Handles joining multicast groups, discovering network interfaces,
//! and configuring multicast settings for RTPS communication.
//!
//! Interface discovery is an [`InterfaceSnapshot`] (see `transport::ifaddrs`):
//! `getifaddrs(3)` on Unix, `local-ip-address` on Windows, no process spawn
//! and no text parsing. The transport constructor captures ONE snapshot and
//! passes it to the `_with_snapshot` helpers below; the public functions keep
//! their historical signatures and each capture their own snapshot.
//!
//! # Interface selection
//!
//! The `HDDS_INTERFACE` environment variable forces ALL network operations
//! (transport bind, SPDP/SEDP locators, multicast joins, IP_MULTICAST_IF)
//! onto a single interface. Accepts either an interface name (`eth0`) or
//! an IPv4 address (`192.0.2.10`).
//!
//! This is the recommended way to avoid issues with Docker bridges, VPNs,
//! multi-NIC machines, and other virtual interfaces. Other DDS stacks have
//! an equivalent, e.g. FastDDS `<interfaceWhiteList>`, CycloneDDS
//! `NetworkInterfaceAddress`.
//!
//! Legacy env vars (`HDDS_UNICAST_IF`, `HDDS_MULTICAST_IF`) are still
//! honored as fallbacks but `HDDS_INTERFACE` takes priority over both.

use crate::transport::filter::InterfaceFilter;
use crate::transport::ifaddrs::{InterfaceEntry, InterfaceSnapshot};
use std::io;
use std::net::{Ipv4Addr, UdpSocket};
use std::sync::OnceLock;

/// Cached result of `HDDS_INTERFACE` resolution.
///
/// Resolved once at first access and cached for the process lifetime
/// (environment, not topology: the variable cannot change under us).
/// `None` means the env var is not set (use auto-detection).
/// `Some(ip)` means all network operations use this IP.
static FORCED_INTERFACE: OnceLock<Option<Ipv4Addr>> = OnceLock::new();

/// Resolve `HDDS_INTERFACE` env var to an IPv4 address.
///
/// Accepts:
/// - An IPv4 address directly: `HDDS_INTERFACE=192.0.2.10`
/// - An interface name: `HDDS_INTERFACE=eth0` (resolved via system lookup)
///
/// Returns `None` if the env var is not set.
/// Logs a warning and returns `None` if set but cannot be resolved.
pub fn resolve_forced_interface() -> Option<Ipv4Addr> {
    *FORCED_INTERFACE.get_or_init(|| {
        let val = match std::env::var("HDDS_INTERFACE") {
            Ok(v) if !v.is_empty() => v,
            _ => return None,
        };

        // Try parsing as IPv4 address first
        if let Ok(ip) = val.parse::<Ipv4Addr>() {
            log::info!("[UDP] HDDS_INTERFACE={} (direct IP)", ip);
            return Some(ip);
        }

        // Try resolving as interface name
        match resolve_interface_name(&val) {
            Some(ip) => {
                log::info!("[UDP] HDDS_INTERFACE={} resolved to {}", val, ip);
                Some(ip)
            }
            None => {
                log::warn!(
                    "[UDP] HDDS_INTERFACE='{}' could not be resolved to an IPv4 address. \
                     Use an IP (192.0.2.10) or interface name (eth0). Falling back to auto-detect.",
                    val
                );
                None
            }
        }
    })
}

/// Resolve an interface name (e.g. `eth0`, or a labelled alias `eth0:1`) to
/// its first IPv4 address, from a fresh interface snapshot.
fn resolve_interface_name(name: &str) -> Option<Ipv4Addr> {
    InterfaceSnapshot::capture_or_empty().resolve_name(name)
}

/// Join RTPS multicast groups (SPDP and SEDP) on all available interfaces.
///
/// RTPS v2.5: SPDP uses 239.255.0.1, SEDP uses 239.255.0.2 (Sec.9.6.1.4.1).
/// HDDS joins on ALL non-loopback interfaces.
///
/// If `HDDS_INTERFACE` is set, joins only on that single interface.
///
/// Resilient: tracks join successes and falls back to UNSPECIFIED if all
/// per-interface joins fail (common on Windows with virtual adapters like
/// Hyper-V Default Switch, WSL, Docker Desktop).
///
/// Back-compat wrapper: allow-all interface filter, multicast TTL 1
/// (the historical hardcoded value). New code should use
/// [`join_multicast_group_filtered`].
pub fn join_multicast_group(socket: &UdpSocket) -> io::Result<Ipv4Addr> {
    join_multicast_group_filtered(
        socket,
        &InterfaceFilter::allow_all(),
        crate::transport::ttl::DEFAULT_MULTICAST_TTL,
    )
}

/// Join RTPS multicast groups on the interfaces allowed by `filter`,
/// then set the requested multicast TTL on the socket.
///
/// Same semantics as [`join_multicast_group`] plus:
/// - interfaces excluded by the allowlist are skipped (no join attempted);
/// - the multicast TTL comes from the resolved transport options instead of
///   the historical hardcoded 1.
///
/// `HDDS_INTERFACE` (forced interface) bypasses the allowlist: an explicit
/// user choice always wins over the heuristic/allowlist path.
///
/// Captures its own interface snapshot; the transport constructor uses
/// [`join_multicast_group_with_snapshot`] to share one capture.
pub fn join_multicast_group_filtered(
    socket: &UdpSocket,
    filter: &InterfaceFilter,
    multicast_ttl: u8,
) -> io::Result<Ipv4Addr> {
    let snapshot = InterfaceSnapshot::capture_or_empty();
    join_multicast_group_with_snapshot(socket, filter, multicast_ttl, &snapshot)
}

/// [`join_multicast_group_filtered`] on an already captured snapshot.
pub(crate) fn join_multicast_group_with_snapshot(
    socket: &UdpSocket,
    filter: &InterfaceFilter,
    multicast_ttl: u8,
    snapshot: &InterfaceSnapshot,
) -> io::Result<Ipv4Addr> {
    let forced_ip = resolve_forced_interface();

    let multicast_groups = [
        Ipv4Addr::new(239, 255, 0, 1), // SPDP (common practice)
        Ipv4Addr::new(239, 255, 0, 2), // SEDP (spec-compliant)
    ];

    // Join multicast on ALL available interfaces (not just one): one
    // IP_ADD_MEMBERSHIP per interface. With HDDS_INTERFACE, we join on
    // exactly one interface.
    let interfaces = if let Some(ip) = forced_ip {
        log::info!(
            "[UDP] HDDS_INTERFACE: joining multicast only on forced interface {}",
            ip
        );
        vec![ip]
    } else {
        multicast_interfaces_with_snapshot(filter, snapshot)
    };
    let mut any_joined = false;
    let mut used_unspecified_fallback = false;

    if interfaces.is_empty() {
        // No interfaces found -- try UNSPECIFIED (let OS choose)
        log::debug!("[UDP] No suitable interfaces found for multicast, trying UNSPECIFIED");
        for group in &multicast_groups {
            match socket.join_multicast_v4(group, &Ipv4Addr::UNSPECIFIED) {
                Ok(()) => {
                    any_joined = true;
                    used_unspecified_fallback = true;
                    log::debug!("[UDP] join_multicast_v4({}) on UNSPECIFIED", group);
                }
                Err(e) => {
                    log::warn!(
                        "[UDP] join_multicast_v4({}) on UNSPECIFIED failed: {}",
                        group,
                        e
                    );
                }
            }
        }
    } else {
        for iface in &interfaces {
            for group in &multicast_groups {
                match socket.join_multicast_v4(group, iface) {
                    Ok(()) => {
                        any_joined = true;
                        log::debug!("[UDP] join_multicast_v4({}) on interface {}", group, iface);
                    }
                    Err(e) if e.raw_os_error() == Some(98) => {
                        // EADDRINUSE (98) Linux: already joined on same physical NIC
                        any_joined = true;
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

        // Fallback: if ALL interface joins failed (e.g. Windows virtual adapters only),
        // try UNSPECIFIED to let the OS pick a working interface
        if !any_joined {
            log::warn!(
                "[UDP] All per-interface multicast joins failed, trying UNSPECIFIED fallback"
            );
            for group in &multicast_groups {
                if socket
                    .join_multicast_v4(group, &Ipv4Addr::UNSPECIFIED)
                    .is_ok()
                {
                    any_joined = true;
                    used_unspecified_fallback = true;
                    log::debug!(
                        "[UDP] join_multicast_v4({}) on UNSPECIFIED (fallback)",
                        group
                    );
                }
            }
        }
    }

    if !any_joined {
        log::warn!("[UDP] WARNING: Could not join any multicast group! Discovery may not work.");
    }

    socket.set_multicast_loop_v4(true)?;
    log::debug!("[UDP] multicast loop enabled");
    // TTL from the resolved transport options (default 1 = link-local,
    // identical to the historical hardcoded value).
    let _ = socket.set_multicast_ttl_v4(u32::from(multicast_ttl));

    // Return forced interface or first discovered.
    // If we fell back to UNSPECIFIED (all per-interface joins failed),
    // return UNSPECIFIED explicitly -- not the first failed interface.
    Ok(forced_ip.unwrap_or_else(|| {
        if used_unspecified_fallback || interfaces.is_empty() {
            Ipv4Addr::UNSPECIFIED
        } else {
            interfaces.first().copied().unwrap_or(Ipv4Addr::UNSPECIFIED)
        }
    }))
}

/// Get all non-loopback IPv4 interfaces suitable for multicast.
///
/// Used to join multicast on multiple interfaces.
///
/// Note: `HDDS_INTERFACE` override is handled in the caller (`join_multicast_group`).
/// This function only checks the legacy `HDDS_MULTICAST_IF` env var.
///
/// Back-compat wrapper around [`get_multicast_interfaces_filtered`] with an
/// allow-all filter (historical behavior).
pub fn get_multicast_interfaces() -> io::Result<Vec<Ipv4Addr>> {
    get_multicast_interfaces_filtered(&InterfaceFilter::allow_all())
}

/// Get all non-loopback IPv4 interfaces suitable for multicast, restricted
/// to the interfaces allowed by `filter` (name OR CIDR match).
///
/// The legacy `HDDS_MULTICAST_IF` env override bypasses the allowlist: like
/// `HDDS_INTERFACE`, an explicit single-interface user choice always wins.
///
/// Captures its own interface snapshot. The `io::Result` is kept for the
/// callers' sake; enumeration failure is logged and yields an empty list.
pub fn get_multicast_interfaces_filtered(filter: &InterfaceFilter) -> io::Result<Vec<Ipv4Addr>> {
    Ok(multicast_interfaces_with_snapshot(
        filter,
        &InterfaceSnapshot::capture_or_empty(),
    ))
}

/// [`get_multicast_interfaces_filtered`] on an already captured snapshot.
///
/// Container bridges are skipped (see [`is_container_bridge`]) unless the
/// allowlist names them explicitly; point-to-point interfaces are NOT
/// skipped here, only by the primary-IP choice, as before.
pub(crate) fn multicast_interfaces_with_snapshot(
    filter: &InterfaceFilter,
    snapshot: &InterfaceSnapshot,
) -> Vec<Ipv4Addr> {
    // Try env var override first (for testing/debugging)
    // HDDS_INTERFACE is checked by caller; this is legacy fallback
    if let Ok(var) = std::env::var("HDDS_MULTICAST_IF") {
        if let Ok(addr) = var.parse::<Ipv4Addr>() {
            log::debug!("[UDP] Using HDDS_MULTICAST_IF override: {}", addr);
            return vec![addr];
        }
    }

    let mut interfaces = Vec::new();
    for entry in snapshot.non_loopback_entries() {
        if skips_container_bridge(filter, entry) {
            log::debug!(
                "[UDP] Skipping container bridge {} ({}) in multicast interfaces",
                entry.name,
                entry.addr
            );
            continue;
        }
        if !interface_matches(filter, entry) {
            log::debug!(
                "[UDP] Interface {} ({}) excluded by interface allowlist",
                entry.name,
                entry.addr
            );
            continue;
        }
        interfaces.push(entry.addr);
    }

    interfaces
}

/// Allowlist check for one snapshot entry.
///
/// A name entry in the allowlist matches the device name (`eth0`) or the
/// exact OS label of THIS entry (`eth0:1`), so an alias written either way is
/// accepted; CIDR entries match the address. The entry is checked as
/// iterated, never re-resolved by address: two entries may share one IPv4
/// (the same address on two devices, or an alias duplicating its parent),
/// and the other entry's label must not decide for this one.
fn interface_matches(filter: &InterfaceFilter, entry: &InterfaceEntry) -> bool {
    filter.allows_interface(&entry.name, entry.addr)
        || (entry.label != entry.name && filter.allows_name(&entry.label))
}

/// Check whether an interface identified only by its IP is allowed.
///
/// Resolves the entry owning `ip` in the snapshot (first match in OS order,
/// as the former `pairs.iter().find` did) so name-based allowlist entries
/// also work here; falls back to a pure CIDR check when the address belongs
/// to no local interface.
fn interface_allowed(filter: &InterfaceFilter, snapshot: &InterfaceSnapshot, ip: Ipv4Addr) -> bool {
    if filter.is_permissive() {
        return true;
    }
    match snapshot.find_by_addr(ip) {
        Some(entry) => interface_matches(filter, entry),
        None => filter.allows_ip(ip),
    }
}

/// Get primary interface IP address (the one used for default route).
///
/// If `HDDS_INTERFACE` is set, returns that IP directly (no probing).
///
/// Otherwise, returns the IP to bind unicast sockets to, avoiding 0.0.0.0
/// binding issues on multi-interface machines (e.g., with docker0 interface).
///
/// Uses the standard UDP "connect" trick to probe the OS routing table,
/// which correctly avoids virtual adapters (Hyper-V, WSL, Docker Desktop)
/// that plague Windows.
///
/// Back-compat wrapper around [`get_primary_interface_ip_filtered`] with an
/// allow-all filter (historical behavior).
pub fn get_primary_interface_ip() -> io::Result<Ipv4Addr> {
    get_primary_interface_ip_filtered(&InterfaceFilter::allow_all())
}

/// Get the primary interface IP, restricted to interfaces allowed by `filter`.
///
/// Same probing strategy as [`get_primary_interface_ip`], but a routing-probe
/// result on a disallowed interface is rejected and the fallback enumeration
/// only considers allowed interfaces. `HDDS_INTERFACE` bypasses the allowlist.
///
/// Captures its own interface snapshot; the transport constructor uses
/// [`get_primary_interface_ip_with_snapshot`] to share one capture.
pub fn get_primary_interface_ip_filtered(filter: &InterfaceFilter) -> io::Result<Ipv4Addr> {
    // HDDS_INTERFACE takes absolute priority -- no probing, no enumeration
    if let Some(ip) = resolve_forced_interface() {
        log::debug!("[UDP] Primary IP forced by HDDS_INTERFACE: {}", ip);
        return Ok(ip);
    }
    let snapshot = InterfaceSnapshot::capture_or_empty();
    get_primary_interface_ip_with_snapshot(filter, &snapshot)
}

/// [`get_primary_interface_ip_filtered`] on an already captured snapshot.
pub(crate) fn get_primary_interface_ip_with_snapshot(
    filter: &InterfaceFilter,
    snapshot: &InterfaceSnapshot,
) -> io::Result<Ipv4Addr> {
    // HDDS_INTERFACE takes absolute priority -- no probing, no guessing
    if let Some(ip) = resolve_forced_interface() {
        log::debug!("[UDP] Primary IP forced by HDDS_INTERFACE: {}", ip);
        return Ok(ip);
    }

    Ok(select_primary_interface(filter, snapshot))
}

/// The primary-interface HEURISTIC, with the `HDDS_INTERFACE` override
/// already stripped out by both callers above.
///
/// Split out of [`get_primary_interface_ip_with_snapshot`] so this ranking
/// can be exercised in a unit test against a synthetic snapshot without
/// going anywhere near [`resolve_forced_interface`]'s process-lifetime
/// [`OnceLock`] cache: that cache is correct for production (the env var
/// genuinely cannot change under a running process) but wrong for a test
/// suite, where it makes the FIRST test in the binary to touch it decide
/// the answer for every other test that reads it afterwards, including
/// ones that never intended to set `HDDS_INTERFACE` at all. Selection tests
/// (`primary_ip_fallback_skips_tunnel_and_docker`,
/// `primary_ip_all_tunnels_uses_first`) that went through the
/// `_with_snapshot` wrapper would assert the forced IP as soon as
/// `HDDS_INTERFACE` is set anywhere in the process (see
/// `test_support::network`) instead of the fixture-driven ranking they exist
/// to check. This function is the fixture-only surface those tests call: no
/// env read, no `OnceLock`, just `filter` and `snapshot` in, one `Ipv4Addr` out.
///
/// [`get_primary_interface_ip_with_snapshot`] and
/// [`get_primary_interface_ip_filtered`] check [`resolve_forced_interface`]
/// first and only fall through to this function when it returns `None`.
fn select_primary_interface(filter: &InterfaceFilter, snapshot: &InterfaceSnapshot) -> Ipv4Addr {
    // Step 1: UDP "connect" probe -- asks the OS which interface reaches 8.8.8.8.
    // No data is sent; this just queries the routing table.
    let probe_ip = UdpSocket::bind("0.0.0.0:0")
        .ok()
        .and_then(|sock| sock.connect("8.8.8.8:80").ok().map(|()| sock))
        .and_then(|sock| sock.local_addr().ok())
        .and_then(|addr| match addr.ip() {
            std::net::IpAddr::V4(ip) if !ip.is_unspecified() && !ip.is_loopback() => Some(ip),
            _ => None,
        });

    // Step 2: Accept probe result only if it's not a VPN/tunnel or a container
    // bridge. When CloudflareWARP or WireGuard is the default route, the probe
    // returns the tunnel IP (e.g. 172.16.0.2) which is unreachable from the
    // LAN; a container bridge is unreachable from remote DDS peers.
    if let Some(ip) = probe_ip {
        let tunnel = snapshot.is_tunnel_ip(ip);
        let bridge = snapshot
            .find_by_addr(ip)
            .is_some_and(|entry| skips_container_bridge(filter, entry));
        if !tunnel && !bridge && interface_allowed(filter, snapshot, ip) {
            log::debug!("[UDP] Primary IP via routing table probe: {}", ip);
            return ip;
        }
        if bridge {
            log::debug!(
                "[UDP] Routing probe returned {} (container bridge), skipping",
                ip
            );
        } else if tunnel {
            log::debug!(
                "[UDP] Routing probe returned {} (POINTOPOINT tunnel), skipping",
                ip
            );
        } else {
            log::debug!(
                "[UDP] Routing probe returned {} (excluded by interface allowlist), skipping",
                ip
            );
        }
    }

    // Step 3: Fallback -- first non-tunnel, allowed interface. The list has
    // already dropped the container bridges.
    let interfaces = multicast_interfaces_with_snapshot(filter, snapshot);
    for &ip in &interfaces {
        if !snapshot.is_tunnel_ip(ip) {
            log::debug!("[UDP] Primary IP via interface enumeration: {}", ip);
            return ip;
        }
    }

    // Step 4: Accept any interface if all are tunnels (weird but possible)
    if let Some(&ip) = interfaces.first() {
        log::debug!("[UDP] Primary IP (all tunnels, using first): {}", ip);
        return ip;
    }

    log::debug!(
        "[UDP] WARNING: No suitable interface found, using UNSPECIFIED (may cause send issues!)"
    );
    Ipv4Addr::UNSPECIFIED
}

/// Whether `entry` is a container-network bridge created on this host by
/// Docker, Podman or WSL: a virtual segment that only this host's containers
/// sit on, which no remote DDS peer can reach.
///
/// Decided by DEVICE NAME, never by address. The former rule skipped every
/// address in 172.16.0.0/12, which is also an RFC 1918 range real LANs use
/// (172.20.x.x is common in corporate networks) and the range Docker gives
/// the `eth0` INSIDE a container: both were silently ignored for discovery.
/// Inside a container the interface is `eth0`, not `docker0`, so it is kept.
///
/// - `docker0`: Docker's default bridge.
/// - `br-` + 12 hex digits: a Docker user-defined bridge (`br-<network id>`).
///   Any other `br-*` (a hand-made bridge enslaving the LAN NIC) is kept.
/// - `veth*`: the host end of a container's veth pair.
/// - `podman<N>`, `cni-podman<N>`: Podman's bridges.
/// - Windows: `vEthernet (WSL...)`, `vEthernet (Default Switch)`,
///   `vEthernet (nat)`, `vEthernet (DockerNAT)`: the WSL / Hyper-V NAT
///   switches. An EXTERNAL Hyper-V switch (`vEthernet (<your name>)`) is the
///   host's real LAN and is kept.
///
/// A Linux bridge is NOT skipped by type: a hypervisor host's LAN address
/// commonly lives on a bridge (`br0`, `virbr*` with a physical NIC), and that
/// is the interface remote peers reach.
pub(crate) fn is_container_bridge(entry: &InterfaceEntry) -> bool {
    let name = entry.name.as_str();
    let numbered = |prefix: &str| {
        name.strip_prefix(prefix)
            .is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit()))
    };
    let docker_network = name
        .strip_prefix("br-")
        .is_some_and(|id| id.len() == 12 && id.bytes().all(|b| b.is_ascii_hexdigit()));
    name == "docker0"
        || docker_network
        || name.starts_with("veth")
        || numbered("podman")
        || numbered("cni-podman")
        || name.starts_with("vEthernet (WSL")
        || matches!(
            name,
            "vEthernet (Default Switch)" | "vEthernet (nat)" | "vEthernet (DockerNAT)"
        )
}

/// Whether auto-detection skips `entry` as a container bridge.
///
/// An allowlist that is not permissive is an explicit choice: an interface
/// it admits is used even when it is a container bridge (the allowlist then
/// decides alone, in [`interface_matches`]). `HDDS_INTERFACE` bypasses all of
/// this before any snapshot is read.
fn skips_container_bridge(filter: &InterfaceFilter, entry: &InterfaceEntry) -> bool {
    filter.is_permissive() && is_container_bridge(entry)
}

/// Get locators for a given port on all non-loopback interfaces.
///
/// Used to generate unicast locator lists for SPDP/SEDP announcements.
///
/// Priority order:
/// 1. `HDDS_INTERFACE` -- forces everything onto one interface
/// 2. `HDDS_UNICAST_IF` -- legacy override (unicast locators only)
/// 3. `primary_iface` -- auto-detected primary interface
///
/// Back-compat wrapper around [`get_unicast_locators_filtered`] with an
/// allow-all filter (historical behavior).
pub fn get_unicast_locators(primary_iface: Ipv4Addr, port: u16) -> Vec<std::net::SocketAddr> {
    get_unicast_locators_filtered(primary_iface, port, &InterfaceFilter::allow_all())
}

/// Get unicast locators restricted to interfaces allowed by `filter`.
///
/// Same priority order as [`get_unicast_locators`]; the explicit overrides
/// (`HDDS_INTERFACE`, `HDDS_UNICAST_IF`) bypass the allowlist, and the
/// all-interfaces fallback (used when no primary interface is known) only
/// advertises allowed interfaces. `primary_iface` itself is expected to have
/// been chosen through [`get_primary_interface_ip_filtered`], so it is not
/// re-checked here.
///
/// An interface snapshot is captured only on the all-interfaces fallback.
pub fn get_unicast_locators_filtered(
    primary_iface: Ipv4Addr,
    port: u16,
    filter: &InterfaceFilter,
) -> Vec<std::net::SocketAddr> {
    use std::net::IpAddr;

    // 1. HDDS_INTERFACE takes absolute priority
    if let Some(forced_ip) = resolve_forced_interface() {
        let sock = std::net::SocketAddr::new(IpAddr::V4(forced_ip), port);
        log::debug!(
            "[UDP] Using HDDS_INTERFACE={} -> locator {}",
            forced_ip,
            sock
        );
        return vec![sock];
    }

    // 2. Legacy: HDDS_UNICAST_IF (kept for backward compat)
    if let Ok(addr_str) = std::env::var("HDDS_UNICAST_IF") {
        if let Ok(ipv4) = addr_str.parse::<std::net::Ipv4Addr>() {
            let sock = std::net::SocketAddr::new(IpAddr::V4(ipv4), port);
            log::debug!("[UDP] Using HDDS_UNICAST_IF={} -> locator {}", ipv4, sock);
            return vec![sock];
        }
        log::debug!(
            "[UDP] [!]  Invalid HDDS_UNICAST_IF='{}' -- falling back to auto-detect",
            addr_str
        );
    }

    // 3. Use the primary interface only (not all interfaces)
    // This prevents announcing localhost IP when running on remote nodes
    // which made remote peers reply to an unreachable address (ICMP unreachable)
    if !primary_iface.is_unspecified() {
        let addr = std::net::SocketAddr::new(IpAddr::V4(primary_iface), port);
        log::debug!("[UDP] Using primary interface for locator: {}", addr);
        return vec![addr];
    }

    // Fallback: enumerate all interfaces (only if primary not available)
    log::debug!("[UDP] WARNING - Primary interface not available, enumerating all interfaces");
    let snapshot = InterfaceSnapshot::capture_or_empty();

    let mut locators = Vec::new();

    for entry in snapshot.non_loopback_entries() {
        // Only advertise interfaces allowed by the allowlist
        if !interface_matches(filter, entry) {
            log::debug!(
                "[UDP] Skipping locator on {} ({}): excluded by interface allowlist",
                entry.name,
                entry.addr
            );
            continue;
        }

        let addr = std::net::SocketAddr::new(IpAddr::V4(entry.addr), port);
        log::debug!(
            "[UDP] Found unicast locator: {} (interface: {})",
            addr,
            entry.name
        );
        locators.push(addr);
    }

    if locators.is_empty() {
        log::debug!(
            "[UDP] [!]  No unicast locators found! Remote peers won't be able to send us data."
        );
    }

    locators
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::ifaddrs::InterfaceEntry;

    fn entry(label: &str, addr: [u8; 4], ptp: bool) -> InterfaceEntry {
        InterfaceEntry::new(label, Ipv4Addr::from(addr), 0, false, ptp, None)
    }

    /// lo, eth0 with a labelled alias, docker0, a point-to-point tunnel.
    fn synthetic() -> InterfaceSnapshot {
        InterfaceSnapshot::from_entries(vec![
            InterfaceEntry::new("lo", Ipv4Addr::LOCALHOST, 0, true, false, None),
            entry("eth0", [192, 168, 1, 10], false),
            entry("eth0:1", [192, 168, 3, 10], false),
            entry("docker0", [172, 17, 0, 1], false),
            entry("wg0", [10, 8, 0, 2], true),
        ])
    }

    #[test]
    fn test_resolve_forced_interface_not_set() {
        // Deliberately does not assert a value: `resolve_forced_interface`
        // caches its answer for the process lifetime, and by the time this
        // test runs some other test in this binary may already have forced
        // `HDDS_INTERFACE` (test_support::network pins the loopback
        // interface the first time a discovery-dependent test leases a
        // domain). Either `None` (nothing forced it yet) or `Some(lo's IP)`
        // is a correct answer here; a panic would not be.
        let _ = resolve_forced_interface();
    }

    #[test]
    fn container_bridges_are_recognised_by_name_not_address() {
        let bridge = |name: &str| is_container_bridge(&entry(name, [172, 17, 0, 1], false));
        for name in [
            "docker0",
            "br-b6e1d99a4193",
            "veth80b60a2",
            "podman0",
            "cni-podman1",
            "vEthernet (WSL)",
            "vEthernet (WSL (Hyper-V firewall))",
            "vEthernet (Default Switch)",
            "vEthernet (nat)",
            "vEthernet (DockerNAT)",
        ] {
            assert!(bridge(name), "{name} is a container bridge");
        }
        // Same 172.16.0.0/12 address, real interfaces: never skipped.
        for name in [
            "eth0",
            "enp3s0f0",
            "br0",
            "br-lan",
            "br-b6e1d99a419",
            "br-b6e1d99a4193x",
            "virbr0",
            "podman",
            "podmanX",
            "docker1",
            "vEthernet (External LAN)",
            "Ethernet",
        ] {
            assert!(!bridge(name), "{name} is not a container bridge");
        }
    }

    /// A real LAN in 172.16.0.0/12, a container's own `eth0` and a Docker
    /// bridge, all in that range: only the bridge is skipped.
    fn lan_in_the_docker_range() -> InterfaceSnapshot {
        InterfaceSnapshot::from_entries(vec![
            InterfaceEntry::new("lo", Ipv4Addr::LOCALHOST, 0, true, false, None),
            entry("docker0", [172, 17, 0, 1], false),
            entry("br-c24ab34786c3", [172, 18, 0, 1], false),
            entry("enp3s0", [172, 20, 4, 17], false),
            entry("eth0", [172, 16, 0, 5], false),
        ])
    }

    #[test]
    fn a_lan_in_172_16_slash_12_is_used_and_only_bridges_are_skipped() {
        let list = multicast_interfaces_with_snapshot(
            &InterfaceFilter::allow_all(),
            &lan_in_the_docker_range(),
        );
        assert_eq!(
            list,
            vec![Ipv4Addr::new(172, 20, 4, 17), Ipv4Addr::new(172, 16, 0, 5)]
        );
    }

    #[test]
    fn inside_a_container_eth0_is_the_interface() {
        // What `getifaddrs` reports inside a Docker container on the
        // default bridge: lo and eth0 on 172.17.0.2.
        let snapshot = InterfaceSnapshot::from_entries(vec![
            InterfaceEntry::new("lo", Ipv4Addr::LOCALHOST, 0, true, false, None),
            entry("eth0", [172, 17, 0, 2], false),
        ]);
        let filter = InterfaceFilter::allow_all();
        assert_eq!(
            multicast_interfaces_with_snapshot(&filter, &snapshot),
            vec![Ipv4Addr::new(172, 17, 0, 2)]
        );
        // The primary choice through the enumeration fallback: a name
        // filter, so the routing probe (an address of the machine running
        // the test, absent from this fixture) is refused. An address rule
        // must not skip 172.17.0.2 before the allowlist is read.
        assert_eq!(
            select_primary_interface(&InterfaceFilter::only_names(&["eth0"]), &snapshot),
            Ipv4Addr::new(172, 17, 0, 2)
        );
    }

    #[test]
    fn primary_ip_fallback_takes_the_lan_in_the_docker_range() {
        // Name filter: the routing probe (a real address of the machine
        // running the test) is not in this fixture, so the enumeration
        // fallback decides, and it must not skip 172.20.4.17.
        let filter = InterfaceFilter::only_names(&["enp3s0"]);
        assert_eq!(
            select_primary_interface(&filter, &lan_in_the_docker_range()),
            Ipv4Addr::new(172, 20, 4, 17)
        );
    }

    #[test]
    fn an_explicit_allowlist_admits_a_container_bridge() {
        let snapshot = lan_in_the_docker_range();
        let by_name = multicast_interfaces_with_snapshot(
            &InterfaceFilter::only_names(&["docker0"]),
            &snapshot,
        );
        assert_eq!(by_name, vec![Ipv4Addr::new(172, 17, 0, 1)]);
        assert_eq!(
            select_primary_interface(&InterfaceFilter::only_names(&["docker0"]), &snapshot),
            Ipv4Addr::new(172, 17, 0, 1)
        );
    }

    #[test]
    fn test_interface_allowed_permissive_short_circuits() {
        // A permissive filter must allow any IP without touching the snapshot
        // (pure fast path): an empty snapshot proves nothing was looked up.
        let filter = InterfaceFilter::allow_all();
        let snapshot = InterfaceSnapshot::default();
        assert!(interface_allowed(
            &filter,
            &snapshot,
            Ipv4Addr::new(203, 0, 113, 7)
        ));
    }

    #[test]
    fn test_interface_allowed_cidr_mismatch_rejects_unknown_ip() {
        // TEST-NET-3 address is not a local interface, so the name lookup
        // falls back to the pure CIDR check, which must reject it.
        let filter = InterfaceFilter::only_cidrs(&["10.0.0.0/8".parse().expect("valid CIDR")]);
        assert!(!interface_allowed(
            &filter,
            &synthetic(),
            Ipv4Addr::new(203, 0, 113, 7)
        ));
    }

    #[test]
    fn interface_allowed_by_name_through_snapshot() {
        let snapshot = synthetic();
        let filter = InterfaceFilter::only_names(&["eth0"]);
        assert!(interface_allowed(
            &filter,
            &snapshot,
            Ipv4Addr::new(192, 168, 1, 10)
        ));
        // The alias belongs to device eth0 too.
        assert!(interface_allowed(
            &filter,
            &snapshot,
            Ipv4Addr::new(192, 168, 3, 10)
        ));
        assert!(!interface_allowed(
            &filter,
            &snapshot,
            Ipv4Addr::new(10, 8, 0, 2)
        ));
    }

    #[test]
    fn multicast_interfaces_drop_docker_and_loopback_keep_tunnel() {
        // Parity: the docker bridge range is filtered here, the tunnel is
        // not (only the primary-IP choice rejects point-to-point).
        let list = multicast_interfaces_with_snapshot(&InterfaceFilter::allow_all(), &synthetic());
        assert_eq!(
            list,
            vec![
                Ipv4Addr::new(192, 168, 1, 10),
                Ipv4Addr::new(192, 168, 3, 10),
                Ipv4Addr::new(10, 8, 0, 2),
            ]
        );
    }

    #[test]
    fn multicast_interfaces_allowlist_by_name_label_and_cidr() {
        let snapshot = synthetic();
        // Device name matches the primary address AND the labelled alias.
        let by_name =
            multicast_interfaces_with_snapshot(&InterfaceFilter::only_names(&["eth0"]), &snapshot);
        assert_eq!(
            by_name,
            vec![
                Ipv4Addr::new(192, 168, 1, 10),
                Ipv4Addr::new(192, 168, 3, 10)
            ]
        );
        // Exact label matches only the alias.
        let by_label = multicast_interfaces_with_snapshot(
            &InterfaceFilter::only_names(&["eth0:1"]),
            &snapshot,
        );
        assert_eq!(by_label, vec![Ipv4Addr::new(192, 168, 3, 10)]);
        // CIDR matches by address.
        let by_cidr = multicast_interfaces_with_snapshot(
            &InterfaceFilter::only_cidrs(&["10.8.0.0/24".parse().expect("valid CIDR")]),
            &snapshot,
        );
        assert_eq!(by_cidr, vec![Ipv4Addr::new(10, 8, 0, 2)]);
        // Nothing matches: empty, no error.
        let none =
            multicast_interfaces_with_snapshot(&InterfaceFilter::only_names(&["eth9"]), &snapshot);
        assert!(none.is_empty());
    }

    #[test]
    fn multicast_interfaces_shared_address_checks_the_iterated_entry() {
        // Two entries share one IPv4 (legal on Linux). The allowlist names
        // only the second one's label: it must be admitted on its own label,
        // not rejected because the FIRST entry owning that address is eth0.
        let snapshot = InterfaceSnapshot::from_entries(vec![
            entry("eth0", [10, 0, 0, 1], false),
            entry("eth1:x", [10, 0, 0, 1], false),
        ]);
        let by_label = multicast_interfaces_with_snapshot(
            &InterfaceFilter::only_names(&["eth1:x"]),
            &snapshot,
        );
        assert_eq!(by_label, vec![Ipv4Addr::new(10, 0, 0, 1)]);
        // And the first entry's name still admits only the first entry.
        let by_name =
            multicast_interfaces_with_snapshot(&InterfaceFilter::only_names(&["eth0"]), &snapshot);
        assert_eq!(by_name, vec![Ipv4Addr::new(10, 0, 0, 1)]);
        // By address alone, the first owner in OS order answers (eth0).
        assert!(interface_allowed(
            &InterfaceFilter::only_names(&["eth0"]),
            &snapshot,
            Ipv4Addr::new(10, 0, 0, 1)
        ));
        assert!(!interface_allowed(
            &InterfaceFilter::only_names(&["eth1:x"]),
            &snapshot,
            Ipv4Addr::new(10, 0, 0, 1)
        ));
    }

    #[test]
    fn primary_ip_fallback_skips_tunnel_and_docker() {
        // Allowlist restricted to the tunnel and the LAN: whatever the routing
        // probe says, the enumeration fallback must prefer the LAN address
        // over the point-to-point one, and never pick docker0.
        //
        // Calls `select_primary_interface` directly, NOT
        // `get_primary_interface_ip_with_snapshot`: the latter checks
        // `resolve_forced_interface()` first, which reads `HDDS_INTERFACE`
        // through a process-lifetime `OnceLock`. If anything else in this
        // `--lib` test binary sets that variable (the discovery tests need
        // exactly that, see `test_support::network`), the wrapper would
        // short-circuit to the forced IP and this fixture would never be
        // consulted -- proven by reintroducing that call: this test then
        // asserted `127.0.0.1 == 192.168.1.10` and failed. Going straight to
        // the pure heuristic keeps this test's outcome a function of
        // `filter` and `snapshot` alone, regardless of what any other test
        // in the process does with the environment.
        let snapshot = InterfaceSnapshot::from_entries(vec![
            entry("docker0", [172, 17, 0, 1], false),
            entry("wg0", [10, 8, 0, 2], true),
            entry("eth0", [192, 168, 1, 10], false),
        ]);
        let filter = InterfaceFilter::only_names(&["wg0", "eth0"]);
        // The routing probe answers with a real address of this host: a
        // name-only filter accepts it only if it is a snapshot entry, i.e.
        // 192.168.1.10 itself; otherwise the fallback runs and picks eth0.
        let ip = select_primary_interface(&filter, &snapshot);
        assert_eq!(ip, Ipv4Addr::new(192, 168, 1, 10));
    }

    #[test]
    fn primary_ip_all_tunnels_uses_first() {
        // Same reasoning as `primary_ip_fallback_skips_tunnel_and_docker`
        // above: goes through `select_primary_interface` so `HDDS_INTERFACE`
        // (real or forced by another test sharing this process) cannot
        // intercept the call before the fixture is even consulted.
        let snapshot = InterfaceSnapshot::from_entries(vec![entry("wg0", [10, 8, 0, 2], true)]);
        let filter = InterfaceFilter::only_names(&["wg0"]);
        let ip = select_primary_interface(&filter, &snapshot);
        assert_eq!(ip, Ipv4Addr::new(10, 8, 0, 2));
    }

    #[test]
    fn test_resolve_interface_name_nonexistent() {
        // Adapted from test_resolve_interface_name_crate_nonexistent: the
        // crate fallback is gone, the snapshot answers for every platform.
        assert!(resolve_interface_name("nonexistent_iface_xyz").is_none());
    }

    #[test]
    fn test_get_primary_interface_ip_returns_valid() {
        // Should always return something (even if UNSPECIFIED)
        let ip = get_primary_interface_ip().expect("should not fail");
        // Just verify it doesn't crash; the actual IP depends on the machine
        let _ = ip;
    }
}
