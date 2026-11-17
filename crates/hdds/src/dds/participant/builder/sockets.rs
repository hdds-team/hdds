// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! UDP socket creation utilities for participant transport.
//!
//! This module provides low-level socket creation functions used during
//! participant initialization. Sockets are configured with appropriate
//! options (SO_REUSEADDR on the shared multicast ports, none on the
//! exclusive unicast ports) and bound to specific ports for RTPS communication.

use crate::config::{DATA_MULTICAST_OFFSET, MULTICAST_IP};
use crate::transport::multicast::{get_multicast_interfaces_filtered, resolve_forced_interface};
use crate::transport::options::ResolvedTransportOptions;
use crate::transport::socket_buffer::{apply_receive_buffer, ResolvedSocketBufferOptions};
use crate::transport::{dscp, ttl};
use socket2::{Domain, Protocol, Socket, Type};
use std::io;
use std::net::{Ipv4Addr, UdpSocket};

/// Apply TTL and user-data DSCP from the resolved transport options to a
/// user-data-carrying listener socket.
///
/// Defaults replicate the historical behavior: TTL multicast=1/unicast=64
/// (the kernel defaults / previous hardcoded values) and no TOS marking when
/// `dscp` is `None`. Both listener sockets created in this module carry user
/// data, so the `user_data` DSCP class applies.
fn apply_transport_options(socket: &UdpSocket, options: &ResolvedTransportOptions) {
    // Non-fatal: TTL/DSCP setsockopt failures are logged inside the helpers.
    let _ = ttl::apply_ttl_config(socket, &options.ttl);
    if let Some(dscp_config) = options.dscp {
        let _ = dscp::set_socket_dscp(socket, dscp_config.user_data);
    }
}

/// Create unicast socket for receiving SEDP and user data from remote peers.
///
/// Phase 1.6: a peer may send SEDP and user data to our unicast locator.
/// This socket listens on the user-data unicast port (7411 for domain 0,
/// participant 0).
///
/// `reserved`: the socket the participant-id auto-assignment already bound
/// on that port, handed over rather than closed and bound again (see
/// `UdpTransport::new_with_reserved_unicast`). `None` binds the port here.
/// Either way the port is EXCLUSIVE (`bind_exclusive_unicast`): a unicast
/// port shared by two sockets delivers each datagram to only one of them.
pub(super) fn create_unicast_socket(
    unicast_port: u16,
    options: &ResolvedTransportOptions,
    socket_buffers: &ResolvedSocketBufferOptions,
    reserved: Option<Socket>,
) -> io::Result<UdpSocket> {
    let socket2 = match reserved {
        Some(socket) => socket,
        // A bare `?` gave the caller an errno and nothing else, on a
        // participant that binds four sockets.
        None => crate::transport::udp::bind_exclusive_unicast(unicast_port).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!(
                    "binding the user-data UNICAST socket on port {unicast_port} failed: {e}. \
                     Unicast ports are exclusive (RTPS 2.5 9.6.1.1): another participant, in \
                     this process or another one, already uses this port. Choose another \
                     participant id (or other custom ports), or leave the id unset so that a \
                     free one is assigned"
                ),
            )
        })?,
    };
    // Size the receive buffer: this socket carries the user-data DATA_FRAG burst
    // of large RELIABLE samples.
    let (receive_bytes, explicit) = socket_buffers.data_receive_buffer();
    apply_receive_buffer(&socket2, receive_bytes, explicit, "user-data unicast");

    let socket: UdpSocket = socket2.into();

    // v0.8.1: Add read timeout for listener thread compatibility
    socket.set_read_timeout(Some(std::time::Duration::from_millis(100)))?;

    // Transport options: TTL + user-data DSCP (defaults = historical behavior)
    apply_transport_options(&socket, options);

    let local_addr = socket.local_addr()?;
    log::debug!(
        "[Unicast Socket] Bound to port {} for RTI SEDP/data reception (local_addr={})",
        unicast_port,
        local_addr
    );

    Ok(socket)
}

/// Create multicast socket for receiving user data sent to the default
/// user-data multicast locator.
///
/// DDSI-RTPS 2.5 9.6.2.2 (Table 9.16) sets the default user-traffic multicast
/// port to PB + DG*domainId + d2 (d2 = 1), so peers that publish user data to
/// the default multicast group 239.255.0.1 send it to port 7401 for domain 0.
/// This socket MUST listen on metatraffic_multicast + 1 (7401 for domain 0).
///
/// # Arguments
/// * `metatraffic_multicast` - The SPDP multicast port (e.g., 7400 for domain 0)
///
/// # Returns
/// A UDP socket bound to the data multicast port and joined to the multicast group.
pub(super) fn create_data_multicast_socket(
    domain_id: u32,
    metatraffic_multicast: u16,
    options: &ResolvedTransportOptions,
    socket_buffers: &ResolvedSocketBufferOptions,
) -> io::Result<UdpSocket> {
    let data_multicast_port = metatraffic_multicast + DATA_MULTICAST_OFFSET;

    // Create socket with SO_REUSEADDR
    let socket2 = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket2.set_reuse_address(true)?;
    // Size the receive buffer: this socket can carry user-data DATA_FRAG bursts
    // for vendors that publish large samples over multicast.
    let (receive_bytes, explicit) = socket_buffers.data_receive_buffer();
    apply_receive_buffer(&socket2, receive_bytes, explicit, "user-data multicast");

    // HDDS_REUSEPORT escape hatch, mirrored from transport/udp.rs so the two files agree:
    // every multicast socket must consult it, or the documented escape hatch could not
    // fix macOS even when set (the failure moves to whichever socket ignores it).
    #[cfg(unix)]
    let reuseport_enabled = std::env::var("HDDS_REUSEPORT")
        .map(|v| v == "1")
        .unwrap_or(false);
    #[cfg(unix)]
    if reuseport_enabled {
        crate::transport::udp::set_reuseport(&socket2)?;
        log::info!(
            "[Data Multicast] SO_REUSEPORT enabled via HDDS_REUSEPORT=1 (multi-process mode)"
        );
    }
    // BSD-family kernels (Darwin included) refuse to share this exact port across
    // participants with SO_REUSEADDR alone ("Address already in use", os error 48 on Darwin).
    // Unconditional here -- not gated behind HDDS_REUSEPORT -- because every participant on a
    // domain binds this identical user-data multicast port as the ordinary case, not as opt-in
    // multi-process sharing; see the matching block and its longer rationale in
    // transport/udp.rs next to the metatraffic multicast socket. This cfg is absent entirely on
    // Linux, so the Linux build does not contain this branch at all. NOT YET verified against a
    // remote peer on macOS.
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    ))]
    if !reuseport_enabled {
        crate::transport::udp::set_reuseport(&socket2)?;
        log::info!(
            "[Data Multicast] SO_REUSEPORT enabled unconditionally on this platform \
             (SO_REUSEADDR alone does not permit two participants to share this port on \
             BSD-family kernels)"
        );
    }
    #[cfg(not(unix))]
    if std::env::var("HDDS_REUSEPORT")
        .map(|v| v == "1")
        .unwrap_or(false)
    {
        log::info!(
            "[Data Multicast] HDDS_REUSEPORT=1 ignored on this platform: SO_REUSEPORT is \
             unix-only, SO_REUSEADDR is already set"
        );
    }

    // Bind to data multicast port
    let bind_addr = format!("0.0.0.0:{}", data_multicast_port);
    let bind_sockaddr: std::net::SocketAddr = bind_addr.parse().map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Invalid data multicast bind address: {}", e),
        )
    })?;
    // A bare `?` here surfaced as `Address already in use (os error 98)` with
    // no port, no role and no hint. bootstrap.rs probes this exact port (and
    // the metatraffic multicast one) before committing to a participant id,
    // and fails fast with a message naming both port and domain, so reaching
    // this bind at all means either the probe was inconclusive (SO_REUSEADDR itself was
    // refused, e.g. a sandboxed setsockopt filter) or something grabbed the
    // port in the window between that probe and this bind. Either way the
    // caller still gets the domain and port named here, not a bare errno.
    // SO_REUSEADDR is set above, so a conflict means the holder did not set it.
    socket2.bind(&bind_sockaddr.into()).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!(
                "binding the user-data MULTICAST socket on port {data_multicast_port} \
                 (domain {domain_id}) failed: {e}. This socket sets SO_REUSEADDR, so \
                 another process holds that port without it. No participant id on this \
                 domain can avoid it: the multicast ports are the same for every \
                 participant id (RTPS v2.5 formula is domain-only)"
            ),
        )
    })?;

    let socket: UdpSocket = socket2.into();

    // Join the multicast group (239.255.0.1)
    // Resilient: track successes, fallback to UNSPECIFIED if all per-interface joins fail
    // (common on Windows with Hyper-V/WSL/Docker virtual adapters)
    let multicast_group = Ipv4Addr::from(MULTICAST_IP);
    // HDDS_INTERFACE forces this join onto one interface, as it does the
    // SPDP/SEDP joins (`join_multicast_group_with_snapshot`): the list below
    // leaves that override to its caller.
    let interfaces = match resolve_forced_interface() {
        Some(ip) => vec![ip],
        None => get_multicast_interfaces_filtered(&options.interface_allowlist)?,
    };
    let mut any_joined = false;

    if interfaces.is_empty() {
        match socket.join_multicast_v4(&multicast_group, &Ipv4Addr::UNSPECIFIED) {
            Ok(()) => {
                any_joined = true;
                log::debug!(
                    "[Data Multicast] join_multicast_v4({}) on UNSPECIFIED",
                    multicast_group
                );
            }
            Err(e) => {
                log::warn!(
                    "[Data Multicast] join_multicast_v4({}) on UNSPECIFIED failed: {}",
                    multicast_group,
                    e
                );
            }
        }
    } else {
        for iface in &interfaces {
            match socket.join_multicast_v4(&multicast_group, iface) {
                Ok(()) => {
                    any_joined = true;
                    log::debug!(
                        "[Data Multicast] join_multicast_v4({}) on interface {}",
                        multicast_group,
                        iface
                    );
                }
                Err(e) if e.raw_os_error() == Some(98) => {
                    // EADDRINUSE: already joined
                    any_joined = true;
                    log::debug!(
                        "[Data Multicast] join_multicast_v4({}) on {} - already joined, skipping",
                        multicast_group,
                        iface
                    );
                }
                Err(e) => {
                    // Non-fatal: skip interfaces that can't join multicast
                    // Windows 10049 (WSAEADDRNOTAVAIL): adapter doesn't support multicast
                    // Windows 10065 (WSAEHOSTUNREACH): no route to multicast group
                    log::debug!(
                        "[Data Multicast] join_multicast_v4({}) on {} failed (non-fatal): {}",
                        multicast_group,
                        iface,
                        e
                    );
                }
            }
        }

        // Fallback: if ALL interface joins failed, try UNSPECIFIED
        if !any_joined {
            log::warn!(
                "[Data Multicast] All per-interface joins failed, trying UNSPECIFIED fallback"
            );
            if socket
                .join_multicast_v4(&multicast_group, &Ipv4Addr::UNSPECIFIED)
                .is_ok()
            {
                any_joined = true;
                log::debug!(
                    "[Data Multicast] join_multicast_v4({}) on UNSPECIFIED (fallback)",
                    multicast_group
                );
            }
        }
    }

    if !any_joined {
        log::warn!(
            "[Data Multicast] WARNING: Could not join multicast group! User data multicast reception may not work."
        );
    }

    // Enable multicast loopback for intra-machine testing
    socket.set_multicast_loop_v4(true)?;

    // Transport options: TTL + user-data DSCP. Replaces the historical
    // hardcoded set_multicast_ttl_v4(1) -- the default multicast TTL is
    // still 1, so unconfigured behavior is unchanged.
    apply_transport_options(&socket, options);

    // Add read timeout for listener thread compatibility
    socket.set_read_timeout(Some(std::time::Duration::from_millis(100)))?;

    let local_addr = socket.local_addr()?;
    log::debug!(
        "[Data Multicast] Bound to port {} for CycloneDDS/FastDDS user data reception (local_addr={})",
        data_multicast_port,
        local_addr
    );

    Ok(socket)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::domains::unique_domain;
    use crate::transport::socket_buffer::SocketBufferOptions;
    use crate::transport::{PortMapping, TransportOptions};
    use socket2::SockRef;
    use std::num::NonZeroUsize;

    /// This socket has the same sharing requirement as
    /// `transport::udp`'s metatraffic multicast socket. Every participant on
    /// a domain binds this identical user-data multicast port too
    /// (metatraffic + `DATA_MULTICAST_OFFSET`), so this function must consult
    /// `HDDS_REUSEPORT` as well -- otherwise the documented escape hatch
    /// could not reach it even when set, and the Darwin failure would move
    /// here from the other socket.
    ///
    /// What this test PROVES on Linux: SO_REUSEADDR alone is
    /// enough here, and the fix (the `cfg(target_os)` block right above
    /// `create_data_multicast_socket`'s bind call, forcing SO_REUSEPORT on
    /// BSD-family kernels) does not disturb that -- it compiles to nothing
    /// on Linux.
    ///
    /// What this test CANNOT prove: Darwin's "Address already in use" (os
    /// error 48) for this exact socket. Only a run on a macOS host
    /// exercises that branch.
    #[test]
    fn two_participants_share_the_data_multicast_port() {
        let domain = unique_domain();
        let mapping = PortMapping::calculate(domain.id(), 0).expect("port mapping");
        let transport_options = TransportOptions::default().resolve();
        let socket_buffers = SocketBufferOptions::default().resolve_with_env(None, None);

        let first = create_data_multicast_socket(
            domain.id(),
            mapping.metatraffic_multicast,
            &transport_options,
            &socket_buffers,
        );
        assert!(
            first.is_ok(),
            "first participant should bind the data multicast socket: {:?}",
            first.err()
        );
        let _first = first.expect("checked above");

        let second = create_data_multicast_socket(
            domain.id(),
            mapping.metatraffic_multicast,
            &transport_options,
            &socket_buffers,
        );
        assert!(
            second.is_ok(),
            "second participant on the SAME domain must also bind the identical data \
             multicast port while the first is still alive -- this is the \
             socket that never consulted HDDS_REUSEPORT at all before this fix. {:?}",
            second.err()
        );
    }

    #[test]
    fn explicit_receive_buffer_reaches_user_data_listener() {
        const REQUESTED: usize = 64 * 1024;
        let transport_options = TransportOptions::default().resolve();
        let socket_buffers = SocketBufferOptions::default()
            .with_receive_buffer_size(NonZeroUsize::new(REQUESTED).unwrap())
            .resolve_with_env(None, None);

        let socket = create_unicast_socket(0, &transport_options, &socket_buffers, None)
            .expect("user-data listener socket");

        assert!(
            SockRef::from(&socket).recv_buffer_size().unwrap() >= REQUESTED,
            "SO_RCVBUF must reach the user-data listener socket"
        );
    }
}
