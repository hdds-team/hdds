// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! UDP socket creation utilities for participant transport.
//!
//! This module provides low-level socket creation functions used during
//! participant initialization. Sockets are configured with appropriate
//! options (SO_REUSEADDR) and bound to specific ports for RTPS communication.

use crate::config::{DATA_MULTICAST_OFFSET, MULTICAST_IP};
use crate::transport::multicast::get_multicast_interfaces;
use socket2::{Domain, Protocol, Socket, Type};
use std::io;
use std::net::{Ipv4Addr, UdpSocket};

/// Create unicast socket for receiving SEDP and user data from RTI.
///
/// Phase 1.6: RTI sends SEDP and Temperature data to our unicast locator.
/// This socket MUST listen on metatraffic_unicast_port (7410 for domain 0).
pub(super) fn create_unicast_socket(unicast_port: u16) -> io::Result<UdpSocket> {
    // Create socket with SO_REUSEADDR
    let socket2 = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket2.set_reuse_address(true)?;

    // Bind to unicast port
    let bind_addr = format!("0.0.0.0:{}", unicast_port);
    let bind_sockaddr: std::net::SocketAddr = bind_addr.parse().map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Invalid unicast bind address: {}", e),
        )
    })?;
    socket2.bind(&bind_sockaddr.into())?;

    let socket: UdpSocket = socket2.into();

    // v0.8.1: Add read timeout for listener thread compatibility
    socket.set_read_timeout(Some(std::time::Duration::from_millis(100)))?;

    let local_addr = socket.local_addr()?;
    log::debug!(
        "[Unicast Socket] Bound to port {} for RTI SEDP/data reception (local_addr={})",
        unicast_port,
        local_addr
    );

    Ok(socket)
}

/// Create multicast socket for receiving user data from CycloneDDS/FastDDS.
///
/// CycloneDDS and FastDDS send user data to 239.255.0.1:7401 (non-standard, but common).
/// This socket MUST listen on metatraffic_multicast + 1 (7401 for domain 0).
///
/// # Arguments
/// * `metatraffic_multicast` - The SPDP multicast port (e.g., 7400 for domain 0)
///
/// # Returns
/// A UDP socket bound to the data multicast port and joined to the multicast group.
pub(super) fn create_data_multicast_socket(metatraffic_multicast: u16) -> io::Result<UdpSocket> {
    let data_multicast_port = metatraffic_multicast + DATA_MULTICAST_OFFSET;

    // Create socket with SO_REUSEADDR
    let socket2 = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket2.set_reuse_address(true)?;

    // Bind to data multicast port
    let bind_addr = format!("0.0.0.0:{}", data_multicast_port);
    let bind_sockaddr: std::net::SocketAddr = bind_addr.parse().map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Invalid data multicast bind address: {}", e),
        )
    })?;
    socket2.bind(&bind_sockaddr.into())?;

    let socket: UdpSocket = socket2.into();

    // Join the multicast group (239.255.0.1)
    let multicast_group = Ipv4Addr::from(MULTICAST_IP);
    let interfaces = get_multicast_interfaces()?;

    if interfaces.is_empty() {
        socket.join_multicast_v4(&multicast_group, &Ipv4Addr::UNSPECIFIED)?;
        log::debug!(
            "[Data Multicast] join_multicast_v4({}) on UNSPECIFIED",
            multicast_group
        );
    } else {
        for iface in &interfaces {
            match socket.join_multicast_v4(&multicast_group, iface) {
                Ok(()) => {
                    log::debug!(
                        "[Data Multicast] join_multicast_v4({}) on interface {}",
                        multicast_group,
                        iface
                    );
                }
                Err(e) if e.raw_os_error() == Some(98) => {
                    // EADDRINUSE: already joined
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
    }

    // Enable multicast loopback for intra-machine testing
    socket.set_multicast_loop_v4(true)?;
    let _ = socket.set_multicast_ttl_v4(1);

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
