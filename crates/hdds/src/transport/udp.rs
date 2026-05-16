// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! UDP transport for RTPS multicast send/receive.
//!
//! Consolidates socket management, multicast configuration, and send/receive operations.

use crate::config::{MULTICAST_GROUP, SEDP_UNICAST_OFFSET};
use crate::core::string_utils::format_string;
use crate::transport::multicast::{
    get_primary_interface_ip, get_unicast_locators, join_multicast_group, resolve_forced_interface,
};
use crate::transport::ttl::{self, TtlConfig};
use crate::transport::PortMapping;
use socket2::{Domain, Protocol, Socket, Type};
use std::io;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::Arc;

/// UDP Transport for bidirectional multicast communication.
///
/// Manages a single UDP socket shared between writers (send) and listeners (receive).
/// Enables multicast loopback for intra-machine pub/sub.
#[allow(clippy::module_name_repetitions)]
pub struct UdpTransport {
    /// RTPS domain ID (for debugging/introspection)
    #[allow(dead_code)]
    pub(super) domain_id: u32,
    /// RTPS participant ID (for debugging/introspection)
    #[allow(dead_code)]
    pub(super) participant_id: u8,
    /// Shared UDP socket (Arc for multi-thread access) - multicast/metatraffic
    pub(super) socket: Arc<UdpSocket>,
    /// Metatraffic unicast socket (bound to 7410 for SEDP/ACKNACK unicast sends)
    pub(super) metatraffic_unicast_socket: Arc<UdpSocket>,
    /// User data unicast socket (bound to 7411 for USER DATA unicast sends) v103
    pub(super) user_unicast_socket: Arc<UdpSocket>,
    /// Multicast destination address for SPDP (239.255.0.1:7400)
    pub(super) multicast_addr: SocketAddr,
    /// Multicast destination address for SEDP (239.255.0.1:7400, RTI compatible)
    pub(super) sedp_multicast_addr: SocketAddr,
    /// Multicast address for user DATA (239.255.0.1:7401 for domain 0)
    /// RTPS spec: PB + DG*domainId + d2, where d2=1
    pub(super) data_multicast_addr: SocketAddr,
    /// Interface used for multicast (if specified via env)
    pub(super) iface: Ipv4Addr,
    /// Metatraffic unicast port for SEDP/discovery (e.g., 7410 for domain 0)
    pub(super) metatraffic_unicast_port: u16,
    /// TTL configuration (multicast/unicast)
    pub(super) ttl_config: TtlConfig,
}

// ===== Construction (builder functionality) =====

impl UdpTransport {
    /// Create new UDP transport with RTPS v2.5 port mapping.
    ///
    /// Binds to the metatraffic multicast port and joins the standard multicast group.
    pub fn new(domain_id: u32, participant_id: u8, mapping: PortMapping) -> io::Result<Self> {
        crate::trace_fn!("UdpTransport::new");
        // Create socket with SO_REUSEADDR for port reuse.
        // We deliberately do NOT use SO_REUSEPORT by default because:
        // 1. RTI Connext doesn't use SO_REUSEPORT
        // 2. On Linux, if ANY process uses SO_REUSEPORT on a port, ALL processes must use it
        // 3. Using SO_REUSEPORT would make HDDS incompatible with RTI on same machine
        // 4. Multicast on localhost has kernel limitations even with SO_REUSEPORT
        // 5. Proper interop testing requires separate machines/VMs with real network routing
        //
        // v242: Set HDDS_REUSEPORT=1 to enable SO_REUSEPORT for multi-process HDDS<->HDDS
        // on the same machine. This breaks RTI interop but enables local multi-process discovery.
        let socket2 = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        socket2.set_reuse_address(true)?;
        let reuseport_enabled = std::env::var("HDDS_REUSEPORT")
            .map(|v| v == "1")
            .unwrap_or(false);
        #[cfg(unix)]
        if reuseport_enabled {
            set_reuseport(&socket2)?;
            log::info!("[UDP] SO_REUSEPORT enabled via HDDS_REUSEPORT=1 (multi-process mode)");
        }

        let bind_addr = parse_socket_addr(
            format_string(format_args!("0.0.0.0:{}", mapping.metatraffic_multicast)),
            "bind address",
        )?;
        socket2.bind(&bind_addr.into())?;
        log::debug!(
            "[UDP] transport bind addr={} domain={} participant_id={}",
            bind_addr,
            domain_id,
            participant_id
        );

        // Compute primary IP early — needed for IP_MULTICAST_IF before socket conversion.
        // HDDS_INTERFACE forces everything onto one interface — no probing needed.
        let forced_ip = resolve_forced_interface();
        let primary_ip = forced_ip.unwrap_or(get_primary_interface_ip()?);

        // Set IP_MULTICAST_IF so outgoing multicast goes through the correct interface.
        // Without this, the kernel sends via the default route which may be a VPN tunnel
        // (e.g. CloudflareWARP 172.16.0.2) instead of the real LAN interface.
        //
        // Probe: CloudflareWARP hijacks all multicast routes and returns EPERM for sends
        // on non-WARP interfaces. If the probe send fails, revert to default routing.
        if !primary_ip.is_unspecified() {
            if let Ok(()) = socket2.set_multicast_if_v4(&primary_ip) {
                let probe_dst: SocketAddr = SocketAddr::new(
                    std::net::IpAddr::V4(Ipv4Addr::new(239, 255, 0, 1)),
                    1, // discard port, no listener needed
                );
                match socket2.send_to(&[0], &probe_dst.into()) {
                    Ok(_) => log::debug!(
                        "[UDP] IP_MULTICAST_IF={} verified (multicast send OK)",
                        primary_ip
                    ),
                    Err(_) if forced_ip.is_some() => {
                        // User explicitly forced this interface via HDDS_INTERFACE.
                        // Don't revert -- trust the user's choice even if probe fails.
                        log::warn!(
                            "[UDP] IP_MULTICAST_IF={} probe failed but HDDS_INTERFACE is set -- keeping forced interface.",
                            primary_ip
                        );
                    }
                    Err(_) => {
                        // EPERM or similar: VPN/tunnel policy blocks multicast on this interface.
                        // Revert to UNSPECIFIED so the kernel uses its default route.
                        let _ = socket2.set_multicast_if_v4(&Ipv4Addr::UNSPECIFIED);
                        log::warn!(
                            "[UDP] IP_MULTICAST_IF={} blocked (VPN/tunnel policy?), reverting to default. \
                             Set HDDS_INTERFACE to force a specific interface.",
                            primary_ip
                        );
                    }
                }
            }
        }

        let socket: UdpSocket = socket2.into();
        let iface = match join_multicast_group(&socket) {
            Ok(iface) => {
                log::debug!(
                    "[UDP] join_multicast_group success multicast=239.255.0.1 iface={}",
                    iface
                );
                iface
            }
            Err(err) => {
                log::debug!(
                    "[UDP] join_multicast_group failed multicast=239.255.0.1 err={}",
                    err
                );
                return Err(err);
            }
        };

        // v133: Create second socket bound to metatraffic_unicast port (7410)
        // This ensures unicast SEDP/ACKNACK packets have correct source port per RTPS v2.5 Sec.9.6.1
        //
        // v133 FIX: Bind to 0.0.0.0:7410 instead of primary_ip:7410.
        // Reason: If we bind to specific IP, Linux delivers incoming packets to THAT socket
        // and NOT to any wildcard listener on 0.0.0.0:7410. Since we now use the same socket
        // for both sending AND receiving (via MulticastListener), binding to 0.0.0.0
        // ensures we can receive from any interface while still sending with correct source port.
        //
        // The original v73 comment about "send issues on multi-interface machines" was about
        // routing when using connect(), but we use send_to() which specifies destination directly.
        let unicast_socket2 = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        unicast_socket2.set_reuse_address(true)?;
        #[cfg(unix)]
        if reuseport_enabled {
            set_reuseport(&unicast_socket2)?;
        }
        let unicast_bind_addr = parse_socket_addr(
            format_string(format_args!("0.0.0.0:{}", mapping.metatraffic_unicast)),
            "metatraffic unicast bind address",
        )?;
        unicast_socket2.bind(&unicast_bind_addr.into())?;
        log::debug!(
            "[UDP] v133: Created metatraffic_unicast_socket bound to 0.0.0.0:{} (for SEDP/ACKNACK send+recv) [primary_ip={}]",
            mapping.metatraffic_unicast,
            primary_ip
        );
        let metatraffic_unicast_socket: UdpSocket = unicast_socket2.into();

        // v104: Create user data unicast socket (NOT BOUND - let OS choose ephemeral port)
        // We should NOT bind the send socket to port 7411 because the listener is already on 7411
        let user_socket2 = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        user_socket2.set_reuse_address(true)?;
        #[cfg(unix)]
        if reuseport_enabled {
            set_reuseport(&user_socket2)?;
        }
        // v104: Bind to primary IP with port 0 (OS will assign ephemeral port)
        // Windows fix: if primary_ip is a virtual adapter (Hyper-V, WSL, Docker),
        // bind may fail with WSAEADDRNOTAVAIL (10049). Fall back to 0.0.0.0:0.
        let user_unicast_bind_addr = parse_socket_addr(
            format_string(format_args!("{}:0", primary_ip)),
            "user unicast bind address",
        )?;
        let user_unicast_socket: UdpSocket = match user_socket2.bind(&user_unicast_bind_addr.into())
        {
            Ok(()) => user_socket2.into(),
            Err(e) => {
                log::warn!(
                    "[UDP] bind({}:0) failed ({}), falling back to 0.0.0.0:0",
                    primary_ip,
                    e
                );
                let fallback = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
                fallback.set_reuse_address(true)?;
                #[cfg(unix)]
                if reuseport_enabled {
                    set_reuseport(&fallback)?;
                }
                let any_addr = parse_socket_addr("0.0.0.0:0".to_string(), "user unicast fallback")?;
                fallback.bind(&any_addr.into())?;
                fallback.into()
            }
        };
        let actual_port = user_unicast_socket.local_addr()?.port();
        log::debug!(
            "[UDP] v104: Created user_unicast_socket bound to {}:{} (ephemeral port for USER DATA sends)",
            user_unicast_socket
                .local_addr()
                .map(|a| a.ip().to_string())
                .unwrap_or_else(|_| primary_ip.to_string()),
            actual_port
        );

        let multicast_addr = parse_multicast_addr(mapping.metatraffic_multicast, "SPDP")?;
        let sedp_multicast_addr = parse_sedp_multicast_addr(mapping.sedp_multicast, "SEDP")?;
        // RTPS v2.5 Sec.9.6.1.1: user data multicast = PB + DG*domainId + d2 (d2=1)
        let data_multicast_addr = parse_multicast_addr(mapping.metatraffic_multicast + 1, "DATA")?;

        // Apply TTL configuration from environment or defaults
        let ttl_config = TtlConfig::from_env();
        ttl::apply_ttl_config(&socket, &ttl_config)?;
        ttl::apply_ttl_config(&metatraffic_unicast_socket, &ttl_config)?;
        ttl::apply_ttl_config(&user_unicast_socket, &ttl_config)?;

        log::debug!(
            "[UDP] transport metatraffic_unicast_port={} data_multicast={} (for SPDP locators)",
            mapping.metatraffic_unicast,
            data_multicast_addr
        );

        Ok(Self {
            domain_id,
            participant_id,
            socket: Arc::new(socket),
            metatraffic_unicast_socket: Arc::new(metatraffic_unicast_socket),
            user_unicast_socket: Arc::new(user_unicast_socket),
            multicast_addr,
            sedp_multicast_addr,
            data_multicast_addr,
            iface,
            metatraffic_unicast_port: mapping.metatraffic_unicast,
            ttl_config,
        })
    }

    /// Create transport with custom port (legacy/testing helper).
    #[deprecated(since = "0.4.0", note = "Use new() with PortMapping instead")]
    // @audit-ok: Sequential initialization (cyclo 13, cogni 0) - linear socket setup without branching
    pub fn with_port(port: u16) -> io::Result<Self> {
        let forced_ip = resolve_forced_interface();
        let primary_ip = forced_ip.unwrap_or(get_primary_interface_ip()?);

        let sock2 = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        sock2.set_reuse_address(true)?;
        let bind_addr: SocketAddr = format_string(format_args!("0.0.0.0:{}", port))
            .parse()
            .map_err(|e: std::net::AddrParseError| {
                io::Error::new(io::ErrorKind::InvalidInput, e.to_string())
            })?;
        sock2.bind(&bind_addr.into())?;
        if !primary_ip.is_unspecified() {
            if let Ok(()) = sock2.set_multicast_if_v4(&primary_ip) {
                let probe_dst: SocketAddr =
                    SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(239, 255, 0, 1)), 1);
                if sock2.send_to(&[0], &probe_dst.into()).is_err() {
                    let _ = sock2.set_multicast_if_v4(&Ipv4Addr::UNSPECIFIED);
                }
            }
        }
        let socket: UdpSocket = sock2.into();
        let iface = join_multicast_group(&socket)?;

        // v133: Create unicast socket bound to 0.0.0.0:port for both send AND recv
        // Now used by MulticastListener for receiving SEDP unicast traffic
        let unicast_port = port + SEDP_UNICAST_OFFSET; // Legacy: SEDP offset from base port
        let unicast_bind_addr = format_string(format_args!("0.0.0.0:{}", unicast_port));
        log::debug!(
            "[UDP] v133: Binding metatraffic_unicast_socket to {} (for send+recv) [primary_ip={}]",
            unicast_bind_addr,
            primary_ip
        );
        let metatraffic_unicast_socket = UdpSocket::bind(&unicast_bind_addr)?;

        // v104: Create user data unicast socket with ephemeral port (NOT bound to 7411)
        // Binding to port 7411 conflicts with the listener on same port
        // Windows fix: fall back to 0.0.0.0:0 if primary_ip bind fails (virtual adapters)
        let user_unicast_bind_addr = format_string(format_args!("{}:0", primary_ip));
        let user_unicast_socket = match UdpSocket::bind(&user_unicast_bind_addr) {
            Ok(s) => s,
            Err(e) => {
                log::warn!(
                    "[UDP] bind({}:0) failed ({}), falling back to 0.0.0.0:0",
                    primary_ip,
                    e
                );
                UdpSocket::bind("0.0.0.0:0")?
            }
        };
        let actual_port = user_unicast_socket.local_addr()?.port();
        log::debug!(
            "[UDP] v104: Binding user_unicast_socket to {}:{} (ephemeral) for USER DATA sends",
            user_unicast_socket
                .local_addr()
                .map(|a| a.ip().to_string())
                .unwrap_or_else(|_| primary_ip.to_string()),
            actual_port
        );

        let multicast_addr = parse_multicast_addr(port, "legacy SPDP")?;
        let sedp_multicast_addr = parse_sedp_multicast_addr(port, "legacy SEDP")?;
        let data_multicast_addr = parse_multicast_addr(port + 1, "legacy DATA")?;

        // Apply TTL configuration
        let ttl_config = TtlConfig::from_env();
        ttl::apply_ttl_config(&socket, &ttl_config)?;
        ttl::apply_ttl_config(&metatraffic_unicast_socket, &ttl_config)?;
        ttl::apply_ttl_config(&user_unicast_socket, &ttl_config)?;

        Ok(Self {
            domain_id: 0,
            participant_id: 0,
            socket: Arc::new(socket),
            metatraffic_unicast_socket: Arc::new(metatraffic_unicast_socket),
            user_unicast_socket: Arc::new(user_unicast_socket),
            multicast_addr,
            sedp_multicast_addr,
            data_multicast_addr,
            metatraffic_unicast_port: unicast_port,
            iface,
            ttl_config,
        })
    }
}

// ===== Send operations =====

impl UdpTransport {
    /// Send data to SPDP multicast group (metatraffic port, e.g. 7400).
    pub fn send(&self, data: &[u8]) -> io::Result<()> {
        crate::trace_fn!("UdpTransport::send");
        let dest = self.multicast_addr;

        log::debug!("[UDP] send attempt dest={} len={}", dest, data.len(),);

        let sent = match self.socket.send_to(data, dest) {
            Ok(n) => n,
            Err(err) => {
                log::debug!(
                    "[UDP] send error={} dest={} len={} iface={}",
                    err,
                    dest,
                    data.len(),
                    self.format_iface()
                );
                return Err(err);
            }
        };

        if Self::should_log_debug() {
            let kind = Self::parse_submessage_kind(data);
            log::debug!(
                "[hdds/udp] send kind={} -> {} len={} iface={}",
                kind,
                dest,
                sent,
                self.format_iface()
            );
        }

        Ok(())
    }

    /// Send user DATA to data multicast group (port 7401 for domain 0).
    /// RTPS v2.5: user data multicast = PB + DG*domainId + d2 (d2=1).
    pub fn send_user_data_multicast(&self, data: &[u8]) -> io::Result<()> {
        crate::trace_fn!("UdpTransport::send_user_data_multicast");
        let dest = self.data_multicast_addr;

        let sent = match self.socket.send_to(data, dest) {
            Ok(n) => n,
            Err(err) => {
                log::debug!(
                    "[UDP] send_user_data_multicast error={} dest={} len={}",
                    err,
                    dest,
                    data.len()
                );
                return Err(err);
            }
        };

        log::debug!(
            "[UDP] send_user_data_multicast -> {} len={} iface={}",
            dest,
            sent,
            self.format_iface()
        );

        Ok(())
    }

    /// Send SEDP data to dedicated multicast port (Phase 1.6).
    ///
    /// Sends endpoint discovery packets to 239.255.0.1:7400 (SEDP multicast address, RTI compatible).
    pub fn send_sedp(&self, data: &[u8]) -> io::Result<()> {
        crate::trace_fn!("UdpTransport::send_sedp");
        log::debug!(
            "[UDP-SEDP] Attempting to send {} bytes to {}",
            data.len(),
            self.sedp_multicast_addr
        );

        // Phase 1.6 DEBUG: Dump first 64 bytes of packet to verify structure
        log::debug!("[UDP-SEDP] [?] Packet hex dump (first 64 bytes):");
        let dump_len = std::cmp::min(64, data.len());
        for chunk in data[..dump_len].chunks(16) {
            let hex: String = chunk.iter().map(|b| format!("{:02x} ", b)).collect();
            log::debug!("  {}", hex);
        }

        // Verify RTPS header (20 bytes: 4 magic + 2 version + 2 vendor + 12 GUID prefix)
        // plus at least one 4-byte submessage header (kind + flags + length).
        if data.len() >= 24 {
            log::debug!("[UDP-SEDP] [?] Packet analysis:");
            log::debug!(
                "  Magic: {:?}",
                std::str::from_utf8(&data[0..4]).unwrap_or("???")
            );
            log::debug!("  Version: {}.{}", data[4], data[5]);
            log::debug!("  Vendor: {:02x}.{:02x}", data[6], data[7]);
            log::debug!("  GUID prefix (12 bytes): {:02x?}", &data[8..20]);
            log::debug!(
                "  Submessage ID: 0x{:02x} ({})",
                data[20],
                Self::submessage_kind_name(data[20])
            );
            log::debug!("  Flags: 0x{:02x}", data[21]);
            let octets = u16::from_le_bytes([data[22], data[23]]);
            log::debug!("  octetsToNextHeader: {}", octets);
        }

        let sent = self.socket.send_to(data, self.sedp_multicast_addr)?;

        log::debug!(
            "[UDP-SEDP] [OK] Sent {} bytes to {} (iface={})",
            sent,
            self.sedp_multicast_addr,
            self.format_iface()
        );

        Ok(())
    }

    /// Send data to specific unicast endpoint (METATRAFFIC: SEDP, ACKNACK).
    ///
    /// v73: Uses metatraffic_unicast_socket (port 7410) for correct source port
    /// per RTPS v2.5 Sec.9.6.1 port mapping.
    pub fn send_to_endpoint(&self, data: &[u8], endpoint: &SocketAddr) -> io::Result<usize> {
        crate::trace_fn!("UdpTransport::send_to_endpoint");
        // v73: Use dedicated unicast socket bound to 7410 for RTPS spec compliance
        let sent = self.metatraffic_unicast_socket.send_to(data, endpoint)?;

        if Self::should_log_debug() {
            let kind = Self::parse_submessage_kind(data);
            log::debug!(
                "[hdds/udp] v73: send_unicast kind={} -> {} len={} src_port=7410 iface={}",
                kind,
                endpoint,
                sent,
                self.format_iface()
            );
        }

        Ok(sent)
    }

    /// Send user data (Temperature, etc.) to specific unicast endpoint.
    ///
    /// v104: Uses user_unicast_socket (ephemeral port) for USER DATA per RTPS v2.5 Sec.9.6.1.
    /// USER DATA must not use metatraffic_unicast_socket (port 7410).
    pub fn send_user_data_unicast(&self, data: &[u8], endpoint: &SocketAddr) -> io::Result<usize> {
        crate::trace_fn!("UdpTransport::send_user_data_unicast");
        let sent = self.user_unicast_socket.send_to(data, endpoint)?;

        if Self::should_log_debug() {
            let src_port = self
                .user_unicast_socket
                .local_addr()
                .map(|addr| addr.port())
                .unwrap_or(0);
            log::debug!(
                "[hdds/udp] v104: send_user_data_unicast -> {} len={} src_port={} iface={}",
                endpoint,
                sent,
                src_port,
                self.format_iface()
            );
        }

        Ok(sent)
    }
}

// ===== Accessors =====

impl UdpTransport {
    /// Get unicast locators for SPDP announcements.
    ///
    /// Returns a list of SocketAddr (IP:port) for unicast communication.
    /// RTI and other DDS implementations use these locators to send SEDP
    /// and user data directly to this participant.
    pub fn get_unicast_locators(&self) -> Vec<SocketAddr> {
        crate::trace_fn!("UdpTransport::get_unicast_locators");
        get_unicast_locators(self.iface, self.metatraffic_unicast_port)
    }

    /// Get user data unicast locators for SEDP announcements.
    ///
    /// Returns a list of SocketAddr (IP:port) for user data communication.
    /// RTI and other DDS implementations use these locators to send user data
    /// directly to this participant.
    pub fn get_user_unicast_locators(&self, user_port: u16) -> Vec<SocketAddr> {
        get_unicast_locators(self.iface, user_port)
    }

    /// Get shared socket reference for MulticastListener.
    #[must_use]
    pub fn socket(&self) -> Arc<UdpSocket> {
        Arc::clone(&self.socket)
    }

    /// Get metatraffic unicast socket reference for SEDP reception.
    ///
    /// v131: This socket is bound to the primary interface IP (e.g. 192.168.1.22:7410)
    /// and should be used for BOTH sending AND receiving SEDP unicast traffic.
    /// Using a separate listener socket on 0.0.0.0:7410 causes packet delivery issues
    /// because Linux delivers packets to the more specific socket first.
    #[must_use]
    pub fn metatraffic_unicast_socket(&self) -> Arc<UdpSocket> {
        Arc::clone(&self.metatraffic_unicast_socket)
    }

    /// Get user data unicast socket reference for user DATA reception.
    ///
    /// Same principle as metatraffic_unicast_socket: use the transport's socket
    /// for BOTH sending AND receiving to avoid Linux socket delivery issue.
    #[must_use]
    pub fn user_unicast_socket(&self) -> Arc<UdpSocket> {
        Arc::clone(&self.user_unicast_socket)
    }

    /// Get multicast destination address.
    #[must_use]
    pub fn multicast_addr(&self) -> SocketAddr {
        self.multicast_addr
    }

    /// Get current TTL configuration.
    #[must_use]
    pub fn ttl_config(&self) -> &TtlConfig {
        &self.ttl_config
    }

    /// Set multicast TTL on all sockets.
    ///
    /// Use this to change the multicast hop limit at runtime.
    /// Returns error if setting fails on any socket.
    pub fn set_multicast_ttl(&self, ttl: u8) -> io::Result<()> {
        ttl::set_multicast_ttl(&self.socket, ttl)?;
        ttl::set_multicast_ttl(&self.metatraffic_unicast_socket, ttl)?;
        ttl::set_multicast_ttl(&self.user_unicast_socket, ttl)?;
        log::debug!("[UDP] Set multicast TTL={} on all sockets", ttl);
        Ok(())
    }

    /// Format interface name for logging.
    fn format_iface(&self) -> String {
        if self.iface.octets() == [0, 0, 0, 0] {
            "default".to_string()
        } else {
            self.iface.to_string()
        }
    }

    /// Check if DEBUG logging is enabled.
    fn should_log_debug() -> bool {
        std::env::var("RUST_LOG")
            .map(|v| v.contains("hdds=debug"))
            .unwrap_or(false)
    }

    /// Parse the first RTPS submessage kind from a packet body for debug
    /// logging. The RTPS header is 20 bytes total (4-byte magic, 2-byte
    /// version, 2-byte vendor, 12-byte guid prefix), so the first
    /// submessage kind lives at offset 20, not 16. Per RTPS v2.5 §8.3.7
    /// Table 8.13 the kind→name mapping is `0x06 ACKNACK`, `0x07
    /// HEARTBEAT`, `0x09 INFO_TS`, `0x15 DATA`, `0x16 DATA_FRAG`. The
    /// previous table read at offset 16 (into the guid prefix) and
    /// swapped ACKNACK with HEARTBEAT, so every diagnostic log line was
    /// garbage.
    fn parse_submessage_kind(data: &[u8]) -> &'static str {
        match data.get(20).copied() {
            Some(byte) => Self::submessage_kind_name(byte),
            None => "OTHER",
        }
    }

    /// Map a raw RTPS submessage-kind byte to its spec name. Shared
    /// between `parse_submessage_kind` (offset-aware) and the hex-dump
    /// debug path so the two diagnostics can never drift apart again.
    /// See RTPS v2.5 §8.3.7 Table 8.13 for the canonical id space, plus
    /// §8.3.5.10 for the v2.5 HEADER_EXTENSION (0x00) addition.
    fn submessage_kind_name(byte: u8) -> &'static str {
        match byte {
            0x00 => "HEADER_EXTENSION",
            0x06 => "ACKNACK",
            0x07 => "HEARTBEAT",
            0x08 => "GAP",
            0x09 => "INFO_TS",
            0x0C => "INFO_SRC",
            0x0D => "INFO_REPLY_IP4",
            0x0E => "INFO_DST",
            0x0F => "INFO_REPLY",
            0x12 => "NACK_FRAG",
            0x13 => "HEARTBEAT_FRAG",
            0x15 => "DATA",
            0x16 => "DATA_FRAG",
            _ => "OTHER",
        }
    }
}

// ===== Helper functions =====

/// Parse socket address with proper error handling.
fn parse_socket_addr(addr_str: String, label: &str) -> io::Result<SocketAddr> {
    addr_str.parse().map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format_string(format_args!("Invalid {}: {}", label, e)),
        )
    })
}

/// Parse multicast address with proper error handling.
fn parse_multicast_addr(port: u16, label: &str) -> io::Result<SocketAddr> {
    parse_socket_addr(
        format_string(format_args!("{}:{}", MULTICAST_GROUP, port)),
        label,
    )
}

/// Parse SEDP multicast address per RTPS v2.3 spec.
///
/// RTPS v2.3 Section 9.6.1.1 says SEDP can use 239.255.0.2:7400, but in practice
/// most DDS implementations (RTI Connext, FastDDS, CycloneDDS) use 239.255.0.1:7400
/// for both SPDP and SEDP. Using .2 is optional and rarely implemented.
///
/// Phase 1.6 RTI Interop: Use 239.255.0.1 like everyone else.
fn parse_sedp_multicast_addr(port: u16, label: &str) -> io::Result<SocketAddr> {
    // Use same multicast address as SPDP (239.255.0.1) for maximum compatibility
    parse_socket_addr(
        format_string(format_args!("{}:{}", MULTICAST_GROUP, port)),
        label,
    )
}

// setup_data_multicast removed: data_multicast_addr is now always computed
// from metatraffic_multicast + 1 (RTPS v2.5 Sec.9.6.1.1, d2=1)

/// v242: Set SO_REUSEPORT on a socket for multi-process port sharing.
///
/// This enables multiple processes to bind to the same port, which is required
/// for HDDS<->HDDS inter-process discovery on the same machine.
/// Only available on Unix systems.
#[cfg(unix)]
fn set_reuseport(socket: &Socket) -> io::Result<()> {
    use std::os::unix::io::AsRawFd;
    let fd = socket.as_raw_fd();
    let optval: libc::c_int = 1;
    // SAFETY: setsockopt FFI with valid fd, standard socket option, and correctly sized optval pointer
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEPORT,
            &optval as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

// ===== Tests =====

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::PortMapping;

    #[test]
    fn test_transport_creation_rtps_compliant() {
        let mapping =
            PortMapping::calculate(0, 0).expect("Port mapping calculation should succeed");
        let transport = UdpTransport::new(0, 0, mapping);
        assert!(transport.is_ok(), "Transport creation should succeed");

        let transport = transport.expect("Transport creation should succeed");
        assert_eq!(transport.domain_id, 0);
        assert_eq!(transport.participant_id, 0);
        assert_eq!(transport.multicast_addr.to_string(), "239.255.0.1:7400");
    }

    #[test]
    fn test_transport_different_participant() {
        let mapping =
            PortMapping::calculate(0, 1).expect("Port mapping calculation should succeed");
        let transport = UdpTransport::new(0, 1, mapping);
        assert!(transport.is_ok(), "Should support multiple participants");

        let transport = transport.expect("Transport creation should succeed");
        assert_eq!(transport.participant_id, 1);
        assert_eq!(transport.multicast_addr.to_string(), "239.255.0.1:7400");
    }

    #[test]
    fn test_transport_different_domain() {
        let mapping =
            PortMapping::calculate(1, 0).expect("Port mapping calculation should succeed");
        let transport = UdpTransport::new(1, 0, mapping);
        assert!(transport.is_ok(), "Should support different domains");

        let transport = transport.expect("Transport creation should succeed");
        assert_eq!(transport.domain_id, 1);
        assert_eq!(transport.multicast_addr.to_string(), "239.255.0.1:7650");
    }

    #[test]
    #[allow(deprecated)]
    fn test_transport_with_custom_port_legacy() {
        let transport = UdpTransport::with_port(17400);
        assert!(transport.is_ok());

        let transport = transport.expect("Legacy transport creation should succeed");
        assert_eq!(transport.multicast_addr.to_string(), "239.255.0.1:17400");
    }

    #[test]
    fn test_transport_send() {
        let mapping =
            PortMapping::calculate(0, 2).expect("Port mapping calculation should succeed");
        let transport =
            UdpTransport::new(0, 2, mapping).expect("Transport creation should succeed");
        let data = b"RTPS test packet";

        let result = transport.send(data);
        assert!(result.is_ok(), "Send should succeed");
    }

    #[test]
    fn test_socket_sharing() {
        let mapping =
            PortMapping::calculate(0, 3).expect("Port mapping calculation should succeed");
        let transport =
            UdpTransport::new(0, 3, mapping).expect("Transport creation should succeed");
        let socket1 = transport.socket();
        let socket2 = transport.socket();

        assert!(Arc::ptr_eq(&socket1, &socket2));
    }

    /// Regression: `parse_submessage_kind` must read at wire offset 20
    /// (past the 20-byte RTPS header) and map IDs per RTPS v2.5 Table
    /// 8.13. The previous implementation read at offset 16 (inside the
    /// guid prefix) and swapped ACKNACK (0x06) with HEARTBEAT (0x07),
    /// turning every diagnostic log line into garbage.
    #[test]
    fn parse_submessage_kind_reads_offset_20_and_maps_per_spec() {
        // Build a minimal RTPS frame: 20-byte header + 1-byte kind byte.
        let mut frame = vec![b'R', b'T', b'P', b'S']; // magic
        frame.extend_from_slice(&[2, 5]); // version 2.5
        frame.extend_from_slice(&[0x01, 0xAA]); // vendor (HDDS)
        frame.extend_from_slice(&[0u8; 12]); // guid prefix
        assert_eq!(frame.len(), 20, "RTPS header is 20 bytes");

        // The byte at offset 20 is the submessage kind.
        let cases: &[(u8, &str)] = &[
            (0x00, "HEADER_EXTENSION"),
            (0x06, "ACKNACK"),
            (0x07, "HEARTBEAT"),
            (0x08, "GAP"),
            (0x09, "INFO_TS"),
            (0x0C, "INFO_SRC"),
            (0x0D, "INFO_REPLY_IP4"),
            (0x0E, "INFO_DST"),
            (0x0F, "INFO_REPLY"),
            (0x12, "NACK_FRAG"),
            (0x13, "HEARTBEAT_FRAG"),
            (0x15, "DATA"),
            (0x16, "DATA_FRAG"),
            (0xFF, "OTHER"),
        ];
        for (id, expected) in cases {
            let mut packet = frame.clone();
            packet.push(*id);
            assert_eq!(
                UdpTransport::parse_submessage_kind(&packet),
                *expected,
                "kind 0x{id:02x} must map to {expected}"
            );
        }

        // A packet shorter than 21 bytes (no submessage byte) must
        // safely return "OTHER" rather than panic.
        assert_eq!(
            UdpTransport::parse_submessage_kind(&frame),
            "OTHER",
            "short packets must not panic"
        );
    }
}
