// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! UDP transport for RTPS multicast send/receive.
//!
//! Consolidates socket management, multicast configuration, and send/receive operations.

use crate::config::{MULTICAST_GROUP, SEDP_UNICAST_OFFSET};
use crate::core::string_utils::format_string;
use crate::transport::dscp;
use crate::transport::external_locator::ExternalLocator;
use crate::transport::filter::InterfaceFilter;
use crate::transport::ifaddrs::InterfaceSnapshot;
use crate::transport::multicast::{
    get_primary_interface_ip, get_primary_interface_ip_with_snapshot,
    get_unicast_locators_filtered, join_multicast_group, join_multicast_group_with_snapshot,
    resolve_forced_interface,
};
use crate::transport::options::{ResolvedTransportOptions, TransportOptions};
use crate::transport::relay::{self, RelayEgress};
use crate::transport::socket_buffer::{
    apply_receive_buffer, apply_send_buffer, ResolvedSocketBufferOptions, SocketBufferOptions,
};
use crate::transport::ttl::{self, TtlConfig};
use crate::transport::PortMapping;
use socket2::{Domain, Protocol, Socket, Type};
use std::io;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

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
    /// User data unicast socket (bound to 7411 for USER DATA unicast sends)
    pub(super) user_unicast_socket: Arc<UdpSocket>,
    /// Multicast destination address for SPDP (239.255.0.1:7400)
    pub(super) multicast_addr: SocketAddr,
    /// Multicast destination address for SEDP (239.255.0.1:7400, same group as SPDP)
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
    /// Interface allowlist used for locator advertising (permissive by default)
    pub(super) interface_filter: InterfaceFilter,
    /// Addresses announced although no socket here is bound to them (NAT
    /// mapping, relay endpoint). Appended to the locators read off local
    /// interfaces, never substituted for them.
    pub(super) external_locators: Vec<ExternalLocator>,
    /// Multicast EMISSION switch (`MulticastMode::Enabled` only). When false
    /// every multicast send on this transport is suppressed (SPDP/SEDP/user
    /// data); unicast sends are unaffected.
    pub(super) multicast_send: bool,
    /// Multicast RECEPTION switch (`Enabled` or `ReceiveOnly`). When false the
    /// SPDP socket never joins the group and the participant starts no
    /// multicast listener. Also false after a degraded join (see
    /// `multicast_join_error`).
    pub(super) multicast_receive: bool,
    /// Why multicast reception is off although the mode asked for it: the
    /// group join failed on every interface and the transport degraded
    /// (`TransportOptions::require_multicast_join` was false).
    pub(super) multicast_join_error: Option<String>,
    /// The multicast send probe on the primary interface was refused and
    /// the transport reverted to the kernel's default route (a VPN or tunnel
    /// policy is the usual cause). Read once, by the discovery hint.
    pub(super) multicast_if_blocked: bool,
    /// Multicast sends refused because emission is disabled by policy. Each
    /// refusal is an `Err(Unsupported)` to the caller; this counts them so a
    /// caller that keeps asking for a path that does not exist is visible.
    pub(super) suppressed_multicast_sends: AtomicU64,
    /// The Discovery Server relay, once the participant has installed one.
    ///
    /// Empty on every transport that has no Discovery Server session, which
    /// is the default. Only ever read when a destination falls in the
    /// synthetic relay range, so a participant that never relays pays one
    /// comparison per unicast send and never touches this at all.
    pub(super) relay: OnceLock<RelayEgress>,
    /// Test-only wiring counters: which USER DATA send method was
    /// actually called (unicast or the multicast fallback alike),
    /// ordinary blocking or best-effort non-blocking (see
    /// `send_user_data_unicast_best_effort`,
    /// `send_user_data_multicast_best_effort`). Per-instance, so parallel
    /// tests on their own `Participant`/transport never share a counter;
    /// not compiled into a release build at all.
    #[cfg(test)]
    pub(super) blocking_user_sends: AtomicU64,
    #[cfg(test)]
    pub(super) best_effort_user_sends: AtomicU64,
}

/// Diagnostic-only: print who opened or closed a transport's sockets when
/// `HDDS_DOMAIN_LEASE_TRACE` is set (the same switch
/// `test_support::domains` uses, so the two logs interleave and a domain's
/// lease events line up against the transport that actually held its
/// ports). Never read on a path a benchmark cares about; checked on every
/// call, same as the lease tracer.
fn trace_transport_event(domain_id: u32, participant_id: u8, event: &str) {
    if std::env::var_os("HDDS_DOMAIN_LEASE_TRACE").is_none() {
        return;
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    eprintln!(
        "[transport] t={}.{:06} pid={} thread={:?} domain={domain_id} participant={participant_id} {event}",
        now.as_secs(),
        now.subsec_micros(),
        std::process::id(),
        std::thread::current().name().unwrap_or("<unnamed>"),
    );
}

impl Drop for UdpTransport {
    fn drop(&mut self) {
        trace_transport_event(self.domain_id, self.participant_id, "CLOSED");
    }
}

// ===== Construction (builder functionality) =====

impl UdpTransport {
    /// Create new UDP transport with RTPS v2.5 port mapping.
    ///
    /// Binds to the metatraffic multicast port and joins the standard multicast group.
    ///
    /// Back-compat constructor: equivalent to [`UdpTransport::new_with_options`]
    /// with default (env-resolved) transport options, which replicates the
    /// historical behavior exactly when no `HDDS_*` transport env vars are set.
    pub fn new(domain_id: u32, participant_id: u8, mapping: PortMapping) -> io::Result<Self> {
        Self::new_with_options(
            domain_id,
            participant_id,
            mapping,
            &TransportOptions::default().resolve(),
        )
    }

    /// Create new UDP transport with explicit resolved transport options.
    ///
    /// Applies, per socket class:
    /// - TTL (`options.ttl`) on all three sockets;
    /// - DSCP (`options.dscp`, when `Some`): metatraffic class on the
    ///   multicast + metatraffic-unicast sockets, user-data class on the
    ///   user-data unicast socket. Discovery traffic shares the metatraffic
    ///   sockets, so `dscp.discovery` is blurred into `metatraffic` here
    ///   (documented in [`ResolvedTransportOptions`]);
    /// - the interface allowlist for multicast joins, primary-interface
    ///   selection and locator advertising;
    /// - the multicast mode: when disabled, all multicast sends are
    ///   suppressed at this central switch.
    pub fn new_with_options(
        domain_id: u32,
        participant_id: u8,
        mapping: PortMapping,
        options: &ResolvedTransportOptions,
    ) -> io::Result<Self> {
        Self::new_with_options_and_socket_buffers(
            domain_id,
            participant_id,
            mapping,
            options,
            &SocketBufferOptions::default().resolve(),
        )
    }

    pub(crate) fn new_with_options_and_socket_buffers(
        domain_id: u32,
        participant_id: u8,
        mapping: PortMapping,
        options: &ResolvedTransportOptions,
        socket_buffers: &ResolvedSocketBufferOptions,
    ) -> io::Result<Self> {
        Self::new_with_reserved_unicast(
            domain_id,
            participant_id,
            mapping,
            options,
            socket_buffers,
            None,
        )
    }

    /// Same as [`Self::new_with_options_and_socket_buffers`], taking the
    /// metatraffic unicast socket already bound by the caller when it has
    /// one.
    ///
    /// The participant-id auto-assignment binds the unicast ports of the
    /// participant id it tries, exclusively, and keeps the sockets it got:
    /// the bind IS the probe. Closing that socket here to bind the same port
    /// again would reopen the window in which another process starting at
    /// the same moment takes the port, so the bound socket is handed over
    /// instead. `None` binds `mapping.metatraffic_unicast` here, exclusively
    /// as well (explicit participant id, `HDDS_PARTICIPANT_ID`, custom ports).
    pub(crate) fn new_with_reserved_unicast(
        domain_id: u32,
        participant_id: u8,
        mapping: PortMapping,
        options: &ResolvedTransportOptions,
        socket_buffers: &ResolvedSocketBufferOptions,
        reserved_metatraffic_unicast: Option<Socket>,
    ) -> io::Result<Self> {
        crate::trace_fn!("UdpTransport::new");
        let multicast_send = options.multicast_send_enabled();
        let mut multicast_receive = options.multicast_receive_enabled();
        let mut multicast_join_error: Option<String> = None;
        // Create socket with SO_REUSEADDR for port reuse.
        // We deliberately do NOT use SO_REUSEPORT by default ON LINUX because:
        // 1. A co-located DDS process from another vendor may bind the same port without
        //    SO_REUSEPORT (this alone is not a reason to decline SO_REUSEPORT ourselves, see
        //    reason 2)
        // 2. On LINUX SPECIFICALLY, if ANY process uses SO_REUSEPORT on a port, ALL processes must
        //    use it. This is a Linux kernel rule; BSD's SO_REUSEPORT does not work this way,
        //    so this reason does not transfer to BSD/Darwin.
        // 3. Using SO_REUSEPORT would keep HDDS from sharing the port with such a process, ON
        //    LINUX -- this follows directly from reason 2, so it is Linux-specific for the same
        //    reason and was never re-derived for BSD/Darwin's different semantics.
        // 4. Multicast on localhost has kernel limitations even with SO_REUSEPORT (general
        //    observation, not platform-specific, and not by itself an argument against
        //    SO_REUSEPORT on any one platform)
        // 5. Proper interop testing requires separate machines/VMs with real network routing
        //    (general, not platform-specific)
        //
        // On BSD-family kernels (Darwin included), SO_REUSEADDR alone
        // is NOT enough for two participants to bind the identical metatraffic multicast port --
        // Darwin refuses with "Address already in use" (os error 48), where Linux permits it.
        // Two participants on one domain on one host bind this exact port every time (SPDP+SEDP
        // share it, see PortMapping::calculate), so on BSD/Darwin this is the ordinary case, not
        // the opt-in multi-process mode HDDS_REUSEPORT exists for below. SO_REUSEPORT is applied
        // unconditionally there for this socket and for the user-data multicast socket
        // (dds/participant/builder/sockets.rs::create_data_multicast_socket, the other port every
        // participant on a domain binds identically); see the cfg(target_os) block right after the
        // HDDS_REUSEPORT check below. The Linux branch below is untouched by that block: it is
        // compiled out entirely on Linux (cfg-gated), so Linux behavior does not move.
        // NOT YET VERIFIED against a peer from another vendor on macOS -- only the HDDS<->HDDS
        // case (this crate's own test suite on the macOS guest) has been checked. Treat
        // BSD/Darwin cross-vendor interop as unproven until that run happens.
        //
        // Set HDDS_REUSEPORT=1 to enable SO_REUSEPORT for multi-process HDDS<->HDDS on the
        // same machine, on Linux (and on any other platform where it is not already forced by the
        // BSD-family block above). This breaks the Linux same-machine cross-vendor case in reasons 2-3
        // but enables local multi-process discovery there. It applies to the MULTICAST sockets
        // only: the unicast ports are exclusive whatever it says (see the metatraffic unicast
        // socket below).
        let socket2 = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        socket2.set_reuse_address(true)?;
        if let Some(receive_bytes) = socket_buffers.metatraffic_receive_buffer() {
            apply_receive_buffer(&socket2, receive_bytes, true, "metatraffic multicast");
        }
        if let Some(send_bytes) = socket_buffers.send_buffer() {
            apply_send_buffer(&socket2, send_bytes, "metatraffic multicast");
        }
        #[cfg(unix)]
        let reuseport_enabled = std::env::var("HDDS_REUSEPORT")
            .map(|v| v == "1")
            .unwrap_or(false);
        #[cfg(unix)]
        if reuseport_enabled {
            set_reuseport(&socket2)?;
            log::info!("[UDP] SO_REUSEPORT enabled via HDDS_REUSEPORT=1 (multi-process mode)");
        }
        // BSD-family kernels (Darwin included) refuse to share this exact port across
        // participants with SO_REUSEADDR alone. Unconditional here -- not gated behind
        // HDDS_REUSEPORT -- because every participant on a domain binds this identical
        // metatraffic multicast port (SPDP+SEDP) as the ordinary case, not as opt-in
        // multi-process sharing. This cfg is absent entirely on Linux, so the Linux build does
        // not contain this branch at all; skip the second call if the env var above already did it.
        #[cfg(any(
            target_os = "macos",
            target_os = "ios",
            target_os = "freebsd",
            target_os = "netbsd",
            target_os = "openbsd",
            target_os = "dragonfly"
        ))]
        if !reuseport_enabled {
            set_reuseport(&socket2)?;
            log::info!(
                "[UDP] SO_REUSEPORT enabled unconditionally on this platform for the metatraffic \
                 multicast socket (SO_REUSEADDR alone does not permit two participants to \
                 share this port on BSD-family kernels)"
            );
        }
        // There is no SO_REUSEPORT outside unix. SO_REUSEADDR (set above)
        // already gives the multi-process bind semantics there, but say so
        // rather than accepting the variable in silence.
        #[cfg(not(unix))]
        if std::env::var("HDDS_REUSEPORT")
            .map(|v| v == "1")
            .unwrap_or(false)
        {
            log::info!(
                "[UDP] HDDS_REUSEPORT=1 ignored on this platform: SO_REUSEPORT is unix-only, SO_REUSEADDR is already set"
            );
        }

        let bind_addr = parse_socket_addr(
            format_string(format_args!("0.0.0.0:{}", mapping.metatraffic_multicast)),
            "bind address",
        )?;
        socket2.bind(&bind_addr.into()).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!(
                    "binding the METATRAFFIC MULTICAST socket on port {} (domain {}) failed: {e}. \
                     This socket sets SO_REUSEADDR, so another process holds that port without it",
                    mapping.metatraffic_multicast, domain_id
                ),
            )
        })?;
        log::debug!(
            "[UDP] transport bind addr={} domain={} participant_id={}",
            bind_addr,
            domain_id,
            participant_id
        );

        // Compute primary IP early -- needed for IP_MULTICAST_IF before socket conversion.
        // HDDS_INTERFACE forces everything onto one interface -- no probing needed.
        // ONE interface snapshot per transport: the primary-IP choice and the
        // multicast joins below read the same view of the host.
        let forced_ip = resolve_forced_interface();
        let snapshot = if forced_ip.is_some() {
            InterfaceSnapshot::default()
        } else {
            InterfaceSnapshot::capture_or_empty()
        };
        let primary_ip = match forced_ip {
            Some(ip) => ip,
            None => {
                get_primary_interface_ip_with_snapshot(&options.interface_allowlist, &snapshot)?
            }
        };

        // Set IP_MULTICAST_IF so outgoing multicast goes through the correct interface.
        // Without this, the kernel sends via the default route which may be a VPN tunnel
        // (e.g. CloudflareWARP 172.16.0.2) instead of the real LAN interface.
        //
        // Probe: CloudflareWARP hijacks all multicast routes and returns EPERM for sends
        // on non-WARP interfaces. If the probe send fails, revert to default routing.
        let mut multicast_if_blocked = false;
        if multicast_send && !primary_ip.is_unspecified() {
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
                        multicast_if_blocked = true;
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
        let iface = if multicast_receive {
            match join_multicast_group_with_snapshot(
                &socket,
                &options.interface_allowlist,
                options.ttl.multicast,
                &snapshot,
            ) {
                Ok(iface) => {
                    log::debug!(
                        "[UDP] join_multicast_group success multicast=239.255.0.1 iface={}",
                        iface
                    );
                    iface
                }
                Err(err) => {
                    let (iface, receive, join_error) =
                        resolve_join_outcome(Err(err), options.require_multicast_join, primary_ip)?;
                    multicast_receive = receive;
                    multicast_join_error = join_error;
                    iface
                }
            }
        } else {
            log::debug!("[UDP] Discovery multicast group join disabled");
            primary_ip
        };

        // Create a second socket bound to the metatraffic_unicast port (7410).
        // This ensures unicast SEDP/ACKNACK packets have correct source port per RTPS v2.5 Sec.9.6.1
        //
        // It binds to 0.0.0.0:7410, not primary_ip:7410: if bound to a specific IP,
        // Linux delivers incoming packets to THAT socket and NOT to any wildcard listener
        // on 0.0.0.0:7410. The same socket is used for both sending AND receiving (via
        // MulticastListener), so binding to 0.0.0.0 ensures we can receive from any
        // interface while still sending with correct source port. Sending uses send_to()
        // with an explicit destination, not connect(), so multi-interface routing is not
        // a concern.
        //
        // This port is EXCLUSIVE: no SO_REUSEADDR, no SO_REUSEPORT (not even under
        // HDDS_REUSEPORT=1, which only concerns the multicast sockets), and
        // SO_EXCLUSIVEADDRUSE on Windows. DDSI-RTPS 2.5 9.6.1.1 derives the unicast
        // ports from the participant id precisely so that they are unique on the
        // host. Two sockets sharing a unicast port do not share its traffic: the
        // kernel hands each datagram to ONE of them, so one participant silently
        // receives nothing. A second participant on these ports must fail to bind,
        // which is what moves the auto-assignment to the next participant id and
        // what turns a duplicate explicit id into an error.
        let unicast_socket2 = match reserved_metatraffic_unicast {
            Some(socket) => socket,
            None => bind_exclusive_unicast(mapping.metatraffic_unicast).map_err(|e| {
                io::Error::new(
                    e.kind(),
                    format!(
                        "binding the METATRAFFIC UNICAST socket on port {} (domain {}, \
                         participant {}) failed: {e}. Unicast ports are exclusive (RTPS 2.5 \
                         9.6.1.1): another participant, in this process or another one, already \
                         uses this participant id on this domain. Choose another participant \
                         id, or leave it unset so that a free one is assigned",
                        mapping.metatraffic_unicast, domain_id, participant_id
                    ),
                )
            })?,
        };
        if let Some(receive_bytes) = socket_buffers.metatraffic_receive_buffer() {
            apply_receive_buffer(&unicast_socket2, receive_bytes, true, "metatraffic unicast");
        }
        if let Some(send_bytes) = socket_buffers.send_buffer() {
            apply_send_buffer(&unicast_socket2, send_bytes, "metatraffic unicast");
        }
        log::debug!(
            "[UDP] Created metatraffic_unicast_socket bound to 0.0.0.0:{} (for SEDP/ACKNACK send+recv) [primary_ip={}]",
            mapping.metatraffic_unicast,
            primary_ip
        );
        let metatraffic_unicast_socket: UdpSocket = unicast_socket2.into();

        // Create user data unicast socket (NOT BOUND - let OS choose ephemeral port)
        // We should NOT bind the send socket to port 7411 because the listener is already on 7411
        // Ephemeral port: no reuse option either. With SO_REUSEADDR set, the
        // kernel's ephemeral pick may land on a port another SO_REUSEADDR socket
        // already holds, and nothing here needs to share a port.
        let user_socket2 = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        // Bind to primary IP with port 0 (OS will assign ephemeral port)
        // Windows fix: if primary_ip is a virtual adapter (Hyper-V, WSL, Docker),
        // bind may fail with WSAEADDRNOTAVAIL (10049). Fall back to 0.0.0.0:0.
        //
        // Windows binds the unspecified address on purpose: under the strong
        // host model a socket bound to the interface address cannot send to
        // 127.0.0.1 at all (WSAEADDRNOTAVAIL on Windows), so a peer announcing a loopback locator was unreachable. The
        // source address of a datagram carries no RTPS meaning (peers answer
        // the announced locators), `primary_ip` still selects the multicast
        // interface and the announced locators, and the port stays ephemeral
        // (a fixed port on 0.0.0.0 would raise the Windows firewall prompt).
        let user_unicast_bind_ip: Ipv4Addr = if cfg!(windows) {
            Ipv4Addr::UNSPECIFIED
        } else {
            primary_ip
        };
        let user_unicast_bind_addr = parse_socket_addr(
            format_string(format_args!("{}:0", user_unicast_bind_ip)),
            "user unicast bind address",
        )?;
        let user_socket2 = match user_socket2.bind(&user_unicast_bind_addr.into()) {
            Ok(()) => user_socket2,
            Err(e) => {
                log::warn!(
                    "[UDP] bind({}:0) failed ({}), falling back to 0.0.0.0:0",
                    primary_ip,
                    e
                );
                let fallback = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
                let any_addr = parse_socket_addr("0.0.0.0:0".to_string(), "user unicast fallback")?;
                fallback.bind(&any_addr.into())?;
                fallback
            }
        };
        if let Some(send_bytes) = socket_buffers.send_buffer() {
            apply_send_buffer(&user_socket2, send_bytes, "user-data unicast");
        }
        let user_unicast_socket: UdpSocket = user_socket2.into();
        let actual_port = user_unicast_socket.local_addr()?.port();
        log::debug!(
            "[UDP] Created user_unicast_socket bound to {}:{} (ephemeral port for USER DATA sends)",
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

        // Apply TTL configuration from the resolved transport options
        // (builder option wins, env vars are the fallback, then defaults).
        let ttl_config = options.ttl;
        ttl::apply_ttl_config(&socket, &ttl_config)?;
        ttl::apply_ttl_config(&metatraffic_unicast_socket, &ttl_config)?;
        ttl::apply_ttl_config(&user_unicast_socket, &ttl_config)?;

        // Apply per-class DSCP marking when configured. None = leave the
        // kernel default TOS (historical behavior). setsockopt failures are
        // non-fatal (some code points need CAP_NET_ADMIN); set_socket_dscp
        // already logs a warning on failure.
        if let Some(dscp_config) = options.dscp {
            let _ = dscp::set_socket_dscp(&socket, dscp_config.metatraffic);
            let _ = dscp::set_socket_dscp(&metatraffic_unicast_socket, dscp_config.metatraffic);
            let _ = dscp::set_socket_dscp(&user_unicast_socket, dscp_config.user_data);
        }

        log::debug!(
            "[UDP] transport metatraffic_unicast_port={} data_multicast={} (for SPDP locators)",
            mapping.metatraffic_unicast,
            data_multicast_addr
        );

        trace_transport_event(domain_id, participant_id, "OPENED");

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
            interface_filter: options.interface_allowlist.clone(),
            external_locators: options.external_locators.clone(),
            multicast_send,
            multicast_receive,
            multicast_join_error,
            multicast_if_blocked,
            suppressed_multicast_sends: AtomicU64::new(0),
            relay: OnceLock::new(),
            #[cfg(test)]
            blocking_user_sends: AtomicU64::new(0),
            #[cfg(test)]
            best_effort_user_sends: AtomicU64::new(0),
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
        sock2.bind(&bind_addr.into()).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!(
                    "binding the legacy with_port MULTICAST socket on port {port} failed: {e}. \
                     This socket sets SO_REUSEADDR, so another process holds that port without it"
                ),
            )
        })?;
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

        // Create unicast socket bound to 0.0.0.0:port for both send AND recv
        // Now used by MulticastListener for receiving SEDP unicast traffic
        let unicast_port = port + SEDP_UNICAST_OFFSET; // Legacy: SEDP offset from base port
        let unicast_bind_addr = format_string(format_args!("0.0.0.0:{}", unicast_port));
        log::debug!(
            "[UDP] Binding metatraffic_unicast_socket to {} (for send+recv) [primary_ip={}]",
            unicast_bind_addr,
            primary_ip
        );
        let metatraffic_unicast_socket = UdpSocket::bind(&unicast_bind_addr).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!(
                    "binding the legacy with_port METATRAFFIC UNICAST socket on port {unicast_port} \
                     failed: {e}. Note this legacy path binds WITHOUT SO_REUSEADDR, so it also \
                     refuses to share with a participant that set it"
                ),
            )
        })?;

        // Create user data unicast socket with ephemeral port (NOT bound to 7411)
        // Binding to port 7411 conflicts with the listener on same port
        // Windows fix: fall back to 0.0.0.0:0 if primary_ip bind fails (virtual adapters)
        // Windows binds the unspecified address outright: see the same block in
        // `new_with_options_and_socket_buffers` (loopback destinations are
        // unreachable from an interface-bound socket there).
        let user_unicast_bind_ip: Ipv4Addr = if cfg!(windows) {
            Ipv4Addr::UNSPECIFIED
        } else {
            primary_ip
        };
        let user_unicast_bind_addr = format_string(format_args!("{}:0", user_unicast_bind_ip));
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
            "[UDP] Binding user_unicast_socket to {}:{} (ephemeral) for USER DATA sends",
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
            interface_filter: InterfaceFilter::allow_all(),
            external_locators: Vec::new(),
            multicast_send: true,
            multicast_receive: true,
            multicast_join_error: None,
            multicast_if_blocked: false,
            suppressed_multicast_sends: AtomicU64::new(0),
            relay: OnceLock::new(),
            #[cfg(test)]
            blocking_user_sends: AtomicU64::new(0),
            #[cfg(test)]
            best_effort_user_sends: AtomicU64::new(0),
        })
    }
}

// ===== Send operations =====

/// Where a best-effort HEARTBEAT unicast send, already resolved OUTSIDE
/// any gate, should actually go: a plain socket destination, or an
/// already-identified relay peer. The lookup that decides between them
/// (`RelayLocators::peer_of`'s `RwLock` read) happens in
/// `UdpTransport::resolve_best_effort_unicast`, never in
/// `UdpTransport::transmit_best_effort_resolved` -- a third review
/// found that lookup still ran inside `HeartbeatSchedulerState::
/// send_gate` when it was left behind `destination_is_relayed` inside
/// the old, combined send method.
pub(crate) enum BestEffortUnicastTarget {
    Direct(SocketAddr),
    Relayed([u8; 12]),
}

impl UdpTransport {
    /// Whether `MulticastMode` permits multicast emission at all, with
    /// NO side effect -- never counts, never logs. For a caller that
    /// must decide whether a fallback will even be worth attempting
    /// BEFORE it knows whether it will actually need one (the periodic
    /// HEARTBEAT path's prepare phase): calling `multicast_send_refused`
    /// here unconditionally would count and log a "refusal" on every tick whose policy
    /// disables multicast, even when unicast delivery succeeded and no
    /// fallback was ever needed, or the tick was revoked before
    /// reaching one. `multicast_send_refused` itself stays exactly as
    /// it was, for every caller that calls it AT THE MOMENT it would
    /// actually use the fallback.
    pub(crate) fn multicast_send_allowed(&self) -> bool {
        self.multicast_send
    }

    /// Refuse a multicast send when emission is disabled by policy.
    ///
    /// Returns `Some(error)` to hand back to the caller: an honest
    /// `ErrorKind::Unsupported`, never a fake success. Every caller of the
    /// multicast sends already treats an error as "not delivered" (unicast
    /// fallback, retransmit accounting, debug log), so the refusal is
    /// visible where it matters and counted in `suppressed_multicast_sends`.
    pub(crate) fn multicast_send_refused(&self, what: &str) -> Option<io::Error> {
        if self.multicast_send {
            return None;
        }
        self.suppressed_multicast_sends
            .fetch_add(1, Ordering::Relaxed);
        log::debug!(
            "[UDP] {} refused: multicast emission disabled by MulticastMode",
            what
        );
        Some(io::Error::new(
            io::ErrorKind::Unsupported,
            "multicast emission disabled by MulticastMode",
        ))
    }

    /// Send data to SPDP multicast group (metatraffic port, e.g. 7400).
    ///
    /// When multicast emission is disabled ([`crate::transport::MulticastMode`]
    /// `ReceiveOnly` / `Disabled`) this returns `Err(ErrorKind::Unsupported)`
    /// and sends nothing.
    pub fn send(&self, data: &[u8]) -> io::Result<()> {
        crate::trace_fn!("UdpTransport::send");
        if let Some(err) = self.multicast_send_refused("send") {
            return Err(err);
        }
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

        // Answered once per process (see `config::env_flags`), so the three
        // send paths below pay no `env::var("RUST_LOG")` lookup or `String`
        // allocation per sent packet.
        if crate::config::env_flags::udp_send_debug_log() {
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
        if let Some(err) = self.multicast_send_refused("send_user_data_multicast") {
            return Err(err);
        }
        let dest = self.data_multicast_addr;

        let sent = match self.transmit_user_data(&self.socket, data, &dest) {
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

    /// Send user DATA to an explicit multicast group (dialect-gated
    /// large-payload routing; see `dds::writer::frag_route`).
    ///
    /// Uses the same multicast-configured socket as
    /// `send_user_data_multicast` so TTL / loopback / egress-interface
    /// behavior is identical to the proven default-group send.
    pub fn send_user_data_multicast_to(&self, data: &[u8], dest: &SocketAddr) -> io::Result<()> {
        crate::trace_fn!("UdpTransport::send_user_data_multicast_to");
        if let Some(err) = self.multicast_send_refused("send_user_data_multicast_to") {
            return Err(err);
        }
        let sent = match self.socket.send_to(data, dest) {
            Ok(n) => n,
            Err(err) => {
                log::debug!(
                    "[UDP] send_user_data_multicast_to error={} dest={} len={}",
                    err,
                    dest,
                    data.len()
                );
                return Err(err);
            }
        };

        log::debug!(
            "[UDP] send_user_data_multicast_to -> {} len={} iface={}",
            dest,
            sent,
            self.format_iface()
        );

        Ok(())
    }

    /// User-data multicast port for this domain (PB + DG*domainId + d2).
    #[must_use]
    pub fn data_multicast_port(&self) -> u16 {
        self.data_multicast_addr.port()
    }

    /// Send SEDP data to dedicated multicast port (Phase 1.6).
    ///
    /// Sends endpoint discovery packets to 239.255.0.1:7400 (same multicast group as SPDP).
    pub fn send_sedp(&self, data: &[u8]) -> io::Result<()> {
        crate::trace_fn!("UdpTransport::send_sedp");
        if let Some(err) = self.multicast_send_refused("send_sedp") {
            return Err(err);
        }
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
            // octetsToNextHeader endianness is governed by the E flag at
            // data[21] bit 0 (DDS-RTPS v2.5 sec. 8.3.3.3). HDDS and most
            // mainstream stacks emit E=1 (little-endian); fall back to BE
            // when the sender explicitly clears the flag.
            let octets = if data[21] & 0x01 != 0 {
                u16::from_le_bytes([data[22], data[23]])
            } else {
                u16::from_be_bytes([data[22], data[23]])
            };
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
    /// Uses metatraffic_unicast_socket (port 7410) for correct source port
    /// per RTPS v2.5 Sec.9.6.1 port mapping.
    pub fn send_to_endpoint(&self, data: &[u8], endpoint: &SocketAddr) -> io::Result<usize> {
        crate::trace_fn!("UdpTransport::send_to_endpoint");
        if let Some(address) = relay::destination_is_relayed(endpoint) {
            return self.send_relayed(data, address);
        }
        // Use dedicated unicast socket bound to 7410 for RTPS spec compliance
        let sent = self.metatraffic_unicast_socket.send_to(data, endpoint)?;

        if crate::config::env_flags::udp_send_debug_log() {
            let kind = Self::parse_submessage_kind(data);
            log::debug!(
                "[hdds/udp] send_unicast kind={} -> {} len={} src_port=7410 iface={}",
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
    /// Uses user_unicast_socket (ephemeral port) for USER DATA per RTPS v2.5 Sec.9.6.1.
    /// USER DATA must not use metatraffic_unicast_socket (port 7410).
    pub fn send_user_data_unicast(&self, data: &[u8], endpoint: &SocketAddr) -> io::Result<usize> {
        crate::trace_fn!("UdpTransport::send_user_data_unicast");
        if let Some(address) = relay::destination_is_relayed(endpoint) {
            return self.send_relayed(data, address);
        }
        let sent = self.transmit_user_data(&self.user_unicast_socket, data, endpoint)?;

        if crate::config::env_flags::udp_send_debug_log() {
            let src_port = self
                .user_unicast_socket
                .local_addr()
                .map(|addr| addr.port())
                .unwrap_or(0);
            log::debug!(
                "[hdds/udp] send_user_data_unicast -> {} len={} src_port={} iface={}",
                endpoint,
                sent,
                src_port,
                self.format_iface()
            );
        }

        Ok(sent)
    }

    /// Resolve `endpoint` for the periodic HEARTBEAT path's best-effort
    /// unicast send, doing the one potentially-blocking lookup (relay
    /// peer resolution) here, OUTSIDE any gate. `None` only when the
    /// destination is in the relay range but names no peer this
    /// participant relays to -- the same "nothing to send" outcome the
    /// old combined method produced, with the SAME diagnostic
    /// (`RelayEgress::resolve_peer`'s own log, also outside any gate).
    pub(crate) fn resolve_best_effort_unicast(
        &self,
        endpoint: &SocketAddr,
    ) -> Option<BestEffortUnicastTarget> {
        match relay::destination_is_relayed(endpoint) {
            Some(address) => self
                .relay()?
                .resolve_peer(address, 0)
                .map(BestEffortUnicastTarget::Relayed),
            None => Some(BestEffortUnicastTarget::Direct(*endpoint)),
        }
    }

    /// Transmit to an already-resolved target: ONLY the raw non-blocking
    /// syscall (`MSG_DONTWAIT`, see [`best_effort_send_to`]) or the
    /// relay's already-non-blocking `offer` -- no lookup, no logging.
    /// Meant to run entirely inside `HeartbeatSchedulerState::send_gate`
    /// (`trace_fn!`/debug logging inside the gate could reach the
    /// application's own synchronous logger under its global mutex).
    ///
    /// On Windows -- the one platform with no per-call non-blocking flag
    /// in this crate's `libc` (see `best_effort_send_to`; every BSD
    /// variant this crate supports DOES have one) -- the `Direct` branch
    /// degrades to the plain blocking send: a known, left-open gap
    /// there, not a silently claimed fix.
    pub(crate) fn transmit_best_effort_resolved(
        &self,
        target: &BestEffortUnicastTarget,
        data: &[u8],
    ) -> io::Result<usize> {
        #[cfg(test)]
        self.best_effort_user_sends.fetch_add(1, Ordering::Relaxed);
        match target {
            BestEffortUnicastTarget::Direct(dest) => {
                best_effort_send_to(&self.user_unicast_socket, data, dest)
            }
            BestEffortUnicastTarget::Relayed(peer) => match self.relay() {
                Some(egress) => egress.offer_resolved(*peer, data),
                None => Err(io::Error::new(
                    io::ErrorKind::AddrNotAvailable,
                    "relay was installed when resolved, gone by the time of the transmit",
                )),
            },
        }
    }

    /// Transmit the periodic HEARTBEAT path's multicast fallback: ONLY
    /// the raw non-blocking syscall, no logging, and -- deliberately --
    /// no `MulticastMode` check: the caller (`heartbeat_scheduler::
    /// send_heartbeat_best_effort`) already resolved that permission
    /// during its prepare phase, outside any gate, via
    /// `multicast_send_refused` (skipping that check would bypass
    /// `ReceiveOnly`/`Disabled` for this one path while every ordinary
    /// multicast send still enforced it). Meant to run entirely inside
    /// the gate. Multicast addresses are never in the relay range
    /// (unicast-only), so there is no lookup to resolve ahead of time
    /// here, unlike the unicast twin above.
    pub(crate) fn transmit_best_effort_multicast_resolved(&self, data: &[u8]) -> io::Result<usize> {
        #[cfg(test)]
        self.best_effort_user_sends.fetch_add(1, Ordering::Relaxed);
        best_effort_send_to(&self.socket, data, &self.data_multicast_addr)
    }

    /// Hand a datagram to the relay instead of to a socket.
    ///
    /// The unicast doors above (both the ordinary and the best-effort
    /// send) are the only places every RTPS datagram passes through, so
    /// this is where a peer reachable only through the Discovery Server
    /// is served, rather than at each of their call sites. The address
    /// carries the whole decision: it was put in the peer's locator list
    /// by the discovery side precisely so the send path would not need to
    /// know anything new.
    ///
    /// With no relay installed the datagram is REFUSED, never written to a
    /// socket. `240.0.0.0/4` is reserved and does not route, so sending it
    /// would put a datagram on the wire that nothing can deliver and report
    /// success for it. The only way such an address reaches here without a
    /// relay is a foreign participant announcing one - `usable_unicast_locator`
    /// accepts any unicast IPv4 - and that is worth an error, not a send.
    fn send_relayed(&self, data: &[u8], address: Ipv4Addr) -> io::Result<usize> {
        match self.relay() {
            Some(egress) => egress.send(data, address),
            None => Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                format!(
                    "{address} is in the reserved relay range and this participant has no relay"
                ),
            )),
        }
    }

    /// THE single place every unicast and multicast USER DATA transmit
    /// that keeps the ordinary blocking semantics (`send_user_data_
    /// unicast`, `send_user_data_multicast` -- DATA, the on-write
    /// "piggyback" HEARTBEAT, ACKNACK, coherent control) reaches a real
    /// socket. The periodic HEARTBEAT path's best-effort transmit does
    /// NOT go through this: see `resolve_best_effort_unicast` /
    /// `transmit_best_effort_resolved` / `transmit_best_effort_
    /// multicast_resolved`, which never touch this function, so a mutex
    /// held while THIS one blocks is never also held under the
    /// periodic origin's send gate.
    fn transmit_user_data(
        &self,
        socket: &UdpSocket,
        data: &[u8],
        dest: &SocketAddr,
    ) -> io::Result<usize> {
        #[cfg(test)]
        {
            self.blocking_user_sends.fetch_add(1, Ordering::Relaxed);
            if let Some(result) = send_seam::intercept(data, false) {
                return result;
            }
        }
        socket.send_to(data, dest)
    }

    /// Install the Discovery Server relay for this transport.
    ///
    /// Returns the argument back if one was already installed: a transport
    /// serves one participant, which has one Discovery Server session, so a
    /// second installation means two sessions believe they own the send path
    /// and is a wiring fault rather than a race to be resolved silently.
    pub(crate) fn install_relay(&self, egress: RelayEgress) -> Result<(), RelayEgress> {
        self.relay.set(egress)
    }

    /// The installed relay, if this participant has one.
    pub(crate) fn relay(&self) -> Option<&RelayEgress> {
        self.relay.get()
    }
}

/// Append the configured external locators to a list of local ones.
///
/// `port_of` picks which of the two public ports applies to this list
/// (metatraffic or user data): the whole point of an external locator is
/// that the public port need not equal the bound one.
///
/// They go LAST so the local addresses keep their historical position: a
/// peer that scans in order, and the `HDDS_REUSEPORT` helper that reads the
/// first entry, both keep seeing a locally bound address first. An external
/// entry that duplicates a local one is dropped rather than announced twice.
fn append_external(
    locators: &mut Vec<SocketAddr>,
    external: &[ExternalLocator],
    port_of: impl Fn(&ExternalLocator) -> u16,
) {
    for entry in external {
        let addr = SocketAddr::new(std::net::IpAddr::V4(entry.address()), port_of(entry));
        if !locators.contains(&addr) {
            locators.push(addr);
        }
    }
}

// ===== Accessors =====

impl UdpTransport {
    /// Return the configured DDS domain ID.
    #[must_use]
    pub fn domain_id(&self) -> u32 {
        self.domain_id
    }

    /// Return the metatraffic unicast port advertised for SPDP/SEDP.
    #[must_use]
    pub fn metatraffic_unicast_port(&self) -> u16 {
        self.metatraffic_unicast_port
    }

    /// Get unicast locators for SPDP announcements.
    ///
    /// Returns a list of SocketAddr (IP:port) for unicast communication.
    /// Remote DDS implementations use these locators to send SEDP
    /// and user data directly to this participant.
    pub fn get_unicast_locators(&self) -> Vec<SocketAddr> {
        crate::trace_fn!("UdpTransport::get_unicast_locators");
        let mut locators = get_unicast_locators_filtered(
            self.iface,
            self.metatraffic_unicast_port,
            &self.interface_filter,
        );
        append_external(&mut locators, &self.external_locators, |external| {
            external.metatraffic_port()
        });
        locators
    }

    /// Get user data unicast locators for SEDP announcements.
    ///
    /// Returns a list of SocketAddr (IP:port) for user data communication.
    /// Remote DDS implementations use these locators to send user data
    /// directly to this participant.
    pub fn get_user_unicast_locators(&self, user_port: u16) -> Vec<SocketAddr> {
        let mut locators =
            get_unicast_locators_filtered(self.iface, user_port, &self.interface_filter);
        append_external(&mut locators, &self.external_locators, |external| {
            external.user_port()
        });
        locators
    }

    /// Addresses this transport announces although nothing here is bound to
    /// them. Empty unless configured (see
    /// [`TransportOptions::external_locators`](crate::transport::TransportOptions::external_locators)).
    #[must_use]
    pub fn external_locators(&self) -> &[ExternalLocator] {
        &self.external_locators
    }

    /// Get shared socket reference for MulticastListener.
    #[must_use]
    pub fn socket(&self) -> Arc<UdpSocket> {
        Arc::clone(&self.socket)
    }

    /// Get metatraffic unicast socket reference for SEDP reception.
    ///
    /// This socket is bound to the primary interface IP (e.g. 192.0.2.1:7410)
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

    /// True when this transport EMITS multicast
    /// ([`crate::transport::MulticastMode::Enabled`]).
    #[must_use]
    pub fn multicast_send_enabled(&self) -> bool {
        self.multicast_send
    }

    /// True when this transport joined the multicast group and the
    /// participant runs multicast listeners (`Enabled` or `ReceiveOnly`,
    /// and the join succeeded).
    #[must_use]
    pub fn multicast_receive_enabled(&self) -> bool {
        self.multicast_receive
    }

    /// Why multicast reception is off although the mode asked for it:
    /// `Some(cause)` when the group join failed on every interface and the
    /// transport degraded instead of failing participant creation.
    #[must_use]
    pub fn multicast_join_error(&self) -> Option<&str> {
        self.multicast_join_error.as_deref()
    }

    /// Whether the multicast send probe on the primary interface was refused
    /// at construction, so multicast leaves through the kernel's default
    /// route (typically a VPN that claims all multicast).
    #[must_use]
    pub fn multicast_if_blocked(&self) -> bool {
        self.multicast_if_blocked
    }

    /// Multicast sends refused so far because emission is disabled by
    /// policy (each returned `Err(ErrorKind::Unsupported)` to its caller).
    #[must_use]
    pub fn suppressed_multicast_sends(&self) -> u64 {
        self.suppressed_multicast_sends.load(Ordering::Relaxed)
    }

    /// Test-only: how many USER DATA sends on this transport (unicast or
    /// the multicast fallback alike) went through the ordinary blocking
    /// call. Used to pin that the periodic HEARTBEAT path is the only
    /// caller of the best-effort twins below, and that DATA / the
    /// on-write ("piggyback") HEARTBEAT / ACKNACK / coherent control keep
    /// the exact send they always had.
    #[cfg(test)]
    pub(crate) fn blocking_sends_for_test(&self) -> u64 {
        self.blocking_user_sends.load(Ordering::Relaxed)
    }

    /// Test-only: how many unicast or multicast USER DATA sends on this
    /// transport went through the best-effort (`MSG_DONTWAIT`, where
    /// available) twin -- see `send_user_data_unicast_best_effort`,
    /// `send_user_data_multicast_best_effort`.
    #[cfg(test)]
    pub(crate) fn best_effort_sends_for_test(&self) -> u64 {
        self.best_effort_user_sends.load(Ordering::Relaxed)
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

    /// Parse the first RTPS submessage kind from a packet body for debug
    /// logging. The RTPS header is 20 bytes total (4-byte magic, 2-byte
    /// version, 2-byte vendor, 12-byte guid prefix), so the first
    /// submessage kind lives at offset 20, not 16. Per RTPS v2.5 sec. 8.3.7
    /// Table 8.13 the kind->name mapping is `0x06 ACKNACK`, `0x07
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
    /// See RTPS v2.5 sec. 8.3.7 Table 8.13 for the canonical id space, plus
    /// sec. 8.3.5.10 for the v2.5 HEADER_EXTENSION (0x00) addition.
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

/// `UdpSocket::send_to`, except this ONE call is told not to block if the
/// kernel's send buffer has no room for it right now (`MSG_DONTWAIT`):
/// used only by the periodic HEARTBEAT path's best-effort sends
/// (`UdpTransport::send_user_data_unicast_best_effort`,
/// `send_user_data_multicast_best_effort`). The flag is per-call, not a
/// socket option, so `socket`'s own blocking mode never changes for any
/// OTHER caller sharing the same fd -- `set_nonblocking` is never called
/// here or anywhere else on this socket. A full buffer surfaces as the
/// ordinary `Err(ErrorKind::WouldBlock)`, which every caller of this path
/// already treats like any other send failure (a dropped tick, never a
/// stalled thread).
///
/// `MSG_DONTWAIT` exists in this crate's pinned `libc` (0.2.177) for
/// every unix target this crate otherwise supports: Linux/Android
/// (`src/unix/linux_like/mod.rs`), Apple's BSD lineage -- macOS/iOS
/// (`src/unix/bsd/apple/mod.rs`) -- and the rest of the BSD family it
/// already special-cases for `SO_REUSEPORT` elsewhere in this file:
/// FreeBSD/DragonFly (`src/unix/bsd/freebsdlike/mod.rs`) and
/// NetBSD/OpenBSD (`src/unix/bsd/netbsdlike/mod.rs`). An earlier version
/// of this function claimed the non-Apple BSD family lacked it and fell
/// back to the plain blocking send there too, which is false for the
/// libc sources of those platforms. Windows remains the one real gap: there
/// is no per-call non-blocking flag in Winsock, so it still degrades to
/// the plain blocking send -- a known, left-open gap there, not silently
/// claimed solved (see `dds::liveliness::scheduler`'s module doc for the
/// design this closes on every platform above).
#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "dragonfly",
    target_os = "netbsd",
    target_os = "openbsd"
))]
fn best_effort_send_to(socket: &UdpSocket, data: &[u8], dest: &SocketAddr) -> io::Result<usize> {
    let flags = libc::MSG_DONTWAIT;
    // Intercepted HERE, reading the actual `flags` this call is about to
    // make, not a separately-passed-in `bool` one level up: interception
    // before this function is even reached could not tell a correct `MSG_DONTWAIT` call apart
    // from a mutant that silently zeroed `flags` or skipped straight to
    // `socket.send_to` -- both took the same early return. Mutating
    // `flags` to `0` here makes the test seam see "not requesting
    // non-blocking" and switch to its releasable-block behavior, the
    // same as the plain blocking send would get.
    #[cfg(test)]
    if let Some(result) = send_seam::intercept(data, flags & libc::MSG_DONTWAIT != 0) {
        return result;
    }
    socket2::SockRef::from(socket).send_to_with_flags(data, &(*dest).into(), flags)
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "dragonfly",
    target_os = "netbsd",
    target_os = "openbsd"
)))]
fn best_effort_send_to(socket: &UdpSocket, data: &[u8], dest: &SocketAddr) -> io::Result<usize> {
    // No per-call non-blocking flag on this target (see the doc above):
    // this IS the real, still-blocking call, so the seam sees "not
    // requesting non-blocking" here too.
    #[cfg(test)]
    if let Some(result) = send_seam::intercept(data, false) {
        return result;
    }
    socket.send_to(data, dest)
}

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
/// DDS implementations commonly use 239.255.0.1:7400 for both SPDP and SEDP.
/// Using .2 is optional and rarely implemented.
///
/// Phase 1.6 interop: use 239.255.0.1 for both.
fn parse_sedp_multicast_addr(port: u16, label: &str) -> io::Result<SocketAddr> {
    // Use same multicast address as SPDP (239.255.0.1) for maximum compatibility
    parse_socket_addr(
        format_string(format_args!("{}:{}", MULTICAST_GROUP, port)),
        label,
    )
}

// data_multicast_addr is always computed from metatraffic_multicast + 1
// (RTPS v2.5 Sec.9.6.1.1, d2=1)

/// Bind a UDP socket on `0.0.0.0:port` that no other socket can share.
///
/// For the participant's unicast ports (metatraffic and user data), which
/// DDSI-RTPS 2.5 9.6.1.1 makes unique on the host through the participant
/// id. No `SO_REUSEADDR` and no `SO_REUSEPORT`: on Linux a socket without
/// them refuses any second binder of the port, whatever that binder sets;
/// BSD-family kernels refuse any second wildcard binder, and still admit a
/// `SO_REUSEADDR` binder on a more specific local address (no HDDS socket
/// binds one). Windows is one-sided: a later binder that sets
/// `SO_REUSEADDR` can take over a port held by a plain socket, so the
/// holder sets `SO_EXCLUSIVEADDRUSE` there, before `bind`.
///
/// UDP has no TIME_WAIT: the port is free again as soon as the last copy of
/// the socket is closed (process exit included).
pub(crate) fn bind_exclusive_unicast(port: u16) -> io::Result<Socket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    #[cfg(windows)]
    set_exclusive_address_use(&socket)?;
    let addr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, port));
    socket.bind(&addr.into())?;
    Ok(socket)
}

/// `SO_EXCLUSIVEADDRUSE` on a Windows socket, before it is bound.
///
/// windows-sys does not export the constant: the SDK defines it as
/// `((int)(~SO_REUSEADDR))`, with `SO_REUSEADDR` = 4.
#[cfg(windows)]
fn set_exclusive_address_use(socket: &Socket) -> io::Result<()> {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{setsockopt, SOCKET, SOCKET_ERROR, SOL_SOCKET};
    const SO_EXCLUSIVEADDRUSE: i32 = !4;
    // size_of::<i32>(), spelled as the i32 the call takes.
    const OPTLEN: i32 = 4;
    let enable: i32 = 1;
    let raw = SOCKET::try_from(socket.as_raw_socket())
        .map_err(|_| io::Error::other("socket handle does not fit a SOCKET"))?;
    // SAFETY: setsockopt on a live socket owned by `socket`, with a pointer
    // to a local i32 and its exact size; the call reads nothing else.
    let ret = unsafe {
        setsockopt(
            raw,
            SOL_SOCKET,
            SO_EXCLUSIVEADDRUSE,
            std::ptr::from_ref(&enable).cast::<u8>(),
            OPTLEN,
        )
    };
    if ret == SOCKET_ERROR {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Set SO_REUSEPORT on a socket for multi-process port sharing.
///
/// This enables multiple processes to bind to the same port, which is required
/// for HDDS<->HDDS inter-process discovery on the same machine.
/// Only available on Unix systems.
///
/// `pub(crate)`: also called from
/// `dds::participant::builder::sockets::create_data_multicast_socket`, the
/// other socket every participant on a domain binds to an identical port.
#[cfg(unix)]
pub(crate) fn set_reuseport(socket: &Socket) -> io::Result<()> {
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

/// Test-only interception at the actual send syscall (inside
/// `best_effort_send_to`'s two variants, and the plain blocking send in
/// `UdpTransport::transmit_user_data`), shared by every unicast and
/// multicast USER DATA transmit, blocking and best-effort alike: lets a
/// test make a SPECIFIC HEARTBEAT behave exactly as if its destination's
/// kernel send buffer were genuinely exhausted, without needing to force
/// that condition for real. Being at the real syscall site, keyed on the
/// REQUESTED flags (did this call actually ask not to block), is what
/// makes it able to tell a correct `MSG_DONTWAIT` call apart from a
/// mutant that silently drops it -- interception any earlier, using a
/// separately-passed-in `bool`, cannot.
///
/// Keyed on the HEARTBEAT's own full writer GUID -- 12-byte
/// participant GUID prefix from the RTPS header (bytes 8..20) plus
/// 4-byte writerEntityId from the HEARTBEAT body (RTPS v2.5 Sec.9.4.5.7)
/// -- never on the destination address or the entity id alone: a writer
/// with no matched reader shares the SAME multicast fallback address
/// with every OTHER writer on its participant, so the destination alone
/// cannot tell two writers' periodic ticks apart; entity ids restart
/// from the same small range on every participant, so a parallel test's
/// unrelated participant can easily collide on just the 4-byte id (a seam keyed on it alone could
/// intercept another test's writer entirely by accident).
#[cfg(test)]
pub(crate) mod send_seam {
    use std::collections::HashMap;
    use std::sync::{Arc, Condvar, Mutex};

    struct Armed {
        release: Arc<(Mutex<bool>, Condvar)>,
    }

    static ARMED: Mutex<Option<HashMap<[u8; 16], Armed>>> = Mutex::new(None);

    /// Arm `writer_guid` (16 bytes: 12-byte participant GUID prefix +
    /// 4-byte `RtpsEndpointContext::writer_entity_id`): the next
    /// HEARTBEAT transmit naming it as writerId either returns
    /// `Err(WouldBlock)` at once (the call actually requested
    /// non-blocking) or blocks until `release`'s flag is set `true` and
    /// its condvar notified (the call did not -- the mutant this seam
    /// exists to catch). Stays armed until `disarm`: several ticks for
    /// the same writer during one test hit it the same way.
    pub(crate) fn arm(writer_guid: [u8; 16], release: Arc<(Mutex<bool>, Condvar)>) {
        let mut slot = ARMED.lock().unwrap_or_else(|e| e.into_inner());
        slot.get_or_insert_with(HashMap::new)
            .insert(writer_guid, Armed { release });
    }

    /// Stop intercepting `writer_guid`. Idempotent.
    pub(crate) fn disarm(writer_guid: [u8; 16]) {
        let mut slot = ARMED.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(map) = slot.as_mut() {
            map.remove(&writer_guid);
        }
    }

    /// `None`: not intercepted (not a HEARTBEAT, or its writer GUID is
    /// not armed) -- the caller must do the real send. `Some`: the whole
    /// outcome for this call. `requested_nonblocking` is the ACTUAL
    /// property of the call about to be made (read at its real syscall
    /// site), never a value computed anywhere else.
    pub(super) fn intercept(
        packet: &[u8],
        requested_nonblocking: bool,
    ) -> Option<std::io::Result<usize>> {
        let writer_guid = heartbeat_writer_guid(packet)?;
        let release = {
            let slot = ARMED.lock().unwrap_or_else(|e| e.into_inner());
            slot.as_ref()?.get(&writer_guid)?.release.clone()
        };
        if requested_nonblocking {
            return Some(Err(std::io::Error::from(std::io::ErrorKind::WouldBlock)));
        }
        let (lock, cv) = &*release;
        let guard = lock.lock().unwrap_or_else(|e| e.into_inner());
        let _guard = cv
            .wait_while(guard, |ready| !*ready)
            .unwrap_or_else(|e| e.into_inner());
        Some(Ok(packet.len()))
    }

    /// The full writer GUID (12-byte participant prefix from the RTPS
    /// header, bytes 8..20, plus the 4-byte writerEntityId) of the
    /// FIRST HEARTBEAT (0x07) submessage found by walking `packet`'s
    /// submessages from offset 20, or `None` if there is none. The
    /// HEARTBEAT is not necessarily the very first submessage (offset 20):
    /// classic-dialect translation
    /// (`WriterWindows::resolve_native`) can prepend an INFO_DST
    /// (0x0e) submessage naming the destination participant ahead of
    /// it, which this walk skips over the same way the HEARTBEAT
    /// decoding helper in `participant_heartbeat_tests.rs` does.
    fn heartbeat_writer_guid(packet: &[u8]) -> Option<[u8; 16]> {
        let mut at = 20usize;
        while at + 4 <= packet.len() {
            let id = packet[at];
            let le = packet[at + 1] & 0x01 != 0;
            let len = if le {
                u16::from_le_bytes([packet[at + 2], packet[at + 3]])
            } else {
                u16::from_be_bytes([packet[at + 2], packet[at + 3]])
            } as usize;
            if id == 0x07 {
                // RTPS v2.5 Sec.9.4.5.7 HEARTBEAT body: readerId at
                // body+0, writerId at body+4; body = at + 4.
                let body = at + 4;
                let mut writer_guid = [0u8; 16];
                writer_guid[..12].copy_from_slice(packet.get(8..20)?);
                writer_guid[12..].copy_from_slice(packet.get(body + 4..body + 8)?);
                return Some(writer_guid);
            }
            if len == 0 {
                return None;
            }
            at += 4 + len;
        }
        None
    }
}

// ===== Tests =====

#[cfg(test)]
#[path = "udp_test.rs"]
mod tests;

/// Decide what a failed multicast group join means for the transport.
///
/// `required` (`TransportOptions::require_multicast_join`): the error is
/// returned and participant creation fails. Otherwise the transport degrades:
/// reception is switched off, the cause is kept for `multicast_join_error()`,
/// a WARN is logged once, and the fallback interface address is used.
fn resolve_join_outcome(
    result: io::Result<Ipv4Addr>,
    required: bool,
    fallback_iface: Ipv4Addr,
) -> io::Result<(Ipv4Addr, bool, Option<String>)> {
    match result {
        Ok(iface) => Ok((iface, true, None)),
        Err(err) if required => {
            log::error!(
                "[UDP] multicast group join failed on every interface and require_multicast_join is set: {}",
                err
            );
            Err(err)
        }
        Err(err) => {
            log::warn!(
                "[UDP] multicast group join failed on every interface ({}); continuing WITHOUT multicast reception (unicast discovery only). Set TransportOptions::require_multicast_join to fail instead.",
                err
            );
            Ok((fallback_iface, false, Some(err.to_string())))
        }
    }
}

#[cfg(test)]
mod multicast_policy_tests {
    use super::*;
    use crate::transport::{CustomPortMapping, MulticastMode, PortMapping, TransportOptions};

    /// Build a transport on freshly reserved ports, retrying when another
    /// test grabbed a reserved port between the reservation and the bind
    /// (the reserve-drop-rebind window is a known race under `cargo test`
    /// parallelism).
    fn transport(mode: MulticastMode) -> UdpTransport {
        let options = TransportOptions {
            multicast: mode,
            ..TransportOptions::default()
        }
        .resolve();
        crate::test_support::ports::with_reserved_ports(
            8,
            |[spdp_multicast, sedp_unicast, user_unicast]| {
                let mapping = PortMapping::from_custom(CustomPortMapping {
                    spdp_multicast,
                    sedp_unicast,
                    user_unicast,
                });
                UdpTransport::new_with_options(42, 0, mapping, &options)
            },
        )
        .unwrap_or_else(|e| panic!("transport: ports kept colliding: {e:?}"))
    }

    #[test]
    fn suppressed_multicast_send_is_an_error_not_a_fake_success() {
        let t = transport(MulticastMode::ReceiveOnly);
        assert_eq!(t.suppressed_multicast_sends(), 0);
        let err = t
            .send(b"RTPS")
            .expect_err("emission disabled must not report success");
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
        let err = t
            .send_user_data_multicast(b"RTPS")
            .expect_err("emission disabled must not report success");
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
        assert!(t.send_sedp(b"RTPS").is_err());
        assert_eq!(t.suppressed_multicast_sends(), 3);
        assert!(t.multicast_join_error().is_none());
    }

    #[test]
    fn enabled_transport_sends_and_counts_nothing() {
        let t = transport(MulticastMode::Enabled);
        t.send(b"RTPS").expect("multicast send in Enabled mode");
        assert_eq!(t.suppressed_multicast_sends(), 0);
    }

    #[test]
    fn join_failure_degrades_unless_required() {
        let fallback = Ipv4Addr::new(10, 0, 0, 1);
        let fail = || io::Error::other("no multicast-capable interface");
        let (iface, receive, error) =
            resolve_join_outcome(Err(fail()), false, fallback).expect("degrade, not fail");
        assert_eq!(iface, fallback);
        assert!(!receive);
        assert_eq!(error.as_deref(), Some("no multicast-capable interface"));

        assert!(resolve_join_outcome(Err(fail()), true, fallback).is_err());

        let ok = Ipv4Addr::new(192, 0, 2, 7);
        let (iface, receive, error) =
            resolve_join_outcome(Ok(ok), true, fallback).expect("join ok");
        assert_eq!((iface, receive, error), (ok, true, None));
    }
}

#[cfg(test)]
mod external_locator_advertising_tests {
    use super::*;
    use crate::transport::{CustomPortMapping, ExternalLocator, PortMapping, TransportOptions};

    /// A routable address nobody here owns. Deliberately NOT a documentation
    /// range: `select_best_locator` does not count those as globally
    /// routable, so a test built on one would not describe a locator a peer
    /// would actually pick.
    const PUBLIC: Ipv4Addr = Ipv4Addr::new(93, 184, 216, 34);
    /// Public ports of the imagined NAT mapping. Different from each other
    /// AND from anything `with_reserved_ports` hands out (it stays in the
    /// ephemeral range), so an assertion can tell them apart.
    const PUBLIC_METATRAFFIC: u16 = 40001;
    const PUBLIC_USER: u16 = 40002;

    /// Build a real transport on reserved ports, returning it with the
    /// user-data port it was bound to (`get_user_unicast_locators` takes
    /// that port as an argument).
    fn transport_with(external: Vec<ExternalLocator>) -> (UdpTransport, u16) {
        let options = TransportOptions::default()
            .with_external_locators(external)
            .resolve();
        crate::test_support::ports::with_reserved_ports(
            8,
            |[spdp_multicast, sedp_unicast, user_unicast]| {
                let mapping = PortMapping::from_custom(CustomPortMapping {
                    spdp_multicast,
                    sedp_unicast,
                    user_unicast,
                });
                UdpTransport::new_with_options(42, 0, mapping, &options)
                    .map(|transport| (transport, user_unicast))
            },
        )
        .unwrap_or_else(|e| panic!("transport: ports kept colliding: {e:?}"))
    }

    fn public_locator() -> ExternalLocator {
        ExternalLocator::new(PUBLIC, PUBLIC_METATRAFFIC, PUBLIC_USER).expect("valid")
    }

    #[test]
    fn nothing_configured_announces_the_default_set() {
        let (transport, user_port) = transport_with(Vec::new());
        assert!(transport.external_locators().is_empty());
        for locator in transport.get_unicast_locators() {
            assert_eq!(locator.port(), transport.metatraffic_unicast_port());
            assert_ne!(locator.ip(), std::net::IpAddr::V4(PUBLIC));
        }
        for locator in transport.get_user_unicast_locators(user_port) {
            assert_eq!(locator.port(), user_port);
        }
    }

    #[test]
    fn an_external_locator_is_added_to_the_local_ones_not_substituted() {
        let (bare, _) = transport_with(Vec::new());
        let local_count = bare.get_unicast_locators().len();
        drop(bare);

        let (transport, _) = transport_with(vec![public_locator()]);
        let announced = transport.get_unicast_locators();
        assert_eq!(
            announced.len(),
            local_count + 1,
            "the external entry must ADD to the local list: {announced:?}"
        );
        // Local addresses keep their historical position, so a peer that
        // scans in order still meets a bound address first.
        if let Some(first) = announced.first() {
            assert_eq!(first.port(), transport.metatraffic_unicast_port());
        }
        assert_eq!(
            announced.last(),
            Some(&SocketAddr::new(
                std::net::IpAddr::V4(PUBLIC),
                PUBLIC_METATRAFFIC
            ))
        );
    }

    #[test]
    fn the_user_data_list_carries_the_public_user_port_not_the_local_one() {
        // The discriminating assertion of this whole change. Deriving the
        // user-data list by rewriting the metatraffic list's port - which is
        // what the code did before - would advertise PUBLIC:<local user
        // port>, an address:port pair that maps to nothing.
        let (transport, user_port) = transport_with(vec![public_locator()]);
        let announced = transport.get_user_unicast_locators(user_port);

        let public_entries: Vec<_> = announced
            .iter()
            .filter(|addr| addr.ip() == std::net::IpAddr::V4(PUBLIC))
            .collect();
        assert_eq!(
            public_entries.len(),
            1,
            "exactly one public entry expected: {announced:?}"
        );
        assert_eq!(public_entries[0].port(), PUBLIC_USER);
        assert_ne!(
            public_entries[0].port(),
            user_port,
            "the public user port must not be the locally bound one"
        );
        assert_ne!(public_entries[0].port(), PUBLIC_METATRAFFIC);
    }

    #[test]
    fn append_external_drops_an_entry_that_duplicates_a_local_one() {
        // Announcing the same address:port twice puts two identical
        // PID_METATRAFFIC_UNICAST_LOCATOR on the wire for no gain.
        let local = SocketAddr::new(std::net::IpAddr::V4(PUBLIC), PUBLIC_METATRAFFIC);
        let mut locators = vec![local];
        append_external(&mut locators, &[public_locator()], |e| e.metatraffic_port());
        assert_eq!(locators, vec![local]);
    }

    #[test]
    fn append_external_keeps_configuration_order_after_the_local_ones() {
        let local = SocketAddr::from(([192, 168, 1, 50], 7410));
        let second =
            ExternalLocator::new(Ipv4Addr::new(198, 51, 100, 9), 50001, 50002).expect("valid");
        let mut locators = vec![local];
        append_external(&mut locators, &[public_locator(), second], |e| {
            e.metatraffic_port()
        });
        assert_eq!(
            locators,
            vec![
                local,
                SocketAddr::new(std::net::IpAddr::V4(PUBLIC), PUBLIC_METATRAFFIC),
                SocketAddr::from(([198, 51, 100, 9], 50001)),
            ]
        );
    }
}
