// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Participant discovery data structures and GAP message handling.

use crate::dds::Result;
// v110: Removed unused imports (SPDP_PAYLOAD_BUFFER_SIZE, rtps_constants)
// - build_spdp_packet() moved to multicast::build_spdp_rtps_packet()
use crate::reliability::{GapMsg, GapRx, GapTracker, NackScheduler, RtpsRange};
use std::net::Ipv4Addr;

/// Bitmask to extract lower 32 bits from 128-bit timestamp
/// Used for generating participant IDs from nanosecond timestamps
const LOWER_32_BITS_MASK: u128 = 0xFFFFFFFF;

/// Network peer address + port (IPv4-mapped IPv6)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetPeer {
    pub addr: [u8; 16], // IPv6 (or IPv4-mapped)
    pub port: u16,
}

impl NetPeer {
    /// Create NetPeer from IPv4 address and port
    pub fn from_ipv4(addr: Ipv4Addr, port: u16) -> Self {
        // Store as IPv6-mapped IPv4: ::ffff:a.b.c.d
        let mut ipv6_addr = [0u8; 16];
        ipv6_addr[10] = 0xFF;
        ipv6_addr[11] = 0xFF;
        ipv6_addr[12..16].copy_from_slice(&addr.octets());

        Self {
            addr: ipv6_addr,
            port,
        }
    }

    /// Extract IPv4 address if this is an IPv4-mapped address
    pub fn as_ipv4(&self) -> Option<Ipv4Addr> {
        // Check for IPv6-mapped IPv4 prefix (::ffff:a.b.c.d)
        if self.addr[10] == 0xFF && self.addr[11] == 0xFF {
            Some(Ipv4Addr::new(
                self.addr[12],
                self.addr[13],
                self.addr[14],
                self.addr[15],
            ))
        } else {
            None
        }
    }
}

/// SPDP discovery & seed bootstrap
///
/// Phase 4 (T0): Basic seed parsing and announce structures.
/// Full threading and UDP networking will be implemented in Phase 5.
pub struct Discovery {
    /// Seed peers parsed from config
    seeds: Vec<NetPeer>,

    /// Local participant ID (generated)
    participant_id: u32,
}

impl Discovery {
    /// Start discovery from seed peers (comma-separated "host:port")
    ///
    /// # Arguments
    /// - `seeds`: Comma-separated list of "host:port" (e.g., "127.0.0.1:5500,127.0.0.1:5501")
    ///
    /// # Returns
    /// Discovery instance with parsed seed peers
    ///
    /// # Errors
    /// Returns Error::Config if seed string is malformed
    ///
    /// # Examples
    ///
    /// ```
    /// use hdds::core::discovery::Discovery;
    ///
    /// let disco = Discovery::start_unicast("127.0.0.1:5500,127.0.0.1:5501")
    ///     .expect("Discovery initialization should succeed");
    /// ```
    pub fn start_unicast(seeds: &str) -> Result<Self> {
        crate::trace_fn!("Discovery::start_unicast");
        let parsed_seeds = parse_seed_peers(seeds)?;

        Ok(Self {
            seeds: parsed_seeds,
            participant_id: generate_participant_id(),
        })
    }

    /// Send SPDP announce message to all seed peers
    ///
    /// Constructs an SPDP DATA packet containing participant metadata and sends
    /// it via UDP to each configured seed peer for unicast discovery.
    ///
    /// # RTPS Packet Structure
    ///
    /// ```text
    /// [RTPS Header - 16 bytes]
    /// [DATA Submessage - variable]
    ///   - SPDP participant announcement
    ///   - PID_PARTICIPANT_GUID
    ///   - PID_PARTICIPANT_LEASE_DURATION
    ///   - PID_SENTINEL
    /// ```
    ///
    /// # Returns
    ///
    /// `Ok(())` if announce was sent to all seeds, `Err(Error::Transport)` on UDP failure.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use hdds::core::discovery::Discovery;
    ///
    /// let disco = Discovery::start_unicast("127.0.0.1:7400").expect("start discovery"); // TEST: Start discovery
    /// disco.announce().expect("announce succeeds"); // TEST: Sends SPDP to 127.0.0.1:7400
    /// ```
    /// v110: Refactored to use centralized multicast::build_spdp_rtps_packet()
    /// This eliminates duplicated RTPS packet construction and uses DialectEncoder
    /// for proper vendor interoperability.
    pub fn announce(&self) -> crate::dds::Result<()> {
        crate::trace_fn!("Discovery::announce");
        use crate::core::discovery::multicast::build_spdp_rtps_packet;
        use crate::core::discovery::GUID;
        use crate::protocol::discovery::SpdpData;

        // Create SPDP participant data
        let spdp_data = SpdpData {
            participant_guid: GUID::from_bytes({
                let mut bytes = [0u8; 16];
                bytes[12..16].copy_from_slice(&self.participant_id.to_le_bytes());
                bytes[15] = 0x01; // Entity kind: PARTICIPANT
                bytes
            }),
            lease_duration_ms: 100_000, // 100 seconds (RTPS default)
            domain_id: 0, // v208: initial announce uses domain 0 (overridden by SpdpAnnouncer)
            metatraffic_unicast_locators: Vec::new(), // No locators in initial announce (discovery-only)
            default_unicast_locators: Vec::new(),
            default_multicast_locators: Vec::new(),
            metatraffic_multicast_locators: Vec::new(),
            identity_token: None,
        };

        // v110: Use centralized builder with DialectEncoder support
        // sequence_number=1 for initial announce, destination_prefix=None for broadcast
        let packet = build_spdp_rtps_packet(&spdp_data, 1, None)
            .map_err(|_| crate::dds::Error::SerializationError)?;

        // Send to all seed peers
        send_to_seeds(&packet, &self.seeds)
    }

    /// Get seed peers
    pub fn seeds(&self) -> &[NetPeer] {
        &self.seeds
    }
}

// ===== Private Helpers for Discovery::announce() =====

// v110: build_spdp_packet() REMOVED - use multicast::build_spdp_rtps_packet() instead
// This eliminates ~40 lines of duplicated RTPS packet construction code.
// The multicast version uses DialectEncoder for proper vendor interop.

/// Send RTPS packet to all seed peers via UDP
///
/// # Arguments
/// - `packet`: Complete RTPS packet to send
/// - `seeds`: List of seed peers
///
/// # Returns
/// `Ok(())` if sent to all seeds, `Err(Error::Transport)` on UDP failure
///
/// # Implementation Notes
/// - Creates ephemeral UDP socket (port 0 = OS-assigned)
/// - Sends to IPv4-mapped seeds only (IPv6 not yet supported)
/// - Fails fast on first transport error
fn send_to_seeds(packet: &[u8], seeds: &[NetPeer]) -> crate::dds::Result<()> {
    use std::net::UdpSocket;

    let socket = UdpSocket::bind("0.0.0.0:0").map_err(|_| crate::dds::Error::TransportError)?;

    for seed in seeds {
        if let Some(ipv4) = seed.as_ipv4() {
            let addr = std::net::SocketAddr::new(std::net::IpAddr::V4(ipv4), seed.port);
            socket
                .send_to(packet, addr)
                .map_err(|_| crate::dds::Error::TransportError)?;
        }
    }

    Ok(())
}

/// Parse seed peers from config string
///
/// # Format
/// "host:port,host:port,..."
///
/// # Returns
/// Vec<NetPeer> on success
///
/// # Errors
/// - Error::Config: Malformed host:port format
fn parse_seed_peers(seed_str: &str) -> Result<Vec<NetPeer>> {
    if seed_str.trim().is_empty() {
        return Ok(Vec::new());
    }

    seed_str
        .split(',')
        .map(|s| {
            let s = s.trim();
            let parts: Vec<&str> = s.split(':').collect();

            if parts.len() != 2 {
                return Err(crate::dds::Error::Config);
            }

            let addr = parts[0]
                .parse::<Ipv4Addr>()
                .map_err(|_| crate::dds::Error::Config)?;
            let port = parts[1]
                .parse::<u16>()
                .map_err(|_| crate::dds::Error::Config)?;

            Ok(NetPeer::from_ipv4(addr, port))
        })
        .collect()
}

/// Generate unique participant ID
///
/// For Phase 4: Simple random ID.
/// For Phase 5: Use MAC address + timestamp + random.
fn generate_participant_id() -> u32 {
    use std::time::{SystemTime, UNIX_EPOCH};

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();

    // Simple hash: timestamp lower 32 bits XOR process ID-like value
    // LOWER_32_BITS_MASK ensures the value fits in u32
    let timestamp = (now.as_nanos() & LOWER_32_BITS_MASK) as u32;
    timestamp ^ std::process::id()
}

/// Apply GAP notification to reader reliability state.
///
/// This helper routes a GAP message through the local `GapRx`, updates the
/// reader's `GapTracker`, and informs the `NackScheduler` so that pending
/// NACK retries stop targeting the lost sequences.
pub fn handle_gap(
    tracker: &mut GapTracker,
    scheduler: &mut NackScheduler,
    gap_rx: &mut GapRx,
    gap: &GapMsg,
) {
    let lost_ranges = gap_rx.on_gap(gap);
    for range in &lost_ranges {
        tracker.mark_lost(range.clone().into());
    }
    scheduler.mark_lost_ranges(lost_ranges.into_iter().map(RtpsRange::from));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reliability::{
        GapMsg, GapRx, GapTracker, NackScheduler, RtpsRange, ENTITYID_UNKNOWN_READER,
        ENTITYID_UNKNOWN_WRITER,
    };
    use std::net::Ipv4Addr;

    #[test]
    fn test_parse_seed_peers_single() {
        let seeds = parse_seed_peers("127.0.0.1:5500").expect("Should parse seed"); // TEST: Parse valid seed
        assert_eq!(seeds.len(), 1);
        assert_eq!(seeds[0].port, 5500);
        assert_eq!(
            seeds[0].as_ipv4().expect("Should be IPv4"), // TEST: Convert to IPv4
            Ipv4Addr::LOCALHOST
        );
    }

    #[test]
    fn test_parse_seed_peers_multiple() {
        let seeds =
            parse_seed_peers("127.0.0.1:5500,192.168.1.10:5501").expect("Should parse seeds"); // TEST: Parse multiple seeds
        assert_eq!(seeds.len(), 2);
        assert_eq!(seeds[0].port, 5500);
        assert_eq!(seeds[1].port, 5501);
        assert_eq!(
            seeds[0].as_ipv4().expect("Should be IPv4"), // TEST: Convert first seed to IPv4
            Ipv4Addr::LOCALHOST
        );
        assert_eq!(
            seeds[1].as_ipv4().expect("Should be IPv4"), // TEST: Convert second seed to IPv4
            Ipv4Addr::new(192, 168, 1, 10)
        );
    }

    #[test]
    fn test_parse_seed_peers_with_whitespace() {
        let seeds = parse_seed_peers(" 127.0.0.1:5500 , 192.168.1.10:5501 ")
            .expect("Should parse with whitespace"); // TEST: Parse with whitespace
        assert_eq!(seeds.len(), 2);
    }

    #[test]
    fn test_parse_seed_peers_empty() {
        let seeds = parse_seed_peers("").expect("Should parse empty"); // TEST: Parse empty string
        assert_eq!(seeds.len(), 0);
    }

    #[test]
    fn test_parse_seed_peers_invalid_format() {
        assert!(parse_seed_peers("127.0.0.1").is_err()); // Missing port
        assert!(parse_seed_peers("127.0.0.1:5500:extra").is_err()); // Too many colons
        assert!(parse_seed_peers("invalid:5500").is_err()); // Invalid IP
        assert!(parse_seed_peers("127.0.0.1:invalid").is_err()); // Invalid port
    }

    #[test]
    fn test_netpeer_from_ipv4() {
        let peer = NetPeer::from_ipv4(Ipv4Addr::new(192, 168, 1, 100), 8080);
        assert_eq!(peer.port, 8080);
        assert_eq!(
            peer.as_ipv4().expect("Should be IPv4"), // TEST: Convert NetPeer to IPv4
            Ipv4Addr::new(192, 168, 1, 100)
        );
    }

    #[test]
    fn test_netpeer_ipv6_mapped() {
        let peer = NetPeer::from_ipv4(Ipv4Addr::new(10, 0, 0, 1), 5500);

        // Check IPv6-mapped format: ::ffff:a.b.c.d
        assert_eq!(peer.addr[10], 0xFF);
        assert_eq!(peer.addr[11], 0xFF);
        assert_eq!(peer.addr[12], 10);
        assert_eq!(peer.addr[13], 0);
        assert_eq!(peer.addr[14], 0);
        assert_eq!(peer.addr[15], 1);
    }

    #[test]
    fn test_discovery_start_unicast() {
        let disco = Discovery::start_unicast("127.0.0.1:5500,127.0.0.1:5501")
            .expect("Should start discovery"); // TEST: Start discovery with seeds
        assert_eq!(disco.seeds().len(), 2);
    }

    #[test]
    fn test_discovery_announce_sends_spdp() {
        let disco = Discovery::start_unicast("127.0.0.1:5500").expect("Should start discovery"); // TEST: Start discovery for announce
        let result = disco.announce();
        assert!(result.is_ok(), "Announce should succeed"); // TEST: Announce returns Ok
    }

    #[test]
    fn test_generate_participant_id_unique() {
        let id1 = generate_participant_id();
        std::thread::sleep(std::time::Duration::from_millis(1));
        let id2 = generate_participant_id();

        // IDs should be different (timestamp-based)
        // Note: This can flake on very fast systems, but generally holds
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_handle_gap_updates_state() {
        let mut tracker = GapTracker::new();
        let mut scheduler = NackScheduler::with_window_ms(1);
        tracker.on_receive(1);
        tracker.on_receive(5);
        scheduler.on_receive(1);
        scheduler.on_receive(5);

        let mut rx = GapRx::new();
        let gap = GapMsg::contiguous(
            ENTITYID_UNKNOWN_READER,
            ENTITYID_UNKNOWN_WRITER,
            RtpsRange::new(2, 5),
        )
        .expect("valid range");

        handle_gap(&mut tracker, &mut scheduler, &mut rx, &gap);

        assert!(tracker.pending_gaps().is_empty());
        assert!(scheduler.pending_gaps().is_empty());
        assert_eq!(rx.total_lost(), 3);
    }
}
