// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Locator PID Handlers for SPDP
//!
//!
//! Handles parsing of locator-related PIDs according to DDS-RTPS v2.3 Sec.8.5.3.1:
//! - PID_METATRAFFIC_UNICAST_LOCATOR (0x0032)
//! - PID_METATRAFFIC_MULTICAST_LOCATOR (0x0033)
//! - PID_DEFAULT_UNICAST_LOCATOR (0x0031)
//! - PID_DEFAULT_MULTICAST_LOCATOR (0x0048)

use crate::protocol::discovery::spdp::types::SpdpData;
use crate::protocol::discovery::types::ParseError;
use std::convert::TryFrom;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

/// Decode locator port handling both big-endian (spec) and little-endian encodings.
/// Some vendors emit the Locator_t.port field in LE; be permissive so discovery works.
fn decode_locator_port(raw: [u8; 4]) -> Option<u16> {
    let be = u32::from_be_bytes(raw);
    let le = u32::from_le_bytes(raw);

    let be_u16 = u16::try_from(be).ok();
    let le_u16 = u16::try_from(le).ok();

    match (be_u16, le_u16) {
        // Only BE fits -> spec-compliant peer.
        (Some(p_be), None) => Some(p_be),
        // Only LE fits -> tolerate a little-endian port encoding.
        (None, Some(p_le)) => Some(p_le),
        // Both decode -> prefer spec value.
        (Some(p_be), Some(_)) => Some(p_be),
        _ => None,
    }
}

/// Parse a 24-byte RTPS `Locator_t` at `buf[offset..]` honoring the `kind` field
/// (RTPS v2.3 Sec.9.3.1: 1 = UDPv4, 2 = UDPv6). A UDPv4 address is the last 4
/// bytes of the 16-byte address; a UDPv6 address is all 16 bytes. Unknown or
/// INVALID (-1) kinds return `None` so the locator is skipped instead of being
/// misread as a garbage IPv4 -- the SEDP parser already does this
/// (`sedp/parse.rs`). The `kind` is read permissively in either byte order, like
/// the port, since some peers emit the Locator_t fields little-endian.
fn parse_locator_kind_aware(buf: &[u8], offset: usize) -> Option<SocketAddr> {
    let port = decode_locator_port([
        buf[offset + 4],
        buf[offset + 5],
        buf[offset + 6],
        buf[offset + 7],
    ])?;
    let kind_raw = [
        buf[offset],
        buf[offset + 1],
        buf[offset + 2],
        buf[offset + 3],
    ];
    let kind = {
        let le = i32::from_le_bytes(kind_raw);
        let be = i32::from_be_bytes(kind_raw);
        if le == 1 || le == 2 {
            le
        } else if be == 1 || be == 2 {
            be
        } else {
            le
        }
    };
    match kind {
        1 => {
            // LOCATOR_KIND_UDPv4: IPv4 in the last 4 bytes of the address field.
            let ip = Ipv4Addr::new(
                buf[offset + 20],
                buf[offset + 21],
                buf[offset + 22],
                buf[offset + 23],
            );
            Some(SocketAddr::new(IpAddr::V4(ip), port))
        }
        2 => {
            // LOCATOR_KIND_UDPv6: HDDS transports over UDPv4 only, so a UDPv6
            // locator is unusable. Skip it (return None) rather than store a
            // SocketAddr we can never send to -- and crucially, never misread
            // its 16 address bytes as a garbage IPv4.
            // The unused Ipv6 parse is kept documented for if/when v6 transport
            // lands; see the SEDP parser which stores v6 once transport exists.
            log::debug!("[spdp] locator: skipping UDPv6 (kind=2), HDDS transport is IPv4-only");
            None
        }
        _ => {
            log::debug!("[spdp] locator: skipping unsupported kind={}", kind);
            None
        }
    }
}

/// Parse PID_METATRAFFIC_UNICAST_LOCATOR (0x0032)
///
/// Metatraffic unicast locators (typically port 7410) are used for:
/// - SEDP discovery messages
/// - ACKNACK/NACKFRAG control messages
///
/// # RTPS v2.3 Sec.9.3.1 Locator_t Structure
/// ```text
/// struct Locator_t {
///   long kind;        // 4 bytes: LOCATOR_KIND_UDPv4 (1), LOCATOR_KIND_UDPv6 (2)
///   unsigned long port; // 4 bytes: Network port (big-endian per RTPS spec)
///   octet address[16]; // 16 bytes: IPv4 in last 4 bytes, first 12 are zeros
/// };
/// ```
/// Total: 24 bytes (RTPS v2.3 Sec.8.3.4.2)
pub(super) fn parse_metatraffic_unicast_locator_pid(
    buf: &[u8],
    offset: usize,
    length: usize,
    spdp_data: &mut SpdpData,
) -> Result<(), ParseError> {
    if length >= 24 {
        if let Some(socket_addr) = parse_locator_kind_aware(buf, offset) {
            log::debug!("[spdp] Metatraffic unicast locator: {}", socket_addr);
            spdp_data.metatraffic_unicast_locators.push(socket_addr); // separate list
        }
    }
    Ok(())
}

/// Parse PID_METATRAFFIC_MULTICAST_LOCATOR (0x0033)
///
/// Parse metatraffic multicast locators (RTPS v2.3 Sec.8.5.3.1)
/// Metatraffic multicast locators (typically port 7400) are used for:
/// - SPDP participant announcements (multicast)
/// - SEDP endpoint announcements (multicast)
pub(super) fn parse_metatraffic_multicast_locator_pid(
    buf: &[u8],
    offset: usize,
    length: usize,
    spdp_data: &mut SpdpData,
) -> Result<(), ParseError> {
    if length >= 24 {
        if let Some(sock) = parse_locator_kind_aware(buf, offset) {
            spdp_data.metatraffic_multicast_locators.push(sock);
            log::debug!("[spdp] Metatraffic multicast locator: {}", sock);
        }
    }
    Ok(())
}

/// Parse PID_DEFAULT_UNICAST_LOCATOR (0x0031)
///
/// Default unicast locators (typically port 7411) are used for:
/// - User data delivery (application messages)
/// - Required per RTPS v2.3 Sec.8.5.3.1
pub(super) fn parse_default_unicast_locator_pid(
    buf: &[u8],
    offset: usize,
    length: usize,
    spdp_data: &mut SpdpData,
) -> Result<(), ParseError> {
    if length >= 24 {
        if let Some(sock) = parse_locator_kind_aware(buf, offset) {
            spdp_data.default_unicast_locators.push(sock); // separate list
            log::debug!("[spdp] Default unicast locator: {}", sock);
        }
    }
    Ok(())
}

/// Parse PID_DEFAULT_MULTICAST_LOCATOR (0x0048)
///
/// Parse default multicast locators (RTPS v2.3 Sec.8.5.3.1)
/// Default multicast locators are used for:
/// - User data multicast delivery
pub(super) fn parse_default_multicast_locator_pid(
    buf: &[u8],
    offset: usize,
    length: usize,
    spdp_data: &mut SpdpData,
) -> Result<(), ParseError> {
    if length >= 24 {
        if let Some(sock) = parse_locator_kind_aware(buf, offset) {
            spdp_data.default_multicast_locators.push(sock);
            log::debug!("[spdp] Default multicast locator: {}", sock);
        }
    }
    Ok(())
}
