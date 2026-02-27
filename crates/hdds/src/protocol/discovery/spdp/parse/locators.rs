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

use crate::core::string_utils::format_string;
use crate::protocol::discovery::spdp::types::SpdpData;
use crate::protocol::discovery::types::ParseError;
use std::convert::TryFrom;
use std::net::Ipv4Addr;

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
        // Only LE fits -> tolerate FastDDS-style encoding.
        (None, Some(p_le)) => Some(p_le),
        // Both decode -> prefer spec value.
        (Some(p_be), Some(_)) => Some(p_be),
        _ => None,
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
        let port_bytes = [
            buf[offset + 4],
            buf[offset + 5],
            buf[offset + 6],
            buf[offset + 7],
        ];

        let addr = Ipv4Addr::new(
            buf[offset + 20],
            buf[offset + 21],
            buf[offset + 22],
            buf[offset + 23],
        );

        if let Some(port_u16) = decode_locator_port(port_bytes) {
            if let Ok(socket_addr) = format_string(format_args!("{}:{}", addr, port_u16)).parse() {
                log::debug!("[spdp] Metatraffic unicast locator: {}", socket_addr);
                spdp_data.metatraffic_unicast_locators.push(socket_addr); // v79: separate list
            }
        } else {
            log::debug!(
                "[spdp] [!]  Failed to decode metatraffic unicast port from bytes: {:02x?}",
                port_bytes
            );
        }
    }
    Ok(())
}

/// Parse PID_METATRAFFIC_MULTICAST_LOCATOR (0x0033)
///
/// v79: Parse metatraffic multicast locators (RTPS v2.3 Sec.8.5.3.1)
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
        let port_bytes = [
            buf[offset + 4],
            buf[offset + 5],
            buf[offset + 6],
            buf[offset + 7],
        ];
        let addr = Ipv4Addr::new(
            buf[offset + 20],
            buf[offset + 21],
            buf[offset + 22],
            buf[offset + 23],
        );
        if let Some(port_u16) = decode_locator_port(port_bytes) {
            if let Ok(sock) = format_string(format_args!("{}:{}", addr, port_u16)).parse() {
                spdp_data.metatraffic_multicast_locators.push(sock);
                log::debug!("[spdp] Metatraffic multicast locator: {}", sock);
            }
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
        let port_bytes = [
            buf[offset + 4],
            buf[offset + 5],
            buf[offset + 6],
            buf[offset + 7],
        ];
        let addr = Ipv4Addr::new(
            buf[offset + 20],
            buf[offset + 21],
            buf[offset + 22],
            buf[offset + 23],
        );
        if let Some(port_u16) = decode_locator_port(port_bytes) {
            if let Ok(sock) =
                crate::core::string_utils::format_string(format_args!("{}:{}", addr, port_u16))
                    .parse()
            {
                spdp_data.default_unicast_locators.push(sock); // v79: separate list
                log::debug!("[spdp] Default unicast locator: {}", sock);
            }
        }
    }
    Ok(())
}

/// Parse PID_DEFAULT_MULTICAST_LOCATOR (0x0048)
///
/// v79: Parse default multicast locators (RTPS v2.3 Sec.8.5.3.1)
/// Default multicast locators are used for:
/// - User data multicast delivery
pub(super) fn parse_default_multicast_locator_pid(
    buf: &[u8],
    offset: usize,
    length: usize,
    spdp_data: &mut SpdpData,
) -> Result<(), ParseError> {
    if length >= 24 {
        let port_bytes = [
            buf[offset + 4],
            buf[offset + 5],
            buf[offset + 6],
            buf[offset + 7],
        ];
        let addr = Ipv4Addr::new(
            buf[offset + 20],
            buf[offset + 21],
            buf[offset + 22],
            buf[offset + 23],
        );
        if let Some(port_u16) = decode_locator_port(port_bytes) {
            if let Ok(sock) = format_string(format_args!("{}:{}", addr, port_u16)).parse() {
                spdp_data.default_multicast_locators.push(sock);
                log::debug!("[spdp] Default multicast locator: {}", sock);
            }
        }
    }
    Ok(())
}
