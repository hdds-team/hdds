// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! RTI dialect SPDP Builder
//!
//! Builds SPDP participant announcements for peers with vendor id 0x0101.
//!
//! Not on the live discovery path: the SPDP HDDS multicasts and unicasts is
//! `protocol::discovery::build_spdp`, for every vendor. This builder is
//! reached only through `DialectEncoder::build_spdp{,_in_domain}` for
//! `Dialect::Rti`.
//!
//! # What this builder writes:
//! - PROTOCOL_VERSION, VENDOR_ID, PARTICIPANT_GUID, BUILTIN_ENDPOINT_SET
//! - Unicast locators before the remaining PIDs
//! - PARTICIPANT_LEASE_DURATION, DOMAIN_ID
//! - Vendor-range PIDs as a Connext peer sends them: PRODUCT_VERSION,
//!   RTI_DOMAIN_ID, TRANSPORT_INFO_LIST, REACHABILITY_LEASE_DURATION,
//!   VENDOR_BUILTIN_ENDPOINT_SET
//!
//! # Open spec question (to be decided after an interop matrix run)
//!
//! A vendor-range PID (0x8000-0xffff) is interpreted per the sender's vendor
//! id (DDSI-RTPS 2.5 Sec.9.6.2.2.1, Table 9.6). Written under HDDS's vendor
//! id 0x011A, the five vendor-range PIDs below are HDDS PIDs to a conforming
//! receiver, not the vendor 0x0101 PIDs whose layout they copy. They are
//! kept, as wire observations of what a Connext peer sends, until an interop
//! matrix run measures what removing them changes.

use std::net::SocketAddr;

use crate::protocol::dialect::error::{EncodeError, EncodeResult};
use crate::protocol::dialect::Guid;

/// PID constants for SPDP encoding
mod pids {
    pub const PID_PARTICIPANT_GUID: u16 = 0x0050;
    pub const PID_BUILTIN_ENDPOINT_SET: u16 = 0x0058;
    pub const PID_PROTOCOL_VERSION: u16 = 0x0015;
    pub const PID_VENDOR_ID: u16 = 0x0016;
    pub const PID_DEFAULT_UNICAST_LOCATOR: u16 = 0x0031;
    pub const PID_METATRAFFIC_UNICAST_LOCATOR: u16 = 0x0032;
    #[allow(dead_code)] // Part of RTPS spec, used for multicast locator announcements
    pub const PID_METATRAFFIC_MULTICAST_LOCATOR: u16 = 0x0033;
    #[allow(dead_code)] // Part of RTPS spec, used for default multicast locators
    pub const PID_DEFAULT_MULTICAST_LOCATOR: u16 = 0x0048;
    pub const PID_PARTICIPANT_LEASE_DURATION: u16 = 0x0002;
    pub const PID_DOMAIN_ID: u16 = 0x000f;
    pub const PID_PRODUCT_VERSION: u16 = 0x8000;
    pub const PID_RTI_DOMAIN_ID: u16 = 0x800f;
    pub const PID_TRANSPORT_INFO_LIST: u16 = 0x8010;
    pub const PID_REACHABILITY_LEASE_DURATION: u16 = 0x8016;
    pub const PID_VENDOR_BUILTIN_ENDPOINT_SET: u16 = 0x8017;
    pub const PID_SENTINEL: u16 = 0x0001;
}

/// HDDS vendor ID (official DDS Foundation assignment, 2026-07)
const VENDOR_ID_HDDS: u16 = 0x011A;

/// Builtin endpoint set flags for the RTI dialect.
///
/// Value 0x000F0C3F, the value of `BUILTIN_ENDPOINT_SET_DEFAULT` in
/// protocol::discovery::constants:
/// - Bits 0-5   (0x003F):  SPDP + SEDP announcer/detector endpoints
/// - Bits 10-11 (0x0C00):  Participant Message Writer/Reader (liveliness)
/// - Bits 16-19 (0xF0000): the SECURE SEDP publications/subscriptions
///   writers and readers (DDS Security v1.1 Sec.7.4.1.4, Table 11), which a
///   participant without security does not serve.
///
/// A Connext peer announces 0x00000C3F (observed on the wire from 6.1, 7.3
/// and the public 7.7 shape_main). Bits 16-19 are kept until an interop matrix
/// run measures what dropping them changes.
const BUILTIN_ENDPOINT_SET_RTI: u32 = 0x000F_0C3F;
/// Build SPDP participant announcement for a peer with vendor id 0x0101.
///
/// `domain_id` is the participant's domain. `None` (the domain-less
/// `DialectEncoder::build_spdp`) omits PID_DOMAIN_ID and PID_RTI_DOMAIN_ID
/// rather than announcing a domain that may be wrong: absent, PID_DOMAIN_ID
/// defaults to the receiver's own domain (DDSI-RTPS 2.5 Table 9.19).
// @audit-ok: Sequential builder (cyclo 17, cogni 2) - linear write_xxx calls without complex branching
pub fn build_spdp(
    participant_guid: &Guid,
    unicast_locators: &[SocketAddr],
    multicast_locators: &[SocketAddr],
    lease_duration_sec: u32,
    domain_id: Option<u32>,
) -> EncodeResult<Vec<u8>> {
    // Pre-allocate buffer (1KB for this dialect's SPDP)
    let mut buf = vec![0u8; 1024];
    let mut offset = 0;

    // CDR encapsulation header
    if buf.len() < 4 {
        return Err(EncodeError::BufferTooSmall);
    }
    buf[0..4].copy_from_slice(&[0x00, 0x03, 0x00, 0x00]); // PL_CDR_LE
    offset += 4;

    // PID order: the head (PROTOCOL_VERSION, VENDOR_ID, PARTICIPANT_GUID,
    // BUILTIN_ENDPOINT_SET, locators) is the generic HDDS order; the tail
    // (LEASE_DURATION, DOMAIN_ID, then 0x800f, 0x8010, 0x8016, 0x8017) is
    // the order observed on the wire in the SPDP of a Connext 6.1 peer.
    // Connext 7.3 and the public 7.7 shape_main order theirs differently,
    // and ParameterList order is not significant (DDSI-RTPS 2.5
    // Sec.9.4.2.11).

    // Position 1: PID_PROTOCOL_VERSION
    write_protocol_version(&mut buf, &mut offset)?;

    // Position 2: PID_VENDOR_ID
    write_vendor_id(&mut buf, &mut offset)?;

    // Position 3: PID_PARTICIPANT_GUID
    write_participant_guid(participant_guid, &mut buf, &mut offset)?;

    // Position 4: PID_BUILTIN_ENDPOINT_SET
    write_builtin_endpoint_set(&mut buf, &mut offset)?;

    // PID_BUILTIN_ENDPOINT_QOS (0x0077) is optional (DDSI-RTPS 2.5
    // Table 9.13) and omitted.

    // Locators before the remaining PIDs. Only unicast ones: multicast
    // locators are optional (DDSI-RTPS 2.5 Sec.8.5.3.1) and not announced.
    for locator in unicast_locators {
        write_locator(
            pids::PID_DEFAULT_UNICAST_LOCATOR,
            locator,
            &mut buf,
            &mut offset,
        )?;
        write_locator(
            pids::PID_METATRAFFIC_UNICAST_LOCATOR,
            locator,
            &mut buf,
            &mut offset,
        )?;
    }

    let _ = multicast_locators; // not announced, see above

    // PID_PARTICIPANT_LEASE_DURATION
    write_lease_duration(lease_duration_sec, &mut buf, &mut offset)?;

    // PID_DOMAIN_ID: the participant's domain, or absent when unknown
    if let Some(domain_id) = domain_id {
        write_domain_id(pids::PID_DOMAIN_ID, domain_id, &mut buf, &mut offset)?;
    }

    // Vendor-range PIDs (0x8000+), as a Connext peer sends them (see the
    // module doc for the open spec question).
    write_product_version(&mut buf, &mut offset)?;
    if let Some(domain_id) = domain_id {
        write_domain_id(pids::PID_RTI_DOMAIN_ID, domain_id, &mut buf, &mut offset)?;
    }
    write_transport_info_list(&mut buf, &mut offset)?;
    write_reachability_lease_duration(&mut buf, &mut offset)?;
    write_vendor_builtin_endpoint_set(&mut buf, &mut offset)?;

    // PID_SENTINEL
    write_sentinel(&mut buf, &mut offset)?;

    buf.truncate(offset);
    Ok(buf)
}

fn write_participant_guid(guid: &Guid, buf: &mut [u8], offset: &mut usize) -> EncodeResult<()> {
    if *offset + 20 > buf.len() {
        return Err(EncodeError::BufferTooSmall);
    }

    buf[*offset..*offset + 2].copy_from_slice(&pids::PID_PARTICIPANT_GUID.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&16u16.to_le_bytes());
    *offset += 4;

    buf[*offset..*offset + 12].copy_from_slice(&guid.prefix);
    buf[*offset + 12..*offset + 16].copy_from_slice(&guid.entity_id);
    *offset += 16;

    Ok(())
}

fn write_builtin_endpoint_set(buf: &mut [u8], offset: &mut usize) -> EncodeResult<()> {
    if *offset + 8 > buf.len() {
        return Err(EncodeError::BufferTooSmall);
    }

    buf[*offset..*offset + 2].copy_from_slice(&pids::PID_BUILTIN_ENDPOINT_SET.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&4u16.to_le_bytes());
    *offset += 4;
    // TypeLookup Service endpoints (BuiltinEndpointSet bits 12-15, mask 0xF000)
    // per DDS-XTypes v1.3 Table 7.6.3.3.4.1. Advertised ONLY when the OMG
    // TypeLookup serve path is compiled in, so cross-vendor writers know
    // they may fetch HDDS's dependency TypeObjects via getTypes. Default
    // OFF => the shipped cross-vendor SPDP wire is unchanged; when ON, the
    // set reads 0x000FFC3F (bits 12-15 = 0xF000 added).
    #[cfg(feature = "xtypes-structural-assignability")]
    let endpoint_set = BUILTIN_ENDPOINT_SET_RTI | 0x0000_F000;
    #[cfg(not(feature = "xtypes-structural-assignability"))]
    let endpoint_set = BUILTIN_ENDPOINT_SET_RTI;
    buf[*offset..*offset + 4].copy_from_slice(&endpoint_set.to_le_bytes());
    *offset += 4;

    Ok(())
}

fn write_protocol_version(buf: &mut [u8], offset: &mut usize) -> EncodeResult<()> {
    if *offset + 8 > buf.len() {
        return Err(EncodeError::BufferTooSmall);
    }

    buf[*offset..*offset + 2].copy_from_slice(&pids::PID_PROTOCOL_VERSION.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&4u16.to_le_bytes());
    *offset += 4;
    // The version the RTPS header of every HDDS message announces
    // (`RtiEncoder::rtps_version`); nothing documents another one here.
    buf[*offset] = 2; // major
    buf[*offset + 1] = 4; // minor
    buf[*offset + 2] = 0;
    buf[*offset + 3] = 0;
    *offset += 4;

    Ok(())
}

fn write_vendor_id(buf: &mut [u8], offset: &mut usize) -> EncodeResult<()> {
    if *offset + 8 > buf.len() {
        return Err(EncodeError::BufferTooSmall);
    }

    buf[*offset..*offset + 2].copy_from_slice(&pids::PID_VENDOR_ID.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&4u16.to_le_bytes());
    *offset += 4;
    buf[*offset..*offset + 2].copy_from_slice(&VENDOR_ID_HDDS.to_le_bytes());
    buf[*offset + 2] = 0;
    buf[*offset + 3] = 0;
    *offset += 4;

    Ok(())
}

fn write_locator(
    pid: u16,
    addr: &SocketAddr,
    buf: &mut [u8],
    offset: &mut usize,
) -> EncodeResult<()> {
    crate::protocol::rtps::encode_locator_parameter(pid, addr, buf, offset)
        .map_err(|_| EncodeError::BufferTooSmall)
}

fn write_lease_duration(seconds: u32, buf: &mut [u8], offset: &mut usize) -> EncodeResult<()> {
    if *offset + 12 > buf.len() {
        return Err(EncodeError::BufferTooSmall);
    }

    buf[*offset..*offset + 2].copy_from_slice(&pids::PID_PARTICIPANT_LEASE_DURATION.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&8u16.to_le_bytes());
    *offset += 4;
    buf[*offset..*offset + 4].copy_from_slice(&seconds.to_le_bytes());
    buf[*offset + 4..*offset + 8].copy_from_slice(&0u32.to_le_bytes());
    *offset += 8;

    Ok(())
}

/// PID_DOMAIN_ID (DDSI-RTPS 2.5 Table 9.19) or PID_RTI_DOMAIN_ID (0x800f,
/// a `long domain_id` in the public Wireshark RTPS dissector), both a u32.
fn write_domain_id(
    pid: u16,
    domain_id: u32,
    buf: &mut [u8],
    offset: &mut usize,
) -> EncodeResult<()> {
    if *offset + 8 > buf.len() {
        return Err(EncodeError::BufferTooSmall);
    }

    buf[*offset..*offset + 2].copy_from_slice(&pid.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&4u16.to_le_bytes());
    *offset += 4;
    buf[*offset..*offset + 4].copy_from_slice(&domain_id.to_le_bytes());
    *offset += 4;

    Ok(())
}

/// PID_PRODUCT_VERSION (0x8000): {major, minor, release, revision} octets,
/// as the public Wireshark RTPS dissector decodes it; the public 7.7
/// shape_main sends its own version there.
fn write_product_version(buf: &mut [u8], offset: &mut usize) -> EncodeResult<()> {
    if *offset + 8 > buf.len() {
        return Err(EncodeError::BufferTooSmall);
    }

    buf[*offset..*offset + 2].copy_from_slice(&pids::PID_PRODUCT_VERSION.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&4u16.to_le_bytes());
    *offset += 4;
    buf[*offset] = 0x00; // major
    buf[*offset + 1] = 0x02; // minor (HDDS v0.2.x)
    buf[*offset + 2] = 0x00;
    buf[*offset + 3] = 0x00;
    *offset += 4;

    Ok(())
}

/// PID_TRANSPORT_INFO_LIST (0x8010): a sequence of {classId, messageSizeMax}
/// (public Wireshark RTPS dissector; classId 1 = UDPv4). A Connext 6.1 peer
/// was observed sending UDPv4 with 65507 (the IPv4 UDP payload maximum,
/// 65535 - 20 - 8), the public 7.7 shape_main sends UDPv4 with 65504.
fn write_transport_info_list(buf: &mut [u8], offset: &mut usize) -> EncodeResult<()> {
    // Fixed-size value, held in the width of parameterLength.
    const SIZE: u16 = 12; // seq_length(4) + classId(4) + messageSizeMax(4)

    if *offset + 4 + usize::from(SIZE) > buf.len() {
        return Err(EncodeError::BufferTooSmall);
    }

    buf[*offset..*offset + 2].copy_from_slice(&pids::PID_TRANSPORT_INFO_LIST.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&SIZE.to_le_bytes());
    *offset += 4;

    buf[*offset..*offset + 4].copy_from_slice(&1u32.to_le_bytes()); // sequence length = 1
    *offset += 4;
    buf[*offset..*offset + 4].copy_from_slice(&1u32.to_le_bytes()); // classId = UDPv4
    *offset += 4;
    buf[*offset..*offset + 4].copy_from_slice(&65507u32.to_le_bytes()); // messageSizeMax
    *offset += 4;

    Ok(())
}

/// PID_REACHABILITY_LEASE_DURATION (0x8016): a Duration_t; the public 7.7
/// shape_main sends INFINITE.
fn write_reachability_lease_duration(buf: &mut [u8], offset: &mut usize) -> EncodeResult<()> {
    if *offset + 12 > buf.len() {
        return Err(EncodeError::BufferTooSmall);
    }

    buf[*offset..*offset + 2].copy_from_slice(&pids::PID_REACHABILITY_LEASE_DURATION.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&8u16.to_le_bytes());
    *offset += 4;
    // INFINITE duration
    buf[*offset..*offset + 4].copy_from_slice(&0x7FFF_FFFFu32.to_le_bytes());
    buf[*offset + 4..*offset + 8].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    *offset += 8;

    Ok(())
}

/// PID_VENDOR_BUILTIN_ENDPOINT_SET (0x8017) = 0x3. Bits 0 and 1 name a
/// service-request writer and reader (public Wireshark RTPS dissector),
/// which HDDS does not implement. Connext 6.1, 7.3 and the public 7.6
/// shape_main were observed announcing 0x3, the public 7.7 shape_main 0x0.
/// Kept until an interop matrix run measures what removing it changes.
fn write_vendor_builtin_endpoint_set(buf: &mut [u8], offset: &mut usize) -> EncodeResult<()> {
    if *offset + 8 > buf.len() {
        return Err(EncodeError::BufferTooSmall);
    }

    buf[*offset..*offset + 2].copy_from_slice(&pids::PID_VENDOR_BUILTIN_ENDPOINT_SET.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&4u16.to_le_bytes());
    *offset += 4;
    buf[*offset..*offset + 4].copy_from_slice(&0x0000_0003u32.to_le_bytes()); // bits 0+1
    *offset += 4;

    Ok(())
}

fn write_sentinel(buf: &mut [u8], offset: &mut usize) -> EncodeResult<()> {
    if *offset + 4 > buf.len() {
        return Err(EncodeError::BufferTooSmall);
    }

    buf[*offset..*offset + 2].copy_from_slice(&pids::PID_SENTINEL.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&0u16.to_le_bytes());
    *offset += 4;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    fn test_guid() -> Guid {
        Guid {
            prefix: [
                0x01, 0x01, 0x00, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            ],
            entity_id: [0x00, 0x00, 0x01, 0xC1],
        }
    }

    #[test]
    fn test_build_spdp_rti() {
        let guid = test_guid();
        let addr = SocketAddr::from(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 100), 7411));
        let unicast = vec![addr];

        let result = build_spdp(&guid, &unicast, &[], 100, Some(0));
        assert!(result.is_ok());

        let buf = result.expect("build_spdp should succeed");
        assert_eq!(&buf[0..4], &[0x00, 0x03, 0x00, 0x00]);
    }

    #[test]
    fn test_rti_has_builtin_endpoint_set_early() {
        let guid = test_guid();
        let result = build_spdp(&guid, &[], &[], 100, Some(0)).expect("build_spdp should succeed");

        // Find PID_BUILTIN_ENDPOINT_SET (0x0058)
        let pid_bytes = 0x0058u16.to_le_bytes();
        let pos = result.windows(2).position(|w| w == pid_bytes);
        assert!(pos.is_some(), "PID_BUILTIN_ENDPOINT_SET must be present");
        // Should be early in packet (after GUID at offset 4+20=24)
        assert!(
            pos.expect("pos must be set") < 50,
            "BUILTIN_ENDPOINT_SET should be early"
        );
    }

    /// Every parameter of the emitted ParameterList, decoded from the bytes:
    /// (pid, value), in wire order, up to PID_SENTINEL.
    fn parameters(buf: &[u8]) -> Vec<(u16, Vec<u8>)> {
        assert_eq!(&buf[0..4], &[0x00, 0x03, 0x00, 0x00], "PL_CDR_LE");
        let mut out = Vec::new();
        let mut offset = 4;
        loop {
            let pid = u16::from_le_bytes([buf[offset], buf[offset + 1]]);
            let len = usize::from(u16::from_le_bytes([buf[offset + 2], buf[offset + 3]]));
            offset += 4;
            if pid == pids::PID_SENTINEL {
                assert_eq!(offset, buf.len(), "nothing after PID_SENTINEL");
                return out;
            }
            out.push((pid, buf[offset..offset + len].to_vec()));
            offset += len;
        }
    }

    fn u32_of(params: &[(u16, Vec<u8>)], pid: u16) -> Option<u32> {
        params
            .iter()
            .find(|(p, _)| *p == pid)
            .map(|(_, v)| u32::from_le_bytes(v[..4].try_into().expect("four octets")))
    }

    /// Both domain-id parameters carry the participant's domain, never a
    /// hardcoded 0.
    #[test]
    fn the_domain_id_parameters_carry_the_participants_domain() {
        for domain in [0u32, 1, 42, 232] {
            let buf = build_spdp(&test_guid(), &[], &[], 100, Some(domain)).expect("build");
            let params = parameters(&buf);
            assert_eq!(u32_of(&params, pids::PID_DOMAIN_ID), Some(domain));
            assert_eq!(u32_of(&params, pids::PID_RTI_DOMAIN_ID), Some(domain));
        }
    }

    /// Without a known domain neither parameter is written: an absent
    /// PID_DOMAIN_ID means the receiver's own domain (DDSI-RTPS 2.5
    /// Table 9.19), a written one could be wrong.
    #[test]
    fn an_unknown_domain_is_omitted_not_announced_as_zero() {
        let buf = build_spdp(&test_guid(), &[], &[], 100, None).expect("build");
        let params = parameters(&buf);
        assert_eq!(u32_of(&params, pids::PID_DOMAIN_ID), None);
        assert_eq!(u32_of(&params, pids::PID_RTI_DOMAIN_ID), None);
        // The trait entry point without a domain takes this path, the one
        // with a domain writes it.
        use crate::protocol::dialect::DialectEncoder;
        let encoder = crate::protocol::dialect::rti::RtiEncoder;
        let via_trait = encoder
            .build_spdp(&test_guid(), &[], &[], 100)
            .expect("build");
        assert_eq!(u32_of(&parameters(&via_trait), pids::PID_DOMAIN_ID), None);
        let in_domain = encoder
            .build_spdp_in_domain(&test_guid(), &[], &[], 100, 7)
            .expect("build");
        assert_eq!(
            u32_of(&parameters(&in_domain), pids::PID_DOMAIN_ID),
            Some(7)
        );
        assert_eq!(
            u32_of(&parameters(&in_domain), pids::PID_RTI_DOMAIN_ID),
            Some(7)
        );
    }

    /// PID_PROTOCOL_VERSION announces the version of the RTPS header HDDS
    /// sends, 2.4, not a version no message carries.
    #[test]
    fn the_protocol_version_parameter_matches_the_header() {
        use crate::protocol::dialect::DialectEncoder;
        let (major, minor) = crate::protocol::dialect::rti::RtiEncoder.rtps_version();
        let buf = build_spdp(&test_guid(), &[], &[], 100, Some(0)).expect("build");
        let params = parameters(&buf);
        let (_, version) = params
            .iter()
            .find(|(p, _)| *p == pids::PID_PROTOCOL_VERSION)
            .expect("PID_PROTOCOL_VERSION");
        assert_eq!((version[0], version[1]), (major, minor));
        assert_eq!((major, minor), (2, 4));
    }
}
