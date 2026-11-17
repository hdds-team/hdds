// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! HDDS Native Dialect Encoder
//!
//! This module provides the **reference RTPS 2.3 implementation** for HDDS.
//! It follows the strict RTPS specification without vendor-specific extensions.
//!
//! **Vendor ID**: 0x011A (official DDS Foundation assignment)
//! **RTPS Version**: 2.3
//! **CDR Encoding**: XCDR2 (OMG DDS-XTypes 1.3)
//!
//! # Design Principles
//!
//! 1. **Strict RTPS 2.3 compliance**: No vendor extensions in wire format
//! 2. **Conservative defaults**: Favor interoperability over features
//! 3. **Minimal PIDs**: Only mandatory PIDs for discovery
//! 4. **Clean separation**: All vendor-specific workarounds go in respective dialect modules
//!
//! # Wire Format Reference
//!
//! - RTPS 2.3 Specification (OMG formal/19-04-03)
//! - DDS-XTypes 1.3 (OMG formal/20-02-04)
//! - DDS Security 1.1 (OMG formal/18-04-01)
//!
//! # ARCHITECTURAL CONSTRAINT
//!
//! This dialect module is ISOLATED. Never import from other dialect modules.
//! Shared RTPS code lives in `crate::protocol::rtps`.
//!
//! FORBIDDEN: use super::fastdds / use super::cyclone / use super::rti
//! ALLOWED:   use crate::protocol::rtps

use std::net::SocketAddr;

use super::common::sequence_number_set_num_bits;
use super::error::{EncodeError, EncodeResult};
use super::{DialectEncoder, Guid, QosProfile, SedpEndpointData};
use crate::protocol::rtps;

/// HDDS Vendor ID (official DDS Foundation assignment: 0x011A)
pub const HDDS_VENDOR_ID: [u8; 2] = [0x01, 0x1A];

/// HDDS Native RTPS 2.3 Encoder
///
/// Reference implementation following strict RTPS 2.3 specification.
pub struct HddsEncoder;

impl DialectEncoder for HddsEncoder {
    // ===== Discovery Protocol =====

    fn build_spdp(
        &self,
        participant_guid: &Guid,
        unicast_locators: &[SocketAddr],
        multicast_locators: &[SocketAddr],
        lease_duration_sec: u32,
    ) -> EncodeResult<Vec<u8>> {
        // The standard SPDP; no domain is known here, PID_DOMAIN_ID says 0.
        super::common::build_standard_spdp(
            participant_guid,
            unicast_locators,
            multicast_locators,
            lease_duration_sec,
            0,
        )
    }

    fn build_spdp_in_domain(
        &self,
        participant_guid: &Guid,
        unicast_locators: &[SocketAddr],
        multicast_locators: &[SocketAddr],
        lease_duration_sec: u32,
        domain_id: u32,
    ) -> EncodeResult<Vec<u8>> {
        super::common::build_standard_spdp(
            participant_guid,
            unicast_locators,
            multicast_locators,
            lease_duration_sec,
            domain_id,
        )
    }

    fn build_sedp(&self, data: &SedpEndpointData) -> EncodeResult<Vec<u8>> {
        // Use the certified SEDP builder directly
        use crate::core::discovery::GUID;
        use crate::protocol::discovery::types::SedpData as LegacySedpData;

        let mut endpoint_guid_bytes = [0u8; 16];
        endpoint_guid_bytes[..12].copy_from_slice(&data.endpoint_guid.prefix);
        endpoint_guid_bytes[12..16].copy_from_slice(&data.endpoint_guid.entity_id);

        let mut participant_guid_bytes = [0u8; 16];
        participant_guid_bytes[..12].copy_from_slice(&data.participant_guid.prefix);
        participant_guid_bytes[12..16].copy_from_slice(&data.participant_guid.entity_id);

        let qos = data.qos.map(QosProfile::to_qos);

        // A decode failure here must not be silent: `.ok()` on the Result
        // with no log would drop PID_TYPE_OBJECT from the endpoint's SEDP with
        // no symptom anywhere but a downstream consumer's machine.
        // `decoded_type_object` logs it at `error!` and continues.
        #[cfg(feature = "xtypes")]
        let type_object = data.decoded_type_object("hdds");
        #[cfg(not(feature = "xtypes"))]
        let type_object = None;

        // Thread the pre-computed TypeInformation (with deps) from
        // SedpEndpointData so build_sedp emits real dep hashes instead of
        // the zero-dep sentinel. Feature OFF: always None (sentinel path).
        #[cfg(feature = "xtypes-structural-assignability")]
        let type_information_for_legacy = data.type_information.clone();
        #[cfg(not(feature = "xtypes-structural-assignability"))]
        let type_information_for_legacy: Option<
            crate::protocol::discovery::types::TypeInformation,
        > = None;

        let legacy_data = LegacySedpData {
            topic_name: data.topic_name.to_string(),
            type_name: data.type_name.to_string(),
            endpoint_guid: GUID::from_bytes(endpoint_guid_bytes),
            participant_guid: GUID::from_bytes(participant_guid_bytes),
            qos_hash: 0,
            qos,
            type_object,
            dependents: Vec::new(),
            type_object_legacy_v1: false,
            unicast_locators: data.unicast_locators.to_vec(),
            // Application UserDataQosPolicy (PID_USER_DATA, 0x002c). Every
            // dialect that routes through build_sedp_with_options propagates
            // this the same way; see SedpEndpointData::user_data.
            user_data: data.user_data.map(str::to_string),
            // HDDS is the only dialect that threads this through to the wire,
            // as the HDDS vendor-specific PID_HDDS_SHM_CAPABILITY (0x8031),
            // never PID_USER_DATA. Every other dialect encoder hardcodes None
            // here so a proprietary SHM hint never leaks onto a
            // foreign-dialect frame; see SedpEndpointData::hdds_shm_capability.
            shm_capability: data.hdds_shm_capability.map(str::to_string),
            has_explicit_reliability: false,
            has_explicit_ownership: false,
            has_ownership_strength: false,
            type_information: type_information_for_legacy,
            type_consistency: data.type_consistency.clone(),
            group_entity_id: data.group_entity_id,
            // Emission never reads this field (see
            // `SedpEndpointData`/`insert_endpoint_security_info`); it
            // exists on `SedpData` for the receive side only.
            endpoint_security_info: None,
        };

        let mut buf = vec![0u8; 8192];
        let len = crate::protocol::discovery::sedp::build::build_sedp_with_options(
            &legacy_data,
            &mut buf,
            data.emit_type_object_pid,
        )
        .map_err(|_| EncodeError::BufferTooSmall)?;
        buf.truncate(len);
        Ok(buf)
    }

    // ===== Reliable Protocol Control =====

    fn build_heartbeat(
        &self,
        reader_id: &[u8; 4],
        writer_id: &[u8; 4],
        first_sn: u64,
        last_sn: u64,
        count: u32,
    ) -> EncodeResult<Vec<u8>> {
        rtps::encode_heartbeat(reader_id, writer_id, first_sn, last_sn, count)
            .map_err(|_| EncodeError::BufferTooSmall)
    }

    fn build_acknack(
        &self,
        reader_id: &[u8; 4],
        writer_id: &[u8; 4],
        base_sn: u64,
        bitmap: &[u32],
        count: u32,
    ) -> EncodeResult<Vec<u8>> {
        let num_bits = sequence_number_set_num_bits(bitmap)?;
        rtps::encode_acknack_with_count(reader_id, writer_id, base_sn, num_bits, bitmap, count)
            .map_err(|_| EncodeError::BufferTooSmall)
    }

    fn build_gap(
        &self,
        reader_id: &[u8; 4],
        writer_id: &[u8; 4],
        gap_start: u64,
        gap_list_base: u64,
        gap_bitmap: &[u32],
    ) -> EncodeResult<Vec<u8>> {
        let num_bits = sequence_number_set_num_bits(gap_bitmap)?;
        rtps::encode_gap(
            reader_id,
            writer_id,
            gap_start,
            gap_list_base,
            num_bits,
            gap_bitmap,
        )
        .map_err(|_| EncodeError::BufferTooSmall)
    }

    // ===== User Data =====

    fn build_data(
        &self,
        reader_id: &[u8; 4],
        writer_id: &[u8; 4],
        sequence_number: u64,
        payload: &[u8],
        _inline_qos: Option<&QosProfile>,
    ) -> EncodeResult<Vec<u8>> {
        rtps::encode_data(reader_id, writer_id, sequence_number, payload)
            .map_err(|_| EncodeError::BufferTooSmall)
    }

    fn build_data_frag(
        &self,
        reader_id: &[u8; 4],
        writer_id: &[u8; 4],
        sequence_number: u64,
        fragment_starting_num: u32,
        fragments_in_submessage: u16,
        data_size: u32,
        fragment_size: u16,
        payload: &[u8],
    ) -> EncodeResult<Vec<u8>> {
        rtps::encode_data_frag(
            reader_id,
            writer_id,
            sequence_number,
            fragment_starting_num,
            fragments_in_submessage,
            data_size,
            fragment_size,
            payload,
        )
        .map_err(|_| EncodeError::BufferTooSmall)
    }

    // ===== Info Submessages =====

    fn build_info_ts(&self, timestamp_sec: u32, timestamp_frac: u32) -> Vec<u8> {
        rtps::encode_info_ts(timestamp_sec, timestamp_frac)
    }

    fn build_info_dst(&self, guid_prefix: &[u8; 12]) -> Vec<u8> {
        rtps::encode_info_dst(guid_prefix)
    }

    // ===== Locators =====

    fn encode_unicast_locator(
        &self,
        addr: &SocketAddr,
        buf: &mut [u8],
        offset: &mut usize,
    ) -> EncodeResult<()> {
        rtps::encode_unicast_locator(addr, buf, offset).map_err(|_| EncodeError::BufferTooSmall)
    }

    fn encode_multicast_locator(
        &self,
        addr: &SocketAddr,
        buf: &mut [u8],
        offset: &mut usize,
    ) -> EncodeResult<()> {
        rtps::encode_multicast_locator(addr, buf, offset).map_err(|_| EncodeError::BufferTooSmall)
    }

    // ===== Metadata =====

    fn name(&self) -> &'static str {
        "HDDS"
    }

    fn rtps_version(&self) -> (u8, u8) {
        (2, 3) // RTPS 2.3
    }

    fn vendor_id(&self) -> [u8; 2] {
        HDDS_VENDOR_ID
    }

    fn requires_type_object(&self) -> bool {
        false // Conservative default - don't require TypeObject
    }

    fn supports_xcdr2(&self) -> bool {
        true // HDDS supports XCDR2 (DDS-XTypes 1.3)
    }

    fn fragment_size(&self) -> usize {
        1300 // Conservative MTU - safe for most networks
    }

    // ===== HDDS Native Mode: Fast Discovery =====

    /// HDDS native mode: skip SPDP barrier for fast discovery
    ///
    /// In HDDS<->HDDS communication, we don't need to wait for multiple SPDP rounds
    /// before sending SEDP. Both participants understand the protocol and can
    /// handle immediate SEDP announcements.
    fn skip_spdp_barrier(&self) -> bool {
        true // HDDS native: fast discovery
    }

    /// HDDS native mode: send immediate SPDP unicast response
    ///
    /// When we see another HDDS participant, respond immediately with unicast SPDP
    /// to accelerate discovery handshake.
    fn requires_immediate_spdp_response(&self) -> bool {
        true // HDDS native: immediate response
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hdds_encoder_metadata() {
        let encoder = HddsEncoder;
        assert_eq!(encoder.name(), "HDDS");
        assert_eq!(encoder.rtps_version(), (2, 3));
        assert_eq!(encoder.vendor_id(), [0x01, 0x1A]);
        assert!(!encoder.requires_type_object());
        assert!(encoder.supports_xcdr2());
        assert_eq!(encoder.fragment_size(), 1300);
    }

    #[test]
    fn test_build_info_dst() {
        let encoder = HddsEncoder;
        let guid_prefix = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let result = encoder.build_info_dst(&guid_prefix);

        // INFO_DST is 16 bytes: header (4) + guid_prefix (12)
        assert_eq!(result.len(), 16);
        assert_eq!(result[0], 0x0E); // INFO_DST submessage ID
        assert_eq!(result[1], 0x01); // Flags: little-endian
    }

    #[test]
    fn test_build_info_ts() {
        let encoder = HddsEncoder;
        let result = encoder.build_info_ts(1000, 500_000_000);

        // INFO_TS is 12 bytes: header (4) + timestamp (8)
        assert_eq!(result.len(), 12);
        assert_eq!(result[0], 0x09); // INFO_TS submessage ID
        assert_eq!(result[1], 0x01); // Flags: little-endian
    }

    #[test]
    fn test_build_heartbeat() {
        let encoder = HddsEncoder;
        let reader_id = [0x00, 0x00, 0x00, 0x04];
        let writer_id = [0x00, 0x00, 0x00, 0x02];

        let result = encoder
            .build_heartbeat(&reader_id, &writer_id, 1, 10, 5)
            .expect("heartbeat should build");

        // HEARTBEAT: header (4) + entityIds (8) + seqNums (16) + count (4) = 32
        assert_eq!(result.len(), 32);
        assert_eq!(result[0], 0x07); // HEARTBEAT submessage ID
    }

    #[test]
    fn test_build_acknack() {
        let encoder = HddsEncoder;
        let reader_id = [0x00, 0x00, 0x00, 0x04];
        let writer_id = [0x00, 0x00, 0x00, 0x02];
        let bitmap = [0x0F_u32]; // First 4 bits set

        let result = encoder
            .build_acknack(&reader_id, &writer_id, 1, &bitmap, 1)
            .expect("acknack should build");

        // Verify submessage ID
        assert_eq!(result[0], 0x06); // ACKNACK submessage ID
    }

    /// Minimal `SedpEndpointData` builder for the tests below. `user_data`
    /// (the application's UserDataQosPolicy, -> PID_USER_DATA 0x002c) and
    /// `hdds_shm_capability` (the HDDS SHM hint, -> PID_HDDS_SHM_CAPABILITY
    /// 0x8031) are the only fields the caller varies, and they are
    /// independent: this is the exact split the defect fix is about.
    fn sedp_endpoint_data<'a>(
        user_data: Option<&'a str>,
        hdds_shm_capability: Option<&'a str>,
        hdds_peer_destination: bool,
    ) -> SedpEndpointData<'a> {
        SedpEndpointData {
            endpoint_guid: Guid {
                prefix: [0x01; 12],
                entity_id: [0x00, 0x00, 0x01, 0x02],
            },
            participant_guid: Guid {
                prefix: [0x01; 12],
                entity_id: [0x00, 0x00, 0x01, 0xc1],
            },
            topic_name: "ShmTopic",
            type_name: "ShmType",
            unicast_locators: &[],
            multicast_locators: &[],
            qos: None,
            type_object: None,
            user_data,
            hdds_shm_capability,
            hdds_peer_destination,
            group_entity_id: None,
            type_consistency: None,
            #[cfg(feature = "xtypes-structural-assignability")]
            type_information: None,
            emit_type_object_pid: true,
        }
    }

    /// The application's `UserDataQosPolicy` must round-trip through
    /// PID_USER_DATA (0x002c) byte-identical, and must NEVER carry the SHM
    /// hint (the defect this test pins: PID_USER_DATA is a standard,
    /// application-owned QoS field, DDS-RTPS Sec.9.6.2.2.1, and must not be
    /// squatted for an internal capability hint, even when no SHM hint is
    /// configured at all).
    #[test]
    fn build_sedp_hdds_dialect_round_trips_application_user_data() {
        use crate::protocol::dialect::{build_sedp_for_dialect, Dialect};
        use crate::protocol::discovery::sedp::parse::parse_sedp;

        let data = sedp_endpoint_data(Some("app-metadata=v1"), None, false);

        let payload = build_sedp_for_dialect(Dialect::Hdds, &data)
            .expect("HDDS dialect build_sedp must succeed");

        let parsed = parse_sedp(&payload).expect("HDDS SEDP payload must parse");
        assert_eq!(
            parsed.user_data.as_deref(),
            Some("app-metadata=v1"),
            "PID_USER_DATA must carry the application's own UserDataQosPolicy byte-identical"
        );
        assert!(
            parsed.shm_capability.is_none(),
            "no SHM hint was configured, so PID_HDDS_SHM_CAPABILITY must be absent"
        );
    }

    /// The HDDS SHM capability hint must round-trip through the vendor PID
    /// 0x8031 byte-identical, and must NEVER land in PID_USER_DATA.
    #[test]
    fn build_sedp_hdds_dialect_round_trips_shm_capability() {
        use crate::protocol::dialect::{build_sedp_for_dialect, Dialect};
        use crate::protocol::discovery::sedp::parse::parse_sedp;

        let data = sedp_endpoint_data(None, Some("shm=1;host_id=deadbeef;v=1"), false);

        let payload = build_sedp_for_dialect(Dialect::Hdds, &data)
            .expect("HDDS dialect build_sedp must succeed");

        let parsed = parse_sedp(&payload).expect("HDDS SEDP payload must parse");
        assert_eq!(
            parsed.shm_capability.as_deref(),
            Some("shm=1;host_id=deadbeef;v=1"),
            "PID_HDDS_SHM_CAPABILITY (0x8031) must round-trip byte-identical through parse_sedp"
        );
        assert!(
            parsed.user_data.is_none(),
            "the SHM hint must never be written into PID_USER_DATA"
        );
    }

    /// Both fields set simultaneously: each must land in its own PID and
    /// come back distinct, with neither clobbering the other.
    #[test]
    fn build_sedp_hdds_dialect_keeps_user_data_and_shm_capability_distinct() {
        use crate::protocol::dialect::{build_sedp_for_dialect, Dialect};
        use crate::protocol::discovery::sedp::parse::parse_sedp;

        let data = sedp_endpoint_data(
            Some("app-metadata=v1"),
            Some("shm=1;host_id=deadbeef;v=1"),
            false,
        );

        let payload = build_sedp_for_dialect(Dialect::Hdds, &data)
            .expect("HDDS dialect build_sedp must succeed");

        let parsed = parse_sedp(&payload).expect("HDDS SEDP payload must parse");
        assert_eq!(parsed.user_data.as_deref(), Some("app-metadata=v1"));
        assert_eq!(
            parsed.shm_capability.as_deref(),
            Some("shm=1;host_id=deadbeef;v=1")
        );
    }

    /// Neither field set: HDDS dialect emits neither PID.
    #[test]
    fn build_sedp_hdds_dialect_omits_both_when_none() {
        use crate::protocol::dialect::{build_sedp_for_dialect, Dialect};
        use crate::protocol::discovery::sedp::parse::parse_sedp;

        let data = sedp_endpoint_data(None, None, false);

        let payload = build_sedp_for_dialect(Dialect::Hdds, &data)
            .expect("HDDS dialect build_sedp must succeed");

        let parsed = parse_sedp(&payload).expect("HDDS SEDP payload must parse");
        assert!(parsed.user_data.is_none());
        assert!(parsed.shm_capability.is_none());
    }

    /// Cross-vendor isolation: every foreign dialect encoder must emit
    /// byte-identical frames whether or not `SedpEndpointData::user_data` /
    /// `hdds_shm_capability` are set. FastDDS, CycloneDDS and Hybrid route
    /// through the shared `build_sedp_with_options`, whose `LegacySedpData`
    /// construction in each of those dialects hardcodes both fields to
    /// `None`; the RTI and OpenDDS dialects use their own independent builders
    /// that never read `SedpEndpointData::user_data` / `hdds_shm_capability`
    /// (the RTI dialect's `qos::write_user_data` hardcodes an empty PID_USER_DATA
    /// unconditionally). This is the proof that a proprietary HDDS hint
    /// (and, symmetrically, the application's own user_data threaded only on
    /// the HDDS path) never reaches a non-HDDS wire frame.
    #[test]
    fn build_sedp_foreign_dialects_are_byte_identical_regardless_of_user_data_and_shm_capability() {
        use crate::protocol::dialect::{build_sedp_for_dialect, Dialect};
        use crate::protocol::discovery::sedp::parse::parse_sedp;

        let baseline = sedp_endpoint_data(None, None, false);
        let with_both = sedp_endpoint_data(
            Some("app-metadata=v1"),
            Some("shm=1;host_id=deadbeef;v=1"),
            false,
        );

        for dialect in [
            Dialect::FastDds,
            Dialect::Rti,
            Dialect::CycloneDds,
            Dialect::OpenDds,
            Dialect::Hybrid,
        ] {
            let payload_baseline = build_sedp_for_dialect(dialect, &baseline).unwrap_or_else(|e| {
                panic!("{dialect:?} build_sedp must succeed (baseline): {e:?}")
            });
            let payload_with_both =
                build_sedp_for_dialect(dialect, &with_both).unwrap_or_else(|e| {
                    panic!("{dialect:?} build_sedp must succeed (with hints): {e:?}")
                });

            assert_eq!(
                payload_baseline, payload_with_both,
                "{dialect:?} dialect frame must be byte-identical regardless of \
                 SedpEndpointData::user_data / hdds_shm_capability"
            );

            let parsed = parse_sedp(&payload_with_both)
                .unwrap_or_else(|e| panic!("{dialect:?} SEDP payload must parse: {e:?}"));
            assert!(
                parsed.user_data.is_none(),
                "{dialect:?} frame must never carry the application user_data \
                 threaded only on the HDDS path"
            );
            assert!(
                parsed.shm_capability.is_none(),
                "{dialect:?} frame must never carry the HDDS SHM capability hint"
            );
        }
    }
}
