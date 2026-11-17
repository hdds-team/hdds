// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Eclipse Cyclone DDS dialect encoder
//!
//! **Vendor ID**: 0x0110
//! **Status**: Active (standard RTPS SPDP/SEDP encoding)
//!
//! CycloneDDS follows the standard RTPS discovery encoding, so this encoder
//! delegates SPDP/SEDP construction to the shared `protocol::discovery`
//! builders rather than carrying vendor-specific quirks.
//!
//! # ARCHITECTURAL CONSTRAINT
//!
//! This dialect module is ISOLATED. Never import from other dialect modules.
//! Shared RTPS code lives in `crate::protocol::rtps`.
//!
//! FORBIDDEN: use super::fastdds / use super::hybrid / use super::rti
//! ALLOWED:   use crate::protocol::rtps

use std::net::SocketAddr;

use super::common::sequence_number_set_num_bits;
use super::error::{EncodeError, EncodeResult};
use super::{DialectEncoder, Guid, QosProfile, SedpEndpointData};
use crate::protocol::rtps;

/// Eclipse Cyclone DDS encoder
pub struct CycloneEncoder;

impl DialectEncoder for CycloneEncoder {
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
        // CycloneDDS uses standard RTPS SEDP encoding
        use crate::core::discovery::GUID;
        use crate::protocol::discovery::types::SedpData as LegacySedpData;
        #[cfg(feature = "xtypes")]
        use crate::Cdr2Decode;

        let mut endpoint_guid_bytes = [0u8; 16];
        endpoint_guid_bytes[..12].copy_from_slice(&data.endpoint_guid.prefix);
        endpoint_guid_bytes[12..16].copy_from_slice(&data.endpoint_guid.entity_id);

        let mut participant_guid_bytes = [0u8; 16];
        participant_guid_bytes[..12].copy_from_slice(&data.participant_guid.prefix);
        participant_guid_bytes[12..16].copy_from_slice(&data.participant_guid.entity_id);

        let qos = data.qos.map(super::QosProfile::to_qos);

        // A decode failure here must not be silent: `.ok()` on the Result
        // with no log would drop PID_TYPE_OBJECT from the endpoint's SEDP with
        // no symptom anywhere but a downstream consumer's machine.
        // `bytes` is OUR OWN previously-encoded TypeObject, so a decode
        // failure here means a local encode/decode mismatch, not a foreign
        // peer sending garbage -- worth an `error!`, not `debug!`. Logged
        // and continued (not propagated): failing the whole SEDP
        // announcement over a missing TypeObject would cost the endpoint
        // its topic/QoS match entirely, which is worse than a peer falling
        // back to placeholder xtypes introspection.
        #[cfg(feature = "xtypes")]
        let type_object = data.type_object.and_then(|bytes| {
            match crate::xtypes::CompleteTypeObject::decode_cdr2_le(bytes) {
                Ok((v, _)) => Some(v),
                Err(e) => {
                    log::error!(
                        "[SEDP][cyclone] TypeObject decode failed for endpoint {:02x?} topic='{}' type='{}' ({} bytes): {}; PID_TYPE_OBJECT omitted from this announcement",
                        endpoint_guid_bytes,
                        data.topic_name,
                        data.type_name,
                        bytes.len(),
                        e
                    );
                    None
                }
            }
        });
        #[cfg(not(feature = "xtypes"))]
        let type_object = None;

        // Thread the pre-computed TypeInformation (real dep hashes) so getTypes
        // dependency resolution works cross-vendor (DDS-XTypes v1.3 sec. 7.6.3.2).
        // Feature OFF: None (sentinel) => wire byte-unchanged.
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
            user_data: None,
            shm_capability: None,
            has_explicit_reliability: false,
            has_explicit_ownership: false,
            has_ownership_strength: false,
            type_information: type_information_for_legacy,
            type_consistency: data.type_consistency.clone(),
            group_entity_id: data.group_entity_id,
            // Emission never reads this field; it exists on `SedpData` for
            // the receive side only (see `insert_endpoint_security_info`).
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

    fn build_info_ts(&self, timestamp_sec: u32, timestamp_frac: u32) -> Vec<u8> {
        rtps::encode_info_ts(timestamp_sec, timestamp_frac)
    }

    fn build_info_dst(&self, guid_prefix: &[u8; 12]) -> Vec<u8> {
        rtps::encode_info_dst(guid_prefix)
    }

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

    fn name(&self) -> &'static str {
        "CycloneDDS"
    }
    fn rtps_version(&self) -> (u8, u8) {
        (2, 3)
    }
    fn vendor_id(&self) -> [u8; 2] {
        [0x01, 0x10]
    }
    fn requires_type_object(&self) -> bool {
        false
    }
    fn supports_xcdr2(&self) -> bool {
        true
    }
    fn fragment_size(&self) -> usize {
        1300
    }

    /// Send SEDP as soon as the peer's SPDP is processed, without waiting
    /// for the SPDP barrier, so endpoint discovery with this dialect's
    /// peers is not delayed by it.
    fn skip_spdp_barrier(&self) -> bool {
        true
    }
}
