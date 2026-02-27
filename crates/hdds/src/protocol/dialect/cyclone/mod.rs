// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Eclipse Cyclone DDS dialect encoder
//!
//! **Vendor ID**: 0x0110
//! **Status**: Stub
//!
//! # ARCHITECTURAL CONSTRAINT
//!
//! This dialect module is ISOLATED. Never import from other dialect modules.
//! Shared RTPS code lives in `crate::protocol::rtps`.
//!
//! FORBIDDEN: use super::fastdds / use super::hybrid / use super::rti
//! ALLOWED:   use crate::protocol::rtps

use std::net::SocketAddr;

use super::error::{EncodeError, EncodeResult};
use super::{DialectEncoder, Guid, QosProfile, SedpEndpointData};
use crate::protocol::rtps;

/// Eclipse Cyclone DDS encoder
pub struct CycloneEncoder;

/// Calculate actual num_bits from bitmap content.
fn calculate_actual_num_bits(bitmap: &[u32]) -> u32 {
    if bitmap.is_empty() {
        return 0;
    }
    let mut last_nonzero_idx = None;
    for (i, &word) in bitmap.iter().enumerate().rev() {
        if word != 0 {
            last_nonzero_idx = Some(i);
            break;
        }
    }
    match last_nonzero_idx {
        None => 0,
        Some(idx) => {
            let word = bitmap[idx];
            let highest_bit = 31 - word.leading_zeros();
            (idx as u32 * 32) + highest_bit + 1
        }
    }
}

impl DialectEncoder for CycloneEncoder {
    fn build_spdp(
        &self,
        participant_guid: &Guid,
        unicast_locators: &[SocketAddr],
        multicast_locators: &[SocketAddr],
        lease_duration_sec: u32,
    ) -> EncodeResult<Vec<u8>> {
        // CycloneDDS uses standard RTPS SPDP encoding
        use crate::core::discovery::GUID;
        use crate::protocol::discovery::SpdpData;

        let mut guid_bytes = [0u8; 16];
        guid_bytes[..12].copy_from_slice(&participant_guid.prefix);
        guid_bytes[12..16].copy_from_slice(&participant_guid.entity_id);

        let spdp_data = SpdpData {
            participant_guid: GUID::from_bytes(guid_bytes),
            lease_duration_ms: (lease_duration_sec as u64) * 1000,
            domain_id: 0,
            metatraffic_unicast_locators: unicast_locators.to_vec(),
            default_unicast_locators: unicast_locators.to_vec(),
            default_multicast_locators: multicast_locators.to_vec(),
            metatraffic_multicast_locators: multicast_locators.to_vec(),
            identity_token: None,
        };

        let mut buf = vec![0u8; 2048];
        let len = crate::protocol::discovery::build_spdp(&spdp_data, &mut buf)
            .map_err(|_| EncodeError::BufferTooSmall)?;
        buf.truncate(len);
        Ok(buf)
    }

    fn build_sedp(&self, data: &SedpEndpointData) -> EncodeResult<Vec<u8>> {
        // CycloneDDS uses standard RTPS SEDP encoding
        use crate::core::discovery::GUID;
        use crate::dds::qos::QoS;
        use crate::protocol::discovery::types::SedpData as LegacySedpData;
        use crate::Cdr2Decode;

        let mut endpoint_guid_bytes = [0u8; 16];
        endpoint_guid_bytes[..12].copy_from_slice(&data.endpoint_guid.prefix);
        endpoint_guid_bytes[12..16].copy_from_slice(&data.endpoint_guid.entity_id);

        let mut participant_guid_bytes = [0u8; 16];
        participant_guid_bytes[..12].copy_from_slice(&data.participant_guid.prefix);
        participant_guid_bytes[12..16].copy_from_slice(&data.participant_guid.entity_id);

        // Convert QosProfile to DDS QoS
        let qos = data.qos.map(|q| {
            let base = match q.reliability_kind {
                1 => QoS::best_effort(),
                _ => QoS::reliable(),
            };
            let with_durability = match q.durability_kind {
                0 => base.volatile(),
                3 => base.persistent(),
                _ => base.transient_local(),
            };
            match q.history_kind {
                1 => with_durability.keep_all(),
                _ => with_durability.keep_last(q.history_depth),
            }
        });

        #[cfg(feature = "xtypes")]
        let type_object = data
            .type_object
            .and_then(|bytes| crate::xtypes::CompleteTypeObject::decode_cdr2_le(bytes).ok())
            .map(|(v, _)| v);
        #[cfg(not(feature = "xtypes"))]
        let type_object = None;

        let legacy_data = LegacySedpData {
            topic_name: data.topic_name.to_string(),
            type_name: data.type_name.to_string(),
            endpoint_guid: GUID::from_bytes(endpoint_guid_bytes),
            participant_guid: GUID::from_bytes(participant_guid_bytes),
            qos_hash: 0,
            qos,
            type_object,
            unicast_locators: data.unicast_locators.to_vec(),
            user_data: None,
        };

        let mut buf = vec![0u8; 8192];
        let len = crate::protocol::discovery::sedp::build::build_sedp(&legacy_data, &mut buf)
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
        let num_bits = calculate_actual_num_bits(bitmap);
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
        let num_bits = calculate_actual_num_bits(gap_bitmap);
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

    /// CycloneDDS has a 5-second timeout for builtin endpoints,
    /// so we need to send SEDP immediately without waiting for SPDP barrier.
    fn skip_spdp_barrier(&self) -> bool {
        true
    }
}
