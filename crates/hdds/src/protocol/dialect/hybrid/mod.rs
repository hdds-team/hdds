// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Hybrid dialect encoder - safe fallback
//!
//! **Status**: Default fallback
//!
//! This encoder uses conservative settings that should work with
//! any spec-compliant RTPS implementation:
//! - All optional PIDs included
//! - Standard RTPS 2.3 encoding
//! - No vendor-specific optimizations
//! - No TypeObject (may limit XTypes interop)
//!
//! # ARCHITECTURAL CONSTRAINT
//!
//! This dialect module is ISOLATED. Never import from other dialect modules.
//! Shared RTPS code lives in `crate::protocol::rtps`.
//!
//! FORBIDDEN: use super::fastdds / use super::cyclone / use super::rti
//! ALLOWED:   use crate::protocol::rtps

mod sedp;
mod spdp;

use std::net::SocketAddr;

use super::common::sequence_number_set_num_bits;
use super::error::{EncodeError, EncodeResult};
use super::{DialectEncoder, Guid, QosProfile, SedpEndpointData};
use crate::protocol::rtps;

/// Hybrid encoder - conservative fallback for unknown vendors
pub struct HybridEncoder;

impl DialectEncoder for HybridEncoder {
    fn build_spdp(
        &self,
        participant_guid: &Guid,
        unicast_locators: &[SocketAddr],
        multicast_locators: &[SocketAddr],
        lease_duration_sec: u32,
    ) -> EncodeResult<Vec<u8>> {
        spdp::build_spdp(
            participant_guid,
            unicast_locators,
            multicast_locators,
            lease_duration_sec,
        )
    }

    fn build_sedp(&self, data: &SedpEndpointData) -> EncodeResult<Vec<u8>> {
        // Use the certified SEDP builder directly
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

        // The one reading of the announced profile (`QosProfile::to_qos`).
        let qos = data.qos.map(QosProfile::to_qos);

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
                        "[SEDP][hybrid] TypeObject decode failed for endpoint {:02x?} topic='{}' type='{}' ({} bytes): {}; PID_TYPE_OBJECT omitted from this announcement",
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

        // Thread the pre-computed TypeInformation (with real dep hashes) from
        // SedpEndpointData so the legacy SEDP builder emits the transitive
        // dependency manifest instead of the zero-dep sentinel. Emitting real
        // dependent_typeids is SPEC-STANDARD (DDS-XTypes v1.3 sec. 7.6.3.2), not a
        // vendor bricolage, so it belongs in the conservative fallback that
        // serves every unrecognised vendor (CoreDX, Dust, GurumDDS, ...).
        // Feature OFF: always None (sentinel path) => cross-vendor SEDP wire
        // byte-unchanged.
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
            qos, // Now properly propagates QoS instead of dropping it
            type_object,
            dependents: Vec::new(),
            type_object_legacy_v1: false,
            unicast_locators: data.unicast_locators.to_vec(),
            user_data: None,
            // The HDDS SHM capability hint, carried ONLY when this frame is
            // addressed to an HDDS peer (see
            // `SedpEndpointData::hdds_peer_destination`). The flush and
            // retransmit paths reach an HDDS peer through this encoder, and
            // the pairing is resolved from whichever SEDP copy arrives
            // first, so omitting it here made shared-memory selection a
            // race. A multicast frame or a frame bound for a foreign vendor
            // leaves the flag false and the bytes unchanged.
            shm_capability: if data.hdds_peer_destination {
                data.hdds_shm_capability.map(str::to_string)
            } else {
                None
            },
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
        // Use standard RTPS encoder from protocol::rtps
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
        // Calculate actual num_bits from bitmap content (FIX for interop)
        let num_bits = sequence_number_set_num_bits(bitmap)?;

        // Use standard RTPS encoder from protocol::rtps
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

        // Use standard RTPS encoder from protocol::rtps
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
        // Use standard RTPS encoder from protocol::rtps
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
        // Use standard RTPS encoder from protocol::rtps
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
        // Use standard RTPS encoder from protocol::rtps
        rtps::encode_info_ts(timestamp_sec, timestamp_frac)
    }

    fn build_info_dst(&self, guid_prefix: &[u8; 12]) -> Vec<u8> {
        // Use standard RTPS encoder from protocol::rtps
        rtps::encode_info_dst(guid_prefix)
    }

    fn encode_unicast_locator(
        &self,
        addr: &SocketAddr,
        buf: &mut [u8],
        offset: &mut usize,
    ) -> EncodeResult<()> {
        // Use standard RTPS encoder from protocol::rtps
        rtps::encode_unicast_locator(addr, buf, offset).map_err(|_| EncodeError::BufferTooSmall)
    }

    fn encode_multicast_locator(
        &self,
        addr: &SocketAddr,
        buf: &mut [u8],
        offset: &mut usize,
    ) -> EncodeResult<()> {
        // Use standard RTPS encoder from protocol::rtps
        rtps::encode_multicast_locator(addr, buf, offset).map_err(|_| EncodeError::BufferTooSmall)
    }

    fn name(&self) -> &'static str {
        "Hybrid"
    }

    fn rtps_version(&self) -> (u8, u8) {
        // RTPS 2.4, announced from the first discovery
        // message on; a receiver that only accepts 2.4 or newer would
        // otherwise discard the message.
        (2, 4)
    }

    fn vendor_id(&self) -> [u8; 2] {
        [0x01, 0x1A] // HDDS
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

    /// Skip SPDP barrier for Hybrid mode.
    ///
    /// The SPDP barrier is not needed for the implementations we
    /// interoperate with: it was designed for legacy implementations
    /// that are gone. In interop mode, if the dialect is not yet locked, we use
    /// Hybrid as the fallback - and blocking SEDP in this case breaks HDDS<->HDDS discovery
    /// when other DDS nodes are present on the network.
    fn skip_spdp_barrier(&self) -> bool {
        true
    }

    /// Send immediate SPDP unicast response for Hybrid mode.
    ///
    /// In mixed networks, we want fast discovery for all peers.
    fn requires_immediate_spdp_response(&self) -> bool {
        true
    }
}
