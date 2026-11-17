// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! eProsima FastDDS dialect encoder
//!
//! **Vendor ID**: 0x010F
//! **Status**: CERTIFIED
//!
//! This encoder handles FastDDS-specific RTPS encoding quirks:
//! - PL_CDR_LE encapsulation for discovery
//! - XCDR2 support for user data
//! - Specific PID ordering in SEDP
//! - No TypeObject requirement (static types)
//!
//! # Certification
//!
//! This encoder was certified against FastDDS v2.x:
//! - SENSOR_STREAMING: BEST_EFFORT/VOLATILE/KEEP_LAST(1) - PASSED
//! - STATE_SYNC: RELIABLE/TRANSIENT_LOCAL/KEEP_LAST(10) - PASSED
//! - EVENT_LOG: RELIABLE/TRANSIENT_LOCAL/KEEP_ALL - PASSED
//!
//! **DO NOT MODIFY WITHOUT FULL REGRESSION TESTING**

mod sedp;
mod spdp;

use std::net::SocketAddr;

use super::common::{cdr_length, octets_to_next_header};
use super::error::{EncodeError, EncodeResult};
use super::{DialectEncoder, Guid, QosProfile, SedpEndpointData};
use crate::protocol::rtps::sequence_number_le_bytes;

/// `numBits` for a bitmap whose every word is announced (FastDDS-style
/// `len * 32`), converted rather than cast.
fn whole_words_num_bits(bitmap: &[u32]) -> EncodeResult<u32> {
    cdr_length(bitmap.len())?
        .checked_mul(32)
        .ok_or_else(|| EncodeError::InvalidParameter("bitmap too long for numBits".into()))
}

/// eProsima FastDDS encoder (certified)
pub struct FastDdsEncoder;

impl DialectEncoder for FastDdsEncoder {
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
                        "[SEDP][fastdds] TypeObject decode failed for endpoint {:02x?} topic='{}' type='{}' ({} bytes): {}; PID_TYPE_OBJECT omitted from this announcement",
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
        .map_err(|_| super::error::EncodeError::BufferTooSmall)?;
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
        // Standard RTPS HEARTBEAT - FastDDS follows spec
        let mut buf = vec![0u8; 32];

        // Submessage header
        buf[0] = 0x07; // HEARTBEAT
        buf[1] = 0x01; // Flags: Endianness=LE
        buf[2..4].copy_from_slice(&28u16.to_le_bytes()); // octetsToNextHeader

        // Reader EntityId
        buf[4..8].copy_from_slice(reader_id);
        // Writer EntityId
        buf[8..12].copy_from_slice(writer_id);

        // First available sequence number (SequenceNumber_t = high:i32 + low:u32)
        buf[12..20].copy_from_slice(&sequence_number_le_bytes(first_sn));

        // Last sequence number
        buf[20..28].copy_from_slice(&sequence_number_le_bytes(last_sn));

        // Count
        buf[28..32].copy_from_slice(&count.to_le_bytes());

        Ok(buf)
    }

    fn build_acknack(
        &self,
        reader_id: &[u8; 4],
        writer_id: &[u8; 4],
        base_sn: u64,
        bitmap: &[u32],
        count: u32,
    ) -> EncodeResult<Vec<u8>> {
        // Standard RTPS ACKNACK
        let num_bits = whole_words_num_bits(bitmap)?;
        let bitmap_bytes = bitmap.len() * 4;
        let submsg_len = 20 + bitmap_bytes + 4; // header fields + bitmap + count
        let octets_to_next = octets_to_next_header(submsg_len)?;

        let mut buf = vec![0u8; 4 + submsg_len];

        // Submessage header
        buf[0] = 0x06; // ACKNACK
        buf[1] = 0x01; // Flags: Endianness=LE
        buf[2..4].copy_from_slice(&octets_to_next.to_le_bytes());

        let mut offset = 4;

        // Reader EntityId
        buf[offset..offset + 4].copy_from_slice(reader_id);
        offset += 4;
        // Writer EntityId
        buf[offset..offset + 4].copy_from_slice(writer_id);
        offset += 4;

        // SequenceNumberSet: base + numBits + bitmap
        buf[offset..offset + 8].copy_from_slice(&sequence_number_le_bytes(base_sn));
        offset += 8;

        // numBits
        buf[offset..offset + 4].copy_from_slice(&num_bits.to_le_bytes());
        offset += 4;

        // bitmap
        for word in bitmap {
            buf[offset..offset + 4].copy_from_slice(&word.to_le_bytes());
            offset += 4;
        }

        // Count
        buf[offset..offset + 4].copy_from_slice(&count.to_le_bytes());

        Ok(buf)
    }

    fn build_gap(
        &self,
        reader_id: &[u8; 4],
        writer_id: &[u8; 4],
        gap_start: u64,
        gap_list_base: u64,
        gap_bitmap: &[u32],
    ) -> EncodeResult<Vec<u8>> {
        let bitmap_bytes = gap_bitmap.len() * 4;
        let submsg_len = 8 + 8 + 8 + 4 + bitmap_bytes; // entityIds + gapStart + gapListBase + numBits + bitmap
        let octets_to_next = octets_to_next_header(submsg_len)?;
        let num_bits = whole_words_num_bits(gap_bitmap)?;

        let mut buf = vec![0u8; 4 + submsg_len];

        // Submessage header
        buf[0] = 0x08; // GAP
        buf[1] = 0x01; // Flags: LE
        buf[2..4].copy_from_slice(&octets_to_next.to_le_bytes());

        let mut offset = 4;

        // Reader EntityId
        buf[offset..offset + 4].copy_from_slice(reader_id);
        offset += 4;
        // Writer EntityId
        buf[offset..offset + 4].copy_from_slice(writer_id);
        offset += 4;

        // Gap start (SequenceNumber_t)
        buf[offset..offset + 8].copy_from_slice(&sequence_number_le_bytes(gap_start));
        offset += 8;

        // Gap list (SequenceNumberSet)
        buf[offset..offset + 8].copy_from_slice(&sequence_number_le_bytes(gap_list_base));
        offset += 8;

        // numBits
        buf[offset..offset + 4].copy_from_slice(&num_bits.to_le_bytes());
        offset += 4;

        // bitmap
        for word in gap_bitmap {
            buf[offset..offset + 4].copy_from_slice(&word.to_le_bytes());
            offset += 4;
        }

        Ok(buf)
    }

    fn build_data(
        &self,
        reader_id: &[u8; 4],
        writer_id: &[u8; 4],
        sequence_number: u64,
        payload: &[u8],
        _inline_qos: Option<&QosProfile>,
    ) -> EncodeResult<Vec<u8>> {
        // FastDDS DATA submessage
        // - No inline QoS by default
        // - Standard RTPS 2.3 format
        let submsg_len = 20 + payload.len();
        let octets_to_next = octets_to_next_header(submsg_len)?;
        let mut buf = vec![0u8; 4 + submsg_len];

        // Submessage header
        buf[0] = 0x15; // DATA
        buf[1] = 0x05; // Flags: LE + Data present (no inline QoS)
        buf[2..4].copy_from_slice(&octets_to_next.to_le_bytes());

        let mut offset = 4;

        // Extra flags + octetsToInlineQos (no inline QoS = 16)
        buf[offset..offset + 2].copy_from_slice(&0u16.to_le_bytes()); // extraFlags
        buf[offset + 2..offset + 4].copy_from_slice(&16u16.to_le_bytes()); // octetsToInlineQos
        offset += 4;

        // Reader EntityId
        buf[offset..offset + 4].copy_from_slice(reader_id);
        offset += 4;
        // Writer EntityId
        buf[offset..offset + 4].copy_from_slice(writer_id);
        offset += 4;

        // Sequence number
        buf[offset..offset + 8].copy_from_slice(&sequence_number_le_bytes(sequence_number));
        offset += 8;

        // Payload (serialized data)
        buf[offset..offset + payload.len()].copy_from_slice(payload);

        Ok(buf)
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
        // DATA_FRAG submessage
        let submsg_len = 28 + payload.len();
        let octets_to_next = octets_to_next_header(submsg_len)?;
        let mut buf = vec![0u8; 4 + submsg_len];

        // Submessage header. RTPS v2.5 Table 9.18: DATA_FRAG flags are
        // E(0x01), Q(0x02), K(0x04), N(0x08); the D bit only exists on plain
        // DATA. Emit only E.
        buf[0] = 0x16; // DATA_FRAG
        buf[1] = 0x01;
        buf[2..4].copy_from_slice(&octets_to_next.to_le_bytes());

        let mut offset = 4;

        // Extra flags + octetsToInlineQos (28 for DATA_FRAG per RTPS v2.5
        // sec. 9.4.5.3.4; see protocol/rtps/data.rs for the rationale).
        buf[offset..offset + 2].copy_from_slice(&0u16.to_le_bytes());
        buf[offset + 2..offset + 4].copy_from_slice(&28u16.to_le_bytes());
        offset += 4;

        // Reader/Writer EntityIds
        buf[offset..offset + 4].copy_from_slice(reader_id);
        offset += 4;
        buf[offset..offset + 4].copy_from_slice(writer_id);
        offset += 4;

        // Sequence number
        buf[offset..offset + 8].copy_from_slice(&sequence_number_le_bytes(sequence_number));
        offset += 8;

        // Fragment starting number
        buf[offset..offset + 4].copy_from_slice(&fragment_starting_num.to_le_bytes());
        offset += 4;

        // Fragments in submessage
        buf[offset..offset + 2].copy_from_slice(&fragments_in_submessage.to_le_bytes());
        offset += 2;

        // Fragment size
        buf[offset..offset + 2].copy_from_slice(&fragment_size.to_le_bytes());
        offset += 2;

        // Sample size (total data size)
        buf[offset..offset + 4].copy_from_slice(&data_size.to_le_bytes());
        offset += 4;

        // Fragment payload
        buf[offset..offset + payload.len()].copy_from_slice(payload);

        Ok(buf)
    }

    fn build_info_ts(&self, timestamp_sec: u32, timestamp_frac: u32) -> Vec<u8> {
        let mut buf = vec![0u8; 12];

        // Submessage header
        buf[0] = 0x09; // INFO_TS
        buf[1] = 0x01; // Flags: LE
        buf[2..4].copy_from_slice(&8u16.to_le_bytes()); // length

        // Timestamp
        buf[4..8].copy_from_slice(&timestamp_sec.to_le_bytes());
        buf[8..12].copy_from_slice(&timestamp_frac.to_le_bytes());

        buf
    }

    fn build_info_dst(&self, guid_prefix: &[u8; 12]) -> Vec<u8> {
        let mut buf = vec![0u8; 16];

        // Submessage header
        buf[0] = 0x0E; // INFO_DST
        buf[1] = 0x01; // Flags: LE
        buf[2..4].copy_from_slice(&12u16.to_le_bytes()); // length

        // GUID prefix
        buf[4..16].copy_from_slice(guid_prefix);

        buf
    }

    fn encode_unicast_locator(
        &self,
        addr: &SocketAddr,
        buf: &mut [u8],
        offset: &mut usize,
    ) -> EncodeResult<()> {
        crate::protocol::rtps::encode_unicast_locator(addr, buf, offset)
            .map_err(|_| EncodeError::BufferTooSmall)
    }

    fn encode_multicast_locator(
        &self,
        addr: &SocketAddr,
        buf: &mut [u8],
        offset: &mut usize,
    ) -> EncodeResult<()> {
        crate::protocol::rtps::encode_multicast_locator(addr, buf, offset)
            .map_err(|_| EncodeError::BufferTooSmall)
    }

    fn name(&self) -> &'static str {
        "FastDDS-v41"
    }

    fn rtps_version(&self) -> (u8, u8) {
        (2, 3)
    }

    fn vendor_id(&self) -> [u8; 2] {
        [0x01, 0x0F] // eProsima
    }

    fn requires_type_object(&self) -> bool {
        false // FastDDS works with static types
    }

    fn supports_xcdr2(&self) -> bool {
        true
    }

    fn fragment_size(&self) -> usize {
        1300 // Conservative MTU - headers
    }

    fn skip_spdp_barrier(&self) -> bool {
        // Skip the SPDP barrier: SEDP goes out as soon as the peer's SPDP
        // is processed.
        true
    }
}
