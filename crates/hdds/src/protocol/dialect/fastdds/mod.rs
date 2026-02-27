// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! eProsima FastDDS dialect encoder
//!
//! **Vendor ID**: 0x010F
//! **Status**: CERTIFIED v41
//!
//! This encoder handles FastDDS-specific RTPS encoding quirks:
//! - PL_CDR_LE encapsulation for discovery
//! - XCDR2 support for user data
//! - Specific PID ordering in SEDP
//! - No TypeObject requirement (static types)
//!
//! # Certification
//!
//! This encoder was certified against FastDDS v2.x on 2025-11-27:
//! - SENSOR_STREAMING: BEST_EFFORT/VOLATILE/KEEP_LAST(1) - PASSED
//! - STATE_SYNC: RELIABLE/TRANSIENT_LOCAL/KEEP_LAST(10) - PASSED
//! - EVENT_LOG: RELIABLE/TRANSIENT_LOCAL/KEEP_ALL - PASSED
//!
//! **DO NOT MODIFY WITHOUT FULL REGRESSION TESTING**

mod sedp;
mod spdp;

use std::net::SocketAddr;

use super::error::{EncodeError, EncodeResult};
use super::{DialectEncoder, Guid, QosProfile, SedpEndpointData};

/// eProsima FastDDS encoder (certified v41)
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
        // Convert new SedpEndpointData to legacy SedpData format
        // and delegate to the certified builder in protocol/discovery/sedp/build
        use crate::core::discovery::GUID;
        use crate::protocol::discovery::types::SedpData as LegacySedpData;

        // Construct GUID from prefix + entity_id
        let mut endpoint_guid_bytes = [0u8; 16];
        endpoint_guid_bytes[..12].copy_from_slice(&data.endpoint_guid.prefix);
        endpoint_guid_bytes[12..16].copy_from_slice(&data.endpoint_guid.entity_id);

        let mut participant_guid_bytes = [0u8; 16];
        participant_guid_bytes[..12].copy_from_slice(&data.participant_guid.prefix);
        participant_guid_bytes[12..16].copy_from_slice(&data.participant_guid.entity_id);

        let legacy_data = LegacySedpData {
            topic_name: data.topic_name.to_string(),
            type_name: data.type_name.to_string(),
            endpoint_guid: GUID::from_bytes(endpoint_guid_bytes),
            participant_guid: GUID::from_bytes(participant_guid_bytes),
            qos_hash: 0,
            qos: None, // QoS conversion deferred - see Gitea issue for QoS interop
            type_object: None,
            unicast_locators: data.unicast_locators.to_vec(),
            user_data: None,
        };

        // Use certified builder (8KB buffer matches original)
        let mut buf = vec![0u8; 8192];
        let len = crate::protocol::discovery::sedp::build::build_sedp(&legacy_data, &mut buf)
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

        // First available sequence number (SequenceNumber_t = 2 x i32)
        let first_high = (first_sn >> 32) as i32;
        let first_low = first_sn as u32;
        buf[12..16].copy_from_slice(&first_high.to_le_bytes());
        buf[16..20].copy_from_slice(&first_low.to_le_bytes());

        // Last sequence number
        let last_high = (last_sn >> 32) as i32;
        let last_low = last_sn as u32;
        buf[20..24].copy_from_slice(&last_high.to_le_bytes());
        buf[24..28].copy_from_slice(&last_low.to_le_bytes());

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
        let num_bits = bitmap.len() as u32 * 32;
        let bitmap_bytes = bitmap.len() * 4;
        let submsg_len = 20 + bitmap_bytes + 4; // header fields + bitmap + count

        let mut buf = vec![0u8; 4 + submsg_len];

        // Submessage header
        buf[0] = 0x06; // ACKNACK
        buf[1] = 0x01; // Flags: Endianness=LE
        buf[2..4].copy_from_slice(&(submsg_len as u16).to_le_bytes());

        let mut offset = 4;

        // Reader EntityId
        buf[offset..offset + 4].copy_from_slice(reader_id);
        offset += 4;
        // Writer EntityId
        buf[offset..offset + 4].copy_from_slice(writer_id);
        offset += 4;

        // SequenceNumberSet: base + numBits + bitmap
        let base_high = (base_sn >> 32) as i32;
        let base_low = base_sn as u32;
        buf[offset..offset + 4].copy_from_slice(&base_high.to_le_bytes());
        offset += 4;
        buf[offset..offset + 4].copy_from_slice(&base_low.to_le_bytes());
        offset += 4;

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

        let mut buf = vec![0u8; 4 + submsg_len];

        // Submessage header
        buf[0] = 0x08; // GAP
        buf[1] = 0x01; // Flags: LE
        buf[2..4].copy_from_slice(&(submsg_len as u16).to_le_bytes());

        let mut offset = 4;

        // Reader EntityId
        buf[offset..offset + 4].copy_from_slice(reader_id);
        offset += 4;
        // Writer EntityId
        buf[offset..offset + 4].copy_from_slice(writer_id);
        offset += 4;

        // Gap start (SequenceNumber_t)
        let start_high = (gap_start >> 32) as i32;
        let start_low = gap_start as u32;
        buf[offset..offset + 4].copy_from_slice(&start_high.to_le_bytes());
        offset += 4;
        buf[offset..offset + 4].copy_from_slice(&start_low.to_le_bytes());
        offset += 4;

        // Gap list (SequenceNumberSet)
        let list_high = (gap_list_base >> 32) as i32;
        let list_low = gap_list_base as u32;
        buf[offset..offset + 4].copy_from_slice(&list_high.to_le_bytes());
        offset += 4;
        buf[offset..offset + 4].copy_from_slice(&list_low.to_le_bytes());
        offset += 4;

        // numBits
        let num_bits = gap_bitmap.len() as u32 * 32;
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
        let mut buf = vec![0u8; 4 + submsg_len];

        // Submessage header
        buf[0] = 0x15; // DATA
        buf[1] = 0x05; // Flags: LE + Data present (no inline QoS)
        buf[2..4].copy_from_slice(&(submsg_len as u16).to_le_bytes());

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
        let sn_high = (sequence_number >> 32) as i32;
        let sn_low = sequence_number as u32;
        buf[offset..offset + 4].copy_from_slice(&sn_high.to_le_bytes());
        offset += 4;
        buf[offset..offset + 4].copy_from_slice(&sn_low.to_le_bytes());
        offset += 4;

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
        let mut buf = vec![0u8; 4 + submsg_len];

        // Submessage header
        buf[0] = 0x16; // DATA_FRAG
        buf[1] = 0x05; // Flags: LE + Data present
        buf[2..4].copy_from_slice(&(submsg_len as u16).to_le_bytes());

        let mut offset = 4;

        // Extra flags + octetsToInlineQos
        buf[offset..offset + 2].copy_from_slice(&0u16.to_le_bytes());
        buf[offset + 2..offset + 4].copy_from_slice(&16u16.to_le_bytes());
        offset += 4;

        // Reader/Writer EntityIds
        buf[offset..offset + 4].copy_from_slice(reader_id);
        offset += 4;
        buf[offset..offset + 4].copy_from_slice(writer_id);
        offset += 4;

        // Sequence number
        let sn_high = (sequence_number >> 32) as i32;
        let sn_low = sequence_number as u32;
        buf[offset..offset + 4].copy_from_slice(&sn_high.to_le_bytes());
        offset += 4;
        buf[offset..offset + 4].copy_from_slice(&sn_low.to_le_bytes());
        offset += 4;

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
        // PID_UNICAST_LOCATOR (0x002F) - 24 bytes
        if *offset + 28 > buf.len() {
            return Err(EncodeError::BufferTooSmall);
        }

        // PID header
        buf[*offset..*offset + 2].copy_from_slice(&0x002Fu16.to_le_bytes());
        buf[*offset + 2..*offset + 4].copy_from_slice(&24u16.to_le_bytes());
        *offset += 4;

        // Locator kind (1 = UDP_v4)
        buf[*offset..*offset + 4].copy_from_slice(&1u32.to_le_bytes());
        *offset += 4;

        // Port
        buf[*offset..*offset + 4].copy_from_slice(&(addr.port() as u32).to_le_bytes());
        *offset += 4;

        // Address (16 bytes, IPv4 mapped to IPv6 format)
        match addr {
            SocketAddr::V4(v4) => {
                buf[*offset..*offset + 12].copy_from_slice(&[0u8; 12]);
                buf[*offset + 12..*offset + 16].copy_from_slice(&v4.ip().octets());
            }
            SocketAddr::V6(v6) => {
                buf[*offset..*offset + 16].copy_from_slice(&v6.ip().octets());
            }
        }
        *offset += 16;

        Ok(())
    }

    fn encode_multicast_locator(
        &self,
        addr: &SocketAddr,
        buf: &mut [u8],
        offset: &mut usize,
    ) -> EncodeResult<()> {
        // PID_MULTICAST_LOCATOR (0x0030) - 24 bytes
        if *offset + 28 > buf.len() {
            return Err(EncodeError::BufferTooSmall);
        }

        // PID header
        buf[*offset..*offset + 2].copy_from_slice(&0x0030u16.to_le_bytes());
        buf[*offset + 2..*offset + 4].copy_from_slice(&24u16.to_le_bytes());
        *offset += 4;

        // Locator kind
        buf[*offset..*offset + 4].copy_from_slice(&1u32.to_le_bytes());
        *offset += 4;

        // Port
        buf[*offset..*offset + 4].copy_from_slice(&(addr.port() as u32).to_le_bytes());
        *offset += 4;

        // Address
        match addr {
            SocketAddr::V4(v4) => {
                buf[*offset..*offset + 12].copy_from_slice(&[0u8; 12]);
                buf[*offset + 12..*offset + 16].copy_from_slice(&v4.ip().octets());
            }
            SocketAddr::V6(v6) => {
                buf[*offset..*offset + 16].copy_from_slice(&v6.ip().octets());
            }
        }
        *offset += 16;

        Ok(())
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
        // FastDDS (RTPS 2.3+) handles rapid discovery well.
        // Skip the SPDP barrier to send SEDP immediately.
        true
    }
}
