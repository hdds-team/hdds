// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! RTI Connext DDS dialect encoder
//!
//! **Vendor ID**: 0x0101
//! **Status**: Active
//!
//! RTI Connext requires specific PIDs and encodings:
//! - PID_KEY_HASH (mandatory)
//! - PID_PROTOCOL_VERSION (mandatory)
//! - PID_DATA_REPRESENTATION (16-byte format)
//! - TypeObject with ZLIB compression
//! - Specific PID ordering
//!
//! Reference: comparison_rtip_vs_hdds_v74.md
//!
//! # ARCHITECTURAL CONSTRAINT
//!
//! This dialect module is ISOLATED. Never import from other dialect modules.
//! Shared RTPS code lives in `crate::protocol::rtps`.
//!
//! FORBIDDEN: use super::fastdds / use super::cyclone / use super::hybrid
//! ALLOWED:   use crate::protocol::rtps

mod handshake;
mod sedp;
mod spdp;

use std::net::SocketAddr;

use super::error::{EncodeError, EncodeResult};
use super::{DialectEncoder, Guid, QosProfile, SedpEndpointData};
use crate::protocol::rtps;

/// RTI Connext DDS encoder
pub struct RtiEncoder;

/// Calculate actual num_bits from bitmap content.
/// Finds the highest bit set to avoid over-reporting numBits.
fn calculate_actual_num_bits(bitmap: &[u32]) -> u32 {
    if bitmap.is_empty() {
        return 0;
    }

    // Find the last non-zero word
    let mut last_nonzero_idx = None;
    for (i, &word) in bitmap.iter().enumerate().rev() {
        if word != 0 {
            last_nonzero_idx = Some(i);
            break;
        }
    }

    match last_nonzero_idx {
        None => 0, // All zeros = 0 bits
        Some(idx) => {
            // Position of highest bit in this word
            let word = bitmap[idx];
            let highest_bit = 31 - word.leading_zeros();
            // Total bits = (words before * 32) + (position + 1)
            (idx as u32 * 32) + highest_bit + 1
        }
    }
}

impl DialectEncoder for RtiEncoder {
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
        // Use RTI-specific SEDP builder with proper PID ordering:
        // - PID_ENDPOINT_GUID first (RTI validates this)
        // - PID_KEY_HASH (mandatory for RTI)
        // - No vendor-specific PIDs (0x8000+) from non-RTI vendors
        sedp::build_sedp(data)
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

    fn sedp_heartbeat_final(&self, writer_entity_id: &[u8; 4]) -> bool {
        // v173: RTI requires Final=true for ALL SEDP HEARTBEATs to prevent
        // HEARTBEAT/ACKNACK storm. Without Final flag, RTI responds with ACKNACK
        // to every HEARTBEAT, causing 22k+ messages instead of ~200.
        //
        // Publications Writer (0x000003c2): Final=1
        // Subscriptions Writer (0x000004c2): Final=1
        matches!(
            writer_entity_id,
            [0x00, 0x00, 0x03, 0xC2] | [0x00, 0x00, 0x04, 0xC2]
        )
    }

    fn build_acknack(
        &self,
        reader_id: &[u8; 4],
        writer_id: &[u8; 4],
        base_sn: u64,
        bitmap: &[u32],
        count: u32,
    ) -> EncodeResult<Vec<u8>> {
        // Calculate actual num_bits from bitmap content (FIX for RTI interop)
        let num_bits = calculate_actual_num_bits(bitmap);

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
        let num_bits = calculate_actual_num_bits(gap_bitmap);

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
        "RTI-Connext-6.x"
    }

    fn rtps_version(&self) -> (u8, u8) {
        (2, 6) // RTI uses RTPS 2.6
    }

    fn vendor_id(&self) -> [u8; 2] {
        [0x01, 0x01] // RTI
    }

    fn requires_type_object(&self) -> bool {
        true // RTI requires TypeObject for XTypes
    }

    fn supports_xcdr2(&self) -> bool {
        false // RTI prefers XCDR1
    }

    fn fragment_size(&self) -> usize {
        1400 // RTI default
    }

    fn default_qos(&self) -> crate::dds::qos::QoS {
        // RTI Connext 6.x defaults (when no QoS PIDs are sent in SEDP)
        crate::dds::qos::QoS::rti_defaults()
    }

    fn skip_spdp_barrier(&self) -> bool {
        // RTI has aggressive discovery timeouts (~3s) and will report
        // "SampleLost" if SEDP DATA arrives after its timeout.
        // Skip the SPDP barrier to send SEDP immediately.
        true
    }

    fn requires_immediate_spdp_response(&self) -> bool {
        // v132: RTI requires immediate SPDP unicast response before HEARTBEATs.
        //
        // FastDDS reference (frames 11-12):
        // - Frame 11: RTI sends SPDP multicast
        // - Frame 12 (+0.5ms): FastDDS sends SPDP unicast to RTI's metatraffic_unicast
        // - Frame 15-17: FastDDS sends discovery HEARTBEATs
        // - Frame 18+: RTI responds immediately with ACKNACKs and DATA
        //
        // Without this, RTI ignores HEARTBEATs and waits for periodic SPDP (~200ms),
        // causing SEDP DATA to arrive 60+ seconds late (instead of ~2ms).
        true
    }

    fn build_discovery_handshake(
        &self,
        our_guid_prefix: &[u8; 12],
        peer_guid_prefix: &[u8; 12],
    ) -> Option<Vec<Vec<u8>>> {
        // v131: RTI requires HEARTBEAT-first handshake (like FastDDS):
        //
        // FastDDS discovery sequence (frames 15-17):
        // 1. HEARTBEAT for 0x03c2 (Publications Writer)
        // 2. HEARTBEAT for 0x04c2 (Subscriptions Writer)
        // 3. HEARTBEAT for 0x200c2 (Service-request Writer)
        //
        // Then RTI responds with ACKNACKs and its own HEARTBEATs, followed by DATA.
        //
        // Key insight: FastDDS does NOT send ACKNACKs in initial handshake.
        // ACKNACKs are responses to HEARTBEATs, not initiators.
        //
        // The empty HEARTBEATs (firstSeq=1, lastSeq=0) signal:
        // "I'm a writer for this endpoint, no data yet, but ready to send."
        Some(vec![
            handshake::build_sedp_publications_heartbeat(our_guid_prefix, peer_guid_prefix),
            handshake::build_sedp_subscriptions_heartbeat(our_guid_prefix, peer_guid_prefix),
            handshake::build_service_request_heartbeat(our_guid_prefix, peer_guid_prefix),
        ])
    }
}
