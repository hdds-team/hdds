// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! OpenDDS dialect encoder
//!
//! **Vendor ID**: 0x0103
//! **Status**: Active (discovery handshake)
//!
//! OpenDDS has a different SEDP state machine than FastDDS/RTI:
//! - It waits for bidirectional SEDP exchange before announcing user endpoints
//! - HDDS must respond to OpenDDS's builtin HEARTBEAT/ACKNACK correctly
//! - Without proper responses, OpenDDS never sends DATA(w) writer announcements
//!
//! ## PCAP Analysis (opendds2hdds.pcap)
//!
//! Key observations:
//! 1. OpenDDS sends SPDP DATA(p) on multicast 239.255.0.1:7400
//! 2. HDDS responds with SPDP DATA(p) - both participants discover each other
//! 3. OpenDDS sends HEARTBEATs/ACKNACKs expecting SEDP responses
//! 4. OpenDDS expects responses on BUILTIN_PUBLICATIONS_WRITER (0x000003c2)
//! 5. Without proper handshake, OpenDDS never sends DATA(w) writer announcements
//!
//! ## Solution
//!
//! Similar to RTI, we need to send HEARTBEATs on our SEDP writers to signal
//! "I exist, ready to exchange endpoint data" even if we have no publications.
//! We also send ACKNACKs requesting OpenDDS's publications.
//!
//! # ARCHITECTURAL CONSTRAINT
//!
//! This dialect module is ISOLATED. Never import from other dialect modules.
//! Shared RTPS code lives in `crate::protocol::rtps`.
//!
//! FORBIDDEN: use super::fastdds / use super::hybrid / use super::rti
//! ALLOWED:   use crate::protocol::rtps

mod handshake;
mod sedp;

use std::net::SocketAddr;

use super::error::{EncodeError, EncodeResult};
use super::{DialectEncoder, Guid, QosProfile, SedpEndpointData};
use crate::protocol::rtps;

/// OpenDDS encoder
pub struct OpenDdsEncoder;

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

impl DialectEncoder for OpenDdsEncoder {
    fn build_spdp(
        &self,
        participant_guid: &Guid,
        unicast_locators: &[SocketAddr],
        multicast_locators: &[SocketAddr],
        lease_duration_sec: u32,
    ) -> EncodeResult<Vec<u8>> {
        // OpenDDS accepts standard SPDP encoding.
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
        // Use OpenDDS-specific SEDP builder with:
        // - PID_DATA_REPRESENTATION (XCDR2 support)
        // - PID_TYPE_INFORMATION (XTypes matching)
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
        "OpenDDS"
    }
    fn rtps_version(&self) -> (u8, u8) {
        (2, 4)
    } // v191: OpenDDS uses RTPS v2.4
    fn vendor_id(&self) -> [u8; 2] {
        [0x01, 0x03]
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

    /// OpenDDS requires immediate SPDP unicast response.
    ///
    /// Without this, OpenDDS may not progress to SEDP exchange within its timeout.
    fn requires_immediate_spdp_response(&self) -> bool {
        true
    }

    /// Skip SPDP barrier for OpenDDS.
    ///
    /// OpenDDS has specific timing requirements for discovery.
    /// We need to send SEDP immediately after SPDP without waiting.
    fn skip_spdp_barrier(&self) -> bool {
        true
    }

    /// Build OpenDDS-specific discovery handshake.
    ///
    /// v185: OpenDDS requires ACKNACKs on ALL SEDP builtin readers, not just Publications.
    /// PCAP analysis (reference.pcapng) shows OpenDDS sends 5 ACKNACKs immediately after
    /// SPDP discovery. Without matching ACKNACKs, OpenDDS delays DATA(w) by 4+ seconds.
    ///
    /// Handshake sequence:
    /// 1. HEARTBEAT for Publications Writer (signals we exist as a publications writer)
    /// 2. HEARTBEAT for Subscriptions Writer (signals we exist as a subscriptions writer)
    /// 3. HEARTBEAT for Service-Request Writer (P2P builtin participant message)
    /// 4. ACKNACK requesting OpenDDS's publications (SEDP_PUBLICATIONS_READER)
    /// 5. ACKNACK requesting OpenDDS's subscriptions (SEDP_SUBSCRIPTIONS_READER)
    /// 6. ACKNACK requesting OpenDDS's participant messages (PARTICIPANT_MESSAGE_READER)
    ///
    /// This handshake triggers OpenDDS to send its DATA(w) writer announcements quickly.
    fn build_discovery_handshake(
        &self,
        our_guid_prefix: &[u8; 12],
        peer_guid_prefix: &[u8; 12],
    ) -> Option<Vec<Vec<u8>>> {
        Some(vec![
            // HEARTBEATs: Signal our writers exist
            handshake::build_sedp_publications_heartbeat(our_guid_prefix, peer_guid_prefix),
            handshake::build_sedp_subscriptions_heartbeat(our_guid_prefix, peer_guid_prefix),
            handshake::build_service_request_heartbeat(our_guid_prefix, peer_guid_prefix),
            // ACKNACKs: Request data from peer's writers (v185: all 3 SEDP endpoints)
            handshake::build_sedp_publications_request(our_guid_prefix, peer_guid_prefix),
            handshake::build_sedp_subscriptions_request(our_guid_prefix, peer_guid_prefix),
            handshake::build_participant_message_request(our_guid_prefix, peer_guid_prefix),
        ])
    }

    /// v180: OpenDDS needs 150ms delay before SEDP DATA.
    ///
    /// PCAP analysis shows OpenDDS receives HDDS's SEDP DATA(r) sent at 1.25s
    /// but doesn't process it until 4.43s (after second SPDP). This is because
    /// OpenDDS needs time to set up its SEDP readers after processing SPDP.
    ///
    /// By adding a 150ms delay before sending SEDP DATA, we give OpenDDS time
    /// to initialize its SEDP infrastructure.
    fn sedp_setup_delay_ms(&self) -> u64 {
        150
    }

    /// v184: OpenDDS requires DATA(r) re-announcement after receiving DATA(w).
    ///
    /// OpenDDS has a peculiar state machine where it won't trigger PUBLICATION_MATCHED
    /// unless it receives a "fresh" DATA(r) after sending its DATA(w). The standard
    /// RTPS retransmissions (same seq number) are dropped as duplicates.
    ///
    /// This flag tells the generic SEDP handler to re-announce our Reader endpoints
    /// with NEW sequence numbers whenever we receive a Writer announcement from OpenDDS.
    fn requires_sedp_reader_confirmation(&self) -> bool {
        true
    }

    /// v186: Build ACKNACK confirmation for received SEDP DATA(w).
    ///
    /// OpenDDS requires an ACKNACK after receiving SEDP DATA(w) to complete
    /// its reliable delivery state machine. Reference PCAP shows OpenDDS subscriber
    /// sends ACKNACK immediately after receiving DATA(w) from publisher.
    fn build_sedp_data_confirmation(
        &self,
        our_guid_prefix: &[u8; 12],
        peer_guid_prefix: &[u8; 12],
        writer_entity_id: &[u8; 4],
        received_seq: i64,
    ) -> Option<Vec<u8>> {
        Some(handshake::build_sedp_data_confirmation(
            our_guid_prefix,
            peer_guid_prefix,
            writer_entity_id,
            received_seq,
        ))
    }

    /// v188: OpenDDS requires INFO_DST in SEDP re-announcements.
    ///
    /// OpenDDS ignores RTPS packets that don't have an INFO_DST submessage.
    /// This is required for the v187 reader re-announcement to work.
    fn requires_info_dst_for_reannouncement(&self) -> bool {
        true
    }

    /// v191: OpenDDS sends INFO_TS before INFO_DST in SEDP DATA packets.
    ///
    /// PCAP analysis shows OpenDDS sends: INFO_TS -> INFO_DST -> DATA
    /// HDDS was sending: INFO_DST -> INFO_TS -> DATA
    ///
    /// OpenDDS may be strict about submessage ordering and ignores packets
    /// with different ordering.
    fn info_ts_before_info_dst(&self) -> bool {
        true
    }
}
