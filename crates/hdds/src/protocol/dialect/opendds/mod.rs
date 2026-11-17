// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! OpenDDS dialect encoder
//!
//! **Vendor ID**: 0x0103
//! **Status**: Active (discovery handshake)
//!
//! What this dialect changes compared with the generic encoder:
//! - an explicit SEDP handshake right after SPDP discovery: HEARTBEATs from
//!   our SEDP and participant-message writers, even when they hold no
//!   sample, and pre-emptive ACKNACKs from the matching builtin readers
//!   (see `handshake`);
//! - SEDP announcements built by `sedp::build_sedp`, carrying
//!   PID_DATA_REPRESENTATION and, for the one type it knows, a computed
//!   PID_TYPE_INFORMATION;
//! - RTPS protocol version 2.4 in the header and in PID_PROTOCOL_VERSION;
//! - the timing and ordering flags documented on each trait method below.
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

use super::common::sequence_number_set_num_bits;
use super::error::{EncodeError, EncodeResult};
use super::{DialectEncoder, Guid, QosProfile, SedpEndpointData};
use crate::protocol::rtps;

/// OpenDDS encoder
pub struct OpenDdsEncoder;

impl DialectEncoder for OpenDdsEncoder {
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
        "OpenDDS"
    }
    fn rtps_version(&self) -> (u8, u8) {
        (2, 4)
    } // RTPS 2.4, also advertised in PID_PROTOCOL_VERSION
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

    /// Answer a newly discovered participant of this vendor with an
    /// immediate unicast SPDP announcement, so it learns our locators
    /// without waiting for our next periodic multicast announcement.
    fn requires_immediate_spdp_response(&self) -> bool {
        true
    }

    /// Skip the SPDP barrier for this dialect.
    ///
    /// SEDP is started right after SPDP discovery of the peer (subject to
    /// `sedp_setup_delay_ms`) instead of waiting for the SPDP barrier.
    fn skip_spdp_barrier(&self) -> bool {
        true
    }

    /// Build OpenDDS-specific discovery handshake.
    ///
    /// Sent right after SPDP discovery of a participant of this vendor, so
    /// the builtin reliable endpoints of both sides exchange their state
    /// without waiting for the first periodic HEARTBEAT (DDSI-RTPS 2.5
    /// 8.3.7.1 AckNack, 8.3.7.5 Heartbeat).
    ///
    /// Handshake sequence:
    /// 1. HEARTBEAT for Publications Writer (signals we exist as a publications writer)
    /// 2. HEARTBEAT for Subscriptions Writer (signals we exist as a subscriptions writer)
    /// 3. HEARTBEAT for Service-Request Writer (P2P builtin participant message)
    /// 4. ACKNACK requesting the peer's publications (SEDP_PUBLICATIONS_READER)
    /// 5. ACKNACK requesting the peer's subscriptions (SEDP_SUBSCRIPTIONS_READER)
    /// 6. ACKNACK requesting the peer's participant messages (PARTICIPANT_MESSAGE_READER)
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
            // ACKNACKs: Request data from peer's writers (all 3 builtin readers)
            handshake::build_sedp_publications_request(our_guid_prefix, peer_guid_prefix),
            handshake::build_sedp_subscriptions_request(our_guid_prefix, peer_guid_prefix),
            handshake::build_participant_message_request(our_guid_prefix, peer_guid_prefix),
        ])
    }

    /// The dialect waits 150 ms after SPDP discovery of the peer before
    /// sending its SEDP DATA, so the samples are sent once the peer has had
    /// time to create its proxies for our participant; a sample sent earlier
    /// is only recovered on a later HEARTBEAT / ACKNACK round.
    fn sedp_setup_delay_ms(&self) -> u64 {
        150
    }

    /// Re-announce our reader endpoints after receiving a writer announcement.
    ///
    /// This flag tells the generic SEDP handler to re-announce our Reader
    /// endpoints with NEW sequence numbers whenever a writer announcement
    /// arrives from a participant of this vendor. A retransmission of an
    /// already sent sample keeps its sequence number and is discarded by a
    /// reader that already holds it; a new sample is
    /// processed again after the peer's writer proxy exists.
    fn requires_sedp_reader_confirmation(&self) -> bool {
        true
    }

    /// Build ACKNACK confirmation for received SEDP DATA(w).
    ///
    /// The dialect acknowledges each received SEDP DATA(w) at once with a
    /// positive ACKNACK instead of waiting for the peer's next HEARTBEAT
    /// (DDSI-RTPS 2.5 8.3.7.1).
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

    /// SEDP re-announcements of this dialect carry INFO_DST.
    ///
    /// The re-announcement sent after a writer announcement (see
    /// `requires_sedp_reader_confirmation`) is addressed to that participant
    /// with an INFO_DST submessage (DDSI-RTPS 2.5 8.3.7.7).
    fn requires_info_dst_for_reannouncement(&self) -> bool {
        true
    }

    /// SEDP DATA packets of this dialect are ordered INFO_TS -> INFO_DST -> DATA.
    ///
    /// Both orders are valid RTPS (each submessage only updates the receiver
    /// state, DDSI-RTPS 2.5 8.3.4); this dialect places INFO_TS first.
    fn info_ts_before_info_dst(&self) -> bool {
        true
    }
}
