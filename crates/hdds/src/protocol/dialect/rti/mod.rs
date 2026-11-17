// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! RTI Connext DDS dialect encoder
//!
//! **Vendor ID**: 0x0101
//! **Status**: Active
//!
//! For vendor id 0x0101 this encoder writes SEDP with:
//! - PID_KEY_HASH (always sent; RTPS 2.5 Sec.9.6.4.8: the key of a builtin
//!   topic is the endpoint GUID)
//! - PID_PROTOCOL_VERSION and PID_VENDOR_ID (always sent)
//! - PID_DATA_REPRESENTATION from the endpoint's QoS (DDS-XTypes 1.3
//!   Sec.7.6.3.1.1)
//! - a fixed PID order (RTPS 2.5 Sec.9.4.2.11 makes the order free)
//!
//! It sends no TypeObject (PID_TYPE_OBJECT_LB is a vendor-range PID; see
//! `sedp`).
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

use super::common::sequence_number_set_num_bits;
use super::error::{EncodeError, EncodeResult};
use super::{DialectEncoder, Guid, QosProfile, SedpEndpointData};
use crate::protocol::rtps;

/// RTI Connext DDS encoder
pub struct RtiEncoder;

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
            None,
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
        spdp::build_spdp(
            participant_guid,
            unicast_locators,
            multicast_locators,
            lease_duration_sec,
            Some(domain_id),
        )
    }

    fn build_sedp(&self, data: &SedpEndpointData) -> EncodeResult<Vec<u8>> {
        // Use the RTI dialect SEDP builder with its fixed PID ordering
        // (locators first, then group/participant ids, names, PID_KEY_HASH,
        // PID_ENDPOINT_GUID; see sedp::build_sedp):
        // - PID_KEY_HASH (always sent)
        // - No vendor-specific PIDs (0x8000+): HDDS never emits another
        //   vendor's PIDs (DDSI-RTPS 2.5 Sec.9.4.2.11)
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
        // For vendor id 0x0101 we set Final=true on ALL SEDP HEARTBEATs.
        // A HEARTBEAT without the Final flag requires the reader to answer
        // with an ACKNACK (DDSI-RTPS 2.5 Sec.8.3.8.6), which on discovery
        // writers turned into a HEARTBEAT/ACKNACK storm.
        //
        // Publications Writer (0x000003c2): Final=1
        // Subscriptions Writer (0x000004c2): Final=1
        matches!(writer_entity_id, [0x00, 0x00, 0x03 | 0x04, 0xC2])
    }

    fn build_acknack(
        &self,
        reader_id: &[u8; 4],
        writer_id: &[u8; 4],
        base_sn: u64,
        bitmap: &[u32],
        count: u32,
    ) -> EncodeResult<Vec<u8>> {
        // Calculate actual num_bits from bitmap content (interop fix)
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
        "RTI-Connext"
    }

    fn rtps_version(&self) -> (u8, u8) {
        (2, 4) // HDDS native version -- must match SPDP announcement
    }

    fn vendor_id(&self) -> [u8; 2] {
        [0x01, 0x1A] // HDDS -- never impersonate another vendor ID
    }

    fn requires_type_object(&self) -> bool {
        false // `sedp::build_sedp` writes no TypeObject PID
    }

    fn supports_xcdr2(&self) -> bool {
        // PID_DATA_REPRESENTATION follows the endpoint's QoS, XCDR2 included
        true
    }

    fn fragment_size(&self) -> usize {
        1400 // HDDS's own choice, below a 1500-octet Ethernet MTU
    }

    // `default_qos` is the trait's (`QoS::default()`, the DDS 1.4 Sec.2.2.3
    // request/offered defaults), as for every other vendor, when a peer's
    // SEDP carries no QoS PID at all. The public 7.7 shape_main SEDP carries
    // QoS PIDs, so that path is not taken for it.

    fn skip_spdp_barrier(&self) -> bool {
        // For vendor id 0x0101 we skip the SPDP barrier and send SEDP
        // immediately after the peer's SPDP, which the interoperability tests
        // require.
        true
    }

    fn requires_immediate_spdp_response(&self) -> bool {
        // For vendor id 0x0101 we answer the peer's SPDP with an
        // immediate unicast SPDP to its metatraffic unicast locators, BEFORE
        // the discovery HEARTBEATs, so SEDP does not wait for our next
        // periodic SPDP announcement.
        true
    }

    fn build_discovery_handshake(
        &self,
        our_guid_prefix: &[u8; 12],
        peer_guid_prefix: &[u8; 12],
    ) -> Option<Vec<Vec<u8>>> {
        // HEARTBEAT-first handshake:
        //
        // 1. HEARTBEAT for 0x03c2 (Publications Writer)
        // 2. HEARTBEAT for 0x04c2 (Subscriptions Writer)
        // 3. HEARTBEAT for 0x200c2 (P2P BuiltinParticipantMessage Writer)
        //
        // The reader answers with ACKNACKs (DDSI-RTPS 2.5 Sec.8.3.8.6), so
        // we do NOT send ACKNACKs in the initial handshake: ACKNACKs are
        // responses to HEARTBEATs, not initiators.
        //
        // The empty HEARTBEATs (firstSeq=1, lastSeq=0) signal:
        // "I'm a writer for this endpoint, no data yet, but ready to send."
        Some(vec![
            handshake::build_sedp_publications_heartbeat(our_guid_prefix, peer_guid_prefix),
            handshake::build_sedp_subscriptions_heartbeat(our_guid_prefix, peer_guid_prefix),
            handshake::build_participant_message_heartbeat(our_guid_prefix, peer_guid_prefix),
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dds::qos::{Durability, History, QoS, Reliability};

    /// A Connext SEDP that carries no QoS PID gets the defaults every other
    /// vendor's gets: the DDS 1.4 Sec.2.2.3 ones for the request/offered
    /// policies (BEST_EFFORT, VOLATILE; a writer is then made RELIABLE by
    /// `EndpointInfo::from_sedp`). Nothing documents other defaults for this
    /// vendor. History is not request/offered, so its depth is HDDS's.
    #[test]
    fn a_peer_that_sends_no_qos_pid_gets_the_spec_defaults() {
        let qos = RtiEncoder.default_qos();
        let spec = QoS::default();
        assert_eq!(qos.reliability, Reliability::BestEffort);
        assert_eq!(qos.reliability, spec.reliability);
        assert_eq!(qos.durability, Durability::Volatile);
        assert_eq!(qos.durability, spec.durability);
        assert_eq!(qos.history, spec.history);
        assert_ne!(qos.history, History::KeepLast(10), "the old preset");
    }
}
