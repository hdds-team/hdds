// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Twin Oaks CoreDX DDS dialect encoder
//!
//! **Vendor ID**: 0x0104
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

/// Twin Oaks CoreDX encoder
pub struct CoreDxEncoder;

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

impl DialectEncoder for CoreDxEncoder {
    fn build_spdp(
        &self,
        _: &Guid,
        _: &[SocketAddr],
        _: &[SocketAddr],
        _: u32,
    ) -> EncodeResult<Vec<u8>> {
        Err(EncodeError::UnsupportedDialect("CoreDX"))
    }

    fn build_sedp(&self, _: &SedpEndpointData) -> EncodeResult<Vec<u8>> {
        Err(EncodeError::UnsupportedDialect("CoreDX"))
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
        "CoreDX"
    }
    fn rtps_version(&self) -> (u8, u8) {
        (2, 3)
    }
    fn vendor_id(&self) -> [u8; 2] {
        [0x01, 0x04]
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
}
