// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Helpers to build and inspect lightweight RTPS packets.

pub mod acknack;
mod extract;
pub mod heartbeat_frag;
mod helpers;
pub mod nack_frag;
mod packet;

pub use acknack::{
    build_acknack_packet, build_acknack_packet_with_final, build_acknack_submessage,
};
pub use extract::{
    extract_data_payload, extract_inline_qos, extract_sequence_number, extract_writer_guid,
};
pub use heartbeat_frag::{build_heartbeat_frag_packet, build_heartbeat_frag_submessage};
pub use nack_frag::{build_nack_frag_packet, build_nack_frag_submessage};
pub use packet::{
    build_acknack_packet_from_ranges, build_data_frag_packets, build_data_packet,
    build_data_packet_with_context, build_gap_packet, build_heartbeat_packet,
    build_heartbeat_packet_with_context, should_fragment, RtpsEndpointContext,
    DEFAULT_FRAGMENT_SIZE, DEFAULT_MAX_UNFRAGMENTED_SIZE,
};

#[cfg(test)]
mod tests;
