// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Helpers to build and inspect lightweight RTPS packets.

pub mod acknack;
mod extract;
pub mod heartbeat_frag;
pub(crate) mod helpers;
pub mod nack_frag;
mod packet;

pub use acknack::{
    build_acknack_packet, build_acknack_packet_with_final, build_acknack_submessage,
};
// Inline-QoS helpers (`extract_inline_qos`, `extract_status_info`,
// `extract_key_hash`, `extract_group_entity_id`, `extract_coherent_set`,
// `extract_group_coherent_set`) are intentionally `pub(crate)`: callers
// inside the hdds crate use them through `crate::protocol::builder::*`, and
// no out-of-crate consumer references them. `extract_inline_qos` now
// returns `Option<(&[u8], bool)>` so the inline-QoS slice and the matching
// E flag come from a single packet scan; legacy `data_submsg_le` has been
// removed in favour of this single-scan API.
#[cfg(feature = "security")]
pub(crate) use extract::extract_participant_dispose_at;
pub(crate) use extract::{
    data_submessage_layout, extract_coherent_set, extract_end_coherent_set,
    extract_end_coherent_set_count, extract_endpoint_guid_from_serialized_key,
    extract_group_coherent_set, extract_group_end_without_coherent_set, extract_group_entity_id,
    extract_group_seq_num, extract_inline_qos, extract_inline_qos_at, extract_key_hash,
    extract_key_payload, extract_key_payload_at, extract_participant_guid_from_serialized_key,
    extract_serialized_key_at, extract_status_info, extract_writer_group_info,
    is_data_at_without_sample,
};
pub use extract::{
    extract_data_payload, extract_ecs_marker, extract_end_coherent_marker, extract_sequence_number,
    extract_writer_guid, is_data_without_sample, is_key_only_data,
};
// `read_u16` / `read_u32` are reused from sedp_handler.rs to read
// submessage-scoped fields with the matching E flag (RTPS v2.5 sec. 8.3.3.3).
pub(crate) use extract::{
    extract_frag_reader_entity_id, extract_reader_entity_id, find_data_frag, read_u16, read_u32,
};
pub use heartbeat_frag::{build_heartbeat_frag_packet, build_heartbeat_frag_submessage};
pub use helpers::StatusInfoKind;
pub use nack_frag::{build_nack_frag_packet, build_nack_frag_submessage};
pub use packet::{
    build_data_frag_packets, build_data_frag_packets_ts, build_data_packet,
    build_data_packet_grouped_ts, build_data_packet_with_context,
    build_data_packet_with_context_full, build_data_packet_with_context_full_keyed,
    build_data_packet_with_context_full_keyed_ts, build_data_packet_with_context_full_ts,
    build_data_packet_with_context_ts, build_dispose_packet_with_context,
    build_dispose_packet_with_context_coherent_ts, build_dispose_packet_with_context_ts,
    build_ecs_close_marker, build_ecs_close_marker_ts, build_ecs_data_submessage,
    build_ecs_data_submessage_count, build_ecs_data_submessage_count_ts,
    build_ecs_data_submessage_ts, build_ecs_spec_ts, build_gap_packet, build_gap_packet_filtered,
    build_gap_packet_from_parts, build_gap_packet_group, build_heartbeat_packet,
    build_heartbeat_packet_group, build_heartbeat_packet_with_context, data_frag_inline_qos,
    downgrade_data_encap_to_plain_cdr2, prepend_header_extension, put_inline_qos_in_first_fragment,
    should_fragment, with_liveliness_assertion_flags, RtpsEndpointContext, DEFAULT_FRAGMENT_SIZE,
    DEFAULT_MAX_UNFRAGMENTED_SIZE, GAP_FILTERED_COUNT_FLAG, GAP_GROUP_INFO_FLAG,
    HEARTBEAT_GROUP_INFO_FLAG, READER_ENTITY_ID_OFFSET,
};
// `now_rtps_timestamp` stays crate-internal: the write() site
// (`dds::writer::runtime`) and the ECS close path (`dds::writer::coherent`)
// capture it once and pass it into the `_ts` builders above; no
// out-of-crate consumer needs a raw clock read.
#[cfg(feature = "security")]
pub(crate) use packet::encapsulate_serialized_payload;
pub(crate) use packet::now_rtps_timestamp;

#[cfg(test)]
mod tests;
