// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! RTPS submessage classification handlers.
//!
//! This module contains specialized handler functions for each RTPS submessage type
//! according to DDS-RTPS v2.3 Sec.8.3. Each function extracts and validates the specific
//! submessage structure and returns the appropriate PacketKind classification.
//!
//! # Module Organization
//!
//! - `info` - INFO_TS and INFO_DST submessages (context for subsequent submessages)
//! - `data` - DATA and DATA_FRAG submessages (user data and discovery)
//! - `control` - HEARTBEAT, ACKNACK, GAP submessages (reliable protocol control)
//! - `vendor` - RTI proprietary and unknown submessages

mod control;
mod data;
mod info;
mod vendor;

// Re-export all handler functions for parent module
pub(super) use control::{
    classify_acknack, classify_gap, classify_heartbeat, classify_heartbeat_frag, classify_nack_frag,
};
pub(super) use data::{calculate_payload_offset, classify_data, classify_data_frag};
pub(super) use info::{classify_info_dst, classify_info_ts};
pub(super) use vendor::{
    classify_eprosima_proprietary, classify_rti_proprietary, classify_unknown,
};
