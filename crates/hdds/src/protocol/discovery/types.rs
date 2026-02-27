// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use crate::core::discovery::GUID;
use crate::xtypes::CompleteTypeObject;
use std::net::SocketAddr;

/// Parse error types for SPDP/SEDP helpers.
#[derive(Debug, PartialEq, Eq)]
pub enum ParseError {
    TruncatedData,
    InvalidEncapsulation,
    InvalidFormat,
    BufferTooSmall,
    EncodingError,
}

/// SEDP (Simple Endpoint Discovery Protocol) parsed data.
#[derive(Debug, Clone)]
pub struct SedpData {
    pub topic_name: String,
    pub type_name: String,
    pub participant_guid: GUID, // v110: Added for PID_PARTICIPANT_GUID (0x0050) - FastDDS interop requirement
    pub endpoint_guid: GUID,
    pub qos_hash: u64,
    pub qos: Option<crate::dds::QoS>, // v60: Added to use actual QoS values instead of hardcoding!
    pub type_object: Option<CompleteTypeObject>,
    pub unicast_locators: Vec<SocketAddr>,
    /// User data for capability advertisement (e.g., SHM transport)
    /// Format for SHM: "shm=1;host_id=XXXXXXXX;v=1"
    pub user_data: Option<String>,
}
