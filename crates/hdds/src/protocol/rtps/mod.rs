// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! # Standard RTPS Submessage Encoders (OMG RTPS 2.3 Specification)
//!
//! This module contains **vendor-neutral** RTPS encoding logic per the OMG specification.
//! Dialect modules import from here - NEVER the reverse.
//!
//! If a vendor needs different encoding, they override in their dialect module.
//!
//! # ARCHITECTURAL CONSTRAINT
//!
//! ```text
//! ALLOWED:   dialect::* -> protocol::rtps::*
//! FORBIDDEN: protocol::rtps -> dialect::*
//! ```
//!
//! # Submessages
//!
//! - ACKNACK (0x06): Positive/negative acknowledgment
//! - HEARTBEAT (0x07): Writer liveliness and available sequences
//! - GAP (0x08): Irrelevant sequence numbers
//! - DATA (0x15): User data payload
//! - DATA_FRAG (0x16): Fragmented user data
//! - INFO_TS (0x09): Timestamp for subsequent submessages
//! - INFO_DST (0x0E): Destination GUID prefix
//!
//! # References
//!
//! - OMG RTPS 2.3 spec: Section 8.3.7 (Submessages)
//! - OMG RTPS 2.3 spec: Section 9.4.5 (SequenceNumberSet)

mod acknack;
mod data;
mod gap;
mod heartbeat;
mod info;
mod locator;

pub use acknack::{encode_acknack, encode_acknack_with_count, encode_acknack_with_final};
pub use data::{encode_data, encode_data_frag};
pub use gap::encode_gap;
pub use heartbeat::{encode_heartbeat, encode_heartbeat_final};
pub use info::{encode_info_dst, encode_info_ts};
pub use locator::{encode_multicast_locator, encode_unicast_locator};

/// Result type for RTPS encoding operations.
pub type RtpsEncodeResult<T> = Result<T, RtpsEncodeError>;

/// Errors that can occur during RTPS encoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RtpsEncodeError {
    /// Buffer is too small for the encoded data.
    BufferTooSmall,
    /// Invalid parameter provided.
    InvalidParameter(&'static str),
}

impl std::fmt::Display for RtpsEncodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BufferTooSmall => write!(f, "buffer too small for RTPS encoding"),
            Self::InvalidParameter(msg) => write!(f, "invalid parameter: {}", msg),
        }
    }
}

impl std::error::Error for RtpsEncodeError {}
