// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! RTPS Lite protocol implementation
//!
//! Minimal subset of RTPS v2.5 protocol for embedded environments.
//! Focuses on BEST_EFFORT QoS and unicast transport.

pub mod header;
pub mod submessages;
pub mod types;

// Re-exports
pub use header::RtpsHeader;
pub use submessages::{AckNack, Data, Heartbeat, Submessage, SubmessageKind};
pub use types::{EntityId, GuidPrefix, Locator, ProtocolVersion, SequenceNumber, VendorId, GUID};
