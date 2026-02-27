// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! RTPS control submessage handlers (HEARTBEAT, ACKNACK, GAP).
//!
//! Control submessages manage reliable communication protocol:
//! - HEARTBEAT: Announces available sequence numbers
//! - ACKNACK: Acknowledges received data and requests missing sequences
//! - GAP: Indicates permanently missing sequence numbers

use super::super::super::PacketKind;

/// Handle HEARTBEAT submessage.
///
/// RTPS v2.5 Sec.8.3.7.5: Writer announces available sequence number range.
///
/// # Returns
/// PacketKind::Heartbeat
pub(in crate::core::discovery::multicast::classifier) fn classify_heartbeat() -> PacketKind {
    crate::trace_fn!("classify_heartbeat");
    PacketKind::Heartbeat
}

/// Handle ACKNACK submessage.
///
/// RTPS v2.5 Sec.8.3.7.1: Reader acknowledges received data and requests retransmissions.
///
/// # Returns
/// PacketKind::AckNack
pub(in crate::core::discovery::multicast::classifier) fn classify_acknack() -> PacketKind {
    crate::trace_fn!("classify_acknack");
    PacketKind::AckNack
}

/// Handle GAP submessage.
///
/// RTPS v2.5 Sec.8.3.7.4: Writer indicates sequence numbers that will not be sent.
///
/// # Returns
/// PacketKind::Gap
pub(in crate::core::discovery::multicast::classifier) fn classify_gap() -> PacketKind {
    crate::trace_fn!("classify_gap");
    PacketKind::Gap
}

/// Handle NACK_FRAG submessage.
///
/// RTPS v2.5 Sec.8.3.7.5: Reader requests retransmission of specific fragments.
///
/// # Returns
/// PacketKind::NackFrag
pub(in crate::core::discovery::multicast::classifier) fn classify_nack_frag() -> PacketKind {
    crate::trace_fn!("classify_nack_frag");
    PacketKind::NackFrag
}

/// Handle HEARTBEAT_FRAG submessage.
///
/// RTPS v2.5 Sec.8.3.7.6: Writer announces fragment availability for reliable fragmented data.
///
/// # Returns
/// PacketKind::HeartbeatFrag
pub(in crate::core::discovery::multicast::classifier) fn classify_heartbeat_frag() -> PacketKind {
    crate::trace_fn!("classify_heartbeat_frag");
    PacketKind::HeartbeatFrag
}
