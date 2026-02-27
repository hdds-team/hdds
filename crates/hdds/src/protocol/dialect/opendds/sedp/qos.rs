// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! OpenDDS SEDP QoS PID Writers
//!
//! Standard QoS policy PIDs for OpenDDS interoperability.

use crate::protocol::dialect::error::{EncodeError, EncodeResult};
use crate::protocol::dialect::QosProfile;

/// PID constants for QoS
mod pids {
    pub const PID_DURABILITY: u16 = 0x001d;
    pub const PID_RELIABILITY: u16 = 0x001a;
    pub const PID_HISTORY: u16 = 0x0040;
    pub const PID_DEADLINE: u16 = 0x0023;
    pub const PID_LIVELINESS: u16 = 0x001b;
    pub const PID_OWNERSHIP: u16 = 0x001f;
}

/// Duration constant for infinite time (little-endian)
/// RTPS Duration_t: { int32_t seconds, uint32_t fraction }
/// Infinite = { 0x7FFFFFFF, 0xFFFFFFFF } in little-endian
const DURATION_INFINITE: [u8; 8] = [0xFF, 0xFF, 0xFF, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF];

/// Write PID_DURABILITY (0x001d) - 4 bytes
pub fn write_durability(
    qos: Option<&QosProfile>,
    buf: &mut [u8],
    offset: &mut usize,
) -> EncodeResult<()> {
    if *offset + 8 > buf.len() {
        return Err(EncodeError::BufferTooSmall);
    }

    let durability_kind = qos.map(|q| q.durability_kind).unwrap_or(0); // 0 = VOLATILE

    buf[*offset..*offset + 2].copy_from_slice(&pids::PID_DURABILITY.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&4u16.to_le_bytes());
    buf[*offset + 4..*offset + 8].copy_from_slice(&durability_kind.to_le_bytes());
    *offset += 8;

    Ok(())
}

/// Write PID_RELIABILITY (0x001a) - 12 bytes
pub fn write_reliability(
    qos: Option<&QosProfile>,
    buf: &mut [u8],
    offset: &mut usize,
) -> EncodeResult<()> {
    if *offset + 16 > buf.len() {
        return Err(EncodeError::BufferTooSmall);
    }

    let reliability_kind = qos.map(|q| q.reliability_kind).unwrap_or(1); // 1 = BEST_EFFORT

    buf[*offset..*offset + 2].copy_from_slice(&pids::PID_RELIABILITY.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&12u16.to_le_bytes());
    buf[*offset + 4..*offset + 8].copy_from_slice(&reliability_kind.to_le_bytes());
    // max_blocking_time: infinite (for RELIABLE)
    buf[*offset + 8..*offset + 16].copy_from_slice(&DURATION_INFINITE);
    *offset += 16;

    Ok(())
}

/// Write PID_HISTORY (0x0040) - 8 bytes
pub fn write_history(
    qos: Option<&QosProfile>,
    buf: &mut [u8],
    offset: &mut usize,
) -> EncodeResult<()> {
    if *offset + 12 > buf.len() {
        return Err(EncodeError::BufferTooSmall);
    }

    let history_kind = qos.map(|q| q.history_kind).unwrap_or(0); // 0 = KEEP_LAST
    let history_depth = qos.map(|q| q.history_depth).unwrap_or(1);

    buf[*offset..*offset + 2].copy_from_slice(&pids::PID_HISTORY.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&8u16.to_le_bytes());
    buf[*offset + 4..*offset + 8].copy_from_slice(&history_kind.to_le_bytes());
    buf[*offset + 8..*offset + 12].copy_from_slice(&history_depth.to_le_bytes());
    *offset += 12;

    Ok(())
}

/// Write PID_DEADLINE (0x0023) - 8 bytes (Duration_t)
pub fn write_deadline(buf: &mut [u8], offset: &mut usize) -> EncodeResult<()> {
    if *offset + 12 > buf.len() {
        return Err(EncodeError::BufferTooSmall);
    }

    buf[*offset..*offset + 2].copy_from_slice(&pids::PID_DEADLINE.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&8u16.to_le_bytes());
    buf[*offset + 4..*offset + 12].copy_from_slice(&DURATION_INFINITE);
    *offset += 12;

    Ok(())
}

/// Write PID_LIVELINESS (0x001b) - 12 bytes
pub fn write_liveliness(buf: &mut [u8], offset: &mut usize) -> EncodeResult<()> {
    if *offset + 16 > buf.len() {
        return Err(EncodeError::BufferTooSmall);
    }

    buf[*offset..*offset + 2].copy_from_slice(&pids::PID_LIVELINESS.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&12u16.to_le_bytes());
    // AUTOMATIC liveliness
    buf[*offset + 4..*offset + 8].copy_from_slice(&0u32.to_le_bytes());
    // lease_duration: infinite
    buf[*offset + 8..*offset + 16].copy_from_slice(&DURATION_INFINITE);
    *offset += 16;

    Ok(())
}

/// Write PID_OWNERSHIP (0x001f) - 4 bytes
pub fn write_ownership(buf: &mut [u8], offset: &mut usize) -> EncodeResult<()> {
    if *offset + 8 > buf.len() {
        return Err(EncodeError::BufferTooSmall);
    }

    buf[*offset..*offset + 2].copy_from_slice(&pids::PID_OWNERSHIP.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&4u16.to_le_bytes());
    // SHARED ownership
    buf[*offset + 4..*offset + 8].copy_from_slice(&0u32.to_le_bytes());
    *offset += 8;

    Ok(())
}
