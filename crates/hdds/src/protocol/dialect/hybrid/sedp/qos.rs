// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Hybrid SEDP QoS Policy PID Writers
//!
//! Full set of standard QoS policies for maximum compatibility.

use crate::protocol::dialect::error::{EncodeError, EncodeResult};
use crate::protocol::dialect::QosProfile;

/// PID constants for QoS policies
// These constants define RTPS PID values for hybrid SEDP QoS encoding.
// Used by the write_* functions below for interoperability.
mod pids {
    pub const PID_RELIABILITY: u16 = 0x001a;
    pub const PID_DURABILITY: u16 = 0x001d;
    pub const PID_HISTORY: u16 = 0x0040;
    pub const PID_DEADLINE: u16 = 0x0023;
    pub const PID_OWNERSHIP: u16 = 0x001f;
    pub const PID_LIVELINESS: u16 = 0x001b;
}

/// Write PID_RELIABILITY (0x001a) - 12 bytes
#[allow(dead_code)] // Part of hybrid SEDP QoS encoding API for future interoperability
pub fn write_reliability(
    qos: Option<&QosProfile>,
    buf: &mut [u8],
    offset: &mut usize,
) -> EncodeResult<()> {
    if *offset + 16 > buf.len() {
        return Err(EncodeError::BufferTooSmall);
    }

    // Default: RELIABLE for conservative interop
    let kind = qos.map(|q| q.reliability_kind).unwrap_or(2);

    buf[*offset..*offset + 2].copy_from_slice(&pids::PID_RELIABILITY.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&12u16.to_le_bytes());
    buf[*offset + 4..*offset + 8].copy_from_slice(&kind.to_le_bytes());
    buf[*offset + 8..*offset + 12].copy_from_slice(&0u32.to_le_bytes()); // max_blocking_time.sec
    buf[*offset + 12..*offset + 16].copy_from_slice(&100_000_000u32.to_le_bytes()); // 100ms
    *offset += 16;

    Ok(())
}

/// Write PID_DURABILITY (0x001d) - 4 bytes
#[allow(dead_code)] // Part of hybrid SEDP QoS encoding API for future interoperability
pub fn write_durability(
    qos: Option<&QosProfile>,
    buf: &mut [u8],
    offset: &mut usize,
) -> EncodeResult<()> {
    if *offset + 8 > buf.len() {
        return Err(EncodeError::BufferTooSmall);
    }

    // Default: VOLATILE
    let kind = qos.map(|q| q.durability_kind).unwrap_or(0);

    buf[*offset..*offset + 2].copy_from_slice(&pids::PID_DURABILITY.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&4u16.to_le_bytes());
    buf[*offset + 4..*offset + 8].copy_from_slice(&kind.to_le_bytes());
    *offset += 8;

    Ok(())
}

/// Write PID_HISTORY (0x0040) - 8 bytes
#[allow(dead_code)] // Part of hybrid SEDP QoS encoding API for future interoperability
pub fn write_history(
    qos: Option<&QosProfile>,
    buf: &mut [u8],
    offset: &mut usize,
) -> EncodeResult<()> {
    if *offset + 12 > buf.len() {
        return Err(EncodeError::BufferTooSmall);
    }

    // Default: KEEP_LAST(1) - conservative
    let (kind, depth) = qos
        .map(|q| (q.history_kind, q.history_depth))
        .unwrap_or((0, 1));

    buf[*offset..*offset + 2].copy_from_slice(&pids::PID_HISTORY.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&8u16.to_le_bytes());
    buf[*offset + 4..*offset + 8].copy_from_slice(&kind.to_le_bytes());
    buf[*offset + 8..*offset + 12].copy_from_slice(&depth.to_le_bytes());
    *offset += 12;

    Ok(())
}

/// Write PID_DEADLINE (0x0023) - 8 bytes
#[allow(dead_code)] // Part of hybrid SEDP QoS encoding API for future interoperability
pub fn write_deadline(buf: &mut [u8], offset: &mut usize) -> EncodeResult<()> {
    if *offset + 12 > buf.len() {
        return Err(EncodeError::BufferTooSmall);
    }

    // DDS Duration_t INFINITE = { 0x7FFFFFFF, 0xFFFFFFFF }
    buf[*offset..*offset + 2].copy_from_slice(&pids::PID_DEADLINE.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&8u16.to_le_bytes());
    buf[*offset + 4..*offset + 8].copy_from_slice(&0x7FFFFFFFu32.to_le_bytes()); // INFINITE sec
    buf[*offset + 8..*offset + 12].copy_from_slice(&0xFFFFFFFFu32.to_le_bytes()); // INFINITE nanosec
    *offset += 12;

    Ok(())
}

/// Write PID_OWNERSHIP (0x001f) - 4 bytes
#[allow(dead_code)] // Part of hybrid SEDP QoS encoding API for future interoperability
pub fn write_ownership(buf: &mut [u8], offset: &mut usize) -> EncodeResult<()> {
    if *offset + 8 > buf.len() {
        return Err(EncodeError::BufferTooSmall);
    }

    buf[*offset..*offset + 2].copy_from_slice(&pids::PID_OWNERSHIP.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&4u16.to_le_bytes());
    buf[*offset + 4..*offset + 8].copy_from_slice(&0u32.to_le_bytes()); // SHARED
    *offset += 8;

    Ok(())
}

/// Write PID_LIVELINESS (0x001b) - 12 bytes
#[allow(dead_code)] // Part of hybrid SEDP QoS encoding API for future interoperability
pub fn write_liveliness(buf: &mut [u8], offset: &mut usize) -> EncodeResult<()> {
    if *offset + 16 > buf.len() {
        return Err(EncodeError::BufferTooSmall);
    }

    // DDS Duration_t INFINITE = { 0x7FFFFFFF, 0xFFFFFFFF }
    buf[*offset..*offset + 2].copy_from_slice(&pids::PID_LIVELINESS.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&12u16.to_le_bytes());
    buf[*offset + 4..*offset + 8].copy_from_slice(&0u32.to_le_bytes()); // AUTOMATIC
    buf[*offset + 8..*offset + 12].copy_from_slice(&0x7FFFFFFFu32.to_le_bytes()); // INFINITE sec
    buf[*offset + 12..*offset + 16].copy_from_slice(&0xFFFFFFFFu32.to_le_bytes()); // INFINITE nanosec
    *offset += 16;

    Ok(())
}
