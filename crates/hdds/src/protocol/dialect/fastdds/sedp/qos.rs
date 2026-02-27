// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! FastDDS SEDP QoS Policy PID Writers
//!
//! Handles encoding of DDS QoS policy PIDs:
//! - PID_RELIABILITY (0x001a)
//! - PID_DURABILITY (0x001d)
//! - PID_HISTORY (0x0040)
//! - PID_DEADLINE (0x0023)
//! - PID_OWNERSHIP (0x001f)
//! - PID_LIVELINESS (0x001b)

use crate::protocol::dialect::error::{EncodeError, EncodeResult};
use crate::protocol::dialect::QosProfile;

/// PID constants for QoS policies
// These constants define RTPS PID values for FastDDS SEDP QoS encoding.
// Used by the write_* functions below for interoperability.
mod pids {
    pub const PID_RELIABILITY: u16 = 0x001a;
    pub const PID_DURABILITY: u16 = 0x001d;
    pub const PID_HISTORY: u16 = 0x0040;
    pub const PID_DEADLINE: u16 = 0x0023;
    pub const PID_OWNERSHIP: u16 = 0x001f;
    pub const PID_LIVELINESS: u16 = 0x001b;
}

/// Write PID_RELIABILITY (0x001a) - 12 bytes.
///
/// Format: kind (u32) + max_blocking_time (Duration_t = 2xu32).
/// DDS v1.4 Section 2.2.3.12: BEST_EFFORT=1, RELIABLE=2.
#[allow(dead_code)] // Part of FastDDS SEDP QoS encoding API for future interoperability
pub fn write_reliability(
    qos: Option<&QosProfile>,
    buf: &mut [u8],
    offset: &mut usize,
) -> EncodeResult<()> {
    if *offset + 16 > buf.len() {
        return Err(EncodeError::BufferTooSmall);
    }

    let kind = qos.map(|q| q.reliability_kind).unwrap_or(2); // Default: RELIABLE

    buf[*offset..*offset + 2].copy_from_slice(&pids::PID_RELIABILITY.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&12u16.to_le_bytes());
    buf[*offset + 4..*offset + 8].copy_from_slice(&kind.to_le_bytes());
    buf[*offset + 8..*offset + 12].copy_from_slice(&0u32.to_le_bytes()); // max_blocking_time.sec
    buf[*offset + 12..*offset + 16].copy_from_slice(&100_000_000u32.to_le_bytes()); // 100ms nanosec
    *offset += 16;

    Ok(())
}

/// Write PID_DURABILITY (0x001d) - 4 bytes.
///
/// Format: kind (u32).
/// DDS v1.4 Section 2.2.3.4: VOLATILE=0, TRANSIENT_LOCAL=1, TRANSIENT=2, PERSISTENT=3.
#[allow(dead_code)] // Part of FastDDS SEDP QoS encoding API for future interoperability
pub fn write_durability(
    qos: Option<&QosProfile>,
    buf: &mut [u8],
    offset: &mut usize,
) -> EncodeResult<()> {
    if *offset + 8 > buf.len() {
        return Err(EncodeError::BufferTooSmall);
    }

    let kind = qos.map(|q| q.durability_kind).unwrap_or(0); // Default: VOLATILE

    buf[*offset..*offset + 2].copy_from_slice(&pids::PID_DURABILITY.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&4u16.to_le_bytes());
    buf[*offset + 4..*offset + 8].copy_from_slice(&kind.to_le_bytes());
    *offset += 8;

    Ok(())
}

/// Write PID_HISTORY (0x0040) - 8 bytes.
///
/// Format: kind (u32) + depth (u32).
/// DDS v1.4 Section 2.2.3.9: KEEP_LAST=0, KEEP_ALL=1.
#[allow(dead_code)] // Part of FastDDS SEDP QoS encoding API for future interoperability
pub fn write_history(
    qos: Option<&QosProfile>,
    buf: &mut [u8],
    offset: &mut usize,
) -> EncodeResult<()> {
    if *offset + 12 > buf.len() {
        return Err(EncodeError::BufferTooSmall);
    }

    let (kind, depth) = qos
        .map(|q| (q.history_kind, q.history_depth))
        .unwrap_or((0, 1)); // Default: KEEP_LAST(1)

    buf[*offset..*offset + 2].copy_from_slice(&pids::PID_HISTORY.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&8u16.to_le_bytes());
    buf[*offset + 4..*offset + 8].copy_from_slice(&kind.to_le_bytes());
    buf[*offset + 8..*offset + 12].copy_from_slice(&depth.to_le_bytes());
    *offset += 12;

    Ok(())
}

/// Write PID_DEADLINE (0x0023) - 8 bytes.
///
/// Format: period (Duration_t = 2xu32).
/// Default: INFINITE (DDS spec: seconds=0x7FFFFFFF, nanosec=0xFFFFFFFF).
#[allow(dead_code)] // Part of FastDDS SEDP QoS encoding API for future interoperability
pub fn write_deadline(buf: &mut [u8], offset: &mut usize) -> EncodeResult<()> {
    if *offset + 12 > buf.len() {
        return Err(EncodeError::BufferTooSmall);
    }

    // DDS Duration_t INFINITE = { 0x7FFFFFFF, 0xFFFFFFFF }
    buf[*offset..*offset + 2].copy_from_slice(&pids::PID_DEADLINE.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&8u16.to_le_bytes());
    buf[*offset + 4..*offset + 8].copy_from_slice(&0x7FFFFFFFu32.to_le_bytes()); // INFINITE sec
    buf[*offset + 8..*offset + 12].copy_from_slice(&0xFFFFFFFFu32.to_le_bytes()); // INFINITE nsec
    *offset += 12;

    Ok(())
}

/// Write PID_OWNERSHIP (0x001f) - 4 bytes.
///
/// Format: kind (u32).
/// Default: SHARED (kind=0).
#[allow(dead_code)] // Part of FastDDS SEDP QoS encoding API for future interoperability
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

/// Write PID_LIVELINESS (0x001b) - 12 bytes.
///
/// Format: kind (u32) + lease_duration (Duration_t = 2xu32).
/// Default: AUTOMATIC (kind=0), lease_duration=INFINITE.
#[allow(dead_code)] // Part of FastDDS SEDP QoS encoding API for future interoperability
pub fn write_liveliness(buf: &mut [u8], offset: &mut usize) -> EncodeResult<()> {
    if *offset + 16 > buf.len() {
        return Err(EncodeError::BufferTooSmall);
    }

    // DDS Duration_t INFINITE = { 0x7FFFFFFF, 0xFFFFFFFF }
    buf[*offset..*offset + 2].copy_from_slice(&pids::PID_LIVELINESS.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&12u16.to_le_bytes());
    buf[*offset + 4..*offset + 8].copy_from_slice(&0u32.to_le_bytes()); // AUTOMATIC
    buf[*offset + 8..*offset + 12].copy_from_slice(&0x7FFFFFFFu32.to_le_bytes()); // INFINITE sec
    buf[*offset + 12..*offset + 16].copy_from_slice(&0xFFFFFFFFu32.to_le_bytes()); // INFINITE nsec
    *offset += 16;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reliability_best_effort() {
        let qos = QosProfile {
            reliability_kind: 1, // BEST_EFFORT
            ..Default::default()
        };
        let mut buf = [0u8; 32];
        let mut offset = 0;

        write_reliability(Some(&qos), &mut buf, &mut offset).expect("write_reliability failed");

        assert_eq!(offset, 16);
        // Kind = 1 (BEST_EFFORT)
        assert_eq!(u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]), 1);
    }

    #[test]
    fn test_durability_transient_local() {
        let qos = QosProfile {
            durability_kind: 1, // TRANSIENT_LOCAL
            ..Default::default()
        };
        let mut buf = [0u8; 16];
        let mut offset = 0;

        write_durability(Some(&qos), &mut buf, &mut offset).expect("write_durability failed");

        assert_eq!(offset, 8);
        assert_eq!(u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]), 1);
    }

    #[test]
    fn test_history_keep_all() {
        let qos = QosProfile {
            history_kind: 1, // KEEP_ALL
            history_depth: 0,
            ..Default::default()
        };
        let mut buf = [0u8; 16];
        let mut offset = 0;

        write_history(Some(&qos), &mut buf, &mut offset).expect("write_history failed");

        assert_eq!(offset, 12);
        // Kind = 1 (KEEP_ALL)
        assert_eq!(u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]), 1);
    }
}
