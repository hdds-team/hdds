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
    pub const PID_OWNERSHIP_STRENGTH: u16 = 0x0006;
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
    // RTPS v2.5 Sec.9.3.2 Duration_t: the endpoint's max_blocking_time, 100 ms
    // (DDS v1.4 Sec.2.2.3.14 default) for an endpoint that names none.
    let max_blocking_time = qos
        .and_then(|q| q.reliability_max_blocking_time)
        .unwrap_or(std::time::Duration::from_millis(100));
    buf[*offset + 8..*offset + 16]
        .copy_from_slice(&crate::protocol::dialect::duration_t_le(max_blocking_time));
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
    buf[*offset + 4..*offset + 8].copy_from_slice(&0x7FFF_FFFFu32.to_le_bytes()); // INFINITE sec
    buf[*offset + 8..*offset + 12].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // INFINITE nanosec
    *offset += 12;

    Ok(())
}

/// Write PID_OWNERSHIP (0x001f) - 4 bytes
#[allow(dead_code)] // Part of hybrid SEDP QoS encoding API for future interoperability
pub fn write_ownership(
    qos: Option<&QosProfile>,
    buf: &mut [u8],
    offset: &mut usize,
) -> EncodeResult<()> {
    if *offset + 8 > buf.len() {
        return Err(EncodeError::BufferTooSmall);
    }

    let kind = qos.map(|q| q.ownership_kind).unwrap_or(0);

    buf[*offset..*offset + 2].copy_from_slice(&pids::PID_OWNERSHIP.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&4u16.to_le_bytes());
    buf[*offset + 4..*offset + 8].copy_from_slice(&kind.to_le_bytes());
    *offset += 8;

    Ok(())
}

/// Write PID_OWNERSHIP_STRENGTH (0x0006) - 4 bytes
#[allow(dead_code)] // Part of hybrid SEDP QoS encoding API for future interoperability
pub fn write_ownership_strength(
    qos: Option<&QosProfile>,
    buf: &mut [u8],
    offset: &mut usize,
) -> EncodeResult<()> {
    if *offset + 8 > buf.len() {
        return Err(EncodeError::BufferTooSmall);
    }

    let strength = qos.map(|q| q.ownership_strength).unwrap_or(0);

    buf[*offset..*offset + 2].copy_from_slice(&pids::PID_OWNERSHIP_STRENGTH.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&4u16.to_le_bytes());
    buf[*offset + 4..*offset + 8].copy_from_slice(&strength.to_le_bytes());
    *offset += 8;

    Ok(())
}

#[cfg(test)]
mod max_blocking_time_tests {
    use super::*;

    /// PID_RELIABILITY carries the endpoint's max_blocking_time as an RTPS
    /// Duration_t (RTPS v2.5 Sec.9.3.2), 100 ms when it names none.
    #[test]
    fn reliability_announces_the_max_blocking_time() {
        for (named, sec, fraction) in [
            (
                Some(std::time::Duration::from_millis(1500)),
                1u32,
                0x8000_0000u32,
            ),
            (None, 0, 0x1999_999A),
        ] {
            let qos = QosProfile {
                reliability_kind: 2,
                reliability_max_blocking_time: named,
                ..Default::default()
            };
            let mut buf = [0u8; 32];
            let mut offset = 0;
            write_reliability(Some(&qos), &mut buf, &mut offset).expect("write_reliability");
            let word = |at: usize| u32::from_le_bytes(buf[at..at + 4].try_into().expect("4"));
            assert_eq!(
                (word(4), word(8), word(12)),
                (2, sec, fraction),
                "{named:?}"
            );
        }
    }
}
