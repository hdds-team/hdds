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
    pub const PID_OWNERSHIP_STRENGTH: u16 = 0x0006;
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
pub fn write_deadline(
    qos: Option<&super::super::QosProfile>,
    buf: &mut [u8],
    offset: &mut usize,
) -> EncodeResult<()> {
    if *offset + 12 > buf.len() {
        return Err(EncodeError::BufferTooSmall);
    }

    let (seconds, fraction) = if let Some(q) = qos {
        // RTPS v2.5 sec. 9.3.2: Duration_t fraction is 2^-32 seconds, not nanoseconds.
        // `try_from` saturates at u32::MAX if nsec violates the Duration_t
        // invariant (< 10^9); for well-formed input the full value fits.
        let frac = u32::try_from(((q.deadline_period_nsec as u64) << 32) / 1_000_000_000)
            .unwrap_or(u32::MAX);
        (q.deadline_period_sec, frac)
    } else {
        (0x7FFF_FFFFu32, 0xFFFF_FFFFu32)
    };

    buf[*offset..*offset + 2].copy_from_slice(&pids::PID_DEADLINE.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&8u16.to_le_bytes());
    buf[*offset + 4..*offset + 8].copy_from_slice(&seconds.to_le_bytes());
    buf[*offset + 8..*offset + 12].copy_from_slice(&fraction.to_le_bytes());
    *offset += 12;

    Ok(())
}

/// Write PID_OWNERSHIP (0x001f) - 4 bytes.
///
/// Format: kind (u32).
/// Default: SHARED (kind=0).
#[allow(dead_code)] // Part of FastDDS SEDP QoS encoding API for future interoperability
pub fn write_ownership(
    qos: Option<&super::super::QosProfile>,
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

/// Write PID_OWNERSHIP_STRENGTH (0x0006) - 4 bytes.
///
/// Format: value (i32).
/// Default: 0. Only meaningful when ownership kind is EXCLUSIVE.
pub fn write_ownership_strength(
    qos: Option<&super::super::QosProfile>,
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
