// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! RTI SEDP QoS Policy PID Writers
//!
//!
//! Full QoS support for RTI interop including:
//! - PID_RELIABILITY (0x001a)
//! - PID_DURABILITY (0x001d)
//! - PID_HISTORY (0x0040)
//! - PID_DEADLINE (0x0023)
//! - PID_OWNERSHIP (0x001f)
//! - PID_LIVELINESS (0x001b)
//! - PID_TIME_BASED_FILTER (0x0004)
//! - PID_PARTITION (0x0029)
//! - PID_RESOURCE_LIMITS (0x0041)

use crate::protocol::dialect::error::{EncodeError, EncodeResult};
use crate::protocol::dialect::QosProfile;

/// PID constants for QoS policies
#[allow(dead_code)] // PIDs defined for completeness per DDS spec; not all used yet
mod pids {
    pub const PID_RELIABILITY: u16 = 0x001a;
    pub const PID_DURABILITY: u16 = 0x001d;
    pub const PID_DURABILITY_SERVICE: u16 = 0x001e;
    pub const PID_HISTORY: u16 = 0x0040;
    pub const PID_DEADLINE: u16 = 0x0023;
    pub const PID_LATENCY_BUDGET: u16 = 0x0027;
    pub const PID_OWNERSHIP: u16 = 0x001f;
    pub const PID_OWNERSHIP_STRENGTH: u16 = 0x0006;
    pub const PID_LIVELINESS: u16 = 0x001b;
    pub const PID_LIFESPAN: u16 = 0x002b;
    pub const PID_USER_DATA: u16 = 0x002c;
    pub const PID_DESTINATION_ORDER: u16 = 0x0025;
    pub const PID_PRESENTATION: u16 = 0x0021;
    pub const PID_TIME_BASED_FILTER: u16 = 0x0004;
    pub const PID_PARTITION: u16 = 0x0029;
    pub const PID_TOPIC_DATA: u16 = 0x002e;
    pub const PID_GROUP_DATA: u16 = 0x002d;
    pub const PID_RESOURCE_LIMITS: u16 = 0x0041;
}

/// Write PID_RELIABILITY (0x001a) - 12 bytes
///
/// Wire format for reliability_kind:
/// - 1 = BEST_EFFORT (DDS kind 0)
/// - 2 = RELIABLE (DDS kind 1)
pub fn write_reliability(
    qos: Option<&QosProfile>,
    buf: &mut [u8],
    offset: &mut usize,
) -> EncodeResult<()> {
    if *offset + 16 > buf.len() {
        return Err(EncodeError::BufferTooSmall);
    }

    // Use QoS from endpoint if provided, otherwise default to RELIABLE (2) for discovery endpoints.
    // QosProfile.reliability_kind is already in wire format: 1=BEST_EFFORT, 2=RELIABLE
    let kind: u32 = qos.map(|q| q.reliability_kind).unwrap_or(2);

    buf[*offset..*offset + 2].copy_from_slice(&pids::PID_RELIABILITY.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&12u16.to_le_bytes());
    buf[*offset + 4..*offset + 8].copy_from_slice(&kind.to_le_bytes());
    buf[*offset + 8..*offset + 12].copy_from_slice(&0u32.to_le_bytes()); // max_blocking_time.sec
                                                                         // RTPS v2.5 §9.3.2: fraction is 2^-32 sec. 100 ms = 0x1999_999A.
    buf[*offset + 12..*offset + 16].copy_from_slice(&0x1999_999Au32.to_le_bytes());
    *offset += 16;

    Ok(())
}

/// Write PID_DURABILITY (0x001d) - 4 bytes
///
/// Wire format for durability_kind:
/// - 0 = VOLATILE
/// - 1 = TRANSIENT_LOCAL
/// - 2 = TRANSIENT
/// - 3 = PERSISTENT
pub fn write_durability(
    qos: Option<&QosProfile>,
    buf: &mut [u8],
    offset: &mut usize,
) -> EncodeResult<()> {
    if *offset + 8 > buf.len() {
        return Err(EncodeError::BufferTooSmall);
    }

    // Use QoS from endpoint if provided, otherwise default to TRANSIENT_LOCAL (1) for discovery endpoints.
    // QosProfile.durability_kind is already in wire format: 0=VOLATILE, 1=TRANSIENT_LOCAL
    let kind: u32 = qos.map(|q| q.durability_kind).unwrap_or(1);

    buf[*offset..*offset + 2].copy_from_slice(&pids::PID_DURABILITY.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&4u16.to_le_bytes());
    buf[*offset + 4..*offset + 8].copy_from_slice(&kind.to_le_bytes());
    *offset += 8;

    Ok(())
}

/// Write PID_HISTORY (0x0040) - 8 bytes
#[allow(dead_code)] // Reserved for future QoS policy support
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
        .unwrap_or((0, 1)); // Default: KEEP_LAST(1) for RTI sensor profile

    buf[*offset..*offset + 2].copy_from_slice(&pids::PID_HISTORY.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&8u16.to_le_bytes());
    buf[*offset + 4..*offset + 8].copy_from_slice(&kind.to_le_bytes());
    buf[*offset + 8..*offset + 12].copy_from_slice(&depth.to_le_bytes());
    *offset += 12;

    Ok(())
}

/// Write PID_DEADLINE (0x0023) - 8 bytes
pub fn write_deadline(
    qos: Option<&super::super::QosProfile>,
    buf: &mut [u8],
    offset: &mut usize,
) -> EncodeResult<()> {
    if *offset + 12 > buf.len() {
        return Err(EncodeError::BufferTooSmall);
    }

    let (seconds, fraction) = if let Some(q) = qos {
        // RTPS v2.5 §9.3.2: Duration_t fraction is 2^-32 seconds, not nanoseconds.
        // For a well-formed Duration_t the nsec portion is < 10^9, so the
        // shifted division stays in u32 range; `try_from` guards the
        // invariant against malformed QoS input.
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

/// Write PID_OWNERSHIP (0x001f) - 4 bytes
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

/// Write PID_OWNERSHIP_STRENGTH (0x0006) - 4 bytes
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

/// Write PID_LIVELINESS (0x001b) - 12 bytes
pub fn write_liveliness(buf: &mut [u8], offset: &mut usize) -> EncodeResult<()> {
    if *offset + 16 > buf.len() {
        return Err(EncodeError::BufferTooSmall);
    }

    // DDS Duration_t INFINITE = { 0x7FFFFFFF, 0xFFFFFFFF }
    buf[*offset..*offset + 2].copy_from_slice(&pids::PID_LIVELINESS.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&12u16.to_le_bytes());
    buf[*offset + 4..*offset + 8].copy_from_slice(&0u32.to_le_bytes()); // AUTOMATIC
    buf[*offset + 8..*offset + 12].copy_from_slice(&0x7FFF_FFFFu32.to_le_bytes()); // INFINITE sec
    buf[*offset + 12..*offset + 16].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // INFINITE nsec
    *offset += 16;

    Ok(())
}

/// Write PID_TIME_BASED_FILTER (0x0004) - 8 bytes
#[allow(dead_code)] // Reserved for future QoS policy support
pub fn write_time_based_filter(buf: &mut [u8], offset: &mut usize) -> EncodeResult<()> {
    if *offset + 12 > buf.len() {
        return Err(EncodeError::BufferTooSmall);
    }

    buf[*offset..*offset + 2].copy_from_slice(&pids::PID_TIME_BASED_FILTER.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&8u16.to_le_bytes());
    buf[*offset + 4..*offset + 8].copy_from_slice(&0u32.to_le_bytes()); // no filter
    buf[*offset + 8..*offset + 12].copy_from_slice(&0u32.to_le_bytes());
    *offset += 12;

    Ok(())
}

/// Write PID_PARTITION (0x0029) - sequence of partition name strings.
pub fn write_partition(
    qos: Option<&QosProfile>,
    buf: &mut [u8],
    offset: &mut usize,
) -> EncodeResult<()> {
    let names = qos.map(|q| q.partition_names.as_slice()).unwrap_or(&[]);

    if names.is_empty() {
        if *offset + 8 > buf.len() {
            return Err(EncodeError::BufferTooSmall);
        }
        buf[*offset..*offset + 2].copy_from_slice(&pids::PID_PARTITION.to_le_bytes());
        buf[*offset + 2..*offset + 4].copy_from_slice(&4u16.to_le_bytes());
        buf[*offset + 4..*offset + 8].copy_from_slice(&0u32.to_le_bytes());
        *offset += 8;
        return Ok(());
    }

    // Calculate total payload size: seq_len (4) + for each string: str_len (4) + chars + NUL + pad
    let mut payload_size: usize = 4;
    for name in names {
        let str_len = name.len() + 1;
        let padded = (str_len + 3) & !3;
        payload_size += 4 + padded;
    }

    if *offset + 4 + payload_size > buf.len() {
        return Err(EncodeError::BufferTooSmall);
    }

    buf[*offset..*offset + 2].copy_from_slice(&pids::PID_PARTITION.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&(payload_size as u16).to_le_bytes());
    *offset += 4;

    buf[*offset..*offset + 4].copy_from_slice(&(names.len() as u32).to_le_bytes());
    *offset += 4;

    for name in names {
        let str_len = (name.len() + 1) as u32;
        buf[*offset..*offset + 4].copy_from_slice(&str_len.to_le_bytes());
        *offset += 4;
        buf[*offset..*offset + name.len()].copy_from_slice(name.as_bytes());
        *offset += name.len();
        buf[*offset] = 0;
        *offset += 1;
        let pad = (4 - (name.len() + 1) % 4) % 4;
        for i in 0..pad {
            buf[*offset + i] = 0;
        }
        *offset += pad;
    }

    Ok(())
}

/// Write PID_RESOURCE_LIMITS (0x0041) - 12 bytes
#[allow(dead_code)] // Reserved for future QoS policy support
pub fn write_resource_limits(buf: &mut [u8], offset: &mut usize) -> EncodeResult<()> {
    if *offset + 16 > buf.len() {
        return Err(EncodeError::BufferTooSmall);
    }

    buf[*offset..*offset + 2].copy_from_slice(&pids::PID_RESOURCE_LIMITS.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&12u16.to_le_bytes());
    buf[*offset + 4..*offset + 8].copy_from_slice(&1000u32.to_le_bytes()); // max_samples
    buf[*offset + 8..*offset + 12].copy_from_slice(&100u32.to_le_bytes()); // max_instances
    buf[*offset + 12..*offset + 16].copy_from_slice(&100u32.to_le_bytes()); // max_samples_per_instance
    *offset += 16;

    Ok(())
}

/// Write PID_DURABILITY_SERVICE (0x001e) - 28 bytes
/// Matches FastDDS format: lease_duration, history kind, history depth, max samples/instances
pub fn write_durability_service(buf: &mut [u8], offset: &mut usize) -> EncodeResult<()> {
    if *offset + 32 > buf.len() {
        return Err(EncodeError::BufferTooSmall);
    }

    buf[*offset..*offset + 2].copy_from_slice(&pids::PID_DURABILITY_SERVICE.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&28u16.to_le_bytes());
    // lease_duration = 0 sec
    buf[*offset + 4..*offset + 8].copy_from_slice(&0u32.to_le_bytes()); // seconds
    buf[*offset + 8..*offset + 12].copy_from_slice(&0u32.to_le_bytes()); // fraction
                                                                         // History Kind = KEEP_LAST (0)
    buf[*offset + 12..*offset + 16].copy_from_slice(&0u32.to_le_bytes());
    // History Depth = 1
    buf[*offset + 16..*offset + 20].copy_from_slice(&1u32.to_le_bytes());
    // Max Samples = -1 (unlimited)
    buf[*offset + 20..*offset + 24].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    // Max Instances = -1 (unlimited)
    buf[*offset + 24..*offset + 28].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    // Max Samples Per Instance = -1 (unlimited)
    buf[*offset + 28..*offset + 32].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    *offset += 32;

    Ok(())
}

/// Write PID_LATENCY_BUDGET (0x0027) - 8 bytes
pub fn write_latency_budget(buf: &mut [u8], offset: &mut usize) -> EncodeResult<()> {
    if *offset + 12 > buf.len() {
        return Err(EncodeError::BufferTooSmall);
    }

    buf[*offset..*offset + 2].copy_from_slice(&pids::PID_LATENCY_BUDGET.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&8u16.to_le_bytes());
    // Duration = 0 sec
    buf[*offset + 4..*offset + 8].copy_from_slice(&0u32.to_le_bytes()); // seconds
    buf[*offset + 8..*offset + 12].copy_from_slice(&0u32.to_le_bytes()); // fraction
    *offset += 12;

    Ok(())
}

/// Write PID_LIFESPAN (0x002b) - 8 bytes
pub fn write_lifespan(
    qos: Option<&QosProfile>,
    buf: &mut [u8],
    offset: &mut usize,
) -> EncodeResult<()> {
    if *offset + 12 > buf.len() {
        return Err(EncodeError::BufferTooSmall);
    }

    let (seconds, fraction) = if let Some(q) = qos {
        if q.lifespan_sec == 0x7FFF_FFFF && q.lifespan_nsec == 0xFFFF_FFFF {
            (0x7FFF_FFFFu32, 0xFFFF_FFFFu32)
        } else {
            // RTPS v2.5 §9.3.2: Duration_t fraction is 2^-32 seconds, not nanoseconds.
            // `try_from` preserves the value when the Duration_t invariant
            // `nsec < 10^9` holds, saturates at u32::MAX otherwise.
            let frac =
                u32::try_from(((q.lifespan_nsec as u64) << 32) / 1_000_000_000).unwrap_or(u32::MAX);
            (q.lifespan_sec, frac)
        }
    } else {
        (0x7FFF_FFFFu32, 0xFFFF_FFFFu32)
    };

    buf[*offset..*offset + 2].copy_from_slice(&pids::PID_LIFESPAN.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&8u16.to_le_bytes());
    buf[*offset + 4..*offset + 8].copy_from_slice(&seconds.to_le_bytes());
    buf[*offset + 8..*offset + 12].copy_from_slice(&fraction.to_le_bytes());
    *offset += 12;

    Ok(())
}

/// Write PID_USER_DATA (0x002c) - 4 bytes (empty sequence)
pub fn write_user_data(buf: &mut [u8], offset: &mut usize) -> EncodeResult<()> {
    if *offset + 8 > buf.len() {
        return Err(EncodeError::BufferTooSmall);
    }

    buf[*offset..*offset + 2].copy_from_slice(&pids::PID_USER_DATA.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&4u16.to_le_bytes());
    buf[*offset + 4..*offset + 8].copy_from_slice(&0u32.to_le_bytes()); // sequenceSize = 0
    *offset += 8;

    Ok(())
}

/// Write PID_DESTINATION_ORDER (0x0025) - 4 bytes
pub fn write_destination_order(buf: &mut [u8], offset: &mut usize) -> EncodeResult<()> {
    if *offset + 8 > buf.len() {
        return Err(EncodeError::BufferTooSmall);
    }

    buf[*offset..*offset + 2].copy_from_slice(&pids::PID_DESTINATION_ORDER.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&4u16.to_le_bytes());
    buf[*offset + 4..*offset + 8].copy_from_slice(&0u32.to_le_bytes()); // BY_RECEPTION_TIMESTAMP
    *offset += 8;

    Ok(())
}

/// Write PID_PRESENTATION (0x0021) - 8 bytes.
///
/// Encodes the actual `Presentation` QoS from the endpoint instead of the
/// previous INSTANCE/false/false hardcoded values. Without honoring this
/// PID, Connext/Fast DDS subscribers that opt into TOPIC- or GROUP-scope
/// coherent/ordered access (e.g. OrderedAccess_10 sub_2, CoherentSets_8)
/// see the default INSTANCE+no-coherent+no-ordered from HDDS and fire
/// INCOMPATIBLE_QOS or refuse to deliver samples.
pub fn write_presentation(
    qos: Option<&super::super::QosProfile>,
    buf: &mut [u8],
    offset: &mut usize,
) -> EncodeResult<()> {
    if *offset + 12 > buf.len() {
        return Err(EncodeError::BufferTooSmall);
    }

    let access_scope = qos.map(|q| q.presentation_access_scope).unwrap_or(0);
    let coherent = qos.map(|q| q.presentation_coherent).unwrap_or(false);
    let ordered = qos.map(|q| q.presentation_ordered).unwrap_or(false);

    buf[*offset..*offset + 2].copy_from_slice(&pids::PID_PRESENTATION.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&8u16.to_le_bytes());
    buf[*offset + 4..*offset + 8].copy_from_slice(&access_scope.to_le_bytes());
    buf[*offset + 8] = u8::from(coherent);
    buf[*offset + 9] = u8::from(ordered);
    buf[*offset + 10] = 0; // padding
    buf[*offset + 11] = 0; // padding
    *offset += 12;

    Ok(())
}

/// Write PID_TOPIC_DATA (0x002e) - 4 bytes (empty sequence)
pub fn write_topic_data(buf: &mut [u8], offset: &mut usize) -> EncodeResult<()> {
    if *offset + 8 > buf.len() {
        return Err(EncodeError::BufferTooSmall);
    }

    buf[*offset..*offset + 2].copy_from_slice(&pids::PID_TOPIC_DATA.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&4u16.to_le_bytes());
    buf[*offset + 4..*offset + 8].copy_from_slice(&0u32.to_le_bytes()); // sequenceSize = 0
    *offset += 8;

    Ok(())
}

/// Write PID_GROUP_DATA (0x002d) - 4 bytes (empty sequence)
pub fn write_group_data(buf: &mut [u8], offset: &mut usize) -> EncodeResult<()> {
    if *offset + 8 > buf.len() {
        return Err(EncodeError::BufferTooSmall);
    }

    buf[*offset..*offset + 2].copy_from_slice(&pids::PID_GROUP_DATA.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&4u16.to_le_bytes());
    buf[*offset + 4..*offset + 8].copy_from_slice(&0u32.to_le_bytes()); // sequenceSize = 0
    *offset += 8;

    Ok(())
}
