// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! SEDP QoS Policy PID Writers
//!
//! Handles encoding of DDS QoS policy PIDs:
//! - PID_RELIABILITY (0x001a) - Reliability QoS (BEST_EFFORT/RELIABLE)
//! - PID_DURABILITY (0x001d) - Durability QoS (VOLATILE/TRANSIENT_LOCAL)
//! - PID_HISTORY (0x0040) - History QoS (KEEP_LAST/KEEP_ALL)
//! - PID_DEADLINE (0x0023) - Deadline QoS
//! - PID_OWNERSHIP (0x001f) - Ownership QoS (SHARED/EXCLUSIVE)
//! - PID_LIVELINESS (0x001b) - Liveliness QoS
//! - PID_TIME_BASED_FILTER (0x0004) - Time-based filter QoS
//! - PID_PARTITION (0x0029) - Partition QoS
//! - PID_RESOURCE_LIMITS (0x0041) - Resource limits QoS
//! - PID_DURABILITY_SERVICE (0x001e) - Durability service QoS

use super::super::super::constants::{
    PID_DEADLINE, PID_DESTINATION_ORDER, PID_DURABILITY, PID_DURABILITY_SERVICE, PID_HISTORY,
    PID_LATENCY_BUDGET, PID_LIFESPAN, PID_LIVELINESS, PID_OWNERSHIP, PID_OWNERSHIP_STRENGTH,
    PID_PARTITION, PID_PRESENTATION, PID_RELIABILITY, PID_RESOURCE_LIMITS, PID_TIME_BASED_FILTER,
    PID_TYPE_CONSISTENCY,
};
use super::super::super::types::{
    parameter_length, wire_u32, ParseError, TypeConsistencyEnforcement,
};
use crate::dds::qos::{
    Durability, History, LivelinessKind, PresentationAccessScope, QoS, Reliability,
};

/// Write PID_RELIABILITY (0x001a) - 12 bytes.
/// Format: kind (u32) + max_blocking_time (Duration_t = 2xu32).
/// DDS v1.4 Sec.2.2.3.12: BEST_EFFORT=1, RELIABLE=2.
pub fn write_reliability(
    qos: Option<&QoS>,
    buf: &mut [u8],
    offset: &mut usize,
) -> Result<(), ParseError> {
    if *offset + 16 > buf.len() {
        return Err(ParseError::BufferTooSmall);
    }

    let reliability_kind = if let Some(qos) = qos {
        match qos.reliability {
            Reliability::BestEffort => 1u32,
            Reliability::Reliable => 2u32,
        }
    } else {
        2u32 // Default: RELIABLE per spec Sec.8.5.3.1
    };

    buf[*offset..*offset + 2].copy_from_slice(&PID_RELIABILITY.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&12u16.to_le_bytes());
    buf[*offset + 4..*offset + 8].copy_from_slice(&reliability_kind.to_le_bytes());
    // RTPS v2.5 Sec.9.3.2 Duration_t: the endpoint's max_blocking_time, 100 ms
    // (DDS v1.4 Sec.2.2.3.14 default) for an endpoint that names none.
    let max_blocking_time = qos.map_or(crate::dds::qos::DEFAULT_MAX_BLOCKING_TIME, |q| {
        q.reliability_max_blocking_time
    });
    buf[*offset + 8..*offset + 16]
        .copy_from_slice(&crate::protocol::dialect::duration_t_le(max_blocking_time));
    *offset += 16;

    Ok(())
}

/// Write PID_DURABILITY (0x001d) - 4 bytes.
/// Format: kind (u32).
/// DDS v1.4 Sec.2.2.3.4: VOLATILE=0, TRANSIENT_LOCAL=1, TRANSIENT=2, PERSISTENT=3.
pub fn write_durability(
    qos: Option<&QoS>,
    buf: &mut [u8],
    offset: &mut usize,
) -> Result<(), ParseError> {
    if *offset + 8 > buf.len() {
        return Err(ParseError::BufferTooSmall);
    }

    let durability_kind = if let Some(qos) = qos {
        match qos.durability {
            Durability::Volatile => 0u32,
            Durability::TransientLocal => 1u32,
            Durability::Transient => 2u32,
            Durability::Persistent => 3u32,
        }
    } else {
        0u32 // Default: VOLATILE (the DDS 1.4 default)
    };

    buf[*offset..*offset + 2].copy_from_slice(&PID_DURABILITY.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&4u16.to_le_bytes());
    buf[*offset + 4..*offset + 8].copy_from_slice(&durability_kind.to_le_bytes());
    *offset += 8;

    Ok(())
}

/// Write PID_HISTORY (0x0040) - 8 bytes.
/// Format: kind (u32) + depth (u32).
/// DDS v1.4 Sec.2.2.3.9: KEEP_LAST=0, KEEP_ALL=1.
pub fn write_history(
    qos: Option<&QoS>,
    buf: &mut [u8],
    offset: &mut usize,
) -> Result<(), ParseError> {
    if *offset + 12 > buf.len() {
        return Err(ParseError::BufferTooSmall);
    }

    let (history_kind, history_depth) = if let Some(qos) = qos {
        match qos.history {
            History::KeepLast(depth) => (0u32, depth),
            History::KeepAll => (1u32, 0u32),
        }
    } else {
        (0u32, 10u32) // Default: KEEP_LAST(10)
    };

    buf[*offset..*offset + 2].copy_from_slice(&PID_HISTORY.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&8u16.to_le_bytes());
    buf[*offset + 4..*offset + 8].copy_from_slice(&history_kind.to_le_bytes());
    buf[*offset + 8..*offset + 12].copy_from_slice(&history_depth.to_le_bytes());
    *offset += 12;

    Ok(())
}

/// Write PID_DEADLINE (0x0023) - 8 bytes.
/// Format: period (Duration_t = 2xu32).
/// Written only when the period is not the default, INFINITE: a receiver
/// takes the default for an absent parameter (RTPS v2.5 Sec.8.5.4.4).
/// Leaving it out also removes any chance of a receiver decoding the
/// explicit INFINITE (seconds 0x7FFFFFFF, fraction 0xFFFFFFFF, Sec.9.3.2)
/// as a finite period and refusing the match.
pub fn write_deadline(
    qos: Option<&QoS>,
    buf: &mut [u8],
    offset: &mut usize,
) -> Result<(), ParseError> {
    if qos.is_none_or(|qos| qos.deadline.is_infinite()) {
        return Ok(());
    }
    if *offset + 12 > buf.len() {
        return Err(ParseError::BufferTooSmall);
    }

    let (seconds, fraction) = if let Some(qos) = qos {
        if qos.deadline.is_infinite() {
            (0x7FFF_FFFFu32, 0xFFFF_FFFFu32)
        } else {
            let secs = qos.deadline.period.as_secs();
            let nanos = qos.deadline.period.subsec_nanos() as u64;
            // RTPS v2.5 sec. 9.3.2: Duration_t fraction is 2^-32 seconds, not nanoseconds.
            // `subsec_nanos() < 10^9` per std::time::Duration contract, so the
            // shifted division fits in u32; `try_from` guards defensively.
            let frac = u32::try_from((nanos << 32) / 1_000_000_000).unwrap_or(u32::MAX);
            (u32::try_from(secs).unwrap_or(u32::MAX), frac)
        }
    } else {
        (0x7FFF_FFFFu32, 0xFFFF_FFFFu32) // INFINITE
    };

    buf[*offset..*offset + 2].copy_from_slice(&PID_DEADLINE.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&8u16.to_le_bytes());
    buf[*offset + 4..*offset + 8].copy_from_slice(&seconds.to_le_bytes());
    buf[*offset + 8..*offset + 12].copy_from_slice(&fraction.to_le_bytes());
    *offset += 12;

    Ok(())
}

/// Write PID_LIFESPAN (0x002b) - 8 bytes.
/// Format: duration (Duration_t = 2xu32).
/// Written only when the duration is not the default, INFINITE (see
/// `write_deadline`).
pub fn write_lifespan(
    qos: Option<&QoS>,
    buf: &mut [u8],
    offset: &mut usize,
) -> Result<(), ParseError> {
    if qos.is_none_or(|qos| qos.lifespan.is_infinite()) {
        return Ok(());
    }
    if *offset + 12 > buf.len() {
        return Err(ParseError::BufferTooSmall);
    }

    let (seconds, fraction) = if let Some(qos) = qos {
        if qos.lifespan.is_infinite() {
            (0x7FFF_FFFFu32, 0xFFFF_FFFFu32)
        } else {
            let secs = qos.lifespan.duration.as_secs();
            let nanos = qos.lifespan.duration.subsec_nanos() as u64;
            // RTPS v2.5 sec. 9.3.2: Duration_t fraction is 2^-32 seconds, not nanoseconds.
            // `subsec_nanos() < 10^9` per std::time::Duration contract, so the
            // shifted division fits in u32; `try_from` guards defensively.
            let frac = u32::try_from((nanos << 32) / 1_000_000_000).unwrap_or(u32::MAX);
            (u32::try_from(secs).unwrap_or(u32::MAX), frac)
        }
    } else {
        (0x7FFF_FFFFu32, 0xFFFF_FFFFu32) // INFINITE
    };

    buf[*offset..*offset + 2].copy_from_slice(&PID_LIFESPAN.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&8u16.to_le_bytes());
    buf[*offset + 4..*offset + 8].copy_from_slice(&seconds.to_le_bytes());
    buf[*offset + 8..*offset + 12].copy_from_slice(&fraction.to_le_bytes());
    *offset += 12;

    Ok(())
}

/// Write PID_OWNERSHIP (0x001f) - 4 bytes.
/// Format: kind (u32).
/// Default: SHARED (kind=0).
pub fn write_ownership(
    qos: Option<&QoS>,
    buf: &mut [u8],
    offset: &mut usize,
) -> Result<(), ParseError> {
    if *offset + 8 > buf.len() {
        return Err(ParseError::BufferTooSmall);
    }

    use crate::dds::qos::OwnershipKind;
    let kind = if let Some(qos) = qos {
        match qos.ownership.kind {
            OwnershipKind::Shared => 0u32,
            OwnershipKind::Exclusive => 1u32,
        }
    } else {
        0u32 // SHARED
    };

    buf[*offset..*offset + 2].copy_from_slice(&PID_OWNERSHIP.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&4u16.to_le_bytes());
    buf[*offset + 4..*offset + 8].copy_from_slice(&kind.to_le_bytes());
    *offset += 8;

    Ok(())
}

/// Write PID_OWNERSHIP_STRENGTH (0x0006) - 4 bytes.
/// Format: value (i32).
/// Default: 0. Only meaningful when ownership kind is EXCLUSIVE.
pub fn write_ownership_strength(
    qos: Option<&QoS>,
    buf: &mut [u8],
    offset: &mut usize,
) -> Result<(), ParseError> {
    if *offset + 8 > buf.len() {
        return Err(ParseError::BufferTooSmall);
    }

    let strength = qos.map(|q| q.ownership_strength.value).unwrap_or(0);

    buf[*offset..*offset + 2].copy_from_slice(&PID_OWNERSHIP_STRENGTH.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&4u16.to_le_bytes());
    buf[*offset + 4..*offset + 8].copy_from_slice(&strength.to_le_bytes());
    *offset += 8;

    Ok(())
}

/// Write PID_LIVELINESS (0x001b) - 12 bytes.
/// Format: kind (u32) + lease_duration (Duration_t = 2xu32).
/// The endpoint's own policy, written only when it is not the default,
/// AUTOMATIC with an INFINITE lease (see `write_deadline`). Kinds on the
/// wire: AUTOMATIC 0, MANUAL_BY_PARTICIPANT 1, MANUAL_BY_TOPIC 2.
pub fn write_liveliness(
    qos: Option<&QoS>,
    buf: &mut [u8],
    offset: &mut usize,
) -> Result<(), ParseError> {
    let Some(liveliness) = qos.map(|qos| &qos.liveliness) else {
        return Ok(());
    };
    if liveliness.kind == LivelinessKind::Automatic && liveliness.is_infinite() {
        return Ok(());
    }
    if *offset + 16 > buf.len() {
        return Err(ParseError::BufferTooSmall);
    }
    let kind: u32 = match liveliness.kind {
        LivelinessKind::Automatic => 0,
        LivelinessKind::ManualByParticipant => 1,
        LivelinessKind::ManualByTopic => 2,
    };
    let (seconds, fraction) = if liveliness.is_infinite() {
        (0x7FFF_FFFFu32, 0xFFFF_FFFFu32)
    } else {
        let secs = liveliness.lease_duration.as_secs();
        let nanos = u64::from(liveliness.lease_duration.subsec_nanos());
        // RTPS v2.5 Sec.9.3.2: the fraction is in 2^-32 seconds.
        let frac = u32::try_from((nanos << 32) / 1_000_000_000).unwrap_or(u32::MAX);
        (
            u32::try_from(secs).unwrap_or(0x7FFF_FFFF).min(0x7FFF_FFFF),
            frac,
        )
    };
    buf[*offset..*offset + 2].copy_from_slice(&PID_LIVELINESS.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&12u16.to_le_bytes());
    buf[*offset + 4..*offset + 8].copy_from_slice(&kind.to_le_bytes());
    buf[*offset + 8..*offset + 12].copy_from_slice(&seconds.to_le_bytes());
    buf[*offset + 12..*offset + 16].copy_from_slice(&fraction.to_le_bytes());
    *offset += 16;

    Ok(())
}

/// Write PID_LATENCY_BUDGET (0x0027) - 8 bytes: Duration_t duration
/// (RTPS v2.5 Sec.9.3.2). The endpoint's own budget, written only when it is
/// not the default, zero (DDS v1.4 Sec.2.2.3.8; a receiver takes an absent
/// PID as the default).
pub fn write_latency_budget(
    qos: Option<&QoS>,
    buf: &mut [u8],
    offset: &mut usize,
) -> Result<(), ParseError> {
    let Some(budget) = qos.map(|qos| qos.latency_budget) else {
        return Ok(());
    };
    if budget.is_zero() {
        return Ok(());
    }
    if *offset + 12 > buf.len() {
        return Err(ParseError::BufferTooSmall);
    }
    buf[*offset..*offset + 2].copy_from_slice(&PID_LATENCY_BUDGET.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&8u16.to_le_bytes());
    buf[*offset + 4..*offset + 12]
        .copy_from_slice(&crate::protocol::dialect::duration_t_le(budget.duration));
    *offset += 12;
    Ok(())
}

/// Write PID_DESTINATION_ORDER (0x0025) - 4 bytes: kind,
/// BY_RECEPTION_TIMESTAMP 0, BY_SOURCE_TIMESTAMP 1. Written only when it is
/// not the default, BY_RECEPTION_TIMESTAMP (DDS v1.4 Sec.2.2.3.17).
pub fn write_destination_order(
    qos: Option<&QoS>,
    buf: &mut [u8],
    offset: &mut usize,
) -> Result<(), ParseError> {
    if !qos.is_some_and(|qos| qos.destination_order.uses_source_timestamp()) {
        return Ok(());
    }
    if *offset + 8 > buf.len() {
        return Err(ParseError::BufferTooSmall);
    }
    buf[*offset..*offset + 2].copy_from_slice(&PID_DESTINATION_ORDER.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&4u16.to_le_bytes());
    buf[*offset + 4..*offset + 8].copy_from_slice(&1u32.to_le_bytes());
    *offset += 8;
    Ok(())
}

/// Write PID_TIME_BASED_FILTER (0x0004) - 12 bytes total (4-byte header + 8-byte payload).
/// Payload format: minimum_separation (Duration_t = seconds:u32 + fraction:u32).
/// RTPS v2.5 sec. 9.3.2: Duration_t fraction is 2^-32 seconds (NOT nanoseconds).
/// When qos is None or minimum_separation is zero, emits 0/0 (filter disabled, default).
/// When minimum_separation is non-zero, advertises the actual configured value so that
/// a remote publisher knows the reader has TIME_BASED_FILTER enabled and can throttle
/// its data delivery accordingly.
pub fn write_time_based_filter(
    qos: Option<&QoS>,
    buf: &mut [u8],
    offset: &mut usize,
) -> Result<(), ParseError> {
    if *offset + 12 > buf.len() {
        return Err(ParseError::BufferTooSmall);
    }

    // Extract minimum_separation from QoS; zero (disabled) when absent or unset.
    let (sep_sec, sep_frac) = match qos {
        Some(q) if !q.time_based_filter.is_disabled() => {
            let secs = q.time_based_filter.minimum_separation.as_secs();
            let nanos = q.time_based_filter.minimum_separation.subsec_nanos() as u64;
            // RTPS v2.5 sec. 9.3.2: fraction is 2^-32 seconds.
            // subsec_nanos() < 10^9, so (nanos << 32) / 10^9 fits in u32.
            let frac = u32::try_from((nanos << 32) / 1_000_000_000).unwrap_or(u32::MAX);
            (u32::try_from(secs).unwrap_or(u32::MAX), frac)
        }
        _ => (0u32, 0u32), // disabled / default: 0 seconds, 0 fraction
    };

    buf[*offset..*offset + 2].copy_from_slice(&PID_TIME_BASED_FILTER.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&8u16.to_le_bytes());
    buf[*offset + 4..*offset + 8].copy_from_slice(&sep_sec.to_le_bytes());
    buf[*offset + 8..*offset + 12].copy_from_slice(&sep_frac.to_le_bytes());
    *offset += 12;

    Ok(())
}

/// Write PID_PARTITION (0x0029) - sequence of partition name strings.
/// Format: sequence_length (u32) + for each: string_length (u32) + string + NUL + padding.
/// Default: empty sequence (no partitions).
pub fn write_partition(
    qos: Option<&QoS>,
    buf: &mut [u8],
    offset: &mut usize,
) -> Result<(), ParseError> {
    let names = qos.map(|q| q.partition.names.as_slice()).unwrap_or(&[]);

    if names.is_empty() {
        // Empty sequence: PID (2) + length (2) + seq_len=0 (4) = 8 bytes
        if *offset + 8 > buf.len() {
            return Err(ParseError::BufferTooSmall);
        }
        buf[*offset..*offset + 2].copy_from_slice(&PID_PARTITION.to_le_bytes());
        buf[*offset + 2..*offset + 4].copy_from_slice(&4u16.to_le_bytes());
        buf[*offset + 4..*offset + 8].copy_from_slice(&0u32.to_le_bytes());
        *offset += 8;
        return Ok(());
    }

    // Calculate total payload size: seq_len (4) + for each string: str_len (4) + chars + NUL + pad
    let mut payload_size: usize = 4; // sequence_length field
    for name in names {
        let str_len = name.len() + 1; // include NUL terminator
        let padded = (str_len + 3) & !3; // align to 4 bytes
        payload_size += 4 + padded; // string_length (u32) + padded string
    }

    if *offset + 4 + payload_size > buf.len() {
        return Err(ParseError::BufferTooSmall);
    }

    buf[*offset..*offset + 2].copy_from_slice(&PID_PARTITION.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&parameter_length(payload_size)?.to_le_bytes());
    *offset += 4;

    // Sequence length (number of strings)
    buf[*offset..*offset + 4].copy_from_slice(&wire_u32(names.len())?.to_le_bytes());
    *offset += 4;

    // Each string: length (u32) + chars + NUL + padding
    for name in names {
        let str_len = wire_u32(name.len() + 1)?; // include NUL
        buf[*offset..*offset + 4].copy_from_slice(&str_len.to_le_bytes());
        *offset += 4;

        buf[*offset..*offset + name.len()].copy_from_slice(name.as_bytes());
        *offset += name.len();
        buf[*offset] = 0; // NUL terminator
        *offset += 1;

        // Pad to 4-byte alignment
        let pad = (4 - (name.len() + 1) % 4) % 4;
        for i in 0..pad {
            buf[*offset + i] = 0;
        }
        *offset += pad;
    }

    Ok(())
}

/// A RESOURCE_LIMITS value as the DDS `long` it travels as: LENGTH_UNLIMITED
/// (`usize::MAX` in HDDS) is -1; a finite value past `i32::MAX` has no wire
/// form and is refused rather than wrapped into a negative number.
fn wire_length_limit(value: usize) -> Result<i32, ParseError> {
    if value == crate::reliability::LENGTH_UNLIMITED {
        return Ok(-1);
    }
    i32::try_from(value).map_err(|_| ParseError::InvalidFormat)
}

/// Write PID_RESOURCE_LIMITS (0x0041) - 12 bytes.
/// Format: max_samples, max_instances, max_samples_per_instance, each a DDS
/// `long` (i32) where -1 is LENGTH_UNLIMITED (DDS v1.4 Sec.2.3.3).
/// Without a QoS: 1000, 100, 100.
pub fn write_resource_limits(
    qos: Option<&QoS>,
    buf: &mut [u8],
    offset: &mut usize,
) -> Result<(), ParseError> {
    if *offset + 16 > buf.len() {
        return Err(ParseError::BufferTooSmall);
    }

    let (max_samples, max_instances, max_samples_per_instance) = if let Some(qos) = qos {
        let limits = &qos.resource_limits;
        (
            wire_length_limit(limits.max_samples)?,
            wire_length_limit(limits.max_instances)?,
            wire_length_limit(limits.max_samples_per_instance)?,
        )
    } else {
        (1000i32, 100i32, 100i32)
    };

    buf[*offset..*offset + 2].copy_from_slice(&PID_RESOURCE_LIMITS.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&12u16.to_le_bytes());
    buf[*offset + 4..*offset + 8].copy_from_slice(&max_samples.to_le_bytes());
    buf[*offset + 8..*offset + 12].copy_from_slice(&max_instances.to_le_bytes());
    buf[*offset + 12..*offset + 16].copy_from_slice(&max_samples_per_instance.to_le_bytes());
    *offset += 16;

    Ok(())
}

/// Write PID_DURABILITY_SERVICE (0x001e) - 28 bytes.
/// Format: service_cleanup_delay (Duration_t = 2xu32) + history_kind (u32) +
///         history_depth (u32) + max_samples (i32) + max_instances (i32) +
///         max_samples_per_instance (i32).
/// DDS v1.4 Sec.2.2.3.5: Only relevant when durability >= TRANSIENT_LOCAL.
pub fn write_durability_service(
    qos: Option<&QoS>,
    buf: &mut [u8],
    offset: &mut usize,
) -> Result<(), ParseError> {
    if *offset + 32 > buf.len() {
        return Err(ParseError::BufferTooSmall);
    }

    let ds = qos.map(|q| q.durability_service).unwrap_or_default();

    // Convert cleanup delay from microseconds to RTPS Duration_t.
    // RTPS v2.5 sec. 9.3.2: fraction is 2^-32 seconds, not nanoseconds.
    let cleanup_secs = u32::try_from(ds.service_cleanup_delay_us / 1_000_000).unwrap_or(u32::MAX);
    let cleanup_ns_u64 = (ds.service_cleanup_delay_us % 1_000_000) * 1_000;
    // `cleanup_ns_u64 < 10^9` by construction (modulo above + *1000 < 10^9
    // as long as microseconds is well-formed), so the shift-then-divide fits
    // in u32. `try_from` guards the invariant at runtime in case of
    // unexpected input.
    let cleanup_fraction =
        u32::try_from((cleanup_ns_u64 << 32) / 1_000_000_000).unwrap_or(u32::MAX);

    // History kind: KEEP_LAST=0 (DurabilityService always uses KEEP_LAST)
    let history_kind = 0u32;

    buf[*offset..*offset + 2].copy_from_slice(&PID_DURABILITY_SERVICE.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&28u16.to_le_bytes());
    buf[*offset + 4..*offset + 8].copy_from_slice(&cleanup_secs.to_le_bytes());
    buf[*offset + 8..*offset + 12].copy_from_slice(&cleanup_fraction.to_le_bytes());
    buf[*offset + 12..*offset + 16].copy_from_slice(&history_kind.to_le_bytes());
    buf[*offset + 16..*offset + 20].copy_from_slice(&ds.history_depth.to_le_bytes());
    buf[*offset + 20..*offset + 24].copy_from_slice(&ds.max_samples.to_le_bytes());
    buf[*offset + 24..*offset + 28].copy_from_slice(&ds.max_instances.to_le_bytes());
    buf[*offset + 28..*offset + 32].copy_from_slice(&ds.max_samples_per_instance.to_le_bytes());
    *offset += 32;

    Ok(())
}

/// Write PID_PRESENTATION (0x0021) - 8 bytes.
/// Format: access_scope (u32) + coherent_access (u8) + ordered_access (u8) + 2 padding.
/// DDS v1.4 Sec.2.2.3.6: INSTANCE=0, TOPIC=1, GROUP=2.
pub fn write_presentation(
    qos: Option<&QoS>,
    buf: &mut [u8],
    offset: &mut usize,
) -> Result<(), ParseError> {
    if *offset + 12 > buf.len() {
        return Err(ParseError::BufferTooSmall);
    }

    let (access_scope, coherent_access, ordered_access) = if let Some(qos) = qos {
        let scope = match qos.presentation.access_scope {
            PresentationAccessScope::Instance => 0u32,
            PresentationAccessScope::Topic => 1u32,
            PresentationAccessScope::Group => 2u32,
        };
        (
            scope,
            u8::from(qos.presentation.coherent_access),
            u8::from(qos.presentation.ordered_access),
        )
    } else {
        (0u32, 0u8, 0u8) // Default: INSTANCE scope, no coherent, no ordered
    };

    buf[*offset..*offset + 2].copy_from_slice(&PID_PRESENTATION.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&8u16.to_le_bytes());
    buf[*offset + 4..*offset + 8].copy_from_slice(&access_scope.to_le_bytes());
    buf[*offset + 8] = coherent_access;
    buf[*offset + 9] = ordered_access;
    buf[*offset + 10] = 0; // padding
    buf[*offset + 11] = 0; // padding
    *offset += 12;

    Ok(())
}

/// Write `PID_TYPE_CONSISTENCY_ENFORCEMENT` (0x0074) - 12 bytes on the wire
/// (4-byte PID header + 8-byte payload).
///
/// Encodes the `TypeConsistencyEnforcementQosPolicy` per DDS-XTypes v1.3
/// (OMG formal/2020-02-04) sec. 7.6.3.3.3 / sec. 7.6.3.5. IDL:
///
/// ```text
/// @bit_bound(16)
/// enum TypeConsistencyKind {
///     DISALLOW_TYPE_COERCION, // = 0 (strict pre-XTypes default)
///     ALLOW_TYPE_COERCION     // = 1 (permissive XTypes default)
/// };
///
/// struct TypeConsistencyEnforcementQosPolicy {
///     TypeConsistencyKind kind;
///     boolean ignore_sequence_bounds;
///     boolean ignore_string_bounds;
///     boolean ignore_member_names;
///     boolean prevent_type_widening;
///     boolean force_type_validation;
/// };
/// ```
///
/// Wire layout (8-byte payload, LE):
///   `kind(u16) ignore_seq(u8) ignore_str(u8) ignore_names(u8)
///    prevent_widening(u8) force_validation(u8) pad(u8)`.
///
/// When `policy` is `None`, the function emits the permissive XTypes interop
/// default (ALLOW_TYPE_COERCION, ignore_seq=1, ignore_str=1, all others=0),
/// i.e. the bytes `01 00 01 01 00 00 00 00`.
/// When `policy` is `Some(p)`, the caller-supplied values override the defaults
/// so that endpoints can advertise the actual `TypeConsistencyEnforcementQosPolicy`
/// they were configured with (e.g. from the OMG harness CLI flags).
///
/// Emitted alongside `PID_TYPE_INFORMATION` whenever a `CompleteTypeObject`
/// is available on the endpoint; without it, a reader that assumes a
/// stricter policy may reject the match even when types are structurally
/// compatible.
pub fn write_type_consistency_enforcement(
    policy: Option<&TypeConsistencyEnforcement>,
    buf: &mut [u8],
    offset: &mut usize,
) -> Result<(), ParseError> {
    if *offset + 12 > buf.len() {
        return Err(ParseError::BufferTooSmall);
    }

    buf[*offset..*offset + 2].copy_from_slice(&PID_TYPE_CONSISTENCY.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&8u16.to_le_bytes());

    if let Some(p) = policy {
        // Caller-supplied policy: encode field-by-field from the struct.
        let kind_bytes = p.kind.to_le_bytes();
        buf[*offset + 4] = kind_bytes[0];
        buf[*offset + 5] = kind_bytes[1];
        buf[*offset + 6] = u8::from(p.ignore_sequence_bounds);
        buf[*offset + 7] = u8::from(p.ignore_string_bounds);
        buf[*offset + 8] = u8::from(p.ignore_member_names);
        buf[*offset + 9] = u8::from(p.prevent_type_widening);
        buf[*offset + 10] = u8::from(p.force_type_validation);
        buf[*offset + 11] = 0; // padding to 8-byte payload
    } else {
        // Permissive XTypes interop default when no explicit policy is set.
        // ignore_member_names=true: name checking is opt-in; peer types with
        // structurally compatible member IDs and types are accepted regardless
        // of member name differences. The OMG struct_different_names_ok and
        // struct_different_ids_ok tests confirm this must be the wire default.
        // Byte layout: kind(u16 LE) | ign_seq_bounds | ign_str_bounds |
        //              ign_member_names | prevent_widening | force_validation | pad
        buf[*offset + 4..*offset + 12]
            .copy_from_slice(&[0x01, 0x00, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00]);
    }
    *offset += 12;

    Ok(())
}

#[cfg(test)]
mod type_consistency_tests {
    use super::*;

    /// Lock the default (None policy) wire payload for PID_TYPE_CONSISTENCY_ENFORCEMENT.
    ///
    /// Expected bytes: `74 00 08 00 01 00 01 01 01 00 00 00`.
    /// - `74 00`      = PID_TYPE_CONSISTENCY_ENFORCEMENT (LE u16 = 0x0074)
    /// - `08 00`      = payload length (LE u16 = 8)
    /// - `01 00`      = `kind` = ALLOW_TYPE_COERCION
    /// - `01`         = `ignore_sequence_bounds` = true
    /// - `01`         = `ignore_string_bounds` = true
    /// - `01`         = `ignore_member_names` = true (permissive default)
    /// - `00`         = `prevent_type_widening` = false
    /// - `00`         = `force_type_validation` = false
    /// - `00`         = padding
    #[test]
    fn write_type_consistency_enforcement_emits_permissive_profile() {
        let mut buf = [0xFFu8; 16];
        let mut offset = 0;
        write_type_consistency_enforcement(None, &mut buf, &mut offset)
            .expect("write must succeed into a 16-byte buffer");

        assert_eq!(offset, 12, "PID header (4) + payload (8) bytes written");
        assert_eq!(
            &buf[..12],
            &[0x74, 0x00, 0x08, 0x00, 0x01, 0x00, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00],
            "wire bytes must match the permissive profile (ignore_member_names=true)",
        );
    }

    #[test]
    fn write_type_consistency_enforcement_kind_decodes_to_allow_coercion() {
        let mut buf = [0u8; 16];
        let mut offset = 0;
        write_type_consistency_enforcement(None, &mut buf, &mut offset).expect("emit succeeds");

        // PID header at [0..4], payload at [4..12]. `kind` (u16 LE) lives
        // at payload offset 0 (= absolute offset 4).
        let kind = u16::from_le_bytes([buf[4], buf[5]]);
        assert_eq!(kind, 1, "DDS-XTypes v1.3 sec. 7.6.3.5 ALLOW_TYPE_COERCION");
        assert_eq!(buf[6], 0x01, "ignore_sequence_bounds = true");
        assert_eq!(buf[7], 0x01, "ignore_string_bounds = true");
        assert_eq!(
            buf[8], 0x01,
            "ignore_member_names = true (permissive default)"
        );
        assert_eq!(buf[9], 0x00, "prevent_type_widening = false");
        assert_eq!(buf[10], 0x00, "force_type_validation = false");
        assert_eq!(buf[11], 0x00, "padding to 8-byte payload");
    }

    #[test]
    fn write_type_consistency_enforcement_rejects_short_buffer() {
        let mut buf = [0u8; 8]; // 4 bytes shy of the 12 required
        let mut offset = 0;
        let err = write_type_consistency_enforcement(None, &mut buf, &mut offset)
            .expect_err("must reject a buffer smaller than the 12-byte total");
        assert_eq!(err, ParseError::BufferTooSmall);
        assert_eq!(offset, 0, "offset must not advance on error");
    }

    #[test]
    fn write_type_consistency_enforcement_caller_policy_is_strict() {
        // Verify that a caller-supplied strict policy is encoded correctly:
        // DISALLOW_TYPE_COERCION (kind=0), no bounds ignoring, prevent widening.
        let policy = TypeConsistencyEnforcement {
            kind: 0, // DISALLOW_TYPE_COERCION
            ignore_sequence_bounds: false,
            ignore_string_bounds: false,
            ignore_member_names: false,
            prevent_type_widening: true,
            force_type_validation: false,
        };
        let mut buf = [0xFFu8; 16];
        let mut offset = 0;
        write_type_consistency_enforcement(Some(&policy), &mut buf, &mut offset)
            .expect("write must succeed");

        assert_eq!(offset, 12);
        let kind = u16::from_le_bytes([buf[4], buf[5]]);
        assert_eq!(kind, 0, "DISALLOW_TYPE_COERCION");
        assert_eq!(buf[6], 0x00, "ignore_sequence_bounds = false");
        assert_eq!(buf[7], 0x00, "ignore_string_bounds = false");
        assert_eq!(buf[8], 0x00, "ignore_member_names = false");
        assert_eq!(buf[9], 0x01, "prevent_type_widening = true");
        assert_eq!(buf[10], 0x00, "force_type_validation = false");
        assert_eq!(buf[11], 0x00, "padding");
    }
}

#[cfg(test)]
mod time_based_filter_tests {
    use super::*;
    use crate::dds::qos::{QoS, TimeBasedFilter};
    use std::time::Duration;

    /// Default (no QoS) emits zero minimum_separation -- filter disabled on the wire.
    ///
    /// Wire layout expected: `04 00 08 00 00 00 00 00 00 00 00 00`
    ///   `04 00` = PID_TIME_BASED_FILTER (LE u16 = 0x0004)
    ///   `08 00` = payload length (8 bytes)
    ///   `00 00 00 00` = minimum_separation.seconds = 0
    ///   `00 00 00 00` = minimum_separation.fraction = 0
    #[test]
    fn write_time_based_filter_none_qos_emits_zero() {
        let mut buf = [0xFFu8; 16];
        let mut offset = 0;
        write_time_based_filter(None, &mut buf, &mut offset)
            .expect("must succeed into a 16-byte buffer");

        assert_eq!(offset, 12, "PID header (4) + payload (8) = 12 bytes");
        assert_eq!(
            &buf[..12],
            &[0x04, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            "zero minimum_separation for disabled filter"
        );
    }

    /// A QoS with TBF disabled (minimum_separation == 0) also emits zeros.
    #[test]
    fn write_time_based_filter_disabled_qos_emits_zero() {
        let qos = QoS::reliable();
        assert!(qos.time_based_filter.is_disabled());
        let mut buf = [0xFFu8; 16];
        let mut offset = 0;
        write_time_based_filter(Some(&qos), &mut buf, &mut offset).expect("must succeed");

        assert_eq!(offset, 12);
        let sec = u32::from_le_bytes(buf[4..8].try_into().unwrap());
        let frac = u32::from_le_bytes(buf[8..12].try_into().unwrap());
        assert_eq!(sec, 0, "disabled TBF -> seconds = 0");
        assert_eq!(frac, 0, "disabled TBF -> fraction = 0");
    }

    /// A non-zero minimum_separation must be advertised truthfully.
    ///
    /// 100 ms = 0 full seconds + 100_000_000 ns.
    /// RTPS fraction = (100_000_000 << 32) / 1_000_000_000 = 429_496_729 (0x19999999).
    #[test]
    fn write_time_based_filter_nonzero_emits_real_duration() {
        let mut qos = QoS::reliable();
        qos.time_based_filter = TimeBasedFilter::new(Duration::from_millis(100));

        let mut buf = [0u8; 16];
        let mut offset = 0;
        write_time_based_filter(Some(&qos), &mut buf, &mut offset).expect("must succeed");

        assert_eq!(offset, 12);
        let pid = u16::from_le_bytes(buf[0..2].try_into().unwrap());
        let len = u16::from_le_bytes(buf[2..4].try_into().unwrap());
        assert_eq!(pid, 0x0004, "PID_TIME_BASED_FILTER");
        assert_eq!(len, 8, "payload length");

        let sec = u32::from_le_bytes(buf[4..8].try_into().unwrap());
        let frac = u32::from_le_bytes(buf[8..12].try_into().unwrap());
        assert_eq!(sec, 0, "100ms < 1s -> seconds = 0");

        // Round-trip: recover nanos from RTPS fraction.
        // frac = (100_000_000 << 32) / 1_000_000_000 = 429_496_729
        let recovered_nanos = ((frac as u64) * 1_000_000_000) >> 32;
        // Fractional conversion loses < 1 ns precision; allow 1 ns tolerance.
        let diff = (recovered_nanos as i64 - 100_000_000i64).unsigned_abs();
        assert!(
            diff <= 1,
            "round-trip error must be <= 1 ns, got {} ns",
            diff
        );
    }

    /// A whole-second minimum_separation (1 s, 0 ns) encodes cleanly.
    #[test]
    fn write_time_based_filter_one_second_emits_exact() {
        let mut qos = QoS::reliable();
        qos.time_based_filter = TimeBasedFilter::new(Duration::from_secs(1));

        let mut buf = [0u8; 16];
        let mut offset = 0;
        write_time_based_filter(Some(&qos), &mut buf, &mut offset).expect("must succeed");

        let sec = u32::from_le_bytes(buf[4..8].try_into().unwrap());
        let frac = u32::from_le_bytes(buf[8..12].try_into().unwrap());
        assert_eq!(sec, 1, "1 s -> seconds field = 1");
        assert_eq!(frac, 0, "0 ns -> fraction = 0");
    }

    /// Buffer too small must return ParseError::BufferTooSmall and leave offset unchanged.
    #[test]
    fn write_time_based_filter_rejects_short_buffer() {
        let mut buf = [0u8; 8]; // 4 bytes shy of the 12 required
        let mut offset = 0;
        let err = write_time_based_filter(None, &mut buf, &mut offset)
            .expect_err("must reject a buffer smaller than 12 bytes");
        assert_eq!(err, ParseError::BufferTooSmall);
        assert_eq!(offset, 0, "offset must not advance on error");
    }
}
