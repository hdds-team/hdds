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
    PID_DEADLINE, PID_DURABILITY, PID_DURABILITY_SERVICE, PID_HISTORY, PID_LIVELINESS,
    PID_OWNERSHIP, PID_PARTITION, PID_PRESENTATION, PID_RELIABILITY, PID_RESOURCE_LIMITS,
    PID_TIME_BASED_FILTER,
};
use super::super::super::types::ParseError;
use crate::dds::qos::{Durability, History, PresentationAccessScope, QoS, Reliability};

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
    buf[*offset + 8..*offset + 12].copy_from_slice(&0u32.to_le_bytes()); // max_blocking_time.sec = 0
    buf[*offset + 12..*offset + 16].copy_from_slice(&100_000_000u32.to_le_bytes()); // max_blocking_time.nanosec = 100ms
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
            Durability::Persistent => 3u32,
        }
    } else {
        0u32 // Default: VOLATILE for RTI compatibility
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
        (0u32, 10u32) // Default: KEEP_LAST(10) for RTI compatibility
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
/// Default: INFINITE (DDS spec: seconds=0x7FFFFFFF, nanosec=0xFFFFFFFF).
pub fn write_deadline(buf: &mut [u8], offset: &mut usize) -> Result<(), ParseError> {
    if *offset + 12 > buf.len() {
        return Err(ParseError::BufferTooSmall);
    }

    // DDS Duration_t INFINITE = { 0x7FFFFFFF, 0xFFFFFFFF }
    // FastDDS interprets u32::MAX (0xFFFFFFFF) for seconds as a concrete value (~136 years),
    // not INFINITE. Using 0x7FFFFFFF (i32::MAX) for seconds is the standard representation.
    buf[*offset..*offset + 2].copy_from_slice(&PID_DEADLINE.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&8u16.to_le_bytes());
    buf[*offset + 4..*offset + 8].copy_from_slice(&0x7FFFFFFFu32.to_le_bytes()); // period.sec = INFINITE
    buf[*offset + 8..*offset + 12].copy_from_slice(&0xFFFFFFFFu32.to_le_bytes()); // period.nanosec = INFINITE
    *offset += 12;

    Ok(())
}

/// Write PID_OWNERSHIP (0x001f) - 4 bytes.
/// Format: kind (u32).
/// Default: SHARED (kind=0).
pub fn write_ownership(buf: &mut [u8], offset: &mut usize) -> Result<(), ParseError> {
    if *offset + 8 > buf.len() {
        return Err(ParseError::BufferTooSmall);
    }

    buf[*offset..*offset + 2].copy_from_slice(&PID_OWNERSHIP.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&4u16.to_le_bytes());
    buf[*offset + 4..*offset + 8].copy_from_slice(&0u32.to_le_bytes()); // SHARED (0)
    *offset += 8;

    Ok(())
}

/// Write PID_LIVELINESS (0x001b) - 12 bytes.
/// Format: kind (u32) + lease_duration (Duration_t = 2xu32).
/// Default: AUTOMATIC (kind=0), lease_duration=INFINITE.
pub fn write_liveliness(buf: &mut [u8], offset: &mut usize) -> Result<(), ParseError> {
    if *offset + 16 > buf.len() {
        return Err(ParseError::BufferTooSmall);
    }

    // DDS Duration_t INFINITE = { 0x7FFFFFFF, 0xFFFFFFFF }
    // FastDDS interprets u32::MAX (0xFFFFFFFF) for seconds as a concrete value (~136 years),
    // not INFINITE. Using 0x7FFFFFFF (i32::MAX) for seconds is the standard representation.
    buf[*offset..*offset + 2].copy_from_slice(&PID_LIVELINESS.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&12u16.to_le_bytes());
    buf[*offset + 4..*offset + 8].copy_from_slice(&0u32.to_le_bytes()); // AUTOMATIC (0)
    buf[*offset + 8..*offset + 12].copy_from_slice(&0x7FFFFFFFu32.to_le_bytes()); // lease_duration.sec = INFINITE
    buf[*offset + 12..*offset + 16].copy_from_slice(&0xFFFFFFFFu32.to_le_bytes()); // lease_duration.nanosec = INFINITE
    *offset += 16;

    Ok(())
}

/// Write PID_TIME_BASED_FILTER (0x0004) - 8 bytes.
/// Format: minimum_separation (Duration_t = 2xu32).
/// Default: 0 (no filtering).
pub fn write_time_based_filter(buf: &mut [u8], offset: &mut usize) -> Result<(), ParseError> {
    if *offset + 12 > buf.len() {
        return Err(ParseError::BufferTooSmall);
    }

    buf[*offset..*offset + 2].copy_from_slice(&PID_TIME_BASED_FILTER.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&8u16.to_le_bytes());
    buf[*offset + 4..*offset + 8].copy_from_slice(&0u32.to_le_bytes()); // minimum_separation.sec = 0
    buf[*offset + 8..*offset + 12].copy_from_slice(&0u32.to_le_bytes()); // minimum_separation.nanosec = 0
    *offset += 12;

    Ok(())
}

/// Write PID_PARTITION (0x0029) - empty sequence.
/// Format: sequence_length (u32).
/// Default: empty (no partitions).
pub fn write_partition(buf: &mut [u8], offset: &mut usize) -> Result<(), ParseError> {
    if *offset + 8 > buf.len() {
        return Err(ParseError::BufferTooSmall);
    }

    buf[*offset..*offset + 2].copy_from_slice(&PID_PARTITION.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&4u16.to_le_bytes());
    buf[*offset + 4..*offset + 8].copy_from_slice(&0u32.to_le_bytes()); // sequence_length = 0 (empty)
    *offset += 8;

    Ok(())
}

/// Write PID_RESOURCE_LIMITS (0x0041) - 12 bytes.
/// Format: max_samples (u32) + max_instances (u32) + max_samples_per_instance (u32).
/// Default: 1000, 100, 100.
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
        let max_samples =
            u32::try_from(limits.max_samples).map_err(|_| ParseError::InvalidFormat)?;
        let max_instances =
            u32::try_from(limits.max_instances).map_err(|_| ParseError::InvalidFormat)?;
        let max_samples_per_instance = u32::try_from(limits.max_samples_per_instance)
            .map_err(|_| ParseError::InvalidFormat)?;
        (max_samples, max_instances, max_samples_per_instance)
    } else {
        (1000u32, 100u32, 100u32)
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

    // Convert cleanup delay from microseconds to Duration_t (seconds + nanoseconds)
    let cleanup_secs = (ds.service_cleanup_delay_us / 1_000_000).min(u32::MAX as u64) as u32;
    // Modulo guarantees < 1_000_000, multiply by 1000 guarantees < 1_000_000_000 (fits in u32)
    let cleanup_nsecs =
        ((ds.service_cleanup_delay_us % 1_000_000) * 1_000).min(u32::MAX as u64) as u32;

    // History kind: KEEP_LAST=0 (DurabilityService always uses KEEP_LAST)
    let history_kind = 0u32;

    buf[*offset..*offset + 2].copy_from_slice(&PID_DURABILITY_SERVICE.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&28u16.to_le_bytes());
    buf[*offset + 4..*offset + 8].copy_from_slice(&cleanup_secs.to_le_bytes());
    buf[*offset + 8..*offset + 12].copy_from_slice(&cleanup_nsecs.to_le_bytes());
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
