// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! OpenDDS SEDP QoS PID Writers
//!
//! Standard QoS policy PIDs for OpenDDS interoperability.

use crate::protocol::dialect::common::{cdr_length, parameter_length};
use crate::protocol::dialect::error::{EncodeError, EncodeResult};
use crate::protocol::dialect::QosProfile;

/// PID constants for QoS
mod pids {
    pub const PID_DURABILITY: u16 = 0x001d;
    pub const PID_RELIABILITY: u16 = 0x001a;
    pub const PID_HISTORY: u16 = 0x0040;
    pub const PID_DEADLINE: u16 = 0x0023;
    pub const PID_OWNERSHIP: u16 = 0x001f;
    pub const PID_OWNERSHIP_STRENGTH: u16 = 0x0006;
    pub const PID_PARTITION: u16 = 0x0029;
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
    // RTPS v2.5 Sec.9.3.2 Duration_t: the endpoint's max_blocking_time,
    // infinite for an endpoint that names none (this encoder's default).
    match qos.and_then(|q| q.reliability_max_blocking_time) {
        Some(max_blocking_time) => buf[*offset + 8..*offset + 16]
            .copy_from_slice(&crate::protocol::dialect::duration_t_le(max_blocking_time)),
        None => buf[*offset + 8..*offset + 16].copy_from_slice(&DURATION_INFINITE),
    }
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

/// Write PID_PARTITION (0x0029) - sequence of partition name strings.
///
/// Format (PL_CDR_LE): sequence_length (u32) then, for each name,
/// string_length (u32, including the NUL) + bytes + NUL + 4-byte padding.
///
/// OpenDDS interop note: the OpenDDS dialect builder previously omitted
/// PID_PARTITION entirely. Because HDDS announces a peer's reader to
/// OpenDDS via this dialect FIRST (at writer SN=1) and only re-sends the
/// generic, partition-bearing copy afterwards at the SAME SN, OpenDDS
/// deduplicates by sequence number and locks in the empty-partition view,
/// so a `p1 == p1` PARTITION RxO check fails (READER_NOT_MATCHED). Emitting
/// the partition here makes the first SEDP sample carry it.
///
/// Only emitted when at least one partition name is present: a default
/// (empty) PARTITION is the absence of the PID, matching the previous
/// behaviour for the many OpenDDS tests that use no partition.
pub fn write_partition(
    qos: Option<&QosProfile>,
    buf: &mut [u8],
    offset: &mut usize,
) -> EncodeResult<()> {
    let empty: &[String] = &[];
    let names = qos.map(|q| q.partition_names.as_slice()).unwrap_or(empty);

    if names.is_empty() {
        // Default partition: emit nothing (back-compat with non-partition tests).
        return Ok(());
    }

    // payload = seq_len (4) + for each: str_len (4) + padded(name + NUL)
    let mut payload_size: usize = 4;
    for name in names {
        let padded = (name.len() + 1 + 3) & !3;
        payload_size += 4 + padded;
    }

    if *offset + 4 + payload_size > buf.len() {
        return Err(EncodeError::BufferTooSmall);
    }

    buf[*offset..*offset + 2].copy_from_slice(&pids::PID_PARTITION.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&parameter_length(payload_size)?.to_le_bytes());
    *offset += 4;

    buf[*offset..*offset + 4].copy_from_slice(&cdr_length(names.len())?.to_le_bytes());
    *offset += 4;

    for name in names {
        let str_len = cdr_length(name.len() + 1)?; // include NUL
        buf[*offset..*offset + 4].copy_from_slice(&str_len.to_le_bytes());
        *offset += 4;

        buf[*offset..*offset + name.len()].copy_from_slice(name.as_bytes());
        *offset += name.len();
        buf[*offset] = 0; // NUL terminator
        *offset += 1;

        let pad = (4 - (name.len() + 1) % 4) % 4;
        for i in 0..pad {
            buf[*offset + i] = 0;
        }
        *offset += pad;
    }

    Ok(())
}
