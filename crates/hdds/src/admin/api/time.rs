// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Timestamp utilities for Admin API (ISO 8601 formatting).

use std::convert::TryFrom;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Generate an ISO 8601 timestamp with millisecond precision in UTC.
pub(crate) fn timestamp_iso8601() -> String {
    let now = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration,
        Err(e) => {
            log::debug!(
                "[AdminApi::timestamp_iso8601] SystemTime before UNIX_EPOCH: {}",
                e
            );
            Duration::from_secs(0)
        }
    };
    let secs = now.as_secs();
    let millis = now.subsec_millis();

    let days_since_epoch = secs / 86_400;
    let remaining_secs = secs % 86_400;
    let hours = remaining_secs / 3_600;
    let minutes = (remaining_secs % 3_600) / 60;
    let seconds = remaining_secs % 60;

    let (year, month, day) = days_to_date(days_since_epoch);

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        year, month, day, hours, minutes, seconds, millis
    )
}

/// Convert days since Unix epoch (1970-01-01) to a calendar date.
pub(crate) fn days_to_date(days: u64) -> (u32, u32, u32) {
    let mut year = 1970;
    let mut remaining_days = days;

    loop {
        let days_in_year = if is_leap_year(year) { 366 } else { 365 };
        if remaining_days < days_in_year {
            break;
        }
        remaining_days -= days_in_year;
        year += 1;
    }

    let days_per_month = if is_leap_year(year) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };

    let mut month = 1;
    for &days_in_month in &days_per_month {
        if remaining_days < days_in_month as u64 {
            break;
        }
        remaining_days -= days_in_month as u64;
        month += 1;
    }

    let day = remaining_days + 1;
    #[allow(clippy::expect_used)] // day is at most 31, always fits in u32
    let day_u32 = u32::try_from(day).expect("day offset fits within u32");

    (year, month, day_u32)
}

/// Determine whether the given year is a leap year in the Gregorian calendar.
pub(crate) fn is_leap_year(year: u32) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
}
