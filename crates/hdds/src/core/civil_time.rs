// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! One proleptic-Gregorian UTC calendar, for every caller that needs one.
//!
//! Proleptic Gregorian UTC and nothing else: no zones, no locales, no leap
//! seconds (Unix time has none). Hand-rolled rather than pulling `chrono`,
//! because two callers need six integers and neither needs a calendar
//! library.
//!
//! # Why it lives here and not next to one caller
//!
//! Its callers are `discovery::cloud::aws_sigv4`, which is behind the
//! `cloud-discovery` feature, and the RFC 5424 audit export in
//! `security::audit`, which is not. A shared, ungated home avoids two copies
//! of the same year-and-month walk, and duplicated logic drifts: a fix lands
//! in one copy while the identical line sits untouched in the other. One walk,
//! two callers, each formatting at its own site.

/// Days in each month of a non-leap year.
const MONTH_DAYS: [u32; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

/// The last instant a four-digit year can express: 9999-12-31T23:59:59Z.
///
/// `date -u -d @253402300799` prints it; one second later is year 10000,
/// which needs five year digits and renders a date neither RFC 3339 nor
/// SigV4 accepts.
pub const MAX_FORMATTABLE_UNIX_SECONDS: u64 = 253_402_300_799;

/// A civil date and time, UTC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CivilTime {
    pub year: u32,
    pub month: u32,
    pub day: u32,
    pub hour: u64,
    pub minute: u64,
    pub second: u64,
}

/// True for a leap year in the proleptic Gregorian calendar.
#[must_use]
pub fn is_leap(year: u32) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
}

/// Split a Unix timestamp into its civil UTC components.
///
/// A timestamp past [`MAX_FORMATTABLE_UNIX_SECONDS`] SATURATES there. The
/// walk counts days from the epoch, and `u64::MAX` seconds is
/// 213_503_982_334_601 days - 49_710 times what a `u32` holds - so an
/// unsaturated count would be truncated into a plausible-looking WRONG date,
/// and without the truncation the year loop would walk some 584 billion
/// years. Saturating at the largest instant the output can express is
/// the only answer that is neither a wrap nor a hang; every value this is ever
/// asked about is below it by more than seven thousand years.
#[must_use]
pub fn civil_from_unix_seconds(unix_seconds: u64) -> CivilTime {
    let unix_seconds = unix_seconds.min(MAX_FORMATTABLE_UNIX_SECONDS);
    let days = unix_seconds / 86_400;
    let secs_of_day = unix_seconds % 86_400;

    // Walk years then months from the epoch. The range this is ever asked
    // about is "now", a few decades at most; the saturation above caps it at
    // 8029 iterations for any input at all. The day count stays a u64 the
    // whole way down - there is no width to narrow to, nothing to truncate.
    let mut year = 1970u32;
    let mut remaining: u64 = days;
    loop {
        let year_days: u64 = if is_leap(year) { 366 } else { 365 };
        if remaining < year_days {
            break;
        }
        remaining -= year_days;
        year += 1;
    }
    let mut month = 1u32;
    for (index, base) in MONTH_DAYS.iter().enumerate() {
        let month_days = u64::from(*base) + u64::from(index == 1 && is_leap(year));
        if remaining < month_days {
            break;
        }
        remaining -= month_days;
        month += 1;
    }

    CivilTime {
        year,
        month,
        day: u32::try_from(remaining + 1).unwrap_or(1),
        hour: secs_of_day / 3_600,
        minute: (secs_of_day % 3_600) / 60,
        second: secs_of_day % 60,
    }
}

/// Render a Unix timestamp as RFC 3339 UTC, `YYYY-MM-DDTHH:MM:SSZ`.
///
/// The form RFC 5424 Sec.6.2.3 requires of a syslog TIMESTAMP field.
#[must_use]
pub fn rfc3339_utc(unix_seconds: u64) -> String {
    let t = civil_from_unix_seconds(unix_seconds);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        t.year, t.month, t.day, t.hour, t.minute, t.second
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Anchors from `date -u -d @N`, so the walk is checked against something
    /// that is not itself.
    #[test]
    fn known_instants_render_as_date_prints_them() {
        assert_eq!(rfc3339_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339_utc(1), "1970-01-01T00:00:01Z");
        // A recent instant. Every anchor here comes from `date -u -d`.
        assert_eq!(rfc3339_utc(1_789_995_996), "2026-09-21T13:06:36Z");
        // A leap day, and the day after it.
        assert_eq!(rfc3339_utc(1_709_164_800), "2024-02-29T00:00:00Z");
        assert_eq!(rfc3339_utc(1_709_251_200), "2024-03-01T00:00:00Z");
        // 2000 is a leap year (divisible by 400), 1900 would not be.
        assert_eq!(rfc3339_utc(951_782_400), "2000-02-29T00:00:00Z");
    }

    #[test]
    fn leap_years_follow_the_gregorian_rule() {
        assert!(is_leap(2024) && is_leap(2000) && is_leap(2400));
        assert!(!is_leap(2023) && !is_leap(1900) && !is_leap(2100));
    }

    /// Past the last four-digit year the result SATURATES rather than
    /// wrapping into a plausible wrong date or walking for hours.
    #[test]
    fn a_timestamp_past_year_9999_saturates() {
        assert_eq!(
            rfc3339_utc(MAX_FORMATTABLE_UNIX_SECONDS),
            "9999-12-31T23:59:59Z"
        );
        assert_eq!(rfc3339_utc(u64::MAX), "9999-12-31T23:59:59Z");
    }
}
