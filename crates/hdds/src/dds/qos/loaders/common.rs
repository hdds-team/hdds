// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Common utilities for QoS XML loaders.

use std::time::Duration;

/// Parse duration from XML `<sec>` and `<nanosec>` elements.
///
/// Handles special values like "DURATION_INFINITY".
pub fn parse_duration(sec_text: Option<&str>, nanosec_text: Option<&str>) -> Duration {
    match (sec_text, nanosec_text) {
        (Some("DURATION_INFINITY"), _) | (_, Some("DURATION_INFINITY")) => Duration::MAX,
        (Some(s), Some(ns)) => {
            let secs = s.parse::<u64>().unwrap_or(0);
            let nanos = ns.parse::<u32>().unwrap_or(0);
            Duration::new(secs, nanos)
        }
        (Some(s), None) => Duration::from_secs(s.parse::<u64>().unwrap_or(0)),
        _ => Duration::ZERO,
    }
}

/// Parse duration from nanoseconds.
pub fn duration_to_nanos(dur: Duration) -> u64 {
    if dur == Duration::MAX {
        u64::MAX
    } else {
        dur.as_nanos() as u64
    }
}
