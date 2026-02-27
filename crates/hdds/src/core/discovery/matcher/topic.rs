// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Topic and type ID matching utilities.
//!
//! Provides matching for endpoint discovery:
//! - Topic name: supports exact match and MQTT-style wildcards
//! - Type ID: FNV-1a hash equality (fast 32-bit comparison)
//!
//! # Wildcard Syntax
//!
//! - `+` matches exactly one topic level (any characters except `/`)
//! - `#` matches zero or more topic levels (must be at end of pattern)
//!
//! # Examples
//!
//! ```text
//! Pattern "sensors/+/temperature" matches:
//!   "sensors/room1/temperature"
//!   "sensors/room2/temperature"
//! But NOT:
//!   "sensors/room1/humidity"
//!   "sensors/building/room1/temperature"
//!
//! Pattern "sensors/#" matches:
//!   "sensors/room1/temperature"
//!   "sensors/building/room1/humidity"
//!   "sensors"
//! ```

/// Check if a reader topic pattern matches a writer topic.
///
/// The reader topic may contain MQTT-style wildcards:
/// - `+` matches a single level
/// - `#` matches zero or more levels (must be at end)
///
/// The writer topic must be a concrete topic name (no wildcards).
pub(super) fn is_topic_match(reader_topic: &str, writer_topic: &str) -> bool {
    if reader_topic.is_empty() || writer_topic.is_empty() {
        return false;
    }

    // Fast path: exact match
    if reader_topic == writer_topic {
        return true;
    }

    // Check for wildcards in reader pattern
    if !reader_topic.contains('+') && !reader_topic.contains('#') {
        return false; // No wildcards and not exact match
    }

    topic_pattern_match(reader_topic, writer_topic)
}

/// Match a topic pattern against a concrete topic name.
///
/// Pattern segments:
/// - `+` matches exactly one segment
/// - `#` matches zero or more remaining segments (must be last)
/// - Any other segment requires exact match
fn topic_pattern_match(pattern: &str, topic: &str) -> bool {
    let pattern_segments: Vec<&str> = pattern.split('/').collect();
    let topic_segments: Vec<&str> = topic.split('/').collect();

    let mut pi = 0; // pattern index
    let mut ti = 0; // topic index

    while pi < pattern_segments.len() {
        let pat = pattern_segments[pi];

        if pat == "#" {
            // # must be the last segment and matches everything remaining
            return pi == pattern_segments.len() - 1;
        }

        if ti >= topic_segments.len() {
            // Topic has fewer segments than pattern requires
            return false;
        }

        if pat == "+" {
            // + matches exactly one segment (any non-empty value)
            // Just advance both indices
        } else if pat != topic_segments[ti] {
            // Literal segment must match exactly
            return false;
        }

        pi += 1;
        ti += 1;
    }

    // Pattern consumed - topic must also be fully consumed
    ti == topic_segments.len()
}

pub(super) fn is_type_match(reader_type_id: u32, writer_type_id: u32) -> bool {
    reader_type_id == writer_type_id
}
