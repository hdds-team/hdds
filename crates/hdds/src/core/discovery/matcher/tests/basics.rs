// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use super::*;
use crate::dds::qos::QoS;

#[test]
fn test_matcher_qos_compatible_history_equal() {
    let reader_qos = QoS::best_effort().keep_last(100);
    let writer_qos = QoS::best_effort().keep_last(100);

    assert!(Matcher::is_compatible(&reader_qos, &writer_qos));
}

#[test]
fn test_matcher_qos_compatible_reader_less() {
    let reader_qos = QoS::best_effort().keep_last(50);
    let writer_qos = QoS::best_effort().keep_last(100);

    assert!(Matcher::is_compatible(&reader_qos, &writer_qos)); // 50 <= 100 -> OK
}

#[test]
fn test_matcher_qos_incompatible_reader_greater() {
    let reader_qos = QoS::best_effort().keep_last(200);
    let writer_qos = QoS::best_effort().keep_last(100);

    assert!(!Matcher::is_compatible(&reader_qos, &writer_qos)); // 200 > 100 -> REJECT
}

#[test]
fn test_matcher_qos_compatible_reader_one() {
    let reader_qos = QoS::best_effort().keep_last(1);
    let writer_qos = QoS::best_effort().keep_last(100);

    assert!(Matcher::is_compatible(&reader_qos, &writer_qos)); // 1 <= 100 -> OK
}

#[test]
fn test_matcher_topic_match_exact() {
    assert!(Matcher::is_topic_match(
        "sensor/temperature",
        "sensor/temperature"
    ));
}

#[test]
fn test_matcher_topic_no_match() {
    assert!(!Matcher::is_topic_match(
        "sensor/temperature",
        "sensor/humidity"
    ));
}

#[test]
fn test_matcher_topic_no_match_case_sensitive() {
    assert!(!Matcher::is_topic_match(
        "sensor/temperature",
        "Sensor/Temperature"
    ));
}

#[test]
fn test_matcher_topic_empty() {
    assert!(!Matcher::is_topic_match("", ""));
}

#[test]
fn test_matcher_type_id_match() {
    let reader_type_id = make_type_id(0x1234_5678);
    let writer_type_id = make_type_id(0x1234_5678);

    assert!(Matcher::is_type_match(reader_type_id, writer_type_id));
}

#[test]
fn test_matcher_type_id_no_match() {
    let reader_type_id = make_type_id(0x1234_5678);
    let writer_type_id = make_type_id(0xDEAD_BEEF);

    assert!(!Matcher::is_type_match(reader_type_id, writer_type_id));
}

#[test]
fn test_matcher_type_id_zero() {
    let reader_type_id = 0_u32;
    let writer_type_id = 0_u32;

    assert!(Matcher::is_type_match(reader_type_id, writer_type_id));
}

#[test]
fn test_matcher_full_check_compatible() {
    let reader_topic = "sensor/temp";
    let writer_topic = "sensor/temp";

    let reader_type_id = make_type_id(0xAAAA_BBBB);
    let writer_type_id = make_type_id(0xAAAA_BBBB);

    let reader_qos = QoS::best_effort().keep_last(10);
    let writer_qos = QoS::best_effort().keep_last(20);

    let topic_ok = Matcher::is_topic_match(reader_topic, writer_topic);
    let type_ok = Matcher::is_type_match(reader_type_id, writer_type_id);
    let qos_ok = Matcher::is_compatible(&reader_qos, &writer_qos);

    assert!(topic_ok && type_ok && qos_ok);
}

#[test]
fn test_matcher_full_check_incompatible_topic() {
    let reader_topic = "sensor/temp";
    let writer_topic = "sensor/humidity";

    let reader_type_id = make_type_id(0xAAAA_BBBB);
    let writer_type_id = make_type_id(0xAAAA_BBBB);

    let reader_qos = QoS::best_effort().keep_last(10);
    let writer_qos = QoS::best_effort().keep_last(20);

    let topic_ok = Matcher::is_topic_match(reader_topic, writer_topic);
    let type_ok = Matcher::is_type_match(reader_type_id, writer_type_id);
    let qos_ok = Matcher::is_compatible(&reader_qos, &writer_qos);

    assert!(!(topic_ok && type_ok && qos_ok)); // Topic mismatch
}

#[test]
fn test_matcher_full_check_incompatible_qos() {
    let reader_topic = "sensor/temp";
    let writer_topic = "sensor/temp";

    let reader_type_id = make_type_id(0xAAAA_BBBB);
    let writer_type_id = make_type_id(0xAAAA_BBBB);

    let reader_qos = QoS::best_effort().keep_last(10);
    let writer_qos = QoS::best_effort().keep_last(5);

    let topic_ok = Matcher::is_topic_match(reader_topic, writer_topic);
    let type_ok = Matcher::is_type_match(reader_type_id, writer_type_id);
    let qos_ok = Matcher::is_compatible(&reader_qos, &writer_qos);

    assert!(!(topic_ok && type_ok && qos_ok)); // QoS incompatible
}

fn make_type_id(seed: u32) -> u32 {
    seed
}

// ============================================================================
// Topic Wildcard Tests
// ============================================================================

#[test]
fn test_wildcard_single_level_match() {
    // + matches exactly one level
    assert!(Matcher::is_topic_match(
        "sensors/+/temperature",
        "sensors/room1/temperature"
    ));
    assert!(Matcher::is_topic_match(
        "sensors/+/temperature",
        "sensors/kitchen/temperature"
    ));
}

#[test]
fn test_wildcard_single_level_no_match_multi_level() {
    // + does NOT match multiple levels
    assert!(!Matcher::is_topic_match(
        "sensors/+/temperature",
        "sensors/building/room1/temperature"
    ));
}

#[test]
fn test_wildcard_single_level_no_match_wrong_suffix() {
    assert!(!Matcher::is_topic_match(
        "sensors/+/temperature",
        "sensors/room1/humidity"
    ));
}

#[test]
fn test_wildcard_multi_level_match() {
    // # matches zero or more levels (must be at end)
    assert!(Matcher::is_topic_match("sensors/#", "sensors"));
    assert!(Matcher::is_topic_match("sensors/#", "sensors/room1"));
    assert!(Matcher::is_topic_match(
        "sensors/#",
        "sensors/room1/temperature"
    ));
    assert!(Matcher::is_topic_match(
        "sensors/#",
        "sensors/building/room1/temperature"
    ));
}

#[test]
fn test_wildcard_multi_level_root() {
    // # at root matches everything
    assert!(Matcher::is_topic_match("#", "sensors"));
    assert!(Matcher::is_topic_match("#", "sensors/room1/temperature"));
}

#[test]
fn test_wildcard_multi_level_no_match_prefix() {
    // # must match from the pattern prefix
    assert!(!Matcher::is_topic_match("sensors/#", "actuators/valve1"));
}

#[test]
fn test_wildcard_combined() {
    // + and # combined
    assert!(Matcher::is_topic_match("sensors/+/#", "sensors/room1"));
    assert!(Matcher::is_topic_match(
        "sensors/+/#",
        "sensors/room1/temperature"
    ));
    assert!(Matcher::is_topic_match(
        "sensors/+/#",
        "sensors/room1/temperature/value"
    ));
}

#[test]
fn test_wildcard_multiple_single_level() {
    // Multiple + wildcards
    assert!(Matcher::is_topic_match(
        "+/+/temperature",
        "building/room1/temperature"
    ));
    assert!(!Matcher::is_topic_match(
        "+/+/temperature",
        "building/floor1/room1/temperature"
    ));
}

#[test]
fn test_wildcard_at_start() {
    assert!(Matcher::is_topic_match(
        "+/temperature",
        "room1/temperature"
    ));
    assert!(Matcher::is_topic_match(
        "+/temperature",
        "kitchen/temperature"
    ));
    assert!(!Matcher::is_topic_match(
        "+/temperature",
        "building/room1/temperature"
    ));
}

#[test]
fn test_no_wildcard_in_writer() {
    // Writer topics are concrete, wildcards in writer are literal
    // Reader exact match should fail against writer with literal +
    assert!(!Matcher::is_topic_match(
        "sensors/room1/temperature",
        "sensors/+/temperature"
    ));
}
