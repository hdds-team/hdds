// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use super::*;

#[test]
fn test_status_mask_bits() {
    assert_eq!(StatusMask::NONE.bits(), 0);
    assert_eq!(StatusMask::DATA_AVAILABLE.bits(), 1);
    assert_eq!(StatusMask::SAMPLE_LOST.bits(), 2);
}

#[test]
fn test_status_mask_contains() {
    let mask = StatusMask::DATA_AVAILABLE | StatusMask::SAMPLE_LOST;
    assert!(mask.contains(StatusMask::DATA_AVAILABLE));
    assert!(mask.contains(StatusMask::SAMPLE_LOST));
    assert!(!mask.contains(StatusMask::LIVELINESS_CHANGED));
}

#[test]
fn test_status_mask_or() {
    let mask1 = StatusMask::DATA_AVAILABLE;
    let mask2 = StatusMask::SAMPLE_LOST;
    let combined = mask1 | mask2;
    assert!(combined.contains(StatusMask::DATA_AVAILABLE));
    assert!(combined.contains(StatusMask::SAMPLE_LOST));
}

#[test]
fn test_status_mask_and() {
    let mask1 = StatusMask::DATA_AVAILABLE | StatusMask::SAMPLE_LOST;
    let mask2 = StatusMask::DATA_AVAILABLE | StatusMask::LIVELINESS_CHANGED;
    let intersection = mask1 & mask2;
    assert!(intersection.contains(StatusMask::DATA_AVAILABLE));
    assert!(!intersection.contains(StatusMask::SAMPLE_LOST));
    assert!(!intersection.contains(StatusMask::LIVELINESS_CHANGED));
}

#[test]
fn test_status_condition_default() {
    let cond = StatusCondition::new();
    assert!(!cond.get_trigger_value());
    assert_eq!(cond.get_enabled_statuses().bits(), 0);
    assert_eq!(cond.get_active_statuses().bits(), 0);
}

#[test]
fn test_status_condition_set_enabled() {
    let cond = StatusCondition::new();
    cond.set_enabled_statuses(StatusMask::DATA_AVAILABLE);
    assert_eq!(
        cond.get_enabled_statuses().bits(),
        StatusMask::DATA_AVAILABLE.bits()
    );
}

#[test]
fn test_status_condition_trigger() {
    let cond = StatusCondition::new();
    cond.set_enabled_statuses(StatusMask::DATA_AVAILABLE);
    assert!(!cond.get_trigger_value());

    cond.set_active_statuses(StatusMask::DATA_AVAILABLE);
    assert!(cond.get_trigger_value());

    cond.clear_active_statuses();
    assert!(!cond.get_trigger_value());
}

#[test]
fn test_status_condition_multiple_statuses() {
    let cond = StatusCondition::new();
    cond.set_enabled_statuses(StatusMask::DATA_AVAILABLE | StatusMask::LIVELINESS_CHANGED);

    cond.set_active_statuses(StatusMask::DATA_AVAILABLE);
    assert!(cond.get_trigger_value());

    cond.set_active_statuses(StatusMask::LIVELINESS_CHANGED);
    assert!(cond.get_trigger_value());

    cond.set_active_statuses(StatusMask::SAMPLE_LOST);
    assert!(!cond.get_trigger_value());
}

#[test]
fn test_guard_condition_default() {
    let guard = GuardCondition::new();
    assert!(!guard.get_trigger_value());
}

#[test]
fn test_guard_condition_set_trigger() {
    let guard = GuardCondition::new();

    guard.set_trigger_value(true);
    assert!(guard.get_trigger_value());

    guard.set_trigger_value(false);
    assert!(!guard.get_trigger_value());
}

#[test]
fn test_condition_ids_unique() {
    let cond1 = StatusCondition::new();
    let cond2 = StatusCondition::new();
    let guard1 = GuardCondition::new();
    let guard2 = GuardCondition::new();

    assert_ne!(cond1.condition_id(), cond2.condition_id());
    assert_ne!(guard1.condition_id(), guard2.condition_id());
}
