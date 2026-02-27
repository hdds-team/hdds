// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use super::*;

#[test]
fn test_sample_state_mask() {
    assert_eq!(SampleStateMask::READ.bits(), 1);
    assert_eq!(SampleStateMask::NOT_READ.bits(), 2);
    assert!(SampleStateMask::ANY.contains(SampleStateMask::READ));
    assert!(SampleStateMask::ANY.contains(SampleStateMask::NOT_READ));
}

#[test]
fn test_view_state_mask() {
    assert_eq!(ViewStateMask::NEW.bits(), 1);
    assert_eq!(ViewStateMask::NOT_NEW.bits(), 2);
    assert!(ViewStateMask::ANY.contains(ViewStateMask::NEW));
    assert!(ViewStateMask::ANY.contains(ViewStateMask::NOT_NEW));
}

#[test]
fn test_instance_state_mask() {
    assert_eq!(InstanceStateMask::ALIVE.bits(), 1);
    assert_eq!(InstanceStateMask::NOT_ALIVE_DISPOSED.bits(), 2);
    assert_eq!(InstanceStateMask::NOT_ALIVE_NO_WRITERS.bits(), 4);
    assert!(InstanceStateMask::ANY.contains(InstanceStateMask::ALIVE));
}

#[test]
fn test_read_condition_creation() {
    let cond = ReadCondition::new(
        SampleStateMask::NOT_READ,
        ViewStateMask::NEW,
        InstanceStateMask::ALIVE,
    );

    assert_eq!(
        cond.get_sample_state_mask().bits(),
        SampleStateMask::NOT_READ.bits()
    );
    assert_eq!(cond.get_view_state_mask().bits(), ViewStateMask::NEW.bits());
    assert_eq!(
        cond.get_instance_state_mask().bits(),
        InstanceStateMask::ALIVE.bits()
    );
    assert!(!cond.get_trigger_value());
}

#[test]
fn test_read_condition_trigger() {
    let cond = ReadCondition::new(
        SampleStateMask::ANY,
        ViewStateMask::ANY,
        InstanceStateMask::ANY,
    );

    assert!(!cond.get_trigger_value());

    cond.set_trigger_value(true);
    assert!(cond.get_trigger_value());

    cond.set_trigger_value(false);
    assert!(!cond.get_trigger_value());
}

#[test]
fn test_query_condition_creation() {
    let cond = QueryCondition::new(
        SampleStateMask::NOT_READ,
        ViewStateMask::ANY,
        InstanceStateMask::ALIVE,
        "temperature > %0".to_string(),
        vec!["25.0".to_string()],
    );

    assert_eq!(cond.get_query_expression(), "temperature > %0");
    assert_eq!(cond.get_query_parameters(), vec!["25.0"]);
    assert!(!cond.get_trigger_value());
}

#[test]
fn test_query_condition_set_parameters() {
    let cond = QueryCondition::new(
        SampleStateMask::ANY,
        ViewStateMask::ANY,
        InstanceStateMask::ANY,
        "value > %0 AND value < %1".to_string(),
        vec!["10".to_string(), "20".to_string()],
    );

    assert_eq!(cond.get_query_parameters(), vec!["10", "20"]);

    cond.set_query_parameters(vec!["15".to_string(), "25".to_string()]);
    assert_eq!(cond.get_query_parameters(), vec!["15", "25"]);
}

#[test]
fn test_query_condition_trigger() {
    let cond = QueryCondition::new(
        SampleStateMask::ANY,
        ViewStateMask::ANY,
        InstanceStateMask::ANY,
        "x > 0".to_string(),
        vec![],
    );

    assert!(!cond.get_trigger_value());

    cond.set_trigger_value(true);
    assert!(cond.get_trigger_value());

    cond.set_trigger_value(false);
    assert!(!cond.get_trigger_value());
}
