// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Mask arithmetic and the detached (reader-less) constructors. The
//! reader-bound behaviour is exercised in `reader::tests_conditions`.

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
#[allow(deprecated)]
fn detached_read_condition_keeps_its_masks_and_never_triggers() {
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
    assert!(!cond.is_attached());
    assert!(!cond.get_trigger_value());
}

#[test]
#[allow(deprecated)]
fn detached_query_condition_holds_expression_and_parameters() {
    let cond = QueryCondition::new(
        SampleStateMask::NOT_READ,
        ViewStateMask::ANY,
        InstanceStateMask::ALIVE,
        "temperature > %0".to_string(),
        vec!["25.0".to_string()],
    )
    .expect("valid expression");

    assert_eq!(cond.get_query_expression(), "temperature > %0");
    assert_eq!(cond.get_query_parameters(), vec!["25.0"]);
    assert!(!cond.get_trigger_value());
    // Deref: a QueryCondition is a ReadCondition.
    assert_eq!(
        cond.get_sample_state_mask().bits(),
        SampleStateMask::NOT_READ.bits()
    );
}

#[test]
#[allow(deprecated)]
fn query_condition_parameters_are_validated_against_the_expression() {
    let cond = QueryCondition::new(
        SampleStateMask::ANY,
        ViewStateMask::ANY,
        InstanceStateMask::ANY,
        "value > %0 AND value < %1".to_string(),
        vec!["10".to_string(), "20".to_string()],
    )
    .expect("valid expression");

    cond.set_query_parameters(vec!["15".to_string(), "25".to_string()]);
    assert_eq!(cond.get_query_parameters(), vec!["15", "25"]);

    // One parameter for a two-parameter expression: rejected, old ones kept.
    assert!(cond
        .try_set_query_parameters(vec!["1".to_string()])
        .is_err());
    assert_eq!(cond.get_query_parameters(), vec!["15", "25"]);

    // An expression that does not parse yields no condition at all.
    assert!(QueryCondition::new(
        SampleStateMask::ANY,
        ViewStateMask::ANY,
        InstanceStateMask::ANY,
        "value >>> 1".to_string(),
        vec![],
    )
    .is_none());
}

#[test]
#[allow(deprecated)]
fn condition_ids_are_unique_and_shared_through_deref() {
    let a = ReadCondition::new(
        SampleStateMask::ANY,
        ViewStateMask::ANY,
        InstanceStateMask::ANY,
    );
    let b = QueryCondition::new(
        SampleStateMask::ANY,
        ViewStateMask::ANY,
        InstanceStateMask::ANY,
        "x > 0".to_string(),
        vec![],
    )
    .expect("valid expression");
    assert_ne!(a.condition_id(), b.condition_id());
    let inner: &ReadCondition = &b;
    assert_eq!(inner.condition_id(), Condition::condition_id(&b));
}
