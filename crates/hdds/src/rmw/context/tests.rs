// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use super::*;
use crate::dds::{GuardCondition, Participant, QoS, StatusCondition, StatusMask};
use crate::generated::temperature::Temperature;
use std::time::Duration;

#[test]
fn context_attaches_graph_guard_on_creation() {
    let context = RmwContext::create("rmw_context_guard").expect("context");
    let guard_key = context.graph_guard_key();

    let guard = context.graph_guard_condition();
    guard.set_trigger_value(true);

    let triggered = context.wait(Some(Duration::from_millis(20))).expect("wait");
    assert_eq!(triggered, vec![guard_key]);

    let condition = context
        .waitset()
        .condition(guard_key)
        .expect("registered condition");
    assert!(
        condition.as_any().is::<GuardCondition>(),
        "expected guard condition from registry"
    );
}

#[test]
fn context_can_attach_reader_status() {
    let context = RmwContext::create("rmw_context_reader").expect("context");
    let participant = context.participant();

    let reader = participant
        .create_reader::<Temperature>("rmw_context_reader_topic", QoS::best_effort())
        .expect("create reader");

    let handle = context.attach_reader(&reader).expect("attach reader");

    let status = reader.get_status_condition();
    status.set_enabled_statuses(StatusMask::DATA_AVAILABLE);
    status.set_active_statuses(StatusMask::DATA_AVAILABLE);

    // Reset graph_guard triggered by reader creation (test focuses on reader status only)
    context.graph_guard_condition().set_trigger_value(false);

    let triggered = context.wait(Some(Duration::from_millis(20))).expect("wait");
    assert_eq!(triggered, vec![handle.key()]);

    let condition = context
        .waitset()
        .condition(handle.key())
        .expect("registered condition");
    assert!(
        condition.as_any().is::<StatusCondition>(),
        "expected status condition from registry"
    );
}

#[test]
fn context_write_read_e2e() {
    let context = RmwContext::create("rmw_context_e2e").expect("context");
    let participant = context.participant();

    let writer = participant
        .create_writer::<Temperature>("rmw_e2e_topic", QoS::best_effort())
        .expect("create writer");

    let reader = participant
        .create_reader::<Temperature>("rmw_e2e_topic", QoS::best_effort())
        .expect("create reader");

    let handle = context.attach_reader(&reader).expect("attach reader");

    let status = reader.get_status_condition();
    status.set_enabled_statuses(StatusMask::DATA_AVAILABLE);

    // Reset graph_guard triggered by writer/reader creation
    context.graph_guard_condition().set_trigger_value(false);

    // Write data
    let sample = Temperature {
        value: 36.6,
        timestamp: 42,
    };
    writer.write(&sample).expect("write");

    // Wait for data
    let triggered = context
        .wait(Some(Duration::from_millis(500)))
        .expect("wait should not fail");
    assert!(
        triggered.contains(&handle.key()),
        "reader status condition should trigger on DATA_AVAILABLE, got: {:?}",
        triggered
    );

    // Read data back
    let received = reader.take().expect("take");
    assert!(received.is_some(), "should receive a sample");
    let sample = received.unwrap();
    assert_eq!(sample.timestamp, 42);
    assert!((sample.value - 36.6).abs() < 0.01);
}

#[test]
fn context_waitset_stress_create_destroy() {
    for idx in 0..16 {
        let name = format!("rmw_context_stress_{}", idx);
        let context = RmwContext::from_builder(Participant::builder(&name)).expect("context");

        let reader = context
            .participant()
            .create_reader::<Temperature>("rmw_context_stress_topic", QoS::best_effort())
            .expect("create reader");

        let handle = context.attach_reader(&reader).expect("attach reader");
        handle.detach().expect("detach reader");
    }
}
