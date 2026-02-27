// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use super::*;
use crate::dds::{GuardCondition, Participant, QoS, StatusCondition, StatusMask};
use crate::generated::temperature::Temperature;
use std::time::Duration;

#[test]
fn waitset_triggers_on_participant_guard() {
    let participant = Participant::builder("rmw_waitset_guard_test")
        .build()
        .expect("participant");
    let waitset = RmwWaitSet::new();

    let handle = waitset
        .attach_participant(&participant)
        .expect("attach participant guard");

    let guard = participant.graph_guard();
    guard.set_trigger_value(true);

    let triggered = waitset
        .wait(Some(Duration::from_millis(20)))
        .expect("wait trigger");
    assert_eq!(triggered, vec![handle.key()]);

    let condition = waitset
        .condition(handle.key())
        .expect("registered condition");
    assert!(
        condition.as_any().is::<GuardCondition>(),
        "expected guard condition back from registry"
    );

    handle.detach().expect("detach guard");
}

#[test]
fn waitset_triggers_on_reader_status() {
    let participant = Participant::builder("rmw_waitset_reader_test")
        .build()
        .expect("participant");
    let reader = participant
        .create_reader::<Temperature>("rmw_waitset_reader", QoS::best_effort())
        .expect("create reader");

    let waitset = RmwWaitSet::new();
    let handle = waitset.attach_reader(&reader).expect("attach reader");

    let status = reader.get_status_condition();
    status.set_enabled_statuses(StatusMask::DATA_AVAILABLE);
    status.set_active_statuses(StatusMask::DATA_AVAILABLE);

    let triggered = waitset
        .wait(Some(Duration::from_millis(20)))
        .expect("wait trigger");
    assert_eq!(triggered, vec![handle.key()]);

    let condition = waitset
        .condition(handle.key())
        .expect("registered condition");
    assert!(
        condition.as_any().is::<StatusCondition>(),
        "expected status condition back from registry"
    );

    handle.detach().expect("detach status");
}
