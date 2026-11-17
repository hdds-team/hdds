// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use super::*;
use crate::dds::{GuardCondition, Participant, QoS, StatusCondition, StatusMask};
use crate::generated::temperature::Temperature;
use crate::test_support::domains::unique_domain;
use std::time::Duration;

#[test]
fn context_attaches_graph_guard_on_creation() {
    let domain = unique_domain();
    let context =
        RmwContext::create_with_domain("rmw_context_guard", domain.id()).expect("context");
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
    let domain = unique_domain();
    let context =
        RmwContext::create_with_domain("rmw_context_reader", domain.id()).expect("context");
    let participant = context.participant();

    let reader = participant
        .topic::<Temperature>("rmw_context_reader_topic")
        .expect("topic")
        .reader()
        .qos(QoS::best_effort())
        .build()
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
fn context_releases_intra_participant_after_endpoints_drop() {
    let context = RmwContext::from_builder(
        Participant::builder("rmw_context_intra_teardown")
            .with_transport(TransportMode::IntraProcess),
    )
    .expect("context");
    let participant = context.participant();
    let participant_weak = Arc::downgrade(&participant);

    let reader = participant
        .topic::<Temperature>("rmw_context_intra_teardown_topic")
        .expect("topic")
        .reader()
        .qos(QoS::best_effort())
        .build()
        .expect("create reader");

    drop(reader);
    drop(participant);
    drop(context);

    assert!(
        participant_weak.upgrade().is_none(),
        "RMW context teardown retained its participant"
    );
}

#[test]
fn context_releases_udp_participant() {
    let domain = unique_domain();
    let context = RmwContext::from_builder(
        Participant::builder("rmw_context_udp_teardown")
            .domain_id(domain.id())
            .with_transport(TransportMode::UdpMulticast),
    )
    .expect("context");
    let participant = context.participant();
    let participant_weak = Arc::downgrade(&participant);

    let reader = participant
        .topic::<Temperature>("rmw_context_udp_teardown_topic")
        .expect("topic")
        .reader()
        .qos(QoS::best_effort())
        .build()
        .expect("create reader");

    drop(reader);
    drop(participant);
    drop(context);

    assert!(
        participant_weak.upgrade().is_none(),
        "RMW context teardown retained its UDP participant"
    );
}

#[test]
fn context_write_read_e2e() {
    let domain = unique_domain();
    let context = RmwContext::create_with_domain("rmw_context_e2e", domain.id()).expect("context");
    let participant = context.participant();

    let writer = participant
        .topic::<Temperature>("rmw_e2e_topic")
        .expect("topic")
        .writer()
        .qos(QoS::best_effort())
        .build()
        .expect("create writer");

    let reader = participant
        .topic::<Temperature>("rmw_e2e_topic")
        .expect("topic")
        .reader()
        .qos(QoS::best_effort())
        .build()
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
    // One lease for the whole loop: sixteen sequential create/destroy cycles
    // on ONE domain is the point of this test. Sixteen leases would prove
    // nothing about teardown, and this test was the one that collided on
    // domain 0 with a sibling test mid-bootstrap (see test_support::domains).
    let domain = unique_domain();
    for idx in 0..16 {
        let name = format!("rmw_context_stress_{}", idx);
        let context = RmwContext::from_builder(Participant::builder(&name).domain_id(domain.id()))
            .expect("context");

        let reader = context
            .participant()
            .topic::<Temperature>("rmw_context_stress_topic")
            .expect("topic")
            .reader()
            .qos(QoS::best_effort())
            .build()
            .expect("create reader");

        let handle = context.attach_reader(&reader).expect("attach reader");
        handle.detach().expect("detach reader");
    }
}

/// `HDDS_DISCOVERY_PEERS` and its documented alias `HDDS_INITIAL_PEERS` must
/// BOTH reach the participant.
///
/// `crates/rmw-hdds/src/env_config.rs` documents the alias at :18 and parses
/// it at :210 as `env::var(ENV_DISCOVERY_PEERS).or_else(|_|
/// env::var(ENV_INITIAL_PEERS))`, and the parsed value was dropped on the
/// floor. Honouring only the first spelling would have closed the defect for
/// one of the two documented names and left a node started with the other one
/// discovering nobody.
///
/// The resolution is tested through its pure half on purpose: a `set_var` in a
/// lib test races every other test in the same binary, and this branch already
/// paid for that once.
#[test]
fn both_documented_peer_spellings_reach_the_participant() {
    assert_eq!(
        resolve_static_peers(Some("10.0.0.2:17160"), None).as_deref(),
        Some("10.0.0.2:17160")
    );
    assert_eq!(
        resolve_static_peers(None, Some("10.0.0.3:17160")).as_deref(),
        Some("10.0.0.3:17160"),
        "HDDS_INITIAL_PEERS is documented as an alias and must not be ignored"
    );
    // HDDS_DISCOVERY_PEERS wins when both are set, which is what
    // env_config.rs documents.
    assert_eq!(
        resolve_static_peers(Some("10.0.0.2:17160"), Some("10.0.0.3:17160")).as_deref(),
        Some("10.0.0.2:17160")
    );
    assert_eq!(resolve_static_peers(None, None), None);
    // An empty or all-blank list is not a peer list.
    assert_eq!(resolve_static_peers(Some(""), None), None);
    assert_eq!(resolve_static_peers(Some(" , "), None), None);
    assert_eq!(resolve_static_peers(Some(""), Some("10.0.0.3:17160")), None);
}

/// `HDDS_MULTICAST_DISABLE=1` is what makes the static-peer path measurable:
/// with multicast on, every peer would have been discovered anyway. The
/// variable is `env_config.rs`'s own `ENV_MULTICAST_DISABLE`, documented and
/// parsed there since it was written and applied to nothing.
#[test]
fn multicast_can_be_turned_off_for_a_ros_node() {
    for off in ["1", "true", "TRUE", " yes ", "on", "disable", "disabled"] {
        assert_eq!(
            resolve_multicast_mode(Some(off)),
            MulticastMode::Disabled,
            "{off} must turn multicast off"
        );
    }
    for on in ["0", "false", "no", "off", ""] {
        assert_eq!(resolve_multicast_mode(Some(on)), MulticastMode::Enabled);
    }
    assert_eq!(resolve_multicast_mode(None), MulticastMode::Enabled);
    // An unparseable value keeps the historical default rather than silently
    // cutting a node off the network.
    assert_eq!(
        resolve_multicast_mode(Some("maybe")),
        MulticastMode::Enabled
    );
}
