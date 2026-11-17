// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! The match registry's installation in participant setup: it comes before
//! any discovery step that consults the registry (`order_probe`), and the
//! samples of the writers the installation judges are woken by it.

use super::order_probe;
use crate::core::discovery::multicast::DiscoveryFsm;
use crate::core::discovery::GUID;
use crate::dds::match_notification::MatchNotificationRegistry;
use crate::engine::{Subscriber, TopicRegistry};
use crate::protocol::discovery::{SedpData, SpdpData};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

const TOPIC: &str = "install_topic";
const OUR_PREFIX: [u8; 12] = [0x01; 12];
const REMOTE_PREFIX: [u8; 12] = [0x0E; 12];

fn spdp(prefix: [u8; 12]) -> SpdpData {
    SpdpData {
        participant_guid: GUID::new(prefix, [0x00, 0x00, 0x01, 0xC1]),
        lease_duration_ms: 100_000,
        domain_id: 0,
        metatraffic_unicast_locators: vec![],
        default_unicast_locators: vec![],
        default_multicast_locators: vec![],
        metatraffic_multicast_locators: vec![],
        identity_token: None,
        permissions_token: None,
        participant_security_info: None,
        vendor_id: None,
        hdds_capabilities: None,
        builtin_endpoint_set: None,
    }
}

fn writer_announcement(writer: GUID) -> SedpData {
    SedpData {
        topic_name: TOPIC.to_string(),
        type_name: "Simple".to_string(),
        participant_guid: GUID::new(writer.prefix, [0x00, 0x00, 0x01, 0xC1]),
        endpoint_guid: writer,
        qos_hash: 1,
        qos: Some(crate::dds::QoS::best_effort()),
        type_object: None,
        dependents: Vec::new(),
        type_object_legacy_v1: false,
        unicast_locators: vec![],
        user_data: None,
        shm_capability: None,
        has_explicit_reliability: true,
        has_explicit_ownership: false,
        has_ownership_strength: false,
        type_information: None,
        type_consistency: None,
        group_entity_id: None,
        endpoint_security_info: None,
    }
}

/// Counts the wake-ups of the deferred samples of its topic's writers.
struct WakeCounter {
    woken: AtomicU32,
}

impl Subscriber for WakeCounter {
    fn on_data(&self, _topic: &str, _seq: u64, _data: &[u8]) {}

    fn topic_name(&self) -> &str {
        TOPIC
    }

    fn on_writer_qos_resolved(&self, _writer_guid: [u8; 16]) {
        self.woken.fetch_add(1, Ordering::SeqCst);
    }
}

/// Participant setup installs the match registry before the first discovery
/// step that consults it is started: an announcement those steps handle is
/// judged, and one handled before the installation would be judged by no one.
#[test]
fn the_match_registry_is_installed_before_any_discovery_step_consults_it() {
    let _ = order_probe::take();
    let participant = crate::dds::Participant::builder("install_order")
        .domain_id(227)
        .build()
        .expect("fixture: a participant builds on loopback");
    let steps = order_probe::take();
    drop(participant);
    assert_eq!(
        steps.first(),
        Some(&"install"),
        "the install precedes every discovery step, steps: {steps:?}"
    );
    assert_eq!(
        steps.iter().filter(|step| **step == "install").count(),
        1,
        "installed once, steps: {steps:?}"
    );
    assert!(
        steps.len() > 1,
        "fixture: discovery steps were started after the install, steps: {steps:?}"
    );
}

/// The writers the installation judges, whose verdict was not on record, have
/// their deferred samples woken by it: a one-shot burst is not left waiting
/// for the writer's next sample.
#[test]
fn a_writer_judged_by_the_install_wakes_its_deferred_samples() {
    let fsm = Arc::new(DiscoveryFsm::new(
        GUID::new(OUR_PREFIX, [0x00, 0x00, 0x01, 0xC1]),
        100_000,
    ));
    fsm.handle_spdp(spdp(REMOTE_PREFIX));
    let writer = GUID::new(REMOTE_PREFIX, [0x00, 0x00, 0x01, 0x02]);
    // Announced before the registry exists: no verdict is on record.
    fsm.handle_sedp(writer_announcement(writer));

    let topics = TopicRegistry::new();
    let counter = Arc::new(WakeCounter {
        woken: AtomicU32::new(0),
    });
    topics
        .register_subscriber(counter.clone())
        .expect("fixture: the topic takes its subscriber");
    topics.register_writer_guid(writer.as_bytes(), TOPIC.to_string());

    let registry = Arc::new(MatchNotificationRegistry::new(&fsm, OUR_PREFIX));
    super::install_match_registry(&fsm, &topics, registry);
    assert_eq!(
        counter.woken.load(Ordering::SeqCst),
        1,
        "the writer judged at the install wakes its deferred samples, once"
    );
}
