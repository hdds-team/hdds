// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! DDS v1.4 Sec.2.2.4.1: SAMPLE_LOST counts never-received samples.
//! RTPS v2.5 Sec.8.4.12.1 T2: a BEST_EFFORT reader passes a sequence
//! gap permanently when it receives a newer DATA from that writer.

use super::tests_history_limits::{encoded, Keyed, NetworkReader};
use crate::dds::{CdrVersion, Condition, DataReaderListener, QoS, StatusMask, WaitSet, DDS};
use crate::engine::Subscriber as _;
use std::sync::{Arc, Mutex};
use std::time::Duration;

const A: [u8; 16] = [0x6A; 16];
const B: [u8; 16] = [0x6B; 16];

fn reader(topic: &str) -> NetworkReader<Keyed> {
    NetworkReader::with_parts(
        topic,
        QoS::best_effort().keep_all(),
        super::reorder::ReorderGate::new_best_effort(),
        crate::qos::ownership::OwnershipKind::Shared,
        super::subscriber::CoherentConfig::default(),
    )
}

fn data(net: &NetworkReader<Keyed>, writer: [u8; 16], seq: u64) {
    data_key(net, writer, seq, 1);
}

fn data_key(net: &NetworkReader<Keyed>, writer: [u8; 16], seq: u64, id: i32) {
    net.subscriber.on_data_with_writer(
        &net.topic,
        writer,
        seq,
        &encoded(&Keyed { id, value: 7 }),
        CdrVersion::Xcdr2,
    );
}

#[test]
fn best_effort_lost_gap_wakes_waitset_and_is_counted_once_per_writer() {
    let net = reader("be-lost-waitset");
    let status = net.reader.get_status_condition();
    status.set_enabled_statuses(StatusMask::SAMPLE_LOST);
    let waitset = WaitSet::new();
    waitset.attach(&*net.reader).expect("attach");
    data(&net, A, 40);
    assert_eq!(net.lost(), 0, "the first DATA establishes the join floor");
    data(&net, B, 100);
    assert_eq!(net.lost(), 0, "every writer establishes its own floor");
    assert!(!status.get_trigger_value());

    data(&net, A, 44);
    assert!(status.get_trigger_value(), "SAMPLE_LOST is active");
    assert_eq!(waitset.wait(Some(Duration::ZERO)).expect("ready").len(), 1);
    let lost = net.reader.get_sample_lost_status();
    assert_eq!((lost.total_count, lost.total_count_change), (3, 3));
    assert!(!status.get_trigger_value(), "reading the status resets it");
    data(&net, A, 42);
    data(&net, A, 44);
    data(&net, B, 101);
    assert_eq!(net.lost(), 3, "late and duplicate DATA add no losses");
    data(&net, A, 46);
    let lost = net.reader.get_sample_lost_status();
    assert_eq!((lost.total_count, lost.total_count_change), (4, 1));
    assert_eq!(net.take_all().len(), 5, "late DATA is never delivered");
}

#[test]
fn best_effort_lost_counts_a_jump_past_the_duplicate_window() {
    let net = reader("be-lost-large-gap");
    data(&net, A, 1);
    data(&net, A, 8194);
    assert_eq!(
        net.lost(),
        8192,
        "count before the window forgets its holes"
    );
    data(&net, A, 8195);
    assert_eq!(net.lost(), 8192);
}

#[test]
fn best_effort_lost_excludes_filtered_changes_and_prior_gap_reports() {
    let net = reader("be-lost-filtered");
    data(&net, A, 1);
    // RTPS v2.5 Sec.8.3.8.4: filtered changes are not samples lost.
    net.subscriber.on_writer_gap_filtered(A, 3, 5, vec![], 2);
    assert_eq!(net.lost(), 0);
    data(&net, A, 6);
    assert_eq!(net.lost(), 2, "only samples 2 and 5 were lost");
    net.subscriber.on_writer_gap(A, 2, 6, vec![]);
    data(&net, A, 7);
    assert_eq!(
        net.lost(),
        2,
        "later GAPs must not report the same loss twice"
    );
}

struct TakingListener {
    reader: Arc<super::DataReader<Keyed>>,
    calls: Mutex<Vec<crate::dds::listener::SampleLostStatus>>,
}

impl DataReaderListener<Keyed> for TakingListener {
    fn on_sample_lost(&self, status: crate::dds::listener::SampleLostStatus) {
        while self.reader.take().expect("reentrant take").is_some() {}
        self.calls.lock().unwrap().push(status);
    }
}

#[test]
fn best_effort_lost_notifies_a_reentrant_listener_with_the_same_status() {
    let net = reader("be-lost-listener");
    let listener = Arc::new(TakingListener {
        reader: Arc::clone(&net.reader),
        calls: Mutex::new(Vec::new()),
    });
    net.subscriber
        .listener
        .set(Some(listener.clone()), StatusMask::SAMPLE_LOST);
    data(&net, A, 1);
    data(&net, A, 4);
    let calls = listener.calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!((calls[0].total_count, calls[0].total_count_change), (2, 2));
    let lost = net.reader.get_sample_lost_status();
    assert_eq!((lost.total_count, lost.total_count_change), (2, 0));
}

#[test]
fn best_effort_lost_does_not_count_a_reliable_gap_awaiting_repair() {
    let net = NetworkReader::<Keyed>::with_parts(
        "be-lost-reliable-control",
        QoS::reliable().keep_all(),
        super::reorder::ReorderGate::new(true, true),
        crate::qos::ownership::OwnershipKind::Shared,
        super::subscriber::CoherentConfig::default(),
    );
    net.credit.match_writer(A);
    data(&net, A, 1);
    data(&net, A, 4);
    assert_eq!(net.lost(), 0, "RELIABLE still awaits samples 2 and 3");
    assert_eq!(net.take_all().len(), 1);
    data(&net, A, 2);
    data(&net, A, 3);
    assert_eq!(net.take_all().len(), 3);
    assert_eq!(net.lost(), 0);
}

#[test]
fn best_effort_lost_counts_coherent_data_before_its_set_commits() {
    let net = NetworkReader::<Keyed>::with_parts(
        "be-lost-coherent-gap",
        QoS::best_effort().keep_all(),
        super::reorder::ReorderGate::new_best_effort(),
        crate::qos::ownership::OwnershipKind::Shared,
        super::subscriber::CoherentConfig {
            coherent_access: true,
            is_group_scope: false,
        },
    );
    for seq in [1, 8194] {
        net.subscriber.on_data_coherent(
            &net.topic,
            A,
            seq,
            &encoded(&Keyed { id: 1, value: 7 }),
            CdrVersion::Xcdr2,
            Some(1),
            None,
            None,
        );
    }
    assert_eq!(
        net.lost(),
        8192,
        "the uncommitted set cannot repair a BE gap"
    );
    assert!(net.take_all().is_empty(), "no incomplete set is delivered");
}

fn limited_reader(topic: &str) -> NetworkReader<Keyed> {
    let mut qos = QoS::best_effort().keep_all();
    qos.resource_limits.max_instances = 1;
    NetworkReader::with_parts(
        topic,
        qos,
        super::reorder::ReorderGate::new_best_effort(),
        crate::qos::ownership::OwnershipKind::Shared,
        super::subscriber::CoherentConfig::default(),
    )
}

/// A DATA carrying unregister occupies history without keeping its
/// instance registered after the application drains that history.
fn occupying_data(net: &NetworkReader<Keyed>, writer: [u8; 16]) {
    data(net, writer, 1);
    net.subscriber.on_dispose_from_writer(
        &net.topic,
        writer,
        1,
        Keyed { id: 1, value: 7 }.compute_key(),
        crate::engine::subscriber::DisposeKind::Unregistered,
    );
}

/// DDS v1.4 Sec.2.2.4.1: a received sample rejected for a resource limit
/// is not a never-received sample, even after the writer moves past it.
#[test]
fn best_effort_lost_excludes_a_sample_rejected_for_an_instance_limit() {
    let net = limited_reader("be-lost-rejected");
    occupying_data(&net, A);
    data_key(&net, A, 2, 2);
    assert_eq!(net.rejected().total_count, 1);
    assert_eq!(net.lost(), 0);
    assert_eq!(net.take_all().len(), 1);
    data_key(&net, A, 3, 2);
    assert_eq!(net.lost(), 0, "sample 2 was received and rejected");
    assert_eq!(net.take_all().len(), 1);
}

#[test]
fn best_effort_lost_counts_true_holes_even_when_the_newer_sample_is_rejected() {
    let net = limited_reader("be-lost-rejected-gap");
    occupying_data(&net, A);
    data_key(&net, A, 5, 2);
    assert_eq!(net.rejected().total_count, 1);
    assert_eq!(net.lost(), 3, "only samples 2, 3 and 4 were never received");
    assert_eq!(net.take_all().len(), 1);
    data_key(&net, A, 6, 2);
    assert_eq!(net.lost(), 3, "rejected sample 5 is not a new loss");
    assert_eq!(net.take_all().len(), 1);
}

#[test]
fn best_effort_lost_first_rejected_data_establishes_its_writers_floor() {
    let net = limited_reader("be-lost-rejected-floor");
    occupying_data(&net, B);
    data_key(&net, A, 40, 2);
    assert_eq!(net.rejected().total_count, 1);
    assert_eq!(net.lost(), 0, "no pre-join samples are losses");
    assert_eq!(net.take_all().len(), 1);
    data_key(&net, A, 42, 2);
    assert_eq!(net.lost(), 1, "only sample 41 was never received");
    assert_eq!(net.take_all().len(), 1);
}

#[test]
fn best_effort_lost_rejection_notifies_a_reentrant_listener() {
    let net = limited_reader("be-lost-rejected-listener");
    let listener = Arc::new(TakingListener {
        reader: Arc::clone(&net.reader),
        calls: Mutex::new(Vec::new()),
    });
    net.subscriber
        .listener
        .set(Some(listener.clone()), StatusMask::SAMPLE_LOST);
    occupying_data(&net, A);
    data_key(&net, A, 5, 2);
    assert_eq!(net.rejected().total_count, 1);
    let calls = listener.calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!((calls[0].total_count, calls[0].total_count_change), (3, 3));
    drop(calls);
    data_key(&net, A, 6, 2);
    assert_eq!(
        net.take_all().len(),
        1,
        "callback released the occupied instance"
    );
    assert_eq!(net.lost(), 3);
}

/// RTPS v2.5 Sec.8.7.6: ECS is DATA without serializedPayload, so T2
/// still advances BEST_EFFORT receipt. The marker itself is not a sample.
#[test]
fn best_effort_lost_controls_count_real_holes_and_never_count_the_marker() {
    for kind in 0..3 {
        let net = NetworkReader::<Keyed>::with_parts(
            &format!("be-lost-control-{kind}"),
            QoS::best_effort().keep_all(),
            super::reorder::ReorderGate::new_best_effort(),
            crate::qos::ownership::OwnershipKind::Shared,
            super::subscriber::CoherentConfig {
                coherent_access: kind != 0,
                is_group_scope: false,
            },
        );
        data(&net, A, 1);
        match kind {
            0 => net.subscriber.on_writer_non_data(A, 8194),
            1 => net.subscriber.on_ecs(&net.topic, A, 8194, 1, None, None),
            _ => net
                .subscriber
                .on_coherent_end_marker(&net.topic, A, None, None, 1, Some(1), 8194),
        }
        assert_eq!(
            net.lost(),
            8192,
            "kind {kind}: count before receipt rollover"
        );
        net.subscriber.on_writer_non_data(A, 8194);
        data(&net, A, 8195);
        assert_eq!(net.lost(), 8192, "kind {kind}: marker adds no loss");
        assert_eq!(
            net.take_all().len(),
            2,
            "controls add no application sample"
        );
    }
}

#[test]
fn best_effort_lost_first_control_establishes_its_writers_floor() {
    let net = reader("be-lost-control-floor");
    net.subscriber.on_writer_non_data(A, 40);
    assert_eq!(net.lost(), 0);
    data(&net, A, 42);
    assert_eq!(net.lost(), 1, "only sample 41 was never received");
    assert_eq!(net.take_all().len(), 1);
}
