// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! ContentFilteredTopic on the intra-process path.
//!
//! The network path evaluates a reader's content filter before its ring
//! insertion (`ReaderSubscriber::process_admitted`). The intra-process
//! path never went through that subscriber: the writer's merger fanned
//! every sample into the CFT reader's ring, so `value > 40` delivered
//! `[10, 50]`. These tests pin the fix at the merger, where the reader's
//! filter now runs before the ring push: a rejected sample never enters
//! the ring (sole-reader and fan-out paths), never raises DATA_AVAILABLE,
//! is not replayed to a TRANSIENT_LOCAL late joiner, and a parameter
//! update applies to the next sample.

use hdds::{Participant, QoS, TransportMode, WaitSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// The derive generates the CDR codec, the type descriptor, and (since the
/// fix pinned by `derive_get_fields.rs`) `get_fields`, so `Reading` no
/// longer needs a hand-written `DDS` impl or a separate wire twin.
#[derive(hdds::DDS, Debug, Clone)]
struct Reading {
    value: i64,
}

fn participant(name: &str) -> Arc<Participant> {
    Participant::builder(name)
        .domain_id(0)
        .with_transport(TransportMode::IntraProcess)
        .build()
        .unwrap()
}

/// Drain `reader` until `expected` samples arrived or `timeout` elapsed,
/// then take one more pass so a sample that should NOT have arrived is
/// counted instead of hidden by the early exit.
fn drain(reader: &hdds::DataReader<Reading>, expected: usize, timeout: Duration) -> Vec<i64> {
    let deadline = Instant::now() + timeout;
    let mut values = Vec::new();
    while values.len() < expected && Instant::now() < deadline {
        while let Some(sample) = reader.take().unwrap() {
            values.push(sample.value);
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    std::thread::sleep(Duration::from_millis(20));
    while let Some(sample) = reader.take().unwrap() {
        values.push(sample.value);
    }
    values
}

#[test]
fn cft_reader_beside_a_plain_reader_receives_only_matching_samples() {
    // Two readers on the writer: the merger takes its refcounted fan-out
    // path. This is the shape of the original reproducer.
    let participant = participant("cft_intra_fanout");
    let topic = "cft_intra_fanout";
    let cft = participant
        .create_content_filtered_topic::<Reading>(
            "cft_intra_fanout_filtered",
            topic,
            "value > %0",
            vec!["40".into()],
        )
        .unwrap();
    let filtered = cft
        .reader()
        .qos(QoS::best_effort().keep_last(16))
        .build()
        .unwrap();
    let plain_topic = participant.topic::<Reading>(topic).unwrap();
    let control = plain_topic
        .reader()
        .qos(QoS::best_effort().keep_last(16))
        .build()
        .unwrap();
    let writer = plain_topic
        .writer()
        .qos(QoS::best_effort().keep_last(16))
        .build()
        .unwrap();

    for value in [10, 50, 40, 41] {
        writer.write(&Reading { value }).unwrap();
    }

    assert_eq!(
        drain(&control, 4, Duration::from_secs(2)),
        vec![10, 50, 40, 41],
        "the plain reader must receive every sample"
    );
    assert_eq!(
        drain(&filtered, 2, Duration::from_secs(2)),
        vec![50, 41],
        "the CFT reader must receive only value > 40"
    );
}

#[test]
fn sole_cft_reader_receives_only_matching_samples_without_spurious_wakeups() {
    // One reader on the writer: the merger takes its EXCLUSIVE sole-reader
    // path. A rejected sample must not raise DATA_AVAILABLE either, which a
    // WaitSet observes as a timeout.
    let participant = participant("cft_intra_sole");
    let topic = "cft_intra_sole";
    let cft = participant
        .create_content_filtered_topic::<Reading>(
            "cft_intra_sole_filtered",
            topic,
            "value > %0",
            vec!["40".into()],
        )
        .unwrap();
    let filtered = cft
        .reader()
        .qos(QoS::best_effort().keep_last(16))
        .build()
        .unwrap();
    let writer = participant
        .topic::<Reading>(topic)
        .unwrap()
        .writer()
        .qos(QoS::best_effort().keep_last(16))
        .build()
        .unwrap();
    let waitset = WaitSet::new();
    waitset.attach(&filtered).unwrap();

    writer.write(&Reading { value: 10 }).unwrap();
    assert!(
        matches!(
            waitset.wait(Some(Duration::from_millis(200))),
            Err(hdds::Error::WouldBlock)
        ),
        "a rejected sample must not raise DATA_AVAILABLE"
    );
    assert!(
        filtered.take().unwrap().is_none(),
        "a rejected sample must not be takeable"
    );

    writer.write(&Reading { value: 50 }).unwrap();
    let triggered = waitset
        .wait(Some(Duration::from_secs(2)))
        .expect("an accepted sample must raise DATA_AVAILABLE");
    assert!(!triggered.is_empty());
    assert_eq!(drain(&filtered, 1, Duration::from_secs(2)), vec![50]);
}

#[test]
fn parameter_update_applies_to_the_next_intra_process_sample() {
    let participant = participant("cft_intra_params");
    let topic = "cft_intra_params";
    let cft = participant
        .create_content_filtered_topic::<Reading>(
            "cft_intra_params_filtered",
            topic,
            "value > %0",
            vec!["40".into()],
        )
        .unwrap();
    let filtered = cft
        .reader()
        .qos(QoS::best_effort().keep_last(16))
        .build()
        .unwrap();
    let writer = participant
        .topic::<Reading>(topic)
        .unwrap()
        .writer()
        .qos(QoS::best_effort().keep_last(16))
        .build()
        .unwrap();

    writer.write(&Reading { value: 50 }).unwrap();
    assert_eq!(drain(&filtered, 1, Duration::from_secs(2)), vec![50]);

    // The evaluator shares the topic's parameters: raising the threshold
    // after the reader exists must reject the next 50 and pass a 70.
    cft.try_set_expression_parameters(vec!["60".into()])
        .unwrap();
    writer.write(&Reading { value: 50 }).unwrap();
    writer.write(&Reading { value: 70 }).unwrap();
    assert_eq!(
        drain(&filtered, 1, Duration::from_secs(2)),
        vec![70],
        "only the sample above the updated threshold may arrive"
    );
}

#[test]
fn reliable_cft_reader_keeps_delivering_across_rejected_samples() {
    // RELIABLE readers keep sequence bookkeeping the BEST_EFFORT ones do
    // not; a rejected sample leaves a hole in the writer's sequence as seen
    // from this reader's ring, and delivery of the accepted samples around
    // it must not stall on that hole.
    let participant = participant("cft_intra_reliable");
    let topic = "cft_intra_reliable";
    let cft = participant
        .create_content_filtered_topic::<Reading>(
            "cft_intra_reliable_filtered",
            topic,
            "value > %0",
            vec!["40".into()],
        )
        .unwrap();
    let filtered = cft
        .reader()
        .qos(QoS::reliable().keep_last(16))
        .build()
        .unwrap();
    let writer = participant
        .topic::<Reading>(topic)
        .unwrap()
        .writer()
        .qos(QoS::reliable().keep_last(16))
        .build()
        .unwrap();

    for value in [10, 50, 20, 30, 60, 5, 70] {
        writer.write(&Reading { value }).unwrap();
    }
    assert_eq!(
        drain(&filtered, 3, Duration::from_secs(2)),
        vec![50, 60, 70],
        "accepted samples must flow past the rejected ones"
    );
}

#[test]
fn transient_local_replay_to_a_cft_late_joiner_is_filtered() {
    let participant = participant("cft_intra_replay");
    let topic = "cft_intra_replay";
    let writer = participant
        .topic::<Reading>(topic)
        .unwrap()
        .writer()
        .qos(QoS::reliable().transient_local().keep_last(16))
        .build()
        .unwrap();
    for value in [10, 50, 30, 60] {
        writer.write(&Reading { value }).unwrap();
    }

    // The reader binds after the writes: the merger replays the retained
    // history into its ring, through the same filter as live samples.
    let cft = participant
        .create_content_filtered_topic::<Reading>(
            "cft_intra_replay_filtered",
            topic,
            "value > %0",
            vec!["40".into()],
        )
        .unwrap();
    let filtered = cft
        .reader()
        .qos(QoS::reliable().transient_local().keep_last(16))
        .build()
        .unwrap();
    assert_eq!(
        drain(&filtered, 2, Duration::from_secs(2)),
        vec![50, 60],
        "replayed history must pass through the content filter"
    );
}
