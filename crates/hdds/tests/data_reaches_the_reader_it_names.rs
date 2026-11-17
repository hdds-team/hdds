// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! A DATA addressed to one reader is that reader's alone (RTPS 2.5 8.3.8.2:
//! readerId identifies the RTPS Reader entity being sent the data;
//! ENTITYID_UNKNOWN, 9.3.1.2, stands for every matched reader of the
//! receiving participant).
//!
//! A TRANSIENT_LOCAL writer replays its history to a late-joining
//! TRANSIENT_LOCAL reader, addressing each DATA to that reader. A VOLATILE
//! reader of the same topic in the same participant shares the unicast
//! locator the replay is sent to. If the receiver ignored readerId, the
//! VOLATILE reader would receive samples written before it matched, which
//! its durability forbids (DDS 1.4 2.2.3.4).
//!
//! Both participants live in this process but talk over UDP.

use hdds::test_support::domains::unique_domain;
use hdds::{Participant, QoS, TransportMode};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Clone, Debug, PartialEq, hdds::DDS)]
struct Tick {
    value: u32,
}

const HISTORY: u32 = 5;

fn history_len() -> usize {
    (1..=HISTORY).count()
}

fn udp_participant(name: &str, domain_id: u32, participant_id: u8) -> Arc<Participant> {
    Participant::builder(name)
        .domain_id(domain_id)
        .participant_id(Some(participant_id))
        .with_transport(TransportMode::UdpMulticast)
        .build()
        .expect("participant")
}

fn wait_for(what: &str, timeout: Duration, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + timeout;
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn drain(reader: &hdds::DataReader<Tick>, into: &mut Vec<u32>) {
    while let Ok(Some(sample)) = reader.take() {
        into.push(sample.value);
    }
}

fn drain_for(reader: &hdds::DataReader<Tick>, into: &mut Vec<u32>, period: Duration) {
    let deadline = Instant::now() + period;
    while Instant::now() < deadline {
        drain(reader, into);
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn a_history_replay_to_a_durable_reader_does_not_reach_a_volatile_neighbour() {
    let domain = unique_domain();
    let publisher = udp_participant("named_data_pub", domain.id(), 70);
    let subscriber = udp_participant("named_data_sub", domain.id(), 71);

    let topic = "NamedDataReplay";
    let writer = publisher
        .topic::<Tick>(topic)
        .expect("topic")
        .writer()
        .qos(QoS::reliable().transient_local().keep_last(HISTORY))
        .build()
        .expect("writer");
    for value in 1..=HISTORY {
        writer.write(&Tick { value }).expect("history write");
    }

    let volatile = subscriber
        .topic::<Tick>(topic)
        .expect("topic")
        .reader()
        .qos(QoS::reliable().keep_all())
        .build()
        .expect("volatile reader");
    wait_for(
        "the volatile reader to match",
        Duration::from_secs(10),
        || writer.matched_reader_count() == 1,
    );
    let mut volatile_got = Vec::new();
    drain_for(&volatile, &mut volatile_got, Duration::from_secs(1));
    assert!(
        volatile_got.is_empty(),
        "control: a VOLATILE reader received history before any durable \
         reader existed: {volatile_got:?}"
    );

    let durable = subscriber
        .topic::<Tick>(topic)
        .expect("topic")
        .reader()
        .qos(QoS::reliable().transient_local().keep_all())
        .build()
        .expect("durable reader");
    wait_for(
        "the durable reader to match",
        Duration::from_secs(10),
        || writer.matched_reader_count() == 2,
    );
    let mut durable_got = Vec::new();
    wait_for(
        "the durable reader's history",
        Duration::from_secs(10),
        || {
            drain(&durable, &mut durable_got);
            drain(&volatile, &mut volatile_got);
            durable_got.iter().filter(|v| **v <= HISTORY).count() == history_len()
        },
    );
    drain_for(&volatile, &mut volatile_got, Duration::from_secs(1));
    assert_eq!(durable_got, (1..=HISTORY).collect::<Vec<_>>());
    assert!(
        volatile_got.is_empty(),
        "the replay addressed to the durable reader reached the VOLATILE \
         reader: {volatile_got:?}"
    );

    // Live traffic still reaches both, once each.
    writer.write(&Tick { value: 100 }).expect("live write");
    wait_for("the live sample", Duration::from_secs(10), || {
        drain(&durable, &mut durable_got);
        drain(&volatile, &mut volatile_got);
        durable_got.contains(&100) && volatile_got.contains(&100)
    });
    drain_for(&volatile, &mut volatile_got, Duration::from_millis(500));
    drain_for(&durable, &mut durable_got, Duration::from_millis(500));
    assert_eq!(volatile_got, vec![100]);
    assert_eq!(durable_got, (1..=HISTORY).chain([100]).collect::<Vec<_>>());
}

#[test]
fn a_volatile_reader_joining_late_receives_no_history() {
    let domain = unique_domain();
    let publisher = udp_participant("late_volatile_pub", domain.id(), 72);
    let subscriber = udp_participant("late_volatile_sub", domain.id(), 73);

    let topic = "LateVolatileNoHistory";
    let writer = publisher
        .topic::<Tick>(topic)
        .expect("topic")
        .writer()
        .qos(QoS::reliable().transient_local().keep_last(HISTORY))
        .build()
        .expect("writer");
    for value in 1..=HISTORY {
        writer.write(&Tick { value }).expect("history write");
    }
    // Longer than any receive-side duplicate window, so nothing the writes
    // left behind on the subscriber's side can mask a later repair.
    std::thread::sleep(Duration::from_secs(3));

    let volatile = subscriber
        .topic::<Tick>(topic)
        .expect("topic")
        .reader()
        .qos(QoS::reliable().keep_all())
        .build()
        .expect("volatile reader");
    wait_for(
        "the volatile reader to match",
        Duration::from_secs(10),
        || writer.matched_reader_count() == 1,
    );
    let mut got = Vec::new();
    drain_for(&volatile, &mut got, Duration::from_secs(2));
    assert!(
        got.is_empty(),
        "a VOLATILE reader received samples written before it matched: {got:?}"
    );

    writer.write(&Tick { value: 100 }).expect("live write");
    wait_for("the live sample", Duration::from_secs(10), || {
        drain(&volatile, &mut got);
        got.contains(&100)
    });
    assert_eq!(got, vec![100]);
}

#[derive(Clone, Debug, PartialEq, hdds::DDS)]
struct Blob {
    value: u32,
    data: Vec<u8>,
}

/// Large enough to travel as DATA_FRAG.
const BLOB_BYTES: usize = 20_000;

fn blob_values(reader: &hdds::DataReader<Blob>, into: &mut Vec<u32>) {
    while let Ok(Some(sample)) = reader.take() {
        assert_eq!(sample.data.len(), BLOB_BYTES, "a reassembled sample");
        into.push(sample.value);
    }
}

#[test]
fn a_fragmented_replay_to_a_durable_reader_does_not_reach_a_volatile_neighbour() {
    let domain = unique_domain();
    let publisher = udp_participant("named_frag_pub", domain.id(), 74);
    let subscriber = udp_participant("named_frag_sub", domain.id(), 75);

    let topic = "NamedFragReplay";
    let writer = publisher
        .topic::<Blob>(topic)
        .expect("topic")
        .writer()
        .qos(QoS::reliable().transient_local().keep_last(HISTORY))
        .build()
        .expect("writer");
    for value in 1..=HISTORY {
        let data = vec![u8::try_from(value).expect("small"); BLOB_BYTES];
        writer.write(&Blob { value, data }).expect("history write");
    }

    let volatile = subscriber
        .topic::<Blob>(topic)
        .expect("topic")
        .reader()
        .qos(QoS::reliable().keep_all())
        .build()
        .expect("volatile reader");
    wait_for(
        "the volatile reader to match",
        Duration::from_secs(10),
        || writer.matched_reader_count() == 1,
    );
    let durable = subscriber
        .topic::<Blob>(topic)
        .expect("topic")
        .reader()
        .qos(QoS::reliable().transient_local().keep_all())
        .build()
        .expect("durable reader");
    wait_for(
        "the durable reader to match",
        Duration::from_secs(10),
        || writer.matched_reader_count() == 2,
    );

    let mut durable_got = Vec::new();
    let mut volatile_got = Vec::new();
    wait_for(
        "the durable reader's history",
        Duration::from_secs(10),
        || {
            blob_values(&durable, &mut durable_got);
            blob_values(&volatile, &mut volatile_got);
            durable_got.len() >= history_len()
        },
    );
    let deadline = Instant::now() + Duration::from_secs(1);
    while Instant::now() < deadline {
        blob_values(&volatile, &mut volatile_got);
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(durable_got, (1..=HISTORY).collect::<Vec<_>>());
    assert!(
        volatile_got.is_empty(),
        "a fragmented replay addressed to the durable reader reached the \
         VOLATILE reader: {volatile_got:?}"
    );
}
