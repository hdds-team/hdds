// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! A VOLATILE reader that matches a writer after another VOLATILE reader
//! already did receives nothing written before its own match (DDS 1.4
//! 2.2.3.4).
//!
//! The writer's VOLATILE HEARTBEAT floor is writer-wide, captured at its
//! first match: while the first reader still leaves samples written before
//! the second match unacknowledged, the writer keeps them and the HEARTBEATs
//! the second reader receives advertise them, so that reader asks for them.
//! The writer answers with a GAP, never a repair: each reader's proxy
//! records, at its match, the last change it is not owed. Behind that, a
//! VOLATILE reader's reorder gate is seeded by the first DATA it observes,
//! never by the writer's advertised `firstSN`.
//!
//! The second reader lives either in a participant of its own or in the
//! first reader's participant (same unicast locator). All participants live
//! in this process but talk over UDP.

use hdds::test_support::domains::unique_domain;
use hdds::{Participant, QoS, TransportMode};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Clone, Debug, PartialEq, hdds::DDS)]
struct Tick {
    value: u32,
}

const BEFORE: u32 = 10;
const AFTER: u32 = 20;

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

fn volatile_reader(
    participant: &Arc<Participant>,
    topic: &str,
    max_samples: Option<usize>,
) -> hdds::DataReader<Tick> {
    let mut qos = QoS::reliable().keep_all();
    if let Some(max) = max_samples {
        qos.resource_limits.max_samples = max;
    }
    participant
        .topic::<Tick>(topic)
        .expect("topic")
        .reader()
        .qos(qos)
        .build()
        .expect("volatile reader")
}

/// How many samples the lagging first reader can hold before it refuses
/// (unacknowledged) what arrives next.
const A_HOLDS: usize = 2;

struct Case {
    writer_qos: QoS,
    /// B is created in A's participant (same unicast locator) instead of
    /// a participant of its own.
    b_beside_a: bool,
    /// A holds `A_HOLDS` samples and is not read until the end: it leaves
    /// the rest of 1..=BEFORE unacknowledged, so the writer still holds
    /// them, and advertises them, when B matches.
    a_lags: bool,
    ids: [u8; 3],
    topic: &'static str,
}

/// Reader A matches and 1..=BEFORE are written. Reader B matches and is
/// left long enough to exchange HEARTBEAT/ACKNACK with the writer before
/// any live sample: when the writer still holds part of 1..=BEFORE (A
/// lagging), its HEARTBEATs to B advertise them, B asks for them, and the
/// writer answers. Then BEFORE+1..=AFTER are written. B must deliver
/// exactly those; A, every sample.
fn run(case: Case) {
    let domain = unique_domain();
    let publisher = udp_participant("second_volatile_pub", domain.id(), case.ids[0]);
    let sub_a = udp_participant("second_volatile_sub_a", domain.id(), case.ids[1]);

    let writer = publisher
        .topic::<Tick>(case.topic)
        .expect("topic")
        .writer()
        .qos(case.writer_qos)
        .build()
        .expect("writer");

    let reader_a = volatile_reader(&sub_a, case.topic, case.a_lags.then_some(A_HOLDS));
    wait_for("reader A to match", Duration::from_secs(10), || {
        writer.matched_reader_count() == 1
    });

    for value in 1..=BEFORE {
        writer.write(&Tick { value }).expect("write before B");
    }
    let mut a_got = Vec::new();
    if case.a_lags {
        // Let 1..=BEFORE arrive at A and be refused past what it holds.
        std::thread::sleep(Duration::from_secs(1));
    } else {
        wait_for(
            "reader A to receive the first batch",
            Duration::from_secs(10),
            || {
                drain(&reader_a, &mut a_got);
                a_got.len() >= BEFORE as usize
            },
        );
        assert_eq!(a_got, (1..=BEFORE).collect::<Vec<_>>());
    }

    let sub_b = if case.b_beside_a {
        None
    } else {
        Some(udp_participant(
            "second_volatile_sub_b",
            domain.id(),
            case.ids[2],
        ))
    };
    let reader_b = volatile_reader(sub_b.as_ref().unwrap_or(&sub_a), case.topic, None);
    wait_for("reader B to match", Duration::from_secs(10), || {
        writer.matched_reader_count() == 2
    });

    // Many writer HEARTBEAT periods with no live traffic.
    let mut b_got = Vec::new();
    drain_for(&reader_b, &mut b_got, Duration::from_secs(2));
    assert!(
        b_got.is_empty(),
        "a second VOLATILE reader delivered samples written before it \
         matched, before any live write: {b_got:?}"
    );

    for value in (BEFORE + 1)..=AFTER {
        writer.write(&Tick { value }).expect("write after B");
    }
    let deadline = Instant::now() + Duration::from_secs(20);
    while (!b_got.contains(&AFTER) || !a_got.contains(&AFTER)) && Instant::now() < deadline {
        drain(&reader_b, &mut b_got);
        drain(&reader_a, &mut a_got);
        std::thread::sleep(Duration::from_millis(20));
    }
    drain_for(&reader_b, &mut b_got, Duration::from_secs(1));
    drain_for(&reader_a, &mut a_got, Duration::from_millis(200));

    let leaked: Vec<u32> = b_got.iter().copied().filter(|v| *v <= BEFORE).collect();
    assert!(
        leaked.is_empty(),
        "a second VOLATILE reader delivered samples written before it \
         matched: leaked={leaked:?} full={b_got:?}"
    );
    assert_eq!(b_got, ((BEFORE + 1)..=AFTER).collect::<Vec<_>>());
    assert_eq!(
        a_got,
        (1..=AFTER).collect::<Vec<_>>(),
        "the first reader lost samples"
    );
}

#[test]
fn a_second_volatile_reader_in_its_own_participant_receives_no_history() {
    run(Case {
        writer_qos: QoS::reliable().keep_all(),
        b_beside_a: false,
        a_lags: false,
        ids: [74, 75, 76],
        topic: "SecondVolatileOwnParticipant",
    });
}

#[test]
fn a_second_volatile_reader_beside_the_first_receives_no_history() {
    run(Case {
        writer_qos: QoS::reliable().keep_all(),
        b_beside_a: true,
        a_lags: false,
        ids: [77, 78, 79],
        topic: "SecondVolatileSameParticipant",
    });
}

#[test]
fn a_second_volatile_reader_of_a_keep_last_writer_receives_no_history() {
    run(Case {
        writer_qos: QoS::reliable().keep_last(64),
        b_beside_a: false,
        a_lags: false,
        ids: [80, 81, 82],
        topic: "SecondVolatileKeepLast",
    });
}

#[test]
fn a_second_volatile_reader_asking_for_unacknowledged_history_receives_none() {
    run(Case {
        writer_qos: QoS::reliable().keep_all(),
        b_beside_a: false,
        a_lags: true,
        ids: [83, 84, 85],
        topic: "SecondVolatileLaggingFirst",
    });
}

#[test]
fn a_second_volatile_reader_beside_a_lagging_first_receives_no_history() {
    run(Case {
        writer_qos: QoS::reliable().keep_all(),
        b_beside_a: true,
        a_lags: true,
        ids: [86, 87, 88],
        topic: "SecondVolatileBesideLaggingFirst",
    });
}
