// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Coherent-set atomicity on the intra-process delivery path (DDS v1.4
//! SS2.2.3.6 PRESENTATION coherent_access, RTPS v2.5 SS8.7.5/SS8.7.6).
//!
//! A writer with no RTPS endpoint context (`TransportMode::IntraProcess`,
//! or any writer with no remote peer yet) must record its durable
//! history WITH coherent-set markers: `commit_intra_process_entry`
//! computes `coherent_sn`/`group_sn` for a non-GROUP writer on the
//! fast path, and `WriterCoherentBridge::emit_ecs_data` journals even when
//! `rtps_endpoint` is `None`. Without them, a late-joining
//! local reader with `coherent_access = true` would replay every
//! retained sample as an independent change, including the members of a
//! set the writer never closed (DDS v1.4 SS2.2.2.4.1.10/11: a coherent
//! set is all-or-nothing, including for a late joiner via durability).
//!
//! The LIVE (not-late-joiner) delivery path has the same requirement from
//! the other direction: a coherent member must not reach a co-located
//! reader's ring the instant `write()` returns, but atomically with the
//! rest of its set.
//!
//! Each `intra_*` test below has a `udp_*` twin on `TransportMode::
//! UdpMulticast` (two participants, real loopback UDP, one process): it
//! pins the behavior the intra-process path must match.

use hdds::test_support::domains::unique_domain;
use hdds::{Participant, QoS, TransportMode};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, hdds::DDS)]
struct Item {
    value: i32,
}

fn topic_coherent_qos() -> QoS {
    QoS::reliable()
        .transient_local()
        .keep_all()
        .presentation_topic_coherent()
}

fn group_coherent_qos() -> QoS {
    QoS::reliable()
        .transient_local()
        .keep_all()
        .presentation_group_coherent()
}

/// Whatever is in the reader's ring right now, no waiting: used to assert
/// that an open (unclosed) coherent set delivered NOTHING, where waiting
/// would only hide a real defect behind a timeout.
fn drain_now(reader: &hdds::DataReader<Item>) -> Vec<i32> {
    let mut values = Vec::new();
    while let Some(sample) = reader.take().unwrap() {
        values.push(sample.value);
    }
    values
}

/// Poll `reader` until at least `expected` samples arrived or `timeout`
/// elapses (UDP control tests: real loopback send/receive is async).
fn drain_eventually(
    reader: &hdds::DataReader<Item>,
    expected: usize,
    timeout: Duration,
) -> Vec<i32> {
    let deadline = Instant::now() + timeout;
    let mut values = Vec::new();
    while values.len() < expected && Instant::now() < deadline {
        while let Some(sample) = reader.take().unwrap() {
            values.push(sample.value);
        }
        if values.len() < expected {
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    values
}

/// Nothing more arrives on `reader` within `window`: used after a UDP
/// control test's late joiner already got its closed set, to confirm the
/// open one never follows.
fn assert_nothing_more(reader: &hdds::DataReader<Item>, window: Duration) {
    let deadline = Instant::now() + window;
    while Instant::now() < deadline {
        if let Some(sample) = reader.take().unwrap() {
            panic!("received an unexpected sample after the closed set: {sample:?}");
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

// ---------------------------------------------------------------------
// TOPIC scope, late joiner, IntraProcess vs. UDP-in-one-process control
// ---------------------------------------------------------------------

#[test]
fn intra_topic_scope_late_joiner_sees_closed_set_only() {
    let participant = Participant::builder("intra-topic-late")
        .domain_id(0)
        .with_transport(TransportMode::IntraProcess)
        .build()
        .unwrap();
    let topic = participant.topic::<Item>("intra-topic-late").unwrap();
    let publisher = Arc::new(participant.create_publisher(topic_coherent_qos()).unwrap());
    let writer = topic
        .writer()
        .qos(topic_coherent_qos())
        .publisher(&publisher)
        .build()
        .unwrap();

    publisher.begin_coherent_changes().unwrap();
    for value in [1, 2, 3] {
        writer.write(&Item { value }).unwrap();
    }
    publisher.end_coherent_changes().unwrap();

    // A second set, left OPEN: never closed. Its one member must never
    // leak to a late joiner (DDSI-RTPS 2.5 SS8.7.6: a coherent set
    // unfinished at replay time must not be delivered).
    publisher.begin_coherent_changes().unwrap();
    writer.write(&Item { value: 99 }).unwrap();

    let late = topic.reader().qos(topic_coherent_qos()).build().unwrap();
    let mut got = drain_now(&late);
    got.sort_unstable();
    assert_eq!(
        got,
        vec![1, 2, 3],
        "late joiner must receive exactly the closed set, atomically, and \
         nothing from the still-open one"
    );
}

/// The same with a live reader bound before the writes, so the members take
/// the intra-process fast path (staged for the live reader) rather than the
/// general one: what they journal for a late joiner must still carry their
/// set, and the live reader must have the closed set and nothing else.
#[test]
fn intra_topic_scope_late_joiner_beside_a_live_reader_sees_closed_set_only() {
    let participant = Participant::builder("intra-topic-late-live")
        .domain_id(0)
        .with_transport(TransportMode::IntraProcess)
        .build()
        .unwrap();
    let topic = participant.topic::<Item>("intra-topic-late-live").unwrap();
    let publisher = Arc::new(participant.create_publisher(topic_coherent_qos()).unwrap());
    let writer = topic
        .writer()
        .qos(topic_coherent_qos())
        .publisher(&publisher)
        .build()
        .unwrap();
    let live = topic.reader().qos(topic_coherent_qos()).build().unwrap();

    publisher.begin_coherent_changes().unwrap();
    for value in [1, 2, 3] {
        writer.write(&Item { value }).unwrap();
    }
    publisher.end_coherent_changes().unwrap();
    publisher.begin_coherent_changes().unwrap();
    writer.write(&Item { value: 99 }).unwrap();

    assert_eq!(drain_now(&live), vec![1, 2, 3], "the live reader");
    let late = topic.reader().qos(topic_coherent_qos()).build().unwrap();
    let mut got = drain_now(&late);
    got.sort_unstable();
    assert_eq!(
        got,
        vec![1, 2, 3],
        "the late joiner: the closed set, nothing of the open one"
    );
}

#[test]
fn udp_topic_scope_late_joiner_sees_closed_set_only() {
    let domain = unique_domain();
    let writer_participant = Participant::builder("udp-topic-late-w")
        .domain_id(domain.id())
        .with_transport(TransportMode::UdpMulticast)
        .build()
        .unwrap();
    let reader_participant = Participant::builder("udp-topic-late-r")
        .domain_id(domain.id())
        .with_transport(TransportMode::UdpMulticast)
        .build()
        .unwrap();
    let writer_topic = writer_participant.topic::<Item>("udp-topic-late").unwrap();
    let reader_topic = reader_participant.topic::<Item>("udp-topic-late").unwrap();
    let publisher = Arc::new(
        writer_participant
            .create_publisher(topic_coherent_qos())
            .unwrap(),
    );
    let writer = writer_topic
        .writer()
        .qos(topic_coherent_qos())
        .publisher(&publisher)
        .build()
        .unwrap();

    publisher.begin_coherent_changes().unwrap();
    for value in [1, 2, 3] {
        writer.write(&Item { value }).unwrap();
    }
    publisher.end_coherent_changes().unwrap();

    publisher.begin_coherent_changes().unwrap();
    writer.write(&Item { value: 99 }).unwrap();

    let late = reader_topic
        .reader()
        .qos(topic_coherent_qos())
        .build()
        .unwrap();
    let mut got = drain_eventually(&late, 3, Duration::from_secs(10));
    got.sort_unstable();
    assert_eq!(
        got,
        vec![1, 2, 3],
        "UDP-in-one-process control: the wire leg already withholds an \
         unclosed set from a late joiner"
    );
    assert_nothing_more(&late, Duration::from_millis(500));
}

// ---------------------------------------------------------------------
// TOPIC scope, LIVE (not late-joiner) delivery, IntraProcess vs. control
// ---------------------------------------------------------------------

#[test]
fn intra_topic_scope_live_delivery_is_atomic() {
    let participant = Participant::builder("intra-topic-live")
        .domain_id(0)
        .with_transport(TransportMode::IntraProcess)
        .build()
        .unwrap();
    let topic = participant.topic::<Item>("intra-topic-live").unwrap();
    let publisher = Arc::new(participant.create_publisher(topic_coherent_qos()).unwrap());
    let writer = topic
        .writer()
        .qos(topic_coherent_qos())
        .publisher(&publisher)
        .build()
        .unwrap();
    // Bound BEFORE any write: this reader takes the LIVE merger fan-out
    // path, not the late-joiner replay path exercised above.
    let reader = topic.reader().qos(topic_coherent_qos()).build().unwrap();

    publisher.begin_coherent_changes().unwrap();
    for value in [10, 20, 30] {
        writer.write(&Item { value }).unwrap();
    }
    assert_eq!(
        drain_now(&reader),
        Vec::<i32>::new(),
        "a coherent-access reader must not see a member of a set its \
         writer has not closed yet, live delivery included"
    );

    publisher.end_coherent_changes().unwrap();

    let mut got = drain_now(&reader);
    got.sort_unstable();
    assert_eq!(
        got,
        vec![10, 20, 30],
        "the whole set must become visible at once, as soon as it closes"
    );
}

#[test]
fn udp_topic_scope_live_delivery_is_atomic() {
    let domain = unique_domain();
    let writer_participant = Participant::builder("udp-topic-live-w")
        .domain_id(domain.id())
        .with_transport(TransportMode::UdpMulticast)
        .build()
        .unwrap();
    let reader_participant = Participant::builder("udp-topic-live-r")
        .domain_id(domain.id())
        .with_transport(TransportMode::UdpMulticast)
        .build()
        .unwrap();
    let writer_topic = writer_participant.topic::<Item>("udp-topic-live").unwrap();
    let reader_topic = reader_participant.topic::<Item>("udp-topic-live").unwrap();
    let publisher = Arc::new(
        writer_participant
            .create_publisher(topic_coherent_qos())
            .unwrap(),
    );
    let writer = writer_topic
        .writer()
        .qos(topic_coherent_qos())
        .publisher(&publisher)
        .build()
        .unwrap();
    let reader = reader_topic
        .reader()
        .qos(topic_coherent_qos())
        .build()
        .unwrap();

    let deadline = Instant::now() + Duration::from_secs(10);
    while writer.matched_reader_count() == 0 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        writer.matched_reader_count() > 0,
        "writer/reader never matched"
    );

    publisher.begin_coherent_changes().unwrap();
    for value in [10, 20, 30] {
        writer.write(&Item { value }).unwrap();
    }
    assert_eq!(
        drain_eventually(&reader, 1, Duration::from_millis(300)),
        Vec::<i32>::new(),
        "UDP-in-one-process control: the wire leg already withholds a \
         member of an open set from a matched live reader"
    );

    publisher.end_coherent_changes().unwrap();

    let mut got = drain_eventually(&reader, 3, Duration::from_secs(10));
    got.sort_unstable();
    assert_eq!(got, vec![10, 20, 30]);
}

// ---------------------------------------------------------------------
// GROUP scope, two writers of one Publisher, late joiners (IntraProcess)
// ---------------------------------------------------------------------

#[test]
fn intra_group_scope_two_writers_late_joiners_see_closed_set_only() {
    let participant = Participant::builder("intra-group-late")
        .domain_id(0)
        .with_transport(TransportMode::IntraProcess)
        .build()
        .unwrap();
    let topic_a = participant.topic::<Item>("intra-group-late-a").unwrap();
    let topic_b = participant.topic::<Item>("intra-group-late-b").unwrap();
    let publisher = Arc::new(participant.create_publisher(group_coherent_qos()).unwrap());
    let writer_a = topic_a
        .writer()
        .qos(group_coherent_qos())
        .publisher(&publisher)
        .build()
        .unwrap();
    let writer_b = topic_b
        .writer()
        .qos(group_coherent_qos())
        .publisher(&publisher)
        .build()
        .unwrap();

    publisher.begin_coherent_changes().unwrap();
    writer_a.write(&Item { value: 1 }).unwrap();
    writer_a.write(&Item { value: 2 }).unwrap();
    writer_b.write(&Item { value: 3 }).unwrap();
    publisher.end_coherent_changes().unwrap();

    // A second GROUP set, left OPEN: writer_a contributes to it, writer_b
    // does not. Neither writer's history may hand any part of it to a
    // late joiner.
    publisher.begin_coherent_changes().unwrap();
    writer_a.write(&Item { value: 99 }).unwrap();

    let late_a = topic_a.reader().qos(group_coherent_qos()).build().unwrap();
    let late_b = topic_b.reader().qos(group_coherent_qos()).build().unwrap();

    let mut got_a = drain_now(&late_a);
    got_a.sort_unstable();
    assert_eq!(
        got_a,
        vec![1, 2],
        "writer A's late joiner must see only its share of the closed set"
    );
    assert_eq!(
        drain_now(&late_b),
        vec![3],
        "writer B's late joiner must see only its share of the closed set"
    );
}

#[test]
fn intra_group_scope_two_writers_live_delivery_is_atomic() {
    let participant = Participant::builder("intra-group-live")
        .domain_id(0)
        .with_transport(TransportMode::IntraProcess)
        .build()
        .unwrap();
    let topic_a = participant.topic::<Item>("intra-group-live-a").unwrap();
    let topic_b = participant.topic::<Item>("intra-group-live-b").unwrap();
    let publisher = Arc::new(participant.create_publisher(group_coherent_qos()).unwrap());
    let writer_a = topic_a
        .writer()
        .qos(group_coherent_qos())
        .publisher(&publisher)
        .build()
        .unwrap();
    let writer_b = topic_b
        .writer()
        .qos(group_coherent_qos())
        .publisher(&publisher)
        .build()
        .unwrap();
    let reader_a = topic_a.reader().qos(group_coherent_qos()).build().unwrap();
    let reader_b = topic_b.reader().qos(group_coherent_qos()).build().unwrap();

    publisher.begin_coherent_changes().unwrap();
    writer_a.write(&Item { value: 1 }).unwrap();
    writer_b.write(&Item { value: 2 }).unwrap();
    assert_eq!(drain_now(&reader_a), Vec::<i32>::new());
    assert_eq!(drain_now(&reader_b), Vec::<i32>::new());

    publisher.end_coherent_changes().unwrap();

    assert_eq!(drain_now(&reader_a), vec![1]);
    assert_eq!(drain_now(&reader_b), vec![2]);
}

// ---------------------------------------------------------------------
// GROUP scope, writer threads racing a closer thread. A sample's "stamp"
// into the active coherent set (`coherent_context_held`, under the
// Publisher's `set_lock`) and the stage of its encoded sample are two
// separate steps, the second well outside `set_lock` (the payload is not
// even serialized yet at stamp time). A close that drained the writer's
// queue the instant it saw the stamp raced the still-in-flight stage: a
// write preempted in that window landed in a queue already drained for its
// own set -- lost outright, or misattributed to whichever LATER set's
// close happened to find it there. The stamp therefore registers an outstanding
// member of its set, and the set is delivered by whichever comes last: its
// close, or its last member's stage (`dds::writer::intra_coherent`).
//
// `test_support::coherent_race::inject_stage_delay` widens that window
// from a handful of non-blocking instructions to a few hundred
// microseconds -- the race needs no help to exist (it is bare OS
// scheduling), but on an idle many-core test machine the odds of a
// quantum landing inside a window that narrow are negligible, so a CI
// run short enough to be useful needs the help to OBSERVE it.
// ---------------------------------------------------------------------

/// Holds the process-wide stage-delay knob for one test: serializes the
/// tests that set it, and resets it when dropped (including on a panic), so
/// it never leaks into another test sharing this binary.
struct StageDelayGuard(#[allow(dead_code)] std::sync::MutexGuard<'static, ()>);

static STAGE_DELAY: std::sync::Mutex<()> = std::sync::Mutex::new(());

impl StageDelayGuard {
    fn set(delay: Duration) -> Self {
        let held = STAGE_DELAY.lock().unwrap_or_else(|e| e.into_inner());
        hdds::test_support::coherent_race::inject_stage_delay(delay);
        Self(held)
    }
}

impl Drop for StageDelayGuard {
    fn drop(&mut self) {
        hdds::test_support::coherent_race::inject_stage_delay(Duration::ZERO);
    }
}

/// `writers[w]` and `readers[w]` together are one GROUP-scope member of
/// `publisher`'s coherent set, on its own topic (DataWriter is `Send`,
/// not `Sync`: each writer is moved into its own thread for the round and
/// handed back by `JoinHandle::join`, never shared by reference).
fn race_closer_vs_writers(
    writer_participant: &Arc<hdds::Participant>,
    reader_participant: &Arc<hdds::Participant>,
    rounds: usize,
    writers_per_round: usize,
) {
    let publisher = Arc::new(
        writer_participant
            .create_publisher(group_coherent_qos())
            .unwrap(),
    );

    let mut writers = Vec::new();
    let mut readers = Vec::new();
    for w in 0..writers_per_round {
        let topic_name = format!("race-closer-vs-writers-{w}");
        let writer_topic = writer_participant.topic::<Item>(&topic_name).unwrap();
        let reader_topic = reader_participant.topic::<Item>(&topic_name).unwrap();
        let writer = writer_topic
            .writer()
            .qos(group_coherent_qos())
            .publisher(&publisher)
            .build()
            .unwrap();
        let reader = reader_topic
            .reader()
            .qos(group_coherent_qos())
            .build()
            .unwrap();
        writers.push(writer);
        readers.push(reader);
    }

    // Let discovery settle (SPDP/SEDP, real for the two-participant UDP
    // control) before the timed per-round checks below start: an
    // unmatched writer's RELIABLE history repair alone can still deliver
    // a sample well past this test's 200ms per-round window, which would
    // be a false failure unrelated to the race this test exists to catch.
    let deadline = Instant::now() + Duration::from_secs(5);
    while writers.iter().any(|w| w.matched_reader_count() == 0) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }

    for round in 0..rounds {
        publisher.begin_coherent_changes().unwrap();

        let barrier = Arc::new(std::sync::Barrier::new(writers_per_round + 1));
        let mut handles = Vec::with_capacity(writers_per_round);
        for (w, writer) in writers.into_iter().enumerate() {
            let barrier = Arc::clone(&barrier);
            let value = i32::try_from(round * writers_per_round + w).unwrap();
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                let _ = writer.write(&Item { value });
                writer
            }));
        }
        let publisher_for_close = Arc::clone(&publisher);
        let barrier_for_close = Arc::clone(&barrier);
        let closer = std::thread::spawn(move || {
            barrier_for_close.wait();
            publisher_for_close.end_coherent_changes().unwrap();
        });

        writers = handles.into_iter().map(|h| h.join().unwrap()).collect();
        closer.join().unwrap();

        // Bounded: a lost sample never arrives at all, so this must not
        // wait long -- the set was delivered by whichever of the close and
        // the writes this thread already joined above came last.
        for (w, reader) in readers.iter().enumerate() {
            let expected = i32::try_from(round * writers_per_round + w).unwrap();
            let got = drain_eventually(reader, 1, Duration::from_millis(200));
            assert_eq!(
                got,
                vec![expected],
                "round {round} writer {w}: its own value must be delivered \
                 whole with THIS round's close -- never lost, never folded \
                 into a later one"
            );
        }
    }
}

#[test]
fn intra_group_scope_race_closer_vs_writers_loses_nothing() {
    let _delay = StageDelayGuard::set(Duration::from_micros(500));
    let participant = Participant::builder("race-closer-vs-writers-intra")
        .domain_id(0)
        .with_transport(TransportMode::IntraProcess)
        .build()
        .unwrap();
    race_closer_vs_writers(&participant, &participant, 100, 8);
}

/// The same race with no injected delay: ordinary scheduling only.
#[test]
fn intra_group_scope_race_closer_vs_writers_loses_nothing_undelayed() {
    let _delay = StageDelayGuard::set(Duration::ZERO);
    let participant = Participant::builder("race-closer-vs-writers-intra-undelayed")
        .domain_id(0)
        .with_transport(TransportMode::IntraProcess)
        .build()
        .unwrap();
    race_closer_vs_writers(&participant, &participant, 100, 8);
}

/// UDP control, TWO participants (writer side, reader side, as in every
/// other `udp_*` control in this file): a writer with a confirmed remote
/// peer never takes the intra-process fast path (`has_remote_peers()` is
/// true), so it never stages anything for local delivery --
/// there is no queue for a close to drain early, so no race to lose
/// anything to. Passes regardless of whatever the stage-delay injection
/// above left set (it only sleeps on the branches that push into that
/// queue, which this path never reaches) -- this test does not reset it
/// on entry, which is itself part of what it is proving.
#[test]
fn udp_group_scope_race_closer_vs_writers_control() {
    let domain = unique_domain();
    let writer_participant = Participant::builder("race-closer-vs-writers-udp-w")
        .domain_id(domain.id())
        .with_transport(TransportMode::UdpMulticast)
        .build()
        .unwrap();
    let reader_participant = Participant::builder("race-closer-vs-writers-udp-r")
        .domain_id(domain.id())
        .with_transport(TransportMode::UdpMulticast)
        .build()
        .unwrap();
    race_closer_vs_writers(&writer_participant, &reader_participant, 20, 4);
}

// ---------------------------------------------------------------------
// The close never waits for a member still on its way
// ---------------------------------------------------------------------

/// A close that comes while a stamped member has not staged yet returns at
/// once and delivers nothing (the set is incomplete); the member's own
/// stage then delivers the whole set, before its write() returns.
#[test]
fn intra_topic_scope_close_before_a_member_stages_is_delivered_by_the_stage() {
    let _delay = StageDelayGuard::set(Duration::from_millis(300));
    let participant = Participant::builder("intra-close-before-stage")
        .domain_id(0)
        .with_transport(TransportMode::IntraProcess)
        .build()
        .unwrap();
    let topic = participant
        .topic::<Item>("intra-close-before-stage")
        .unwrap();
    let publisher = Arc::new(participant.create_publisher(topic_coherent_qos()).unwrap());
    let writer = topic
        .writer()
        .qos(topic_coherent_qos())
        .publisher(&publisher)
        .build()
        .unwrap();
    let reader = topic.reader().qos(topic_coherent_qos()).build().unwrap();

    publisher.begin_coherent_changes().unwrap();
    writer.write(&Item { value: 1 }).unwrap();
    let (write_tx, write_rx) = std::sync::mpsc::channel();
    let straggler = std::thread::spawn(move || {
        let _ = write_tx.send(writer.write(&Item { value: 2 }));
        writer
    });
    // Let the second write stamp and park in the injected delay.
    std::thread::sleep(Duration::from_millis(60));

    let (close_tx, close_rx) = std::sync::mpsc::channel();
    let closer_publisher = Arc::clone(&publisher);
    std::thread::spawn(move || {
        let _ = close_tx.send(closer_publisher.end_coherent_changes());
    });
    let closed = close_rx
        .recv_timeout(Duration::from_millis(200))
        .expect("the close must not wait for the member still on its way");
    closed.unwrap();
    assert!(
        write_rx.try_recv().is_err(),
        "fixture: the second write must still be on its way at the close"
    );
    assert_eq!(
        drain_now(&reader),
        Vec::<i32>::new(),
        "an incomplete set delivers nothing, not even its staged member"
    );

    write_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("the straggling write returns")
        .unwrap();
    assert_eq!(
        drain_now(&reader),
        vec![1, 2],
        "the last member's stage delivers the whole set, in order"
    );
    drop(straggler.join().unwrap());
}

/// A VOLATILE writer with no confirmed remote reader keeps its sets off the
/// wire (no end of set is sent), but its co-located readers are still owed
/// each set, whole, at its close.
#[test]
fn intra_topic_scope_volatile_live_delivery_is_atomic() {
    let qos = || QoS::reliable().keep_all().presentation_topic_coherent();
    let participant = Participant::builder("intra-topic-volatile")
        .domain_id(0)
        .with_transport(TransportMode::IntraProcess)
        .build()
        .unwrap();
    let topic = participant.topic::<Item>("intra-topic-volatile").unwrap();
    let publisher = Arc::new(participant.create_publisher(qos()).unwrap());
    let writer = topic
        .writer()
        .qos(qos())
        .publisher(&publisher)
        .build()
        .unwrap();
    let reader = topic.reader().qos(qos()).build().unwrap();

    for round in 0..2 {
        publisher.begin_coherent_changes().unwrap();
        for value in [10, 20, 30] {
            writer
                .write(&Item {
                    value: value + round,
                })
                .unwrap();
        }
        assert_eq!(drain_now(&reader), Vec::<i32>::new());
        publisher.end_coherent_changes().unwrap();
        assert_eq!(
            drain_now(&reader),
            vec![10 + round, 20 + round, 30 + round],
            "round {round}: the whole set at its close"
        );
    }
}

/// A listener run by the delivery of a set, on the closing thread, begins,
/// writes into and ends a set of the SAME Publisher. The delivery runs with
/// the Publisher's lock released, so this completes.
#[test]
fn intra_listener_reentering_the_publisher_from_a_delivery_completes() {
    use hdds::dds::DataReaderListener;

    struct Reenter {
        publisher: Arc<hdds::dds::Publisher>,
        writer_b: std::sync::Mutex<Option<hdds::DataWriter<Item>>>,
        done: std::sync::Mutex<std::sync::mpsc::Sender<hdds::Result<()>>>,
    }
    impl DataReaderListener<Item> for Reenter {
        fn on_data_available(&self, sample: &Item) {
            if sample.value != 1 {
                return;
            }
            let Some(writer_b) = self.writer_b.lock().unwrap().take() else {
                return;
            };
            let result = self
                .publisher
                .begin_coherent_changes()
                .and_then(|()| writer_b.write(&Item { value: 7 }))
                .and_then(|()| self.publisher.end_coherent_changes());
            let _ = self.done.lock().unwrap().send(result);
        }
    }

    let participant = Participant::builder("intra-reenter")
        .domain_id(0)
        .with_transport(TransportMode::IntraProcess)
        .build()
        .unwrap();
    let topic_a = participant.topic::<Item>("intra-reenter-a").unwrap();
    let topic_b = participant.topic::<Item>("intra-reenter-b").unwrap();
    let publisher = Arc::new(participant.create_publisher(topic_coherent_qos()).unwrap());
    let writer_a = topic_a
        .writer()
        .qos(topic_coherent_qos())
        .publisher(&publisher)
        .build()
        .unwrap();
    let writer_b = topic_b
        .writer()
        .qos(topic_coherent_qos())
        .publisher(&publisher)
        .build()
        .unwrap();
    let reader_b = topic_b.reader().qos(topic_coherent_qos()).build().unwrap();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let listener = Arc::new(Reenter {
        publisher: Arc::clone(&publisher),
        writer_b: std::sync::Mutex::new(Some(writer_b)),
        done: std::sync::Mutex::new(done_tx),
    });
    let reader_a = topic_a
        .reader()
        .qos(topic_coherent_qos())
        .with_listener(Arc::clone(&listener) as Arc<dyn DataReaderListener<Item>>)
        .build()
        .unwrap();

    let (close_tx, close_rx) = std::sync::mpsc::channel();
    let closer_publisher = Arc::clone(&publisher);
    std::thread::spawn(move || {
        let result = closer_publisher
            .begin_coherent_changes()
            .and_then(|()| writer_a.write(&Item { value: 1 }))
            .and_then(|()| closer_publisher.end_coherent_changes());
        let _ = close_tx.send(result);
        writer_a
    });

    done_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("the listener's own set never completed: deadlocked")
        .unwrap();
    close_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("the outer close never returned: deadlocked")
        .unwrap();
    assert_eq!(drain_now(&reader_a), vec![1]);
    assert_eq!(
        drain_now(&reader_b),
        vec![7],
        "the nested set is delivered too"
    );
}

// ---------------------------------------------------------------------
// Probe: a writer dropped mid-open GROUP set (its Bridge kept
// alive by the Publisher's `state.held`) -- does its ALREADY-STAGED
// local member still reach a live co-located reader when another
// writer's thread later closes the set?
// ---------------------------------------------------------------------

#[test]
fn intra_group_scope_writer_dropped_mid_set_local_live_reader() {
    let participant = Participant::builder("intra-drop-mid-set")
        .domain_id(0)
        .with_transport(TransportMode::IntraProcess)
        .build()
        .unwrap();
    let topic_a = participant.topic::<Item>("intra-drop-mid-set-a").unwrap();
    let topic_b = participant.topic::<Item>("intra-drop-mid-set-b").unwrap();
    let publisher = Arc::new(participant.create_publisher(group_coherent_qos()).unwrap());
    let writer_a = topic_a
        .writer()
        .qos(group_coherent_qos())
        .publisher(&publisher)
        .build()
        .unwrap();
    let writer_b = topic_b
        .writer()
        .qos(group_coherent_qos())
        .publisher(&publisher)
        .build()
        .unwrap();
    // Live, bound BEFORE any write: takes the merger fast path.
    let reader_a = topic_a.reader().qos(group_coherent_qos()).build().unwrap();
    let reader_b = topic_b.reader().qos(group_coherent_qos()).build().unwrap();

    publisher.begin_coherent_changes().unwrap();
    writer_a.write(&Item { value: 1 }).unwrap();
    assert_eq!(
        drain_now(&reader_a),
        Vec::<i32>::new(),
        "the set is still open: nothing delivered yet"
    );

    // The application drops writer_a's handle WHILE the GROUP set it just
    // contributed to is still open. The Publisher's `state.held` keeps
    // writer_a's Bridge (and the Arc<IntraCoherentSets> it shares with the
    // now-dead DataWriter) alive for the rest of this set.
    drop(writer_a);

    writer_b.write(&Item { value: 2 }).unwrap();
    publisher.end_coherent_changes().unwrap();

    let got_a = drain_now(&reader_a);
    let got_b = drain_now(&reader_b);
    assert_eq!(got_b, vec![2], "writer B's live reader: unaffected");
    assert_eq!(
        got_a,
        vec![1],
        "writer A's live, already-bound reader must still get its own \
         already-staged member of a set that DID go on to close normally \
         (driven by writer B / the Publisher), not lose it just because \
         writer A's own DataWriter handle was dropped first"
    );
}

// ---------------------------------------------------------------------
// A writer with BOTH a co-located reader AND a remote one (DDS v1.4
// SS2.2.3.6): write()'s mixed branch must not deliver the co-located
// reader at once, through the merger, without holding it back for the
// rest of the set -- the SAME change's `CoherentStamp`, taken for
// the wire tags, would sit unused and silently withdraw on drop. The
// branch therefore stages through `CoherentStamp` too, exactly as the
// intra-process-only fast path above does.
// ---------------------------------------------------------------------

/// Poll `done` until it reports true or `timeout` elapses.
fn wait_for(timeout: Duration, mut done: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if done() {
            return true;
        }
        if Instant::now() >= deadline {
            return done();
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// A writer participant with a co-located reader, and a second,
/// independent participant with a remote reader of the same topic: the
/// writer has BOTH a local AND a remote target once discovery completes,
/// which is write()'s MIXED branch (`has_local_readers && has_remote_peers`),
/// never the intra-process-only fast path the tests above exercise.
#[allow(clippy::type_complexity)]
fn mixed_local_and_remote_pair<T: hdds::DdsTrait>(
    name: &str,
) -> (
    hdds::DataWriter<T>,
    hdds::DataReader<T>,
    hdds::DataReader<T>,
    Arc<hdds::dds::Publisher>,
    Arc<Participant>,
    Arc<Participant>,
    hdds::test_support::domains::DomainLease,
) {
    let domain = unique_domain();
    let writer_participant = Participant::builder(&format!("{name}-w"))
        .domain_id(domain.id())
        .with_transport(TransportMode::UdpMulticast)
        .build()
        .unwrap();
    let remote_participant = Participant::builder(&format!("{name}-r"))
        .domain_id(domain.id())
        .with_transport(TransportMode::UdpMulticast)
        .build()
        .unwrap();
    let writer_topic = writer_participant.topic::<T>(name).unwrap();
    let remote_topic = remote_participant.topic::<T>(name).unwrap();
    let publisher = Arc::new(
        writer_participant
            .create_publisher(topic_coherent_qos())
            .unwrap(),
    );
    let writer = writer_topic
        .writer()
        .qos(topic_coherent_qos())
        .publisher(&publisher)
        .build()
        .unwrap();
    // Co-located: bound on the writer's own participant, before any write,
    // so it takes the live merger fan-out path.
    let local_reader = writer_topic
        .reader()
        .qos(topic_coherent_qos())
        .build()
        .unwrap();
    let remote_reader = remote_topic
        .reader()
        .qos(topic_coherent_qos())
        .build()
        .unwrap();
    // Both targets must be matched before the mixed branch is exercised:
    // the co-located one is synchronous, the remote one is real SEDP over
    // loopback UDP.
    assert!(
        wait_for(Duration::from_secs(10), || writer
            .get_matched_subscriptions()
            .len()
            >= 2),
        "writer did not match both the co-located and the remote reader"
    );
    (
        writer,
        local_reader,
        remote_reader,
        publisher,
        writer_participant,
        remote_participant,
        domain,
    )
}

#[test]
fn mixed_topic_scope_live_delivery_is_atomic_for_the_local_reader() {
    let (writer, local_reader, remote_reader, publisher, _wp, _rp, _domain) =
        mixed_local_and_remote_pair::<Item>("mixed-topic-live");

    publisher.begin_coherent_changes().unwrap();
    for value in [10, 20, 30] {
        writer.write(&Item { value }).unwrap();
    }
    assert_eq!(
        drain_now(&local_reader),
        Vec::<i32>::new(),
        "the co-located reader of a writer with a remote peer too must not \
         see a member of a set its writer has not closed yet"
    );

    publisher.end_coherent_changes().unwrap();

    let mut got_local = drain_now(&local_reader);
    got_local.sort_unstable();
    assert_eq!(
        got_local,
        vec![10, 20, 30],
        "the whole set must become visible to the co-located reader at \
         once, as soon as it closes"
    );
    let mut got_remote = drain_eventually(&remote_reader, 3, Duration::from_secs(10));
    got_remote.sort_unstable();
    assert_eq!(
        got_remote,
        vec![10, 20, 30],
        "control: the wire leg to the remote reader is unaffected"
    );
}

/// A keyed type, for the dispose/unregister coverage below: a lifecycle
/// change needs an instance to dispose or unregister.
#[derive(Debug, Clone, PartialEq, hdds::DDS)]
struct Keyed {
    #[key]
    id: i32,
    value: i32,
}

/// A dispose inside the same open set a sample belongs to is itself a
/// member of it (DDS v1.4 SS2.2.3.6 draws no distinction between a data
/// change and a lifecycle change): the co-located reader of a writer with
/// a remote peer must not see it ahead of the rest of the set either.
#[test]
fn mixed_topic_scope_dispose_inside_an_open_set_is_held_back_for_the_local_reader() {
    let (writer, local_reader, remote_reader, publisher, _wp, _rp, _domain) =
        mixed_local_and_remote_pair::<Keyed>("mixed-topic-dispose");

    publisher.begin_coherent_changes().unwrap();
    writer.write(&Keyed { id: 1, value: 10 }).unwrap();
    writer.dispose(&Keyed { id: 1, value: 10 }).unwrap();
    writer.write(&Keyed { id: 1, value: 11 }).unwrap();
    assert_eq!(
        lifecycle_shape(drain_lifecycle_now(&local_reader)),
        Vec::<String>::new(),
        "nothing of the open set, dispose included, reaches the \
         co-located reader ahead of the close"
    );

    publisher.end_coherent_changes().unwrap();

    assert_eq!(
        lifecycle_shape(drain_lifecycle_now(&local_reader)),
        vec!["D(1,10)", "NotAliveDisposed", "D(1,11)"],
        "the set closes with the dispose ordered between the samples \
         around it, all delivered together"
    );
    let remote_shape = lifecycle_shape(drain_lifecycle_eventually(
        &remote_reader,
        3,
        Duration::from_secs(10),
    ));
    assert_eq!(
        remote_shape,
        vec!["D(1,10)", "NotAliveDisposed", "D(1,11)"],
        "control: the wire leg to the remote reader is unaffected"
    );
}

// ---------------------------------------------------------------------
// A dispose/unregister inside an open coherent set, intra-process-only
// writer (no transport at all): `emit_lifecycle_change`'s no-transport
// branch must not take a `CoherentStamp` for its wire tags and drop it on
// the spot, then deliver to the co-located reader unconditionally and
// immediately -- a member of an open set must not reach a coherent-access
// reader ahead of the rest of it.
// ---------------------------------------------------------------------

fn lifecycle_shape(seen: Vec<(Option<i32>, hdds::dds::InstanceState)>) -> Vec<String> {
    seen.into_iter()
        .map(|(value, state)| match value {
            Some(value) => format!("D(1,{value})"),
            None => format!("{state:?}"),
        })
        .collect()
}

fn drain_lifecycle_now(
    reader: &hdds::DataReader<Keyed>,
) -> Vec<(Option<i32>, hdds::dds::InstanceState)> {
    let mut out = Vec::new();
    while let Some((sample, info)) = reader.take_with_info().unwrap() {
        out.push((sample.map(|s| s.value), info.instance_state));
    }
    out
}

fn drain_lifecycle_eventually(
    reader: &hdds::DataReader<Keyed>,
    expected: usize,
    timeout: Duration,
) -> Vec<(Option<i32>, hdds::dds::InstanceState)> {
    let deadline = Instant::now() + timeout;
    let mut out = Vec::new();
    while out.len() < expected && Instant::now() < deadline {
        out.extend(drain_lifecycle_now(reader));
        if out.len() < expected {
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    out
}

#[test]
fn intra_topic_scope_dispose_inside_an_open_set_is_held_back() {
    let participant = Participant::builder("intra-topic-dispose")
        .domain_id(0)
        .with_transport(TransportMode::IntraProcess)
        .build()
        .unwrap();
    let topic = participant.topic::<Keyed>("intra-topic-dispose").unwrap();
    let publisher = Arc::new(participant.create_publisher(topic_coherent_qos()).unwrap());
    let writer = topic
        .writer()
        .qos(topic_coherent_qos())
        .publisher(&publisher)
        .build()
        .unwrap();
    // Bound BEFORE any write: the live merger fan-out path.
    let reader = topic.reader().qos(topic_coherent_qos()).build().unwrap();

    publisher.begin_coherent_changes().unwrap();
    writer.write(&Keyed { id: 1, value: 10 }).unwrap();
    writer.dispose(&Keyed { id: 1, value: 10 }).unwrap();
    writer.write(&Keyed { id: 1, value: 11 }).unwrap();
    assert_eq!(
        lifecycle_shape(drain_lifecycle_now(&reader)),
        Vec::<String>::new(),
        "a coherent-access reader must not see a dispose that is a member \
         of a set its writer has not closed yet"
    );

    publisher.end_coherent_changes().unwrap();

    assert_eq!(
        lifecycle_shape(drain_lifecycle_now(&reader)),
        vec!["D(1,10)", "NotAliveDisposed", "D(1,11)"],
        "the whole set, dispose included, becomes visible at once"
    );
}

// ---------------------------------------------------------------------
// A durable lone intra-process writer's journal carries coherent-set
// markers on a lifecycle change, same as a sample, so a TRANSIENT_LOCAL
// late joiner's `HistoryCache::snapshot_for_local_replay` replays a
// closed set's dispose whole, with the rest of its set, and withholds an
// open one -- this pins that behavior.
// ---------------------------------------------------------------------

#[test]
fn intra_topic_scope_late_joiner_replays_a_dispose_inside_a_closed_set_whole() {
    let participant = Participant::builder("intra-topic-dispose-late")
        .domain_id(0)
        .with_transport(TransportMode::IntraProcess)
        .build()
        .unwrap();
    let topic = participant
        .topic::<Keyed>("intra-topic-dispose-late")
        .unwrap();
    let publisher = Arc::new(participant.create_publisher(topic_coherent_qos()).unwrap());
    let writer = topic
        .writer()
        .qos(topic_coherent_qos())
        .publisher(&publisher)
        .build()
        .unwrap();

    publisher.begin_coherent_changes().unwrap();
    writer.write(&Keyed { id: 1, value: 10 }).unwrap();
    writer.dispose(&Keyed { id: 1, value: 10 }).unwrap();
    writer.write(&Keyed { id: 1, value: 11 }).unwrap();
    publisher.end_coherent_changes().unwrap();

    // A second set, left OPEN: its member must never reach the late
    // joiner's replay (DDS v1.4 SS2.2.2.4.1.10/11).
    publisher.begin_coherent_changes().unwrap();
    writer.dispose(&Keyed { id: 1, value: 11 }).unwrap();

    let late = topic.reader().qos(topic_coherent_qos()).build().unwrap();
    assert_eq!(
        lifecycle_shape(drain_lifecycle_now(&late)),
        vec!["D(1,10)", "NotAliveDisposed", "D(1,11)"],
        "the late joiner replays the closed set whole, dispose included, \
         and nothing of the still-open second set"
    );
}
