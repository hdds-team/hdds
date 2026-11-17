// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Two gaps `same_participant_matching.rs` and `local_pairs_judged_like_remote.rs`
//! do not cover: a writer and a reader of DIFFERENT participants in
//! `TransportMode::IntraProcess` (no `discovery_fsm` on either side, so
//! nothing but domain_registry.rs's `LocalMatchStatus` can report the
//! match), and the order a late reader is told of a TRANSIENT_LOCAL
//! writer's existing history in: PUBLICATION_MATCHED/SUBSCRIPTION_MATCHED
//! BEFORE on_data_available (DDS v1.4 Sec.2.2.4.1), not after.

use hdds::dds::{
    DataReaderListener, DataWriterListener, PublicationMatchedStatus, SubscriptionMatchedStatus,
};
use hdds::{Participant, QoS, TransportMode};
use std::sync::atomic::{AtomicI32, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(hdds::DDS, Debug, Clone)]
struct Probe {
    value: i64,
}

fn wait_for(timeout: Duration, mut done: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if done() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    done()
}

#[derive(Default)]
struct Seen {
    current: AtomicI32,
    total: AtomicU32,
}

impl DataWriterListener<Probe> for Seen {
    fn on_publication_matched(&self, status: PublicationMatchedStatus) {
        self.current
            .store(status.current_count as i32, Ordering::SeqCst);
        self.total.store(status.total_count, Ordering::SeqCst);
    }
}

impl DataReaderListener<Probe> for Seen {
    fn on_subscription_matched(&self, status: SubscriptionMatchedStatus) {
        self.current
            .store(status.current_count as i32, Ordering::SeqCst);
        self.total.store(status.total_count, Ordering::SeqCst);
    }
}

/// Two IntraProcess participants, same process, same domain -- a writer in
/// one, a reader in the other. Neither has a `discovery_fsm`
/// (`TransportMode::IntraProcess` never builds one), so neither has a
/// `MatchNotificationRegistry` either: domain_registry.rs's
/// `LocalMatchStatus` is the ONLY thing that can report this pair as
/// matched, and it must, whichever side registers first.
fn cross_participant_intra_process_match(name: &str, writer_first: bool) {
    let publisher = Participant::builder(&format!("{name}_pub"))
        .domain_id(0)
        .with_transport(TransportMode::IntraProcess)
        .build()
        .unwrap();
    let subscriber = Participant::builder(&format!("{name}_sub"))
        .domain_id(0)
        .with_transport(TransportMode::IntraProcess)
        .build()
        .unwrap();

    let writer_seen = Arc::new(Seen::default());
    let reader_seen = Arc::new(Seen::default());
    let build_writer = || {
        publisher
            .topic::<Probe>(name)
            .unwrap()
            .writer()
            .qos(QoS::reliable().keep_last(8))
            .with_listener(Arc::clone(&writer_seen) as Arc<dyn DataWriterListener<Probe>>)
            .build()
            .unwrap()
    };
    let build_reader = || {
        subscriber
            .topic::<Probe>(name)
            .unwrap()
            .reader()
            .qos(QoS::reliable().keep_last(8))
            .with_listener(Arc::clone(&reader_seen) as Arc<dyn DataReaderListener<Probe>>)
            .build()
            .unwrap()
    };
    let (writer, reader) = if writer_first {
        let writer = build_writer();
        (writer, build_reader())
    } else {
        let reader = build_reader();
        (build_writer(), reader)
    };

    assert!(
        wait_for(Duration::from_secs(5), || writer_seen
            .current
            .load(Ordering::SeqCst)
            == 1
            && writer.matched_reader_count() == 1),
        "{name}: the cross-participant IntraProcess writer never saw its reader matched \
         (current={}, matched_reader_count={})",
        writer_seen.current.load(Ordering::SeqCst),
        writer.matched_reader_count()
    );
    assert!(
        wait_for(Duration::from_secs(5), || reader_seen
            .current
            .load(Ordering::SeqCst)
            == 1),
        "{name}: the cross-participant IntraProcess reader never saw its writer matched"
    );
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(writer_seen.total.load(Ordering::SeqCst), 1, "{name}");
    assert_eq!(reader_seen.total.load(Ordering::SeqCst), 1, "{name}");

    writer.write(&Probe { value: 42 }).unwrap();
    assert!(
        wait_for(Duration::from_secs(5), || reader
            .take()
            .ok()
            .flatten()
            .is_some_and(|s| s.value == 42)),
        "{name}: cross-participant IntraProcess data was not delivered"
    );

    // current_count must go down when the matched peer is deleted (DDS
    // v1.4 Sec.2.2.4.1), across participants as well as within one.
    drop(reader);
    assert!(
        wait_for(Duration::from_secs(5), || writer_seen
            .current
            .load(Ordering::SeqCst)
            == 0),
        "{name}: the writer's PUBLICATION_MATCHED current_count did not drop after its \
         cross-participant reader was deleted"
    );
    assert_eq!(writer.matched_reader_count(), 0, "{name}");
}

#[test]
fn cross_participant_intra_process_match_writer_first() {
    cross_participant_intra_process_match("xpart_intra_wf", true);
}

#[test]
fn cross_participant_intra_process_match_reader_first() {
    cross_participant_intra_process_match("xpart_intra_rf", false);
}

/// A TRANSIENT_LOCAL writer that already has history must tell a late
/// reader it matched BEFORE that history is replayed into it: the merger's
/// replay (`TopicMerger::add_reader`) fires `on_data_available` for each
/// replayed sample from inside the SAME registration call that fires
/// SUBSCRIPTION_MATCHED, so the order the application is told in is the
/// order it reads here (`reader::notices`: FIFO, oldest queued first, told
/// once the registration's own delivery scope ends).
#[derive(Default)]
struct OrderLog {
    events: Mutex<Vec<&'static str>>,
}

impl DataReaderListener<Probe> for OrderLog {
    fn on_subscription_matched(&self, _status: SubscriptionMatchedStatus) {
        self.events
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push("matched");
    }
    fn on_data_available(&self, _sample: &Probe) {
        self.events
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push("data");
    }
}

fn transient_local_replay_is_announced_after_the_match(mode: TransportMode, name: &str) {
    let lease = matches!(mode, TransportMode::UdpMulticast)
        .then(hdds::test_support::domains::unique_domain);
    let participant = Participant::builder(name)
        .domain_id(lease.as_ref().map_or(0, |l| l.id()))
        .with_transport(mode)
        .build()
        .unwrap();
    let topic = participant.topic::<Probe>(name).unwrap();

    // The writer exists first, with history, before any reader does.
    let writer = topic
        .writer()
        .qos(QoS::reliable().keep_last(8).transient_local())
        .build()
        .unwrap();
    for value in 1..=3 {
        writer.write(&Probe { value }).unwrap();
    }
    // Let the writer's own history settle before the late reader joins, so
    // the replay below is unambiguously a late-joiner catch-up, not a race
    // with the writes above.
    std::thread::sleep(Duration::from_millis(100));

    let log = Arc::new(OrderLog::default());
    let _reader = topic
        .reader()
        .qos(QoS::reliable().keep_last(8).transient_local())
        .with_listener(Arc::clone(&log) as Arc<dyn DataReaderListener<Probe>>)
        .build()
        .unwrap();

    assert!(
        wait_for(Duration::from_secs(5), || !log
            .events
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_empty()),
        "{name}: the late reader was told nothing at all"
    );
    // Give the replay's remaining samples time to arrive too.
    std::thread::sleep(Duration::from_millis(300));

    let events = log.events.lock().unwrap_or_else(|e| e.into_inner()).clone();
    assert!(
        events.contains(&"matched"),
        "{name}: SUBSCRIPTION_MATCHED never reached the late reader: {events:?}"
    );
    assert!(
        events.contains(&"data"),
        "{name}: the TRANSIENT_LOCAL history was never replayed to the late reader: {events:?}"
    );
    let matched_at = events.iter().position(|e| *e == "matched").unwrap();
    let first_data_at = events.iter().position(|e| *e == "data").unwrap();
    assert!(
        matched_at < first_data_at,
        "{name}: the late reader was handed replayed data before it was told of the match: \
         {events:?}"
    );
}

#[test]
fn transient_local_replay_is_announced_after_the_match_intra_process() {
    transient_local_replay_is_announced_after_the_match(
        TransportMode::IntraProcess,
        "replay_order_intra",
    );
}

#[test]
fn transient_local_replay_is_announced_after_the_match_udp() {
    transient_local_replay_is_announced_after_the_match(
        TransportMode::UdpMulticast,
        "replay_order_udp",
    );
}
