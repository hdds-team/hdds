// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! A writer and a reader of the SAME participant match each other.
//!
//! DDS v1.4 Sec.2.2.4.1 defines PUBLICATION_MATCHED (SUBSCRIPTION_MATCHED)
//! as the DataWriter (DataReader) having found a DataReader (DataWriter)
//! that matches the Topic and has compatible QoS: nothing in it excludes an
//! endpoint of the same participant. Such a pairing was never reported.

use hdds::dds::{
    DataReaderListener, DataWriterListener, PublicationMatchedStatus, SubscriptionMatchedStatus,
};
use hdds::{Participant, QoS, TransportMode};
use std::sync::atomic::{AtomicI32, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(hdds::DDS, Debug, Clone)]
struct Probe {
    value: i64,
}

#[derive(Default)]
struct Seen {
    current: AtomicI32,
    total: AtomicU32,
    calls: AtomicU32,
}

impl DataWriterListener<Probe> for Seen {
    fn on_publication_matched(&self, status: PublicationMatchedStatus) {
        self.current
            .store(status.current_count as i32, Ordering::SeqCst);
        self.total.store(status.total_count, Ordering::SeqCst);
        self.calls.fetch_add(1, Ordering::SeqCst);
    }
}

impl DataReaderListener<Probe> for Seen {
    fn on_subscription_matched(&self, status: SubscriptionMatchedStatus) {
        self.current
            .store(status.current_count as i32, Ordering::SeqCst);
        self.total.store(status.total_count, Ordering::SeqCst);
        self.calls.fetch_add(1, Ordering::SeqCst);
    }
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

fn local_endpoints_match(mode: TransportMode, name: &str, reader_first: bool) {
    // Only UDP opens real sockets; IntraProcess never touches a domain's
    // ports, so it keeps the harmless literal 0 instead of spending a lease.
    let lease = matches!(mode, TransportMode::UdpMulticast)
        .then(hdds::test_support::domains::unique_domain);
    let participant = Participant::builder(name)
        .domain_id(lease.as_ref().map_or(0, |l| l.id()))
        .with_transport(mode)
        .build()
        .unwrap();
    let topic = participant.topic::<Probe>(name).unwrap();
    let writer_seen = Arc::new(Seen::default());
    let reader_seen = Arc::new(Seen::default());
    let build_reader = || {
        topic
            .reader()
            .qos(QoS::reliable().keep_last(8))
            .with_listener(Arc::clone(&reader_seen) as Arc<dyn DataReaderListener<Probe>>)
            .build()
            .unwrap()
    };
    let build_writer = || {
        topic
            .writer()
            .qos(QoS::reliable().keep_last(8))
            .with_listener(Arc::clone(&writer_seen) as Arc<dyn DataWriterListener<Probe>>)
            .build()
            .unwrap()
    };
    let (writer, reader) = if reader_first {
        let reader = build_reader();
        (build_writer(), reader)
    } else {
        let writer = build_writer();
        (writer, build_reader())
    };

    assert!(
        wait_for(Duration::from_secs(5), || reader_seen
            .current
            .load(Ordering::SeqCst)
            == 1),
        "{name}: on_subscription_matched never reported the writer of its own participant"
    );
    assert!(
        wait_for(Duration::from_secs(5), || writer_seen
            .current
            .load(Ordering::SeqCst)
            == 1
            && writer.matched_reader_count() == 1),
        "{name}: on_publication_matched never reported the reader of its own participant \
         (current={}, matched_reader_count={})",
        writer_seen.current.load(Ordering::SeqCst),
        writer.matched_reader_count()
    );
    // Once each, not once per path.
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(writer_seen.total.load(Ordering::SeqCst), 1, "{name}");
    assert_eq!(reader_seen.total.load(Ordering::SeqCst), 1, "{name}");

    // The pairing is the application's view only: the samples still go
    // through the writer's merger, each once, and the reader is owed no
    // acknowledgement (no RTPS proxy on either side), so the reliable
    // writer is fully acknowledged.
    for value in 1..=3 {
        writer.write(&Probe { value }).unwrap();
    }
    let mut taken = Vec::new();
    assert!(
        wait_for(Duration::from_secs(5), || {
            while let Some(sample) = reader.take().unwrap() {
                taken.push(sample.value);
            }
            taken.len() >= 3
        }),
        "{name}: the local reader did not receive the samples"
    );
    std::thread::sleep(Duration::from_millis(200));
    while let Some(sample) = reader.take().unwrap() {
        taken.push(sample.value);
    }
    assert_eq!(taken, vec![1, 2, 3], "{name}: each sample once");
    assert!(
        wait_for(Duration::from_secs(2), || writer.fully_acked()),
        "{name}: the writer waits for an acknowledgement from its own participant's reader"
    );

    // The match ends with the reader.
    drop(reader);
    assert!(
        wait_for(Duration::from_secs(5), || writer_seen
            .current
            .load(Ordering::SeqCst)
            == 0),
        "{name}: the deleted reader stayed matched"
    );
    assert_eq!(writer.matched_reader_count(), 0, "{name}");
}

#[test]
fn local_endpoints_match_each_other_over_udp_writer_first() {
    local_endpoints_match(TransportMode::UdpMulticast, "same_part_udp_wf", false);
}

#[test]
fn local_endpoints_match_each_other_over_udp_reader_first() {
    local_endpoints_match(TransportMode::UdpMulticast, "same_part_udp_rf", true);
}

// IntraProcess: `Participant::match_registry` is `None` (no `discovery_fsm`
// to feed SEDP into at all), so before domain_registry.rs grew its own
// `LocalMatchStatus` bookkeeping, NOTHING raised PUBLICATION_MATCHED /
// SUBSCRIPTION_MATCHED for an IntraProcess pair, same participant or not --
// a strictly bigger gap than the UDP same-participant one above, which at
// least had `match_registry` to report through (SEDP loopback).

#[test]
fn local_endpoints_match_each_other_intra_process_writer_first() {
    local_endpoints_match(TransportMode::IntraProcess, "same_part_intra_wf", false);
}

#[test]
fn local_endpoints_match_each_other_intra_process_reader_first() {
    local_endpoints_match(TransportMode::IntraProcess, "same_part_intra_rf", true);
}
