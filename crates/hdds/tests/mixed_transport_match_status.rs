// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Counted must equal delivered. `domain_registry.rs::scope_allows` binds
//! the DATA path for any pair where at least one endpoint has no wire
//! path at all (an `IntraProcess` endpoint can never be announced over
//! SEDP), regardless of what its peer's OWN transport is. Before this
//! fix, the application-visible MATCH STATUS followed a different, purely
//! per-endpoint rule: a wire-capable endpoint (one with a real transport,
//! hence a `MatchNotificationRegistry`) got `match_status = None` and
//! relied entirely on SEDP -- which never hears of an `IntraProcess` peer,
//! because such a peer is never announced at all. The result: a sample
//! crossed the pair (delivered, through domain_registry.rs's own
//! auto-bind), but the wire-capable side's SUBSCRIPTION_MATCHED /
//! PUBLICATION_MATCHED `current_count` stayed at 0 forever.
//!
//! Both orientations here build the two participants in the SAME process
//! and domain: an `IntraProcess` one and a `UdpMulticast` one, so exactly
//! one side of the pair has no wire path.

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

/// IntraProcess writer, UdpMulticast reader (a different participant, same
/// process and domain). The writer has no wire path at all: domain_registry
/// is the ONLY route for this pair, on BOTH the data path and the match
/// status, even though the reader's OWN participant has a real
/// `MatchNotificationRegistry` for its (other) wire-reachable peers.
#[test]
fn intra_writer_udp_reader_counts_on_both_ends_and_delivers() {
    let lease = hdds::test_support::domains::unique_domain();
    let domain_id = lease.id();
    let name = "mt_intra_writer_udp_reader";

    let pub_participant = Participant::builder(&format!("{name}_pub"))
        .domain_id(domain_id)
        .with_transport(TransportMode::IntraProcess)
        .build()
        .unwrap();
    let sub_participant = Participant::builder(&format!("{name}_sub"))
        .domain_id(domain_id)
        .with_transport(TransportMode::UdpMulticast)
        .build()
        .unwrap();

    let writer_seen = Arc::new(Seen::default());
    let reader_seen = Arc::new(Seen::default());
    let writer = pub_participant
        .topic::<Probe>(name)
        .unwrap()
        .writer()
        .qos(QoS::reliable().keep_last(8))
        .with_listener(Arc::clone(&writer_seen) as Arc<dyn DataWriterListener<Probe>>)
        .build()
        .unwrap();
    let reader = sub_participant
        .topic::<Probe>(name)
        .unwrap()
        .reader()
        .qos(QoS::reliable().keep_last(8))
        .with_listener(Arc::clone(&reader_seen) as Arc<dyn DataReaderListener<Probe>>)
        .build()
        .unwrap();

    assert!(
        wait_for(Duration::from_secs(5), || writer_seen
            .current
            .load(Ordering::SeqCst)
            == 1
            && writer.matched_reader_count() == 1),
        "the IntraProcess writer never saw its UdpMulticast-side reader \
         matched (listener current={}, matched_reader_count={})",
        writer_seen.current.load(Ordering::SeqCst),
        writer.matched_reader_count()
    );
    assert!(
        wait_for(Duration::from_secs(5), || reader_seen
            .current
            .load(Ordering::SeqCst)
            == 1),
        "the UdpMulticast reader never saw the IntraProcess writer matched \
         (its participant has a match_registry, but the writer is never \
         announced over SEDP at all) -- listener current={}",
        reader_seen.current.load(Ordering::SeqCst),
    );

    writer.write(&Probe { value: 42 }).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut got = None;
    while Instant::now() < deadline {
        if let Some(sample) = reader.take().unwrap() {
            got = Some(sample.value);
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(
        got,
        Some(42),
        "the sample never reached the reader, though it was counted matched"
    );
}

/// Mirror orientation: UdpMulticast writer, IntraProcess reader (a
/// different participant, same process and domain). The READER has no
/// wire path this time: the writer's own participant has a real
/// `MatchNotificationRegistry`, but it must ALSO carry this one peer that
/// registry can never see.
#[test]
fn udp_writer_intra_reader_counts_on_both_ends_and_delivers() {
    let lease = hdds::test_support::domains::unique_domain();
    let domain_id = lease.id();
    let name = "mt_udp_writer_intra_reader";

    let pub_participant = Participant::builder(&format!("{name}_pub"))
        .domain_id(domain_id)
        .with_transport(TransportMode::UdpMulticast)
        .build()
        .unwrap();
    let sub_participant = Participant::builder(&format!("{name}_sub"))
        .domain_id(domain_id)
        .with_transport(TransportMode::IntraProcess)
        .build()
        .unwrap();

    let writer_seen = Arc::new(Seen::default());
    let reader_seen = Arc::new(Seen::default());
    let writer = pub_participant
        .topic::<Probe>(name)
        .unwrap()
        .writer()
        .qos(QoS::reliable().keep_last(8))
        .with_listener(Arc::clone(&writer_seen) as Arc<dyn DataWriterListener<Probe>>)
        .build()
        .unwrap();
    let reader = sub_participant
        .topic::<Probe>(name)
        .unwrap()
        .reader()
        .qos(QoS::reliable().keep_last(8))
        .with_listener(Arc::clone(&reader_seen) as Arc<dyn DataReaderListener<Probe>>)
        .build()
        .unwrap();

    assert!(
        wait_for(Duration::from_secs(5), || writer_seen
            .current
            .load(Ordering::SeqCst)
            == 1
            && writer.matched_reader_count() == 1),
        "the UdpMulticast writer never saw its IntraProcess-only reader \
         matched (its participant has a match_registry, but the reader is \
         never announced over SEDP at all) -- listener current={}, \
         matched_reader_count={}",
        writer_seen.current.load(Ordering::SeqCst),
        writer.matched_reader_count()
    );
    assert!(
        wait_for(Duration::from_secs(5), || reader_seen
            .current
            .load(Ordering::SeqCst)
            == 1),
        "the IntraProcess reader never saw the UdpMulticast writer matched \
         -- listener current={}",
        reader_seen.current.load(Ordering::SeqCst),
    );

    writer.write(&Probe { value: 7 }).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut got = None;
    while Instant::now() < deadline {
        if let Some(sample) = reader.take().unwrap() {
            got = Some(sample.value);
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(
        got,
        Some(7),
        "the sample never reached the reader, though it was counted matched"
    );
}

/// A same-participant pair where BOTH endpoints are wire-capable (the
/// ordinary SEDP loopback case) must NOT be double-counted now that every
/// wire-capable endpoint also carries a `LocalMatchStatus` fallback: the
/// writer and the reader of ONE UdpMulticast participant still see
/// exactly one match each, not two.
#[test]
fn same_participant_udp_pair_is_not_double_counted() {
    let lease = hdds::test_support::domains::unique_domain();
    let domain_id = lease.id();
    let name = "mt_same_participant_udp_not_doubled";

    let participant = Participant::builder(name)
        .domain_id(domain_id)
        .with_transport(TransportMode::UdpMulticast)
        .build()
        .unwrap();
    let topic = participant.topic::<Probe>(name).unwrap();

    let writer_seen = Arc::new(Seen::default());
    let reader_seen = Arc::new(Seen::default());
    let writer = topic
        .writer()
        .qos(QoS::reliable().keep_last(8))
        .with_listener(Arc::clone(&writer_seen) as Arc<dyn DataWriterListener<Probe>>)
        .build()
        .unwrap();
    let reader = topic
        .reader()
        .qos(QoS::reliable().keep_last(8))
        .with_listener(Arc::clone(&reader_seen) as Arc<dyn DataReaderListener<Probe>>)
        .build()
        .unwrap();

    assert!(
        wait_for(Duration::from_secs(5), || writer.matched_reader_count()
            == 1),
        "matched_reader_count was {}, expected exactly 1 (no double-count \
         from the always-built LocalMatchStatus fallback)",
        writer.matched_reader_count()
    );
    assert!(wait_for(Duration::from_secs(5), || writer_seen
        .current
        .load(Ordering::SeqCst)
        == 1));
    assert!(wait_for(Duration::from_secs(5), || reader_seen
        .current
        .load(Ordering::SeqCst)
        == 1));
    drop(reader);
}
