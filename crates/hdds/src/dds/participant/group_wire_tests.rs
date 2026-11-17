// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! GROUP coherent sets between two participants on a real UDP transport,
//! each speaking the RTPS v2.5 GROUP dialect or the HDDS 1.4.x one (no
//! `CAP_SPEC_GROUP_COHERENT` in its `PID_HDDS_CAPABILITIES`, D1): spec to
//! spec, 1.4.x wire to spec, spec to 1.4.x wire, 1.4.x to 1.4.x. Each pair
//! agrees on one dialect at pairing, and the Subscriber receives every set
//! whole, in one access each, across its two readers.

use super::{Participant, TransportMode};
use crate::dds::qos::{Presentation, PresentationAccessScope};
use crate::dds::QoS;
use crate::protocol::group::{GroupDialect, CAP_SPEC_GROUP_COHERENT};
use crate::test_support::domains::{unique_domain, DomainLease};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, crate::DDS)]
struct Item {
    id: i32,
}

fn participant(name: &str, domain: &DomainLease, caps: u32) -> Arc<Participant> {
    Participant::builder(name)
        .domain_id(domain.id())
        .with_transport(TransportMode::UdpMulticast)
        .hdds_capabilities_for_test(caps)
        .build()
        .expect("participant")
}

fn group_qos() -> QoS {
    QoS::reliable().keep_all().presentation(Presentation::new(
        PresentationAccessScope::Group,
        true,
        false,
    ))
}

fn prefix(p: &Participant) -> [u8; 12] {
    let mut prefix = [0u8; 12];
    prefix.copy_from_slice(&p.guid().as_bytes()[..12]);
    prefix
}

/// The sets written: each the ids of its samples.
const SETS: [&[i32]; 3] = [&[1, 2], &[3], &[4, 5]];

/// Run the three sets from a participant announcing `writer_caps` to one
/// announcing `reader_caps`: the dialect each side decided for the other,
/// and what each access of the Subscriber took.
fn run(
    name: &str,
    writer_caps: u32,
    reader_caps: u32,
) -> (GroupDialect, GroupDialect, Vec<Vec<i32>>) {
    let domain = unique_domain();
    let pw = participant(&format!("{name}-w"), &domain, writer_caps);
    let pr = participant(&format!("{name}-r"), &domain, reader_caps);
    let publisher = Arc::new(pw.create_publisher(group_qos()).expect("publisher"));
    let subscriber = pr.create_subscriber(group_qos()).expect("subscriber");
    let (topic_a, topic_b) = (format!("{name}A"), format!("{name}B"));
    let wa = pw
        .topic::<Item>(&topic_a)
        .expect("topic")
        .writer()
        .qos(group_qos())
        .publisher(&publisher)
        .build()
        .expect("writer A");
    let wb = pw
        .topic::<Item>(&topic_b)
        .expect("topic")
        .writer()
        .qos(group_qos())
        .publisher(&publisher)
        .build()
        .expect("writer B");
    let ra = pr
        .topic::<Item>(&topic_a)
        .expect("topic")
        .reader()
        .qos(group_qos())
        .subscriber(&subscriber)
        .build()
        .expect("reader A");
    let rb = pr
        .topic::<Item>(&topic_b)
        .expect("topic")
        .reader()
        .qos(group_qos())
        .subscriber(&subscriber)
        .build()
        .expect("reader B");
    let fsm_w = pw.discovery().expect("discovery");
    let fsm_r = pr.discovery().expect("discovery");
    // Each side's departures of the other: a run whose sets went torn
    // tells whether discovery took the peer for gone meanwhile (printed,
    // shown with a failure).
    let departures = Arc::new(Departures::default());
    fsm_w.register_listener(departures.clone());
    fsm_r.register_listener(departures.clone());
    let deadline = Instant::now() + Duration::from_secs(10);
    while (wa.matched_reader_count() == 0
        || wb.matched_reader_count() == 0
        || fsm_r.find_writers_for_topic(&topic_a).is_empty()
        || fsm_r.find_writers_for_topic(&topic_b).is_empty())
        && Instant::now() < deadline
    {
        std::thread::sleep(Duration::from_millis(20));
    }
    // The pairing settles both ways before the first set.
    std::thread::sleep(Duration::from_millis(300));
    let writer_side = fsm_w.group_dialect_of(&prefix(&pr));
    let reader_side = fsm_r.group_dialect_of(&prefix(&pw));
    for set in SETS {
        publisher.begin_coherent_changes().expect("begin");
        for &id in set {
            let writer = if id == 3 || id == 5 { &wb } else { &wa };
            writer.write(&Item { id }).expect("write");
        }
        publisher.end_coherent_changes().expect("end");
    }
    let mut accesses = Vec::new();
    let mut got = 0;
    let deadline = Instant::now() + Duration::from_secs(10);
    while got < 5 && Instant::now() < deadline {
        subscriber.begin_access().expect("begin access");
        let mut taken = Vec::new();
        for reader in [&ra, &rb] {
            // take_all: a reader of a Subscriber's coherent group takes its
            // part of the generation the access released.
            taken.extend(reader.take_all().expect("take").iter().map(|item| item.id));
        }
        subscriber.end_access().expect("end access");
        if taken.is_empty() {
            std::thread::sleep(Duration::from_millis(20));
        } else {
            got += taken.len();
            taken.sort_unstable();
            accesses.push(taken);
        }
    }
    eprintln!(
        "{name}: reader A lost={:?} rejected={:?}; reader B lost={:?} rejected={:?}",
        ra.get_sample_lost_status(),
        ra.get_sample_rejected_status(),
        rb.get_sample_lost_status(),
        rb.get_sample_rejected_status(),
    );
    eprintln!(
        "{name}: departures announced={} unannounced={}",
        departures
            .announced
            .load(std::sync::atomic::Ordering::SeqCst),
        departures
            .unannounced
            .load(std::sync::atomic::Ordering::SeqCst),
    );
    (writer_side, reader_side, accesses)
}

/// Counts the participants discovery takes for gone (`run`).
#[derive(Default)]
struct Departures {
    announced: std::sync::atomic::AtomicUsize,
    unannounced: std::sync::atomic::AtomicUsize,
}

impl crate::core::discovery::multicast::DiscoveryListener for Departures {
    fn on_endpoint_discovered(&self, endpoint: crate::core::discovery::multicast::EndpointInfo) {
        drop(endpoint);
    }

    fn on_participant_left(&self, _participant: crate::core::discovery::GUID, announced: bool) {
        let count = if announced {
            &self.announced
        } else {
            &self.unannounced
        };
        count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}

/// Every set whole in one access, every set once.
fn assert_whole(accesses: &[Vec<i32>]) {
    let mut seen: Vec<i32> = accesses.iter().flatten().copied().collect();
    seen.sort_unstable();
    assert_eq!(seen, vec![1, 2, 3, 4, 5], "every sample once: {accesses:?}");
    assert_no_set_in_part(accesses, &SETS);
}

/// What the HDDS 1.4.x GROUP wire gives a Subscriber of two topics: the set
/// written on both, whole in one access; no set in part, none twice. The
/// sets written on one topic only are lost on it: a writer that wrote
/// nothing in a set says nothing of it on that wire, the other topic's
/// reader holds no part of the set, and the presentation barrier, unable
/// to align it, discards it. The spec dialect delivers them
/// (`assert_whole`).
fn assert_1_4_wire(accesses: &[Vec<i32>]) {
    let mut seen: Vec<i32> = accesses.iter().flatten().copied().collect();
    seen.sort_unstable();
    let mut deduped = seen.clone();
    deduped.dedup();
    assert_eq!(seen, deduped, "no sample twice: {accesses:?}");
    assert!(
        seen.contains(&4) && seen.contains(&5),
        "the set on both topics delivered: {accesses:?}"
    );
    assert_no_set_in_part(accesses, &SETS);
}

fn assert_no_set_in_part(accesses: &[Vec<i32>], sets: &[&[i32]]) {
    for set in sets {
        let holders: Vec<&Vec<i32>> = accesses
            .iter()
            .filter(|access| set.iter().any(|id| access.contains(id)))
            .collect();
        if holders.is_empty() {
            continue;
        }
        let holders: Vec<&Vec<i32>> = accesses
            .iter()
            .filter(|access| set.iter().any(|id| access.contains(id)))
            .collect();
        assert_eq!(holders.len(), 1, "set {set:?} split: {accesses:?}");
        assert!(
            set.iter().all(|id| holders[0].contains(id)),
            "set {set:?} in part: {accesses:?}"
        );
    }
}

#[test]
fn spec_to_spec_speaks_the_spec_dialect() {
    let (w, r, accesses) = run(
        "GroupWireSpec",
        CAP_SPEC_GROUP_COHERENT,
        CAP_SPEC_GROUP_COHERENT,
    );
    assert_eq!((w, r), (GroupDialect::Spec, GroupDialect::Spec));
    assert_whole(&accesses);
}

#[test]
fn a_spec_writer_speaks_the_1_4_wire_to_a_1_4_reader() {
    let (w, r, accesses) = run("GroupWireToOld", CAP_SPEC_GROUP_COHERENT, 0);
    assert_eq!((w, r), (GroupDialect::HddsLegacy, GroupDialect::HddsLegacy));
    assert_1_4_wire(&accesses);
}

#[test]
fn a_1_4_writer_is_read_in_its_wire_by_a_spec_reader() {
    let (w, r, accesses) = run("GroupWireFromOld", 0, CAP_SPEC_GROUP_COHERENT);
    assert_eq!((w, r), (GroupDialect::HddsLegacy, GroupDialect::HddsLegacy));
    assert_1_4_wire(&accesses);
}

#[test]
fn the_1_4_wire_between_two_1_4_participants() {
    let (w, r, accesses) = run("GroupWireOld", 0, 0);
    assert_eq!((w, r), (GroupDialect::HddsLegacy, GroupDialect::HddsLegacy));
    assert_1_4_wire(&accesses);
}

#[derive(Debug, Clone, PartialEq, crate::DDS)]
struct Blob {
    id: i32,
    data: Vec<u8>,
}

/// A set of a large change of writer A (sent as DATA_FRAGs, its set's tags
/// in the first one) and a small one of writer B, from a participant
/// announcing `caps` to one announcing the same: the ids each access took.
fn run_fragmented(name: &str, caps: u32) -> Vec<Vec<i32>> {
    let domain = unique_domain();
    let pw = participant(&format!("{name}-w"), &domain, caps);
    let pr = participant(&format!("{name}-r"), &domain, caps);
    let publisher = Arc::new(pw.create_publisher(group_qos()).expect("publisher"));
    let subscriber = pr.create_subscriber(group_qos()).expect("subscriber");
    let (topic_a, topic_b) = (format!("{name}A"), format!("{name}B"));
    let writer = |topic: &str| {
        pw.topic::<Blob>(topic)
            .expect("topic")
            .writer()
            .qos(group_qos())
            .publisher(&publisher)
            .build()
            .expect("writer")
    };
    let reader = |topic: &str| {
        pr.topic::<Blob>(topic)
            .expect("topic")
            .reader()
            .qos(group_qos())
            .subscriber(&subscriber)
            .build()
            .expect("reader")
    };
    let (wa, wb) = (writer(&topic_a), writer(&topic_b));
    let (ra, rb) = (reader(&topic_a), reader(&topic_b));
    let fsm_r = pr.discovery().expect("discovery");
    let deadline = Instant::now() + Duration::from_secs(10);
    while (wa.matched_reader_count() == 0
        || wb.matched_reader_count() == 0
        || fsm_r.find_writers_for_topic(&topic_a).is_empty()
        || fsm_r.find_writers_for_topic(&topic_b).is_empty())
        && Instant::now() < deadline
    {
        std::thread::sleep(Duration::from_millis(20));
    }
    std::thread::sleep(Duration::from_millis(300));
    let take = |accesses: &mut Vec<Vec<i32>>| {
        subscriber.begin_access().expect("begin access");
        let mut taken = Vec::new();
        for reader in [&ra, &rb] {
            for blob in reader.take_all().expect("take") {
                if blob.id == 10 {
                    assert_eq!(blob.data, vec![0xA5; 30_000], "the large change whole");
                }
                taken.push(blob.id);
            }
        }
        subscriber.end_access().expect("end access");
        if !taken.is_empty() {
            taken.sort_unstable();
            accesses.push(taken);
        }
    };
    let mut accesses = Vec::new();
    publisher.begin_coherent_changes().expect("begin");
    wa.write(&Blob {
        id: 10,
        data: vec![0xA5; 30_000],
    })
    .expect("large write");
    // The large change has landed long before its set ends: nothing of the
    // set may be taken yet.
    let landed = Instant::now() + Duration::from_millis(600);
    while Instant::now() < landed {
        take(&mut accesses);
        std::thread::sleep(Duration::from_millis(20));
    }
    wb.write(&Blob {
        id: 11,
        data: vec![1, 2, 3],
    })
    .expect("small write");
    publisher.end_coherent_changes().expect("end");
    let deadline = Instant::now() + Duration::from_secs(10);
    while accesses.iter().map(Vec::len).sum::<usize>() < 2 && Instant::now() < deadline {
        take(&mut accesses);
        std::thread::sleep(Duration::from_millis(20));
    }
    accesses
}

/// A fragmented change of a set is a member of it, in the spec dialect and
/// in the 1.4.x one: the set is delivered whole, in one access. Its
/// DATA_FRAGs must carry the inline QoS naming the set, or it would reach
/// the application alone, outside its set.
#[test]
fn a_fragmented_change_is_delivered_with_its_set() {
    for (name, caps) in [
        ("GroupFragSpec", CAP_SPEC_GROUP_COHERENT),
        ("GroupFragOld", 0),
    ] {
        let accesses = run_fragmented(name, caps);
        assert_eq!(
            accesses,
            vec![vec![10, 11]],
            "{name}: one access, the whole set"
        );
    }
}

/// One spec writer, two readers of one topic on two participants of the
/// same host, one of each class: whatever leg carries the sets (shared
/// memory between co-located participants, UDP), each reader receives
/// every set whole, in its own form (D18). (In one process the
/// participants pair over UDP: the shared-memory leg's rule,
/// `shm_audience_is_one_class`, is pinned by its own test.)
#[test]
fn a_mixed_audience_on_one_host_gets_every_set_in_its_form() {
    let domain = unique_domain();
    let pw = participant("GroupMixW", &domain, CAP_SPEC_GROUP_COHERENT);
    let ps = participant("GroupMixS", &domain, CAP_SPEC_GROUP_COHERENT);
    let pl = participant("GroupMixL", &domain, 0);
    let publisher = Arc::new(pw.create_publisher(group_qos()).expect("publisher"));
    let topic = "GroupMixTopic";
    let writer = pw
        .topic::<Item>(topic)
        .expect("topic")
        .writer()
        .qos(group_qos())
        .publisher(&publisher)
        .build()
        .expect("writer");
    let make_reader = |p: &Arc<Participant>| {
        let subscriber = p.create_subscriber(group_qos()).expect("subscriber");
        let reader = p
            .topic::<Item>(topic)
            .expect("topic")
            .reader()
            .qos(group_qos())
            .subscriber(&subscriber)
            .build()
            .expect("reader");
        (subscriber, reader)
    };
    let (ss, rs) = make_reader(&ps);
    let (sl, rl) = make_reader(&pl);
    let deadline = Instant::now() + Duration::from_secs(10);
    while writer.matched_reader_count() < 2 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    std::thread::sleep(Duration::from_millis(500));
    for set in [[1, 2], [3, 4], [5, 6]] {
        publisher.begin_coherent_changes().expect("begin");
        for id in set {
            writer.write(&Item { id }).expect("write");
        }
        publisher.end_coherent_changes().expect("end");
    }
    for (name, subscriber, reader) in [("spec", &ss, &rs), ("1.4.x", &sl, &rl)] {
        let mut accesses: Vec<Vec<i32>> = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(10);
        while accesses.iter().map(Vec::len).sum::<usize>() < 6 && Instant::now() < deadline {
            subscriber.begin_access().expect("begin access");
            let mut taken: Vec<i32> = reader
                .take_all()
                .expect("take")
                .iter()
                .map(|i| i.id)
                .collect();
            subscriber.end_access().expect("end access");
            if taken.is_empty() {
                std::thread::sleep(Duration::from_millis(20));
            } else {
                taken.sort_unstable();
                accesses.push(taken);
            }
        }
        let flat: Vec<i32> = accesses.iter().flatten().copied().collect();
        let mut sorted = flat.clone();
        sorted.sort_unstable();
        assert_eq!(
            sorted,
            vec![1, 2, 3, 4, 5, 6],
            "{name}: every sample once: {accesses:?}"
        );
        assert_no_set_in_part(&accesses, &[&[1, 2], &[3, 4], &[5, 6]]);
    }
}

/// A Subscriber's barrier keys a remote writer by its Publisher, from the
/// writer's SEDP (PID_GROUP_ENTITY_ID): two Publishers of one participant are
/// two keys (`coherent_barrier::PublisherKey`).
#[test]
fn the_barrier_keys_a_remote_writer_by_its_publisher() {
    let domain = unique_domain();
    let pw = participant("GroupKeyW", &domain, CAP_SPEC_GROUP_COHERENT);
    let pr = participant("GroupKeyR", &domain, CAP_SPEC_GROUP_COHERENT);
    let publishers = [
        Arc::new(pw.create_publisher(group_qos()).expect("publisher 1")),
        Arc::new(pw.create_publisher(group_qos()).expect("publisher 2")),
    ];
    let topic = "GroupKeyTopic";
    let writers: Vec<_> = publishers
        .iter()
        .map(|publisher| {
            pw.topic::<Item>(topic)
                .expect("topic")
                .writer()
                .qos(group_qos())
                .publisher(publisher)
                .build()
                .expect("writer")
        })
        .collect();
    let subscriber = pr.create_subscriber(group_qos()).expect("subscriber");
    let _reader = pr
        .topic::<Item>(topic)
        .expect("topic")
        .reader()
        .qos(group_qos())
        .subscriber(&subscriber)
        .build()
        .expect("reader");
    let guids: Vec<[u8; 16]> = writers
        .iter()
        .map(|w| {
            let ctx = w.rtps_endpoint_for_test().expect("context");
            let mut guid = [0u8; 16];
            guid[..12].copy_from_slice(&ctx.guid_prefix);
            guid[12..].copy_from_slice(&ctx.writer_entity_id);
            guid
        })
        .collect();
    let barrier = subscriber.coherent_barrier();
    let deadline = Instant::now() + Duration::from_secs(10);
    while guids.iter().any(|g| barrier.registered_key(0, g).is_none()) && Instant::now() < deadline
    {
        std::thread::sleep(Duration::from_millis(20));
    }
    let keys: Vec<_> = guids.iter().map(|g| barrier.registered_key(0, g)).collect();
    for (key, (publisher, guid)) in keys.iter().zip(publishers.iter().zip(&guids)) {
        let mut expected = [0u8; 16];
        expected[..12].copy_from_slice(&guid[..12]);
        expected[12..].copy_from_slice(&publisher.core.entity_id);
        assert_eq!(*key, Some(expected), "the writer's Publisher");
    }
    assert_ne!(keys[0], keys[1], "two Publishers, two keys");
}
