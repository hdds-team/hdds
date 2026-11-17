// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Local delivery must not duplicate a wire-capable writer's RTPS path.

use hdds::test_support::domains::unique_domain;
use hdds::{Participant, QoS, TransportMode};
use std::time::{Duration, Instant};

#[derive(Clone, Debug, PartialEq, hdds::DDS)]
struct ScopeProbe {
    value: u32,
}

fn udp_participant_in_domain(
    name: &str,
    domain_id: u32,
    participant_id: u8,
) -> std::sync::Arc<Participant> {
    Participant::builder(name)
        .domain_id(domain_id)
        .participant_id(Some(participant_id))
        .with_transport(TransportMode::UdpMulticast)
        .build()
        .expect("participant")
}

fn intra_participant(name: &str, domain_id: u32) -> std::sync::Arc<Participant> {
    Participant::builder(name)
        .domain_id(domain_id)
        .with_transport(TransportMode::IntraProcess)
        .build()
        .expect("participant")
}

#[test]
fn wire_capable_writer_only_binds_readers_from_its_participant() {
    // Both participants must sit on the SAME domain: the test proves that a
    // cross-participant pair is still served by RTPS. Leased first so the
    // lease outlives both participants' sockets.
    let domain = unique_domain();
    let participant_a = udp_participant_in_domain("scope_a", domain.id(), 40);
    let participant_b = udp_participant_in_domain("scope_b", domain.id(), 41);

    // Writer-first and reader-first cover the two mirrored registry paths.
    let writer_first = participant_a
        .topic::<ScopeProbe>("ScopeWriterFirst")
        .expect("topic")
        .writer()
        .build()
        .expect("writer");
    let cross_reader = participant_b
        .topic::<ScopeProbe>("ScopeWriterFirst")
        .expect("topic")
        .reader()
        .build()
        .expect("reader");
    assert_eq!(writer_first.merger().reader_count(), 0);

    // With no local merger binding, successful delivery proves that the
    // cross-participant pair is still served by RTPS rather than dropped.
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut received = None;
    let mut value = 0;
    while Instant::now() < deadline {
        value += 1;
        writer_first
            .write(&ScopeProbe { value })
            .expect("wire write");
        std::thread::sleep(Duration::from_millis(50));
        if let Some(sample) = cross_reader.take().expect("wire take") {
            received = Some(sample);
            break;
        }
    }
    assert!(
        received.is_some(),
        "cross-participant RTPS delivery stopped"
    );

    let _reader_first = participant_b
        .topic::<ScopeProbe>("ScopeReaderFirst")
        .expect("topic")
        .reader()
        .build()
        .expect("reader");
    let cross_writer = participant_a
        .topic::<ScopeProbe>("ScopeReaderFirst")
        .expect("topic")
        .writer()
        .build()
        .expect("writer");
    assert_eq!(cross_writer.merger().reader_count(), 0);

    let same_writer = participant_a
        .topic::<ScopeProbe>("ScopeSameParticipant")
        .expect("topic")
        .writer()
        .build()
        .expect("writer");
    let _same_reader = participant_a
        .topic::<ScopeProbe>("ScopeSameParticipant")
        .expect("topic")
        .reader()
        .build()
        .expect("reader");
    assert_eq!(same_writer.merger().reader_count(), 1);
}

#[test]
fn wire_writer_keeps_local_delivery_to_intra_only_participant() {
    // The wire participant and the intra-only participant must share one
    // domain, otherwise the local-delivery binding under test never forms.
    let domain = unique_domain();
    let writer_participant = Participant::builder("mixed_scope_wire")
        .domain_id(domain.id())
        .participant_id(Some(42))
        .with_transport(TransportMode::UdpMulticast)
        .build()
        .expect("wire participant");
    let reader_participant = intra_participant("mixed_scope_intra", domain.id());

    let writer = writer_participant
        .topic::<ScopeProbe>("MixedTransportScope")
        .expect("topic")
        .writer()
        .build()
        .expect("writer");
    let reader = reader_participant
        .topic::<ScopeProbe>("MixedTransportScope")
        .expect("topic")
        .reader()
        .build()
        .expect("reader");

    assert_eq!(writer.merger().reader_count(), 1);
    writer.write(&ScopeProbe { value: 7 }).expect("local write");
    let sample = reader
        .take()
        .expect("local take")
        .expect("mixed-transport local delivery");
    assert_eq!(sample.value, 7);
}

#[test]
fn mixed_local_and_remote_sources_both_reach_the_reader() {
    // One domain for the pair: the "remote" source has to reach the local
    // reader over RTPS for the second half of the assertion to mean anything.
    let domain = unique_domain();
    let local_participant = udp_participant_in_domain("mixed_source_local", domain.id(), 43);
    let remote_participant = udp_participant_in_domain("mixed_source_remote", domain.id(), 44);

    let reader = local_participant
        .topic::<ScopeProbe>("MixedSourceScope")
        .expect("topic")
        .reader()
        .build()
        .expect("reader");
    let local_writer = local_participant
        .topic::<ScopeProbe>("MixedSourceScope")
        .expect("topic")
        .writer()
        .build()
        .expect("local writer");
    let remote_writer = remote_participant
        .topic::<ScopeProbe>("MixedSourceScope")
        .expect("topic")
        .writer()
        .build()
        .expect("remote writer");

    assert_eq!(local_writer.merger().reader_count(), 1);
    assert_eq!(remote_writer.merger().reader_count(), 0);

    local_writer
        .write(&ScopeProbe { value: 11 })
        .expect("local write");
    let local = reader
        .take()
        .expect("local take")
        .expect("local source delivery");
    assert_eq!(local.value, 11);

    let deadline = Instant::now() + Duration::from_secs(5);
    let mut remote_seen = false;
    let mut value = 100;
    while Instant::now() < deadline && !remote_seen {
        remote_writer
            .write(&ScopeProbe { value })
            .expect("remote write");
        std::thread::sleep(Duration::from_millis(50));
        while let Some(sample) = reader.take().expect("mixed take") {
            if sample.value >= 100 {
                remote_seen = true;
                break;
            }
        }
        value += 1;
    }
    assert!(remote_seen, "dedicated network source was not drained");
}

#[test]
fn rtps_partition_default_matches_wildcard_without_weakening_isolation() {
    // Same domain for both: PARTITION isolation, not domain isolation, is
    // what this test is asserting.
    let domain = unique_domain();
    let writer_participant = udp_participant_in_domain("partition_writer", domain.id(), 45);
    let reader_participant = udp_participant_in_domain("partition_reader", domain.id(), 46);

    let wildcard_reader = reader_participant
        .topic::<ScopeProbe>("PartitionDefaultWildcard")
        .expect("wildcard topic")
        .reader()
        .qos(QoS::best_effort().partition_single("*"))
        .build()
        .expect("wildcard reader");
    let default_writer = writer_participant
        .topic::<ScopeProbe>("PartitionDefaultWildcard")
        .expect("default topic")
        .writer()
        .qos(QoS::best_effort())
        .build()
        .expect("default writer");

    assert_eq!(default_writer.merger().reader_count(), 0);
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut value = 1;
    let mut wildcard_received = false;
    while Instant::now() < deadline && !wildcard_received {
        default_writer
            .write(&ScopeProbe { value })
            .expect("default partition write");
        std::thread::sleep(Duration::from_millis(50));
        wildcard_received = wildcard_reader
            .take()
            .expect("wildcard partition take")
            .is_some();
        value += 1;
    }
    assert!(
        wildcard_received,
        "default writer did not match wildcard reader over RTPS"
    );

    let isolated_reader = reader_participant
        .topic::<ScopeProbe>("PartitionIsolation")
        .expect("isolated reader topic")
        .reader()
        .qos(QoS::best_effort().partition_single("reader-only"))
        .build()
        .expect("isolated reader");
    let isolated_writer = writer_participant
        .topic::<ScopeProbe>("PartitionIsolation")
        .expect("isolated writer topic")
        .writer()
        .qos(QoS::best_effort().partition_single("writer-only"))
        .build()
        .expect("isolated writer");

    let isolation_deadline = Instant::now() + Duration::from_millis(750);
    while Instant::now() < isolation_deadline {
        isolated_writer
            .write(&ScopeProbe { value })
            .expect("isolated partition write");
        std::thread::sleep(Duration::from_millis(50));
        assert!(
            isolated_reader
                .take()
                .expect("isolated partition take")
                .is_none(),
            "disjoint partitions exchanged data over RTPS"
        );
        value += 1;
    }
}
