// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Intra-process auto-binding must apply the same QoS gates as the wire.
//!
//! The DomainRegistry's auto-bind checks ONLY Reliability compatibility
//! (`domain_registry::qos_compatible`), while the wire path additionally
//! enforces PARTITION (DDS v1.4 sec 2.2.3.13), OWNERSHIP and type gates at
//! the reader (`ReaderSubscriber::on_data_with_writer`). Two co-located
//! participants whose partitions do not intersect therefore still deliver
//! through the intra slab -- traffic the SAME pair over UDP would drop.
//!
//! Unifying this predicate is a prerequisite for any suppression or
//! re-scoping of the intra path: it is semantically wrong while intra and
//! wire disagree about which pairs deliver at all.
//!
//! `partition_mismatched_colocated_pair_must_not_deliver` is the pin: the intra bind
//! consults the shared predicate.

use hdds::test_support::domains::unique_domain;
use hdds::{Participant, QoS, TransportMode};
use std::time::{Duration, Instant};

#[derive(Clone, Debug, PartialEq, hdds::DDS)]
struct GateProbe {
    value: u32,
}

/// Both participants of a case MUST get the same `domain_id`: "co-located"
/// here means the same `DomainRegistry`, and that registry is keyed by
/// domain. Each test leases one domain and passes it to both calls.
fn intra_participant(name: &str, domain_id: u32) -> std::sync::Arc<Participant> {
    Participant::builder(name)
        .domain_id(domain_id)
        .with_transport(TransportMode::IntraProcess)
        .build()
        .expect("participant")
}

/// Two co-located participants, disjoint partitions: the wire would never
/// match this pair, so the intra path must not deliver either.
#[test]
fn partition_mismatched_colocated_pair_must_not_deliver() {
    let domain = unique_domain();
    let pub_participant = intra_participant("gate_pub", domain.id());
    let sub_participant = intra_participant("gate_sub", domain.id());

    let writer = pub_participant
        .topic::<GateProbe>("GateParityTopic")
        .expect("writer topic")
        .writer()
        .qos(QoS::reliable().partition_single("region_alpha"))
        .build()
        .expect("writer");
    let reader = sub_participant
        .topic::<GateProbe>("GateParityTopic")
        .expect("reader topic")
        .reader()
        .qos(QoS::reliable().partition_single("region_beta"))
        .build()
        .expect("reader");

    writer.write(&GateProbe { value: 7 }).expect("write");

    // Deliveries on the intra path are effectively synchronous; the grace
    // window only guards against scheduler noise.
    let deadline = Instant::now() + Duration::from_millis(500);
    let mut leaked = None;
    while Instant::now() < deadline {
        if let Ok(Some(sample)) = reader.take() {
            leaked = Some(sample);
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }

    assert!(
        leaked.is_none(),
        "a sample crossed between disjoint partitions over the intra-process path: {:?}. \
         The wire path enforces PARTITION at the reader and would have dropped this pair; \
         the intra auto-bind checks only Reliability, so co-located deployments silently \
         ignore partition isolation",
        leaked
    );
}

/// Control: identical partitions must keep delivering intra. Guards the fix
/// against over-correcting into "no intra delivery at all".
#[test]
fn partition_matched_colocated_pair_still_delivers() {
    let domain = unique_domain();
    let pub_participant = intra_participant("gate_pub_ok", domain.id());
    let sub_participant = intra_participant("gate_sub_ok", domain.id());

    let writer = pub_participant
        .topic::<GateProbe>("GateParityOkTopic")
        .expect("writer topic")
        .writer()
        .qos(QoS::reliable().partition_single("region_alpha"))
        .build()
        .expect("writer");
    let reader = sub_participant
        .topic::<GateProbe>("GateParityOkTopic")
        .expect("reader topic")
        .reader()
        .qos(QoS::reliable().partition_single("region_alpha"))
        .build()
        .expect("reader");

    writer.write(&GateProbe { value: 9 }).expect("write");

    let deadline = Instant::now() + Duration::from_secs(2);
    let mut received = None;
    while Instant::now() < deadline {
        if let Ok(Some(sample)) = reader.take() {
            received = Some(sample);
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }

    assert_eq!(
        received,
        Some(GateProbe { value: 9 }),
        "the matched-partition control pair stopped delivering: the gate fix over-corrected"
    );
}
