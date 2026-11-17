// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! A KEEP_LAST reader whose network ring is full replaces its oldest
//! samples with the newer ones: DDS 1.4 2.2.3.18 has a KEEP_LAST reader
//! keep "the latest values of the instance and discard the older ones".
//! It neither drops the newest sample after acknowledging it, which left
//! the application an old value for good, nor rejects it: a KEEP_LAST
//! history never runs out of room for the instance's newest value.
//!
//! The application does not take while the writer writes more than the
//! reader's network ring holds, then takes until the last value written
//! arrives.

use hdds::test_support::domains::unique_domain;
use hdds::{Participant, QoS, TransportMode};
use std::time::{Duration, Instant};

#[derive(Clone, Debug, PartialEq, hdds::DDS)]
struct Seq {
    value: u32,
}

const TOPIC: &str = "FullKeepLast";
/// More than the network ring of a KEEP_LAST reader holds (1023 entries).
const WRITES: u32 = 1500;

fn udp_participant(name: &str, domain_id: u32, participant_id: u8) -> std::sync::Arc<Participant> {
    Participant::builder(name)
        .domain_id(domain_id)
        .participant_id(Some(participant_id))
        .with_transport(TransportMode::UdpMulticast)
        .build()
        .expect("participant")
}

#[test]
fn a_full_keep_last_reader_keeps_the_newest() {
    let domain = unique_domain();
    let publisher = udp_participant("full_keep_last_pub", domain.id(), 85);
    let reliable_sub = udp_participant("full_keep_last_reliable", domain.id(), 86);
    let best_effort_sub = udp_participant("full_keep_last_best_effort", domain.id(), 87);

    let reliable = reliable_sub
        .topic::<Seq>(TOPIC)
        .expect("topic")
        .reader()
        .qos(QoS::reliable().keep_last(1))
        .build()
        .expect("reliable reader");
    let best_effort = best_effort_sub
        .topic::<Seq>(TOPIC)
        .expect("topic")
        .reader()
        .qos(QoS::best_effort().keep_last(1))
        .build()
        .expect("best-effort reader");
    let writer = publisher
        .topic::<Seq>(TOPIC)
        .expect("topic")
        .writer()
        .qos(QoS::reliable().keep_all())
        .build()
        .expect("writer");
    std::thread::sleep(Duration::from_millis(1500));

    for value in 1..=WRITES {
        writer.write(&Seq { value }).expect("write");
    }
    // Let everything that can arrive arrive, without taking.
    std::thread::sleep(Duration::from_secs(2));

    for (name, reader) in [("best-effort", &best_effort), ("reliable", &reliable)] {
        let rejected = reader.get_sample_rejected_status();
        assert_eq!(
            rejected.total_count, 0,
            "a full {name} KEEP_LAST reader replaces, it does not reject: {rejected:?}"
        );
    }
    // KEEP_LAST(1): one sample, the newest the best-effort reader received
    // (a best-effort burst may lose some on the way).
    let first = best_effort.take().expect("take");
    assert!(
        first.is_some(),
        "the best-effort reader kept its newest value"
    );
    assert_eq!(best_effort.take().expect("take"), None, "and only that one");

    let mut last = None;
    let deadline = Instant::now() + Duration::from_secs(20);
    while last != Some(WRITES) && Instant::now() < deadline {
        while let Ok(Some(sample)) = reliable.take() {
            last = Some(sample.value);
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(
        last,
        Some(WRITES),
        "the reliable KEEP_LAST reader never received the last value written"
    );
}
