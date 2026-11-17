// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! A RELIABLE KEEP_ALL reader whose storage is full must not lose a sample
//! for good. DDS 1.4 2.2.3.19: "If the
//! reliability is RELIABLE, the Service will block the DataWriter or discard
//! the sample at the DataReader in order not to lose existing samples",
//! footnote 28: "So that the sample can be re-sent at a later time."
//!
//! The application does not take while the writer writes more than the
//! reader can hold, then takes everything. Every sample must arrive in the
//! end: the ones the reader could not hold are sent again.

use hdds::test_support::domains::unique_domain;
use hdds::{Participant, QoS, TransportMode};
use std::time::{Duration, Instant};

#[derive(Clone, Debug, PartialEq, hdds::DDS)]
struct Seq {
    value: u32,
}

const WRITES: u32 = 1500;

#[test]
fn a_full_reliable_reader_loses_nothing() {
    let domain = unique_domain();
    let publisher = Participant::builder("full_reader_pub")
        .domain_id(domain.id())
        .participant_id(Some(80))
        .with_transport(TransportMode::UdpMulticast)
        .build()
        .expect("publisher");
    let subscriber = Participant::builder("full_reader_sub")
        .domain_id(domain.id())
        .participant_id(Some(81))
        .with_transport(TransportMode::UdpMulticast)
        .build()
        .expect("subscriber");

    let mut reader_qos = QoS::reliable().keep_all();
    reader_qos.resource_limits.max_samples = 64;
    let reader = subscriber
        .topic::<Seq>("FullReader")
        .expect("topic")
        .reader()
        .qos(reader_qos)
        .build()
        .expect("reader");
    let writer = publisher
        .topic::<Seq>("FullReader")
        .expect("topic")
        .writer()
        .qos(QoS::reliable().keep_all())
        .build()
        .expect("writer");

    std::thread::sleep(Duration::from_millis(1500));
    let mut written = 0u32;
    for value in 1..=WRITES {
        match writer.write(&Seq { value }) {
            Ok(()) => written += 1,
            Err(e) => panic!("write {value} failed: {e:?}"),
        }
    }
    // Let everything that can arrive arrive, without taking.
    std::thread::sleep(Duration::from_secs(2));

    let mut got = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(20);
    while got.len() < written as usize && Instant::now() < deadline {
        while let Ok(Some(sample)) = reader.take() {
            got.push(sample.value);
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    // A RELIABLE reader delivers one writer's samples once each, in the
    // writer's order (RTPS 2.5 8.4.12: a change is available once every
    // earlier one is), including those it could not hold at first.
    let mut sorted = got.clone();
    sorted.sort_unstable();
    sorted.dedup();
    let missing: Vec<u32> = (1..=written)
        .filter(|v| sorted.binary_search(v).is_err())
        .collect();
    assert!(
        missing.is_empty(),
        "{} of {} samples never arrived; first missing: {:?}",
        missing.len(),
        written,
        &missing[..missing.len().min(10)]
    );
    let expected: Vec<u32> = (1..=written).collect();
    if got != expected {
        let first_bad = got
            .iter()
            .zip(&expected)
            .position(|(g, e)| g != e)
            .unwrap_or(expected.len().min(got.len()));
        panic!(
            "{} samples taken for {} written, not once each in order; from index {}: {:?}",
            got.len(),
            written,
            first_bad,
            &got[first_bad..got.len().min(first_bad + 10)]
        );
    }
}
