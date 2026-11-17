// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! A sample a writer sends in fragments reaches a reader of its own
//! participant once.
//!
//! The writer delivers to a reader of its own participant in process, and
//! sends the same sample over UDP for a remote reader. Whatever of that
//! traffic comes back to the sender must not reach the local reader a
//! second time, whole or in fragments. This passed before the router's own
//! fragment suppression worked (the pin for that rule is at the router
//! loop); it is kept as the end-to-end statement of the property.

use hdds::test_support::domains::unique_domain;
use hdds::{Participant, QoS, TransportMode};
use std::time::{Duration, Instant};

#[derive(Clone, Debug, PartialEq, hdds::DDS)]
struct Blob {
    value: u32,
    data: Vec<u8>,
}

/// Large enough to travel as DATA_FRAG.
const BLOB_BYTES: usize = 20_000;
const SAMPLES: u32 = 5;

fn received(reader: &hdds::DataReader<Blob>, period: Duration) -> Vec<u32> {
    let mut values = Vec::new();
    let deadline = Instant::now() + period;
    while Instant::now() < deadline {
        while let Ok(Some(sample)) = reader.take() {
            values.push(sample.value);
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    values
}

fn once_each(payload: usize) -> Vec<u32> {
    let domain = unique_domain();
    let participant = Participant::builder("own_fragments")
        .domain_id(domain.id())
        .with_transport(TransportMode::UdpMulticast)
        .build()
        .expect("participant");
    let topic = participant.topic::<Blob>("OwnFragments").expect("topic");
    let reader = topic
        .reader()
        .qos(QoS::reliable().keep_all())
        .build()
        .expect("reader");
    let writer = topic
        .writer()
        .qos(QoS::reliable().keep_all())
        .build()
        .expect("writer");
    // A remote reader, so the writer does send over UDP.
    let remote = Participant::builder("own_fragments_remote")
        .domain_id(domain.id())
        .with_transport(TransportMode::UdpMulticast)
        .build()
        .expect("remote participant");
    let remote_reader = remote
        .topic::<Blob>("OwnFragments")
        .expect("topic")
        .reader()
        .qos(QoS::reliable().keep_all())
        .build()
        .expect("remote reader");
    std::thread::sleep(Duration::from_millis(1500));
    for value in 1..=SAMPLES {
        writer
            .write(&Blob {
                value,
                data: vec![value as u8; payload],
            })
            .expect("write");
    }
    let local = received(&reader, Duration::from_secs(2));
    let far = received(&remote_reader, Duration::from_millis(200));
    assert_eq!(
        far,
        (1..=SAMPLES).collect::<Vec<_>>(),
        "the remote reader, over UDP"
    );
    local
}

#[test]
fn a_sample_written_whole_reaches_a_local_reader_once() {
    assert_eq!(once_each(16), (1..=SAMPLES).collect::<Vec<_>>());
}

#[test]
fn a_sample_written_in_fragments_reaches_a_local_reader_once() {
    assert_eq!(once_each(BLOB_BYTES), (1..=SAMPLES).collect::<Vec<_>>());
}
