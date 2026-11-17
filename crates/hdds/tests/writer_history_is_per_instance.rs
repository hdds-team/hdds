// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! A writer's history is kept PER INSTANCE (DDS 1.4 2.2.3.18): a
//! TRANSIENT_LOCAL KEEP_LAST(depth) writer owes a late joiner the last
//! `depth` samples of EACH instance.
//!
//! A KEEP_LAST(1) writer of three instances must replay three samples, not
//! one. Four things must not stack: accounting every change to instance
//! 0, a durable writer's depth becoming its total `max_samples`, adopting
//! DURABILITY_SERVICE `max_instances` (default 1), and RESOURCE_LIMITS
//! `max_instances` defaulting to 1. Fixing the first alone would make it
//! worse (a KEEP_ALL writer would then keep only its first instance), which
//! is why the controls below matter as much as the two cases.

use hdds::{DdsTrait, Participant, QoS, TransportMode};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq)]
struct Keyed {
    id: u32,
    value: u32,
}

#[derive(hdds::DDS)]
struct KeyedWire {
    id: u32,
    value: u32,
}

impl DdsTrait for Keyed {
    fn type_descriptor() -> &'static hdds::core::types::TypeDescriptor {
        KeyedWire::type_descriptor()
    }

    fn encode(&self, buf: &mut [u8], _version: hdds::dds::CdrVersion) -> hdds::Result<usize> {
        if buf.len() < 8 {
            return Err(hdds::Error::BufferTooSmall);
        }
        buf[..4].copy_from_slice(&self.id.to_le_bytes());
        buf[4..8].copy_from_slice(&self.value.to_le_bytes());
        Ok(8)
    }

    fn decode(buf: &[u8], _version: hdds::dds::CdrVersion) -> hdds::Result<Self> {
        if buf.len() < 8 {
            return Err(hdds::Error::InvalidState("short".to_string()));
        }
        Ok(Self {
            id: u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]),
            value: u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]),
        })
    }

    fn has_key() -> bool {
        true
    }

    fn compute_key(&self) -> [u8; 16] {
        let mut key = [0u8; 16];
        key[..4].copy_from_slice(&self.id.to_be_bytes());
        key
    }
}

fn drain(reader: &hdds::DataReader<Keyed>, expected: usize, timeout: Duration) -> Vec<(u32, u32)> {
    let deadline = Instant::now() + timeout;
    let mut values = Vec::new();
    while Instant::now() < deadline {
        while let Some(sample) = reader.take().unwrap() {
            values.push((sample.id, sample.value));
        }
        if values.len() >= expected {
            // Linger briefly so an over-delivery would also be seen.
            std::thread::sleep(Duration::from_millis(200));
            while let Some(sample) = reader.take().unwrap() {
                values.push((sample.id, sample.value));
            }
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    values
}

fn late_joiner(
    name: &str,
    writer_qos: QoS,
    writes: &[(u32, u32)],
    expected: usize,
) -> Vec<(u32, u32)> {
    let participant = Participant::builder(name)
        .domain_id(0)
        .with_transport(TransportMode::IntraProcess)
        .build()
        .unwrap();
    let topic = participant.topic::<Keyed>(name).unwrap();
    let writer = topic.writer().qos(writer_qos).build().unwrap();
    for &(id, value) in writes {
        writer.write(&Keyed { id, value }).unwrap();
    }
    let late = topic
        .reader()
        .qos(QoS::reliable().transient_local().keep_all())
        .build()
        .unwrap();
    let mut got = drain(&late, expected, Duration::from_secs(3));
    got.sort_unstable();
    got
}

#[test]
fn keep_last_1_replays_the_newest_sample_of_every_instance() {
    let got = late_joiner(
        "ks_m1",
        QoS::reliable().transient_local().keep_last(1),
        &[(1, 10), (2, 20), (3, 30)],
        3,
    );
    assert_eq!(
        got,
        vec![(1, 10), (2, 20), (3, 30)],
        "DDS: depth 1 PER INSTANCE"
    );
}

#[test]
fn keep_last_2_replays_two_samples_of_every_instance() {
    let got = late_joiner(
        "ks_m2",
        QoS::reliable().transient_local().keep_last(2),
        &[(1, 10), (1, 11), (2, 20), (2, 21)],
        4,
    );
    assert_eq!(
        got,
        vec![(1, 10), (1, 11), (2, 20), (2, 21)],
        "DDS: depth 2 PER INSTANCE"
    );
}

#[test]
fn keep_last_1_of_one_instance_replays_only_its_newest() {
    let got = late_joiner(
        "ks_c1",
        QoS::reliable().transient_local().keep_last(1),
        &[(1, 10), (1, 11), (1, 12)],
        1,
    );
    assert_eq!(got, vec![(1, 12)], "one instance, depth 1: only the newest");
}

#[test]
fn keep_last_3_of_three_instances_replays_all_three() {
    let got = late_joiner(
        "ks_c2",
        QoS::reliable().transient_local().keep_last(3),
        &[(1, 10), (2, 20), (3, 30)],
        3,
    );
    assert_eq!(got, vec![(1, 10), (2, 20), (3, 30)]);
}

#[test]
fn keep_all_replays_every_instance() {
    // Same late reader, a writer that evicts nothing: the reader side keeps
    // every instance, so a loss in the cases above is the writer's.
    let got = late_joiner(
        "ks_c3",
        QoS::reliable().transient_local().keep_all(),
        &[(1, 10), (2, 20), (3, 30)],
        3,
    );
    assert_eq!(got, vec![(1, 10), (2, 20), (3, 30)]);
}

#[test]
fn a_live_keep_last_1_reader_keeps_one_sample_per_instance() {
    // Reader side: a live KEEP_LAST(1) reader, writer keeps everything,
    // nothing taken until all three instances were written.
    let participant = Participant::builder("ks_r1")
        .domain_id(0)
        .with_transport(TransportMode::IntraProcess)
        .build()
        .unwrap();
    let topic = participant.topic::<Keyed>("ks_r1").unwrap();
    let writer = topic
        .writer()
        .qos(QoS::reliable().keep_all())
        .build()
        .unwrap();
    let reader = topic
        .reader()
        .qos(QoS::reliable().keep_last(1))
        .build()
        .unwrap();
    std::thread::sleep(Duration::from_millis(200));
    for (id, value) in [(1, 10), (2, 20), (3, 30)] {
        writer.write(&Keyed { id, value }).unwrap();
    }
    std::thread::sleep(Duration::from_millis(500));
    let mut got = drain(&reader, 3, Duration::from_secs(2));
    got.sort_unstable();
    assert_eq!(
        got,
        vec![(1, 10), (2, 20), (3, 30)],
        "DDS: reader depth 1 PER INSTANCE"
    );
}
