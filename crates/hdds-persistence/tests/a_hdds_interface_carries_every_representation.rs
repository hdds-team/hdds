// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Item 6 through the REAL `DdsInterface` implementation
//! (`HddsDdsInterface`), not the mock the rest of this crate's test suite
//! uses: `HddsDataWriter` must relay through a writer that actually
//! offers a sample's representation, and `HddsDataReader::take` must
//! report the representation a sample actually arrived in.
//!
//! Needs a multicast-capable interface (HDDS refuses loopback as the
//! primary interface), so it is a host test, run by the service-crates
//! gate.

use std::thread;
use std::time::{Duration, Instant};

use hdds::dds::{Participant, QoS, TransportMode};
use hdds_persistence::dds_interface::{DdsInterface, DurabilityKind};
use hdds_persistence::HddsDdsInterface;

const DOMAIN: u32 = 145;
const TYPE_NAME: &str = "PersistRelayProbe";

fn wait_for(timeout: Duration, mut done: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if done() {
            return true;
        }
        thread::sleep(Duration::from_millis(20));
    }
    done()
}

/// `HddsDataWriter::write_sample` must relay an XCDR1 sample and an XCDR2
/// sample each through a writer that actually offers that representation:
/// a native reader that requests only one representation must receive
/// only the sample encoded in it.
#[test]
fn the_writer_relays_each_sample_through_the_representation_it_was_given() {
    let topic = "persist_relay_writer_probe";

    let participant = Participant::builder("persist-relay-writer-under-test")
        .domain_id(DOMAIN)
        .with_transport(TransportMode::UdpMulticast)
        .build()
        .expect("participant");
    let dds = HddsDdsInterface::new(participant).expect("dds interface");
    let writer = dds
        .create_writer(topic, TYPE_NAME, DurabilityKind::Volatile)
        .expect("writer");

    let native = Participant::builder("persist-relay-writer-native")
        .domain_id(DOMAIN)
        .with_transport(TransportMode::UdpMulticast)
        .build()
        .expect("native participant");
    let xcdr1_reader = native
        .create_raw_reader_with_type(
            topic,
            TYPE_NAME,
            Some(QoS::reliable().data_representation_xcdr1()),
            None,
            None,
        )
        .expect("xcdr1 reader");
    let xcdr2_reader = native
        .create_raw_reader_with_type(
            topic,
            TYPE_NAME,
            Some(QoS::reliable().data_representation_xcdr2()),
            None,
            None,
        )
        .expect("xcdr2 reader");

    thread::sleep(Duration::from_millis(1500));

    writer
        .write_sample(&[0x11, 0x22], 0, 0x0000)
        .expect("xcdr1 write");
    writer
        .write_sample(&[0x33, 0x44], 0, 0x0002)
        .expect("xcdr2 write");

    // Accumulate into two Vecs rather than checking "both non-empty" with
    // `&&` across two draining try_take_raw calls: that would short-circuit
    // the second reader's poll whenever the first reader's queue is
    // momentarily empty (e.g. already drained on a prior iteration),
    // permanently starving the check for the one that arrives later.
    let mut xcdr1_got = Vec::new();
    let mut xcdr2_got = Vec::new();
    let settled = wait_for(Duration::from_secs(10), || {
        xcdr1_got.extend(xcdr1_reader.try_take_raw().unwrap());
        xcdr2_got.extend(xcdr2_reader.try_take_raw().unwrap());
        !xcdr1_got.is_empty() && !xcdr2_got.is_empty()
    });

    assert!(
        settled,
        "both representations must reach their matching reader: xcdr1={} xcdr2={}",
        xcdr1_got.len(),
        xcdr2_got.len()
    );
    assert_eq!(xcdr1_got[0].payload, vec![0x11, 0x22]);
    assert_eq!(xcdr2_got[0].payload, vec![0x33, 0x44]);
}

/// `HddsDataReader::take` must report each sample's true
/// DATA_REPRESENTATION (`ReceivedSample::representation`), not drop it
/// (`try_take_raw`) or mislabel it: two native writers on the same topic,
/// one XCDR1 and one XCDR2, both relayed samples carrying the right tag.
#[test]
fn the_reader_reports_each_samples_true_representation() {
    let topic = "persist_relay_reader_probe";

    let participant = Participant::builder("persist-relay-reader-under-test")
        .domain_id(DOMAIN)
        .with_transport(TransportMode::UdpMulticast)
        .build()
        .expect("participant");
    let dds = HddsDdsInterface::new(participant).expect("dds interface");
    let reader = dds
        .create_reader(topic, TYPE_NAME, DurabilityKind::Volatile)
        .expect("reader");

    let native = Participant::builder("persist-relay-reader-native")
        .domain_id(DOMAIN)
        .with_transport(TransportMode::UdpMulticast)
        .build()
        .expect("native participant");
    let w1 = native
        .create_raw_writer_with_type(
            topic,
            TYPE_NAME,
            Some(QoS::reliable().data_representation_xcdr1()),
            None,
            None,
        )
        .expect("xcdr1 writer");
    let w2 = native
        .create_raw_writer_with_type(
            topic,
            TYPE_NAME,
            Some(QoS::reliable().data_representation_xcdr2()),
            None,
            None,
        )
        .expect("xcdr2 writer");

    thread::sleep(Duration::from_millis(1500));

    w1.write_raw(&[0xAA]).expect("xcdr1 write");
    w2.write_raw(&[0xBB]).expect("xcdr2 write");

    let mut got = Vec::new();
    let settled = wait_for(Duration::from_secs(10), || {
        got.extend(reader.take().unwrap());
        got.len() >= 2
    });

    assert!(settled, "both samples must be taken; got {}", got.len());
    let xcdr1_sample = got
        .iter()
        .find(|s| s.payload == [0xAA])
        .expect("xcdr1 payload missing");
    assert_eq!(xcdr1_sample.representation, 0x0000);
    let xcdr2_sample = got
        .iter()
        .find(|s| s.payload == [0xBB])
        .expect("xcdr2 payload missing");
    assert_eq!(xcdr2_sample.representation, 0x0002);
}
