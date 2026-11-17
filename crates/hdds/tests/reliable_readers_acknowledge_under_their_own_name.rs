// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Each reliable reader acknowledges under its own name (RTPS 2.5 8.4.12:
//! a reliable reader keeps one WriterProxy per matched writer and sends its
//! ACKNACKs with its own readerId).
//!
//! A KEEP_ALL RELIABLE writer frees a sample only once EVERY matched
//! reliable reader acknowledged it (RTPS 2.5 8.4.1, `is_acked_by_all`), and
//! its `write()` waits for room up to `max_blocking_time` then fails with a
//! timeout (DDS 1.4 2.2.2.4.2.11). The writer attributes an ACKNACK to the
//! reader GUID it names. So if a participant acknowledged once for all its
//! readers, or under an identifier it never announced, the writer would see
//! no reader progress and `write()` would stall at its resource limits.
//!
//! Both participants live in this process but talk over UDP: a
//! cross-participant pair is served by RTPS, not by the intra-process path
//! (`local_delivery_scope.rs`).

use hdds::test_support::domains::unique_domain;
use hdds::{Participant, QoS, TransportMode};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Clone, Debug, PartialEq, hdds::DDS)]
struct Tick {
    value: u32,
}

/// Room for this many samples: past it, `write()` needs acknowledgements.
const LIMIT: usize = 4;
/// Many times the limit, so the writer must recycle its history repeatedly.
const WRITES: u32 = 40;

fn udp_participant(name: &str, domain_id: u32, participant_id: u8) -> Arc<Participant> {
    Participant::builder(name)
        .domain_id(domain_id)
        .participant_id(Some(participant_id))
        .with_transport(TransportMode::UdpMulticast)
        .build()
        .expect("participant")
}

fn small_keep_all_writer_qos() -> QoS {
    let mut qos = QoS::reliable().keep_all();
    qos.resource_limits.max_samples = LIMIT;
    qos.resource_limits.max_samples_per_instance = LIMIT;
    qos
}

fn wait_for(what: &str, timeout: Duration, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + timeout;
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Write `WRITES` samples, draining every reader between writes, and
/// return how many writes succeeded before the first refusal.
fn write_through(writer: &hdds::DataWriter<Tick>, readers: &[&hdds::DataReader<Tick>]) -> u32 {
    let mut written = 0;
    for value in 0..WRITES {
        // A refused write is retried for a while: acknowledgements travel
        // through the reader's periodic HEARTBEAT answer, not instantly.
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match writer.write(&Tick { value }) {
                Ok(()) => break,
                Err(_) if Instant::now() < deadline => {}
                Err(_) => return written,
            }
        }
        written += 1;
        for reader in readers {
            while let Ok(Some(_)) = reader.take() {}
        }
    }
    written
}

#[test]
fn two_reliable_readers_of_one_participant_both_release_the_writer() {
    let domain = unique_domain();
    let publisher = udp_participant("own_name_pub", domain.id(), 60);
    let subscriber = udp_participant("own_name_sub", domain.id(), 61);

    let topic = "OwnNameTwoReaders";
    let first = subscriber
        .topic::<Tick>(topic)
        .expect("topic")
        .reader()
        .qos(QoS::reliable().keep_all())
        .build()
        .expect("first reader");
    let second = subscriber
        .topic::<Tick>(topic)
        .expect("topic")
        .reader()
        .qos(QoS::reliable().keep_all())
        .build()
        .expect("second reader");
    let writer = publisher
        .topic::<Tick>(topic)
        .expect("topic")
        .writer()
        .qos(small_keep_all_writer_qos())
        .build()
        .expect("writer");

    wait_for("both readers to match", Duration::from_secs(10), || {
        writer.matched_reader_count() == 2
    });

    let written = write_through(&writer, &[&first, &second]);
    assert_eq!(
        written, WRITES,
        "the writer stalled: its readers' acknowledgements never reached \
         the proxies it keeps for them"
    );
}

#[test]
fn one_reliable_reader_releases_the_writer() {
    // Control: the single-reader case, which the per-participant answer
    // happened to name correctly.
    let domain = unique_domain();
    let publisher = udp_participant("own_name_pub1", domain.id(), 62);
    let subscriber = udp_participant("own_name_sub1", domain.id(), 63);

    let topic = "OwnNameOneReader";
    let reader = subscriber
        .topic::<Tick>(topic)
        .expect("topic")
        .reader()
        .qos(QoS::reliable().keep_all())
        .build()
        .expect("reader");
    let writer = publisher
        .topic::<Tick>(topic)
        .expect("topic")
        .writer()
        .qos(small_keep_all_writer_qos())
        .build()
        .expect("writer");

    wait_for("the reader to match", Duration::from_secs(10), || {
        writer.matched_reader_count() == 1
    });

    assert_eq!(write_through(&writer, &[&reader]), WRITES);
}

/// DDS 1.4 2.2.2.4.2.15 counts every matched reliable reader. A local
/// synchronous delivery acknowledges at cache admission, before take().
#[test]
fn a_same_participant_reader_acknowledges_at_cache_admission() {
    let domain = unique_domain();
    let participant = udp_participant("own_name_intra", domain.id(), 64);
    let topic = "OwnNameIntraWaitForAck";
    let writer = participant
        .topic::<Tick>(topic)
        .expect("topic")
        .writer()
        .qos(QoS::reliable().keep_all())
        .build()
        .expect("writer");
    let reader = participant
        .topic::<Tick>(topic)
        .expect("topic")
        .reader()
        .qos(QoS::reliable().keep_all())
        .build()
        .expect("reader");
    wait_for("the reader to match", Duration::from_secs(10), || {
        writer.matched_reader_count() == 1
    });
    writer.write(&Tick { value: 1 }).expect("write");
    assert_eq!(writer.acked_through(), 1, "the reader really acknowledged");
    writer
        .wait_for_acknowledgments(Duration::ZERO)
        .expect("admitted before take");
    assert_eq!(reader.take().expect("take").expect("sample").value, 1);
    assert!(reader.take().expect("take empty").is_none());
}
