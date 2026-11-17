// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! `DataWriter::stats()` and `DataReader::stats()` report the figures of
//! that one entity, raised at the same doors as the process telemetry
//! counters. Intra-process pairs make every write and take synchronous, so
//! the figures can be asserted exactly after each step.

use hdds::test_support::domains::unique_domain;
use hdds::{DataReader, DataWriter, Participant, QoS, TransportMode};
use std::sync::Arc;

#[derive(hdds::DDS, Debug, Clone, PartialEq)]
struct Blob {
    value: i64,
    pad: Vec<u8>,
}

/// A leased domain in the 200..=230 band; leases the pool hands out below
/// it are held only until one in the band comes up.
fn domain() -> hdds::test_support::domains::DomainLease {
    let mut other = Vec::new();
    loop {
        let lease = unique_domain();
        if (200..=230).contains(&lease.id()) {
            return lease;
        }
        other.push(lease);
    }
}

fn intra(name: &str, domain: u32) -> Arc<Participant> {
    Participant::builder(name)
        .domain_id(domain)
        .with_transport(TransportMode::IntraProcess)
        .build()
        .expect("participant")
}

fn writer_on(p: &Arc<Participant>, topic: &str, qos: QoS) -> DataWriter<Blob> {
    p.topic::<Blob>(topic)
        .expect("writer topic")
        .writer()
        .qos(qos)
        .build()
        .expect("writer")
}

fn reader_on(p: &Arc<Participant>, topic: &str, qos: QoS) -> DataReader<Blob> {
    p.topic::<Blob>(topic)
        .expect("reader topic")
        .reader()
        .qos(qos)
        .build()
        .expect("reader")
}

#[test]
fn writer_and_reader_stats_count_their_own_writes_and_takes() {
    let domain = domain();
    let p = intra("ps_counts", domain.id());
    let topic = "ps_counts_roundtrip";
    let writer = writer_on(&p, topic, QoS::reliable().keep_last(64));
    let reader = reader_on(&p, topic, QoS::reliable().keep_last(64));

    let w0 = writer.stats();
    let r0 = reader.stats();
    assert_eq!(
        (w0.messages_sent, w0.bytes_sent, w0.drops),
        (0, 0, 0),
        "a fresh writer has written nothing"
    );
    assert_eq!(
        (r0.messages_received, r0.drops),
        (0, 0),
        "a fresh reader has received nothing"
    );

    // One write first: its serialized size is the unit every later write
    // of the same payload must add.
    let pad = vec![3u8; 10];
    writer
        .write(&Blob {
            value: 0,
            pad: pad.clone(),
        })
        .expect("write");
    let unit = writer.stats().bytes_sent;
    assert!(unit > 10, "bytes_sent counts the serialized sample");
    assert_eq!(writer.stats().messages_sent, 1);

    const N: i64 = 6;
    for value in 1..N {
        writer
            .write(&Blob {
                value,
                pad: pad.clone(),
            })
            .expect("write");
    }
    let ws = writer.stats();
    assert_eq!(ws.messages_sent, N as u64, "one messages_sent per write");
    assert_eq!(ws.bytes_sent, N as u64 * unit, "bytes_sent per write");
    assert_eq!(ws.drops, 0, "no intra-process delivery was abandoned");

    // A second writer on the same topic counts only its own writes.
    let other = writer_on(&p, topic, QoS::reliable().keep_last(64));
    other
        .write(&Blob {
            value: 100,
            pad: vec![],
        })
        .expect("write");
    assert_eq!(other.stats().messages_sent, 1, "per-writer, not per-topic");
    assert_eq!(
        writer.stats().messages_sent,
        N as u64,
        "the first writer is untouched by the second"
    );

    // Nothing is taken yet: the reader has not been asked for anything.
    let taken = reader.take_all().expect("take_all");
    assert_eq!(taken.len(), N as usize + 1, "every sample arrives once");
    let rs = reader.stats();
    assert_eq!(
        rs.messages_received,
        N as u64 + 1,
        "one messages_received per sample that reached the history"
    );
    assert_eq!(rs.drops, 0, "a KEEP_LAST(64) history never fills here");
    assert_eq!(rs.bytes_received, 0, "documented as not counted: always 0");
    assert_eq!(
        writer.stats().messages_sent,
        N as u64,
        "taking does not move the writer's figures"
    );
}

#[test]
fn reader_drops_count_the_samples_a_keep_last_history_pushes_out_unread() {
    let domain = domain();
    let p = intra("ps_drops", domain.id());
    let topic = "ps_keep_last_drops";
    let writer = writer_on(&p, topic, QoS::best_effort().keep_last(1));
    let reader = reader_on(&p, topic, QoS::best_effort().keep_last(1));

    const N: usize = 5;
    for value in 0..N as i64 {
        writer.write(&Blob { value, pad: vec![] }).expect("write");
    }
    let kept = reader.take_all().expect("take_all");
    assert_eq!(kept.len(), 1, "KEEP_LAST(1) keeps the newest sample");
    assert_eq!(kept[0].value, N as i64 - 1);

    let rs = reader.stats();
    assert_eq!(
        rs.drops,
        (N - kept.len()) as u64,
        "every sample not handed to the application was a drop"
    );
    assert_eq!(
        rs.messages_received, N as u64,
        "all 5 were deposited in the history before being replaced"
    );
    assert_eq!(
        writer.stats().drops,
        0,
        "a reader-side replacement is not a writer drop"
    );
}
