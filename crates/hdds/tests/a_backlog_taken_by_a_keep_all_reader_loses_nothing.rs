// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! A RELIABLE KEEP_ALL reader keeps every sample it acknowledged until the
//! application takes it (DDS 1.4 2.2.3.18), holds at most its RESOURCE_LIMITS
//! `max_samples` (2.2.3.19), and refuses the rest unacknowledged so the
//! writer sends them again.
//!
//! The reader's history is its network ring and the cache `take` fills from
//! it. When the history's room counted only the ring, `take` moving the
//! backlog into the cache gave every place back at once: the writer's
//! retransmissions then filled the ring again, the next `take` moved them
//! into a cache already holding the backlog, and the cache's KEEP_ALL bound
//! (1024 per instance) evicted the oldest samples, acknowledged, in silence.

use hdds::test_support::domains::unique_domain;
use hdds::{DataReader, DataWriter, Participant, QoS, TransportMode};
use std::time::{Duration, Instant};

#[derive(Clone, Debug, PartialEq, hdds::DDS)]
struct Seq {
    value: u32,
}

const WRITES: u32 = 1500;
const WRITER_HISTORY: usize = 64;

struct Pair {
    _publisher: std::sync::Arc<Participant>,
    _subscriber: std::sync::Arc<Participant>,
    reader: DataReader<Seq>,
    writer: DataWriter<Seq>,
    // Last, so it is released after the participants: dropped at the end of
    // `pair()`, the domain went back to the pool while both participants
    // still held its ports.
    _domain: hdds::test_support::domains::DomainLease,
}

fn pair(topic: &str, ids: (u8, u8), reader_max_samples: usize) -> Pair {
    let domain = unique_domain();
    let publisher = Participant::builder("backlog_pub")
        .domain_id(domain.id())
        .participant_id(Some(ids.0))
        .with_transport(TransportMode::UdpMulticast)
        .build()
        .expect("publisher");
    let subscriber = Participant::builder("backlog_sub")
        .domain_id(domain.id())
        .participant_id(Some(ids.1))
        .with_transport(TransportMode::UdpMulticast)
        .build()
        .expect("subscriber");

    let mut reader_qos = QoS::reliable().keep_all();
    reader_qos.resource_limits.max_samples = reader_max_samples;
    let reader = subscriber
        .topic::<Seq>(topic)
        .expect("topic")
        .reader()
        .qos(reader_qos)
        .build()
        .expect("reader");
    let mut writer_qos = QoS::reliable().keep_all();
    writer_qos.resource_limits.max_samples = WRITER_HISTORY;
    let writer = publisher
        .topic::<Seq>(topic)
        .expect("topic")
        .writer()
        .qos(writer_qos)
        .build()
        .expect("writer");
    // Both endpoints VOLATILE: wait for the match itself, not a delay.
    let matched_by = Instant::now() + Duration::from_secs(10);
    while writer.matched_reader_count() < 1 {
        assert!(Instant::now() < matched_by, "the reader never matched");
        std::thread::sleep(Duration::from_millis(20));
    }
    std::thread::sleep(Duration::from_millis(500));
    Pair {
        _publisher: publisher,
        _subscriber: subscriber,
        reader,
        writer,
        _domain: domain,
    }
}

/// Write without taking until the writer stays blocked for 3 s; returns the
/// next value to write.
fn write_until_blocked(writer: &DataWriter<Seq>) -> u32 {
    let mut next = 1u32;
    let mut stuck_since: Option<Instant> = None;
    while next <= WRITES {
        if writer.write(&Seq { value: next }).is_ok() {
            next += 1;
            stuck_since = None;
        } else if stuck_since.get_or_insert_with(Instant::now).elapsed() > Duration::from_secs(3) {
            break;
        }
    }
    next
}

/// Take everything while writing the rest, then check every value arrived
/// once and in order.
fn take_all_writing_the_rest(pair: &Pair, mut next: u32, mut got: Vec<u32>, context: &str) {
    let deadline = Instant::now() + Duration::from_secs(60);
    while got.len() < WRITES as usize && Instant::now() < deadline {
        while let Ok(Some(sample)) = pair.reader.take() {
            got.push(sample.value);
        }
        if next <= WRITES && pair.writer.write(&Seq { value: next }).is_ok() {
            next += 1;
        } else {
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    let expected: Vec<u32> = (1..=WRITES).collect();
    if got != expected {
        let mut sorted = got.clone();
        sorted.sort_unstable();
        sorted.dedup();
        let missing: Vec<u32> = expected
            .iter()
            .copied()
            .filter(|v| sorted.binary_search(v).is_err())
            .collect();
        panic!(
            "{context}: {} taken, {} distinct, {} missing (first {:?}), written {}",
            got.len(),
            sorted.len(),
            missing.len(),
            &missing[..missing.len().min(10)],
            next - 1
        );
    }
}

/// The reader is full at `max_samples`, the writer at its own history: the
/// application then takes one sample, the writer's retransmissions arrive,
/// and the application works through everything.
#[test]
fn a_backlog_taken_by_a_keep_all_reader_loses_nothing() {
    const READER_MAX_SAMPLES: usize = 64;
    let pair = pair("Backlog", (84, 85), READER_MAX_SAMPLES);

    let next = write_until_blocked(&pair.writer);
    let backlog = next as usize - 1;
    assert!(
        backlog <= READER_MAX_SAMPLES + WRITER_HISTORY,
        "backlog {backlog}: the reader held more than its max_samples {READER_MAX_SAMPLES}"
    );

    let mut got = Vec::new();
    if let Ok(Some(sample)) = pair.reader.take() {
        got.push(sample.value);
    }
    std::thread::sleep(Duration::from_secs(3));
    take_all_writing_the_rest(&pair, next, got, &format!("backlog {backlog}"));
}

/// A reader whose `max_samples` is above the cache's own per-instance bound
/// (1024) receives every sample before the application takes any: `take`
/// moves them all into the cache at once, and the cache keeps them all.
#[test]
fn a_keep_all_reader_above_the_cache_bound_loses_nothing() {
    let pair = pair("AboveCacheBound", (86, 87), 2000);

    let next = write_until_blocked(&pair.writer);
    // Let the last samples reach the reader before the first take.
    std::thread::sleep(Duration::from_secs(1));
    take_all_writing_the_rest(
        &pair,
        next,
        Vec::new(),
        &format!("written first {}", next - 1),
    );
}
