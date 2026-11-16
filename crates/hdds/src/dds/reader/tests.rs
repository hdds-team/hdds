// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use super::ReaderBuilder;
use crate::core::rt::{self, IndexEntry};
use crate::dds::QoS;
use crate::dds::DDS;
use crate::engine::TopicRegistry;
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, crate::DDS)]
struct Point {
    x: i32,
    y: i32,
}

/// CDR bytes as the router hands them to a subscriber (encapsulation stripped).
fn encoded(point: Point) -> Vec<u8> {
    let mut buf = vec![0u8; 64];
    let len = point
        .encode(&mut buf, crate::dds::CdrVersion::Xcdr2)
        .expect("encode should succeed");
    buf.truncate(len);
    buf
}

/// Deliver `seq` from `writer` exactly as the router does: record reception
/// first (RTPS v2.5 §8.3.7.1, pre-delivery and independent of subscribers),
/// then fan the sample out to the topic's subscribers.
fn route(registry: &TopicRegistry, topic: &str, writer: [u8; 16], seq: u64, point: Point) {
    registry.note_user_sample_received(writer, seq);
    registry
        .get_topic(topic)
        .expect("topic must exist after reader registration")
        .deliver_with_writer(writer, seq, &encoded(point), crate::dds::CdrVersion::Xcdr2);
}

/// Non-VOLATILE readers floor the reorder gate at the participant's
/// acknowledged low mark: hdds already acknowledged 1..2 under this reader's
/// entity id (RTPS v2.5 §8.3.7.1) and the writer has retired them
/// (§8.4.2.3.3), so the reader must resume at 3 instead of stalling.
#[test]
fn non_volatile_reader_floors_gate_at_registry_low_mark() {
    let _ = rt::init_slab_pool();
    let registry = Arc::new(TopicRegistry::new());
    let writer = [0xA1u8; 16];

    // A predecessor reader on this participant consumed 1..2.
    registry.note_user_sample_received(writer, 1);
    registry.note_user_sample_received(writer, 2);

    let reader = ReaderBuilder::<Point>::new("floored".to_string())
        .qos(QoS::reliable().transient_local())
        .with_registry(Arc::clone(&registry))
        .build()
        .expect("reader build should succeed");

    route(&registry, "floored", writer, 3, Point { x: 3, y: 30 });

    let got = reader
        .take()
        .expect("take should not error")
        .expect("seq 3 must be delivered, not held behind the retired 1..2");
    assert_eq!(got.x, 3);
}

/// Control for the test above: with nothing acknowledged the registry reports no
/// floor, so a non-VOLATILE reader keeps the late-joiner contract and holds the
/// sample until a HEARTBEAT seeds the base (RTPS v2.5 §8.3.7.5).
#[test]
fn non_volatile_reader_without_acknowledged_prefix_holds_for_history() {
    let _ = rt::init_slab_pool();
    let registry = Arc::new(TopicRegistry::new());
    let writer = [0xA2u8; 16];

    let reader = ReaderBuilder::<Point>::new("unfloored".to_string())
        .qos(QoS::reliable().transient_local())
        .with_registry(Arc::clone(&registry))
        .build()
        .expect("reader build should succeed");

    route(&registry, "unfloored", writer, 3, Point { x: 3, y: 30 });

    assert!(
        reader.take().expect("take should not error").is_none(),
        "no acknowledged prefix means no floor: seq 3 must wait for 1..2"
    );

    // The writer then announces it starts at 3; the gate fast-forwards.
    registry
        .get_topic("unfloored")
        .expect("topic")
        .deliver_writer_heartbeat(writer, 3);
    let got = reader
        .take()
        .expect("take should not error")
        .expect("HEARTBEAT firstSN=3 must release the held sample");
    assert_eq!(got.x, 3);
}

/// VOLATILE readers get no gate and no floor (DDS v1.4 §2.2.3.4): a sample at or
/// below the acknowledged low mark still passes straight through.
#[test]
fn volatile_reader_is_unfloored_and_ungated() {
    let _ = rt::init_slab_pool();
    let registry = Arc::new(TopicRegistry::new());
    let writer = [0xA3u8; 16];

    for seq in 1..=5 {
        registry.note_user_sample_received(writer, seq);
    }

    let reader = ReaderBuilder::<Point>::new("volatile".to_string())
        .qos(QoS::reliable().volatile())
        .with_registry(Arc::clone(&registry))
        .build()
        .expect("reader build should succeed");

    // Floor would be 6. Out-of-order arrival: a floored gate would deliver 4 and
    // then drop 3 as below-base, and an unfloored gate would hold both.
    route(&registry, "volatile", writer, 4, Point { x: 4, y: 40 });
    route(&registry, "volatile", writer, 3, Point { x: 3, y: 30 });

    let mut received = Vec::new();
    while let Ok(Some(point)) = reader.take() {
        received.push(point.x);
    }
    assert_eq!(
        received,
        vec![4, 3],
        "VOLATILE readers must pass samples through verbatim, ungated and unfloored"
    );
}

#[test]
fn reader_returns_none_when_ring_empty() {
    let reader = ReaderBuilder::<Point>::new("test".to_string())
        .qos(QoS::best_effort())
        .build()
        .expect("reader build should succeed");

    let result = reader.take().expect("take should not error");
    assert!(result.is_none(), "Should return None when ring empty");
}

#[test]
fn reader_reads_written_sample() {
    let _ = rt::init_slab_pool();

    let writer = crate::dds::writer::WriterBuilder::<Point>::new("test".to_string())
        .qos(QoS::best_effort())
        .build()
        .expect("writer build should succeed");

    let reader = ReaderBuilder::<Point>::new("test".to_string())
        .qos(QoS::best_effort())
        .build()
        .expect("reader build should succeed");

    reader.bind_to_writer(writer.merger());

    let msg = Point { x: 42, y: 123 };
    writer.write(&msg).expect("write should succeed");

    let received = reader
        .take()
        .expect("take should not error")
        .expect("should receive message");
    assert_eq!(received.x, 42);
    assert_eq!(received.y, 123);
}

#[test]
fn keep_last_drops_oldest_samples() {
    let _ = rt::init_slab_pool();

    let writer = crate::dds::writer::WriterBuilder::<Point>::new("test".to_string())
        .qos(QoS::best_effort())
        .build()
        .expect("writer build should succeed");

    let reader = ReaderBuilder::<Point>::new("test".to_string())
        .qos(QoS::best_effort().keep_last(3))
        .build()
        .expect("reader build should succeed");

    reader.bind_to_writer(writer.merger());

    for i in 0_i32..5 {
        let msg = Point { x: i, y: i * 2 };
        writer.write(&msg).expect("write should succeed");
    }

    let mut received = Vec::new();
    while let Ok(Some(msg)) = reader.take() {
        received.push(msg.x);
    }

    assert_eq!(received.len(), 3, "Should keep only the configured depth");
    assert_eq!(received, vec![2, 3, 4], "Should contain the newest samples");
}

#[test]
fn batch_read_limits_number_of_samples() {
    let _ = rt::init_slab_pool();

    let writer = crate::dds::writer::WriterBuilder::<Point>::new("test".to_string())
        .qos(QoS::best_effort())
        .build()
        .expect("writer build should succeed");

    let reader = ReaderBuilder::<Point>::new("test".to_string())
        .qos(QoS::best_effort())
        .build()
        .expect("reader build should succeed");

    reader.bind_to_writer(writer.merger());

    for i in 0_i32..10 {
        writer
            .write(&Point { x: i, y: i })
            .expect("write should succeed");
    }

    let batch = reader.take_batch(5).expect("batch read should succeed");
    assert_eq!(
        batch.len(),
        5,
        "Should read the requested number of samples"
    );

    for (expected, msg) in (0_i32..).zip(batch.iter()) {
        assert_eq!(msg.x, expected);
    }
}

#[test]
fn reliable_reader_tracks_sequences() {
    let _ = rt::init_slab_pool();

    let reader = ReaderBuilder::<Point>::new("test".to_string())
        .qos(QoS::reliable())
        .build()
        .expect("reliable reader build should succeed");

    let writer = crate::dds::writer::WriterBuilder::<Point>::new("test".to_string())
        .qos(QoS::best_effort())
        .build()
        .expect("writer build should succeed");

    reader.bind_to_writer(writer.merger());

    for i in 1_i32..=5 {
        writer
            .write(&Point { x: i, y: i })
            .expect("write should succeed");
    }

    for _ in 0..5 {
        let _ = reader.take().expect("take should not error");
    }

    if let Some(scheduler) = reader.nack_scheduler_for_test() {
        let lock = match scheduler.lock() {
            Ok(lock) => lock,
            Err(err) => {
                log::debug!(
                    "[reliable_reader_tracks_sequences] nack_scheduler lock poisoned, recovering"
                );
                err.into_inner()
            }
        };
        assert!(lock.pending_gaps().is_empty(), "No gaps expected");
    }
}

#[test]
fn take_deduplicates_replay_scenario() {
    let _ = rt::init_slab_pool();

    let writer = crate::dds::writer::WriterBuilder::<Point>::new("test".to_string())
        .qos(QoS::best_effort())
        .build()
        .expect("writer build should succeed");

    let reader = ReaderBuilder::<Point>::new("test".to_string())
        .qos(QoS::best_effort())
        .build()
        .expect("reader build should succeed");

    reader.bind_to_writer(writer.merger());

    // Write 3 messages (goes through merger → reader ring)
    let msgs = [
        Point { x: 1, y: 10 },
        Point { x: 2, y: 20 },
        Point { x: 3, y: 30 },
    ];
    for msg in &msgs {
        writer.write(msg).expect("write should succeed");
    }

    // Simulate TRANSIENT_LOCAL replay: push duplicate entries with same seqs into ring.
    // The writer starts at seq=1, so writes produce seq 1, 2, 3.
    let slab_pool = rt::get_slab_pool();
    let ring = reader.ring_for_test();
    for (i, msg) in msgs.iter().enumerate() {
        let seq = (i as u32) + 1; // match writer's seq numbering
        let mut buf = vec![0u8; 256];
        let len = msg
            .encode(&mut buf, crate::dds::CdrVersion::Xcdr2)
            .expect("encode should succeed");
        let (handle, _metric) = slab_pool
            .reserve_and_write(&buf[..len])
            .expect("slab reserve");
        // Test uses 256-byte buffer, but clamp defensively per IndexEntry protocol
        let entry = IndexEntry::new(seq, handle, len.min(u32::MAX as usize) as u32);
        ring.push(entry);
    }

    // take() pumps ring → cache (dedup rejects duplicates), then takes from cache
    let mut received = Vec::new();
    while let Ok(Some(msg)) = reader.take() {
        received.push(msg);
    }

    assert_eq!(
        received.len(),
        3,
        "Should get exactly 3 messages, not 6 (dedup should reject replay duplicates)"
    );
    assert_eq!(received[0], Point { x: 1, y: 10 });
    assert_eq!(received[1], Point { x: 2, y: 20 });
    assert_eq!(received[2], Point { x: 3, y: 30 });
}
