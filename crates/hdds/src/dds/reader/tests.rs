// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use super::ReaderBuilder;
use crate::core::rt::{self, IndexEntry};
use crate::dds::QoS;
use crate::dds::DDS;

#[derive(Debug, Clone, Copy, PartialEq, crate::DDS)]
struct Point {
    x: i32,
    y: i32,
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
        let len = msg.encode_cdr2(&mut buf).expect("encode should succeed");
        let (handle, slab_buf) = slab_pool.reserve(len).expect("slab reserve");
        slab_buf[..len].copy_from_slice(&buf[..len]);
        slab_pool.commit(handle, len);
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
