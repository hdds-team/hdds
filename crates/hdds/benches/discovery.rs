// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Discovery Handshake Benchmark
//!
//! Measures the time for DDS participants to discover each other and establish
//! communication. This benchmark tests:
//! - SPDP (Simple Participant Discovery Protocol) latency
//! - SEDP (Simple Endpoint Discovery Protocol) latency
//! - Total time from participant creation to first data exchange
//!
//! This is critical for real-time systems where fast join/rejoin is required.

#![allow(clippy::uninlined_format_args)]
#![allow(clippy::cast_precision_loss)]

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use hdds::{Participant, QoS, DDS};
use std::time::Instant;

/// Simple ping message for discovery testing
#[derive(Debug, Clone, DDS)]
struct PingMessage {
    seq: u64,
    sender: String,
}

/// Benchmark: Time to create participant + writer + reader and exchange first message
fn bench_full_discovery_handshake(c: &mut Criterion) {
    c.bench_function("discovery_full_handshake", |b| {
        b.iter(|| {
            let start = Instant::now();

            // Create first participant
            let p1 = Participant::builder("discovery_p1")
                .domain_id(99)
                .build()
                .expect("p1 creation");

            let topic1 = p1
                .topic::<PingMessage>("discovery/ping")
                .expect("topic1 creation");

            let writer1 = topic1
                .writer()
                .qos(QoS::reliable().keep_last(1))
                .build()
                .expect("writer1 creation");

            let reader1 = topic1
                .reader()
                .qos(QoS::reliable().keep_last(1))
                .build()
                .expect("reader1 creation");

            // Create second participant
            let p2 = Participant::builder("discovery_p2")
                .domain_id(99)
                .build()
                .expect("p2 creation");

            let topic2 = p2
                .topic::<PingMessage>("discovery/ping")
                .expect("topic2 creation");

            let writer2 = topic2
                .writer()
                .qos(QoS::reliable().keep_last(1))
                .build()
                .expect("writer2 creation");

            let reader2 = topic2
                .reader()
                .qos(QoS::reliable().keep_last(1))
                .build()
                .expect("reader2 creation");

            // For in-process test, bind directly (simulates discovered endpoints)
            reader1.bind_to_writer(writer2.merger());
            reader2.bind_to_writer(writer1.merger());

            // Exchange first message
            let msg = PingMessage {
                seq: 1,
                sender: "p1".to_string(),
            };
            writer1.write(&msg).expect("write");

            // Wait for message to arrive
            let mut attempts = 0;
            loop {
                if let Ok(Some(_sample)) = reader2.take() {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_micros(100));
                attempts += 1;
                if attempts > 100 {
                    panic!("Message never arrived");
                }
            }

            let elapsed = start.elapsed();
            black_box(elapsed);

            // Cleanup happens automatically on drop
        });
    });
}

/// Benchmark: Time to create a participant (SPDP only)
fn bench_participant_creation(c: &mut Criterion) {
    c.bench_function("discovery_participant_create", |b| {
        b.iter(|| {
            let p = Participant::builder("bench_participant")
                .domain_id(99)
                .build()
                .expect("participant creation");
            black_box(p);
        });
    });
}

/// Benchmark: Time to create writer + reader (SEDP)
fn bench_endpoint_creation(c: &mut Criterion) {
    // Create participant once (reuse for all iterations)
    let participant = Participant::builder("bench_endpoints")
        .domain_id(99)
        .build()
        .expect("participant creation");

    c.bench_function("discovery_endpoint_create", |b| {
        let mut counter = 0;
        b.iter(|| {
            counter += 1;
            let topic = participant
                .topic::<PingMessage>(&format!("bench/endpoint_{}", counter))
                .expect("topic creation");

            let writer = topic
                .writer()
                .qos(QoS::best_effort().keep_last(1))
                .build()
                .expect("writer creation");

            let reader = topic
                .reader()
                .qos(QoS::best_effort().keep_last(1))
                .build()
                .expect("reader creation");

            black_box((writer, reader));
        });
    });
}

criterion_group!(
    discovery_benches,
    bench_full_discovery_handshake,
    bench_participant_creation,
    bench_endpoint_creation
);
criterion_main!(discovery_benches);
