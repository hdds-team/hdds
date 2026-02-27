// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Read Latency Benchmark
//!
//! Measures the latency of DataReader::take() and DataReader::read() with:
//! - Pre-filled cache (hot path - samples already in cache)
//! - Different payload sizes
//! - read() vs take() comparison
//!
//! This benchmark validates that take() has minimal overhead compared to
//! direct cache access.

#![allow(clippy::uninlined_format_args)]
#![allow(clippy::cast_precision_loss)]

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use hdds::{Participant, QoS, DDS};
use std::hint::black_box as bb;

/// Simple benchmark message
#[derive(Debug, Clone, DDS)]
struct BenchMessage {
    seq: u64,
    payload: Vec<u8>,
}

impl BenchMessage {
    fn new(seq: u64, size: usize) -> Self {
        Self {
            seq,
            payload: vec![0xCD; size],
        }
    }
}

/// Benchmark take() latency with pre-filled cache
fn bench_take_latency(c: &mut Criterion) {
    let mut group = c.benchmark_group("read_take_latency");

    let participant = Participant::builder("bench_read")
        .domain_id(99)
        .build()
        .expect("participant creation");

    let topic = participant
        .topic::<BenchMessage>("bench/read_latency")
        .expect("topic creation");

    let writer = topic
        .writer()
        .qos(QoS::best_effort().keep_last(100))
        .build()
        .expect("writer creation");

    let reader = topic
        .reader()
        .qos(QoS::best_effort().keep_last(100))
        .build()
        .expect("reader creation");

    // Bind reader to writer for in-process communication
    reader.bind_to_writer(writer.merger());

    // Pre-fill cache with 10 samples
    for i in 0..10 {
        let msg = BenchMessage::new(i, 256);
        writer.write(&msg).expect("write should succeed");
    }

    // Give time for samples to propagate
    std::thread::sleep(std::time::Duration::from_millis(10));

    group.bench_function("take_single_256b", |b| {
        b.iter(|| {
            // Take one sample
            let sample = reader.take().expect("take should succeed");
            bb(sample);

            // Refill for next iteration
            let msg = BenchMessage::new(100, 256);
            writer.write(&msg).expect("write should succeed");
            std::thread::sleep(std::time::Duration::from_micros(100));
        });
    });

    group.finish();
}

/// Benchmark read() vs take() comparison
fn bench_read_vs_take(c: &mut Criterion) {
    let mut group = c.benchmark_group("read_vs_take");

    let participant = Participant::builder("bench_read_vs_take")
        .domain_id(99)
        .build()
        .expect("participant creation");

    let topic = participant
        .topic::<BenchMessage>("bench/comparison")
        .expect("topic creation");

    let writer = topic
        .writer()
        .qos(QoS::best_effort().keep_last(100))
        .build()
        .expect("writer creation");

    let reader = topic
        .reader()
        .qos(QoS::best_effort().keep_last(100))
        .build()
        .expect("reader creation");

    reader.bind_to_writer(writer.merger());

    // Pre-fill cache with samples
    for i in 0..50 {
        let msg = BenchMessage::new(i, 256);
        writer.write(&msg).expect("write should succeed");
    }

    std::thread::sleep(std::time::Duration::from_millis(10));

    group.bench_function("read_nondestructive", |b| {
        b.iter(|| {
            let sample = reader.read().expect("read should succeed");
            bb(sample);
        });
    });

    group.bench_function("take_destructive", |b| {
        b.iter(|| {
            let sample = reader.take().expect("take should succeed");
            bb(sample);

            // Refill for next iteration
            let msg = BenchMessage::new(42, 256);
            writer.write(&msg).expect("write should succeed");
            std::thread::sleep(std::time::Duration::from_micros(100));
        });
    });

    group.finish();
}

/// Benchmark take() with different payload sizes
fn bench_take_payload_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("read_take_by_size");

    let participant = Participant::builder("bench_take_sizes")
        .domain_id(99)
        .build()
        .expect("participant creation");

    for size in [64, 256, 1024, 4096] {
        let topic = participant
            .topic::<BenchMessage>(&format!("bench/take_{}", size))
            .expect("topic creation");

        let writer = topic
            .writer()
            .qos(QoS::best_effort().keep_last(10))
            .build()
            .expect("writer creation");

        let reader = topic
            .reader()
            .qos(QoS::best_effort().keep_last(10))
            .build()
            .expect("reader creation");

        reader.bind_to_writer(writer.merger());

        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            b.iter(|| {
                // Write sample
                let msg = BenchMessage::new(42, size);
                writer.write(&msg).expect("write should succeed");
                std::thread::sleep(std::time::Duration::from_micros(50));

                // Take sample
                let sample = reader.take().expect("take should succeed");
                bb(sample);
            });
        });
    }

    group.finish();
}

criterion_group!(
    read_benches,
    bench_take_latency,
    bench_read_vs_take,
    bench_take_payload_sizes
);
criterion_main!(read_benches);
