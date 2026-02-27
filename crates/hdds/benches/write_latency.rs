// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Write Latency Benchmark
//!
//! Measures the latency of DataWriter::write() with different:
//! - Payload sizes (64B, 1KB, 4KB, 64KB)
//! - QoS policies (best-effort vs reliable)
//! - History depth (keep-last 1 vs 10)
//!
//! This benchmark isolates the writer-side overhead without network I/O.

#![allow(clippy::uninlined_format_args)]
#![allow(clippy::cast_precision_loss)]

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use hdds::{Participant, QoS, DDS};
use std::hint::black_box as bb;

/// Simple benchmark message with configurable payload
#[derive(Debug, Clone, DDS)]
struct BenchMessage {
    seq: u64,
    timestamp_ns: u64,
    payload: Vec<u8>,
}

impl BenchMessage {
    fn new(seq: u64, size: usize) -> Self {
        Self {
            seq,
            timestamp_ns: 0,
            payload: vec![0xAB; size],
        }
    }
}

/// Benchmark write latency with different payload sizes
fn bench_write_payload_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("write_latency_by_size");

    // Create participant and writer once
    let participant = Participant::builder("bench_write")
        .domain_id(99)
        .build()
        .expect("participant creation");

    let topic = participant
        .topic::<BenchMessage>("bench/latency")
        .expect("topic creation");

    let writer = topic
        .writer()
        .qos(QoS::best_effort().keep_last(1))
        .build()
        .expect("writer creation");

    // Benchmark different payload sizes
    for size in [64, 256, 1024, 4096, 16384, 65536] {
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            let msg = BenchMessage::new(42, size);
            b.iter(|| {
                writer.write(bb(&msg)).expect("write should succeed");
            });
        });
    }

    group.finish();
}

/// Benchmark write latency with best-effort vs reliable QoS
fn bench_write_qos_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("write_latency_by_qos");

    let participant = Participant::builder("bench_write_qos")
        .domain_id(99)
        .build()
        .expect("participant creation");

    // Best-effort writer
    let topic_be = participant
        .topic::<BenchMessage>("bench/best_effort")
        .expect("topic creation");

    let writer_be = topic_be
        .writer()
        .qos(QoS::best_effort().keep_last(1))
        .build()
        .expect("writer creation");

    // Reliable writer
    let topic_rel = participant
        .topic::<BenchMessage>("bench/reliable")
        .expect("topic creation");

    let writer_rel = topic_rel
        .writer()
        .qos(QoS::reliable().keep_last(1))
        .build()
        .expect("writer creation");

    let msg = BenchMessage::new(42, 256);

    group.bench_function("best_effort", |b| {
        b.iter(|| {
            writer_be.write(bb(&msg)).expect("write should succeed");
        });
    });

    group.bench_function("reliable", |b| {
        b.iter(|| {
            writer_rel.write(bb(&msg)).expect("write should succeed");
        });
    });

    group.finish();
}

/// Benchmark write latency with different history depths
fn bench_write_history_depth(c: &mut Criterion) {
    let mut group = c.benchmark_group("write_latency_by_history");

    let participant = Participant::builder("bench_write_history")
        .domain_id(99)
        .build()
        .expect("participant creation");

    for depth in [1, 10, 100] {
        let topic = participant
            .topic::<BenchMessage>(&format!("bench/history_{}", depth))
            .expect("topic creation");

        let writer = topic
            .writer()
            .qos(QoS::best_effort().keep_last(depth))
            .build()
            .expect("writer creation");

        let msg = BenchMessage::new(42, 256);

        group.bench_with_input(BenchmarkId::from_parameter(depth), &depth, |b, _depth| {
            b.iter(|| {
                writer.write(bb(&msg)).expect("write should succeed");
            });
        });
    }

    group.finish();
}

criterion_group!(
    write_benches,
    bench_write_payload_sizes,
    bench_write_qos_comparison,
    bench_write_history_depth
);
criterion_main!(write_benches);
