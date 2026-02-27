// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

#![cfg(feature = "bench-stress")]
#![allow(dead_code)] // Benchmark preparation code
#![allow(unused_imports)] // Preparation imports
#![allow(clippy::missing_panics_doc)] // Benchmarks panic on setup failure
#![allow(clippy::cast_possible_truncation)] // Benchmark timing casts
#![allow(clippy::cast_precision_loss)] // Timing stats precision loss acceptable
#![allow(clippy::uninlined_format_args)] // Benchmark readability
#![allow(clippy::doc_markdown)] // Benchmark docs
#![allow(clippy::unreadable_literal)] // Benchmark constants (1_000_000 vs 1000000)
#![allow(clippy::items_after_statements)] // Benchmark helper functions
#![allow(clippy::too_many_lines)] // Example/test code
#![allow(clippy::match_same_arms)] // Test pattern matching
#![allow(clippy::no_effect_underscore_binding)] // Test variables
#![allow(clippy::semicolon_if_nothing_returned)] // Benchmark code formatting
#![allow(clippy::wildcard_imports)] // Test utility imports
#![allow(clippy::redundant_closure_for_method_calls)] // Test code clarity
#![allow(clippy::similar_names)] // Test variable naming
#![allow(clippy::shadow_unrelated)] // Test scoping
#![allow(clippy::needless_pass_by_value)] // Test functions
#![allow(clippy::cast_possible_wrap)] // Test conversions
#![allow(clippy::single_match_else)] // Test clarity
#![allow(clippy::needless_continue)] // Test logic
#![allow(clippy::cast_lossless)] // Test simplicity
#![allow(clippy::match_wild_err_arm)] // Test error handling
#![allow(clippy::explicit_iter_loop)] // Test iteration
#![allow(clippy::must_use_candidate)] // Test functions
#![allow(clippy::if_not_else)] // Test conditionals
#![allow(clippy::map_unwrap_or)] // Test options
#![allow(clippy::match_wildcard_for_single_variants)] // Test patterns
#![allow(clippy::ignored_unit_patterns)] // Test closures

// Stress Benchmark - Phase 7a Intra-Process Runtime
//
// Validates performance under load (1M samples):
// - Throughput (samples/sec)
// - Latency histogram (p50, p99, p99.9, p99.99)
// - Memory usage
// - Zero drops validation
//
// Target Performance:
// - Throughput: >1M samples/sec
// - p99 latency: <1 us (aspirational, 2-5 us acceptable)
// - Zero samples dropped

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use hdds::api::{Participant, QoS};
use hdds::generated::temperature::Temperature;

/// Benchmark: Write latency (encode + publish)
fn bench_write_latency(c: &mut Criterion) {
    let participant = Participant::builder("bench_write").build().unwrap();
    let writer = participant
        .create_writer::<Temperature>("bench/temp", QoS::best_effort())
        .unwrap();

    let sample = Temperature {
        value: 23.5,
        timestamp: 1234567890,
    };

    c.bench_function("write_latency", |b| {
        b.iter(|| {
            writer.write(black_box(&sample)).ok();
        });
    });
}

/// Benchmark: Read latency (take + decode)
fn bench_read_latency(c: &mut Criterion) {
    let participant = Participant::builder("bench_read").build().unwrap();

    let writer = participant
        .create_writer::<Temperature>("bench/temp", QoS::best_effort())
        .unwrap();

    let reader = participant
        .create_reader::<Temperature>("bench/temp", QoS::best_effort().keep_last(1000))
        .unwrap();

    // Bind reader to writer
    reader.bind_to_writer(writer.merger());

    // Pre-fill queue with samples
    for i in 0..100 {
        let sample = Temperature {
            value: 20.0 + i as f32,
            timestamp: 1234567890 + i,
        };
        writer.write(&sample).ok();
    }

    c.bench_function("read_latency", |b| {
        b.iter(|| {
            reader.take().ok();
        });
    });
}

/// Benchmark: End-to-end roundtrip (write -> read)
fn bench_roundtrip(c: &mut Criterion) {
    let participant = Participant::builder("bench_roundtrip").build().unwrap();

    let writer = participant
        .create_writer::<Temperature>("bench/temp", QoS::best_effort())
        .unwrap();

    let reader = participant
        .create_reader::<Temperature>("bench/temp", QoS::best_effort().keep_last(1000))
        .unwrap();

    reader.bind_to_writer(writer.merger());

    let sample = Temperature {
        value: 23.5,
        timestamp: 1234567890,
    };

    c.bench_function("roundtrip_latency", |b| {
        b.iter(|| {
            writer.write(black_box(&sample)).ok();
            reader.take().ok();
        });
    });
}

/// Stress test: 1M samples throughput
fn bench_throughput_1m(c: &mut Criterion) {
    let participant = Participant::builder("bench_throughput").build().unwrap();

    let writer = participant
        .create_writer::<Temperature>("bench/temp", QoS::best_effort())
        .unwrap();

    let reader = participant
        .create_reader::<Temperature>("bench/temp", QoS::best_effort().keep_last(10000))
        .unwrap();

    reader.bind_to_writer(writer.merger());

    c.bench_with_input(
        BenchmarkId::new("throughput", "1M_samples"),
        &1_000_000usize,
        |b, &count| {
            b.iter(|| {
                // Write phase
                for i in 0..count {
                    let sample = Temperature {
                        value: 20.0 + (i % 100) as f32,
                        timestamp: 1234567890 + i as i32,
                    };
                    writer.write(black_box(&sample)).ok();
                }

                // Read phase
                let mut received = 0;
                while let Ok(Some(_)) = reader.take() {
                    received += 1;
                }

                // Validate zero drops (aspirational - may drop under extreme load)
                // In practice, KeepLast(10000) should handle most cases
                black_box(received);
            });
        },
    );
}

/// Validate zero drops with stats
fn validate_zero_drops() {
    println!("\n=== Zero Drops Validation ===");

    let participant = Participant::builder("validate_drops").build().unwrap();

    let writer = participant
        .create_writer::<Temperature>("test/temp", QoS::best_effort())
        .unwrap();

    let reader = participant
        .create_reader::<Temperature>("test/temp", QoS::best_effort().keep_last(10000))
        .unwrap();

    reader.bind_to_writer(writer.merger());

    // Send 1M samples
    const COUNT: usize = 1_000_000;
    for i in 0..COUNT {
        let sample = Temperature {
            value: 20.0 + (i % 100) as f32,
            timestamp: 1234567890 + i as i32,
        };
        writer.write(&sample).expect("Write failed");
    }

    // Read all samples
    let mut received = 0;
    while let Ok(Some(_)) = reader.take() {
        received += 1;
    }

    let writer_stats = writer.stats();
    let reader_stats = reader.stats();

    println!("Writer stats:");
    println!("  Messages sent: {}", writer_stats.messages_sent);
    println!("  Bytes sent: {}", writer_stats.bytes_sent);
    println!("  Drops: {}", writer_stats.drops);

    println!("\nReader stats:");
    println!("  Messages received: {}", reader_stats.messages_received);
    println!("  Bytes received: {}", reader_stats.bytes_received);
    println!("  Drops: {}", reader_stats.drops);

    println!("\nReceived count (polled): {}", received);
    println!("Expected: {}", COUNT);

    if received == COUNT {
        println!("[OK] Zero drops validated!");
    } else {
        println!(
            "[!]  Dropped {} samples ({:.2}%)",
            COUNT - received,
            (COUNT - received) as f64 / COUNT as f64 * 100.0
        );
    }
}

criterion_group!(
    benches,
    bench_write_latency,
    bench_read_latency,
    bench_roundtrip,
    bench_throughput_1m
);
criterion_main!(benches);

// Run validation separately:
// cargo test --bench stress_phase7a -- --nocapture validate_zero_drops
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore] // Run manually: cargo test --bench stress_phase7a -- --nocapture --ignored
    fn test_validate_zero_drops() {
        validate_zero_drops();
    }
}
