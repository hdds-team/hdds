// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

#![allow(clippy::uninlined_format_args)] // Test/bench code readability over pedantic
#![allow(clippy::cast_precision_loss)] // Stats/metrics need this
#![allow(clippy::cast_sign_loss)] // Test data conversions
#![allow(clippy::cast_possible_truncation)] // Test parameters
#![allow(clippy::float_cmp)] // Test assertions with constants
#![allow(clippy::unreadable_literal)] // Large test constants
#![allow(clippy::doc_markdown)] // Test documentation
#![allow(clippy::missing_panics_doc)] // Tests/examples panic on failure
#![allow(clippy::missing_errors_doc)] // Test documentation
#![allow(clippy::items_after_statements)] // Test helpers
#![allow(clippy::module_name_repetitions)] // Test modules
#![allow(clippy::too_many_lines)] // Example/test code
#![allow(clippy::match_same_arms)] // Test pattern matching
#![allow(clippy::no_effect_underscore_binding)] // Test variables
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

/// Latency Benchmark Example for HDDS
///
/// Demonstrates:
/// - Measuring end-to-end latency
/// - High-frequency publishing
/// - Performance measurement and statistics
/// - Zero-copy message passing
use hdds::{Participant, QoS, DDS};
use std::time::Instant;

// Simple message type for benchmarking
#[derive(Debug, Clone, Copy, PartialEq, DDS)]
struct BenchMessage {
    seq: u64,
    timestamp_ns: u64,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== HDDS Latency Benchmark ===\n");

    // Configuration
    const NUM_MESSAGES: usize = 10_000;
    const WARMUP_MESSAGES: usize = 1_000;

    // Create participant
    let participant = Participant::builder("latency_benchmark").build()?;
    println!("[OK] Created participant");

    // Create topic
    let topic = participant.topic::<BenchMessage>("BenchTopic")?;
    println!("[OK] Created topic");

    // Create writer and reader with KeepLast(1) for minimal queuing
    let writer = topic
        .writer()
        .qos(QoS::best_effort().keep_last(1))
        .build()?;

    let reader = topic
        .reader()
        .qos(QoS::best_effort().keep_last(1))
        .build()?;

    // Bind reader to writer
    reader.bind_to_writer(writer.merger());
    println!("[OK] Created writer and reader with KeepLast(1)");

    println!("\n--- Warmup ({} messages) ---", WARMUP_MESSAGES);

    // Warmup run to stabilize performance
    for seq in 0..WARMUP_MESSAGES as u64 {
        let msg = BenchMessage {
            seq,
            timestamp_ns: get_timestamp_ns(),
        };
        writer.write(&msg)?;
        let _ = reader.take()?;
    }
    println!("[OK] Warmup complete");

    println!("\n--- Benchmark ({} messages) ---", NUM_MESSAGES);

    let mut latencies = Vec::with_capacity(NUM_MESSAGES);
    let bench_start = Instant::now();

    // Benchmark loop
    for seq in 0..NUM_MESSAGES as u64 {
        let send_time = get_timestamp_ns();

        let msg = BenchMessage {
            seq,
            timestamp_ns: send_time,
        };

        // Write message
        writer.write(&msg)?;

        // Read message
        if let Some(received) = reader.take()? {
            let recv_time = get_timestamp_ns();
            let latency_ns = recv_time.saturating_sub(received.timestamp_ns);
            latencies.push(latency_ns);
        }
    }

    let total_duration = bench_start.elapsed();
    println!("[OK] Benchmark complete in {:?}", total_duration);

    // Calculate statistics
    println!("\n--- Latency Statistics ---");

    if !latencies.is_empty() {
        latencies.sort_unstable();

        let min = latencies[0];
        let max = latencies[latencies.len() - 1];
        let mean = latencies.iter().sum::<u64>() / latencies.len() as u64;
        let p50 = latencies[latencies.len() / 2];
        let p95 = latencies[latencies.len() * 95 / 100];
        let p99 = latencies[latencies.len() * 99 / 100];

        println!("Messages:     {}", latencies.len());
        println!("Min latency:  {:>6} ns", min);
        println!("Mean latency: {:>6} ns", mean);
        println!("p50 latency:  {:>6} ns", p50);
        println!("p95 latency:  {:>6} ns", p95);
        println!("p99 latency:  {:>6} ns", p99);
        println!("Max latency:  {:>6} ns", max);

        let throughput = (NUM_MESSAGES as f64 / total_duration.as_secs_f64()) / 1000.0;
        println!("\nThroughput:   {:.1} k msg/s", throughput);

        // Performance assessment
        println!("\n--- Performance Assessment ---");
        if p99 < 1000 {
            println!("[OK] EXCELLENT: p99 < 1 us (target achieved!)");
        } else if p99 < 2000 {
            println!("[OK] GOOD: p99 < 2 us");
        } else if p99 < 5000 {
            println!("[!] FAIR: p99 < 5 us");
        } else {
            println!("[X] NEEDS IMPROVEMENT: p99 >= 5 us");
        }

        if throughput > 50.0 {
            println!("[OK] EXCELLENT: Throughput > 50k msg/s");
        } else if throughput > 25.0 {
            println!("[OK] GOOD: Throughput > 25k msg/s");
        } else {
            println!("[!] FAIR: Throughput < 25k msg/s");
        }
    } else {
        println!("[X] No messages received");
    }

    Ok(())
}

// Get high-resolution timestamp in nanoseconds
#[inline]
fn get_timestamp_ns() -> u64 {
    // Use a simple approach for the example
    // In production, this would use crate::core::time_utils::current_time_ns()
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}
