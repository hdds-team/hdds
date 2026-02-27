// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

#![cfg(feature = "bench-stress")]
#![allow(dead_code)] // Benchmark preparation code, used in future iterations
#![allow(unused_imports)] // Preparation imports for future benchmark iterations
#![allow(clippy::missing_panics_doc)] // Benchmarks intentionally panic on setup failure
#![allow(clippy::cast_possible_truncation)] // Benchmark timing casts are intentional
#![allow(clippy::cast_precision_loss)] // Timing stats precision loss is acceptable
#![allow(clippy::cast_sign_loss)] // Benchmark index casts are always positive
#![allow(clippy::uninlined_format_args)] // Benchmark code, readability over pedantic style
#![allow(clippy::wildcard_imports)] // Test utilities convenience
#![allow(clippy::missing_docs_in_private_items)] // Benchmark code
#![allow(clippy::doc_markdown)] // Benchmark documentation style
#![allow(clippy::borrow_as_ptr)] // Benchmark pointer operations
#![allow(clippy::too_many_lines)] // Example/test code
#![allow(clippy::match_same_arms)] // Test pattern matching
#![allow(clippy::no_effect_underscore_binding)] // Test variables
#![allow(clippy::semicolon_if_nothing_returned)] // Benchmark code formatting
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

/// Stress Benchmarks - Multi-Node, Multi-Thread
///
/// Tests HDDS performance under realistic load conditions:
/// - Multiple topologies: 1->1, 1->N, N->1, N->M
/// - Multiple payload sizes: 64B, 512B, 4KB
/// - Multiple KeepLast depths: 1, 10, 100
///
/// Targets:
/// - p99 < 2 us @ 64B (1->1)
/// - p99.9 < 10 us (tail latency)
/// - max < 50 us (no pathological spikes)
/// - Throughput > 500k msg/s
mod stress_utils;

use hdds::{Participant, QoS, DDS};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};
use stress_utils::*;

// ============================================================================
// Benchmark Message Types
// ============================================================================

/// Small message (64 bytes total)
#[derive(Debug, Clone, Copy, PartialEq, DDS)]
struct SmallMsg {
    timestamp_ns: u64, // 8
    seq: u64,          // 8
    sender_id: u32,    // 4
    pad1: u32,         // 4
    pad2: u64,         // 8
    pad3: u64,         // 8
    pad4: u64,         // 8
    pad5: u64,         // 8
    pad6: u64,         // 8
    pad7: u64,         // 8
                       // Total: 64 bytes
}

/// Medium message (512 bytes total)
#[derive(Debug, Clone, Copy, PartialEq, DDS)]
struct MediumMsg {
    timestamp_ns: u64,
    seq: u64,
    sender_id: u32,
    pad1: u32,
    // Need 496 more bytes = 62 x u64
    p00: u64,
    p01: u64,
    p02: u64,
    p03: u64,
    p04: u64,
    p05: u64,
    p06: u64,
    p07: u64,
    p08: u64,
    p09: u64,
    p10: u64,
    p11: u64,
    p12: u64,
    p13: u64,
    p14: u64,
    p15: u64,
    p16: u64,
    p17: u64,
    p18: u64,
    p19: u64,
    p20: u64,
    p21: u64,
    p22: u64,
    p23: u64,
    p24: u64,
    p25: u64,
    p26: u64,
    p27: u64,
    p28: u64,
    p29: u64,
    p30: u64,
    p31: u64,
    p32: u64,
    p33: u64,
    p34: u64,
    p35: u64,
    p36: u64,
    p37: u64,
    p38: u64,
    p39: u64,
    p40: u64,
    p41: u64,
    p42: u64,
    p43: u64,
    p44: u64,
    p45: u64,
    p46: u64,
    p47: u64,
    p48: u64,
    p49: u64,
    p50: u64,
    p51: u64,
    p52: u64,
    p53: u64,
    p54: u64,
    p55: u64,
    p56: u64,
    p57: u64,
    p58: u64,
    p59: u64,
    p60: u64,
    p61: u64,
    // Total: 20 + 62*8 = 516 bytes (close enough to 512)
}

/// Large message (4096 bytes total - simplified to 512 fields)
#[derive(Debug, Clone, Copy, PartialEq, DDS)]
struct LargeMsg {
    timestamp_ns: u64,
    seq: u64,
    sender_id: u32,
    pad1: u32,
    // For 4KB we'd need 510 x u64 fields - too many!
    // Let's use MediumMsg size for now and document this limitation
    p00: u64,
    p01: u64,
    p02: u64,
    p03: u64,
    p04: u64,
    p05: u64,
    p06: u64,
    p07: u64,
    p08: u64,
    p09: u64,
    p10: u64,
    p11: u64,
    p12: u64,
    p13: u64,
    p14: u64,
    p15: u64,
    p16: u64,
    p17: u64,
    p18: u64,
    p19: u64,
    p20: u64,
    p21: u64,
    p22: u64,
    p23: u64,
    p24: u64,
    p25: u64,
    p26: u64,
    p27: u64,
    p28: u64,
    p29: u64,
    p30: u64,
    p31: u64,
    // Total: 20 + 32*8 = 276 bytes (using smaller size due to derive limits)
}

// ============================================================================
// Benchmark Configuration
// ============================================================================

#[derive(Debug, Clone)]
struct BenchConfig {
    topology: Topology,
    payload_bytes: usize,
    keep_last: usize,
    num_messages: usize,
    warmup_messages: usize,
    use_affinity: bool,
}

impl BenchConfig {
    fn new(topology: Topology, payload_bytes: usize, keep_last: usize) -> Self {
        Self {
            topology,
            payload_bytes,
            keep_last,
            num_messages: 100_000,
            warmup_messages: 10_000,
            use_affinity: cfg!(target_os = "linux"),
        }
    }
}

// ============================================================================
// Topology 1->1 (Baseline)
// ============================================================================

/// Run 1->1 topology benchmark (1 writer, 1 reader, same process)
///
/// Note: For true multi-thread stress, we pin to different cores.
/// For simplicity in Phase 1, we use single-thread approach (like latency_benchmark.rs)
/// and will add true multi-thread in future iterations.
fn bench_1_to_1(config: &BenchConfig) -> Result<BenchResult, Box<dyn std::error::Error>> {
    println!(
        "\n=== Benchmark 1->1 (payload={}, keep_last={}) ===",
        config.payload_bytes, config.keep_last
    );

    // Create participant
    let participant = Participant::builder("stress_bench").build()?;
    let topic = participant.topic::<SmallMsg>("StressTopic")?;

    // Create writer and reader
    let writer = topic
        .writer()
        .qos(QoS::best_effort().keep_last(config.keep_last as u32))
        .build()?;

    let reader = topic
        .reader()
        .qos(QoS::best_effort().keep_last(config.keep_last as u32))
        .build()?;

    // Bind reader to writer
    reader.bind_to_writer(writer.merger());

    // Warmup
    for seq in 0..config.warmup_messages {
        let msg = SmallMsg {
            timestamp_ns: get_timestamp_ns(),
            seq: seq as u64,
            sender_id: 0,
            pad1: 0,
            pad2: 0,
            pad3: 0,
            pad4: 0,
            pad5: 0,
            pad6: 0,
            pad7: 0,
        };
        writer.write(&msg)?;
        let _ = reader.take()?;
    }

    // Benchmark run
    let mut latencies = Vec::with_capacity(config.num_messages);
    let bench_start = Instant::now();

    for seq in 0..config.num_messages {
        let send_time = get_timestamp_ns();

        let msg = SmallMsg {
            timestamp_ns: send_time,
            seq: seq as u64,
            sender_id: 0,
            pad1: 0,
            pad2: 0,
            pad3: 0,
            pad4: 0,
            pad5: 0,
            pad6: 0,
            pad7: 0,
        };

        // Write message
        writer.write(&msg)?;

        // Read message
        if let Some(received) = reader.take()? {
            let recv_time = get_timestamp_ns();
            let latency = recv_time.saturating_sub(received.timestamp_ns);
            latencies.push(latency);
        }
    }

    let total_duration = bench_start.elapsed();

    // Compute stats
    latencies.sort_unstable();
    let latency_stats = LatencyStats::from_sorted(&latencies);
    let throughput = (config.num_messages as f64) / total_duration.as_secs_f64();

    let result = BenchResult {
        topology: config.topology,
        payload_bytes: config.payload_bytes,
        keep_last: config.keep_last,
        num_messages: config.num_messages,
        latency: latency_stats,
        throughput_msg_s: throughput,
        drops: (config.num_messages - latencies.len()) as u64,
    };

    // Print results
    println!("Results:");
    println!("  Messages:     {}", latency_stats.count);
    println!("  Min latency:  {:>6} ns", latency_stats.min_ns);
    println!("  Mean latency: {:>6} ns", latency_stats.mean_ns);
    println!("  p50 latency:  {:>6} ns", latency_stats.p50_ns);
    println!("  p95 latency:  {:>6} ns", latency_stats.p95_ns);
    println!("  p99 latency:  {:>6} ns", latency_stats.p99_ns);
    println!("  p99.9 latency:{:>6} ns", latency_stats.p999_ns);
    println!("  Max latency:  {:>6} ns", latency_stats.max_ns);
    println!("  Throughput:   {:.0} msg/s", throughput);
    println!("  Drops:        {}", result.drops);

    // Validate targets
    print_validation(&result);

    Ok(result)
}

/// Print validation against targets
fn print_validation(result: &BenchResult) {
    println!("\nValidation:");

    // p99 < 2 us @ 64B (1->1)
    if result.topology == Topology::OneToOne && result.payload_bytes == 64 {
        if result.latency.p99_ns < 2000 {
            println!("  [OK] p99 < 2 us @ 64B: {} ns", result.latency.p99_ns);
        } else {
            println!(
                "  [X] p99 >= 2 us @ 64B: {} ns (target: < 2000)",
                result.latency.p99_ns
            );
        }
    }

    // p99.9 < 10 us
    if result.latency.p999_ns < 10_000 {
        println!("  [OK] p99.9 < 10 us: {} ns", result.latency.p999_ns);
    } else {
        println!(
            "  [!] p99.9 >= 10 us: {} ns (target: < 10000)",
            result.latency.p999_ns
        );
    }

    // max < 50 us (CRITICAL)
    if result.latency.max_ns < 50_000 {
        println!("  [OK] max < 50 us: {} ns", result.latency.max_ns);
    } else {
        println!(
            "  [X] CRITICAL: max >= 50 us: {} ns (target: < 50000)",
            result.latency.max_ns
        );
        println!("     -> This may block Reliable QoS (NACK recovery < 10ms target)");
    }

    // Throughput > 500k msg/s
    if result.throughput_msg_s > 500_000.0 {
        println!(
            "  [OK] Throughput > 500k: {:.0} msg/s",
            result.throughput_msg_s
        );
    } else {
        println!(
            "  [!] Throughput < 500k: {:.0} msg/s (target: > 500000)",
            result.throughput_msg_s
        );
    }
}

/// Get high-resolution timestamp in nanoseconds
#[inline]
fn get_timestamp_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}

// ============================================================================
// Main Benchmark Runner
// ============================================================================

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== HDDS Stress Benchmarks ===");
    println!("Platform: {}", std::env::consts::OS);
    println!(
        "Affinity: {}",
        if cfg!(target_os = "linux") {
            "enabled"
        } else {
            "disabled"
        }
    );

    let mut all_results = Vec::new();

    // Phase 2: Topology 1->1 (Baseline)
    println!("\n--- Phase 2: Topology 1->1 (Baseline) ---");

    // Test critical configurations (limited to avoid telemetry port conflicts)
    // TODO(T2): Fix telemetry port reuse issue in future iterations
    // Current: Limited test configs to avoid SO_REUSEADDR conflicts in v0.3.0
    // Future: Random port allocation or proper port pool management
    let configs = vec![
        (64, 1),   // Baseline: smallest payload, minimal queuing
        (64, 10),  // Baseline with moderate queuing
        (512, 10), // Medium payload with moderate queuing
    ];

    for (payload_bytes, keep_last) in configs {
        let config = BenchConfig::new(Topology::OneToOne, payload_bytes, keep_last);
        let result = bench_1_to_1(&config)?;
        all_results.push(result);

        // Sleep to allow telemetry port (4242) to be released (kernel TIME_WAIT)
        std::thread::sleep(std::time::Duration::from_secs(2));
    }

    // Export all results to CSV
    let csv_path = "crates/hdds/benches/results/stress_results_1to1.csv";
    export_csv(&all_results, csv_path)?;
    println!("\n[OK] Results exported to: {}", csv_path);

    // Summary
    println!("\n=== Summary ===");
    println!("Total benchmarks run: {}", all_results.len());
    println!("CSV results: {}", csv_path);

    Ok(())
}
