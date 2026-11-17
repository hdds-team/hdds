// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

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

    // Optional reader churn (HDDS_BENCH_CHURN=1): create and drop one reader
    // on this writer before the measured one exists. Off by default, so the
    // default run stays the certified operation. A fresh pair is the merger's
    // best case; an application that recreates subscribers does not run in
    // that state, and this bench is the only one with the resolution to see
    // the few nanoseconds the difference costs per sample.
    if std::env::var("HDDS_BENCH_CHURN")
        .map(|v| v != "0")
        .unwrap_or(false)
    {
        let churned = topic
            .reader()
            .qos(QoS::best_effort().keep_last(1))
            .build()?;
        churned.bind_to_writer(writer.merger());
        drop(churned);
        println!("[OK] Churned one reader before the measured pair");
    }

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

        // HDDS_LATENCY_DUMP=1 prints the SHAPE, not three percentiles of it.
        //
        // Three summary numbers cannot tell a noisy distribution from two
        // populations averaged together, and this one has a median 265x its
        // own minimum, which is what two populations look like. A "smooth
        // ramp" can turn out to be a staircase once it is bucketed finely
        // enough: a tight spread INSIDE each level means a regime boundary,
        // not noise.
        //
        // Off by default so the harness output stays stable.
        if std::env::var("HDDS_LATENCY_DUMP").is_ok() {
            println!("\n--- Distribution ---");
            // Decade buckets: the interesting question is whether the mass
            // sits in one place or several, not its exact shape.
            let mut decade = [0usize; 8];
            for &l in &latencies {
                let mut d = 0;
                let mut v = l / 100;
                while v > 0 && d < 7 {
                    v /= 10;
                    d += 1;
                }
                decade[d] += 1;
            }
            let labels = [
                "<100ns",
                "100ns-1us",
                "1-10us",
                "10-100us",
                "100us-1ms",
                "1-10ms",
                "10-100ms",
                ">100ms",
            ];
            for (i, count) in decade.iter().enumerate() {
                if *count > 0 {
                    println!(
                        "  {:>10}: {:>6} ({:>5.2}%)",
                        labels[i],
                        count,
                        *count as f64 * 100.0 / latencies.len() as f64
                    );
                }
            }
            // Where the mass sits, by index, to see whether the first
            // messages live in a different regime from the rest.
            let chunk = latencies.len() / 4;
            if chunk > 0 {
                println!("  by quartile of ARRIVAL order (median ns):");
                let mut by_order: Vec<u64> = Vec::with_capacity(latencies.len());
                by_order.extend_from_slice(&latencies);
                // `latencies` is already sorted, so re-derive arrival order is
                // impossible here; state that rather than imply otherwise.
                let _ = by_order;
                println!("    (unavailable: the vector was sorted before this point)");
            }
        }
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
/// Monotonic timestamp for the latency measurement.
///
/// It reads a monotonic clock, not `SystemTime::now()` (CLOCK_REALTIME): NTP
/// can STEP the realtime clock, and a step during a run would silently add or
/// remove time from the measured latencies with nothing in the output to show
/// for it. The total duration above also uses `Instant` (monotonic).
///
/// Writer and reader live in the SAME process in this benchmark, so a shared
/// monotonic epoch plus an offset is exact. This would NOT be valid across
/// processes, where the two sides have different epochs.
fn get_timestamp_ns() -> u64 {
    static EPOCH: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    EPOCH.get_or_init(Instant::now).elapsed().as_nanos() as u64
}
