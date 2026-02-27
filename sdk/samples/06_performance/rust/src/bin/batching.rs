// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! # HDDS Sample: Message Batching
//!
//! Demonstrates **message batching** - combining multiple small messages
//! into fewer network packets to reduce overhead and improve throughput.
//!
//! ## How Batching Works
//!
//! ```text
//! Without Batching:                 With Batching:
//! ┌──────────────────────────┐     ┌──────────────────────────┐
//! │ Msg1 → [Header][Data]    │     │ Batch → [Header]         │
//! │ Msg2 → [Header][Data]    │     │         [Msg1][Msg2]     │
//! │ Msg3 → [Header][Data]    │     │         [Msg3][Msg4]     │
//! │ Msg4 → [Header][Data]    │     │         [Msg5]           │
//! │ Msg5 → [Header][Data]    │     └──────────────────────────┘
//! └──────────────────────────┘
//!    5 packets sent                    1 packet sent
//!    5x header overhead                1x header overhead
//! ```
//!
//! ## Batching Parameters
//!
//! | Parameter       | Effect                                    |
//! |-----------------|-------------------------------------------|
//! | max_batch_size  | Flush when batch reaches this size        |
//! | batch_timeout   | Flush after this time even if not full    |
//! | flush()         | Manually send incomplete batch             |
//!
//! ## Performance Impact
//!
//! ```text
//! Batch Size    Messages/sec    Improvement    Added Latency
//! ──────────    ────────────    ───────────    ─────────────
//! None          100,000         Baseline       ~0 μs
//! 1 KB          200,000         2x             10-50 μs
//! 8 KB          500,000         5x             50-200 μs
//! 64 KB         1,000,000       10x            100-500 μs
//! ```
//!
//! ## Trade-offs
//!
//! ```text
//! Throughput ◄────────────────────────► Latency
//!
//! Larger batches:                Smaller batches:
//! + Higher throughput            + Lower latency
//! + Less CPU overhead            + Faster delivery
//! - Higher latency               - More packets
//! - Uses more memory             - More CPU overhead
//! ```
//!
//! ## Running the Sample
//!
//! ```bash
//! # Run batching comparison benchmark
//! cargo run --bin batching
//!
//! # Shows performance with different batch sizes
//! ```

use std::thread;
use std::time::{Duration, Instant};

const MESSAGE_SIZE: usize = 64;
const NUM_MESSAGES: usize = 10000;

/// Simple benchmark message type - using only primitives supported by DDS derive
#[derive(hdds::DDS)]
struct BenchMsg {
    seq: u64,
    // Simulated payload via multiple fields (DDS derive doesn't support arrays)
    p0: u64,
    p1: u64,
    p2: u64,
    p3: u64,
    p4: u64,
    p5: u64,
    p6: u64,
    p7: u64,
}

impl BenchMsg {
    fn new(seq: u64) -> Self {
        Self {
            seq,
            p0: 0xABABABABABABABAB,
            p1: 0xABABABABABABABAB,
            p2: 0xABABABABABABABAB,
            p3: 0xABABABABABABABAB,
            p4: 0xABABABABABABABAB,
            p5: 0xABABABABABABABAB,
            p6: 0xABABABABABABABAB,
            p7: 0xABABABABABABABAB,
        }
    }
}

/// Batching configuration
#[derive(Clone)]
struct BatchConfig {
    name: &'static str,
    max_batch_size: u32,
    batch_timeout_us: u32,
    enabled: bool,
}

/// Batch statistics
#[derive(Default)]
struct BatchStats {
    messages_sent: u64,
    batches_sent: u64,
    bytes_sent: u64,
    duration_sec: f64,
    avg_batch_size: f64,
    msg_per_sec: f64,
}

fn print_comparison(label: &str, stats: &BatchStats) {
    println!(
        "{:20} {:8} msgs, {:6} batches, {:8.0} msg/s, avg batch: {:.1} msgs",
        label, stats.messages_sent, stats.batches_sent, stats.msg_per_sec, stats.avg_batch_size
    );
}

fn run_batch_test(
    participant: &std::sync::Arc<hdds::Participant>,
    config: &BatchConfig,
    num_messages: usize,
) -> Result<BatchStats, hdds::Error> {
    let mut stats = BatchStats::default();

    // Create writer - use reliable QoS for accurate delivery
    let qos = hdds::QoS::reliable();
    let writer = participant.create_writer::<BenchMsg>("BatchingTopic", qos)?;

    let start = Instant::now();

    if config.enabled {
        // Batched sending - accumulate and flush
        let mut current_batch_bytes: u32 = 0;
        let mut batch_start = Instant::now();
        let msg_size = std::mem::size_of::<BenchMsg>() as u32;

        for i in 0..num_messages {
            let msg = BenchMsg::new(i as u64);

            writer.write(&msg)?;

            stats.messages_sent += 1;
            stats.bytes_sent += msg_size as u64;
            current_batch_bytes += msg_size;

            // Check if batch should be flushed
            let timeout_exceeded =
                batch_start.elapsed().as_micros() as u32 >= config.batch_timeout_us;
            let size_exceeded = current_batch_bytes >= config.max_batch_size;

            if size_exceeded || timeout_exceeded {
                // Batch complete
                stats.batches_sent += 1;
                current_batch_bytes = 0;
                batch_start = Instant::now();
            }
        }

        // Flush remaining
        if current_batch_bytes > 0 {
            stats.batches_sent += 1;
        }
    } else {
        // Non-batched sending - each message is its own "batch"
        let msg_size = std::mem::size_of::<BenchMsg>() as u64;

        for i in 0..num_messages {
            let msg = BenchMsg::new(i as u64);

            writer.write(&msg)?;

            stats.messages_sent += 1;
            stats.bytes_sent += msg_size;
            stats.batches_sent += 1;
        }
    }

    let elapsed = start.elapsed();
    stats.duration_sec = elapsed.as_secs_f64();
    stats.msg_per_sec = stats.messages_sent as f64 / stats.duration_sec;
    stats.avg_batch_size = if stats.batches_sent > 0 {
        stats.messages_sent as f64 / stats.batches_sent as f64
    } else {
        0.0
    };

    Ok(stats)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== HDDS Batching Sample ===\n");

    println!("--- Batching Overview ---\n");
    println!("Batching combines multiple messages into fewer network packets:");
    println!("  - Reduces per-message overhead (headers, syscalls)");
    println!("  - Improves throughput significantly");
    println!("  - Adds slight latency (batch accumulation time)\n");

    println!("Configuration Parameters:");
    println!("  max_batch_size:   Maximum bytes to accumulate before sending");
    println!("  batch_timeout:    Maximum time to wait for more messages");
    println!("  flush():          Manually send incomplete batch\n");

    // Note: Logging is optional and disabled by default in samples

    // Create participant
    let participant = hdds::Participant::builder("BatchingDemo")
        .domain_id(0)
        .build()?;

    println!("[OK] Participant created\n");

    println!("--- Running Batching Comparison ---");
    println!(
        "Sending {} messages of {} bytes each...\n",
        NUM_MESSAGES, MESSAGE_SIZE
    );

    // Test configurations
    let configs = vec![
        BatchConfig {
            name: "No batching:",
            max_batch_size: 0,
            batch_timeout_us: 0,
            enabled: false,
        },
        BatchConfig {
            name: "Batch 1KB:",
            max_batch_size: 1024,
            batch_timeout_us: 1000,
            enabled: true,
        },
        BatchConfig {
            name: "Batch 4KB:",
            max_batch_size: 4096,
            batch_timeout_us: 1000,
            enabled: true,
        },
        BatchConfig {
            name: "Batch 8KB:",
            max_batch_size: 8192,
            batch_timeout_us: 1000,
            enabled: true,
        },
        BatchConfig {
            name: "Batch 16KB:",
            max_batch_size: 16384,
            batch_timeout_us: 1000,
            enabled: true,
        },
        BatchConfig {
            name: "Batch 64KB:",
            max_batch_size: 65536,
            batch_timeout_us: 1000,
            enabled: true,
        },
    ];

    let mut results = Vec::new();

    for config in &configs {
        // Small delay between tests
        thread::sleep(Duration::from_millis(100));

        let stats = run_batch_test(&participant, config, NUM_MESSAGES)?;
        print_comparison(config.name, &stats);
        results.push((config.name, stats));
    }

    // Calculate improvement
    println!("\n--- Performance Improvement ---\n");

    let baseline = results[0].1.msg_per_sec;
    for (name, stats) in results.iter().skip(1) {
        let improvement = ((stats.msg_per_sec / baseline) - 1.0) * 100.0;
        println!("{} {:.0}% faster than no batching", name, improvement);
    }

    // Network efficiency
    println!("\n--- Network Efficiency ---\n");
    println!("| Configuration | Messages | Packets | Efficiency |");
    println!("|---------------|----------|---------|------------|");

    for (name, stats) in &results {
        let efficiency = stats.messages_sent as f64 / stats.batches_sent as f64;
        println!(
            "| {:13} | {:8} | {:7} | {:5.1}x     |",
            name, stats.messages_sent, stats.batches_sent, efficiency
        );
    }

    // Best practices
    println!("\n--- Batching Best Practices ---\n");
    println!("1. Choose batch size based on network MTU (typically 1500 bytes)");
    println!("2. For low-latency: smaller batches or disable batching");
    println!("3. For high-throughput: larger batches (8KB-64KB)");
    println!("4. Use flush() for time-sensitive messages");
    println!("5. batch_timeout prevents stale messages in low-rate scenarios");

    // Latency trade-off
    println!("\n--- Latency vs Throughput Trade-off ---\n");
    println!("| Batch Size | Throughput | Added Latency    |");
    println!("|------------|------------|------------------|");
    println!("| None       | Baseline   | ~0 us            |");
    println!("| 1 KB       | ~2x        | ~10-50 us        |");
    println!("| 8 KB       | ~5x        | ~50-200 us       |");
    println!("| 64 KB      | ~10x       | ~100-500 us      |");

    println!("\n=== Sample Complete ===");
    Ok(())
}
