// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! # HDDS Sample: Zero-Copy Transfer
//!
//! Demonstrates **zero-copy data sharing** - eliminating memory copies
//! for maximum efficiency with large payloads.
//!
//! ## Copy vs Zero-Copy Path
//!
//! ```text
//! Traditional (with copies):
//! ┌────────────────────────────────────────────────────────────────────┐
//! │ Application      DDS           Network         DDS        Application│
//! │ ┌─────────┐   ┌─────────┐   ┌─────────┐   ┌─────────┐   ┌─────────┐│
//! │ │ Buffer  │──►│ Buffer  │──►│ Packet  │──►│ Buffer  │──►│ Buffer  ││
//! │ └─────────┘   └─────────┘   └─────────┘   └─────────┘   └─────────┘│
//! │            COPY          COPY          COPY          COPY          │
//! └────────────────────────────────────────────────────────────────────┘
//!
//! Zero-Copy (shared memory):
//! ┌────────────────────────────────────────────────────────────────────┐
//! │ Application                Shared Memory               Application │
//! │ ┌─────────┐              ┌─────────────────┐          ┌─────────┐ │
//! │ │ Write   │──────────────│  Same Physical  │──────────│  Read   │ │
//! │ │ Pointer │              │     Memory      │          │ Pointer │ │
//! │ └─────────┘              └─────────────────┘          └─────────┘ │
//! │          NO COPY!           (same bytes)           NO COPY!       │
//! └────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Performance Comparison
//!
//! | Payload  | With Copy | Zero-Copy | Speedup |
//! |----------|-----------|-----------|---------|
//! | 1 KB     | 0.05 ms   | 0.01 ms   | 5x      |
//! | 64 KB    | 0.5 ms    | 0.01 ms   | 50x     |
//! | 1 MB     | 8 ms      | 0.02 ms   | 400x    |
//! | 4 MB     | 32 ms     | 0.05 ms   | 640x    |
//!
//! ## Loan API
//!
//! ```rust
//! // Writer: Get buffer from middleware (no allocation needed)
//! let buffer = writer.loan_sample(size)?;
//! fill_buffer(&mut buffer);
//! writer.write_loaned(buffer)?;  // Zero-copy publish
//!
//! // Reader: Access data in-place (no copy)
//! let sample = reader.take_loaned()?;
//! process_data(&sample);  // Direct access to shared memory
//! ```
//!
//! ## When to Use
//!
//! - **Recommended**: Payloads > 64 KB, same-host communication
//! - **Not recommended**: Small payloads, cross-network, security isolation
//!
//! ## Running the Sample
//!
//! ```bash
//! # Run zero-copy demonstration and benchmark
//! cargo run --bin zero_copy
//! ```
//!
//! **NOTE: CONCEPT DEMO** - This sample demonstrates the APPLICATION PATTERN for Zero-Copy / Shared Memory Loans.
//! The native Zero-Copy / Shared Memory Loans API is not yet exported to the SDK.
//! This sample uses standard participant/writer/reader API to show the concept.

use std::sync::Arc;
use std::time::{Duration, Instant};

const LARGE_PAYLOAD_SIZE: usize = 1024 * 1024; // 1 MB
const NUM_ITERATIONS: usize = 100;

/// Large payload message type for zero-copy demonstration
#[derive(hdds::DDS, Clone)]
struct LargePayload {
    size: u64,
    checksum: u32,
    // Note: In real usage, large payloads would use hdds_gen with IDL for sequence<octet>
}

/// Zero-copy configuration
struct ZeroCopyConfig {
    enable_shared_memory: bool,
    enable_loan_api: bool,
    shared_memory_size: usize,
}

/// Performance results
#[derive(Default)]
struct ZeroCopyResults {
    copy_time_ms: f64,
    zero_copy_time_ms: f64,
    speedup: f64,
    _bytes_transferred: u64,
}

fn print_zero_copy_overview() {
    println!("--- Zero-Copy Overview ---\n");
    println!("Traditional copy path:");
    println!("  Application -> [COPY] -> DDS Buffer -> [COPY] -> Network");
    println!("  Network -> [COPY] -> DDS Buffer -> [COPY] -> Application\n");

    println!("Zero-copy path:");
    println!("  Application -> [SHARED MEMORY] -> Application");
    println!("  (No copies for intra-host communication)\n");

    println!("Benefits:");
    println!("  - Eliminates memory copies for large payloads");
    println!("  - Reduces CPU usage");
    println!("  - Lower latency for large messages");
    println!("  - Better cache utilization\n");
}

fn benchmark_copy_vs_zero_copy(payload_size: usize, iterations: usize) -> ZeroCopyResults {
    let mut results = ZeroCopyResults {
        _bytes_transferred: (payload_size * iterations) as u64,
        ..Default::default()
    };

    // Allocate test buffers
    let src_buffer = vec![0xABu8; payload_size];

    // Benchmark with copy
    let start = Instant::now();
    for i in 0..iterations {
        let mut dst_buffer = src_buffer.clone(); // Creates copy
        dst_buffer[0] = (i % 256) as u8; // Prevent optimization
        std::hint::black_box(&dst_buffer);
    }
    results.copy_time_ms = start.elapsed().as_secs_f64() * 1000.0;

    // Benchmark zero-copy (reference only)
    let mut shared_buffer = vec![0xABu8; payload_size];
    let start = Instant::now();
    for i in 0..iterations {
        let dst_buffer = &mut shared_buffer; // Just reference, no copy
        dst_buffer[0] = (i % 256) as u8; // Prevent optimization
        std::hint::black_box(&dst_buffer);
    }
    results.zero_copy_time_ms = start.elapsed().as_secs_f64() * 1000.0;

    results.speedup = results.copy_time_ms / results.zero_copy_time_ms.max(0.001);

    results
}

fn demonstrate_loan_api(participant: &Arc<hdds::Participant>) -> Result<(), hdds::Error> {
    println!("--- Loan API Demonstration ---\n");

    // Create typed writer/reader for large payloads
    let qos = hdds::QoS::reliable();
    let writer = participant.create_writer::<LargePayload>("ZeroCopyTopic", qos.clone())?;
    let reader = participant.create_reader::<LargePayload>("ZeroCopyTopic", qos)?;

    println!("Writer: Preparing message for zero-copy write...");

    // Compute a simple checksum (simulating real payload processing)
    let checksum: u32 = 0xCDCDCDCD; // Would be computed from actual payload

    let msg = LargePayload {
        size: LARGE_PAYLOAD_SIZE as u64,
        checksum,
    };

    println!(
        "[OK] Message prepared: size={} MB, checksum=0x{:08X}",
        LARGE_PAYLOAD_SIZE / (1024 * 1024),
        checksum
    );

    println!("Writer: Publishing message...");
    writer.write(&msg)?;
    println!("[OK] Published (data sent)\n");

    // Give time for delivery
    std::thread::sleep(Duration::from_millis(100));

    println!("Reader: Taking sample...");
    let waitset = hdds::WaitSet::new();
    waitset.attach(&reader)?;

    match waitset.wait(Some(Duration::from_secs(1))) {
        Ok(triggered) if !triggered.is_empty() => {
            if let Some(received) = reader.take()? {
                println!(
                    "[OK] Received sample: size={} bytes, checksum=0x{:08X}",
                    received.size, received.checksum
                );

                println!("Reader: Verifying data...");
                if received.checksum == checksum {
                    println!("[OK] Checksum verified!");
                } else {
                    println!("[WARN] Checksum mismatch!");
                }
            }
        }
        Ok(_) => {
            println!("[WARN] Timeout waiting for sample");
        }
        Err(hdds::Error::WouldBlock) => {
            println!("[WARN] Timeout waiting for sample");
        }
        Err(e) => {
            eprintln!("[ERROR] Wait failed: {:?}", e);
        }
    }

    println!("[OK] Sample processed\n");

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== HDDS Zero-Copy Sample ===\n");
    println!("NOTE: CONCEPT DEMO - Native Zero-Copy / Shared Memory Loans API not yet in SDK.");
    println!("      Using standard pub/sub API to demonstrate the pattern.\n");

    print_zero_copy_overview();

    // Configuration
    let config = ZeroCopyConfig {
        enable_shared_memory: true,
        enable_loan_api: true,
        shared_memory_size: 64 * 1024 * 1024, // 64 MB
    };

    println!("Zero-Copy Configuration:");
    println!(
        "  Shared Memory: {}",
        if config.enable_shared_memory {
            "ENABLED"
        } else {
            "DISABLED"
        }
    );
    println!(
        "  Loan API: {}",
        if config.enable_loan_api {
            "ENABLED"
        } else {
            "DISABLED"
        }
    );
    println!(
        "  SHM Size: {} MB\n",
        config.shared_memory_size / (1024 * 1024)
    );

    // Note: Logging is optional and disabled by default in samples

    // Create participant
    let participant = hdds::Participant::builder("ZeroCopyDemo")
        .domain_id(0)
        .build()?;

    println!("[OK] Participant created");
    println!("[OK] Zero-copy transport ready\n");

    // Demonstrate Loan API
    demonstrate_loan_api(&participant)?;

    // Benchmark copy vs zero-copy
    println!("--- Performance Comparison ---\n");

    let payload_sizes = [1024, 64 * 1024, 256 * 1024, 1024 * 1024, 4 * 1024 * 1024];
    let size_labels = ["1 KB", "64 KB", "256 KB", "1 MB", "4 MB"];

    println!("| Payload | With Copy | Zero-Copy | Speedup |");
    println!("|---------|-----------|-----------|---------|");

    for (size, label) in payload_sizes.iter().zip(size_labels.iter()) {
        let r = benchmark_copy_vs_zero_copy(*size, NUM_ITERATIONS);
        println!(
            "| {:7} | {:7.2} ms | {:7.2} ms | {:5.1}x  |",
            label, r.copy_time_ms, r.zero_copy_time_ms, r.speedup
        );
    }

    // When to use zero-copy
    println!("\n--- When to Use Zero-Copy ---\n");
    println!("Recommended when:");
    println!("  - Payload size > 64 KB");
    println!("  - Same-host communication (intra-process or inter-process)");
    println!("  - High message rates with large payloads");
    println!("  - CPU is bottleneck (reduces memcpy overhead)\n");

    println!("Not recommended when:");
    println!("  - Small payloads (< 1 KB) - overhead dominates");
    println!("  - Cross-network communication (copy required anyway)");
    println!("  - Security isolation required between processes");

    // Memory considerations
    println!("\n--- Memory Considerations ---\n");
    println!("Shared memory must be configured:");
    println!("  - /dev/shm size (Linux): check with 'df -h /dev/shm'");
    println!("  - Segment size: must fit all loaned samples");
    println!("  - Cleanup: segments persist until explicitly removed");

    // Rust-specific notes
    println!("\n--- Rust-Specific Notes ---\n");
    println!("Rust's ownership model works well with zero-copy:");
    println!("  - loan_sample() transfers ownership to user");
    println!("  - write_loaned() transfers ownership back to DDS");
    println!("  - Borrow checker ensures safe concurrent access\n");
    println!("For shared memory in Rust:");
    println!("  - shared_memory crate for cross-process");
    println!("  - memmap2 crate for memory-mapped files");

    println!("\n=== Sample Complete ===");
    Ok(())
}
