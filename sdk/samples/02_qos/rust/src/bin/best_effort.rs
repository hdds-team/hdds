// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! # HDDS Sample: Best Effort QoS
//!
//! Demonstrates **BEST_EFFORT** reliability - the "fire-and-forget" delivery mode
//! that prioritizes low latency over guaranteed delivery.
//!
//! ## BEST_EFFORT vs RELIABLE
//!
//! | Aspect          | BEST_EFFORT           | RELIABLE              |
//! |-----------------|----------------------|----------------------|
//! | Delivery        | No guarantee         | Guaranteed           |
//! | Latency         | Lowest               | Higher (ACK overhead)|
//! | Retransmission  | None                 | On packet loss       |
//! | Use cases       | Sensors, video       | Commands, state      |
//!
//! ## When to Use BEST_EFFORT
//!
//! - **High-frequency sensor data**: Missing one reading isn't critical
//! - **Video/audio streams**: Stale data is worse than missing data
//! - **Network-constrained**: Reduce bandwidth with no retransmissions
//! - **Soft real-time**: Predictable latency more important than completeness
//!
//! ## Running the Sample
//!
//! ```bash
//! # Terminal 1 - Subscriber
//! cargo run --bin best_effort
//!
//! # Terminal 2 - Publisher (fast, may lose some messages)
//! cargo run --bin best_effort -- pub
//! ```

use std::env;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

#[allow(dead_code)]
mod generated {
    include!("../../../../01_basics/rust/generated/hello_world.rs");
}

use generated::hdds_samples::HelloWorld;

const NUM_MESSAGES: u32 = 20;

// =============================================================================
// Publisher
// =============================================================================

fn run_publisher(participant: &Arc<hdds::Participant>) -> Result<(), hdds::Error> {
    // -------------------------------------------------------------------------
    // BEST_EFFORT Writer
    // -------------------------------------------------------------------------
    //
    // With BEST_EFFORT:
    // - write() returns immediately (no waiting for ACKs)
    // - Lost packets are NOT retransmitted
    // - Ideal for high-throughput, latency-sensitive data

    let qos = hdds::QoS::best_effort();
    let writer = participant.create_writer::<HelloWorld>("BestEffortTopic", qos)?;

    println!(
        "Publishing {} messages with BEST_EFFORT QoS...",
        NUM_MESSAGES
    );
    println!("(Some messages may be lost - fire-and-forget)\n");

    for i in 0..NUM_MESSAGES {
        let msg = HelloWorld::new(format!("BestEffort #{}", i + 1), i + 1);
        writer.write(&msg)?;

        println!("  [{:02}] Sent: \"{}\"", i + 1, msg.message);

        // Fast publishing to demonstrate potential loss
        thread::sleep(Duration::from_millis(50));
    }

    println!("\nPublisher finished. Some messages may have been dropped.");
    Ok(())
}

// =============================================================================
// Subscriber
// =============================================================================

fn run_subscriber(participant: &Arc<hdds::Participant>) -> Result<(), hdds::Error> {
    let qos = hdds::QoS::best_effort();
    let reader = participant.create_reader::<HelloWorld>("BestEffortTopic", qos)?;

    let waitset = hdds::dds::WaitSet::new();
    waitset.attach_condition(reader.get_status_condition())?;

    println!("Waiting for BEST_EFFORT messages...");
    println!("(Lower latency, but delivery not guaranteed)\n");

    let mut received = 0u32;
    let mut timeouts = 0;
    let max_timeouts = 3;

    while timeouts < max_timeouts {
        match waitset.wait(Some(Duration::from_secs(2))) {
            Ok(triggered) if !triggered.is_empty() => {
                while let Some(msg) = reader.take().ok().flatten() {
                    println!("  [{:02}] Received: \"{}\"", msg.count, msg.message);
                    received += 1;
                }
                timeouts = 0;
            }
            Ok(_) | Err(hdds::Error::WouldBlock) => {
                timeouts += 1;
                println!("  (timeout {}/{})", timeouts, max_timeouts);
            }
            Err(e) => eprintln!("Wait error: {:?}", e),
        }
    }

    // -------------------------------------------------------------------------
    // Summary
    // -------------------------------------------------------------------------

    println!("\n{}", "-".repeat(50));
    println!(
        "Received {}/{} messages ({:.0}% delivery rate)",
        received,
        NUM_MESSAGES,
        (received as f64 / NUM_MESSAGES as f64) * 100.0
    );
    println!("BEST_EFFORT trades reliability for speed.");
    println!("{}", "-".repeat(50));

    Ok(())
}

// =============================================================================
// Main
// =============================================================================

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let is_publisher = args.get(1).map(|s| s == "pub").unwrap_or(false);

    println!("{}", "=".repeat(60));
    println!("HDDS Best Effort QoS Sample");
    println!("Fire-and-forget delivery with lowest latency");
    println!("{}\n", "=".repeat(60));

    let participant = hdds::Participant::builder("BestEffortDemo")
        .with_transport(hdds::TransportMode::IntraProcess)
        .build()?;

    if is_publisher {
        run_publisher(&participant)?;
    } else {
        run_subscriber(&participant)?;
    }

    Ok(())
}
