// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! # HDDS Sample: Lifespan QoS
//!
//! Demonstrates **LIFESPAN** QoS - data automatically expires after a
//! configurable duration, preventing delivery of stale samples.
//!
//! ## How LIFESPAN Works
//!
//! ```text
//! Lifespan: 2 seconds
//!
//! Time:  0.0s   0.5s   1.0s   1.5s   2.0s   2.5s   3.0s   3.5s
//!         |      |      |      |      |      |      |      |
//! Write: [1]    [2]    [3]    [4]    [5]    [6]    [7]
//!         |      |      |      |      |      |      |
//!         |  expires   expires        |      |      |
//!         |  at 2.5s   at 3.0s       |      |      |
//!         v      v      v             v      v      v
//!        DEAD   DEAD   DEAD   DEAD  alive  alive  alive
//!                          ^
//!                          |
//!                Late-joiner at t=3.0s only sees [5][6][7]
//! ```
//!
//! ## Use Cases
//!
//! - **Sensor data aging**: Old readings become irrelevant
//! - **Cache freshness**: Prevent consumers from acting on stale data
//! - **Market data validity**: Price quotes expire after a known interval
//!
//! ## Running the Sample
//!
//! ```bash
//! # Single-process mode (recommended for demo):
//! cargo run --bin lifespan
//!
//! # Two-terminal mode:
//! # Terminal 1 - Publisher (sends 10 messages at 500ms intervals)
//! cargo run --bin lifespan -- pub
//!
//! # Terminal 2 - Subscriber (joins after 3s, reads surviving messages)
//! cargo run --bin lifespan
//! ```

use std::env;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

#[allow(dead_code)]
mod generated {
    include!("../../../../01_basics/rust/generated/hello_world.rs");
}

use generated::hdds_samples::HelloWorld;

/// Lifespan duration in seconds
const LIFESPAN_SECS: u64 = 2;
/// Number of messages to publish
const NUM_MESSAGES: u32 = 10;
/// Interval between publishes in milliseconds
const PUBLISH_INTERVAL_MS: u64 = 500;
/// Delay before late-joiner subscribes in seconds
const LATE_JOIN_DELAY_SECS: u64 = 3;

// =============================================================================
// Publisher
// =============================================================================

fn run_publisher(participant: &Arc<hdds::Participant>) -> Result<(), hdds::Error> {
    // -------------------------------------------------------------------------
    // LIFESPAN Writer
    // -------------------------------------------------------------------------
    //
    // Samples written with this QoS will expire after LIFESPAN_SECS seconds.
    // Combined with TRANSIENT_LOCAL so the cache is available for late joiners,
    // but expired samples are automatically purged before delivery.

    let qos = hdds::QoS::reliable()
        .transient_local()
        .lifespan_secs(LIFESPAN_SECS);

    let writer = participant.create_writer::<HelloWorld>("LifespanTopic", qos)?;

    println!(
        "Publishing {} messages at {}ms intervals (lifespan={}s)...\n",
        NUM_MESSAGES, PUBLISH_INTERVAL_MS, LIFESPAN_SECS
    );

    let start = Instant::now();

    for i in 0..NUM_MESSAGES {
        let msg = HelloWorld::new(format!("Sample #{}", i + 1), i + 1);
        writer.write(&msg)?;

        let elapsed = start.elapsed().as_millis();
        let expires_at = elapsed as u64 + LIFESPAN_SECS * 1000;
        println!(
            "  [{:5}ms] Sent #{} (expires at ~{}ms)",
            elapsed,
            i + 1,
            expires_at
        );

        thread::sleep(Duration::from_millis(PUBLISH_INTERVAL_MS));
    }

    println!("\nAll messages published. Waiting for late-joiners...");
    println!("(Start subscriber in another terminal)\n");

    // Keep writer alive long enough for late-joiner demo
    for i in 0..10 {
        println!("  Waiting... {} seconds remaining", 10 - i);
        thread::sleep(Duration::from_secs(1));
    }

    println!("\nPublisher shutting down.");
    Ok(())
}

// =============================================================================
// Subscriber (Late Joiner)
// =============================================================================

fn run_subscriber(participant: &Arc<hdds::Participant>) -> Result<(), hdds::Error> {
    // -------------------------------------------------------------------------
    // LIFESPAN Reader
    // -------------------------------------------------------------------------
    //
    // The reader also uses TRANSIENT_LOCAL + LIFESPAN so it can receive
    // cached data, but only samples that have not yet expired.

    let qos = hdds::QoS::reliable()
        .transient_local()
        .lifespan_secs(LIFESPAN_SECS);

    let reader = participant.create_reader::<HelloWorld>("LifespanTopic", qos)?;

    let waitset = hdds::dds::WaitSet::new();
    waitset.attach_condition(reader.get_status_condition())?;

    println!(
        "Subscribing with LIFESPAN={}s (TRANSIENT_LOCAL)...\n",
        LIFESPAN_SECS
    );

    let mut received = 0u32;
    let mut timeouts = 0;
    let start = Instant::now();

    while timeouts < 2 {
        match waitset.wait(Some(Duration::from_secs(3))) {
            Ok(triggered) if !triggered.is_empty() => {
                while let Some(msg) = reader.take().ok().flatten() {
                    let elapsed = start.elapsed().as_millis();
                    println!(
                        "  [{:5}ms] Received #{}: \"{}\" (survived lifespan!)",
                        elapsed, msg.count, msg.message
                    );
                    received += 1;
                }
                timeouts = 0;
            }
            Ok(_) | Err(hdds::Error::WouldBlock) => {
                timeouts += 1;
            }
            Err(e) => eprintln!("Wait error: {:?}", e),
        }
    }

    // -------------------------------------------------------------------------
    // Summary
    // -------------------------------------------------------------------------

    println!("\n{}", "-".repeat(50));
    if received > 0 {
        println!(
            "Received {} messages (others expired before arrival).",
            received
        );
        println!(
            "Only samples younger than {}s were delivered.",
            LIFESPAN_SECS
        );
    } else {
        println!("No messages received.");
        println!("All samples may have expired. Try starting publisher first.");
    }
    println!("{}", "-".repeat(50));

    Ok(())
}

// =============================================================================
// Single-Process Demo
// =============================================================================

fn run_single_process(participant: &Arc<hdds::Participant>) -> Result<(), hdds::Error> {
    // -------------------------------------------------------------------------
    // Demonstrate lifespan expiration in a single process
    // -------------------------------------------------------------------------
    //
    // 1. Publisher sends 10 messages at 500ms intervals (total ~5s)
    // 2. Subscriber joins 3s after first publish
    // 3. Only messages within the 2s lifespan window survive

    let qos = hdds::QoS::reliable()
        .transient_local()
        .lifespan_secs(LIFESPAN_SECS);

    let writer = participant.create_writer::<HelloWorld>("LifespanTopic", qos.clone())?;

    println!(
        "Phase 1: Publishing {} messages at {}ms intervals...\n",
        NUM_MESSAGES, PUBLISH_INTERVAL_MS
    );

    let start = Instant::now();

    for i in 0..NUM_MESSAGES {
        let msg = HelloWorld::new(format!("Sample #{}", i + 1), i + 1);
        writer.write(&msg)?;

        let elapsed = start.elapsed().as_millis();
        println!("  [{:5}ms] Sent #{}", elapsed, i + 1);

        thread::sleep(Duration::from_millis(PUBLISH_INTERVAL_MS));
    }

    let publish_done = start.elapsed().as_millis();
    println!(
        "\nPhase 2: Waiting {}s before subscribing (simulating late-join)...",
        LATE_JOIN_DELAY_SECS
    );

    let remaining_wait =
        LATE_JOIN_DELAY_SECS * 1000 - publish_done.min(LATE_JOIN_DELAY_SECS as u128 * 1000) as u64;
    if remaining_wait > 0 {
        thread::sleep(Duration::from_millis(remaining_wait));
    }

    let join_time = start.elapsed().as_millis();
    println!("  [{:5}ms] Late-joiner subscribing now...\n", join_time);

    let reader = participant.create_reader::<HelloWorld>("LifespanTopic", qos)?;

    let waitset = hdds::dds::WaitSet::new();
    waitset.attach_condition(reader.get_status_condition())?;

    let mut received = 0u32;
    let mut timeouts = 0;

    while timeouts < 2 {
        match waitset.wait(Some(Duration::from_secs(2))) {
            Ok(triggered) if !triggered.is_empty() => {
                while let Some(msg) = reader.take().ok().flatten() {
                    let elapsed = start.elapsed().as_millis();
                    println!(
                        "  [{:5}ms] Received #{}: \"{}\"",
                        elapsed, msg.count, msg.message
                    );
                    received += 1;
                }
                timeouts = 0;
            }
            Ok(_) | Err(hdds::Error::WouldBlock) => {
                timeouts += 1;
            }
            Err(e) => eprintln!("Wait error: {:?}", e),
        }
    }

    // -------------------------------------------------------------------------
    // Summary
    // -------------------------------------------------------------------------

    let expired = NUM_MESSAGES - received;
    println!("\n{}", "-".repeat(50));
    println!(
        "Published:  {} messages over ~{}ms",
        NUM_MESSAGES, publish_done
    );
    println!("Joined at:  ~{}ms", join_time);
    println!("Lifespan:   {}s", LIFESPAN_SECS);
    println!("Received:   {} (survived)", received);
    println!("Expired:    {} (too old)", expired);
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
    println!("HDDS Lifespan QoS Sample");
    println!("Data expires after a configurable duration");
    println!("{}\n", "=".repeat(60));

    let participant = hdds::Participant::builder("LifespanDemo")
        .with_transport(hdds::TransportMode::IntraProcess)
        .build()?;

    if is_publisher {
        run_publisher(&participant)?;
    } else if args.get(1).map(|s| s == "sub").unwrap_or(false) {
        run_subscriber(&participant)?;
    } else {
        run_single_process(&participant)?;
    }

    Ok(())
}
