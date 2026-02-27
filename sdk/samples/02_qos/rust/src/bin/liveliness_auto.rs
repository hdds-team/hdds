// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! # HDDS Sample: Automatic Liveliness QoS
//!
//! Demonstrates **AUTOMATIC** liveliness - the DDS infrastructure automatically
//! sends heartbeats to indicate the writer is alive.
//!
//! ## Liveliness Kinds
//!
//! | Kind                  | Assertion Method     | Use Case              |
//! |-----------------------|---------------------|-----------------------|
//! | AUTOMATIC             | DDS heartbeats      | Process health        |
//! | MANUAL_BY_PARTICIPANT | App calls assert()  | App-level health      |
//! | MANUAL_BY_TOPIC       | Writing data        | Per-topic health      |
//!
//! ## How AUTOMATIC Liveliness Works
//!
//! ```text
//! Writer                                         Reader
//!   │                                              │
//!   │──────── Heartbeat (I'm alive) ─────────────▶│
//!   │                                              │ Timer resets
//!   │                                              │
//!   │        ... lease period ...                  │
//!   │                                              │
//!   │──────── Heartbeat ─────────────────────────▶│
//!   │                                              │
//!   │        ... writer crashes ...                │
//!   │                                              │ Lease expires
//!   │                                              │
//!   │                                              │ LIVELINESS_LOST!
//! ```
//!
//! ## Use Cases
//!
//! - **Watchdog**: Detect crashed processes
//! - **Failover**: Trigger backup when primary dies
//! - **Dashboard**: Show system health status
//!
//! ## Running the Sample
//!
//! ```bash
//! # Terminal 1 - Subscriber (monitors liveliness)
//! cargo run --bin liveliness_auto
//!
//! # Terminal 2 - Publisher (sends heartbeats automatically)
//! cargo run --bin liveliness_auto -- pub
//! # Then Ctrl+C to simulate crash - subscriber detects lost liveliness
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

/// Liveliness lease duration in milliseconds
const LEASE_MS: u64 = 1000;
const NUM_MESSAGES: u32 = 8;

// =============================================================================
// Publisher
// =============================================================================

fn run_publisher(participant: &Arc<hdds::Participant>) -> Result<(), hdds::Error> {
    // -------------------------------------------------------------------------
    // AUTOMATIC Liveliness Writer
    // -------------------------------------------------------------------------
    //
    // DDS automatically sends heartbeats at regular intervals.
    // As long as the process is running, liveliness is maintained.

    let qos = hdds::QoS::reliable().liveliness_automatic_millis(LEASE_MS);
    let writer = participant.create_writer::<HelloWorld>("LivelinessTopic", qos)?;

    println!(
        "Publishing with AUTOMATIC liveliness (lease: {}ms)",
        LEASE_MS
    );
    println!("DDS automatically sends heartbeats.\n");

    let start = Instant::now();

    for i in 0..NUM_MESSAGES {
        let msg = HelloWorld::new(format!("Heartbeat #{}", i + 1), i + 1);
        writer.write(&msg)?;

        let elapsed = start.elapsed().as_millis();
        println!("  [{}ms] Published #{} - writer ALIVE", elapsed, i + 1);

        thread::sleep(Duration::from_millis(400)); // Faster than lease
    }

    println!("\nPublisher exiting. Subscriber should detect LIVELINESS_LOST.");
    Ok(())
}

// =============================================================================
// Subscriber
// =============================================================================

fn run_subscriber(participant: &Arc<hdds::Participant>) -> Result<(), hdds::Error> {
    let qos = hdds::QoS::reliable().liveliness_automatic_millis(LEASE_MS);
    let reader = participant.create_reader::<HelloWorld>("LivelinessTopic", qos)?;

    let waitset = hdds::dds::WaitSet::new();
    waitset.attach_condition(reader.get_status_condition())?;

    println!("Monitoring AUTOMATIC liveliness (lease: {}ms)...", LEASE_MS);
    println!("Will detect when writer goes offline.\n");

    let mut received = 0u32;
    let mut liveliness_lost = 0u32;
    let start = Instant::now();
    let mut last_msg = start;

    while received < NUM_MESSAGES + 2 {
        match waitset.wait(Some(Duration::from_millis(LEASE_MS * 2))) {
            Ok(triggered) if !triggered.is_empty() => {
                while let Some(msg) = reader.take().ok().flatten() {
                    let elapsed = start.elapsed().as_millis();
                    println!("  [{}ms] Received #{} - writer ALIVE", elapsed, msg.count);
                    last_msg = Instant::now();
                    received += 1;
                }
            }
            Ok(_) | Err(hdds::Error::WouldBlock) => {
                let elapsed = start.elapsed().as_millis();
                let since_last = (Instant::now() - last_msg).as_millis();

                if since_last > LEASE_MS as u128 {
                    println!(
                        "  [{}ms] LIVELINESS LOST - no heartbeat for {}ms!",
                        elapsed, since_last
                    );
                    liveliness_lost += 1;
                    if liveliness_lost >= 2 {
                        break;
                    }
                }
            }
            Err(e) => eprintln!("Wait error: {:?}", e),
        }
    }

    // -------------------------------------------------------------------------
    // Summary
    // -------------------------------------------------------------------------

    println!("\n{}", "-".repeat(50));
    println!(
        "Summary: {} messages, liveliness lost {} times",
        received, liveliness_lost
    );
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
    println!("HDDS Automatic Liveliness QoS Sample");
    println!("DDS automatically sends heartbeats");
    println!("{}\n", "=".repeat(60));

    let participant = hdds::Participant::builder("LivelinessAutoDemo")
        .with_transport(hdds::TransportMode::IntraProcess)
        .build()?;

    if is_publisher {
        run_publisher(&participant)?;
    } else {
        run_subscriber(&participant)?;
    }

    Ok(())
}
