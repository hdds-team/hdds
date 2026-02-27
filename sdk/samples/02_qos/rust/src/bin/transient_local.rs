// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! # HDDS Sample: Transient Local QoS
//!
//! Demonstrates **TRANSIENT_LOCAL** durability - enables late-joining
//! subscribers to receive historical data from the writer's cache.
//!
//! ## Durability Levels
//!
//! | Level            | Persistence | Late-Joiner Support       |
//! |------------------|-------------|---------------------------|
//! | VOLATILE         | None        | No historical data        |
//! | TRANSIENT_LOCAL  | Writer cache| Gets cached samples       |
//! | TRANSIENT        | Service     | Gets from durability svc  |
//! | PERSISTENT       | Disk        | Survives restarts         |
//!
//! ## How TRANSIENT_LOCAL Works
//!
//! ```text
//! Time ────────────────────────────────────────────▶
//!
//! Writer:  [pub 1] [pub 2] [pub 3]              [pub 4]
//!              │       │       │                    │
//!              ▼       ▼       ▼                    ▼
//!          ┌───────────────────────────────────────────┐
//!          │  Writer Cache: [1] [2] [3]     [1][2][3][4]
//!          └───────────────────────────────────────────┘
//!                                    │
//!                                    │ Late-joiner connects
//!                                    ▼
//!                           Reader receives [1][2][3]
//! ```
//!
//! ## Use Cases
//!
//! - **Configuration topics**: New nodes get current config
//! - **State synchronization**: Late joiners catch up
//! - **Discovery data**: New participants learn system state
//!
//! ## Running the Sample
//!
//! ```bash
//! # Step 1: Start publisher (caches messages)
//! cargo run --bin transient_local -- pub
//!
//! # Step 2: Start late-joining subscriber (receives cached data)
//! cargo run --bin transient_local
//! ```

use std::env;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

#[allow(dead_code)]
mod generated {
    include!("../../../../01_basics/rust/generated/hello_world.rs");
}

use generated::hdds_samples::HelloWorld;

const NUM_MESSAGES: u32 = 5;

// =============================================================================
// Publisher
// =============================================================================

fn run_publisher(participant: &Arc<hdds::Participant>) -> Result<(), hdds::Error> {
    // -------------------------------------------------------------------------
    // TRANSIENT_LOCAL Writer
    // -------------------------------------------------------------------------
    //
    // Configuration:
    // - RELIABLE: Ensures delivery to existing subscribers
    // - TRANSIENT_LOCAL: Caches samples for late joiners
    // - KEEP_LAST(N): Controls cache size

    let qos = hdds::QoS::reliable()
        .transient_local()
        .keep_last(NUM_MESSAGES);

    let writer = participant.create_writer::<HelloWorld>("TransientTopic", qos)?;

    println!(
        "Publishing {} messages with TRANSIENT_LOCAL QoS...\n",
        NUM_MESSAGES
    );

    for i in 0..NUM_MESSAGES {
        let msg = HelloWorld::new(format!("Historical data #{}", i + 1), i + 1);
        writer.write(&msg)?;
        println!("  [{:02}] Cached: \"{}\"", i + 1, msg.message);
    }

    println!("\nAll messages cached. Waiting for late-joining subscribers...");
    println!("(Start subscriber in another terminal)");
    println!("Press Ctrl+C to exit.\n");

    let running = Arc::new(AtomicBool::new(true));

    // Keep writer alive for demo (10 seconds)
    for i in 0..10 {
        if !running.load(Ordering::SeqCst) {
            break;
        }
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
    println!("Creating TRANSIENT_LOCAL subscriber (late-joiner)...");
    println!("If publisher ran first, we'll receive cached historical data.\n");

    // -------------------------------------------------------------------------
    // TRANSIENT_LOCAL Reader
    // -------------------------------------------------------------------------
    //
    // Must also be TRANSIENT_LOCAL to receive historical data.
    // A VOLATILE reader would NOT receive cached samples.

    let qos = hdds::QoS::reliable().transient_local();
    let reader = participant.create_reader::<HelloWorld>("TransientTopic", qos)?;

    let waitset = hdds::dds::WaitSet::new();
    waitset.attach_condition(reader.get_status_condition())?;

    println!("Waiting for historical data...\n");

    let mut received = 0u32;
    let mut timeouts = 0;

    while timeouts < 2 {
        match waitset.wait(Some(Duration::from_secs(3))) {
            Ok(triggered) if !triggered.is_empty() => {
                while let Some(msg) = reader.take().ok().flatten() {
                    println!("  [{:02}] Historical: \"{}\"", msg.count, msg.message);
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
            "Received {} historical messages via TRANSIENT_LOCAL!",
            received
        );
        println!("Late-joiners automatically get cached data.");
    } else {
        println!("No historical data received.");
        println!("Start publisher first: cargo run --bin transient_local -- pub");
    }
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
    println!("HDDS Transient Local QoS Sample");
    println!("Late-joiners receive historical data from writer cache");
    println!("{}\n", "=".repeat(60));

    let participant = hdds::Participant::builder("TransientLocalDemo")
        .with_transport(hdds::TransportMode::IntraProcess)
        .build()?;

    if is_publisher {
        run_publisher(&participant)?;
    } else {
        run_subscriber(&participant)?;
    }

    Ok(())
}
