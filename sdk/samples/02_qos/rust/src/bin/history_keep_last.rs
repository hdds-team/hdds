// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! # HDDS Sample: History Keep Last QoS
//!
//! Demonstrates **KEEP_LAST** history - retains only the N most recent
//! samples per instance, discarding older data.
//!
//! ## History QoS Explained
//!
//! ```text
//! KEEP_LAST(3) - Only 3 most recent samples retained:
//!
//! Write: [1] [2] [3] [4] [5]
//!                ↓
//! Cache:         [3] [4] [5]    ← Samples 1,2 discarded
//! ```
//!
//! ## KEEP_LAST vs KEEP_ALL
//!
//! | Mode      | Behavior                    | Memory  | Use Case           |
//! |-----------|-----------------------------|---------|--------------------|
//! | KEEP_LAST | Bounded buffer, drops old   | Fixed   | Latest state only  |
//! | KEEP_ALL  | Unbounded, keeps everything | Growing | Complete history   |
//!
//! ## When to Use KEEP_LAST
//!
//! - **Sensor readings**: Only latest value matters
//! - **Position updates**: Old positions are irrelevant
//! - **Memory-constrained**: Prevent unbounded growth
//! - **Late joiners**: Get recent samples, not full history
//!
//! ## Running the Sample
//!
//! ```bash
//! # Terminal 1 - Publisher (sends 10 messages, keeps all)
//! cargo run --bin history_keep_last -- pub
//!
//! # Terminal 2 - Subscriber with depth=3 (only sees last 3)
//! cargo run --bin history_keep_last
//!
//! # Or specify custom depth
//! cargo run --bin history_keep_last -- sub 5
//! ```

use std::env;
use std::io::{self, BufRead};
use std::sync::Arc;
use std::time::Duration;

#[allow(dead_code)]
mod generated {
    include!("../../../../01_basics/rust/generated/hello_world.rs");
}

use generated::hdds_samples::HelloWorld;

const NUM_MESSAGES: u32 = 10;

// =============================================================================
// Publisher
// =============================================================================

fn run_publisher(participant: &Arc<hdds::Participant>) -> Result<(), hdds::Error> {
    // -------------------------------------------------------------------------
    // Publisher with Full History
    // -------------------------------------------------------------------------
    //
    // Writer keeps all messages so late-joining subscribers can get
    // historical data (up to their own history depth limit).
    //
    // Combined with TRANSIENT_LOCAL for late-joiner support.

    let qos = hdds::QoS::reliable()
        .transient_local()
        .keep_last(NUM_MESSAGES);

    let writer = participant.create_writer::<HelloWorld>("HistoryTopic", qos)?;

    println!("Publishing {} messages rapidly...\n", NUM_MESSAGES);

    for i in 0..NUM_MESSAGES {
        let msg = HelloWorld::new(format!("Message #{}", i + 1), i + 1);
        writer.write(&msg)?;
        println!("  [{:02}] Sent: \"{}\"", i + 1, msg.message);
    }

    println!("\nAll messages published and cached.");
    println!(
        "Subscriber with history depth < {} will only see most recent.",
        NUM_MESSAGES
    );
    println!("\nPress Enter to exit (keeping writer alive for late-join test)...");

    let stdin = io::stdin();
    let _ = stdin.lock().lines().next();

    Ok(())
}

// =============================================================================
// Subscriber
// =============================================================================

fn run_subscriber(participant: &Arc<hdds::Participant>, depth: u32) -> Result<(), hdds::Error> {
    // -------------------------------------------------------------------------
    // Subscriber with Limited History
    // -------------------------------------------------------------------------
    //
    // If publisher sent 10 messages but subscriber has depth=3,
    // only the 3 most recent will be delivered.

    let qos = hdds::QoS::reliable().transient_local().keep_last(depth);

    let reader = participant.create_reader::<HelloWorld>("HistoryTopic", qos)?;

    let waitset = hdds::dds::WaitSet::new();
    waitset.attach_condition(reader.get_status_condition())?;

    println!("Subscribing with KEEP_LAST history (depth={})...", depth);
    println!("Will only retain the {} most recent samples.\n", depth);

    let mut received = 0u32;
    let mut timeouts = 0;

    while timeouts < 2 {
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
            }
            Err(e) => eprintln!("Wait error: {:?}", e),
        }
    }

    // -------------------------------------------------------------------------
    // Summary
    // -------------------------------------------------------------------------

    println!("\n{}", "-".repeat(50));
    println!(
        "Received {} messages (history depth was {})",
        received, depth
    );

    if received < NUM_MESSAGES && received <= depth {
        println!("History depth limited samples to most recent {}.", depth);
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
    let history_depth: u32 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(3).max(1);

    println!("{}", "=".repeat(60));
    println!("HDDS History Keep Last QoS Sample");
    println!("Retain only N most recent samples per instance");
    println!("{}\n", "=".repeat(60));

    let participant = hdds::Participant::builder("HistoryDemo")
        .with_transport(hdds::TransportMode::IntraProcess)
        .build()?;

    if is_publisher {
        run_publisher(&participant)?;
    } else {
        run_subscriber(&participant, history_depth)?;
    }

    Ok(())
}
