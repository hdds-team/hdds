// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! # HDDS Sample: Exclusive Ownership QoS
//!
//! Demonstrates **EXCLUSIVE** ownership - only the writer with the highest
//! ownership strength delivers data to readers.
//!
//! ## Ownership Kinds
//!
//! | Kind      | Behavior                          | Use Case              |
//! |-----------|-----------------------------------|-----------------------|
//! | SHARED    | All writers deliver (default)     | Normal pub/sub        |
//! | EXCLUSIVE | Only highest-strength writer wins | Primary/backup        |
//!
//! ## How EXCLUSIVE Ownership Works
//!
//! ```text
//! Writer A (strength=100)  ────────────▶ ╲
//!                                         ╲
//!                                          ▶ Reader only sees Writer B
//!                                         ╱
//! Writer B (strength=200)  ────────────▶ ╱
//!
//! If Writer B crashes → Reader sees Writer A (failover!)
//! ```
//!
//! ## Use Cases
//!
//! - **Primary/Backup**: Automatic failover when primary fails
//! - **Redundant systems**: Hot standby without duplicate data
//! - **Priority levels**: Higher priority sources win
//!
//! ## Running the Sample
//!
//! ```bash
//! # Terminal 1 - Subscriber
//! cargo run --bin ownership_exclusive
//!
//! # Terminal 2 - Low-priority publisher (strength=100)
//! cargo run --bin ownership_exclusive -- pub 100
//!
//! # Terminal 3 - High-priority publisher (strength=200, wins)
//! cargo run --bin ownership_exclusive -- pub 200
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

// =============================================================================
// Publisher
// =============================================================================

fn run_publisher(participant: &Arc<hdds::Participant>, strength: i32) -> Result<(), hdds::Error> {
    // -------------------------------------------------------------------------
    // EXCLUSIVE Ownership Writer
    // -------------------------------------------------------------------------
    //
    // ownership_strength determines priority:
    // - Higher strength = wins ownership
    // - On tie, first writer wins
    // - When owner dies, next-highest takes over

    let qos = hdds::QoS::reliable()
        .ownership_exclusive()
        .ownership_strength(strength);

    let writer = participant.create_writer::<HelloWorld>("OwnershipTopic", qos)?;

    println!(
        "Publishing with EXCLUSIVE ownership (strength: {})",
        strength
    );
    println!("Higher strength wins. Try another publisher with different strength.\n");

    let running = Arc::new(AtomicBool::new(true));

    for seq in 0..10u32 {
        if !running.load(Ordering::SeqCst) {
            break;
        }

        let msg = HelloWorld::new(format!("Writer[str={}] seq={}", strength, seq), seq);
        writer.write(&msg)?;

        println!("  [strength={}] Published seq={}", strength, seq);
        thread::sleep(Duration::from_millis(500));
    }

    println!("\nPublisher (strength={}) shutting down.", strength);
    Ok(())
}

// =============================================================================
// Subscriber
// =============================================================================

fn run_subscriber(participant: &Arc<hdds::Participant>) -> Result<(), hdds::Error> {
    // Reader doesn't specify strength - it just receives from the winner
    let qos = hdds::QoS::reliable().ownership_exclusive();
    let reader = participant.create_reader::<HelloWorld>("OwnershipTopic", qos)?;

    let waitset = hdds::dds::WaitSet::new();
    waitset.attach_condition(reader.get_status_condition())?;

    println!("Subscribing with EXCLUSIVE ownership...");
    println!("Only data from highest-strength writer will be received.\n");

    let running = Arc::new(AtomicBool::new(true));
    let mut iterations = 0;

    while running.load(Ordering::SeqCst) && iterations < 20 {
        iterations += 1;

        match waitset.wait(Some(Duration::from_secs(1))) {
            Ok(triggered) if !triggered.is_empty() => {
                while let Some(msg) = reader.take().ok().flatten() {
                    // Parse strength from message for demo purposes
                    println!("  [RECV] \"{}\"", msg.message);
                }
            }
            Ok(_) | Err(hdds::Error::WouldBlock) => {
                // Timeout, continue
            }
            Err(e) => eprintln!("Wait error: {:?}", e),
        }
    }

    println!("\nSubscriber shutting down.");
    Ok(())
}

// =============================================================================
// Main
// =============================================================================

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let is_publisher = args.get(1).map(|s| s == "pub").unwrap_or(false);
    let strength: i32 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(100);

    println!("{}", "=".repeat(60));
    println!("HDDS Exclusive Ownership QoS Sample");
    println!("Only highest-strength writer delivers data");
    println!("{}\n", "=".repeat(60));

    let participant = hdds::Participant::builder("OwnershipDemo")
        .with_transport(hdds::TransportMode::IntraProcess)
        .build()?;

    if is_publisher {
        run_publisher(&participant, strength)?;
    } else {
        run_subscriber(&participant)?;
    }

    Ok(())
}
