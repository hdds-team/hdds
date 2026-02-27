// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! # HDDS Sample: Reliable Delivery QoS
//!
//! Demonstrates **RELIABLE** QoS - guaranteed message delivery with
//! automatic retransmission of lost packets.
//!
//! ## How RELIABLE Works
//!
//! ```text
//! Writer                                    Reader
//!   │                                         │
//!   │──────── DATA (seq=1) ─────────────────▶│
//!   │◀─────── ACKNACK (received=1) ──────────│
//!   │                                         │
//!   │──────── DATA (seq=2) ──────X (lost)    │
//!   │                                         │
//!   │◀─────── ACKNACK (missing=2) ───────────│  ← Reader detects gap
//!   │                                         │
//!   │──────── DATA (seq=2) ─────────────────▶│  ← Retransmit
//!   │◀─────── ACKNACK (received=2) ──────────│
//! ```
//!
//! ## When to Use RELIABLE
//!
//! - **Commands**: Every command must be delivered
//! - **Configuration**: Settings must not be lost
//! - **State synchronization**: Consistency is critical
//! - **Transactions**: All-or-nothing semantics
//!
//! ## Trade-offs
//!
//! - Higher latency due to ACK/NACK overhead
//! - More network traffic (heartbeats, ACKs)
//! - Potential blocking if receiver is slow (flow control)
//!
//! ## Running the Sample
//!
//! ```bash
//! # Terminal 1 - Subscriber
//! cargo run --bin reliable_delivery
//!
//! # Terminal 2 - Publisher
//! cargo run --bin reliable_delivery -- pub
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

const NUM_MESSAGES: u32 = 10;

// =============================================================================
// Publisher
// =============================================================================

fn run_publisher(participant: &Arc<hdds::Participant>) -> Result<(), hdds::Error> {
    // -------------------------------------------------------------------------
    // RELIABLE Writer
    // -------------------------------------------------------------------------
    //
    // With RELIABLE QoS:
    // - Writer maintains history for retransmission
    // - Lost packets trigger NACK from reader
    // - Writer retransmits until acknowledged
    // - Guarantees in-order, complete delivery

    let qos = hdds::QoS::reliable();
    let writer = participant.create_writer::<HelloWorld>("ReliableTopic", qos)?;

    println!("Publishing {} messages with RELIABLE QoS...", NUM_MESSAGES);
    println!("All messages will be delivered (with retransmission if needed)\n");

    for i in 0..NUM_MESSAGES {
        let msg = HelloWorld::new(format!("Reliable message #{}", i + 1), i + 1);
        writer.write(&msg)?;

        println!("  [{:02}] Sent: \"{}\"", i + 1, msg.message);
        thread::sleep(Duration::from_millis(100));
    }

    println!("\nPublisher finished. RELIABLE ensures all messages delivered.");
    Ok(())
}

// =============================================================================
// Subscriber
// =============================================================================

fn run_subscriber(participant: &Arc<hdds::Participant>) -> Result<(), hdds::Error> {
    let qos = hdds::QoS::reliable();
    let reader = participant.create_reader::<HelloWorld>("ReliableTopic", qos)?;

    let waitset = hdds::dds::WaitSet::new();
    waitset.attach_condition(reader.get_status_condition())?;

    println!("Waiting for RELIABLE messages...");
    println!("(Guaranteed delivery via NACK-based retransmission)\n");

    let mut received = 0u32;
    while received < NUM_MESSAGES {
        match waitset.wait(Some(Duration::from_secs(5))) {
            Ok(triggered) if !triggered.is_empty() => {
                while let Some(msg) = reader.take().ok().flatten() {
                    println!("  [{:02}] Received: \"{}\"", msg.count, msg.message);
                    received += 1;
                }
            }
            Ok(_) | Err(hdds::Error::WouldBlock) => {
                println!("  (waiting for publisher...)");
            }
            Err(e) => eprintln!("Wait error: {:?}", e),
        }
    }

    // -------------------------------------------------------------------------
    // Summary
    // -------------------------------------------------------------------------

    println!("\n{}", "-".repeat(50));
    println!("Received all {} messages.", received);
    println!("RELIABLE QoS guarantees complete, in-order delivery!");
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
    println!("HDDS Reliable Delivery QoS Sample");
    println!("Guaranteed delivery via NACK-based retransmission");
    println!("{}\n", "=".repeat(60));

    let participant = hdds::Participant::builder("ReliableDemo")
        .with_transport(hdds::TransportMode::IntraProcess)
        .build()?;

    if is_publisher {
        run_publisher(&participant)?;
    } else {
        run_subscriber(&participant)?;
    }

    Ok(())
}
