// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! # HDDS Sample: Partition QoS
//!
//! Demonstrates **PARTITION** QoS - logical namespaces for filtering
//! communication without creating separate topics.
//!
//! ## How Partitions Work
//!
//! ```text
//! Same Topic: "DataTopic"
//!
//! Partition "A":          Partition "B":
//! ┌─────────────┐         ┌─────────────┐
//! │ Writer [A]  │         │ Writer [B]  │
//! │     │       │         │     │       │
//! │     ▼       │         │     ▼       │
//! │ Reader [A]  │         │ Reader [B]  │
//! └─────────────┘         └─────────────┘
//!       ╳ No cross-communication ╳
//! ```
//!
//! ## Partition Features
//!
//! - **Wildcards**: `*` matches any, `Sales/*` matches `Sales/US`, `Sales/EU`
//! - **Multiple**: Entity can be in multiple partitions simultaneously
//! - **Dynamic**: Can change at runtime via QoS update
//!
//! ## Use Cases
//!
//! - **Multi-tenancy**: Isolate data per customer
//! - **Regions**: Separate by geographic area
//! - **Environment**: dev/staging/prod on same infrastructure
//! - **Teams**: Isolate team-specific data flows
//!
//! ## Running the Sample
//!
//! ```bash
//! # Terminal 1 - Subscriber in partition A (default)
//! cargo run --bin partition_filter
//!
//! # Terminal 2 - Publisher to partition A (matches!)
//! cargo run --bin partition_filter -- pub A
//!
//! # Terminal 3 - Publisher to partition B (no match!)
//! cargo run --bin partition_filter -- pub B
//!
//! # Terminal 4 - Subscriber in partition B
//! cargo run --bin partition_filter -- sub B
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

const NUM_MESSAGES: u32 = 5;

// =============================================================================
// Publisher
// =============================================================================

fn run_publisher(participant: &Arc<hdds::Participant>, partition: &str) -> Result<(), hdds::Error> {
    // -------------------------------------------------------------------------
    // Partitioned Writer
    // -------------------------------------------------------------------------
    //
    // partition_single() sets a single partition.
    // Use partition_multi() for multiple partitions: ["A", "B"]
    // Use partition_pattern() for wildcards: "Sales/*"

    let qos = hdds::QoS::reliable().partition_single(partition);
    let writer = participant.create_writer::<HelloWorld>("PartitionTopic", qos)?;

    println!("Publishing to partition '{}'...\n", partition);

    for i in 0..NUM_MESSAGES {
        let msg = HelloWorld::new(format!("[{}] Message #{}", partition, i + 1), i + 1);
        writer.write(&msg)?;

        println!(
            "  [{:02}] Sent to '{}': \"{}\"",
            i + 1,
            partition,
            msg.message
        );
        thread::sleep(Duration::from_millis(200));
    }

    println!(
        "\nPublisher finished. Only readers in '{}' received data.",
        partition
    );
    Ok(())
}

// =============================================================================
// Subscriber
// =============================================================================

fn run_subscriber(
    participant: &Arc<hdds::Participant>,
    partition: &str,
) -> Result<(), hdds::Error> {
    let qos = hdds::QoS::reliable().partition_single(partition);
    let reader = participant.create_reader::<HelloWorld>("PartitionTopic", qos)?;

    let waitset = hdds::dds::WaitSet::new();
    waitset.attach_condition(reader.get_status_condition())?;

    println!("Subscribing to partition '{}'...", partition);
    println!("Only publishers in '{}' will be received.\n", partition);

    let mut received = 0u32;
    let mut timeouts = 0;

    while timeouts < 3 {
        match waitset.wait(Some(Duration::from_secs(2))) {
            Ok(triggered) if !triggered.is_empty() => {
                while let Some(msg) = reader.take().ok().flatten() {
                    println!(
                        "  [{:02}] Received in '{}': \"{}\"",
                        msg.count, partition, msg.message
                    );
                    received += 1;
                }
                timeouts = 0;
            }
            Ok(_) | Err(hdds::Error::WouldBlock) => {
                timeouts += 1;
                println!("  (waiting for partition '{}'...)", partition);
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
            "Received {} messages in partition '{}'.",
            received, partition
        );
    } else {
        println!("No messages received in partition '{}'.", partition);
        println!("Is there a publisher in the same partition?");
        println!("Try: cargo run --bin partition_filter -- pub {}", partition);
    }
    println!("{}", "-".repeat(50));

    Ok(())
}

// =============================================================================
// Main
// =============================================================================

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let mode = args.get(1).map(|s| s.as_str()).unwrap_or("sub");
    let partition = args.get(2).map(|s| s.as_str()).unwrap_or("A");
    let is_publisher = mode == "pub";

    println!("{}", "=".repeat(60));
    println!("HDDS Partition QoS Sample");
    println!("Logical namespaces for filtering communication");
    println!("{}\n", "=".repeat(60));

    let participant = hdds::Participant::builder("PartitionDemo")
        .with_transport(hdds::TransportMode::IntraProcess)
        .build()?;

    println!("Participant: {}", participant.name());
    println!("Partition: '{}'\n", partition);

    if is_publisher {
        run_publisher(&participant, partition)?;
    } else {
        run_subscriber(&participant, partition)?;
    }

    Ok(())
}
