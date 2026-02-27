// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! # HDDS Sample: Multi-Topic
//!
//! Demonstrates a single participant publishing and subscribing to
//! **multiple topics** simultaneously - a common pattern for complex systems.
//!
//! ## When to Use Multiple Topics?
//!
//! - **Logical separation**: Different data types on different topics
//! - **Different QoS**: Commands need RELIABLE, telemetry can be BEST_EFFORT
//! - **Access control**: Security policies can differ per topic
//! - **Filtering**: Subscribers can choose which topics to receive
//!
//! ## Architecture
//!
//! ```text
//! ┌────────────────────────────────────────────────────────────┐
//! │                      Participant                           │
//! │                                                            │
//! │   Writers:                      Readers:                   │
//! │   ┌─────────────┐              ┌─────────────┐            │
//! │   │ SensorData  │──────────────│ SensorData  │            │
//! │   └─────────────┘              └─────────────┘            │
//! │   ┌─────────────┐              ┌─────────────┐            │
//! │   │  Commands   │──────────────│  Commands   │            │
//! │   └─────────────┘              └─────────────┘            │
//! │   ┌─────────────┐              ┌─────────────┐            │
//! │   │   Status    │──────────────│   Status    │            │
//! │   └─────────────┘              └─────────────┘            │
//! │                                                            │
//! └────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Real-World Example
//!
//! A robot might use:
//! - `SensorData` topic: IMU, LIDAR, camera data (BEST_EFFORT, high frequency)
//! - `Commands` topic: Movement commands (RELIABLE, low frequency)
//! - `Status` topic: Battery, errors, state (RELIABLE, periodic)
//!
//! ## Running the Sample
//!
//! ```bash
//! # Terminal 1 - Subscriber (listens to all 3 topics)
//! cargo run --bin multi_topic
//!
//! # Terminal 2 - Publisher (publishes to all 3 topics)
//! cargo run --bin multi_topic -- pub
//! ```

use std::collections::HashMap;
use std::env;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

// =============================================================================
// Generated Types
// =============================================================================

#[allow(dead_code)]
mod generated {
    include!("../../generated/hello_world.rs");
}

use generated::hdds_samples::HelloWorld;

/// Topics to demonstrate
const TOPICS: &[&str] = &["SensorData", "Commands", "Status"];

// =============================================================================
// Publisher
// =============================================================================

/// Creates writers for multiple topics and publishes to all of them.
///
/// Demonstrates:
/// - Creating multiple writers from one participant
/// - Managing writers in a collection
/// - Round-robin publishing to different topics
fn run_publisher(participant: &Arc<hdds::Participant>) -> Result<(), hdds::Error> {
    // -------------------------------------------------------------------------
    // Create Writers for All Topics
    // -------------------------------------------------------------------------
    //
    // One participant can have many writers. They share the same discovery
    // infrastructure but operate independently.

    let mut writers = HashMap::new();

    println!("Creating writers for {} topics:", TOPICS.len());
    for &topic in TOPICS {
        let writer = participant.create_writer::<HelloWorld>(topic, hdds::QoS::default())?;
        println!("  - {}", topic);
        writers.insert(topic, writer);
    }

    println!("\nPublishing to all topics...\n");

    // -------------------------------------------------------------------------
    // Publish to All Topics
    // -------------------------------------------------------------------------

    for i in 0..5u32 {
        for &topic in TOPICS {
            let msg = HelloWorld::new(format!("{} update", topic), i);

            writers.get(topic).unwrap().write(&msg)?;
            println!("  [{}] Sent #{}: \"{}\"", topic, i, msg.message);
        }

        println!(); // Visual separation between rounds
        thread::sleep(Duration::from_millis(500));
    }

    println!("Publisher finished. Sent {} messages per topic.", 5);
    Ok(())
}

// =============================================================================
// Subscriber
// =============================================================================

/// Creates readers for multiple topics and receives from all of them.
///
/// Demonstrates:
/// - Multiple readers sharing one WaitSet
/// - Processing data from multiple sources
/// - Tracking per-topic statistics
fn run_subscriber(participant: &Arc<hdds::Participant>) -> Result<(), hdds::Error> {
    // -------------------------------------------------------------------------
    // Create Readers and Shared WaitSet
    // -------------------------------------------------------------------------
    //
    // A single WaitSet can monitor multiple readers. When wait() returns,
    // you need to check each reader for data (the triggered conditions
    // tell you which ones have data, but here we just poll all of them).

    let mut readers = HashMap::new();
    let mut received: HashMap<&str, i32> = HashMap::new();
    let waitset = hdds::dds::WaitSet::new();

    println!("Creating readers for {} topics:", TOPICS.len());
    for &topic in TOPICS {
        let reader = participant.create_reader::<HelloWorld>(topic, hdds::QoS::default())?;

        // Attach each reader's condition to the shared WaitSet
        waitset.attach_condition(reader.get_status_condition())?;

        readers.insert(topic, reader);
        received.insert(topic, 0);
        println!("  - {}", topic);
    }

    println!("\nWaiting for messages on all topics...\n");

    // -------------------------------------------------------------------------
    // Receive from All Topics
    // -------------------------------------------------------------------------

    let total_expected = (TOPICS.len() * 5) as i32;
    let mut total_received = 0;

    while total_received < total_expected {
        match waitset.wait(Some(Duration::from_secs(3))) {
            Ok(triggered) if !triggered.is_empty() => {
                // Check all readers when WaitSet triggers
                for &topic in TOPICS {
                    while let Some(msg) = readers.get(topic).unwrap().take().ok().flatten() {
                        println!("  [{}] Received #{}: \"{}\"", topic, msg.count, msg.message);

                        *received.get_mut(topic).unwrap() += 1;
                        total_received += 1;
                    }
                }
            }
            Ok(_) | Err(hdds::Error::WouldBlock) => {
                println!("  (waiting for data...)");
            }
            Err(e) => {
                eprintln!("Wait error: {:?}", e);
            }
        }
    }

    // -------------------------------------------------------------------------
    // Summary
    // -------------------------------------------------------------------------

    println!("\n{}", "-".repeat(40));
    println!("Messages received per topic:");
    for &topic in TOPICS {
        println!("  {}: {} messages", topic, received[topic]);
    }

    println!("\nSubscriber finished. Total: {} messages.", total_received);
    Ok(())
}

// =============================================================================
// Main
// =============================================================================

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let is_publisher = args.get(1).map(|s| s == "pub").unwrap_or(false);

    println!("{}", "=".repeat(60));
    println!("HDDS Multi-Topic Sample");
    println!("Topics: {}", TOPICS.join(", "));
    println!("{}\n", "=".repeat(60));

    let participant = hdds::Participant::builder("MultiTopicDemo")
        .with_transport(hdds::TransportMode::IntraProcess)
        .build()?;

    println!("Participant: {}", participant.name());
    println!("Managing {} topics from single participant\n", TOPICS.len());

    if is_publisher {
        run_publisher(&participant)?;
    } else {
        run_subscriber(&participant)?;
    }

    Ok(())
}
