// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! # HDDS Sample: Instance Keys
//!
//! Demonstrates **keyed instances** - a powerful DDS concept for managing
//! multiple independent data streams within a single topic.
//!
//! ## What Are Instance Keys?
//!
//! In DDS, a **key** identifies unique instances of data. Think of it like
//! a primary key in a database:
//!
//! ```text
//! Topic: "SensorTopic"
//! ┌─────────────────────────────────────────────────────────┐
//! │  Instance (key=0): Sensor-0 readings                    │
//! │  Instance (key=1): Sensor-1 readings                    │
//! │  Instance (key=2): Sensor-2 readings                    │
//! └─────────────────────────────────────────────────────────┘
//! ```
//!
//! Each instance maintains:
//! - Independent lifecycle (can be disposed/unregistered separately)
//! - Separate history (KEEP_LAST applies per-instance)
//! - QoS tracking (deadline, liveliness per-instance)
//!
//! ## Use Cases
//!
//! - **Sensor networks**: Each sensor has its own instance
//! - **Fleet tracking**: Each vehicle is an instance
//! - **Stock tickers**: Each symbol is an instance
//! - **Game state**: Each player/entity is an instance
//!
//! ## IDL Definition
//!
//! ```idl
//! struct KeyedData {
//!     @key long id;           // <-- @key annotation marks the key field
//!     string data;
//!     unsigned long sequence_num;
//! };
//! ```
//!
//! ## Running the Sample
//!
//! ```bash
//! # Terminal 1 - Subscriber (tracks per-instance state)
//! cargo run --bin instance_keys
//!
//! # Terminal 2 - Publisher (updates 3 sensor instances)
//! cargo run --bin instance_keys -- pub
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
    include!("../../generated/keyed_data.rs");
}

use generated::hdds_samples::KeyedData;

/// Number of sensor instances to simulate
const NUM_INSTANCES: i32 = 3;

// =============================================================================
// Publisher
// =============================================================================

/// Publishes updates for multiple sensor instances.
///
/// Each sensor (instance) gets 5 updates with incrementing sequence numbers.
/// The key field (`id`) identifies which sensor the data belongs to.
fn run_publisher(participant: &Arc<hdds::Participant>) -> Result<(), hdds::Error> {
    let writer = participant.create_writer::<KeyedData>("SensorTopic", hdds::QoS::default())?;

    println!(
        "Publishing updates for {} sensor instances...\n",
        NUM_INSTANCES
    );

    // -------------------------------------------------------------------------
    // Publish to Multiple Instances
    // -------------------------------------------------------------------------
    //
    // Even though we use one writer and one topic, DDS tracks each key value
    // as a separate instance. Subscribers can filter or process by instance.

    for seq in 0..5u32 {
        for sensor_id in 0..NUM_INSTANCES {
            let msg = KeyedData::new(
                sensor_id,
                format!("Sensor-{} reading #{}", sensor_id, seq),
                seq,
            );

            writer.write(&msg)?;
            println!("  [Sensor {}] seq={} -> \"{}\"", sensor_id, seq, msg.data);
        }

        println!(); // Visual separation between rounds
        thread::sleep(Duration::from_millis(500));
    }

    println!("Publisher finished. Sent {} updates per instance.", 5);
    Ok(())
}

// =============================================================================
// Subscriber
// =============================================================================

/// Receives and tracks state for each sensor instance.
///
/// Demonstrates how to:
/// - Process samples from multiple instances
/// - Track per-instance state (last sequence number)
/// - Detect gaps or out-of-order delivery
fn run_subscriber(participant: &Arc<hdds::Participant>) -> Result<(), hdds::Error> {
    let reader = participant.create_reader::<KeyedData>("SensorTopic", hdds::QoS::default())?;

    let waitset = hdds::dds::WaitSet::new();
    waitset.attach_condition(reader.get_status_condition())?;

    // -------------------------------------------------------------------------
    // Per-Instance State Tracking
    // -------------------------------------------------------------------------
    //
    // In a real application, you might track:
    // - Last received timestamp (for staleness detection)
    // - Running statistics (min, max, avg)
    // - Alert thresholds

    let mut instance_state: HashMap<i32, i32> = HashMap::new();
    for i in 0..NUM_INSTANCES {
        instance_state.insert(i, -1); // -1 = no data received yet
    }

    println!("Subscribing to {} sensor instances...\n", NUM_INSTANCES);

    let total_expected = NUM_INSTANCES * 5;
    let mut received = 0;

    while received < total_expected {
        match waitset.wait(Some(Duration::from_secs(3))) {
            Ok(triggered) if !triggered.is_empty() => {
                while let Some(msg) = reader.take().ok().flatten() {
                    // Track the previous sequence number for this instance
                    let prev_seq = *instance_state.get(&msg.id).unwrap_or(&-1);
                    instance_state.insert(msg.id, msg.sequence_num as i32);

                    // Display with gap detection
                    let gap_indicator = if prev_seq >= 0 && msg.sequence_num as i32 != prev_seq + 1
                    {
                        " [GAP!]"
                    } else {
                        ""
                    };

                    println!(
                        "  [Sensor {}] seq={} (prev={}) -> \"{}\"{}",
                        msg.id, msg.sequence_num, prev_seq, msg.data, gap_indicator
                    );

                    received += 1;
                }
            }
            Ok(_) | Err(hdds::Error::WouldBlock) => {
                println!("  (waiting for sensor data...)");
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
    println!("Final instance states:");

    let mut keys: Vec<_> = instance_state.keys().collect();
    keys.sort();
    for id in keys {
        println!("  Sensor {}: last_seq={}", id, instance_state[id]);
    }

    println!(
        "\nSubscriber finished. Received {} total samples.",
        received
    );
    Ok(())
}

// =============================================================================
// Main
// =============================================================================

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let is_publisher = args.get(1).map(|s| s == "pub").unwrap_or(false);

    println!("{}", "=".repeat(60));
    println!("HDDS Instance Keys Sample");
    println!("Demonstrates keyed instances for {} sensors", NUM_INSTANCES);
    println!("{}\n", "=".repeat(60));

    let participant = hdds::Participant::builder("InstanceKeysDemo")
        .with_transport(hdds::TransportMode::IntraProcess)
        .build()?;

    println!("Participant: {}", participant.name());
    println!("Topic: SensorTopic (keyed by sensor_id)\n");

    if is_publisher {
        run_publisher(&participant)?;
    } else {
        run_subscriber(&participant)?;
    }

    Ok(())
}
