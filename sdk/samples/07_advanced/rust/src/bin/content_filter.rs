// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! # HDDS Sample: Content Filter
//!
//! Demonstrates **content-filtered topics** - SQL-like filtering that lets
//! subscribers receive only data matching specified criteria.
//!
//! ## How Content Filtering Works
//!
//! ```text
//! Publisher sends ALL data:              Subscriber with filter:
//! ┌────────────────────────┐            ┌────────────────────────┐
//! │ sensor_id=1, temp=22   │───┐        │ Filter: temp > 30      │
//! │ sensor_id=2, temp=35 ← │───┼────────│                        │
//! │ sensor_id=3, temp=28   │───┤        │ Only receives:         │
//! │ sensor_id=4, temp=40 ← │───┼────────│   - sensor_id=2 (35°)  │
//! │ sensor_id=5, temp=31 ← │───┘        │   - sensor_id=4 (40°)  │
//! └────────────────────────┘            │   - sensor_id=5 (31°)  │
//!                                       └────────────────────────┘
//!      ← Matching samples only
//! ```
//!
//! ## Filter Expression Syntax
//!
//! | Expression                 | Description                    |
//! |----------------------------|--------------------------------|
//! | `temperature > 25.0`       | Comparison operators           |
//! | `location = 'Room1'`       | String equality                |
//! | `sensor_id BETWEEN 1 AND 10`| Range check                   |
//! | `humidity > %0`            | Parameterized (runtime value)  |
//! | `location LIKE 'Building%'`| Pattern matching (wildcards)   |
//! | `status = 'ACTIVE' AND priority > 5` | Logical AND/OR    |
//!
//! ## Benefits
//!
//! ```text
//! Without Filter:                With Filter:
//! ┌────────────────────────────┐ ┌────────────────────────────┐
//! │ Publisher sends all data   │ │ Publisher sends all data   │
//! │           ↓                │ │           ↓                │
//! │ Network transmits ALL      │ │ Middleware filters BEFORE  │
//! │           ↓                │ │ transmission               │
//! │ Subscriber processes ALL   │ │           ↓                │
//! │ (wastes CPU)               │ │ Only matching data sent    │
//! └────────────────────────────┘ └────────────────────────────┘
//! ```
//!
//! ## Running the Sample
//!
//! ```bash
//! # Terminal 1 - Subscriber (filter: temperature > 30)
//! cargo run --bin content_filter
//!
//! # Terminal 2 - Publisher (sends all temperatures)
//! cargo run --bin content_filter -- pub
//! ```
//!
//! **NOTE: CONCEPT DEMO** - This sample demonstrates the APPLICATION PATTERN for ContentFilteredTopic.
//! The native ContentFilteredTopic API is not yet exported to the SDK.
//! This sample uses standard participant/writer/reader API to show the concept.

use std::env;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

// =============================================================================
// Generated Types
// =============================================================================

#[allow(dead_code)]
mod generated {
    include!("../../generated/sensor_data.rs");
}

use generated::SensorData;

fn print_filter_info() {
    println!("--- Content Filter Overview ---\n");
    println!("Content filters use SQL-like WHERE clause syntax:\n");
    println!("  Filter Expression          | Description");
    println!("  ---------------------------|---------------------------");
    println!("  temperature > 25.0         | High temperature readings");
    println!("  location = 'Room1'         | Specific location only");
    println!("  sensor_id BETWEEN 1 AND 10 | Sensor ID range");
    println!("  humidity > %0              | Parameterized threshold");
    println!("  location LIKE 'Building%'  | Pattern matching");
    println!();
}

fn run_publisher(participant: &Arc<hdds::Participant>) -> Result<(), hdds::Error> {
    println!("[Publisher] Creating writer...");
    let writer =
        participant.create_writer::<SensorData>("SensorDataTopic", hdds::QoS::default())?;

    println!("[Publisher] Publishing sensor data from multiple locations...\n");

    let locations = ["ServerRoom", "Office1", "Lobby", "DataCenter"];
    let mut sensor_id = 1u32;

    // Generate and publish sensor data
    for round in 0..3 {
        println!("--- Round {} ---", round + 1);
        for loc in &locations {
            // Generate somewhat random temperature and humidity
            let temp = 20.0 + (sensor_id as f32 * 3.7) % 20.0;
            let hum = 40.0 + (sensor_id as f32 * 5.3) % 40.0;

            let data = SensorData::new(sensor_id, *loc, temp, hum);
            writer.write(&data)?;

            println!(
                "  [SENT] sensor={}, loc={}, temp={:.1}, hum={:.1}",
                data.sensor_id, data.location, data.temperature, data.humidity
            );

            sensor_id += 1;
            thread::sleep(Duration::from_millis(100));
        }
        println!();
    }

    println!("[Publisher] Done. Published {} samples.", sensor_id - 1);
    Ok(())
}

fn run_subscriber(participant: &Arc<hdds::Participant>) -> Result<(), Box<dyn std::error::Error>> {
    println!("[Subscriber] Creating reader with content filter...");

    // Create content filtered topic for high temperature readings
    let filtered_topic = participant.create_content_filtered_topic::<SensorData>(
        "HighTempSensors",
        "SensorDataTopic",
        "temperature > %0",
        vec!["30.0".to_string()],
    )?;

    // Create reader from filtered topic
    let reader = filtered_topic.reader().build()?;

    let waitset = hdds::WaitSet::new();
    waitset.attach(&reader)?;

    println!("[Subscriber] Filter: temperature > 30.0");
    println!("[Subscriber] Only high-temperature readings will be received.\n");

    println!("--- Waiting for filtered data ---\n");

    let mut received = 0;
    let mut timeouts = 0;

    while timeouts < 3 {
        match waitset.wait(Some(Duration::from_secs(2))) {
            Ok(triggered) => {
                if !triggered.is_empty() {
                    while let Some(sensor) = reader.take()? {
                        println!(
                            "  [RECV] sensor={}, loc={}, temp={:.1}, hum={:.1}",
                            sensor.sensor_id, sensor.location, sensor.temperature, sensor.humidity
                        );
                        received += 1;
                    }
                    timeouts = 0; // Reset on successful receive
                }
            }
            Err(hdds::Error::WouldBlock) => {
                println!("  (timeout - waiting for data...)");
                timeouts += 1;
            }
            Err(e) => {
                eprintln!("Wait error: {:?}", e);
                break;
            }
        }
    }

    println!(
        "\n[Subscriber] Received {} samples matching filter.",
        received
    );
    println!("[Subscriber] Non-matching samples were filtered at the source.");
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let is_publisher = args.get(1).map(|s| s == "pub").unwrap_or(false);

    println!("{}", "=".repeat(60));
    println!("HDDS Content Filter Sample");
    println!("{}", "=".repeat(60));
    println!();
    println!("NOTE: CONCEPT DEMO - Native ContentFilteredTopic API not yet in SDK.");
    println!("      Using standard pub/sub API to demonstrate the pattern.\n");

    print_filter_info();

    let participant = hdds::Participant::builder("ContentFilterDemo")
        .with_transport(hdds::TransportMode::IntraProcess)
        .build()?;
    println!("[OK] Participant created\n");

    if is_publisher {
        run_publisher(&participant)?;
    } else {
        run_subscriber(&participant)?;
    }

    // Benefits summary
    println!("\n--- Content Filter Benefits ---");
    println!("1. Network Efficiency: Filtering at source reduces traffic");
    println!("2. CPU Efficiency: Subscriber processes only relevant data");
    println!("3. Flexibility: SQL-like expressions for complex filters");
    println!("4. Dynamic Updates: Change filters without recreating readers");
    println!("5. Parameterization: Use %0, %1 for runtime values");

    println!("\n=== Sample Complete ===");
    Ok(())
}
