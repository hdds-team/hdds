// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! # HDDS Sample: Map Types
//!
//! Demonstrates **map** type support in DDS/IDL - key-value associative
//! containers for efficient lookups.
//!
//! ## Map Syntax
//!
//! ```text
//! ┌───────────────────────────────────────────────────────────────────┐
//! │ IDL Syntax              │ Rust Mapping            │ Bound         │
//! ├─────────────────────────┼─────────────────────────┼───────────────┤
//! │ map<string, long>       │ HashMap<String, i32>    │ Unbounded     │
//! │ map<long, string>       │ HashMap<i32, String>    │ Unbounded     │
//! │ map<string, long, 100>  │ HashMap<String, i32>    │ Max 100 pairs │
//! └───────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Map Structure
//!
//! ```text
//! map<string, long> scores:
//! ┌─────────────────────────────┐
//! │ Key          │ Value        │
//! ├──────────────┼──────────────┤
//! │ "Alice"      │ 100          │
//! │ "Bob"        │ 85           │
//! │ "Charlie"    │ 92           │
//! └─────────────────────────────┘
//!
//! map<long, string> labels:
//! ┌─────────────────────────────┐
//! │ Key    │ Value              │
//! ├────────┼────────────────────┤
//! │ 1      │ "First"            │
//! │ 2      │ "Second"           │
//! │ 42     │ "The Answer"       │
//! └─────────────────────────────┘
//! ```
//!
//! ## IDL Definition
//!
//! ```idl
//! struct Maps {
//!     map<string, long>   scores;   // Name -> score mapping
//!     map<long, string>   labels;   // ID -> label mapping
//! };
//! ```
//!
//! ## Use Cases
//!
//! - **Configuration**: String key -> value lookups
//! - **Localization**: Language ID -> translated string
//! - **Metadata**: Flexible attribute storage
//!
//! ## Running the Sample
//!
//! ```bash
//! # Terminal 1 - Subscriber
//! cargo run --bin maps
//!
//! # Terminal 2 - Publisher
//! cargo run --bin maps -- pub
//! ```

use std::collections::HashMap;
use std::env;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

// Include generated type
#[allow(dead_code)]
mod generated {
    include!("../../generated/maps.rs");
}

use generated::hdds_samples::Maps;

fn run_publisher(participant: &Arc<hdds::Participant>) -> Result<(), hdds::Error> {
    println!("Creating writer...");
    let writer = participant.create_writer::<Maps>("MapsTopic", hdds::QoS::reliable())?;

    println!("Publishing map samples...\n");

    let samples = [
        {
            let mut scores = HashMap::new();
            scores.insert("Alice".to_string(), 100);
            scores.insert("Bob".to_string(), 85);
            scores.insert("Charlie".to_string(), 92);

            let mut labels = HashMap::new();
            labels.insert(1, "First".to_string());
            labels.insert(2, "Second".to_string());
            labels.insert(3, "Third".to_string());

            Maps::builder()
                .scores(scores)
                .labels(labels)
                .build()
                .expect("build")
        },
        {
            let mut scores = HashMap::new();
            scores.insert("Player1".to_string(), 1000);

            let mut labels = HashMap::new();
            labels.insert(42, "The Answer".to_string());

            Maps::builder()
                .scores(scores)
                .labels(labels)
                .build()
                .expect("build")
        },
        {
            Maps::builder()
                .scores(HashMap::new())
                .labels(HashMap::new())
                .build()
                .expect("build")
        },
    ];

    for (i, data) in samples.iter().enumerate() {
        writer.write(data)?;
        println!("Published sample {}:", i);
        println!("  scores ({} entries):", data.scores.len());
        for (k, v) in &data.scores {
            println!("    \"{}\" => {}", k, v);
        }
        println!("  labels ({} entries):", data.labels.len());
        for (k, v) in &data.labels {
            println!("    {} => \"{}\"", k, v);
        }
        println!();
        thread::sleep(Duration::from_millis(500));
    }

    println!("Done publishing.");
    Ok(())
}

fn run_subscriber(participant: &Arc<hdds::Participant>) -> Result<(), hdds::Error> {
    println!("Creating reader...");
    let reader = participant.create_reader::<Maps>("MapsTopic", hdds::QoS::reliable())?;

    let status_condition = reader.get_status_condition();
    let waitset = hdds::dds::WaitSet::new();
    waitset.attach_condition(status_condition)?;

    println!("Waiting for map samples...\n");

    let mut received = 0;
    while received < 3 {
        match waitset.wait(Some(Duration::from_secs(5))) {
            Ok(triggered) => {
                if !triggered.is_empty() {
                    while let Some(data) = reader.take()? {
                        received += 1;
                        println!("Received sample {}:", received);
                        println!("  scores ({} entries):", data.scores.len());
                        for (k, v) in &data.scores {
                            println!("    \"{}\" => {}", k, v);
                        }
                        println!("  labels ({} entries):", data.labels.len());
                        for (k, v) in &data.labels {
                            println!("    {} => \"{}\"", k, v);
                        }
                        println!();
                    }
                }
            }
            Err(hdds::Error::WouldBlock) => {
                println!("  (timeout - no data)");
            }
            Err(e) => {
                eprintln!("Wait error: {:?}", e);
            }
        }
    }

    println!("Done receiving.");
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let is_publisher = args.get(1).map(|s| s == "pub").unwrap_or(false);

    println!("{}", "=".repeat(60));
    println!("Map Types Demo");
    println!("Demonstrates: String->Long and Long->String maps");
    println!("{}", "=".repeat(60));

    let participant = hdds::Participant::builder("MapsDemo")
        .with_transport(hdds::TransportMode::UdpMulticast)
        .build()?;

    if is_publisher {
        run_publisher(&participant)?;
    } else {
        run_subscriber(&participant)?;
    }

    Ok(())
}
