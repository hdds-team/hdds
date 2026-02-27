// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! # HDDS Sample: Enum Types
//!
//! Demonstrates **enumeration** type support in DDS/IDL - named constants
//! for type-safe, self-documenting code.
//!
//! ## Enum Definition Styles
//!
//! ```text
//! Sequential (default):            Explicit values:
//! ┌─────────────────────┐         ┌─────────────────────────┐
//! │ enum Color {        │         │ enum Status {           │
//! │   RED,    // = 0    │         │   UNKNOWN = 0,          │
//! │   GREEN,  // = 1    │         │   ACTIVE  = 100,        │
//! │   BLUE    // = 2    │         │   ERROR   = -1          │
//! │ };                  │         │ };                      │
//! └─────────────────────┘         └─────────────────────────┘
//! ```
//!
//! ## Wire Format
//!
//! ```text
//! Enums are serialized as their underlying integer value:
//!
//! Color::Green → [0x01, 0x00, 0x00, 0x00]  (little-endian i32)
//!
//! This enables:
//! - Compact wire representation
//! - Cross-language compatibility
//! - Version evolution (add new values)
//! ```
//!
//! ## IDL Definition
//!
//! ```idl
//! // Sequential values: RED=0, GREEN=1, BLUE=2
//! enum Color { RED, GREEN, BLUE };
//!
//! // Explicit values for API stability
//! enum Status {
//!     UNKNOWN = 0,
//!     ACTIVE  = 100,
//!     ERROR   = -1
//! };
//!
//! struct Enums {
//!     Color  color;
//!     Status status;
//! };
//! ```
//!
//! ## Use Cases
//!
//! - **State machines**: IDLE, RUNNING, PAUSED, STOPPED
//! - **Error codes**: Named error constants
//! - **Categories**: Classification with type safety
//!
//! ## Running the Sample
//!
//! ```bash
//! # Terminal 1 - Subscriber
//! cargo run --bin enums
//!
//! # Terminal 2 - Publisher
//! cargo run --bin enums -- pub
//! ```

use std::env;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

// Include generated type
#[allow(dead_code)]
mod generated {
    include!("../../generated/enums.rs");
}

use generated::hdds_samples::{Color, Enums, Status};

fn run_publisher(participant: &Arc<hdds::Participant>) -> Result<(), hdds::Error> {
    println!("Creating writer...");
    let writer = participant.create_writer::<Enums>("EnumsTopic", hdds::QoS::reliable())?;

    println!("Publishing enum samples...\n");

    let samples = [
        Enums::builder()
            .color(Color::Red)
            .status(Status::Unknown)
            .build()
            .expect("build"),
        Enums::builder()
            .color(Color::Green)
            .status(Status::Active)
            .build()
            .expect("build"),
        Enums::builder()
            .color(Color::Blue)
            .status(Status::Error)
            .build()
            .expect("build"),
    ];

    for (i, data) in samples.iter().enumerate() {
        writer.write(data)?;
        println!("Published sample {}:", i);
        println!("  color:  {:?} (value={})", data.color, data.color as u32);
        println!("  status: {:?} (value={})", data.status, data.status as u32);
        println!();
        thread::sleep(Duration::from_millis(500));
    }

    println!("Done publishing.");
    Ok(())
}

fn run_subscriber(participant: &Arc<hdds::Participant>) -> Result<(), hdds::Error> {
    println!("Creating reader...");
    let reader = participant.create_reader::<Enums>("EnumsTopic", hdds::QoS::reliable())?;

    let status_condition = reader.get_status_condition();
    let waitset = hdds::dds::WaitSet::new();
    waitset.attach_condition(status_condition)?;

    println!("Waiting for enum samples...\n");

    let mut received = 0;
    while received < 3 {
        match waitset.wait(Some(Duration::from_secs(5))) {
            Ok(triggered) => {
                if !triggered.is_empty() {
                    while let Some(data) = reader.take()? {
                        received += 1;
                        println!("Received sample {}:", received);
                        println!("  color:  {:?}", data.color);
                        println!("  status: {:?}", data.status);
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
    println!("Enum Types Demo");
    println!("Demonstrates: Color (sequential), Status (explicit values)");
    println!("{}", "=".repeat(60));

    let participant = hdds::Participant::builder("EnumsDemo")
        .with_transport(hdds::TransportMode::UdpMulticast)
        .build()?;

    if is_publisher {
        run_publisher(&participant)?;
    } else {
        run_subscriber(&participant)?;
    }

    Ok(())
}
