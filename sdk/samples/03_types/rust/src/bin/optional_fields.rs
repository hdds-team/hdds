// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! # HDDS Sample: Optional Fields
//!
//! Demonstrates **optional field** support in DDS/IDL using the `@optional`
//! annotation - fields that may or may not be present in a sample.
//!
//! ## Required vs Optional
//!
//! ```text
//! ┌───────────────────────────────────────────────────────────────────┐
//! │ Attribute   │ Required           │ Optional (@optional)          │
//! ├─────────────┼────────────────────┼───────────────────────────────┤
//! │ Presence    │ Always present     │ May be absent                 │
//! │ Rust type   │ T                  │ Option<T>                     │
//! │ Wire size   │ Full size          │ 1-bit flag + data if present  │
//! │ Default     │ Must be set        │ None / not sent               │
//! └───────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Wire Format
//!
//! ```text
//! Sample with all optional fields:   Sample with partial fields:
//! ┌────────────────────────────────┐ ┌────────────────────────────┐
//! │ required_id: 1                 │ │ required_id: 2             │
//! │ [present] name: "FullRecord"   │ │ [absent] name              │
//! │ [present] value: 3.14159       │ │ [absent] value             │
//! │ [present] data: [1,2,3,4,5]    │ │ [absent] data              │
//! └────────────────────────────────┘ └────────────────────────────┘
//!
//! Partial fields save bandwidth when data is sparse!
//! ```
//!
//! ## IDL Definition
//!
//! ```idl
//! struct OptionalFields {
//!     long required_id;                    // Always present
//!
//!     @optional string optional_name;      // May be absent
//!     @optional double optional_value;     // May be absent
//!     @optional sequence<long> optional_data; // May be absent
//! };
//! ```
//!
//! ## Rust Usage
//!
//! ```rust
//! // Building with optional fields
//! OptionalFields::builder()
//!     .required_id(1)
//!     .optional_name("Value")  // Sets Some("Value")
//!     .build();                // optional_value and data are None
//!
//! // Reading optional fields
//! if let Some(ref name) = data.optional_name {
//!     println!("Name: {}", name);
//! } else {
//!     println!("Name: (absent)");
//! }
//! ```
//!
//! ## Use Cases
//!
//! - **Sparse data**: Only send fields that changed
//! - **Backwards compatibility**: Add new optional fields safely
//! - **Partial updates**: Delta updates instead of full state
//!
//! ## Running the Sample
//!
//! ```bash
//! # Terminal 1 - Subscriber
//! cargo run --bin optional_fields
//!
//! # Terminal 2 - Publisher
//! cargo run --bin optional_fields -- pub
//! ```

use std::env;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

// Include generated type
#[allow(dead_code)]
mod generated {
    include!("../../generated/optional.rs");
}

use generated::hdds_samples::OptionalFields;

fn run_publisher(participant: &Arc<hdds::Participant>) -> Result<(), hdds::Error> {
    println!("Creating writer...");
    let writer =
        participant.create_writer::<OptionalFields>("OptionalTopic", hdds::QoS::reliable())?;

    println!("Publishing optional field samples...\n");

    let samples = [
        // All fields present
        OptionalFields::builder()
            .required_id(1)
            .optional_name("FullRecord")
            .optional_value(std::f64::consts::PI)
            .optional_data(vec![1, 2, 3, 4, 5])
            .build()
            .expect("build"),
        // Only required field
        OptionalFields::builder()
            .required_id(2)
            .build()
            .expect("build"),
        // Partial - name only
        OptionalFields::builder()
            .required_id(3)
            .optional_name("NameOnly")
            .build()
            .expect("build"),
    ];

    for (i, data) in samples.iter().enumerate() {
        writer.write(data)?;
        println!("Published sample {}:", i);
        println!("  required_id:    {}", data.required_id);
        println!("  optional_name:  {:?}", data.optional_name);
        println!("  optional_value: {:?}", data.optional_value);
        println!("  optional_data:  {:?}", data.optional_data);
        println!();
        thread::sleep(Duration::from_millis(500));
    }

    println!("Done publishing.");
    Ok(())
}

fn run_subscriber(participant: &Arc<hdds::Participant>) -> Result<(), hdds::Error> {
    println!("Creating reader...");
    let reader =
        participant.create_reader::<OptionalFields>("OptionalTopic", hdds::QoS::reliable())?;

    let status_condition = reader.get_status_condition();
    let waitset = hdds::dds::WaitSet::new();
    waitset.attach_condition(status_condition)?;

    println!("Waiting for optional field samples...\n");

    let mut received = 0;
    while received < 3 {
        match waitset.wait(Some(Duration::from_secs(5))) {
            Ok(triggered) => {
                if !triggered.is_empty() {
                    while let Some(data) = reader.take()? {
                        received += 1;
                        println!("Received sample {}:", received);
                        println!("  required_id: {}", data.required_id);

                        // Check which optional fields are present
                        if let Some(ref name) = data.optional_name {
                            println!("  name: \"{}\"", name);
                        } else {
                            println!("  name: (absent)");
                        }

                        if let Some(value) = data.optional_value {
                            println!("  value: {:.6}", value);
                        } else {
                            println!("  value: (absent)");
                        }

                        if let Some(ref data_vec) = data.optional_data {
                            println!("  data: {:?}", data_vec);
                        } else {
                            println!("  data: (absent)");
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
    println!("Optional Fields Demo");
    println!("Demonstrates: @optional annotation for omittable fields");
    println!("{}", "=".repeat(60));

    let participant = hdds::Participant::builder("OptionalFieldsDemo")
        .with_transport(hdds::TransportMode::UdpMulticast)
        .build()?;

    if is_publisher {
        run_publisher(&participant)?;
    } else {
        run_subscriber(&participant)?;
    }

    Ok(())
}
