// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! # HDDS Sample: Sequence Types
//!
//! Demonstrates **sequence** support in DDS/IDL - variable-length collections
//! that can grow and shrink dynamically.
//!
//! ## Sequence Variants
//!
//! ```text
//! ┌───────────────────────────────────────────────────────────────────┐
//! │ Type                │ IDL Syntax         │ Rust Mapping          │
//! ├─────────────────────┼────────────────────┼───────────────────────┤
//! │ Unbounded sequence  │ sequence<long>     │ Vec<i32>              │
//! │ Bounded sequence    │ sequence<long, 100>│ Vec<i32> (max 100)    │
//! │ Nested sequence     │ sequence<sequence> │ Vec<Vec<T>>           │
//! └───────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Memory Layout
//!
//! ```text
//! Unbounded sequence<long>:        Bounded sequence<long, 5>:
//! ┌──────────────────────────┐    ┌─────────────────┐
//! │ Capacity: dynamic        │    │ Capacity: ≤ 5   │
//! │ Length: varies           │    │ Length: varies  │
//! ├──────────────────────────┤    ├─────────────────┤
//! │ 1 │ 2 │ 3 │ ... │ N     │    │ 1 │ 2 │ 3 │ _ │ │
//! └──────────────────────────┘    └─────────────────┘
//!   Can grow indefinitely          Capped at 5 elements
//! ```
//!
//! ## IDL Definition
//!
//! ```idl
//! struct Sequences {
//!     sequence<long>       numbers;         // Unbounded
//!     sequence<string>     names;           // Unbounded strings
//!     sequence<long, 10>   bounded_numbers; // Max 10 elements
//! };
//! ```
//!
//! ## Use Cases
//!
//! - **Variable sensor data**: Dynamic number of readings
//! - **Lists**: Collections that grow/shrink at runtime
//! - **Batch processing**: Variable-size data batches
//!
//! ## Running the Sample
//!
//! ```bash
//! # Terminal 1 - Subscriber
//! cargo run --bin sequences
//!
//! # Terminal 2 - Publisher
//! cargo run --bin sequences -- pub
//! ```

use std::env;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

// Include generated type
#[allow(dead_code)]
mod generated {
    include!("../../generated/sequences.rs");
}

use generated::hdds_samples::Sequences;

fn run_publisher(participant: &Arc<hdds::Participant>) -> Result<(), hdds::Error> {
    println!("Creating writer...");
    let writer = participant.create_writer::<Sequences>("SequencesTopic", hdds::QoS::reliable())?;

    println!("Publishing sequence samples...\n");

    let samples = [
        Sequences::builder()
            .numbers(vec![1, 2, 3, 4, 5])
            .names(vec![
                "Alice".to_string(),
                "Bob".to_string(),
                "Charlie".to_string(),
            ])
            .bounded_numbers(vec![10, 20, 30])
            .build()
            .expect("build"),
        Sequences::builder()
            .numbers(vec![-100, 0, 100, 1000])
            .names(vec!["Single".to_string()])
            .bounded_numbers(vec![])
            .build()
            .expect("build"),
        Sequences::builder()
            .numbers(vec![])
            .names(vec![])
            .bounded_numbers(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10])
            .build()
            .expect("build"),
    ];

    for (i, data) in samples.iter().enumerate() {
        writer.write(data)?;
        println!("Published sample {}:", i);
        println!("  numbers: {:?} (len={})", data.numbers, data.numbers.len());
        println!("  names: {:?} (len={})", data.names, data.names.len());
        println!(
            "  bounded: {:?} (len={})",
            data.bounded_numbers,
            data.bounded_numbers.len()
        );
        println!();
        thread::sleep(Duration::from_millis(500));
    }

    println!("Done publishing.");
    Ok(())
}

fn run_subscriber(participant: &Arc<hdds::Participant>) -> Result<(), hdds::Error> {
    println!("Creating reader...");
    let reader = participant.create_reader::<Sequences>("SequencesTopic", hdds::QoS::reliable())?;

    let status_condition = reader.get_status_condition();
    let waitset = hdds::dds::WaitSet::new();
    waitset.attach_condition(status_condition)?;

    println!("Waiting for sequence samples...\n");

    let mut received = 0;
    while received < 3 {
        match waitset.wait(Some(Duration::from_secs(5))) {
            Ok(triggered) => {
                if !triggered.is_empty() {
                    while let Some(data) = reader.take()? {
                        received += 1;
                        println!("Received sample {}:", received);
                        println!("  numbers: {:?}", data.numbers);
                        println!("  names: {:?}", data.names);
                        println!("  bounded: {:?}", data.bounded_numbers);
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
    println!("Sequence Types Demo");
    println!("Demonstrates: Vec<T>, bounded sequences");
    println!("{}", "=".repeat(60));

    let participant = hdds::Participant::builder("SequencesDemo")
        .with_transport(hdds::TransportMode::UdpMulticast)
        .build()?;

    if is_publisher {
        run_publisher(&participant)?;
    } else {
        run_subscriber(&participant)?;
    }

    Ok(())
}
