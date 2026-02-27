// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! # HDDS Sample: Array Types
//!
//! Demonstrates **fixed-size array** support in DDS/IDL - collections with
//! compile-time known dimensions.
//!
//! ## Arrays vs Sequences
//!
//! ```text
//! ┌────────────────────────────────────────────────────────────────────┐
//! │ Type      │ IDL Syntax       │ Rust Mapping    │ Size            │
//! ├───────────┼──────────────────┼─────────────────┼─────────────────┤
//! │ Array     │ long nums[10]    │ [i32; 10]       │ Fixed at 10     │
//! │ Sequence  │ sequence<long>   │ Vec<i32>        │ Variable        │
//! │ Bounded   │ sequence<long,10>│ Vec<i32>        │ Max 10          │
//! └────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Multi-Dimensional Arrays
//!
//! ```text
//! 1D Array:           2D Array (Matrix):      3D Array:
//! ┌─────────────┐    ┌───┬───┬───┐           ┌───────────┐
//! │ 1 2 3 4 5   │    │ 1 │ 0 │ 0 │  row 0    │  Layer 0  │
//! └─────────────┘    ├───┼───┼───┤           ├───────────┤
//!                    │ 0 │ 1 │ 0 │  row 1    │  Layer 1  │
//!                    ├───┼───┼───┤           └───────────┘
//!                    │ 0 │ 0 │ 1 │  row 2
//!                    └───┴───┴───┘
//! ```
//!
//! ## IDL Definition
//!
//! ```idl
//! struct Arrays {
//!     long numbers[10];              // Fixed 10 integers
//!     string names[3];               // Fixed 3 strings
//!     double transform[3][3];        // 3x3 matrix
//! };
//! ```
//!
//! ## Use Cases
//!
//! - **Sensor arrays**: Fixed number of sensor readings
//! - **Transform matrices**: 3x3, 4x4 transformation matrices (robotics, graphics)
//! - **Configuration**: Fixed set of parameters
//!
//! ## Running the Sample
//!
//! ```bash
//! # Terminal 1 - Subscriber
//! cargo run --bin arrays
//!
//! # Terminal 2 - Publisher
//! cargo run --bin arrays -- pub
//! ```

use std::env;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

// Include generated type
#[allow(dead_code)]
mod generated {
    include!("../../generated/arrays.rs");
}

use generated::hdds_samples::Arrays;

#[allow(clippy::useless_vec)]
fn run_publisher(participant: &Arc<hdds::Participant>) -> Result<(), hdds::Error> {
    println!("Creating writer...");
    let writer = participant.create_writer::<Arrays>("ArraysTopic", hdds::QoS::reliable())?;

    println!("Publishing array samples...\n");

    let samples = vec![
        Arrays::builder()
            .numbers(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10])
            .names(vec![
                "Alpha".to_string(),
                "Beta".to_string(),
                "Gamma".to_string(),
            ])
            .transform(vec![
                vec![1.0, 0.0, 0.0],
                vec![0.0, 1.0, 0.0],
                vec![0.0, 0.0, 1.0],
            ])
            .build()
            .expect("build"),
        Arrays::builder()
            .numbers(vec![10, 20, 30])
            .names(vec!["One".to_string()])
            .transform(vec![
                vec![2.0, 0.0, 0.0],
                vec![0.0, 2.0, 0.0],
                vec![0.0, 0.0, 2.0],
            ])
            .build()
            .expect("build"),
        Arrays::builder()
            .numbers(vec![])
            .names(vec![])
            .transform(vec![])
            .build()
            .expect("build"),
    ];

    for (i, data) in samples.iter().enumerate() {
        writer.write(data)?;
        println!("Published sample {}:", i);
        println!("  numbers: {:?} (len={})", data.numbers, data.numbers.len());
        println!("  names: {:?} (len={})", data.names, data.names.len());
        println!(
            "  transform: {:?} ({}x rows)",
            data.transform,
            data.transform.len()
        );
        println!();
        thread::sleep(Duration::from_millis(500));
    }

    println!("Done publishing.");
    Ok(())
}

fn run_subscriber(participant: &Arc<hdds::Participant>) -> Result<(), hdds::Error> {
    println!("Creating reader...");
    let reader = participant.create_reader::<Arrays>("ArraysTopic", hdds::QoS::reliable())?;

    let status_condition = reader.get_status_condition();
    let waitset = hdds::dds::WaitSet::new();
    waitset.attach_condition(status_condition)?;

    println!("Waiting for array samples...\n");

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
                        println!("  transform:");
                        for (i, row) in data.transform.iter().enumerate() {
                            println!("    row {}: {:?}", i, row);
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
    println!("Array Types Demo");
    println!("Demonstrates: bounded sequences, nested sequences (matrices)");
    println!("{}", "=".repeat(60));

    let participant = hdds::Participant::builder("ArraysDemo")
        .with_transport(hdds::TransportMode::UdpMulticast)
        .build()?;

    if is_publisher {
        run_publisher(&participant)?;
    } else {
        run_subscriber(&participant)?;
    }

    Ok(())
}
