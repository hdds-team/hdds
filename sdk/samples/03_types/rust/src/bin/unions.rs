// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! # HDDS Sample: Union Types
//!
//! Demonstrates **discriminated union** support in DDS/IDL - tagged variants
//! where a discriminator determines which field is active.
//!
//! ## Union Concept
//!
//! ```text
//! ┌───────────────────────────────────────────────────────────────────┐
//! │ Discriminator │ Active Branch │ Data                              │
//! ├───────────────┼───────────────┼───────────────────────────────────┤
//! │ INTEGER (0)   │ int_val       │ [42 as i32]                       │
//! │ FLOAT   (1)   │ float_val     │ [3.14159 as f64]                  │
//! │ STRING  (2)   │ str_val       │ ["Hello" as String]               │
//! └───────────────────────────────────────────────────────────────────┘
//!
//! Only ONE branch is valid at a time, determined by discriminator!
//! ```
//!
//! ## Memory Efficiency
//!
//! ```text
//! Without union:                   With union:
//! struct DataAll {                 union DataValue switch(DataKind) {
//!   long  int_val;    // 4 bytes     case INTEGER: long   int_val;
//!   double float_val; // 8 bytes     case FLOAT:   double float_val;
//!   string str_val;   // N bytes     case STRING:  string str_val;
//! };                               };
//! Total: 12+N bytes               Total: max(4,8,N) + discriminator
//! ```
//!
//! ## IDL Definition
//!
//! ```idl
//! enum DataKind { INTEGER, FLOAT, STRING };
//!
//! union DataValue switch(DataKind) {
//!     case INTEGER: long   int_val;
//!     case FLOAT:   double float_val;
//!     case STRING:  string str_val;
//! };
//!
//! struct Unions {
//!     DataKind  kind;
//!     DataValue value;
//! };
//! ```
//!
//! ## Rust Pattern Matching
//!
//! ```rust
//! match &data.value {
//!     DataValue::IntVal(i)   => println!("Integer: {}", i),
//!     DataValue::FloatVal(f) => println!("Float: {}", f),
//!     DataValue::StrVal(s)   => println!("String: {}", s),
//! }
//! ```
//!
//! ## Use Cases
//!
//! - **Protocol messages**: Different message types in one topic
//! - **Variants**: Configuration with different value types
//! - **Polymorphism**: Type-safe heterogeneous data
//!
//! ## Running the Sample
//!
//! ```bash
//! # Terminal 1 - Subscriber
//! cargo run --bin unions
//!
//! # Terminal 2 - Publisher
//! cargo run --bin unions -- pub
//! ```

use std::env;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

// Include generated type
#[allow(dead_code, clippy::enum_variant_names)]
mod generated {
    include!("../../generated/unions.rs");
}

use generated::hdds_samples::{DataKind, DataValue, Unions};

fn run_publisher(participant: &Arc<hdds::Participant>) -> Result<(), hdds::Error> {
    println!("Creating writer...");
    let writer = participant.create_writer::<Unions>("UnionsTopic", hdds::QoS::reliable())?;

    println!("Publishing union samples...\n");

    let samples = [
        Unions::builder()
            .kind(DataKind::Integer)
            .value(DataValue::IntVal(42))
            .build()
            .expect("build"),
        Unions::builder()
            .kind(DataKind::Float)
            .value(DataValue::FloatVal(std::f64::consts::PI))
            .build()
            .expect("build"),
        Unions::builder()
            .kind(DataKind::String)
            .value(DataValue::StrVal("Hello, DDS Unions!".to_string()))
            .build()
            .expect("build"),
    ];

    for (i, data) in samples.iter().enumerate() {
        writer.write(data)?;
        println!("Published sample {}:", i);
        println!("  kind:  {:?}", data.kind);
        println!("  value: {:?}", data.value);
        println!();
        thread::sleep(Duration::from_millis(500));
    }

    println!("Done publishing.");
    Ok(())
}

fn run_subscriber(participant: &Arc<hdds::Participant>) -> Result<(), hdds::Error> {
    println!("Creating reader...");
    let reader = participant.create_reader::<Unions>("UnionsTopic", hdds::QoS::reliable())?;

    let status_condition = reader.get_status_condition();
    let waitset = hdds::dds::WaitSet::new();
    waitset.attach_condition(status_condition)?;

    println!("Waiting for union samples...\n");

    let mut received = 0;
    while received < 3 {
        match waitset.wait(Some(Duration::from_secs(5))) {
            Ok(triggered) => {
                if !triggered.is_empty() {
                    while let Some(data) = reader.take()? {
                        received += 1;
                        println!("Received sample {}:", received);
                        println!("  kind: {:?}", data.kind);

                        // Pattern match on the union value
                        match &data.value {
                            DataValue::IntVal(i) => println!("  value: integer {}", i),
                            DataValue::FloatVal(f) => println!("  value: float {:.6}", f),
                            DataValue::StrVal(s) => println!("  value: string \"{}\"", s),
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
    println!("Union Types Demo");
    println!("Demonstrates: discriminated unions with int/float/string variants");
    println!("{}", "=".repeat(60));

    let participant = hdds::Participant::builder("UnionsDemo")
        .with_transport(hdds::TransportMode::UdpMulticast)
        .build()?;

    if is_publisher {
        run_publisher(&participant)?;
    } else {
        run_subscriber(&participant)?;
    }

    Ok(())
}
