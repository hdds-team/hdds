// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! # HDDS Sample: Primitive Types
//!
//! Demonstrates all **primitive types** supported by DDS/IDL - the foundational
//! building blocks for all data structures in the DDS type system.
//!
//! ## IDL to Rust Type Mapping
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │ IDL Type          │ Rust Type  │ Size   │ Range                 │
//! ├───────────────────┼────────────┼────────┼───────────────────────┤
//! │ boolean           │ bool       │ 1 byte │ true/false            │
//! │ octet             │ u8         │ 1 byte │ 0 to 255              │
//! │ char              │ char       │ 4 byte │ Unicode scalar        │
//! ├───────────────────┼────────────┼────────┼───────────────────────┤
//! │ short             │ i16        │ 2 byte │ -32,768 to 32,767     │
//! │ unsigned short    │ u16        │ 2 byte │ 0 to 65,535           │
//! │ long              │ i32        │ 4 byte │ ±2.1 billion          │
//! │ unsigned long     │ u32        │ 4 byte │ 0 to 4.2 billion      │
//! │ long long         │ i64        │ 8 byte │ ±9.2 quintillion      │
//! │ unsigned long long│ u64        │ 8 byte │ 0 to 18.4 quintillion │
//! ├───────────────────┼────────────┼────────┼───────────────────────┤
//! │ float             │ f32        │ 4 byte │ ~7 decimal digits     │
//! │ double            │ f64        │ 8 byte │ ~15 decimal digits    │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## IDL Definition
//!
//! ```idl
//! struct Primitives {
//!     boolean   bool_val;
//!     octet     octet_val;
//!     char      char_val;
//!     short     short_val;
//!     unsigned short ushort_val;
//!     long      long_val;
//!     unsigned long ulong_val;
//!     long long llong_val;
//!     unsigned long long ullong_val;
//!     float     float_val;
//!     double    double_val;
//! };
//! ```
//!
//! ## Use Cases
//!
//! - **Sensor data**: Temperature (f32), humidity (u8), status flags (bool)
//! - **Counters**: Message sequence (u32), timestamps (i64)
//! - **Identifiers**: Device IDs (u64), error codes (i16)
//!
//! ## Running the Sample
//!
//! ```bash
//! # Terminal 1 - Subscriber (receives primitive data)
//! cargo run --bin primitives
//!
//! # Terminal 2 - Publisher (sends all primitive types)
//! cargo run --bin primitives -- pub
//! ```

use std::env;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

// Include generated type (implements hdds::api::DDS trait)
#[allow(dead_code)]
mod generated {
    include!("../../generated/primitives.rs");
}

use generated::hdds_samples::Primitives;

fn run_publisher(participant: &Arc<hdds::Participant>) -> Result<(), hdds::Error> {
    println!("Creating writer...");
    let writer =
        participant.create_writer::<Primitives>("PrimitivesTopic", hdds::QoS::reliable())?;

    println!("Publishing primitive types samples...\n");

    for i in 0..5 {
        let data = Primitives::builder()
            .bool_val(i % 2 == 0)
            .octet_val((i * 10) as u8)
            .char_val(char::from(b'A' + i as u8))
            .short_val((i * 100) as i16)
            .ushort_val((i * 200) as u16)
            .long_val(i * 1000)
            .ulong_val((i * 2000) as u32)
            .llong_val(i as i64 * 10_000_000_000)
            .ullong_val(i as u64 * 20_000_000_000)
            .float_val(i as f32 * 1.5)
            .double_val(i as f64 * 2.5)
            .build()
            .expect("Failed to build Primitives");

        writer.write(&data)?;

        println!("Published sample {}:", i);
        println!(
            "  bool={}, octet={}, char='{}'",
            data.bool_val, data.octet_val, data.char_val
        );
        println!("  short={}, ushort={}", data.short_val, data.ushort_val);
        println!("  long={}, ulong={}", data.long_val, data.ulong_val);
        println!("  llong={}, ullong={}", data.llong_val, data.ullong_val);
        println!(
            "  float={:.2}, double={:.2}",
            data.float_val, data.double_val
        );
        println!();

        thread::sleep(Duration::from_millis(500));
    }

    println!("Done publishing.");
    Ok(())
}

fn run_subscriber(participant: &Arc<hdds::Participant>) -> Result<(), hdds::Error> {
    println!("Creating reader...");
    let reader =
        participant.create_reader::<Primitives>("PrimitivesTopic", hdds::QoS::reliable())?;

    let status_condition = reader.get_status_condition();
    let waitset = hdds::dds::WaitSet::new();
    waitset.attach_condition(status_condition)?;

    println!("Waiting for primitive types samples...\n");

    let mut received = 0;
    while received < 5 {
        match waitset.wait(Some(Duration::from_secs(5))) {
            Ok(triggered) => {
                if !triggered.is_empty() {
                    while let Some(data) = reader.take()? {
                        received += 1;
                        println!("Received sample {}:", received);
                        println!(
                            "  bool={}, octet={}, char='{}'",
                            data.bool_val, data.octet_val, data.char_val
                        );
                        println!("  short={}, ushort={}", data.short_val, data.ushort_val);
                        println!("  long={}, ulong={}", data.long_val, data.ulong_val);
                        println!("  llong={}, ullong={}", data.llong_val, data.ullong_val);
                        println!(
                            "  float={:.2}, double={:.2}",
                            data.float_val, data.double_val
                        );
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
    println!("Primitive Types Demo");
    println!("Demonstrates: bool, i8-i64, u8-u64, f32, f64, char");
    println!("{}", "=".repeat(60));

    let participant = hdds::Participant::builder("PrimitivesDemo")
        .with_transport(hdds::TransportMode::UdpMulticast)
        .build()?;

    if is_publisher {
        run_publisher(&participant)?;
    } else {
        run_subscriber(&participant)?;
    }

    Ok(())
}
