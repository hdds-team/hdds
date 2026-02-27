// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! # HDDS Sample: String Types
//!
//! Demonstrates **string type** support in DDS/IDL - text handling with optional
//! bounds and full Unicode support.
//!
//! ## String Variants
//!
//! ```text
//! ┌───────────────────────────────────────────────────────────────────┐
//! │ Type              │ IDL Syntax        │ Rust Mapping │ Bound     │
//! ├───────────────────┼───────────────────┼──────────────┼───────────┤
//! │ Unbounded string  │ string            │ String       │ None      │
//! │ Bounded string    │ string<256>       │ String       │ 256 chars │
//! │ Wide string       │ wstring           │ String       │ None      │
//! │ Bounded wide      │ wstring<100>      │ String       │ 100 chars │
//! └───────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Memory Considerations
//!
//! ```text
//! Unbounded String:                Bounded String<8>:
//! ┌────────────────────────┐      ┌──────────────┐
//! │ "Hello, HDDS World!"   │      │ "ShortTxt"   │  ← Truncated if > 8
//! │ (can grow to any size) │      │ (max 8 chars)│
//! └────────────────────────┘      └──────────────┘
//!
//! Bounded strings are useful for:
//! - Fixed-size message buffers
//! - Memory-constrained systems
//! - Guaranteed serialization size
//! ```
//!
//! ## IDL Definition
//!
//! ```idl
//! struct Strings {
//!     string          unbounded_str;   // Unlimited length
//!     string<256>     bounded_str;     // Max 256 characters
//!     wstring         wide_str;        // Unicode (UTF-8 in Rust)
//! };
//! ```
//!
//! ## Use Cases
//!
//! - **Device names**: Human-readable identifiers
//! - **Log messages**: Variable-length text data
//! - **Internationalization**: Multi-byte character support
//!
//! ## Running the Sample
//!
//! ```bash
//! # Terminal 1 - Subscriber
//! cargo run --bin strings
//!
//! # Terminal 2 - Publisher
//! cargo run --bin strings -- pub
//! ```

use std::env;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

// Include generated type
#[allow(dead_code)]
mod generated {
    include!("../../generated/strings.rs");
}

use generated::hdds_samples::Strings;

#[allow(clippy::useless_vec)]
fn run_publisher(participant: &Arc<hdds::Participant>) -> Result<(), hdds::Error> {
    println!("Creating writer...");
    let writer = participant.create_writer::<Strings>("StringsTopic", hdds::QoS::reliable())?;

    println!("Publishing string samples...\n");

    let samples = vec![
        Strings::builder()
            .unbounded_str("Hello, HDDS!")
            .bounded_str("Short")
            .wide_str("UTF-8: cafe")
            .build()
            .expect("build"),
        Strings::builder()
            .unbounded_str("This is a longer unbounded string that can grow as needed")
            .bounded_str("Bounded to 256 chars")
            .wide_str("Multi-byte: konnichiwa")
            .build()
            .expect("build"),
        Strings::builder()
            .unbounded_str("")
            .bounded_str("")
            .wide_str("")
            .build()
            .expect("build"),
    ];

    for (i, data) in samples.iter().enumerate() {
        writer.write(data)?;
        println!("Published sample {}:", i);
        println!("  unbounded: \"{}\"", data.unbounded_str);
        println!("  bounded:   \"{}\"", data.bounded_str);
        println!("  wide:      \"{}\"", data.wide_str);
        println!();
        thread::sleep(Duration::from_millis(500));
    }

    println!("Done publishing.");
    Ok(())
}

fn run_subscriber(participant: &Arc<hdds::Participant>) -> Result<(), hdds::Error> {
    println!("Creating reader...");
    let reader = participant.create_reader::<Strings>("StringsTopic", hdds::QoS::reliable())?;

    let status_condition = reader.get_status_condition();
    let waitset = hdds::dds::WaitSet::new();
    waitset.attach_condition(status_condition)?;

    println!("Waiting for string samples...\n");

    let mut received = 0;
    while received < 3 {
        match waitset.wait(Some(Duration::from_secs(5))) {
            Ok(triggered) => {
                if !triggered.is_empty() {
                    while let Some(data) = reader.take()? {
                        received += 1;
                        println!("Received sample {}:", received);
                        println!(
                            "  unbounded: \"{}\" ({} bytes)",
                            data.unbounded_str,
                            data.unbounded_str.len()
                        );
                        println!(
                            "  bounded:   \"{}\" ({} bytes)",
                            data.bounded_str,
                            data.bounded_str.len()
                        );
                        println!(
                            "  wide:      \"{}\" ({} bytes)",
                            data.wide_str,
                            data.wide_str.len()
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
    println!("String Types Demo");
    println!("Demonstrates: unbounded, bounded, and wide strings");
    println!("{}", "=".repeat(60));

    let participant = hdds::Participant::builder("StringsDemo")
        .with_transport(hdds::TransportMode::UdpMulticast)
        .build()?;

    if is_publisher {
        run_publisher(&participant)?;
    } else {
        run_subscriber(&participant)?;
    }

    Ok(())
}
