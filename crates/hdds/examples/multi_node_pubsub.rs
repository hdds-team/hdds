// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

#![allow(clippy::uninlined_format_args)] // Test/bench code readability over pedantic
#![allow(clippy::cast_precision_loss)] // Stats/metrics need this
#![allow(clippy::cast_sign_loss)] // Test data conversions
#![allow(clippy::cast_possible_truncation)] // Test parameters
#![allow(clippy::float_cmp)] // Test assertions with constants
#![allow(clippy::unreadable_literal)] // Large test constants
#![allow(clippy::doc_markdown)] // Test documentation
#![allow(clippy::missing_panics_doc)] // Tests/examples panic on failure
#![allow(clippy::missing_errors_doc)] // Test documentation
#![allow(clippy::items_after_statements)] // Test helpers
#![allow(clippy::module_name_repetitions)] // Test modules
#![allow(clippy::too_many_lines)] // Example/test code
#![allow(clippy::match_same_arms)] // Test pattern matching
#![allow(clippy::no_effect_underscore_binding)] // Test variables
#![allow(clippy::wildcard_imports)] // Test utility imports
#![allow(clippy::redundant_closure_for_method_calls)] // Test code clarity
#![allow(clippy::similar_names)] // Test variable naming
#![allow(clippy::shadow_unrelated)] // Test scoping
#![allow(clippy::needless_pass_by_value)] // Test functions
#![allow(clippy::cast_possible_wrap)] // Test conversions
#![allow(clippy::single_match_else)] // Test clarity
#![allow(clippy::needless_continue)] // Test logic
#![allow(clippy::cast_lossless)] // Test simplicity
#![allow(clippy::match_wild_err_arm)] // Test error handling
#![allow(clippy::explicit_iter_loop)] // Test iteration
#![allow(clippy::must_use_candidate)] // Test functions
#![allow(clippy::if_not_else)] // Test conditionals
#![allow(clippy::map_unwrap_or)] // Test options
#![allow(clippy::match_wildcard_for_single_variants)] // Test patterns
#![allow(clippy::ignored_unit_patterns)] // Test closures

//! Multi-Node Pub/Sub Demo (v0.3.0 UDP Multicast)
//!
//! Demonstrates inter-process communication via UDP multicast.
//!
//! # Usage
//!
//! Terminal 1 (Publisher):
//! ```bash
//! cargo run --example multi_node_pubsub -- pub
//! ```
//!
//! Terminal 2 (Subscriber):
//! ```bash
//! cargo run --example multi_node_pubsub -- sub
//! ```
//!
//! # Validation
//!
//! - Terminal 1: publishes Temperature samples every 1s
//! - Terminal 2: receives and prints samples
//! - Wireshark: capture UDP 239.255.0.1:7400 packets to see RTPS traffic

use hdds::api::{Participant, QoS, TransportMode};
use hdds::generated::temperature::Temperature;
use std::env;
use std::thread;
use std::time::Duration;

fn main() {
    let args: Vec<String> = env::args().collect();

    match args.get(1).map(|s| s.as_str()) {
        Some("pub") => run_publisher(),
        Some("sub") => run_subscriber(),
        _ => {
            println!("Usage: multi_node_pubsub [pub|sub]");
            println!();
            println!("Commands:");
            println!("  pub    Run as publisher (sends Temperature samples via UDP)");
            println!("  sub    Run as subscriber (receives Temperature samples via UDP)");
            println!();
            println!("Example:");
            println!("  Terminal 1: cargo run --example multi_node_pubsub -- pub");
            println!("  Terminal 2: cargo run --example multi_node_pubsub -- sub");
        }
    }
}

/// Publisher mode: sends Temperature samples via UDP multicast
fn run_publisher() {
    println!("[*] Starting Publisher (UDP Multicast)");
    println!("   - Sending to: 239.255.0.1:7400");
    println!("   - Topic: sensor/temp");
    println!("   - Rate: 1 Hz");
    println!();

    // Create participant with UDP multicast mode
    let participant = Participant::builder("publisher_node")
        .with_transport(TransportMode::UdpMulticast)
        .build()
        .expect("Failed to create participant");

    // Create writer
    let writer = participant
        .create_writer::<Temperature>(
            "sensor/temp",
            QoS::reliable().transient_local().keep_last(10),
        )
        .expect("Failed to create writer");

    println!("[OK] Publisher ready - sending samples...");
    println!();

    // Publish loop
    let mut seq = 0u64;
    let start_time = std::time::Instant::now();

    loop {
        let elapsed_secs = start_time.elapsed().as_secs();
        let temp_value = 20.0 + (seq as f32 * 0.5) % 10.0; // Vary temperature

        let sample = Temperature {
            value: temp_value,
            timestamp: elapsed_secs as i32,
        };

        match writer.write(&sample) {
            Ok(_) => {
                println!(
                    "[{:06}] Published: {:.1} degC (timestamp: {}s)",
                    seq, temp_value, elapsed_secs
                );
            }
            Err(e) => {
                eprintln!("Write failed: {:?}", e);
            }
        }

        seq += 1;
        thread::sleep(Duration::from_secs(1));
    }
}

/// Subscriber mode: receives Temperature samples via UDP multicast
fn run_subscriber() {
    println!("[*] Starting Subscriber (UDP Multicast)");
    println!("   - Listening on: 239.255.0.1:7400");
    println!("   - Topic: sensor/temp");
    println!("   - Polling: 10 Hz");
    println!();

    // Create participant with UDP multicast mode
    let participant = Participant::builder("subscriber_node")
        .with_transport(TransportMode::UdpMulticast)
        .build()
        .expect("Failed to create participant");

    // Create reader
    let reader = participant
        .create_reader::<Temperature>("sensor/temp", QoS::best_effort().keep_last(100))
        .expect("Failed to create reader");

    println!("[OK] Subscriber ready - waiting for samples...");
    println!();

    let mut received_count = 0u64;

    // Subscribe loop
    loop {
        match reader.take() {
            Ok(Some(sample)) => {
                received_count += 1;
                println!(
                    "[RX {:06}] Temperature: {:.1} degC (timestamp: {}s)",
                    received_count, sample.value, sample.timestamp
                );
            }
            Ok(None) => {
                // No data available - continue polling
            }
            Err(e) => {
                eprintln!("Read failed: {:?}", e);
            }
        }

        // Poll at 10 Hz
        thread::sleep(Duration::from_millis(100));
    }
}
