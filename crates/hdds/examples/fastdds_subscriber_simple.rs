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

//! FastDDS Interoperability Test - Simple Subscriber
//!
//! Receives HelloWorld messages published by FastDDS test_simple_pub.
//! SIMPLIFIED: Only reads the index field (u32) for initial validation.
//!
//! Run FastDDS publisher first (from FastDDS HelloWorld example directory):
//!   ./test_simple_pub
//!
//! Then run this subscriber:
//!   cargo run --example fastdds_subscriber_simple

use hdds::api::{Participant, QoS, TransportMode};
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("[*] FastDDS Interoperability Test - HDDS Simple Subscriber\n");

    // Create participant with UDP multicast (domain 0, same as FastDDS)
    println!("[*] Creating participant with UDP multicast transport...");
    let participant = Participant::builder("fastdds_test")
        .with_transport(TransportMode::UdpMulticast)
        .build()?;

    println!("   Participant: fastdds_test");
    println!("   Domain: 0");
    println!("   Transport: UDP Multicast (239.255.0.1:7400)");
    println!();

    // For now, let's just use the existing Temperature type as a test
    // (We'll implement proper HelloWorld codegen later)
    println!("[<] Creating DataReader for 'sensor/temp' (test topic)...");

    use hdds::generated::temperature::Temperature;

    let reader = participant
        .create_reader::<Temperature>("sensor/temp", QoS::best_effort().keep_last(10))?;

    println!("   Topic: sensor/temp");
    println!("   Type: Temperature (for testing)");
    println!();

    println!("[*] Listening for messages...");
    println!("   (Press Ctrl+C to stop)\n");

    let mut received_count = 0;
    let start = std::time::Instant::now();

    // Listen for 30 seconds
    loop {
        // Poll for messages using try_take()
        match reader.take() {
            Ok(Some(sample)) => {
                received_count += 1;
                let elapsed = start.elapsed().as_secs_f64();

                println!("[OK] [{}] Received Temperature:", received_count);
                println!("   value: {:.1}", sample.value);
                println!("   timestamp: {}", sample.timestamp);
                println!("   elapsed: {:.3}s", elapsed);
                println!();
            }
            Ok(None) => {
                // No data available, continue polling
            }
            Err(e) => {
                eprintln!("[!] Error reading: {:?}", e);
            }
        }

        // Sleep briefly to avoid busy loop
        std::thread::sleep(Duration::from_millis(10));

        // Stop after 30 seconds
        if start.elapsed().as_secs() > 30 {
            break;
        }
    }

    println!("\n[i] Summary:");
    println!("   Messages received: {}", received_count);
    println!("   Duration: {:.1}s", start.elapsed().as_secs_f64());

    let stats = reader.stats();
    println!("\n[i] Reader Stats:");
    println!("   Messages received: {}", stats.messages_received);
    println!("   Bytes received: {}", stats.bytes_received);
    println!("   Drops: {}", stats.drops);

    if received_count > 0 {
        println!("\n[OK] SUCCESS: HDDS received messages via UDP multicast!");
        println!("   Next step: Test with real FastDDS publisher");
    } else {
        println!("\n[!] No messages received.");
        println!("\nTo test intra-process first, run:");
        println!("   cargo run --example temperature_pubsub");
    }

    Ok(())
}
