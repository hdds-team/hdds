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

//! FastDDS Interoperability Test - Simple Publisher
//!
//! Publishes Temperature messages that FastDDS can subscribe to.
//! Tests HDDS -> FastDDS interoperability via UDP multicast.
//!
//! Run this publisher:
//!   cargo run --example fastdds_publisher_simple
//!
//! Then monitor with HDDS subscriber or FastDDS subscriber.

use hdds::api::{Participant, QoS, TransportMode};
use hdds::generated::temperature::Temperature;
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("[*] FastDDS Interoperability Test - HDDS Simple Publisher\n");

    // Create participant with UDP multicast (domain 0)
    println!("[*] Creating participant with UDP multicast transport...");
    let participant = Participant::builder("hdds_publisher")
        .with_transport(TransportMode::UdpMulticast)
        .build()?;

    println!("   Participant: hdds_publisher");
    println!("   Domain: 0");
    println!("   Transport: UDP Multicast (239.255.0.1:7400)");
    println!();

    // Create writer for Temperature topic
    println!("[>] Creating DataWriter for 'sensor/temp'...");
    let writer = participant
        .create_writer::<Temperature>("sensor/temp", QoS::best_effort().keep_last(10))?;

    println!("   Topic: sensor/temp");
    println!("   Type: Temperature");
    println!("   QoS: BestEffort, KeepLast(10)");
    println!();

    println!("[*] Publishing 10 Temperature samples via UDP multicast...");
    println!("   (1 sample/second)\n");

    // Publish 10 samples
    for i in 0..10 {
        let temp = Temperature {
            value: 20.0 + i as f32 * 0.5, // 20.0, 20.5, 21.0, ...
            timestamp: 1700000000 + i,
        };

        match writer.write(&temp) {
            Ok(()) => {
                println!(
                    "[OK] [{}] Published: {:.1} C (ts: {})",
                    i + 1,
                    temp.value,
                    temp.timestamp
                );
            }
            Err(e) => {
                eprintln!("[!] [{}] Error: {:?}", i + 1, e);
            }
        }

        std::thread::sleep(Duration::from_secs(1));
    }

    let stats = writer.stats();
    println!("\n[i] Publisher Stats:");
    println!("   Messages sent: {}", stats.messages_sent);
    println!("   Bytes sent: {}", stats.bytes_sent);
    println!("   Drops: {}", stats.drops);

    println!("\n[OK] Publishing complete!");
    println!("   All samples sent via UDP multicast to 239.255.0.1:7400");

    Ok(())
}
