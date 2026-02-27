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

/// Basic Pub/Sub Example for HDDS
///
/// Demonstrates:
/// - Using #[derive(DDS)] macro
/// - Creating a Participant
/// - Creating DataWriter and DataReader
/// - Publishing and subscribing to messages
/// - Simple in-process communication
use hdds::{Participant, QoS, DDS};

// Define a simple message type using the DDS derive macro
#[derive(Debug, Clone, Copy, PartialEq, DDS)]
struct Temperature {
    sensor_id: u32,
    celsius: f32,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== HDDS Basic Pub/Sub Example ===\n");

    // Create a participant (represents a DDS application)
    let participant = Participant::builder("basic_pubsub_example").build()?;
    println!("[OK] Created participant");

    // Create a topic for Temperature messages
    let topic = participant.topic::<Temperature>("TemperatureTopic")?;
    println!("[OK] Created topic: TemperatureTopic");

    // Create a DataWriter (publisher) with best-effort QoS
    let writer = topic
        .writer()
        .qos(QoS::best_effort().keep_last(10))
        .build()?;
    println!("[OK] Created DataWriter with KeepLast(10)");

    // Create a DataReader (subscriber) with best-effort QoS
    let reader = topic
        .reader()
        .qos(QoS::best_effort().keep_last(10))
        .build()?;
    println!("[OK] Created DataReader with KeepLast(10)");

    // Bind reader to writer (for in-process communication)
    reader.bind_to_writer(writer.merger());
    println!("[OK] Bound reader to writer");

    println!("\n--- Publishing Messages ---");

    // Publish some temperature readings
    for i in 1..=5 {
        let temp = Temperature {
            sensor_id: 101,
            celsius: 20.0 + (i as f32 * 0.5),
        };

        writer.write(&temp)?;
        println!(
            "Published: sensor_id={}, celsius={:.1} C",
            temp.sensor_id, temp.celsius
        );

        // Small delay to simulate real-world publishing
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    println!("\n--- Receiving Messages ---");

    // Read messages from the DataReader
    let mut received_count = 0;
    while let Some(temp) = reader.take()? {
        println!(
            "Received:  sensor_id={}, celsius={:.1} C",
            temp.sensor_id, temp.celsius
        );
        received_count += 1;
    }

    println!("\n--- Summary ---");
    println!("Messages published: 5");
    println!("Messages received:  {}", received_count);

    if received_count == 5 {
        println!("[OK] All messages delivered successfully!");
    } else {
        println!("[!] Some messages were lost (expected with best-effort QoS)");
    }

    Ok(())
}
