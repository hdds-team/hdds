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

/// Multi-Node Communication Example for HDDS
///
/// Demonstrates:
/// - Multiple publishers and subscribers
/// - Topic-based routing
/// - Fan-out communication pattern
/// - Message distribution across multiple readers
///
/// Note: This example simulates multi-node communication within a single process.
/// Full multi-process discovery will be integrated in future phases.
use hdds::{Participant, QoS, DDS};

// Simple sensor data message
#[derive(Debug, Clone, Copy, PartialEq, DDS)]
struct SensorData {
    node_id: u32,
    value: f32,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== HDDS Multi-Node Communication Example ===\n");
    println!("Simulating 1 publisher -> 3 subscribers\n");

    // Create participant
    let participant = Participant::builder("multi_node_example").build()?;
    println!("[OK] Created participant");

    // Create topic
    let topic = participant.topic::<SensorData>("SensorTopic")?;
    println!("[OK] Created topic: SensorTopic");

    // Create ONE writer (publisher node)
    let writer = topic
        .writer()
        .qos(QoS::best_effort().keep_last(5))
        .build()?;
    println!("\n[OK] Created Publisher (Writer)");

    // Create THREE readers (subscriber nodes)
    let reader1 = topic
        .reader()
        .qos(QoS::best_effort().keep_last(5))
        .build()?;

    let reader2 = topic
        .reader()
        .qos(QoS::best_effort().keep_last(5))
        .build()?;

    let reader3 = topic
        .reader()
        .qos(QoS::best_effort().keep_last(5))
        .build()?;

    println!("[OK] Created 3 Subscribers (Readers)");

    // Bind all readers to the writer (simulates discovery)
    reader1.bind_to_writer(writer.merger());
    reader2.bind_to_writer(writer.merger());
    reader3.bind_to_writer(writer.merger());
    println!("[OK] Bound all readers to writer (discovery complete)");

    println!("\n--- Publishing Sensor Data ---");

    // Publish 5 messages from the publisher
    for i in 1..=5 {
        let data = SensorData {
            node_id: 100,
            value: 20.0 + (i as f32),
        };

        writer.write(&data)?;
        println!(
            "Published: node_id={}, value={:.1}",
            data.node_id, data.value
        );

        // Small delay to simulate real-world timing
        std::thread::sleep(std::time::Duration::from_millis(50));
    }

    println!("\n--- Subscribers Receiving Data ---");

    // Each reader should receive all 5 messages
    println!("\nSubscriber 1:");
    let mut count1 = 0;
    while let Some(data) = reader1.take()? {
        println!(
            "  Received: node_id={}, value={:.1}",
            data.node_id, data.value
        );
        count1 += 1;
    }

    println!("\nSubscriber 2:");
    let mut count2 = 0;
    while let Some(data) = reader2.take()? {
        println!(
            "  Received: node_id={}, value={:.1}",
            data.node_id, data.value
        );
        count2 += 1;
    }

    println!("\nSubscriber 3:");
    let mut count3 = 0;
    while let Some(data) = reader3.take()? {
        println!(
            "  Received: node_id={}, value={:.1}",
            data.node_id, data.value
        );
        count3 += 1;
    }

    println!("\n--- Summary ---");
    println!("Messages published:  5");
    println!("Subscriber 1 received: {}", count1);
    println!("Subscriber 2 received: {}", count2);
    println!("Subscriber 3 received: {}", count3);

    if count1 == 5 && count2 == 5 && count3 == 5 {
        println!("\n[OK] SUCCESS: All subscribers received all messages!");
        println!("[OK] Fan-out pattern working correctly (1 -> N communication)");
    } else {
        println!("\n[!] Some messages were not delivered to all subscribers");
    }

    println!("\nNote: This example demonstrates in-process multi-reader communication.");
    println!("Full multi-process node discovery will be integrated in future phases.");

    Ok(())
}
