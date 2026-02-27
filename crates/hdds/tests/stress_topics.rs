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
#![allow(clippy::ignore_without_reason)] // Test ignore attributes

//! Stress test: 1000+ topics simultaneously
//!
//! Validates that a single participant can handle a large number of unique
//! topics, each with its own writer/reader pair, exchanging data concurrently.
//!
//! Run with: `cargo test -p hdds --test stress_topics -- --ignored`
//! Timeout: 60 seconds max

use hdds::generated::temperature::Temperature;
use hdds::{Participant, QoS, TransportMode};
use std::thread;
use std::time::{Duration, Instant};

// Target is 1000 topics. If this proves too heavy for a single test run,
// reduce to a lower value (e.g., 100 or 500) and note the target.
const NUM_TOPICS: usize = 1000;

/// Maximum time allowed for the entire test
const TEST_TIMEOUT: Duration = Duration::from_secs(60);

/// Time to wait for intra-process routing after writes
const ROUTING_DELAY: Duration = Duration::from_millis(500);

/// Stress test: Create 1 participant with 1000 unique topics, each with a
/// writer/reader pair. Write one message per topic, then verify each reader
/// receives its message.
#[test]
#[ignore]
fn stress_1000_topics_simultaneously() {
    let start = Instant::now();

    println!("[stress_topics] Creating participant...");
    let participant = Participant::builder("stress_topics")
        .domain_id(0)
        .with_transport(TransportMode::IntraProcess)
        .build()
        .expect("Failed to create participant");

    let create_start = Instant::now();

    println!(
        "[stress_topics] Creating {} writer/reader pairs...",
        NUM_TOPICS
    );
    let mut writers = Vec::with_capacity(NUM_TOPICS);
    let mut readers = Vec::with_capacity(NUM_TOPICS);

    for i in 0..NUM_TOPICS {
        assert!(
            start.elapsed() < TEST_TIMEOUT,
            "Timeout during creation at topic {}",
            i
        );

        let topic_name = format!("Topic_{}", i);

        let writer = participant
            .create_writer::<Temperature>(&topic_name, QoS::best_effort())
            .unwrap_or_else(|e| panic!("Failed to create writer for {}: {:?}", topic_name, e));

        let reader = participant
            .create_reader::<Temperature>(&topic_name, QoS::best_effort())
            .unwrap_or_else(|e| panic!("Failed to create reader for {}: {:?}", topic_name, e));

        writers.push(writer);
        readers.push(reader);

        // Print progress every 100 topics
        if (i + 1) % 100 == 0 {
            println!(
                "[stress_topics]   Created {}/{} pairs ({:?} elapsed)",
                i + 1,
                NUM_TOPICS,
                create_start.elapsed()
            );
        }
    }

    let create_elapsed = create_start.elapsed();
    println!(
        "[stress_topics] All {} pairs created in {:?}",
        NUM_TOPICS, create_elapsed
    );

    // Allow routing to settle
    thread::sleep(ROUTING_DELAY);

    // Write one message per topic
    let write_start = Instant::now();
    println!("[stress_topics] Writing one message per topic...");

    for (i, writer) in writers.iter().enumerate() {
        let sample = Temperature {
            value: i as f32 * 0.1,
            timestamp: i as i32,
        };
        writer
            .write(&sample)
            .unwrap_or_else(|e| panic!("Write failed for Topic_{}: {:?}", i, e));
    }

    let write_elapsed = write_start.elapsed();
    println!(
        "[stress_topics] All {} writes completed in {:?}",
        NUM_TOPICS, write_elapsed
    );

    // Wait for delivery across all topics
    thread::sleep(ROUTING_DELAY);

    // Read and verify
    let read_start = Instant::now();
    println!("[stress_topics] Reading from all {} readers...", NUM_TOPICS);

    let mut success_count = 0;
    let mut fail_count = 0;

    for (i, reader) in readers.iter().enumerate() {
        match reader.take() {
            Ok(Some(msg)) => {
                // Verify the message has the expected timestamp (identifies topic index)
                assert_eq!(
                    msg.timestamp, i as i32,
                    "Topic_{} received wrong message: expected timestamp {}, got {}",
                    i, i, msg.timestamp
                );
                success_count += 1;
            }
            Ok(None) => {
                fail_count += 1;
            }
            Err(e) => {
                panic!("Read error for Topic_{}: {:?}", i, e);
            }
        }
    }

    let read_elapsed = read_start.elapsed();
    let total_elapsed = start.elapsed();

    println!("[stress_topics] Read phase completed in {:?}", read_elapsed);
    println!(
        "[stress_topics] Results: {}/{} received, {} missed",
        success_count, NUM_TOPICS, fail_count
    );
    println!("[stress_topics] Timing breakdown:");
    println!("  - Create: {:?}", create_elapsed);
    println!("  - Write:  {:?}", write_elapsed);
    println!("  - Read:   {:?}", read_elapsed);
    println!("  - Total:  {:?}", total_elapsed);

    // With IntraProcess, most messages should arrive
    // Allow some tolerance for best-effort delivery
    let min_success = NUM_TOPICS * 80 / 100; // 80% threshold
    assert!(
        success_count >= min_success,
        "Expected at least {} successful reads (80%), got {}/{}",
        min_success,
        success_count,
        NUM_TOPICS
    );

    assert!(
        total_elapsed < TEST_TIMEOUT,
        "Test exceeded timeout of {:?} (took {:?})",
        TEST_TIMEOUT,
        total_elapsed
    );

    println!(
        "[stress_topics] PASSED - {}/{} topics verified in {:?}",
        success_count, NUM_TOPICS, total_elapsed
    );
}
