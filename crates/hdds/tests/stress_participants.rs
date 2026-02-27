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

//! Stress test: 100+ participants per domain
//!
//! Validates that 100 participants can coexist on the same domain,
//! each writing to a shared topic, with a single reader participant
//! receiving messages from all writers.
//!
//! Run with: `cargo test -p hdds --test stress_participants -- --ignored`
//! Timeout: 120 seconds max

use hdds::generated::temperature::Temperature;
use hdds::{Participant, QoS, TransportMode};
use std::thread;
use std::time::{Duration, Instant};

/// Number of writer participants
const NUM_WRITERS: usize = 100;

/// Maximum time allowed for the entire test
const TEST_TIMEOUT: Duration = Duration::from_secs(120);

/// Time to wait for intra-process routing after writes
const ROUTING_DELAY: Duration = Duration::from_millis(500);

/// The shared topic all writers and the reader use
const SHARED_TOPIC: &str = "SharedTopic";

/// Stress test: Create 100 participants, each with a writer on "SharedTopic".
/// Create 1 additional reader participant. Each writer publishes 1 message.
/// Verify the reader receives messages from all (or most) writers.
#[test]
#[ignore]
fn stress_100_participants_shared_topic() {
    let start = Instant::now();

    // Phase 1: Create the reader participant first
    println!("[stress_participants] Creating reader participant...");
    let reader_participant = Participant::builder("stress_reader")
        .domain_id(0)
        .with_transport(TransportMode::IntraProcess)
        .build()
        .expect("Failed to create reader participant");

    let reader = reader_participant
        .create_reader::<Temperature>(SHARED_TOPIC, QoS::best_effort())
        .expect("Failed to create reader");

    // Phase 2: Create 100 writer participants
    println!(
        "[stress_participants] Creating {} writer participants...",
        NUM_WRITERS
    );
    let create_start = Instant::now();

    // We keep all participants alive so they are not dropped prematurely.
    let mut writer_participants = Vec::with_capacity(NUM_WRITERS);
    let mut writers = Vec::with_capacity(NUM_WRITERS);

    for i in 0..NUM_WRITERS {
        assert!(
            start.elapsed() < TEST_TIMEOUT,
            "Timeout during creation at writer {}",
            i
        );

        let name = format!("stress_writer_{}", i);
        let p = Participant::builder(&name)
            .domain_id(0)
            .with_transport(TransportMode::IntraProcess)
            .build()
            .unwrap_or_else(|e| panic!("Failed to create writer participant {}: {:?}", i, e));

        let w = p
            .create_writer::<Temperature>(SHARED_TOPIC, QoS::best_effort())
            .unwrap_or_else(|e| panic!("Failed to create writer {}: {:?}", i, e));

        writer_participants.push(p);
        writers.push(w);

        // Print progress every 25 participants
        if (i + 1) % 25 == 0 {
            println!(
                "[stress_participants]   Created {}/{} writers ({:?} elapsed)",
                i + 1,
                NUM_WRITERS,
                create_start.elapsed()
            );
        }
    }

    let create_elapsed = create_start.elapsed();
    println!(
        "[stress_participants] All {} writer participants created in {:?}",
        NUM_WRITERS, create_elapsed
    );

    // Allow routing to settle
    thread::sleep(ROUTING_DELAY);

    // Phase 3: Each writer publishes 1 message with a unique identifier
    let write_start = Instant::now();
    println!("[stress_participants] Each writer publishing 1 message...");

    for (i, writer) in writers.iter().enumerate() {
        let sample = Temperature {
            value: i as f32,
            timestamp: i as i32,
        };
        writer
            .write(&sample)
            .unwrap_or_else(|e| panic!("Write failed for writer {}: {:?}", i, e));
    }

    let write_elapsed = write_start.elapsed();
    println!(
        "[stress_participants] All {} writes completed in {:?}",
        NUM_WRITERS, write_elapsed
    );

    // Wait for delivery
    thread::sleep(ROUTING_DELAY);

    // Phase 4: Reader drains all messages
    let read_start = Instant::now();
    println!("[stress_participants] Reader draining messages...");

    let mut received_timestamps = Vec::new();
    let mut drain_attempts = 0;
    let max_drain_attempts = 3;

    // Drain in multiple passes to catch late arrivals
    while drain_attempts < max_drain_attempts {
        let mut got_any = false;
        while let Ok(Some(msg)) = reader.take() {
            received_timestamps.push(msg.timestamp);
            got_any = true;
        }
        if !got_any && drain_attempts > 0 {
            break;
        }
        drain_attempts += 1;
        if drain_attempts < max_drain_attempts {
            thread::sleep(Duration::from_millis(200));
        }
    }

    let read_elapsed = read_start.elapsed();
    let total_elapsed = start.elapsed();

    // Deduplicate in case of duplicates
    received_timestamps.sort();
    received_timestamps.dedup();
    let unique_writers = received_timestamps.len();

    println!(
        "[stress_participants] Reader received {} unique messages in {:?}",
        unique_writers, read_elapsed
    );
    println!("[stress_participants] Timing breakdown:");
    println!("  - Create:  {:?}", create_elapsed);
    println!("  - Write:   {:?}", write_elapsed);
    println!("  - Read:    {:?}", read_elapsed);
    println!("  - Total:   {:?}", total_elapsed);

    // With IntraProcess and best-effort, expect a good percentage of messages
    // to arrive. The exact number depends on internal routing and timing.
    // We use a 50% threshold as a reasonable minimum.
    let min_expected = NUM_WRITERS / 2;
    assert!(
        unique_writers >= min_expected,
        "Expected at least {} unique messages (50%), got {}/{}",
        min_expected,
        unique_writers,
        NUM_WRITERS
    );

    assert!(
        total_elapsed < TEST_TIMEOUT,
        "Test exceeded timeout of {:?} (took {:?})",
        TEST_TIMEOUT,
        total_elapsed
    );

    println!(
        "[stress_participants] PASSED - {}/{} writers delivered to reader in {:?}",
        unique_writers, NUM_WRITERS, total_elapsed
    );

    // Explicit drop order: writers first, then reader, then participants
    drop(writers);
    drop(reader);
    drop(writer_participants);
    drop(reader_participant);
}
