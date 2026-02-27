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

//! Stress test: Discovery with 10+ participants
//!
//! Validates that multiple participants using IntraProcess transport can
//! discover each other by successfully exchanging data on a shared topic.
//! Also tests dynamic joining of new participants into an existing group.
//!
//! Run with: `cargo test -p hdds --test stress_discovery -- --ignored`
//! Timeout: 30 seconds max

use hdds::generated::temperature::Temperature;
use hdds::{Participant, QoS, TransportMode};
use std::thread;
use std::time::{Duration, Instant};

/// Number of initial participants to create
const INITIAL_PARTICIPANTS: usize = 10;

/// Number of additional participants to join later
const ADDITIONAL_PARTICIPANTS: usize = 5;

/// Maximum time allowed for the entire test
const TEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Time to wait for intra-process routing after writes
const ROUTING_DELAY: Duration = Duration::from_millis(200);

/// Stress test: Create 10 participants, each with a writer and reader on the
/// same topic, verify they can all exchange data. Then add 5 more participants
/// and verify they also discover and exchange data with the existing group.
#[test]
#[ignore]
fn stress_discovery_10_participants_then_5_more() {
    let start = Instant::now();

    println!(
        "[stress_discovery] Creating {} initial participants...",
        INITIAL_PARTICIPANTS
    );

    // Phase 1: Create initial 10 participants, each with a writer and reader
    let mut participants = Vec::with_capacity(INITIAL_PARTICIPANTS + ADDITIONAL_PARTICIPANTS);
    let mut writers = Vec::with_capacity(INITIAL_PARTICIPANTS + ADDITIONAL_PARTICIPANTS);
    let mut readers = Vec::with_capacity(INITIAL_PARTICIPANTS + ADDITIONAL_PARTICIPANTS);

    for i in 0..INITIAL_PARTICIPANTS {
        assert!(
            start.elapsed() < TEST_TIMEOUT,
            "Timeout creating initial participants"
        );

        let name = format!("stress_disc_p{}", i);
        let p = Participant::builder(&name)
            .domain_id(0)
            .with_transport(TransportMode::IntraProcess)
            .build()
            .unwrap_or_else(|e| panic!("Failed to create participant {}: {:?}", i, e));

        let w = p
            .create_writer::<Temperature>("StressDiscoveryTopic", QoS::best_effort())
            .unwrap_or_else(|e| panic!("Failed to create writer for participant {}: {:?}", i, e));

        let r = p
            .create_reader::<Temperature>("StressDiscoveryTopic", QoS::best_effort())
            .unwrap_or_else(|e| panic!("Failed to create reader for participant {}: {:?}", i, e));

        participants.push(p);
        writers.push(w);
        readers.push(r);
    }

    println!(
        "[stress_discovery] {} participants created in {:?}",
        INITIAL_PARTICIPANTS,
        start.elapsed()
    );

    // Allow time for intra-process routing to settle
    thread::sleep(ROUTING_DELAY);

    // Phase 2: Each participant writes a unique message
    println!("[stress_discovery] Each participant publishing one message...");
    for (i, writer) in writers.iter().enumerate() {
        let sample = Temperature {
            value: 100.0 + i as f32,
            timestamp: i as i32,
        };
        writer
            .write(&sample)
            .unwrap_or_else(|e| panic!("Write failed for participant {}: {:?}", i, e));
    }

    // Wait for delivery
    thread::sleep(ROUTING_DELAY);

    // Phase 3: Verify each reader received at least one message
    // (In IntraProcess mode, readers on the same topic should see writes)
    let mut total_received = 0;
    for (i, reader) in readers.iter().enumerate() {
        let mut count = 0;
        while let Ok(Some(_msg)) = reader.take() {
            count += 1;
        }
        if count > 0 {
            total_received += 1;
        }
        // Not all readers may receive all messages in best-effort mode,
        // but each reader should see at least some traffic
        println!(
            "[stress_discovery] Reader {} received {} messages",
            i, count
        );
    }

    println!(
        "[stress_discovery] Phase 1 complete: {}/{} readers received data",
        total_received, INITIAL_PARTICIPANTS
    );

    // At least half the readers should have received something
    assert!(
        total_received >= INITIAL_PARTICIPANTS / 2,
        "Expected at least {} readers to receive data, only {} did",
        INITIAL_PARTICIPANTS / 2,
        total_received
    );

    // Phase 4: Add 5 more participants
    println!(
        "[stress_discovery] Adding {} more participants...",
        ADDITIONAL_PARTICIPANTS
    );

    let base_idx = INITIAL_PARTICIPANTS;
    for i in 0..ADDITIONAL_PARTICIPANTS {
        assert!(
            start.elapsed() < TEST_TIMEOUT,
            "Timeout creating additional participants"
        );

        let name = format!("stress_disc_p{}", base_idx + i);
        let p = Participant::builder(&name)
            .domain_id(0)
            .with_transport(TransportMode::IntraProcess)
            .build()
            .unwrap_or_else(|e| panic!("Failed to create additional participant {}: {:?}", i, e));

        let w = p
            .create_writer::<Temperature>("StressDiscoveryTopic", QoS::best_effort())
            .unwrap_or_else(|e| {
                panic!(
                    "Failed to create writer for additional participant {}: {:?}",
                    i, e
                )
            });

        let r = p
            .create_reader::<Temperature>("StressDiscoveryTopic", QoS::best_effort())
            .unwrap_or_else(|e| {
                panic!(
                    "Failed to create reader for additional participant {}: {:?}",
                    i, e
                )
            });

        participants.push(p);
        writers.push(w);
        readers.push(r);
    }

    println!(
        "[stress_discovery] Total {} participants now active",
        participants.len()
    );

    // Allow routing to settle
    thread::sleep(ROUTING_DELAY);

    // Phase 5: New participants publish
    println!("[stress_discovery] New participants publishing...");
    for (i, writer) in writers.iter().enumerate().skip(base_idx) {
        let sample = Temperature {
            value: 200.0 + i as f32,
            timestamp: i as i32,
        };
        writer
            .write(&sample)
            .unwrap_or_else(|e| panic!("Write failed for new participant {}: {:?}", i, e));
    }

    thread::sleep(ROUTING_DELAY);

    // Phase 6: Verify new participants' readers can receive data
    let mut new_received = 0;
    for (i, reader) in readers.iter().enumerate().skip(base_idx) {
        let mut count = 0;
        while let Ok(Some(_msg)) = reader.take() {
            count += 1;
        }
        if count > 0 {
            new_received += 1;
        }
        println!(
            "[stress_discovery] New reader {} received {} messages",
            i, count
        );
    }

    println!(
        "[stress_discovery] Phase 2 complete: {}/{} new readers received data",
        new_received, ADDITIONAL_PARTICIPANTS
    );

    // At least some of the new readers should have received data
    assert!(
        new_received >= ADDITIONAL_PARTICIPANTS / 2,
        "Expected at least {} new readers to receive data, only {} did",
        ADDITIONAL_PARTICIPANTS / 2,
        new_received
    );

    let elapsed = start.elapsed();
    assert!(
        elapsed < TEST_TIMEOUT,
        "Test exceeded timeout of {:?} (took {:?})",
        TEST_TIMEOUT,
        elapsed
    );

    println!(
        "[stress_discovery] PASSED - {} total participants, completed in {:?}",
        participants.len(),
        elapsed
    );
}
