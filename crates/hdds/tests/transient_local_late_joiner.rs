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

/// Integration test for TRANSIENT_LOCAL late-joiner delivery (v0.5.0+)
///
/// Validates that late-joining readers receive historical samples
/// when TRANSIENT_LOCAL durability is configured.
///
/// Test Scenario:
/// 1. Create Writer with TRANSIENT_LOCAL + KeepLast(5)
/// 2. Writer publishes 3 samples
/// 3. Late-joiner Reader created after publications
/// 4. Reader binds to Writer's merger
/// 5. Reader should receive all 3 historical samples
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use hdds::api::{Participant, QoS};
use hdds::core::rt::{IndexRing, MergerReader, SlabPool, TopicMerger};
use hdds::generated::temperature::Temperature;
use hdds::reliability::HistoryCache;

#[test]
fn test_transient_local_late_joiner_delivery() {
    // Create participant (single-process mode)
    let participant = Participant::builder("late_joiner_test")
        .build()
        .expect("Failed to create participant");

    // Create Writer with TRANSIENT_LOCAL durability (BestEffort + TransientLocal)
    let writer = participant
        .create_writer::<Temperature>(
            "LateJoinerTopic",
            QoS::best_effort().transient_local().keep_last(5),
        )
        .expect("Failed to create writer");

    // Publish 3 samples (retry on WouldBlock to handle slab pool exhaustion)
    let sample1 = Temperature {
        value: 21.5,
        timestamp: 1000,
    };
    let sample2 = Temperature {
        value: 22.0,
        timestamp: 2000,
    };
    let sample3 = Temperature {
        value: 22.5,
        timestamp: 3000,
    };

    // Write samples (no retry needed with TRANSIENT_LOCAL fix)
    writer.write(&sample1).expect("write sample1");
    writer.write(&sample2).expect("write sample2");
    writer.write(&sample3).expect("write sample3");

    // Give writer time to cache samples
    thread::sleep(Duration::from_millis(50));

    // Late-joiner: Create reader AFTER samples are published
    let reader = participant
        .create_reader::<Temperature>("LateJoinerTopic", QoS::best_effort().keep_last(10))
        .expect("Failed to create reader");

    // Bind reader to writer's merger (triggers historical sample delivery)
    reader.bind_to_writer(writer.merger());

    // Give time for historical samples to be delivered and processed
    thread::sleep(Duration::from_millis(100));

    // Reader should have received all 3 historical samples
    let mut received = Vec::new();
    for _ in 0..3 {
        if let Ok(Some(sample)) = reader.take() {
            received.push(sample);
        } else {
            break;
        }
    }

    assert_eq!(
        received.len(),
        3,
        "Late-joiner should receive 3 historical samples"
    );

    // Verify samples are in correct order and have correct values
    assert_eq!(received[0].value, 21.5);
    assert_eq!(received[0].timestamp, 1000);

    assert_eq!(received[1].value, 22.0);
    assert_eq!(received[1].timestamp, 2000);

    assert_eq!(received[2].value, 22.5);
    assert_eq!(received[2].timestamp, 3000);
}

#[test]
fn test_transient_local_history_respects_keep_last() {
    // Create participant
    let participant = Participant::builder("keep_last_test")
        .build()
        .expect("Failed to create participant");

    // Create Writer with TRANSIENT_LOCAL + KeepLast(2)
    let writer = participant
        .create_writer::<Temperature>(
            "KeepLastTopic",
            QoS::reliable().transient_local().keep_last(2),
        )
        .expect("Failed to create writer");

    // Publish 5 samples (exceeds KeepLast(2) limit)
    for i in 1..=5 {
        let sample = Temperature {
            value: 20.0 + i as f32,
            timestamp: i * 1000,
        };
        writer.write(&sample).expect("write sample");
    }

    thread::sleep(Duration::from_millis(50));

    // Late-joiner reader
    let reader = participant
        .create_reader::<Temperature>("KeepLastTopic", QoS::reliable().keep_last(10))
        .expect("Failed to create reader");

    reader.bind_to_writer(writer.merger());
    thread::sleep(Duration::from_millis(100));

    // Should only receive last 2 samples (due to KeepLast(2))
    let mut received = Vec::new();
    for _ in 0..10 {
        if let Ok(Some(sample)) = reader.take() {
            received.push(sample);
        } else {
            break;
        }
    }

    assert_eq!(
        received.len(),
        2,
        "Should receive only last 2 samples (KeepLast(2))"
    );

    // Verify we got samples 4 and 5 (newest ones)
    assert_eq!(received[0].value, 24.0);
    assert_eq!(received[0].timestamp, 4000);
    assert_eq!(received[1].value, 25.0);
    assert_eq!(received[1].timestamp, 5000);
}

#[test]
fn test_volatile_no_late_joiner_delivery() {
    // This test verifies that VOLATILE durability does NOT cache samples for late-joiners.
    //
    // With VOLATILE:
    // - Samples are delivered only to connected readers (real-time)
    // - No cache exists, so writes without readers fail with WouldBlock
    // - Late-joining readers get nothing (no historical data)
    //
    // Test approach: Create reader first, receive samples, then verify cache doesn't exist.

    let participant = Participant::builder("volatile_test")
        .build()
        .expect("Failed to create participant");

    let writer = participant
        .create_writer::<Temperature>("VolatileTopic", QoS::best_effort().keep_last(5))
        .expect("Failed to create writer");

    // Create reader BEFORE writing (VOLATILE requires connected readers to accept writes)
    let reader = participant
        .create_reader::<Temperature>("VolatileTopic", QoS::best_effort().keep_last(10))
        .expect("Failed to create reader");

    reader.bind_to_writer(writer.merger());
    thread::sleep(Duration::from_millis(10));

    // Write samples (these go directly to reader, not cached)
    for i in 1..=3 {
        let sample = Temperature {
            value: 20.0 + i as f32,
            timestamp: i * 1000,
        };
        writer.write(&sample).expect("write sample");
    }

    thread::sleep(Duration::from_millis(10));

    // Reader should receive samples in real-time (not via late-joiner mechanism)
    let mut received = Vec::new();
    for _ in 0..10 {
        if let Ok(Some(sample)) = reader.take() {
            received.push(sample);
        } else {
            break;
        }
    }

    // Verify real-time delivery works
    assert_eq!(
        received.len(),
        3,
        "VOLATILE should deliver samples to connected readers"
    );

    // To test late-joiner behavior: drop reader, create new one, verify it gets nothing
    drop(reader);

    let late_joiner = participant
        .create_reader::<Temperature>("VolatileTopic", QoS::best_effort().keep_last(10))
        .expect("Failed to create reader");

    late_joiner.bind_to_writer(writer.merger());
    thread::sleep(Duration::from_millis(50));

    let mut late_received = Vec::new();
    for _ in 0..10 {
        if let Ok(Some(sample)) = late_joiner.take() {
            late_received.push(sample);
        } else {
            break;
        }
    }

    assert_eq!(
        late_received.len(),
        0,
        "VOLATILE durability should NOT deliver historical samples to late-joiners"
    );
}

#[test]
fn test_transient_local_with_merger_directly() {
    // Unit test: Verify TopicMerger::with_history() delivers samples

    let slab_pool = Arc::new(SlabPool::new());
    let limits = hdds::qos::ResourceLimits::default();
    let cache = Arc::new(HistoryCache::new(slab_pool.clone(), &limits));

    // Insert 3 samples into cache
    cache.insert(1, b"sample1").expect("insert 1");
    cache.insert(2, b"sample2").expect("insert 2");
    cache.insert(3, b"sample3").expect("insert 3");

    // Create TopicMerger with history
    let merger = TopicMerger::with_history(cache.clone(), slab_pool.clone());

    // Create a reader ring
    let reader_ring = Arc::new(IndexRing::with_capacity(16));

    // Add reader (should trigger historical sample delivery)
    let notify: Arc<dyn Fn() + Send + Sync> = Arc::new(|| {});
    let reader = MergerReader::new(reader_ring.clone(), notify);
    merger.add_reader(reader);

    // Reader ring should have 3 entries
    let mut count = 0;
    while reader_ring.pop().is_some() {
        count += 1;
    }

    assert_eq!(count, 3, "Reader should receive 3 historical samples");
}
