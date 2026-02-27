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

//! WaitSet Demo - Event-Driven Data Reading
//!
//! Demonstrates how to use WaitSet with DataReader StatusCondition
//! for efficient event-driven messaging without polling.
//!
//! Run with: cargo run --package hdds --example waitset_demo

use hdds::api::{Participant, QoS, StatusMask, WaitSet};
use hdds::generated::temperature::Temperature;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== HDDS WaitSet Demo ===\n");

    // 1. Create Participant
    let participant = Arc::new(Participant::builder("waitset_demo").build()?);
    println!("[OK] Participant created: waitset_demo\n");

    // 2. Create DataWriter<Temperature>
    let writer = participant
        .create_writer::<Temperature>("sensor/temp", QoS::best_effort().keep_last(10))?;
    println!("[OK] Writer created for topic: sensor/temp");

    // 3. Create DataReader<Temperature>
    let reader = participant
        .create_reader::<Temperature>("sensor/temp", QoS::best_effort().keep_last(10))?;
    println!("[OK] Reader created for topic: sensor/temp");

    // 4. Bind reader to writer (intra-process communication)
    reader.bind_to_writer(writer.merger());
    println!("[OK] Reader bound to writer (intra-process)\n");

    // 5. Create WaitSet and attach Reader's StatusCondition
    let waitset = WaitSet::new();
    let condition = reader.get_status_condition();
    condition.set_enabled_statuses(StatusMask::DATA_AVAILABLE);
    waitset.attach_condition(condition)?;
    println!("[OK] Created WaitSet");
    println!("[OK] Attached Reader StatusCondition (DATA_AVAILABLE enabled)\n");

    // 6. Publisher thread: Write 5 samples
    let writer_handle = thread::spawn(move || {
        thread::sleep(Duration::from_millis(100)); // Let reader setup complete

        println!("[Publisher] Publishing Temperature samples...");
        for i in 1..=5 {
            let temp = Temperature {
                value: 20.0 + i as f32,
                timestamp: 1000 + i,
            };

            match writer.write(&temp) {
                Ok(()) => {
                    println!(
                        "[Publisher] Sent: {:.1}  degC (ts: {})",
                        temp.value, temp.timestamp
                    );
                }
                Err(e) => {
                    eprintln!("[Publisher] Error: {:?}", e);
                }
            }

            thread::sleep(Duration::from_millis(100));
        }

        println!("[Publisher] Finished publishing\n");
    });

    // 7. Subscriber: Wait for data using WaitSet (event-driven, no polling!)
    println!("[Subscriber] Waiting for data (using WaitSet, no polling)...\n");
    let mut received_count = 0;

    while received_count < 5 {
        // Block until DATA_AVAILABLE or 2s timeout
        match waitset.wait(Some(Duration::from_secs(2))) {
            Ok(triggered) => {
                if triggered.is_empty() {
                    println!("[Subscriber] WaitSet timeout - no data available");
                    break;
                }

                println!(
                    "[Subscriber] WaitSet triggered! {} condition(s) active",
                    triggered.len()
                );

                // Read all available samples
                loop {
                    match reader.take() {
                        Ok(Some(sample)) => {
                            received_count += 1;
                            println!(
                                "[Subscriber] Received #{}: {:.1}  degC (ts: {})",
                                received_count, sample.value, sample.timestamp
                            );
                        }
                        Ok(None) => {
                            // No more samples - WaitSet will notify us when more arrive
                            println!("[Subscriber] No more samples (WaitSet will notify)\n");
                            break;
                        }
                        Err(e) => {
                            eprintln!("[Subscriber] Error: {:?}", e);
                            break;
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("[Subscriber] WaitSet error: {:?}", e);
                break;
            }
        }
    }

    // 8. Wait for publisher to complete
    writer_handle.join().unwrap();

    println!("=== Demo Complete ===");
    println!("[OK] Received {} samples using WaitSet", received_count);
    println!("[OK] Event-driven pattern (no polling loops!)");
    println!("[OK] Efficient blocking wait vs. busy polling");

    Ok(())
}
