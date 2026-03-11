// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! WaitSet Demo - Event-Driven Data Reading
//!
//! Demonstrates how to use WaitSet with DataReader StatusCondition
//! for efficient event-driven messaging without polling.
//!
//! Run with: cargo run --package hdds --example waitset_demo

use hdds::dds::StatusMask;
use hdds::generated::temperature::Temperature;
use hdds::{Participant, QoS, WaitSet};
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
        .topic::<Temperature>("sensor/temp")?
        .writer()
        .qos(QoS::best_effort().keep_last(10))
        .build()?;
    println!("[OK] Writer created for topic: sensor/temp");

    // 3. Create DataReader<Temperature>
    let reader = participant
        .topic::<Temperature>("sensor/temp")?
        .reader()
        .qos(QoS::best_effort().keep_last(10))
        .build()?;
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
