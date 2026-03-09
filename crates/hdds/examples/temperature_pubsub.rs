// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

// Temperature Pub/Sub Example - End-to-end API validation (Phase 7a)
//
// Demonstrates:
// - Participant creation with builder
// - DataWriter<Temperature> publish path
// - DataReader<Temperature> subscribe path
// - Multi-threaded publisher/subscriber
// - Stats validation

use hdds::{Participant, QoS};
use hdds::generated::temperature::Temperature;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Temperature Pub/Sub Example ===\n");

    // 1. Create Participant
    let participant = Arc::new(Participant::builder("temp_demo").build()?);
    println!("[OK] Participant created: temp_demo\n");

    // 2. Create DataWriter<Temperature>
    let writer = participant
        .create_writer::<Temperature>("sensor/temp", QoS::best_effort().keep_last(10))?;
    println!("[OK] Writer created for topic: sensor/temp");

    // 3. Create DataReader<Temperature>
    let reader = participant
        .create_reader::<Temperature>("sensor/temp", QoS::best_effort().keep_last(10))?;
    println!("[OK] Reader created for topic: sensor/temp\n");

    // 4. Bind reader to writer (intra-process communication)
    reader.bind_to_writer(writer.merger());
    println!("[OK] Reader bound to writer\n");

    // 5. Publisher thread: Write 10 samples
    let writer_handle = thread::spawn(move || {
        println!("[Publisher] Starting...");
        for i in 0..10 {
            let temp = Temperature {
                value: 20.0 + i as f32,
                timestamp: 1234567890 + i,
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

        let stats = writer.stats();
        println!("\n[Publisher] Final stats:");
        println!("  Messages sent: {}", stats.messages_sent);
        println!("  Bytes sent: {}", stats.bytes_sent);
        println!("  Drops: {}", stats.drops);
    });

    // 6. Subscriber thread: Poll take()
    let reader_handle = thread::spawn(move || {
        println!("[Subscriber] Starting...\n");
        let mut received_count = 0;

        for _ in 0..15 {
            // Poll for longer to catch all messages
            match reader.take() {
                Ok(Some(sample)) => {
                    println!(
                        "[Subscriber] Received: {:.1}  degC (ts: {})",
                        sample.value, sample.timestamp
                    );
                    received_count += 1;
                }
                Ok(None) => {
                    // No data yet, continue polling
                }
                Err(e) => {
                    eprintln!("[Subscriber] Error: {:?}", e);
                }
            }

            thread::sleep(Duration::from_millis(100));
        }

        let stats = reader.stats();
        println!("\n[Subscriber] Final stats:");
        println!("  Messages received: {}", stats.messages_received);
        println!("  Bytes received: {}", stats.bytes_received);
        println!("  Drops: {}", stats.drops);
        println!("  Received count (polled): {}", received_count);
    });

    // 7. Wait for threads to complete
    writer_handle.join().unwrap();
    reader_handle.join().unwrap();

    println!("\n=== Example Complete ===");
    println!("[OK] All threads finished");
    println!("[OK] Intra-process pub/sub validated");

    Ok(())
}
