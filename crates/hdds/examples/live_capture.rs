// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Live DDS Capture Example
//!
//! Demonstrates the Live Capture API for runtime topic discovery and
//! type-agnostic traffic monitoring (similar to Wireshark for DDS).
//!
//! # Usage
//!
//! Terminal 1 - Start a publisher:
//! ```bash
//! cargo run --example generated_types_demo
//! ```
//!
//! Terminal 2 - Run live capture:
//! ```bash
//! cargo run --example live_capture
//! ```
//!
//! Expected output:
//! - List of discovered topics
//! - Raw CDR payloads from each topic
//! - Timestamps and metadata

use hdds::Participant;
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== HDDS Live Capture Example ===\n");

    // Create participant for monitoring
    println!("[1/3] Creating participant 'live_capture_monitor'...");
    let participant = Participant::builder("live_capture_monitor")
        .domain_id(0)
        .build()?;

    println!("      Participant created successfully!\n");

    // Wait for discovery to propagate
    println!("[2/3] Waiting 2 seconds for topic discovery...");
    std::thread::sleep(Duration::from_secs(2));

    // Discover all active topics on the bus
    println!("[3/3] Discovering topics...\n");
    let topics = participant.discover_topics()?;

    if topics.is_empty() {
        println!("No topics discovered.");
        println!("\nHINT: Start a publisher in another terminal:");
        println!("  cargo run --example generated_types_demo");
        return Ok(());
    }

    println!("Discovered {} topic(s):\n", topics.len());

    for (idx, topic) in topics.iter().enumerate() {
        println!("  Topic {}: {}", idx + 1, topic.name);
        println!("    Type: {}", topic.type_name);
        println!("    Publishers: {}", topic.publisher_count);
        println!("    Subscribers: {}", topic.subscriber_count);
        println!("    QoS Hash: 0x{:08x}", topic.qos_hash);

        // Create raw reader for first topic (demonstration)
        if idx == 0 {
            println!("\n--- Subscribing to '{}' ---", topic.name);

            let raw_reader = participant.create_raw_reader(&topic.name, None)?;

            println!("Waiting for samples (10 seconds)...\n");
            std::thread::sleep(Duration::from_secs(10));

            // Try to read raw samples
            let samples = raw_reader.try_take_raw()?;

            if samples.is_empty() {
                println!("No samples received.");
            } else {
                println!("Received {} sample(s):", samples.len());

                for (sample_idx, sample) in samples.iter().enumerate() {
                    println!("\n  Sample {}:", sample_idx + 1);
                    println!("    Payload size: {} bytes", sample.payload.len());
                    println!(
                        "    Reception time: {:?}",
                        sample
                            .reception_timestamp
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_secs()
                    );

                    // Print first 32 bytes of payload (hex dump)
                    print!("    Payload (hex): ");
                    for byte in sample.payload.iter().take(32) {
                        print!("{:02x} ", byte);
                    }
                    if sample.payload.len() > 32 {
                        print!("...");
                    }
                    println!();
                }
            }
        }
    }

    println!("\n=== Live Capture Example Complete ===");
    Ok(())
}
