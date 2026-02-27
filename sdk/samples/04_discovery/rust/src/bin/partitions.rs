// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! # HDDS Sample: Partitions
//!
//! Demonstrates **partition-based filtering** - logical separation of data
//! within the same domain without creating separate topics.
//!
//! ## Partition Matching
//!
//! ```text
//! ┌───────────────────────────────────────────────────────────────────┐
//! │                        Same Topic: "SensorData"                   │
//! │                                                                   │
//! │   Partition "SensorA":         Partition "SensorB":               │
//! │   ┌─────────────────────┐      ┌─────────────────────┐            │
//! │   │ Writer [SensorA]    │      │ Writer [SensorB]    │            │
//! │   │        │            │      │        │            │            │
//! │   │        ▼            │      │        ▼            │            │
//! │   │ Reader [SensorA]    │      │ Reader [SensorB]    │            │
//! │   └─────────────────────┘      └─────────────────────┘            │
//! │           ╳ No communication across partitions ╳                  │
//! │                                                                   │
//! │   Wildcard "*" Reader:                                            │
//! │   ┌─────────────────────────────────────────────────┐             │
//! │   │ Reader [*] receives from BOTH SensorA & SensorB │             │
//! │   └─────────────────────────────────────────────────┘             │
//! └───────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Partition Patterns
//!
//! | Writer Partition | Reader Partition | Match? |
//! |------------------|------------------|--------|
//! | "SensorA"        | "SensorA"        | Yes    |
//! | "SensorA"        | "SensorB"        | No     |
//! | "SensorA"        | "*"              | Yes    |
//! | "SensorA"        | "Sensor*"        | Yes    |
//! | "Sales/US"       | "Sales/*"        | Yes    |
//!
//! ## Use Cases
//!
//! - **Multi-tenancy**: Isolate customer data
//! - **Regions**: Geographic separation
//! - **Teams**: Team-specific data flows
//! - **A/B testing**: Route traffic to different versions
//!
//! ## Running the Sample
//!
//! ```bash
//! # Terminal 1 - Partition A
//! cargo run --bin partitions -- --partition "SensorA"
//!
//! # Terminal 2 - Partition B (won't see A's messages)
//! cargo run --bin partitions -- --partition "SensorB"
//!
//! # Terminal 3 - Wildcard (sees ALL partitions)
//! cargo run --bin partitions -- --wildcard
//! ```

use std::thread;
use std::time::Duration;

fn print_usage(prog: &str) {
    println!("Usage: {} [OPTIONS]", prog);
    println!("\nOptions:");
    println!("  -p, --partition NAME   Add partition (can be repeated)");
    println!("  -w, --wildcard         Use wildcard partition '*'");
    println!("  -h, --help             Show this help");
    println!("\nExamples:");
    println!("  {} --partition SensorA", prog);
    println!("  {} --partition SensorA --partition SensorB", prog);
    println!("  {} --wildcard  # matches all partitions", prog);
}

/// Format partition list for display
fn format_partitions(names: &[String]) -> String {
    if names.is_empty() {
        return "[]".to_string();
    }
    let quoted: Vec<String> = names.iter().map(|n| format!("\"{}\"", n)).collect();
    format!("[{}]", quoted.join(", "))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== HDDS Partitions Sample ===\n");

    let args: Vec<String> = std::env::args().collect();
    let mut partition_names: Vec<String> = Vec::new();

    // Simple argument parsing
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-p" | "--partition" => {
                if i + 1 < args.len() {
                    i += 1;
                    partition_names.push(args[i].clone());
                }
            }
            "-w" | "--wildcard" => {
                partition_names.clear();
                partition_names.push("*".to_string());
            }
            "-h" | "--help" => {
                print_usage(&args[0]);
                return Ok(());
            }
            _ => {}
        }
        i += 1;
    }

    // Default partition
    if partition_names.is_empty() {
        partition_names.push("DefaultPartition".to_string());
    }

    println!("Configuration:");
    println!("  Partitions: {}\n", format_partitions(&partition_names));

    // Create participant
    println!("Creating DomainParticipant...");

    let participant = hdds::Participant::builder("Partitions")
        .domain_id(0)
        .with_transport(hdds::TransportMode::UdpMulticast)
        .build()?;

    println!("[OK] Participant created");

    // Create QoS with partition settings
    println!(
        "\nCreating endpoints with partitions {}...",
        format_partitions(&partition_names)
    );

    // Build QoS with partition - use Partition type
    use hdds::qos::partition::Partition;
    let partition = Partition::new(partition_names.clone());
    let qos = hdds::QoS::default().partition(partition);

    // Create writer and reader with partition QoS
    let writer = participant.create_raw_writer("PartitionDemo", Some(qos.clone()))?;
    println!("[OK] DataWriter created");

    let reader = participant.create_raw_reader("PartitionDemo", Some(qos))?;
    println!("[OK] DataReader created");

    println!("\n--- Partition Matching Rules ---");
    println!("Two endpoints match if they share at least one partition.");
    println!("The '*' wildcard matches any partition name.");
    println!("'Sensor*' matches 'SensorA', 'SensorB', etc.\n");

    println!("--- Communication Loop ---");
    println!("Only endpoints in matching partitions will communicate.\n");

    // Communication loop
    for msg_count in 1..=10 {
        // Send message
        let message = format!(
            "Message #{} from partition {}",
            msg_count,
            format_partitions(&partition_names)
        );

        println!("[SEND] {}", message);
        if let Err(e) = writer.write_raw(message.as_bytes()) {
            println!("[WARN] Write failed: {}", e);
        }

        // Small delay to allow data to arrive
        thread::sleep(Duration::from_millis(100));

        // Check for messages using try_take_raw()
        match reader.try_take_raw() {
            Ok(samples) => {
                for sample in samples {
                    if let Ok(text) = String::from_utf8(sample.payload) {
                        println!("[RECV] {}", text);
                    }
                }
            }
            Err(e) => {
                if !matches!(e, hdds::Error::WouldBlock) {
                    println!("[WARN] Read error: {}", e);
                }
            }
        }

        thread::sleep(Duration::from_secs(2));
    }

    // Summary
    println!("\n--- Partition Summary ---");
    println!(
        "Partition names used: {}",
        format_partitions(&partition_names)
    );
    if let Some(discovery) = participant.discovery() {
        println!("Discovered participants: {}", discovery.participant_count());
    }

    println!("\n=== Sample Complete ===");
    Ok(())
}
