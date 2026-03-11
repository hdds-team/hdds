// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Multi-Node Pub/Sub Demo (v0.3.0 UDP Multicast)
//!
//! Demonstrates inter-process communication via UDP multicast.
//!
//! # Usage
//!
//! Terminal 1 (Publisher):
//! ```bash
//! cargo run --example multi_node_pubsub -- pub
//! ```
//!
//! Terminal 2 (Subscriber):
//! ```bash
//! cargo run --example multi_node_pubsub -- sub
//! ```
//!
//! # Validation
//!
//! - Terminal 1: publishes Temperature samples every 1s
//! - Terminal 2: receives and prints samples
//! - Wireshark: capture UDP 239.255.0.1:7400 packets to see RTPS traffic

use hdds::generated::temperature::Temperature;
use hdds::{Participant, QoS, TransportMode};
use std::env;
use std::thread;
use std::time::Duration;

fn main() {
    let args: Vec<String> = env::args().collect();

    match args.get(1).map(|s| s.as_str()) {
        Some("pub") => run_publisher(),
        Some("sub") => run_subscriber(),
        _ => {
            println!("Usage: multi_node_pubsub [pub|sub]");
            println!();
            println!("Commands:");
            println!("  pub    Run as publisher (sends Temperature samples via UDP)");
            println!("  sub    Run as subscriber (receives Temperature samples via UDP)");
            println!();
            println!("Example:");
            println!("  Terminal 1: cargo run --example multi_node_pubsub -- pub");
            println!("  Terminal 2: cargo run --example multi_node_pubsub -- sub");
        }
    }
}

/// Publisher mode: sends Temperature samples via UDP multicast
fn run_publisher() {
    println!("[*] Starting Publisher (UDP Multicast)");
    println!("   - Sending to: 239.255.0.1:7400");
    println!("   - Topic: sensor/temp");
    println!("   - Rate: 1 Hz");
    println!();

    // Create participant with UDP multicast mode
    let participant = Participant::builder("publisher_node")
        .with_transport(TransportMode::UdpMulticast)
        .build()
        .expect("Failed to create participant");

    // Create writer
    let writer = participant
        .topic::<Temperature>("sensor/temp")
        .expect("Failed to create topic")
        .writer()
        .qos(QoS::reliable().transient_local().keep_last(10))
        .build()
        .expect("Failed to create writer");

    println!("[OK] Publisher ready - sending samples...");
    println!();

    // Publish loop
    let mut seq = 0u64;
    let start_time = std::time::Instant::now();

    loop {
        let elapsed_secs = start_time.elapsed().as_secs();
        let temp_value = 20.0 + (seq as f32 * 0.5) % 10.0; // Vary temperature

        let sample = Temperature {
            value: temp_value,
            timestamp: elapsed_secs as i32,
        };

        match writer.write(&sample) {
            Ok(_) => {
                println!(
                    "[{:06}] Published: {:.1} degC (timestamp: {}s)",
                    seq, temp_value, elapsed_secs
                );
            }
            Err(e) => {
                eprintln!("Write failed: {:?}", e);
            }
        }

        seq += 1;
        thread::sleep(Duration::from_secs(1));
    }
}

/// Subscriber mode: receives Temperature samples via UDP multicast
fn run_subscriber() {
    println!("[*] Starting Subscriber (UDP Multicast)");
    println!("   - Listening on: 239.255.0.1:7400");
    println!("   - Topic: sensor/temp");
    println!("   - Polling: 10 Hz");
    println!();

    // Create participant with UDP multicast mode
    let participant = Participant::builder("subscriber_node")
        .with_transport(TransportMode::UdpMulticast)
        .build()
        .expect("Failed to create participant");

    // Create reader
    let reader = participant
        .topic::<Temperature>("sensor/temp")
        .expect("Failed to create topic")
        .reader()
        .qos(QoS::best_effort().keep_last(100))
        .build()
        .expect("Failed to create reader");

    println!("[OK] Subscriber ready - waiting for samples...");
    println!();

    let mut received_count = 0u64;

    // Subscribe loop
    loop {
        match reader.take() {
            Ok(Some(sample)) => {
                received_count += 1;
                println!(
                    "[RX {:06}] Temperature: {:.1} degC (timestamp: {}s)",
                    received_count, sample.value, sample.timestamp
                );
            }
            Ok(None) => {
                // No data available - continue polling
            }
            Err(e) => {
                eprintln!("Read failed: {:?}", e);
            }
        }

        // Poll at 10 Hz
        thread::sleep(Duration::from_millis(100));
    }
}
