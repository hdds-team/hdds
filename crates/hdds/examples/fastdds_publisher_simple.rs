// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! FastDDS Interoperability Test - Simple Publisher
//!
//! Publishes Temperature messages that FastDDS can subscribe to.
//! Tests HDDS -> FastDDS interoperability via UDP multicast.
//!
//! Run this publisher:
//!   cargo run --example fastdds_publisher_simple
//!
//! Then monitor with HDDS subscriber or FastDDS subscriber.

use hdds::generated::temperature::Temperature;
use hdds::{Participant, QoS, TransportMode};
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("[*] FastDDS Interoperability Test - HDDS Simple Publisher\n");

    // Create participant with UDP multicast (domain 0)
    println!("[*] Creating participant with UDP multicast transport...");
    let participant = Participant::builder("hdds_publisher")
        .with_transport(TransportMode::UdpMulticast)
        .build()?;

    println!("   Participant: hdds_publisher");
    println!("   Domain: 0");
    println!("   Transport: UDP Multicast (239.255.0.1:7400)");
    println!();

    // Create writer for Temperature topic
    println!("[>] Creating DataWriter for 'sensor/temp'...");
    let writer = participant
        .topic::<Temperature>("sensor/temp")?
        .writer()
        .qos(QoS::best_effort().keep_last(10))
        .build()?;

    println!("   Topic: sensor/temp");
    println!("   Type: Temperature");
    println!("   QoS: BestEffort, KeepLast(10)");
    println!();

    println!("[*] Publishing 10 Temperature samples via UDP multicast...");
    println!("   (1 sample/second)\n");

    // Publish 10 samples
    for i in 0..10 {
        let temp = Temperature {
            value: 20.0 + i as f32 * 0.5, // 20.0, 20.5, 21.0, ...
            timestamp: 1700000000 + i,
        };

        match writer.write(&temp) {
            Ok(()) => {
                println!(
                    "[OK] [{}] Published: {:.1} C (ts: {})",
                    i + 1,
                    temp.value,
                    temp.timestamp
                );
            }
            Err(e) => {
                eprintln!("[!] [{}] Error: {:?}", i + 1, e);
            }
        }

        std::thread::sleep(Duration::from_secs(1));
    }

    let stats = writer.stats();
    println!("\n[i] Publisher Stats:");
    println!("   Messages sent: {}", stats.messages_sent);
    println!("   Bytes sent: {}", stats.bytes_sent);
    println!("   Drops: {}", stats.drops);

    println!("\n[OK] Publishing complete!");
    println!("   All samples sent via UDP multicast to 239.255.0.1:7400");

    Ok(())
}
