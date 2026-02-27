// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! # HDDS Sample: Simple Discovery (SPDP)
//!
//! Demonstrates **automatic multicast discovery** using SPDP (Simple Participant
//! Discovery Protocol) - the zero-configuration way to find peers.
//!
//! ## How SPDP Works
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │                        Multicast Group                              │
//! │                      (239.255.0.1:7400)                             │
//! │                                                                     │
//! │   ┌──────────────┐         ┌──────────────┐        ┌─────────────┐ │
//! │   │ Participant A│◄───────►│ Participant B│◄──────►│Participant C│ │
//! │   │              │         │              │        │             │ │
//! │   │ GUID: 0xA... │         │ GUID: 0xB... │        │ GUID: 0xC...│ │
//! │   └──────────────┘         └──────────────┘        └─────────────┘ │
//! │                                                                     │
//! │   1. Each participant announces itself periodically                 │
//! │   2. Announcements include GUID, locators, QoS                      │
//! │   3. Peers receive announcements and update their database          │
//! └─────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Discovery Phases
//!
//! | Phase | Protocol | Purpose                          |
//! |-------|----------|----------------------------------|
//! | SPDP  | Multicast| Find participants in domain      |
//! | SEDP  | Unicast  | Exchange endpoint information    |
//!
//! ## Domain IDs
//!
//! ```text
//! Domain 0:              Domain 1:              Domain 2:
//! ┌──────────────┐      ┌──────────────┐       ┌──────────────┐
//! │ App A        │      │ App C        │       │ App E        │
//! │ App B        │      │ App D        │       │              │
//! └──────────────┘      └──────────────┘       └──────────────┘
//!     Isolated              Isolated              Isolated
//!
//! Different domains use different multicast ports - no cross-talk!
//! ```
//!
//! ## Running the Sample
//!
//! ```bash
//! # Terminal 1 - First participant
//! cargo run --bin simple_discovery
//!
//! # Terminal 2 - Second participant (will discover first)
//! cargo run --bin simple_discovery
//!
//! # Watch them discover each other automatically!
//! ```

use std::thread;
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== HDDS Simple Discovery Sample ===\n");

    // Get instance ID from args or generate random
    let instance_id: u32 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(std::process::id);

    println!("Instance ID: {}", instance_id);
    println!("Domain ID: 0 (default)\n");

    // Create participant with default discovery settings
    // This automatically enables SPDP multicast discovery
    println!("Creating DomainParticipant...");
    let participant = hdds::Participant::builder(&format!("SimpleDiscovery_{}", instance_id))
        .domain_id(0)
        .with_transport(hdds::TransportMode::UdpMulticast)
        .build()?;

    println!("[OK] Participant created: {}", participant.name());
    println!("     GUID: {:?}", participant.guid());

    // Create a raw writer and reader for demonstration
    let writer = participant.create_raw_writer("DiscoveryDemo", None)?;
    println!("[OK] DataWriter created");

    let reader = participant.create_raw_reader("DiscoveryDemo", None)?;
    println!("[OK] DataReader created");

    println!("\n--- Discovery in Progress ---");
    println!("Waiting for other participants to join...");
    println!("(Run another instance of this sample to see discovery)\n");

    // Announce ourselves periodically
    let announce_interval = Duration::from_secs(2);
    let mut announce_count = 0;

    loop {
        // Send an announcement
        announce_count += 1;
        let message = format!(
            "Hello from instance {} (message #{})",
            instance_id, announce_count
        );

        match writer.write_raw(message.as_bytes()) {
            Ok(_) => println!("[SENT] {}", message),
            Err(e) => println!("[ERROR] Failed to send: {}", e),
        }

        // Small delay to allow data to arrive
        thread::sleep(Duration::from_millis(100));

        // Check for messages from other participants
        match reader.try_take_raw() {
            Ok(samples) => {
                for sample in samples {
                    if let Ok(data) = String::from_utf8(sample.payload) {
                        println!("[RECV] {}", data);
                    }
                }
            }
            Err(e) => println!("[WARN] Read error: {}", e),
        }

        // Wait before next announcement
        thread::sleep(announce_interval);

        // Exit after a while for demo purposes
        if announce_count >= 10 {
            println!("\n--- Sample complete (10 announcements sent) ---");
            break;
        }
    }

    // Show discovery statistics
    println!("\n--- Discovery Statistics ---");
    if let Some(discovery) = participant.discovery() {
        let count = discovery.participant_count();
        println!("Discovered {} other participant(s)", count);
    } else {
        println!("Discovery not available in IntraProcess mode");
    }

    println!("\n=== Sample Complete ===");
    Ok(())
}
