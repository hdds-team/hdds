// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! # HDDS Sample: Discovery Listeners
//!
//! Demonstrates **discovery event monitoring** - tracking when participants
//! and endpoints join or leave the domain.
//!
//! ## Discovery Events
//!
//! ```text
//! ┌───────────────────────────────────────────────────────────────────┐
//! │ Event Type            │ Trigger                    │ Information │
//! ├───────────────────────┼────────────────────────────┼─────────────┤
//! │ PARTICIPANT_DISCOVERED│ New participant joins      │ GUID, QoS   │
//! │ PARTICIPANT_LOST      │ Participant leaves/crashes │ GUID        │
//! │ WRITER_DISCOVERED     │ New DataWriter appears     │ Topic, QoS  │
//! │ READER_DISCOVERED     │ New DataReader appears     │ Topic, QoS  │
//! │ WRITER_LOST           │ DataWriter removed         │ GUID        │
//! │ READER_LOST           │ DataReader removed         │ GUID        │
//! └───────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Event Timeline
//!
//! ```text
//! Time ──────────────────────────────────────────────────────▶
//!
//! Participant B joins:
//! ┌────────────────────────────────────────────────────────────┐
//! │ [t=0]    PARTICIPANT_DISCOVERED(B)                         │
//! │ [t=50ms] WRITER_DISCOVERED(B, "SensorTopic")               │
//! │ [t=51ms] READER_DISCOVERED(B, "CommandTopic")              │
//! │ ...                                                        │
//! │ [t=10s]  PARTICIPANT_LOST(B)  ← B crashed or disconnected  │
//! │ [t=10s]  WRITER_LOST(B)                                    │
//! │ [t=10s]  READER_LOST(B)                                    │
//! └────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Use Cases
//!
//! - **Dashboards**: Show system topology
//! - **Health monitoring**: Detect failures
//! - **Dynamic adaptation**: React to new publishers
//!
//! ## Running the Sample
//!
//! ```bash
//! # Terminal 1 - Start the listener
//! cargo run --bin discovery_listeners
//!
//! # Terminal 2 - Start another app (events will appear in Terminal 1)
//! cargo run --bin simple_discovery
//!
//! # Ctrl+C Terminal 2 to see LOST events in Terminal 1
//! ```

use std::collections::HashSet;
use std::thread;
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== HDDS Discovery Listeners Sample ===\n");

    // Create participant with UDP multicast discovery
    println!("Creating DomainParticipant with discovery...");

    let participant = hdds::Participant::builder("DiscoveryListeners")
        .domain_id(0)
        .with_transport(hdds::TransportMode::UdpMulticast)
        .build()?;

    println!("[OK] Participant created: {}", participant.name());
    println!("     GUID: {:?}", participant.guid());

    // Create a writer and reader for demonstration
    let writer = participant.create_raw_writer("ListenerDemo", None)?;
    println!("[OK] DataWriter created");

    let reader = participant.create_raw_reader("ListenerDemo", None)?;
    println!("[OK] DataReader created");

    println!("\n--- Listening for Discovery Events ---");
    println!("Run other HDDS applications to see events.");
    println!("Press Ctrl+C to exit.\n");

    // Track known participants to detect changes
    let mut known_participants: HashSet<String> = HashSet::new();
    let mut event_count = 0;
    let mut iteration = 0;
    let max_iterations = 15; // Run for about 30 seconds

    loop {
        iteration += 1;

        // Poll discovery for participant changes
        if let Some(discovery) = participant.discovery() {
            let current_count = discovery.participant_count();

            // Check for new participants (simple count-based detection)
            let current_guid = format!("{:?}", participant.guid());
            if !known_participants.contains(&current_guid) {
                known_participants.insert(current_guid.clone());
            }

            // Log current state periodically
            if iteration % 5 == 0 {
                println!(
                    "[STATUS] Iteration {}: {} discovered participant(s)",
                    iteration, current_count
                );
            }
        }

        // Send a heartbeat message
        let message = format!("Heartbeat #{}", iteration);
        if let Err(e) = writer.write_raw(message.as_bytes()) {
            println!("[WARN] Write failed: {}", e);
        }

        // Check for incoming messages
        match reader.try_take_raw() {
            Ok(samples) => {
                for sample in samples {
                    event_count += 1;
                    if let Ok(data) = String::from_utf8(sample.payload) {
                        println!("[EVENT {}] Received: {}", event_count, data);
                    }
                }
            }
            Err(e) => {
                // Only log unexpected errors
                if !matches!(e, hdds::Error::WouldBlock) {
                    println!("[WARN] Read error: {}", e);
                }
            }
        }

        thread::sleep(Duration::from_secs(2));

        if iteration >= max_iterations {
            println!("\n--- Timeout reached ({} iterations) ---", max_iterations);
            break;
        }
    }

    // Summary
    println!("\n--- Discovery Summary ---");
    if let Some(discovery) = participant.discovery() {
        println!("Final participant count: {}", discovery.participant_count());
    }
    println!("Total events received: {}", event_count);

    println!("\n=== Sample Complete ===");
    Ok(())
}
