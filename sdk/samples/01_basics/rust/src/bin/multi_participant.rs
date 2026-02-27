// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! # HDDS Sample: Multi-Participant
//!
//! Demonstrates running **multiple DDS participants** within the same process,
//! each in its own thread - a common pattern for modular applications.
//!
//! ## Why Multiple Participants?
//!
//! While one participant can host many readers/writers, separate participants
//! are useful for:
//!
//! - **Isolation**: Different components with different lifecycles
//! - **Different domains**: Participants in different domain IDs
//! - **Different QoS profiles**: Each participant can have different defaults
//! - **Testing**: Simulate multi-node scenarios in one process
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────── Process ───────────────────┐
//! │                                               │
//! │  ┌─────────────┐       ┌─────────────┐       │
//! │  │ Publisher-A │       │ Publisher-B │       │
//! │  │ (Participant)│       │ (Participant)│       │
//! │  └──────┬──────┘       └──────┬──────┘       │
//! │         │                     │              │
//! │         └──────────┬──────────┘              │
//! │                    │                         │
//! │                    ▼                         │
//! │           Topic: "MultiParticipantTopic"     │
//! │                    │                         │
//! │                    ▼                         │
//! │            ┌─────────────┐                   │
//! │            │  Subscriber │                   │
//! │            │ (Participant)│                   │
//! │            └─────────────┘                   │
//! │                                               │
//! └───────────────────────────────────────────────┘
//! ```
//!
//! ## Running the Sample
//!
//! ```bash
//! # Runs automatically with 2 publishers and 1 subscriber
//! cargo run --bin multi_participant
//! ```

use std::thread;
use std::time::Duration;

// =============================================================================
// Generated Types
// =============================================================================

#[allow(dead_code)]
mod generated {
    include!("../../generated/hello_world.rs");
}

use generated::hdds_samples::HelloWorld;

// =============================================================================
// Publisher Thread
// =============================================================================

/// Creates a participant and publishes messages in a separate thread.
///
/// Each publisher thread:
/// 1. Creates its own Participant (independent discovery)
/// 2. Creates a DataWriter on the shared topic
/// 3. Publishes messages with its identity
fn publisher_thread(name: &str, topic: &str) {
    println!("[{}] Starting...", name);

    // -------------------------------------------------------------------------
    // Each Thread Gets Its Own Participant
    // -------------------------------------------------------------------------
    //
    // Participants are thread-safe and can be shared (via Arc), but here we
    // create separate participants to demonstrate full isolation.

    let participant = hdds::Participant::builder(name)
        .with_transport(hdds::TransportMode::IntraProcess)
        .build()
        .expect("Failed to create participant");

    let writer = participant
        .create_writer::<HelloWorld>(topic, hdds::QoS::default())
        .expect("Failed to create writer");

    println!("[{}] Publishing to '{}'...", name, topic);

    for i in 0..5 {
        let msg = HelloWorld::new(format!("From {}", name), i);
        writer.write(&msg).expect("Write failed");
        println!("[{}] Sent: \"{}\" #{}", name, msg.message, msg.count);

        thread::sleep(Duration::from_millis(300));
    }

    println!("[{}] Finished.", name);

    // Participant is automatically cleaned up when it goes out of scope
}

// =============================================================================
// Subscriber Thread
// =============================================================================

/// Creates a participant and receives messages from multiple publishers.
///
/// Demonstrates receiving messages from multiple sources on the same topic.
fn subscriber_thread(name: &str, topic: &str) {
    println!("[{}] Starting...", name);

    let participant = hdds::Participant::builder(name)
        .with_transport(hdds::TransportMode::IntraProcess)
        .build()
        .expect("Failed to create participant");

    let reader = participant
        .create_reader::<HelloWorld>(topic, hdds::QoS::default())
        .expect("Failed to create reader");

    let waitset = hdds::dds::WaitSet::new();
    waitset
        .attach_condition(reader.get_status_condition())
        .expect("Failed to attach condition");

    println!("[{}] Listening on '{}'...", name, topic);

    // -------------------------------------------------------------------------
    // Receive from Multiple Publishers
    // -------------------------------------------------------------------------
    //
    // The subscriber doesn't know (or care) how many publishers exist.
    // DDS discovery automatically matches compatible endpoints.

    let expected = 10; // 5 messages × 2 publishers
    let mut received = 0;

    while received < expected {
        match waitset.wait(Some(Duration::from_secs(2))) {
            Ok(triggered) if !triggered.is_empty() => {
                while let Some(msg) = reader.take().ok().flatten() {
                    println!("[{}] Received: \"{}\" #{}", name, msg.message, msg.count);
                    received += 1;
                }
            }
            Ok(_) | Err(hdds::Error::WouldBlock) => {
                // Timeout - continue waiting
            }
            Err(e) => {
                eprintln!("[{}] Error: {:?}", name, e);
            }
        }
    }

    println!("[{}] Finished. Received {} messages.", name, received);
}

// =============================================================================
// Main
// =============================================================================

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", "=".repeat(60));
    println!("HDDS Multi-Participant Sample");
    println!("Running 3 participants: 2 publishers + 1 subscriber");
    println!("{}\n", "=".repeat(60));

    let topic = "MultiParticipantTopic";

    // -------------------------------------------------------------------------
    // Thread Orchestration
    // -------------------------------------------------------------------------
    //
    // Start subscriber first to ensure it's ready when publishers begin.
    // In DDS, late-joining subscribers may miss messages depending on QoS.

    // Start subscriber thread
    let topic_sub = topic.to_string();
    let subscriber = thread::spawn(move || subscriber_thread("Subscriber", &topic_sub));

    // Give subscriber time to initialize
    thread::sleep(Duration::from_millis(200));

    // Start two publisher threads
    let topic_a = topic.to_string();
    let publisher_a = thread::spawn(move || publisher_thread("Publisher-A", &topic_a));

    let topic_b = topic.to_string();
    let publisher_b = thread::spawn(move || publisher_thread("Publisher-B", &topic_b));

    // Wait for all threads to complete
    subscriber.join().expect("Subscriber thread panicked");
    publisher_a.join().expect("Publisher-A thread panicked");
    publisher_b.join().expect("Publisher-B thread panicked");

    // -------------------------------------------------------------------------
    // Summary
    // -------------------------------------------------------------------------

    println!("\n{}", "=".repeat(60));
    println!("All participants finished successfully.");
    println!("Each participant ran independently in its own thread.");
    println!("{}", "=".repeat(60));

    Ok(())
}
