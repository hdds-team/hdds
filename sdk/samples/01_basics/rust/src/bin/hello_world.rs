// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! # HDDS Sample: Hello World
//!
//! The classic "Hello World" of DDS - demonstrates the fundamental
//! **publish-subscribe** pattern that is the core of DDS communication.
//!
//! ## What You'll Learn
//!
//! - Creating a DDS Participant (entry point to DDS)
//! - Creating typed DataWriters and DataReaders
//! - Publishing and receiving messages
//! - Using WaitSet for efficient blocking reads
//!
//! ## DDS Basics
//!
//! ```text
//! ┌─────────────┐         Topic: "HelloWorldTopic"        ┌─────────────┐
//! │  Publisher  │ ───────────────────────────────────────▶│  Subscriber │
//! │ (DataWriter)│            HelloWorld message           │ (DataReader)│
//! └─────────────┘                                         └─────────────┘
//! ```
//!
//! - **Participant**: Container for all DDS entities, handles discovery
//! - **Topic**: Named channel for data exchange
//! - **DataWriter**: Sends typed messages to a topic
//! - **DataReader**: Receives typed messages from a topic
//!
//! ## Running the Sample
//!
//! ```bash
//! # Terminal 1 - Start subscriber first
//! cargo run --bin hello_world
//!
//! # Terminal 2 - Start publisher
//! cargo run --bin hello_world -- pub
//! ```
//!
//! ## Message Type (IDL)
//!
//! ```idl
//! struct HelloWorld {
//!     string message;
//!     long count;
//! };
//! ```

use std::env;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

// =============================================================================
// Generated Types
// =============================================================================
//
// Types are generated from IDL files using hddsgen. The generated code
// implements the hdds::api::DDS trait (with Cdr2Encode/Cdr2Decode for
// serialization), enabling type registration with the DDS infrastructure.
//
// include!() is a Rust compiler macro that inserts a file's contents at
// compile time. Generated modules may export constructors and builders you
// don't use directly, hence #[allow(dead_code)].

#[allow(dead_code)]
mod generated {
    include!("../../generated/hello_world.rs");
}

use generated::hdds_samples::HelloWorld;

// =============================================================================
// Publisher
// =============================================================================

/// Publishes HelloWorld messages to demonstrate basic DDS writing.
///
/// Key concepts:
/// - Topic builder pattern creates typed writers
/// - `write()` serializes and sends the message
/// - QoS controls delivery guarantees (default = best_effort)
fn run_publisher(participant: &Arc<hdds::Participant>) -> Result<(), hdds::Error> {
    println!("Creating DataWriter...");

    // -------------------------------------------------------------------------
    // Create Typed Writer
    // -------------------------------------------------------------------------
    //
    // The generic parameter <HelloWorld> tells HDDS:
    // - What type to serialize (CDR encoding)
    // - What type name to advertise in discovery
    //
    // QoS::default() provides sensible defaults for most use cases.

    let topic = participant.topic::<HelloWorld>("HelloWorldTopic")?;
    let writer = topic.writer().qos(hdds::QoS::default()).build()?;

    println!("Publishing 10 messages...\n");

    for i in 0..10 {
        // Create message using generated constructor
        let msg = HelloWorld::new("Hello from HDDS Rust!", i);

        // write() serializes to CDR and sends via configured transport
        writer.write(&msg)?;

        println!(
            "  [{}] Published: \"{}\" (count={})",
            i, msg.message, msg.count
        );

        thread::sleep(Duration::from_millis(500));
    }

    println!("\nPublisher finished.");
    Ok(())
}

// =============================================================================
// Subscriber
// =============================================================================

/// Receives HelloWorld messages to demonstrate basic DDS reading.
///
/// Key concepts:
/// - Topic builder pattern creates typed readers
/// - WaitSet blocks efficiently until data arrives
/// - `take()` retrieves AND removes samples from the reader cache
fn run_subscriber(participant: &Arc<hdds::Participant>) -> Result<(), hdds::Error> {
    println!("Creating DataReader...");

    let topic = participant.topic::<HelloWorld>("HelloWorldTopic")?;
    let reader = topic.reader().qos(hdds::QoS::default()).build()?;

    // -------------------------------------------------------------------------
    // WaitSet Pattern
    // -------------------------------------------------------------------------
    //
    // WaitSet is the standard DDS pattern for blocking until data arrives.
    // Much more efficient than polling in a loop!
    //
    // Flow:
    // 1. Get reader's status condition (signals "data available")
    // 2. Attach condition to a WaitSet
    // 3. Call wait() - blocks until condition triggers or timeout
    // 4. Use take() to retrieve samples

    let status_condition = reader.get_status_condition();
    let waitset = hdds::dds::WaitSet::new();
    waitset.attach_condition(status_condition)?;

    println!("Waiting for messages (start publisher with: cargo run --bin hello_world -- pub)\n");

    let mut received = 0;
    while received < 10 {
        // Wait with 5-second timeout
        match waitset.wait(Some(Duration::from_secs(5))) {
            Ok(triggered) => {
                if !triggered.is_empty() {
                    // take() retrieves AND removes samples
                    // Use read() to leave samples in cache
                    while let Some(msg) = reader.take()? {
                        println!(
                            "  [{}] Received: \"{}\" (count={})",
                            received, msg.message, msg.count
                        );
                        received += 1;
                    }
                }
            }
            Err(hdds::Error::WouldBlock) => {
                // WouldBlock = timeout expired with no data.
                // (DDS spec uses this name; think of it as "nothing to do yet")
                println!(
                    "  (waiting for publisher... hint: run with '-- pub' in another terminal)"
                );
            }
            Err(e) => {
                eprintln!("Wait error: {:?}", e);
            }
        }
    }

    println!("\nSubscriber finished. Received {} messages.", received);
    Ok(())
}

// =============================================================================
// Main
// =============================================================================

fn main() -> hdds::Result<()> {
    // Parse command line arguments
    let args: Vec<String> = env::args().collect();
    let is_publisher = args
        .get(1)
        .map(|s| s == "pub" || s == "publisher" || s == "-p")
        .unwrap_or(false);

    println!("{}", "=".repeat(60));
    println!("HDDS Hello World Sample");
    println!("The fundamental DDS publish-subscribe pattern");
    println!("{}\n", "=".repeat(60));

    // -------------------------------------------------------------------------
    // Create Participant
    // -------------------------------------------------------------------------
    //
    // The Participant is the entry point to DDS. It:
    // - Manages discovery of other participants
    // - Contains all readers/writers
    // - Configures transport
    //
    // UdpMulticast enables communication between separate processes/machines.
    // For same-process testing only, use TransportMode::IntraProcess instead.

    println!("Creating DDS Participant...");

    let participant = hdds::Participant::builder("HelloWorld")
        .domain_id(0)
        .with_transport(hdds::TransportMode::UdpMulticast)
        .build()?;

    println!("  Name: {}", participant.name());
    println!("  Transport: UdpMulticast\n");

    // Run as publisher or subscriber based on command line
    if is_publisher {
        run_publisher(&participant)?;
    } else {
        run_subscriber(&participant)?;
    }

    println!("\nCleanup complete.");
    Ok(())
}
