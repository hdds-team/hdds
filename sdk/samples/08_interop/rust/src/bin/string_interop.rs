// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! # HDDS Sample: DDS String Interoperability
//!
//! This sample demonstrates **cross-vendor DDS interoperability** using HDDS.
//! It shows how to communicate with other DDS implementations like FastDDS,
//! CycloneDDS, or RTI Connext using standard DDS wire protocol (RTPS).
//!
//! ## Key Concepts
//!
//! - **Interoperability**: DDS implementations following the RTPS standard can
//!   communicate regardless of vendor. HDDS implements RTPS 2.3.
//! - **Topic & Type matching**: For interop to work, both sides must use:
//!   - Same topic name (here: "InteropTopic")
//!   - Compatible type (CDR-encoded StringMsg)
//!   - Same domain ID (here: 0)
//! - **UDP Multicast**: Standard discovery mechanism for DDS on local networks.
//!
//! ## Running the Sample
//!
//! ```bash
//! # Terminal 1 - Start HDDS subscriber
//! cargo run --bin string_interop
//!
//! # Terminal 2 - Start HDDS publisher
//! cargo run --bin string_interop -- pub
//!
//! # Alternative: Start a publisher from another DDS implementation
//! # (FastDDS, CycloneDDS, RTI) on topic "InteropTopic" with StringMsg type
//! ```
//!
//! ## Type Definition (IDL)
//!
//! The message type is defined in `sdk/samples/idl/Interop.idl`:
//! ```idl
//! module hdds_interop {
//!     struct StringMsg {
//!         string data;  // Variable-length string
//!     };
//! };
//! ```

use std::env;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

// =============================================================================
// Step 1: Include Generated Types
// =============================================================================
//
// Types are generated from IDL using hdds_gen. The generated code implements:
// - CDR serialization (Cdr2Encode, Cdr2Decode traits)
// - DDS type support (hdds::api::DDS trait)
//
// This ensures wire-format compatibility with other DDS implementations.

#[allow(dead_code)]
mod generated {
    include!("../../generated/interop.rs");
}

use generated::hdds_interop::StringMsg;

// =============================================================================
// Publisher Implementation
// =============================================================================

/// Runs the publisher side of the interop demo.
///
/// Creates a DataWriter and publishes StringMsg samples that can be received
/// by any DDS-compliant subscriber on the same topic.
fn run_publisher(participant: &Arc<hdds::Participant>) -> Result<(), hdds::Error> {
    println!("Creating DataWriter for interop testing...");

    // -------------------------------------------------------------------------
    // QoS Selection for Interoperability
    // -------------------------------------------------------------------------
    //
    // RELIABLE QoS ensures:
    // - Message delivery is acknowledged
    // - Lost messages are retransmitted
    // - Better compatibility with other DDS implementations' default settings
    //
    // For high-throughput scenarios, consider BEST_EFFORT instead.

    let qos = hdds::QoS::reliable();

    // -------------------------------------------------------------------------
    // Create Typed DataWriter
    // -------------------------------------------------------------------------
    //
    // The generic parameter <StringMsg> tells HDDS:
    // - What type to serialize (using generated CDR code)
    // - What type name to advertise in discovery
    //
    // Topic name "InteropTopic" must match on subscriber side.

    let writer = participant.create_writer::<StringMsg>("InteropTopic", qos)?;

    println!("Publishing StringMsg messages...");
    println!("(Start a subscriber from FastDDS/CycloneDDS/RTI on same topic)\n");

    // -------------------------------------------------------------------------
    // Publish Messages
    // -------------------------------------------------------------------------

    for i in 0..20 {
        // Create message using the generated struct
        let msg = StringMsg {
            data: format!("Hello from HDDS Rust #{}", i),
        };

        // write() serializes the message to CDR format and sends it
        writer.write(&msg)?;
        println!("  [{:02}] Published: \"{}\"", i, msg.data);

        thread::sleep(Duration::from_millis(500));
    }

    println!("\nPublisher finished. Sent 20 messages.");
    Ok(())
}

// =============================================================================
// Subscriber Implementation
// =============================================================================

/// Runs the subscriber side of the interop demo.
///
/// Creates a DataReader and receives StringMsg samples from any DDS publisher
/// on the same topic, regardless of vendor.
fn run_subscriber(participant: &Arc<hdds::Participant>) -> Result<(), hdds::Error> {
    println!("Creating DataReader for interop testing...");

    let qos = hdds::QoS::reliable();
    let reader = participant.create_reader::<StringMsg>("InteropTopic", qos)?;

    // -------------------------------------------------------------------------
    // WaitSet Pattern
    // -------------------------------------------------------------------------
    //
    // WaitSet is the standard DDS pattern for blocking until data arrives.
    // It's more efficient than polling and works across all DDS implementations.
    //
    // Flow:
    // 1. Get the reader's status condition (signals when data available)
    // 2. Attach it to a WaitSet
    // 3. Call wait() to block until condition triggers
    // 4. Use take() to retrieve and remove samples from the reader

    let status_condition = reader.get_status_condition();
    let waitset = hdds::dds::WaitSet::new();
    waitset.attach_condition(status_condition)?;

    println!("Waiting for messages from any DDS vendor...");
    println!("(Start a publisher from HDDS/FastDDS/CycloneDDS/RTI)\n");

    let mut received = 0;
    while received < 20 {
        // Wait with timeout - returns triggered conditions or WouldBlock
        match waitset.wait(Some(Duration::from_secs(5))) {
            Ok(triggered) => {
                if !triggered.is_empty() {
                    // take() retrieves AND removes samples from the reader
                    // Use read() instead to leave samples in the cache
                    while let Some(msg) = reader.take()? {
                        println!("  [{:02}] Received: \"{}\"", received, msg.data);
                        received += 1;
                    }
                }
            }
            Err(hdds::Error::WouldBlock) => {
                // Timeout - no data received within 5 seconds
                println!("  (waiting for peer publisher...)");
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
// Main Entry Point
// =============================================================================

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse command line: "pub" for publisher, otherwise subscriber
    let args: Vec<String> = env::args().collect();
    let is_publisher = args.get(1).map(|s| s == "pub").unwrap_or(false);

    println!("{}", "=".repeat(60));
    println!("HDDS DDS Interoperability Sample");
    println!("Topic: InteropTopic | Type: hdds_interop::StringMsg");
    println!("{}\n", "=".repeat(60));

    // -------------------------------------------------------------------------
    // Create DDS Participant
    // -------------------------------------------------------------------------
    //
    // The Participant is the entry point to DDS. Key settings:
    //
    // - Transport: UdpMulticast enables standard SPDP/SEDP discovery
    //   that other DDS implementations expect
    // - Domain ID: Must match across all participants that want to communicate
    //   (default is 0, same as ROS2 default)

    let participant = hdds::Participant::builder("InteropTest")
        .with_transport(hdds::TransportMode::UdpMulticast)
        .domain_id(0) // Standard DDS domain
        .build()?;

    println!("DDS Participant created:");
    println!("  Name: {}", participant.name());
    println!("  Domain: {}", participant.domain_id());
    println!("  Transport: UDP Multicast (RTPS standard)\n");

    // Run as publisher or subscriber based on command line
    if is_publisher {
        run_publisher(&participant)?;
    } else {
        run_subscriber(&participant)?;
    }

    Ok(())
}
