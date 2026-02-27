// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! # HDDS Sample: Cross-Vendor Discovery Test
//!
//! This sample tests **DDS discovery** (SPDP/SEDP) with multiple vendors.
//! It creates a participant and listens for other DDS participants on the network.
//!
//! ## How DDS Discovery Works
//!
//! DDS uses a two-phase discovery protocol:
//!
//! 1. **SPDP (Simple Participant Discovery Protocol)**
//!    - Participants announce themselves via multicast
//!    - Default multicast group: 239.255.0.1
//!    - Port based on domain ID: 7400 + (domain * 250)
//!
//! 2. **SEDP (Simple Endpoint Discovery Protocol)**
//!    - After participants discover each other, they exchange endpoint info
//!    - Topics, types, and QoS are matched
//!    - Compatible readers/writers are connected
//!
//! ## Running the Test
//!
//! ```bash
//! # Terminal 1 - Start HDDS discovery test
//! cargo run --bin discovery_test
//!
//! # Terminal 2+ - Start participants from other DDS implementations
//! # FastDDS: ./DDSHelloWorldExample
//! # CycloneDDS: ./HelloWorldSubscriber
//! # RTI: ./objs/<arch>/HelloWorld_publisher
//! ```
//!
//! ## Expected Output
//!
//! When other DDS participants join domain 0, you should see them discovered
//! in HDDS logs (set RUST_LOG=debug for verbose output).

use std::thread;
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", "=".repeat(60));
    println!("HDDS Cross-Vendor Discovery Test");
    println!("Domain: 0 | Transport: UDP Multicast");
    println!("{}\n", "=".repeat(60));

    // -------------------------------------------------------------------------
    // Create Participant for Discovery
    // -------------------------------------------------------------------------
    //
    // Creating a participant automatically:
    // - Starts SPDP announcements (multicast "I exist" messages)
    // - Listens for other participants' announcements
    // - Initiates SEDP when new participants are found
    //
    // For debugging discovery issues:
    //   RUST_LOG=hdds::discovery=debug cargo run --bin discovery_test

    println!("Creating participant and starting discovery...\n");

    let participant = hdds::Participant::builder("DiscoveryTest")
        .with_transport(hdds::TransportMode::UdpMulticast)
        .domain_id(0)
        .build()?;

    println!("Participant Details:");
    println!("  Name: {}", participant.name());
    println!("  Domain ID: {}", participant.domain_id());
    println!();

    // -------------------------------------------------------------------------
    // Discovery Information
    // -------------------------------------------------------------------------

    println!("Discovery Configuration:");
    println!("  SPDP Multicast: 239.255.0.1");
    println!("  Port Range: 7400+ (domain-dependent)");
    println!("  Protocol: RTPS 2.3");
    println!();

    println!("Listening for other DDS participants...");
    println!("Start participants from FastDDS, CycloneDDS, RTI, etc.");
    println!("Set RUST_LOG=debug to see discovery messages.\n");

    // -------------------------------------------------------------------------
    // Discovery Loop
    // -------------------------------------------------------------------------
    //
    // In a real application, you might use:
    //   participant.get_discovered_participants()
    // to query discovered peers programmatically.
    //
    // For this test, we simply keep the participant alive and let the
    // discovery protocol run. Check logs for discovered peers.

    println!("Running discovery for 30 seconds...");
    println!("Press Ctrl+C to exit early.\n");

    for i in 1..=30 {
        print!(
            "  [{:02}/30] Discovering peers... (check logs for activity)\r",
            i
        );

        // Discovery happens in background threads.
        // This sleep just keeps the main thread alive.
        thread::sleep(Duration::from_secs(1));
    }

    // -------------------------------------------------------------------------
    // Summary
    // -------------------------------------------------------------------------

    println!("\n\n{}", "=".repeat(60));
    println!("Discovery test complete.");
    println!();
    println!("What to check:");
    println!("  - Did other participants appear in HDDS logs?");
    println!("  - Did HDDS appear in other implementations' logs?");
    println!("  - Were there any 'unknown vendor' or 'type mismatch' warnings?");
    println!();
    println!("Troubleshooting:");
    println!("  - Ensure all participants use domain 0");
    println!("  - Check firewall allows UDP multicast (239.255.x.x)");
    println!("  - Verify network interface supports multicast");
    println!("{}", "=".repeat(60));

    Ok(())
}
