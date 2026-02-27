// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com
//
// Phase 2.1: HDDS <-> RTI Discovery Test
// Lists all discovered DDS participants on the network

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::missing_errors_doc)]

use hdds::{Participant, TransportMode};
use std::thread;
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== HDDS Participant Discovery Test ===");
    println!("Scanning for DDS participants on the network...\n");

    // Create HDDS participant with UDP multicast
    let participant = Participant::builder("hdds_scanner")
        .with_transport(TransportMode::UdpMulticast)
        .domain_id(0)
        .build()?;

    println!(
        "[OK] HDDS participant created (GUID: {:?})",
        participant.guid()
    );
    println!("  Listening for SPDP announcements on port 7400...\n");

    // Wait for discovery (SPDP packets sent every 3 seconds)
    println!("Waiting 10 seconds for participant discovery...");
    for i in 1..=10 {
        thread::sleep(Duration::from_secs(1));
        print!(".");
        std::io::Write::flush(&mut std::io::stdout())?;

        // Check discovery every second
        if let Some(ref discovery) = participant.discovery() {
            let participants = discovery.get_participants();
            if !participants.is_empty() && i >= 3 {
                println!(
                    "\n\n[OK] Discovered {} remote participant(s)!",
                    participants.len()
                );

                for info in &participants {
                    println!("\n  Participant:");
                    println!("    GUID: {:?}", info.guid);
                    println!("    Lease Duration: {} ms", info.lease_duration_ms);
                    println!("    Unicast Locators: {}", info.endpoints.len());

                    for locator in &info.endpoints {
                        println!("      - {}", locator);
                    }
                }

                println!("\n[OK] SUCCESS: HDDS discovered remote DDS participants!");
                return Ok(());
            }
        }
    }

    println!("\n");

    // Final check
    if let Some(ref discovery) = participant.discovery() {
        let participants = discovery.get_participants();

        if participants.is_empty() {
            println!("[!]  No participants discovered");
            println!("   Make sure a DDS participant (RTI/FastDDS/HDDS) is running");
        } else {
            println!("[OK] Discovered {} participant(s)", participants.len());
        }
    } else {
        println!("[X] Discovery FSM not available (IntraProcess mode?)");
    }

    Ok(())
}
