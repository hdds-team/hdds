// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Test end-to-end SPDP discovery functionality.
//!
//! This example verifies that SPDP announcements actually work by:
//! 1. Creating a participant with UdpMulticast transport
//! 2. Waiting for SPDP announcements to be sent
//! 3. Checking if the DiscoveryFsm has received and parsed the announcements
//!
//! This test will FAIL if discovery doesn't actually work.

use hdds::api::{Participant, TransportMode};
use std::thread;
use std::time::Duration;

fn main() {
    println!("=== HDDS End-to-End Discovery Test ===\n");
    println!("[!]  This test will FAIL if SPDP is just 'static code' that does nothing.\n");

    // Enable UDP logging
    std::env::set_var("HDDS_LOG_UDP", "1");

    println!("1  Creating participant with UdpMulticast...");
    let participant = Participant::builder("TestParticipant")
        .with_transport(TransportMode::UdpMulticast)
        .domain_id(0)
        .build()
        .expect("Failed to create participant");

    let guid = participant.guid();
    println!("   [OK] Participant created: GUID={:?}\n", guid);

    println!("2  Checking initial DiscoveryFsm state...");
    if let Some(discovery) = participant.discovery() {
        let initial_participants = discovery.get_participants();
        println!(
            "   Initial participant count: {}\n",
            initial_participants.len()
        );
    } else {
        println!("   [X] FAIL: No DiscoveryFsm (IntraProcess mode?)");
        return;
    }

    println!("3  Waiting 5 seconds for SPDP announcements...");
    println!("   (Announcements sent every 3 seconds)");
    thread::sleep(Duration::from_secs(5));
    println!();

    println!("4  Checking DiscoveryFsm after announcements...");
    if let Some(discovery) = participant.discovery() {
        let discovered_participants = discovery.get_participants();
        let final_count = discovered_participants.len();
        println!("   Final participant count: {}", final_count);

        if final_count == 0 {
            println!("\n[X] FAIL: DiscoveryFsm is EMPTY!");
            println!("   -> Packets are sent but NOT parsed/added to FSM");
            println!("   -> Discovery is non-functional");
            println!("\n   Possible causes:");
            println!("   - Classifier not recognizing packets correctly");
            println!("   - DiscoveryCallback not invoking parse_spdp()");
            println!("   - DiscoveryFsm.handle_spdp() not storing participants");
            std::process::exit(1);
        } else {
            println!("\n[OK] SUCCESS: Discovery is FUNCTIONAL!");
            println!("   -> {} participant(s) discovered", final_count);
            println!("   -> SPDP announcer is working end-to-end");

            // List discovered participants
            println!("\n5  Discovered participants:");
            for p in discovered_participants {
                println!("   - GUID: {:?}", p.guid);
                println!("     Lease: {}ms", p.lease_duration_ms);
            }
        }
    }

    println!("\n[OK] Test complete. Participant shutting down...");
}
