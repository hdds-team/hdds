// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Two-participant SPDP discovery validation test.
//!
//! This is the definitive end-to-end test for HDDS discovery.
//!
//! ## What This Test Validates:
//!
//! 1. Participant A announces itself via SPDP (239.255.0.1:7400)
//! 2. Participant B receives A's announcement and adds it to DiscoveryFsm
//! 3. Participant B announces itself via SPDP
//! 4. Participant A receives B's announcement and adds it to DiscoveryFsm
//! 5. After 10 seconds, each participant's DiscoveryFsm contains the OTHER participant
//!
//! ## Success Criteria:
//!
//! - Participant A discovers Participant B (FSM has 1 remote participant)
//! - Participant B discovers Participant A (FSM has 1 remote participant)
//! - GUIDs match correctly (A sees B's GUID, B sees A's GUID)
//!
//! ## Failure Scenarios:
//!
//! - If DiscoveryFsm is empty -> Discovery is broken (static code)
//! - If participants only see themselves -> Self-discovery filter is broken
//! - If GUIDs don't match -> Parsing or packet routing is broken

use hdds::api::{Participant, TransportMode};
use std::thread;
use std::time::Duration;

fn main() {
    println!("=======================================================");
    println!("  HDDS Two-Participant Discovery Test");
    println!("=======================================================\n");

    // Enable UDP logging
    std::env::set_var("HDDS_LOG_UDP", "1");

    println!("1  Creating Participant A (domain 0, participant_id 0)...");
    let participant_a = Participant::builder("ParticipantA")
        .with_transport(TransportMode::UdpMulticast)
        .domain_id(0)
        .participant_id(Some(0))
        .build()
        .expect("Failed to create participant A");

    let guid_a = participant_a.guid();
    println!("   [OK] Participant A created: GUID={:?}\n", guid_a);

    println!("2  Creating Participant B (domain 0, participant_id 1)...");
    let participant_b = Participant::builder("ParticipantB")
        .with_transport(TransportMode::UdpMulticast)
        .domain_id(0)
        .participant_id(Some(1))
        .build()
        .expect("Failed to create participant B");

    let guid_b = participant_b.guid();
    println!("   [OK] Participant B created: GUID={:?}\n", guid_b);

    println!("3  Initial DiscoveryFsm state (should be empty)...");
    let initial_a = participant_a
        .discovery()
        .expect("No discovery on participant A")
        .get_participants();
    let initial_b = participant_b
        .discovery()
        .expect("No discovery on participant B")
        .get_participants();

    println!("   Participant A FSM: {} participants", initial_a.len());
    println!("   Participant B FSM: {} participants\n", initial_b.len());

    println!("4  Waiting 10 seconds for SPDP announcements...");
    println!("   (Announcements sent every 3 seconds)");
    println!("   -> A announces to 239.255.0.1:7400");
    println!("   -> B receives A's announcement");
    println!("   -> B announces to 239.255.0.1:7400");
    println!("   -> A receives B's announcement\n");

    for i in 1..=10 {
        print!("   {}...", i);
        std::io::Write::flush(&mut std::io::stdout()).ok();
        thread::sleep(Duration::from_secs(1));
    }
    println!("\n");

    println!("5  Checking Participant A's DiscoveryFsm...");
    let discovered_by_a = participant_a
        .discovery()
        .expect("No discovery on participant A")
        .get_participants();

    println!(
        "   Participant A sees {} remote participant(s)",
        discovered_by_a.len()
    );

    if discovered_by_a.is_empty() {
        println!("\n[X] FAIL: Participant A's DiscoveryFsm is EMPTY!");
        println!("   -> A did not discover B");
        println!("   -> Possible causes:");
        println!("     - B's SPDP announcements not sent");
        println!("     - A's listener not receiving packets");
        println!("     - Callback or parser broken");
        std::process::exit(1);
    }

    // Verify A discovered B (not itself)
    let found_b_in_a = discovered_by_a.iter().any(|p| p.guid == guid_b);
    let found_self_in_a = discovered_by_a.iter().any(|p| p.guid == guid_a);

    if found_self_in_a {
        println!("\n[X] FAIL: Participant A discovered ITSELF!");
        println!("   -> Self-discovery filtering is broken");
        std::process::exit(1);
    }

    if !found_b_in_a {
        println!("\n[X] FAIL: Participant A did not discover Participant B!");
        println!("   -> Discovered GUIDs:");
        for p in &discovered_by_a {
            println!("     - {:?}", p.guid);
        }
        println!("   -> Expected to find: {:?}", guid_b);
        std::process::exit(1);
    }

    println!("   [OK] Participant A discovered Participant B correctly");
    println!("      GUID: {:?}", guid_b);
    println!("      Lease: {}ms\n", discovered_by_a[0].lease_duration_ms);

    println!("6  Checking Participant B's DiscoveryFsm...");
    let discovered_by_b = participant_b
        .discovery()
        .expect("No discovery on participant B")
        .get_participants();

    println!(
        "   Participant B sees {} remote participant(s)",
        discovered_by_b.len()
    );

    if discovered_by_b.is_empty() {
        println!("\n[X] FAIL: Participant B's DiscoveryFsm is EMPTY!");
        println!("   -> B did not discover A");
        std::process::exit(1);
    }

    // Verify B discovered A (not itself)
    let found_a_in_b = discovered_by_b.iter().any(|p| p.guid == guid_a);
    let found_self_in_b = discovered_by_b.iter().any(|p| p.guid == guid_b);

    if found_self_in_b {
        println!("\n[X] FAIL: Participant B discovered ITSELF!");
        println!("   -> Self-discovery filtering is broken");
        std::process::exit(1);
    }

    if !found_a_in_b {
        println!("\n[X] FAIL: Participant B did not discover Participant A!");
        println!("   -> Discovered GUIDs:");
        for p in &discovered_by_b {
            println!("     - {:?}", p.guid);
        }
        println!("   -> Expected to find: {:?}", guid_a);
        std::process::exit(1);
    }

    println!("   [OK] Participant B discovered Participant A correctly");
    println!("      GUID: {:?}", guid_a);
    println!("      Lease: {}ms\n", discovered_by_b[0].lease_duration_ms);

    println!("=======================================================");
    println!("  [OK] SUCCESS: HDDS SPDP Discovery is FULLY FUNCTIONAL!");
    println!("=======================================================");
    println!();
    println!("[OK] Participant A announced itself via SPDP");
    println!("[OK] Participant B received and parsed A's announcement");
    println!("[OK] Participant B announced itself via SPDP");
    println!("[OK] Participant A received and parsed B's announcement");
    println!("[OK] Self-discovery filtering working correctly");
    println!("[OK] DiscoveryFsm state management working correctly");
    println!();
    println!("This is NOT 'static code' - discovery actually works!");
    println!();

    // Keep participants alive for a bit to observe final announcements
    println!("Keeping participants alive for 3 more seconds...");
    thread::sleep(Duration::from_secs(3));

    println!("Shutting down participants...");
    drop(participant_a);
    drop(participant_b);
    println!("[OK] Test complete.\n");
}
