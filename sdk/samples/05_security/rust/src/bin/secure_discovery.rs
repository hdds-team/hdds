// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! # HDDS Sample: Secure Discovery
//!
//! Demonstrates **authenticated discovery** - protecting the SPDP/SEDP protocols
//! to prevent rogue participants from joining the domain.
//!
//! ## Standard vs Secure Discovery
//!
//! ```text
//! Standard Discovery:              Secure Discovery:
//! +---------------------------+   +---------------------------+
//! | SPDP: Plaintext multicast |   | SPDP: Signed + encrypted  |
//! |                           |   |                           |
//! | [WARN] Any node can join      |   | [ok] Only authenticated join |
//! | [WARN] Metadata visible       |   | [ok] Metadata protected      |
//! | [WARN] No identity check      |   | [ok] Certificate verified    |
//! +---------------------------+   +---------------------------+
//! ```
//!
//! ## Secure Discovery Flow
//!
//! ```text
//! Participant A                              Participant B
//! -------------                              -------------
//!      |                                           |
//!      |---- Signed SPDP Announcement ------------>|
//!      |     (includes certificate)                |
//!      |                                           |
//!      |<--- Verify signature ---------------------|
//!      |     Check CA trust chain                  |
//!      |                                           |
//!      |<--- Signed SPDP Announcement ------------|
//!      |     (includes certificate)                |
//!      |                                           |
//!      |---- Verify signature -------------------->|
//!      |                                           |
//!      |<----- Mutual Authentication ------------->|
//!      |       (handshake complete)                |
//!      |                                           |
//!      |<----- Encrypted SEDP -------------------->|
//!      |       (endpoint info)                     |
//! ```
//!
//! ## Governance Settings
//!
//! ```xml
//! <domain_rule>
//!   <domains><id>0</id></domains>
//!   <allow_unauthenticated_participants>false</allow_unauthenticated_participants>
//!   <enable_join_access_control>true</enable_join_access_control>
//!   <discovery_protection_kind>ENCRYPT</discovery_protection_kind>
//!   <data_protection_kind>ENCRYPT</data_protection_kind>
//! </domain_rule>
//! ```
//!
//! Every one of those five elements is required: this release picks no
//! security setting on the operator's behalf, so a rule that omits one is
//! refused at load, naming it. The earlier version of this example listed
//! three elements, two of which are not among them, and asked for
//! `<enable_liveliness_protection>`. Liveliness protection is part of
//! DDS-Security and is not enforced by this release, so a document that asks
//! for it is now refused rather than silently ignored - which is why it is
//! gone from here rather than left in as decoration.
//!
//! ## Use Cases
//!
//! - **Secure networks**: Prevent unauthorized nodes
//! - **Zero-trust**: Verify all participants
//! - **Compliance**: Audit-ready discovery
//!
//! ## Running the Sample
//!
//! ```bash
//! # Terminal 1 - First secure node (announcer)
//! cargo run --bin secure_discovery
//!
//! # Terminal 2 - Second secure node (discoverer)
//! cargo run --bin secure_discovery -- SecureNode2
//! ```
//!
//! **NOTE: CONCEPT DEMO** - This sample demonstrates the APPLICATION PATTERN for DDS Security Secure Discovery.
//! The native DDS Security Secure Discovery API is not yet exported to the SDK.
//! This sample uses standard participant/writer/reader API to show the concept.

use std::env;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// Include generated types
#[allow(dead_code)]
mod generated {
    include!("../../generated/security_types.rs");
}

use generated::DiscoveryAnnouncement;

/// Secure discovery configuration (for documentation purposes)
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct SecureDiscoveryConfig {
    enable_discovery_protection: bool,
    // There is deliberately no `enable_liveliness_protection` here. The
    // governance element of that name is not enforced by this release, so a
    // document asking for it is refused; a field advertising it would promise
    // a setting the operator cannot actually write.
    allow_unauthenticated: bool,
    identity_ca: PathBuf,
    identity_cert: PathBuf,
    private_key: PathBuf,
}

/// Discovered participant info (simulated)
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct DiscoveredParticipant {
    guid: String,
    name: String,
    subject_name: String,
    authenticated: bool,
    discovered_at: u64,
}

fn get_certs_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../certs")
}

fn print_discovery_security_info() {
    println!("--- Secure Discovery Overview ---");
    println!();
    println!("Standard SPDP sends participant info in plaintext.");
    println!("Secure SPDP adds:");
    println!("  1. Authentication of participant announcements");
    println!("  2. Encryption of discovery metadata");
    println!("  3. Rejection of unauthenticated participants");
    println!();
    println!("Governance Settings:");
    println!("  <domain_rule>");
    println!("    <domains><id>0</id></domains>");
    println!("    <allow_unauthenticated_participants>false</allow_unauthenticated_participants>");
    println!("    <enable_join_access_control>true</enable_join_access_control>");
    println!("    <discovery_protection_kind>ENCRYPT</discovery_protection_kind>");
    println!("    <data_protection_kind>ENCRYPT</data_protection_kind>");
    println!("  </domain_rule>");
    println!();
    println!("  Note: <enable_liveliness_protection> is part of DDS-Security and");
    println!("  is NOT enforced by this release, so a governance document that asks");
    println!("  for it is refused rather than silently ignored. All five elements");
    println!("  above are required - none of them has a default.");
    println!();
}

fn print_discovery_process() {
    println!("--- Secure Discovery Process ---");
    println!();
    println!("1. Send authenticated SPDP announcement");
    println!("2. Receive and verify peer announcements");
    println!("3. Perform mutual authentication handshake");
    println!("4. Exchange encrypted endpoint info (SEDP)");
    println!("5. Establish secure data channels");
    println!();
}

fn get_mock_guid() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!(
        "01.0f.{:02x}.{:02x}.00.00.00.01",
        (now >> 8) as u8,
        now as u8
    )
}

fn run_announcer(participant: &Arc<hdds::Participant>, name: &str) -> Result<(), hdds::Error> {
    println!("Creating discovery writer...");
    let writer = participant
        .topic::<DiscoveryAnnouncement>("SecureDiscoveryTopic")?
        .writer()
        .build()?;
    println!("[OK] Secure discovery writer created");
    println!();

    println!("--- Broadcasting Discovery Announcements ---");
    println!();

    for i in 1..=5 {
        let announcement = DiscoveryAnnouncement {
            participant_name: name.to_string(),
            domain_id: 0,
            capabilities: "auth,encrypt,access_control".to_string(),
        };

        writer.write(&announcement)?;
        println!("[ANNOUNCE] Participant: {}", announcement.participant_name);
        println!("           Domain: {}", announcement.domain_id);
        println!("           Capabilities: {}", announcement.capabilities);
        println!("           (Announcement #{} - authenticated)", i);
        println!();

        thread::sleep(Duration::from_secs(3));
    }

    Ok(())
}

fn run_discoverer(
    participant: &Arc<hdds::Participant>,
    name: &str,
) -> Result<Vec<DiscoveredParticipant>, hdds::Error> {
    println!("Creating discovery reader...");
    let reader = participant
        .topic::<DiscoveryAnnouncement>("SecureDiscoveryTopic")?
        .reader()
        .build()?;
    println!("[OK] Secure discovery reader created");

    println!();
    println!("--- Discovering Authenticated Peers ---");
    println!("Local participant: {}", name);
    println!("Waiting for secure participants...");
    println!();

    let mut discovered: Vec<DiscoveredParticipant> = Vec::new();

    for _ in 0..30 {
        if let Some(announcement) = reader.take()? {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();

            let peer = DiscoveredParticipant {
                guid: get_mock_guid(),
                name: announcement.participant_name.clone(),
                subject_name: format!("CN={},O=HDDS,C=US", announcement.participant_name),
                authenticated: true,
                discovered_at: now,
            };

            println!("[DISCOVERED] Authenticated Participant");
            println!("  GUID:         {}", peer.guid);
            println!("  Name:         {}", peer.name);
            println!("  Subject:      {}", peer.subject_name);
            println!(
                "  Status:       {}",
                if peer.authenticated {
                    "AUTHENTICATED"
                } else {
                    "PENDING"
                }
            );
            println!("  Capabilities: {}", announcement.capabilities);
            println!();

            discovered.push(peer);
        } else {
            println!("  (scanning for authenticated peers...)");
            thread::sleep(Duration::from_secs(1));
        }
    }

    Ok(discovered)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== HDDS Secure Discovery Sample ===");
    println!();
    println!("NOTE: CONCEPT DEMO - Native DDS Security Secure Discovery API not yet in SDK.");
    println!("      Using standard pub/sub API to demonstrate the pattern.\n");

    let args: Vec<String> = env::args().collect();
    let participant_name = args.get(1).map(|s| s.as_str()).unwrap_or("SecureNode1");
    let is_announcer =
        participant_name == "SecureNode1" || args.get(2).map(|s| s == "pub").unwrap_or(false);

    let certs_dir = get_certs_dir();

    print_discovery_security_info();

    // Configure secure discovery (for documentation)
    let config = SecureDiscoveryConfig {
        enable_discovery_protection: true,
        allow_unauthenticated: false,
        identity_ca: certs_dir.join("ca_cert.pem"),
        identity_cert: certs_dir.join(format!("{}_cert.pem", participant_name)),
        private_key: certs_dir.join(format!("{}_key.pem", participant_name)),
    };

    println!("Secure Discovery Configuration:");
    println!(
        "  Discovery Protection:  {}",
        if config.enable_discovery_protection {
            "ENABLED"
        } else {
            "DISABLED"
        }
    );
    println!(
        "  Allow Unauthenticated: {}",
        if config.allow_unauthenticated {
            "YES"
        } else {
            "NO"
        }
    );
    println!();

    // Create participant with secure discovery
    println!("Creating DomainParticipant with secure discovery...");
    let participant = hdds::Participant::builder(participant_name)
        .domain_id(0)
        .build()?;

    println!("[OK] Participant created: {}", participant_name);
    println!("[OK] Secure discovery enabled");
    println!("[OK] Builtin endpoints protected");
    println!();

    print_discovery_process();

    if is_announcer {
        run_announcer(&participant, participant_name)?;
    } else {
        let discovered = run_discoverer(&participant, participant_name)?;

        // Show discovery summary
        println!("--- Secure Discovery Summary ---");
        println!();
        println!("Total authenticated participants: {}", discovered.len());
        println!();

        for (i, p) in discovered.iter().enumerate() {
            println!("Participant {}:", i + 1);
            println!("  Name: {}", p.name);
            println!("  Subject: {}", p.subject_name);
            println!(
                "  Authenticated: {}",
                if p.authenticated { "YES" } else { "NO" }
            );
            println!();
        }
    }

    println!("Security Benefits:");
    println!("  - Only trusted participants can join");
    println!("  - Discovery metadata is encrypted");
    println!("  - Prevents rogue participant injection");
    println!("  - Protects endpoint information");

    println!();
    println!("=== Sample Complete ===");
    Ok(())
}
