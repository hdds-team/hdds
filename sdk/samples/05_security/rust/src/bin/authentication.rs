// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! # HDDS Sample: Authentication
//!
//! Demonstrates **PKI-based authentication** - X.509 certificate-based identity
//! verification for DDS participants.
//!
//! ## Authentication Flow
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────────────┐
//! │                    Certificate Authority (CA)                        │
//! │                    ┌─────────────────────┐                           │
//! │                    │  ca_cert.pem        │                           │
//! │                    │  (trusted root)     │                           │
//! │                    └──────────┬──────────┘                           │
//! │                               │ signs                                │
//! │              ┌────────────────┼────────────────┐                     │
//! │              ▼                                 ▼                     │
//! │   ┌─────────────────────┐          ┌─────────────────────┐          │
//! │   │ participant1_cert   │          │ participant2_cert   │          │
//! │   │ participant1_key    │          │ participant2_key    │          │
//! │   └──────────┬──────────┘          └──────────┬──────────┘          │
//! │              │                                 │                     │
//! │              ▼                                 ▼                     │
//! │   ┌─────────────────────┐          ┌─────────────────────┐          │
//! │   │  Participant 1      │◄────────►│  Participant 2      │          │
//! │   │  (authenticated)    │  mutual  │  (authenticated)    │          │
//! │   └─────────────────────┘   auth   └─────────────────────┘          │
//! └──────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Certificate Components
//!
//! | File                 | Purpose                        |
//! |----------------------|--------------------------------|
//! | ca_cert.pem          | Certificate Authority root     |
//! | participant_cert.pem | Participant's identity cert    |
//! | participant_key.pem  | Participant's private key      |
//!
//! ## X.509 Subject Name
//!
//! ```text
//! CN=Participant1,O=HDDS,C=US
//! │              │         │
//! │              │         └── Country
//! │              └── Organization
//! └── Common Name (identity)
//! ```
//!
//! ## Use Cases
//!
//! - **Identity verification**: Ensure only authorized nodes join
//! - **Mutual authentication**: Both parties verify each other
//! - **Audit trail**: Track which certificate accessed what
//!
//! ## Running the Sample
//!
//! ```bash
//! # Terminal 1 - First participant (publisher)
//! cargo run --bin authentication
//!
//! # Terminal 2 - Second participant (subscriber)
//! cargo run --bin authentication -- Participant2
//! ```
//!
//! **NOTE: CONCEPT DEMO** - This sample demonstrates the APPLICATION PATTERN for DDS Security Authentication.
//! The native DDS Security Authentication API is not yet exported to the SDK.
//! This sample uses standard participant/writer/reader API to show the concept.

use std::env;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

// Include generated types
#[allow(dead_code)]
mod generated {
    include!("../../generated/security_types.rs");
}

use generated::SecureMessage;

/// Authentication configuration (for documentation purposes)
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct AuthenticationConfig {
    identity_ca: PathBuf,     // CA certificate path
    identity_cert: PathBuf,   // Participant certificate path
    private_key: PathBuf,     // Private key path
    password: Option<String>, // Private key password
}

/// Authentication status
#[derive(Debug)]
struct AuthStatus {
    authenticated: bool,
    peer_identity: String,
    status_message: String,
}

fn get_certs_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../certs")
}

fn print_cert_info(label: &str, path: &Path) {
    let status = if path.exists() { "[OK]" } else { "[NOT FOUND]" };
    println!("  {}: {} {}", label, path.display(), status);
}

fn print_security_concepts() {
    println!("--- DDS Security Authentication ---");
    println!("Authentication uses X.509 PKI:");
    println!("1. Each participant has an identity certificate");
    println!("2. Certificates are signed by a trusted CA");
    println!("3. Participants validate each other's certificates");
    println!("4. Only authenticated participants can communicate");
    println!();
}

fn run_publisher(participant: &Arc<hdds::Participant>, name: &str) -> Result<(), hdds::Error> {
    println!("Creating authenticated writer...");
    let writer = participant.create_raw_writer("SecureAuthTopic", None)?;

    println!("[OK] Secure DataWriter created");
    println!();
    println!("--- Sending Authenticated Messages ---");
    println!("Run another instance with different identity:");
    println!("  cargo run --bin authentication -- Participant2");
    println!();

    for i in 1..=5 {
        let msg = SecureMessage::new(name, format!("Authenticated message #{}", i), i);
        let data = msg.serialize();

        writer.write_raw(&data)?;
        println!("[SEND] {} (seq={})", msg.payload, msg.sequence);
        println!("       From authenticated sender: {}", msg.sender_id);

        thread::sleep(Duration::from_secs(2));
    }

    println!();
    println!("Done sending authenticated messages.");
    Ok(())
}

fn run_subscriber(participant: &Arc<hdds::Participant>, name: &str) -> Result<(), hdds::Error> {
    println!("Creating authenticated reader...");
    let reader = participant.create_raw_reader("SecureAuthTopic", None)?;

    println!("[OK] Secure DataReader created");
    println!();
    println!("--- Waiting for Authenticated Messages ---");
    println!("Receiver identity: {}", name);
    println!();

    let mut received = 0;
    let mut attempts = 0;
    while received < 5 && attempts < 30 {
        let samples = reader.try_take_raw()?;
        if samples.is_empty() {
            println!("  (waiting for authenticated peers...)");
            thread::sleep(Duration::from_secs(1));
            attempts += 1;
        } else {
            for sample in samples {
                match SecureMessage::deserialize(&sample.payload) {
                    Ok((msg, _)) => {
                        println!("[RECV] {} (seq={})", msg.payload, msg.sequence);
                        println!("       Verified sender: {}", msg.sender_id);
                        received += 1;
                    }
                    Err(e) => {
                        eprintln!("  Deserialize error: {}", e);
                    }
                }
            }
        }
    }

    println!();
    println!("Done receiving authenticated messages.");
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== HDDS Authentication Sample ===");
    println!();
    println!("NOTE: CONCEPT DEMO - Native DDS Security Authentication API not yet in SDK.");
    println!("      Using standard pub/sub API to demonstrate the pattern.\n");

    let args: Vec<String> = env::args().collect();
    let participant_name = args.get(1).map(|s| s.as_str()).unwrap_or("Participant1");
    let is_publisher = args
        .get(2)
        .map(|s| s == "pub")
        .unwrap_or(participant_name == "Participant1");

    let certs_dir = get_certs_dir();

    // Configure authentication (conceptual - would be used with DDS Security)
    let auth_config = AuthenticationConfig {
        identity_ca: certs_dir.join("ca_cert.pem"),
        identity_cert: certs_dir.join(format!("{}_cert.pem", participant_name)),
        private_key: certs_dir.join(format!("{}_key.pem", participant_name)),
        password: None,
    };

    println!("Security Configuration:");
    print_cert_info("CA Certificate", &auth_config.identity_ca);
    print_cert_info("Identity Cert ", &auth_config.identity_cert);
    print_cert_info("Private Key   ", &auth_config.private_key);
    println!();

    print_security_concepts();

    // Create participant
    println!(
        "Creating secure DomainParticipant '{}'...",
        participant_name
    );
    let participant = hdds::Participant::builder(participant_name)
        .domain_id(0)
        .build()?;
    println!("[OK] Participant created");

    // Simulated authentication status
    let status = AuthStatus {
        authenticated: true,
        peer_identity: format!("CN={},O=HDDS,C=US", participant_name),
        status_message: "AUTHENTICATED".to_string(),
    };

    println!();
    println!("Authentication Status:");
    println!(
        "  Authenticated: {}",
        if status.authenticated { "YES" } else { "NO" }
    );
    println!("  Local Identity: {}", status.peer_identity);
    println!("  Status: {}", status.status_message);
    println!();

    if is_publisher {
        run_publisher(&participant, participant_name)?;
    } else {
        run_subscriber(&participant, participant_name)?;
    }

    // Show authentication summary
    println!();
    println!("--- Authentication Summary ---");
    println!("This participant: {}", participant_name);
    println!(
        "Authentication: {}",
        if status.authenticated {
            "SUCCESS"
        } else {
            "FAILED"
        }
    );
    println!();
    println!("Note: In a production system with DDS Security enabled,");
    println!("      unauthenticated participants would be rejected.");
    println!("      Only peers with valid certificates could join.");

    println!();
    println!("=== Sample Complete ===");
    Ok(())
}
