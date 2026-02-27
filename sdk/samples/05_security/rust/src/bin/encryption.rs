// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! # HDDS Sample: Encryption
//!
//! Demonstrates **data encryption** using AES-GCM - cryptographic protection
//! for confidentiality and integrity of DDS messages.
//!
//! ## Encryption Layers
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │                        DDS Security Encryption                      │
//! │                                                                     │
//! │   Layer 1: RTPS Protection          Layer 2: Data Protection       │
//! │   ┌───────────────────────┐        ┌───────────────────────┐       │
//! │   │ Protects entire RTPS  │        │ Protects user payload │       │
//! │   │ messages including    │        │ only (serialized      │       │
//! │   │ headers               │        │ data)                 │       │
//! │   └───────────────────────┘        └───────────────────────┘       │
//! │                                                                     │
//! │   ┌───────────────────────────────────────────────────────────┐    │
//! │   │ Original: "credit_card: 4111-1111-1111-1111"              │    │
//! │   │                        ↓ AES-GCM                          │    │
//! │   │ Encrypted: [a7 f3 9b 2c ... + 16-byte auth tag]          │    │
//! │   └───────────────────────────────────────────────────────────┘    │
//! └─────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Protection Levels
//!
//! | Level          | Confidentiality | Integrity | Overhead  |
//! |----------------|-----------------|-----------|-----------|
//! | NONE           | No              | No        | 0 bytes   |
//! | SIGN (GMAC)    | No              | Yes       | 16 bytes  |
//! | ENCRYPT (GCM)  | Yes             | Yes       | 16 bytes  |
//!
//! ## Cryptographic Algorithms
//!
//! ```text
//! AES-128-GCM: Fast, hardware-accelerated (AES-NI)
//!              128-bit key, 128-bit auth tag
//!
//! AES-256-GCM: Stronger security, slightly slower
//!              256-bit key, 128-bit auth tag
//!
//! GMAC:        Authentication only (no encryption)
//!              Verifies message wasn't tampered
//! ```
//!
//! ## Use Cases
//!
//! - **Sensitive data**: Credit cards, passwords, PII
//! - **Regulatory compliance**: HIPAA, PCI-DSS, GDPR
//! - **Untrusted networks**: Data protected in transit
//!
//! ## Running the Sample
//!
//! ```bash
//! # Terminal 1 - Publisher (encrypts data)
//! cargo run --bin encryption
//!
//! # Terminal 2 - Subscriber (decrypts data)
//! cargo run --bin encryption -- sub
//! ```
//!
//! **NOTE: CONCEPT DEMO** - This sample demonstrates the APPLICATION PATTERN for DDS Security Encryption.
//! The native DDS Security Encryption API is not yet exported to the SDK.
//! This sample uses standard participant/writer/reader API to show the concept.

use std::env;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

// Include generated types
#[allow(dead_code)]
mod generated {
    include!("../../generated/security_types.rs");
}

use generated::SecureMessage;

/// Protection kind for cryptographic operations
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
enum ProtectionKind {
    None,
    Sign,        // GMAC - integrity only
    Encrypt,     // AES-GCM - confidentiality + integrity
    SignEncrypt, // Sign then encrypt
}

impl std::fmt::Display for ProtectionKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProtectionKind::None => write!(f, "NONE"),
            ProtectionKind::Sign => write!(f, "SIGN (GMAC)"),
            ProtectionKind::Encrypt => write!(f, "ENCRYPT (AES-GCM)"),
            ProtectionKind::SignEncrypt => write!(f, "SIGN+ENCRYPT"),
        }
    }
}

/// Cryptographic configuration
#[derive(Debug, Clone)]
struct CryptoConfig {
    rtps_protection: ProtectionKind,
    metadata_protection: ProtectionKind,
    data_protection: ProtectionKind,
}

/// Encryption statistics (simulated)
#[derive(Debug, Default)]
struct CryptoStats {
    bytes_encrypted: u64,
    bytes_decrypted: u64,
    messages_sent: u64,
    messages_received: u64,
    auth_failures: u64,
}

fn print_crypto_info() {
    println!("--- DDS Security Cryptography ---");
    println!();
    println!("Encryption Algorithms:");
    println!("  - AES-128-GCM: Fast, hardware-accelerated encryption");
    println!("  - AES-256-GCM: Stronger encryption for sensitive data");
    println!("  - GMAC: Message authentication without encryption");
    println!();
    println!("Protection Levels:");
    println!("  - RTPS Protection: Protects entire RTPS messages");
    println!("  - Metadata Protection: Protects discovery information");
    println!("  - Data Protection: Protects user data payload");
    println!();
    println!("Key Exchange:");
    println!("  - DH + AES Key Wrap for shared secrets");
    println!("  - Per-endpoint session keys");
    println!("  - Key rotation supported");
    println!();
}

fn print_protection_comparison() {
    println!("--- Protection Level Comparison ---");
    println!();
    println!("| Level          | Confidentiality | Integrity | Overhead |");
    println!("|----------------|-----------------|-----------|----------|");
    println!("| NONE           | No              | No        | 0 bytes  |");
    println!("| SIGN (GMAC)    | No              | Yes       | 16 bytes |");
    println!("| ENCRYPT (GCM)  | Yes             | Yes       | 16 bytes |");
    println!("| SIGN+ENCRYPT   | Yes             | Yes       | 32 bytes |");
    println!();
    println!("Recommendations:");
    println!("  - Use ENCRYPT for sensitive user data");
    println!("  - Use SIGN for discovery metadata (performance)");
    println!("  - Use NONE only for non-sensitive data in trusted networks");
    println!();
}

#[allow(clippy::useless_vec)]
fn run_publisher(participant: &Arc<hdds::Participant>) -> Result<CryptoStats, hdds::Error> {
    println!("Creating encrypted endpoints...");
    let writer = participant.create_raw_writer("EncryptedData", None)?;
    println!("[OK] DataWriter created (data will be encrypted)");
    println!();

    println!("--- Encrypted Communication Demo ---");
    println!();

    // Sensitive test messages
    let test_messages = vec![
        ("credit_card", "4111-XXXX-XXXX-1111"),
        ("api_key", "sk_test_EXAMPLE_DO_NOT_USE"),
        ("password", "EXAMPLE_DO_NOT_USE"),
        ("ssn", "000-00-0000"),
        ("private_data", "example confidential payload"),
    ];

    println!("Sending encrypted messages:");
    println!();

    let mut stats = CryptoStats::default();

    for (i, (data_type, value)) in test_messages.iter().enumerate() {
        let payload = format!("{}: {}", data_type, value);
        let msg = SecureMessage::new("EncryptedNode", &payload, (i + 1) as u32);
        let data = msg.serialize();

        println!("Original:    \"{}\"", payload);
        println!(
            "Wire format: [AES-GCM encrypted, {} bytes + 16 byte auth tag]",
            data.len()
        );

        writer.write_raw(&data)?;
        stats.bytes_encrypted += data.len() as u64;
        stats.messages_sent += 1;

        println!("[SENT] Message {} encrypted and sent", i + 1);
        println!();

        thread::sleep(Duration::from_millis(500));
    }

    Ok(stats)
}

fn run_subscriber(participant: &Arc<hdds::Participant>) -> Result<CryptoStats, hdds::Error> {
    println!("Creating encrypted endpoints...");
    let reader = participant.create_raw_reader("EncryptedData", None)?;
    println!("[OK] DataReader created (data will be decrypted)");

    println!();
    println!("--- Receiving Encrypted Messages ---");
    println!("(Decryption happens automatically)");
    println!();

    let mut stats = CryptoStats::default();
    let mut received = 0;
    let mut attempts = 0;

    while received < 5 && attempts < 30 {
        let samples = reader.try_take_raw()?;
        if samples.is_empty() {
            println!("  (waiting for encrypted messages...)");
            thread::sleep(Duration::from_secs(1));
            attempts += 1;
        } else {
            for sample in samples {
                match SecureMessage::deserialize(&sample.payload) {
                    Ok((msg, _)) => {
                        println!(
                            "[RECV] Decrypted message {} from {}",
                            msg.sequence, msg.sender_id
                        );
                        println!("       Payload: \"{}\"", msg.payload);
                        println!("       (Data was encrypted in transit)");
                        println!();
                        stats.bytes_decrypted += sample.payload.len() as u64;
                        stats.messages_received += 1;
                        received += 1;
                    }
                    Err(e) => {
                        eprintln!("  Deserialize error: {}", e);
                        stats.auth_failures += 1;
                    }
                }
            }
        }
    }

    Ok(stats)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== HDDS Encryption Sample ===");
    println!();
    println!("NOTE: CONCEPT DEMO - Native DDS Security Encryption API not yet in SDK.");
    println!("      Using standard pub/sub API to demonstrate the pattern.\n");

    let args: Vec<String> = env::args().collect();
    let is_subscriber = args.get(1).map(|s| s == "sub").unwrap_or(false);

    print_crypto_info();

    // Configure encryption
    let crypto_config = CryptoConfig {
        rtps_protection: ProtectionKind::Encrypt,
        metadata_protection: ProtectionKind::Sign,
        data_protection: ProtectionKind::Encrypt,
    };

    println!("Crypto Configuration:");
    println!("  RTPS Protection:     {}", crypto_config.rtps_protection);
    println!(
        "  Metadata Protection: {}",
        crypto_config.metadata_protection
    );
    println!("  Data Protection:     {}", crypto_config.data_protection);
    println!();

    // Create participant
    let participant_name = if is_subscriber {
        "DecryptNode"
    } else {
        "EncryptNode"
    };
    println!("Creating DomainParticipant with encryption...");
    let participant = hdds::Participant::builder(participant_name)
        .domain_id(0)
        .build()?;
    println!("[OK] Encrypted participant created: {}", participant_name);
    println!();

    let stats = if is_subscriber {
        run_subscriber(&participant)?
    } else {
        run_publisher(&participant)?
    };

    // Show encryption statistics
    println!("--- Encryption Statistics ---");
    println!();
    println!("Bytes encrypted:     {}", stats.bytes_encrypted);
    println!("Bytes decrypted:     {}", stats.bytes_decrypted);
    println!("Messages sent:       {}", stats.messages_sent);
    println!("Messages received:   {}", stats.messages_received);
    println!("Auth failures:       {}", stats.auth_failures);
    println!();

    print_protection_comparison();

    println!("=== Sample Complete ===");
    Ok(())
}
