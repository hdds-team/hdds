// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! # HDDS Sample: Access Control
//!
//! Demonstrates **DDS Security permissions** - fine-grained topic and domain
//! access rules enforced at the middleware level.
//!
//! ## Access Control Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │                     Access Control Documents                        │
//! │                                                                     │
//! │   governance.xml                    permissions.xml                 │
//! │   ┌───────────────────────┐        ┌───────────────────────┐       │
//! │   │ Domain-wide policies  │        │ Per-participant rules │       │
//! │   │ • Enable encryption   │        │ • Subject: CN=Node1   │       │
//! │   │ • Enable auth         │        │ • Allow: SensorData   │       │
//! │   │ • Topic rules         │        │ • Deny: RestrictedTopic│       │
//! │   └───────────────────────┘        └───────────────────────┘       │
//! │                                                                     │
//! │   Both signed by Permissions CA for tamper protection              │
//! └─────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Permission Rules
//!
//! ```text
//! Participant "SensorNode" permissions:
//!
//! ┌────────────────────┬─────────┬───────────┐
//! │ Topic              │ Publish │ Subscribe │
//! ├────────────────────┼─────────┼───────────┤
//! │ SensorData         │ ALLOW   │ ALLOW     │
//! │ CommandTopic       │ ALLOW   │ ALLOW     │
//! │ RestrictedTopic    │ DENY    │ ALLOW     │  ← Can read, can't write
//! │ LogData            │ ALLOW   │ ALLOW     │
//! └────────────────────┴─────────┴───────────┘
//! ```
//!
//! ## Enforcement Points
//!
//! ```text
//! 1. create_writer() → check publish permission  → DENIED if no access
//! 2. create_reader() → check subscribe permission → DENIED if no access
//! 3. SEDP matching   → verify remote permissions  → no match if incompatible
//! ```
//!
//! ## Use Cases
//!
//! - **Role-based access**: Sensors publish, operators subscribe
//! - **Data isolation**: Prevent unauthorized topic access
//! - **Audit**: Track permission usage
//!
//! ## Running the Sample
//!
//! ```bash
//! # Terminal 1 - Publisher (demonstrates allowed/denied topics)
//! cargo run --bin access_control
//!
//! # Terminal 2 - Subscriber
//! cargo run --bin access_control -- sub
//! ```
//!
//! **NOTE: CONCEPT DEMO** - This sample demonstrates the APPLICATION PATTERN for DDS Security Access Control.
//! The native DDS Security Access Control API is not yet exported to the SDK.
//! This sample uses standard participant/writer/reader API to show the concept.

use std::env;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

// Include generated types
#[allow(dead_code)]
mod generated {
    include!("../../generated/security_types.rs");
}

use generated::SensorData;

/// Access control configuration (for documentation purposes)
#[derive(Debug, Clone)]
struct AccessControlConfig {
    governance_file: PathBuf,
    permissions_file: PathBuf,
    permissions_ca: PathBuf,
}

/// Topic permission rule
#[derive(Debug, Clone)]
struct TopicPermission {
    topic_pattern: String,
    can_publish: bool,
    can_subscribe: bool,
}

/// Access control policy (simulated)
#[derive(Debug)]
#[allow(dead_code)]
struct AccessControlPolicy {
    subject_name: String,
    allowed_domains: Vec<u32>,
    topic_rules: Vec<TopicPermission>,
}

impl AccessControlPolicy {
    fn new(subject: &str) -> Self {
        Self {
            subject_name: subject.to_string(),
            allowed_domains: vec![0],
            topic_rules: vec![
                TopicPermission {
                    topic_pattern: "SensorData".to_string(),
                    can_publish: true,
                    can_subscribe: true,
                },
                TopicPermission {
                    topic_pattern: "CommandTopic".to_string(),
                    can_publish: true,
                    can_subscribe: true,
                },
                TopicPermission {
                    topic_pattern: "RestrictedTopic".to_string(),
                    can_publish: false, // Publishing denied!
                    can_subscribe: true,
                },
                TopicPermission {
                    topic_pattern: "LogData".to_string(),
                    can_publish: true,
                    can_subscribe: true,
                },
            ],
        }
    }

    fn check_permission(&self, topic: &str, publish: bool) -> bool {
        for rule in &self.topic_rules {
            if rule.topic_pattern == topic {
                return if publish {
                    rule.can_publish
                } else {
                    rule.can_subscribe
                };
            }
        }
        // Default: allow if no specific rule
        true
    }
}

fn print_sample_governance() {
    println!("Sample Governance Document:");
    println!("  <domain_access_rules>");
    println!("    <domain_rule>");
    println!("      <domains><id>0</id></domains>");
    println!(
        "      <allow_unauthenticated_participants>false</allow_unauthenticated_participants>"
    );
    println!("      <enable_discovery_protection>true</enable_discovery_protection>");
    println!("      <topic_access_rules>");
    println!("        <topic_rule>");
    println!("          <topic_expression>*</topic_expression>");
    println!("          <enable_data_protection>true</enable_data_protection>");
    println!("        </topic_rule>");
    println!("      </topic_access_rules>");
    println!("    </domain_rule>");
    println!("  </domain_access_rules>");
    println!();
}

fn print_sample_permissions(subject: &str) {
    println!("Sample Permissions Document for {}:", subject);
    println!("  <permissions>");
    println!("    <grant name=\"ParticipantGrant\">");
    println!("      <subject_name>{}</subject_name>", subject);
    println!("      <validity><not_before>2024-01-01</not_before></validity>");
    println!("      <allow_rule>");
    println!("        <domains><id>0</id></domains>");
    println!("        <publish><topics><topic>SensorData</topic></topics></publish>");
    println!("        <subscribe><topics><topic>*</topic></topics></subscribe>");
    println!("      </allow_rule>");
    println!("      <deny_rule>");
    println!("        <domains><id>0</id></domains>");
    println!("        <publish><topics><topic>RestrictedTopic</topic></topics></publish>");
    println!("      </deny_rule>");
    println!("    </grant>");
    println!("  </permissions>");
    println!();
}

fn run_publisher(
    participant: &Arc<hdds::Participant>,
    policy: &AccessControlPolicy,
) -> Result<(), hdds::Error> {
    println!("--- Creating Endpoints with Access Control ---");
    println!();

    // Test topic permissions
    let test_topics = vec![
        ("SensorData", true),
        ("CommandTopic", true),
        ("RestrictedTopic", true),
        ("LogData", true),
    ];

    for (topic, attempt_publish) in &test_topics {
        let can_pub = policy.check_permission(topic, true);
        let can_sub = policy.check_permission(topic, false);

        println!("Topic '{}':", topic);
        println!(
            "  Publish:   {}",
            if can_pub { "ALLOWED" } else { "DENIED" }
        );
        println!(
            "  Subscribe: {}",
            if can_sub { "ALLOWED" } else { "DENIED" }
        );

        if *attempt_publish && !can_pub {
            println!("  [SKIP] Cannot create writer - no publish permission");
        }
        println!();
    }

    // Create writer for allowed topic
    println!("Creating writer for 'SensorData'...");
    if policy.check_permission("SensorData", true) {
        let writer = participant.create_raw_writer("SensorData", None)?;
        println!("[OK] DataWriter created");
        println!();

        // Send sensor data
        println!("--- Sending Sensor Data ---");
        println!();

        for i in 1..=5 {
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            let msg = SensorData::new(
                format!("sensor_{:02}", i % 3 + 1),
                20.0 + (i as f64) * 0.5,
                timestamp,
            );
            let data = msg.serialize();

            writer.write_raw(&data)?;
            println!(
                "[SEND] sensor_id={}, value={:.1}, ts={}",
                msg.sensor_id, msg.value, msg.timestamp
            );

            thread::sleep(Duration::from_secs(1));
        }
    } else {
        println!("[DENIED] No publish permission");
    }

    // Attempt to create writer for restricted topic
    println!();
    println!("Attempting to create writer for 'RestrictedTopic'...");
    if policy.check_permission("RestrictedTopic", true) {
        println!("[OK] DataWriter created");
    } else {
        println!("[DENIED] No publish permission for this topic");
        println!("         Access control prevents unauthorized writes.");
    }

    Ok(())
}

fn run_subscriber(
    participant: &Arc<hdds::Participant>,
    policy: &AccessControlPolicy,
) -> Result<(), hdds::Error> {
    println!("--- Creating Reader with Access Control ---");
    println!();

    // Check subscribe permission
    if !policy.check_permission("SensorData", false) {
        println!("[DENIED] No subscribe permission for SensorData");
        return Ok(());
    }

    println!("Creating reader for 'SensorData'...");
    let reader = participant.create_raw_reader("SensorData", None)?;
    println!("[OK] DataReader created");

    println!();
    println!("--- Receiving Sensor Data ---");
    println!("(Access control verified for subscribe)");
    println!();

    let mut received = 0;
    let mut attempts = 0;
    while received < 5 && attempts < 30 {
        let samples = reader.try_take_raw()?;
        if samples.is_empty() {
            println!("  (waiting for data...)");
            thread::sleep(Duration::from_secs(1));
            attempts += 1;
        } else {
            for sample in samples {
                match SensorData::deserialize(&sample.payload) {
                    Ok((msg, _)) => {
                        println!(
                            "[RECV] sensor_id={}, value={:.1}, ts={}",
                            msg.sensor_id, msg.value, msg.timestamp
                        );
                        received += 1;
                    }
                    Err(e) => {
                        eprintln!("  Deserialize error: {}", e);
                    }
                }
            }
        }
    }

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== HDDS Access Control Sample ===");
    println!();
    println!("NOTE: CONCEPT DEMO - Native DDS Security Access Control API not yet in SDK.");
    println!("      Using standard pub/sub API to demonstrate the pattern.\n");

    let args: Vec<String> = env::args().collect();
    let participant_name = args.get(1).map(|s| s.as_str()).unwrap_or("SensorNode");
    let is_subscriber = participant_name == "sub";
    let subject_name = "CN=SensorNode,O=HDDS,C=US";

    println!("--- DDS Security Access Control ---");
    println!("Access control uses two XML documents:");
    println!("1. Governance: Domain-wide security policies");
    println!("2. Permissions: Per-participant access rights");
    println!();

    // Show example documents
    print_sample_governance();
    print_sample_permissions(subject_name);

    // Configure access control (for documentation)
    let ac_config = AccessControlConfig {
        governance_file: PathBuf::from("../certs/governance.xml"),
        permissions_file: PathBuf::from("../certs/permissions.xml"),
        permissions_ca: PathBuf::from("../certs/permissions_ca.pem"),
    };

    println!("Access Control Configuration:");
    println!("  Governance:     {}", ac_config.governance_file.display());
    println!("  Permissions:    {}", ac_config.permissions_file.display());
    println!("  Permissions CA: {}", ac_config.permissions_ca.display());
    println!();

    // Create participant
    let actual_name = if is_subscriber {
        "SensorSubscriber"
    } else {
        participant_name
    };
    println!("Creating DomainParticipant with access control...");
    let participant = hdds::Participant::builder(actual_name)
        .domain_id(0)
        .build()?;

    // Create access control policy (simulated)
    let policy = AccessControlPolicy::new(subject_name);

    println!("[OK] Participant created: {}", actual_name);
    println!("     Subject: {}", subject_name);
    println!();

    if is_subscriber {
        run_subscriber(&participant, &policy)?;
    } else {
        run_publisher(&participant, &policy)?;
    }

    // Summary
    println!();
    println!("--- Access Control Summary ---");
    println!("Participant: {}", actual_name);
    println!("Subject DN: {}", subject_name);
    println!();
    println!("Permissions:");
    println!("  - Can publish to: SensorData, CommandTopic, LogData");
    println!("  - Cannot publish to: RestrictedTopic");
    println!("  - Can subscribe to: all topics");
    println!();
    println!("Note: In a production system with DDS Security enabled,");
    println!("      permissions are enforced at endpoint creation time.");
    println!("      Attempts to access denied topics will fail.");

    println!();
    println!("=== Sample Complete ===");
    Ok(())
}
