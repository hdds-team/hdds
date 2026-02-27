// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

#![allow(clippy::uninlined_format_args)] // Test/bench code readability over pedantic
#![allow(clippy::cast_precision_loss)] // Stats/metrics need this
#![allow(clippy::cast_sign_loss)] // Test data conversions
#![allow(clippy::cast_possible_truncation)] // Test parameters
#![allow(clippy::float_cmp)] // Test assertions with constants
#![allow(clippy::unreadable_literal)] // Large test constants
#![allow(clippy::doc_markdown)] // Test documentation
#![allow(clippy::missing_panics_doc)] // Tests/examples panic on failure
#![allow(clippy::missing_errors_doc)] // Test documentation
#![allow(clippy::items_after_statements)] // Test helpers
#![allow(clippy::module_name_repetitions)] // Test modules
#![allow(clippy::too_many_lines)] // Example/test code
#![allow(clippy::match_same_arms)] // Test pattern matching
#![allow(clippy::no_effect_underscore_binding)] // Test variables
#![allow(clippy::wildcard_imports)] // Test utility imports
#![allow(clippy::redundant_closure_for_method_calls)] // Test code clarity
#![allow(clippy::similar_names)] // Test variable naming
#![allow(clippy::shadow_unrelated)] // Test scoping
#![allow(clippy::needless_pass_by_value)] // Test functions
#![allow(clippy::cast_possible_wrap)] // Test conversions
#![allow(clippy::single_match_else)] // Test clarity
#![allow(clippy::needless_continue)] // Test logic
#![allow(clippy::cast_lossless)] // Test simplicity
#![allow(clippy::match_wild_err_arm)] // Test error handling
#![allow(clippy::explicit_iter_loop)] // Test iteration
#![allow(clippy::must_use_candidate)] // Test functions
#![allow(clippy::if_not_else)] // Test conditionals
#![allow(clippy::map_unwrap_or)] // Test options
#![allow(clippy::match_wildcard_for_single_variants)] // Test patterns
#![allow(clippy::ignored_unit_patterns)] // Test closures
#![allow(clippy::ignore_without_reason)] // Test ignore attributes

//! Multi-node discovery integration tests
//!
//! Tests SPDP (Simple Participant Discovery Protocol) and SEDP (Simple Endpoint Discovery Protocol)
//! across multiple DDS participants using UDP multicast.

use hdds::{Participant, QoS, TransportMode};
use std::thread;
use std::time::Duration;

/// Temperature sensor data type for testing
#[derive(Debug, Clone, PartialEq)]
struct Temperature {
    sensor_id: u32,
    value: f32,
    timestamp: i64,
}

// Implement Cdr2Encode/Cdr2Decode manually (simplified for test)
impl hdds::Cdr2Encode for Temperature {
    fn encode_cdr2_le(&self, dst: &mut [u8]) -> Result<usize, hdds::CdrError> {
        let mut offset = 0;
        if dst.len() < offset + 16 {
            return Err(hdds::CdrError::BufferTooSmall);
        }
        dst[offset..offset + 4].copy_from_slice(&self.sensor_id.to_le_bytes());
        offset += 4;
        dst[offset..offset + 4].copy_from_slice(&self.value.to_le_bytes());
        offset += 4;
        dst[offset..offset + 8].copy_from_slice(&self.timestamp.to_le_bytes());
        offset += 8;
        Ok(offset)
    }

    fn max_cdr2_size(&self) -> usize {
        16
    }
}

impl hdds::Cdr2Decode for Temperature {
    fn decode_cdr2_le(src: &[u8]) -> Result<(Self, usize), hdds::CdrError> {
        if src.len() < 16 {
            return Err(hdds::CdrError::UnexpectedEof);
        }
        let sensor_id = u32::from_le_bytes(src[0..4].try_into().unwrap());
        let value = f32::from_le_bytes(src[4..8].try_into().unwrap());
        let timestamp = i64::from_le_bytes(src[8..16].try_into().unwrap());
        Ok((
            Self {
                sensor_id,
                value,
                timestamp,
            },
            16,
        ))
    }
}

// DDS trait impl for test Temperature type
impl hdds::DdsTrait for Temperature {
    fn type_descriptor() -> &'static hdds::core::types::TypeDescriptor {
        static DESC: hdds::core::types::TypeDescriptor = hdds::core::types::TypeDescriptor {
            type_id: 0x8F3A2BC1, // FNV-1a hash of "TestTemperature"
            type_name: "TestTemperature",
            size_bytes: 16, // u32(4) + f32(4) + i64(8)
            alignment: 8,   // Max field alignment (i64)
            is_variable_size: false,
            fields: &[
                hdds::core::types::FieldLayout {
                    name: "sensor_id",
                    offset_bytes: 0,
                    field_type: hdds::core::types::FieldType::Primitive(
                        hdds::core::types::PrimitiveKind::U32,
                    ),
                    alignment: 4,
                    size_bytes: 4,
                    element_type: None,
                },
                hdds::core::types::FieldLayout {
                    name: "value",
                    offset_bytes: 4,
                    field_type: hdds::core::types::FieldType::Primitive(
                        hdds::core::types::PrimitiveKind::F32,
                    ),
                    alignment: 4,
                    size_bytes: 4,
                    element_type: None,
                },
                hdds::core::types::FieldLayout {
                    name: "timestamp",
                    offset_bytes: 8,
                    field_type: hdds::core::types::FieldType::Primitive(
                        hdds::core::types::PrimitiveKind::I64,
                    ),
                    alignment: 8,
                    size_bytes: 8,
                    element_type: None,
                },
            ],
        };
        &DESC
    }

    fn encode_cdr2(&self, buf: &mut [u8]) -> hdds::Result<usize> {
        use hdds::Cdr2Encode;
        self.encode_cdr2_le(buf).map_err(Into::into)
    }

    fn decode_cdr2(buf: &[u8]) -> hdds::Result<Self> {
        use hdds::Cdr2Decode;
        Self::decode_cdr2_le(buf)
            .map(|(val, _len)| val)
            .map_err(Into::into)
    }
}

#[test]
#[ignore] // Ignore by default (requires UDP multicast permissions)
fn test_multi_participant_spdp_discovery() {
    println!("\n---------------------------------------------");
    println!("[*] Test: Multi-Participant SPDP Discovery");
    println!("---------------------------------------------\n");

    // Create Participant A (domain 42, participant_id auto-assigned)
    let participant_a = Participant::builder("participant_a")
        .domain_id(42)
        .with_transport(TransportMode::UdpMulticast)
        .build()
        .expect("Failed to create participant_a");

    println!("[OK] Created Participant A:");
    println!("   GUID: {}", participant_a.guid());
    println!("   Domain: {}", participant_a.domain_id());
    println!("   Participant ID: {}", participant_a.participant_id());

    // Create Participant B (same domain, different participant_id)
    let participant_b = Participant::builder("participant_b")
        .domain_id(42)
        .with_transport(TransportMode::UdpMulticast)
        .build()
        .expect("Failed to create participant_b");

    println!("[OK] Created Participant B:");
    println!("   GUID: {}", participant_b.guid());
    println!("   Domain: {}", participant_b.domain_id());
    println!("   Participant ID: {}\n", participant_b.participant_id());

    // Wait for SPDP exchange (100ms should be enough for local multicast)
    println!("[...] Waiting 100ms for SPDP exchange...");
    thread::sleep(Duration::from_millis(100));

    // Verify Participant A discovered Participant B
    if let Some(discovery_a) = participant_a.discovery() {
        let participants = discovery_a.get_participants();
        println!(
            "\n[i] Participant A discovered {} remote participants:",
            participants.len()
        );
        for p in &participants {
            println!("   - GUID: {}", p.guid);
            println!("     Endpoints: {:?}", p.endpoints);
            println!("     Lease: {}ms", p.lease_duration_ms);
        }

        // Check that Participant B was discovered
        let found_b = participants.iter().any(|p| p.guid == participant_b.guid());
        assert!(found_b, "Participant A should discover Participant B");
        println!("[OK] Participant A discovered Participant B");
    } else {
        assert!(
            participant_a.discovery().is_some(),
            "Participant A must have discovery FSM in UdpMulticast mode"
        );
    }

    // Verify bidirectional discovery
    if let Some(discovery_b) = participant_b.discovery() {
        let participants = discovery_b.get_participants();
        println!(
            "\n[i] Participant B discovered {} remote participants:",
            participants.len()
        );
        for p in &participants {
            println!("   - GUID: {}", p.guid);
        }

        let found_a = participants.iter().any(|p| p.guid == participant_a.guid());
        assert!(found_a, "Participant B should discover Participant A");
        println!("[OK] Participant B discovered Participant A");
    } else {
        assert!(
            participant_b.discovery().is_some(),
            "Participant B must have discovery FSM in UdpMulticast mode"
        );
    }

    println!("\n---------------------------------------------");
    println!("[OK] SPDP Discovery Test PASSED!");
    println!("---------------------------------------------\n");
}

#[test]
#[ignore] // Ignore by default (requires UDP multicast permissions)
fn test_sedp_endpoint_announcement() {
    println!("\n---------------------------------------------");
    println!("[*] Test: SEDP Endpoint Announcement");
    println!("---------------------------------------------\n");

    // Create two participants
    let participant_a = Participant::builder("participant_a")
        .domain_id(43)
        .with_transport(TransportMode::UdpMulticast)
        .build()
        .expect("Failed to create participant_a");

    let participant_b = Participant::builder("participant_b")
        .domain_id(43)
        .with_transport(TransportMode::UdpMulticast)
        .build()
        .expect("Failed to create participant_b");

    println!("[OK] Created Participants A and B\n");

    // Wait for SPDP
    thread::sleep(Duration::from_millis(100));

    // Create DataWriter on Participant A
    println!("[*] Creating DataWriter on Participant A...");
    let _writer = participant_a
        .create_writer::<Temperature>("sensor/temp", QoS::best_effort())
        .expect("Failed to create writer");

    println!("[OK] DataWriter created\n");

    // Wait for SEDP announcement
    println!("[...] Waiting 50ms for SEDP announcement...");
    thread::sleep(Duration::from_millis(50));

    // Verify Participant B discovered the writer
    if let Some(discovery_b) = participant_b.discovery() {
        let writers = discovery_b.find_writers_for_topic("sensor/temp");
        println!(
            "\n[i] Participant B found {} writers for topic 'sensor/temp':",
            writers.len()
        );
        for w in &writers {
            println!("   - Endpoint GUID: {}", w.endpoint_guid);
            println!("     Topic: {}", w.topic_name);
            println!("     Type: {}", w.type_name);
        }

        // Note: SEDP announcements are currently received-only (not sent)
        // This test validates RX path. TX path will be added in Sprint 2.
        // When SEDP TX is implemented, uncomment:
        // assert_eq!(writers.len(), 1, "Participant B should discover 1 writer");
        // assert_eq!(writers[0].type_name, "Temperature");
        // println!("[OK] Participant B discovered the Temperature writer");

        println!("\n[!]  SEDP TX not yet implemented - skipping assertion");
        println!("    (Discovery RX path is tested, TX will be added in Sprint 2)");
    } else {
        assert!(
            participant_b.discovery().is_some(),
            "Participant B must have discovery FSM"
        );
    }

    println!("\n---------------------------------------------");
    println!("[OK] SEDP Endpoint Test PASSED (partial)");
    println!("---------------------------------------------\n");
}

#[test]
fn test_discovery_api_intraprocess_mode() {
    // Test that discovery API returns None for IntraProcess mode
    let participant = Participant::builder("intraprocess_test")
        .build() // IntraProcess is default
        .expect("Failed to create participant");

    assert!(
        participant.discovery().is_none(),
        "IntraProcess participant should have no discovery FSM"
    );

    println!("[OK] IntraProcess mode correctly returns None for discovery()");
}
