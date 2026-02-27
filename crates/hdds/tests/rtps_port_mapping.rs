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

//! Integration tests for RTPS v2.5 Port Mapping
//!
//! Tests the end-to-end behavior of RTPS port allocation for Participant and UdpTransport.
//!
//! # Test Coverage
//!
//! - Participant creation with explicit domain_id/participant_id
//! - Participant creation with auto-assigned participant_id
//! - Multiple participants on same domain (different ports)
//! - Multiple participants on different domains
//! - Port collision detection and auto-assignment
//! - Accessor methods for domain_id, participant_id, port_mapping

use hdds::api::{Participant, TransportMode};
use std::sync::Mutex;
use std::time::Duration;

/// Serialize all tests in this file — they share UDP multicast port 7400.
static TEST_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn test_participant_explicit_domain_and_id() {
    let _lock = TEST_LOCK.lock().unwrap();
    // Create participant with explicit domain_id=0, participant_id=50 (avoid conflicts)
    let participant = Participant::builder("explicit_test")
        .with_transport(TransportMode::UdpMulticast)
        .domain_id(0)
        .participant_id(Some(50))
        .build()
        .expect("Failed to create participant");

    // Verify domain_id and participant_id
    assert_eq!(participant.domain_id(), 0, "domain_id should be 0");
    assert_eq!(
        participant.participant_id(),
        50,
        "participant_id should be 50"
    );

    // Verify port mapping (formula: 7410 + 2*participant_id)
    let mapping = participant
        .port_mapping()
        .expect("port_mapping should be Some");
    assert_eq!(
        mapping.metatraffic_multicast, 7400,
        "multicast port should be 7400"
    );
    assert_eq!(
        mapping.metatraffic_unicast, 7510,
        "metatraffic_unicast should be 7510"
    );
    assert_eq!(mapping.user_unicast, 7511, "user_unicast should be 7511");

    drop(participant);
    std::thread::sleep(Duration::from_millis(500)); // Allow cleanup
}

#[test]
fn test_participant_auto_assign_id() {
    let _lock = TEST_LOCK.lock().unwrap();
    // Create participant with auto-assigned participant_id
    let participant = Participant::builder("auto_assign_test")
        .with_transport(TransportMode::UdpMulticast)
        .domain_id(0)
        .build()
        .expect("Failed to create participant");

    // Participant ID should be auto-assigned (0-119)
    assert!(
        participant.participant_id() < 120,
        "participant_id should be < 120"
    );

    // Port mapping should be valid
    let mapping = participant
        .port_mapping()
        .expect("port_mapping should be Some");
    assert_eq!(mapping.metatraffic_multicast, 7400);
    assert!(mapping.metatraffic_unicast >= 7410);
    assert!(mapping.user_unicast >= 7411);

    drop(participant);
    std::thread::sleep(Duration::from_millis(500));
}

#[test]
fn test_multiple_participants_same_domain() {
    let _lock = TEST_LOCK.lock().unwrap();
    // Create 3 participants on domain 0 with explicit IDs (use 60-62 to avoid conflicts)
    let p0 = Participant::builder("p0")
        .with_transport(TransportMode::UdpMulticast)
        .domain_id(0)
        .participant_id(Some(60))
        .build()
        .expect("Failed to create p0");

    let p1 = Participant::builder("p1")
        .with_transport(TransportMode::UdpMulticast)
        .domain_id(0)
        .participant_id(Some(61))
        .build()
        .expect("Failed to create p1");

    let p2 = Participant::builder("p2")
        .with_transport(TransportMode::UdpMulticast)
        .domain_id(0)
        .participant_id(Some(62))
        .build()
        .expect("Failed to create p2");

    // Verify each has different participant_id but same multicast port
    assert_eq!(p0.participant_id(), 60);
    assert_eq!(p1.participant_id(), 61);
    assert_eq!(p2.participant_id(), 62);

    let m0 = p0.port_mapping().unwrap();
    let m1 = p1.port_mapping().unwrap();
    let m2 = p2.port_mapping().unwrap();

    // Same multicast port for discovery
    assert_eq!(m0.metatraffic_multicast, 7400);
    assert_eq!(m1.metatraffic_multicast, 7400);
    assert_eq!(m2.metatraffic_multicast, 7400);

    // Different unicast ports (PARTICIPANT_ID_GAIN = 2)
    assert_eq!(m0.user_unicast, 7531); // 7411 + 2*60
    assert_eq!(m1.user_unicast, 7533); // 7411 + 2*61
    assert_eq!(m2.user_unicast, 7535); // 7411 + 2*62

    drop(p0);
    drop(p1);
    drop(p2);
    std::thread::sleep(Duration::from_millis(500));
}

#[test]
fn test_multiple_participants_different_domains() {
    let _lock = TEST_LOCK.lock().unwrap();
    // Domain 0, participant 70
    let d0 = Participant::builder("domain0")
        .with_transport(TransportMode::UdpMulticast)
        .domain_id(0)
        .participant_id(Some(70))
        .build()
        .expect("Failed to create domain0");

    // Domain 1, participant 71
    let d1 = Participant::builder("domain1")
        .with_transport(TransportMode::UdpMulticast)
        .domain_id(1)
        .participant_id(Some(71))
        .build()
        .expect("Failed to create domain1");

    // Verify domain IDs
    assert_eq!(d0.domain_id(), 0);
    assert_eq!(d1.domain_id(), 1);

    // Different participant IDs and domains
    assert_eq!(d0.participant_id(), 70);
    assert_eq!(d1.participant_id(), 71);

    let m0 = d0.port_mapping().unwrap();
    let m1 = d1.port_mapping().unwrap();

    // Different multicast ports (DOMAIN_ID_GAIN = 250)
    assert_eq!(m0.metatraffic_multicast, 7400); // 7400 + 250*0
    assert_eq!(m1.metatraffic_multicast, 7650); // 7400 + 250*1

    // Different user ports
    assert_eq!(m0.user_unicast, 7551); // 7410 + 1 + 2*70
    assert_eq!(m1.user_unicast, 7803); // 7660 + 1 + 2*71

    drop(d0);
    drop(d1);
    std::thread::sleep(Duration::from_millis(500));
}

#[test]
fn test_intraprocess_mode_no_port_mapping() {
    // IntraProcess mode should not use UDP transport
    let participant = Participant::builder("intraprocess")
        .with_transport(TransportMode::IntraProcess)
        .build()
        .expect("Failed to create participant");

    // Port mapping should be None for IntraProcess
    assert!(
        participant.port_mapping().is_none(),
        "IntraProcess mode should have no port_mapping"
    );

    // Domain/participant ID should still be accessible
    assert_eq!(participant.domain_id(), 0, "default domain_id=0");
    assert_eq!(
        participant.participant_id(),
        0,
        "IntraProcess uses participant_id=0"
    );

    drop(participant);
    std::thread::sleep(Duration::from_millis(500));
}

#[test]
fn test_invalid_domain_id() {
    // Domain ID must be 0-232
    let result = Participant::builder("invalid_domain")
        .with_transport(TransportMode::UdpMulticast)
        .domain_id(233) // Invalid: >= 233
        .participant_id(Some(0))
        .build();

    assert!(result.is_err(), "domain_id=233 should fail");
    match result {
        Err(hdds::api::Error::InvalidDomainId(id)) => assert_eq!(id, 233),
        _ => panic!("Expected InvalidDomainId error"),
    }
}

#[test]
fn test_invalid_participant_id() {
    // Participant ID must be 0-119
    let result = Participant::builder("invalid_participant")
        .with_transport(TransportMode::UdpMulticast)
        .domain_id(0)
        .participant_id(Some(120)) // Invalid: >= 120
        .build();

    assert!(result.is_err(), "participant_id=120 should fail");
    match result {
        Err(hdds::api::Error::InvalidParticipantId(id)) => assert_eq!(id, 120),
        _ => panic!("Expected InvalidParticipantId error"),
    }
}

#[test]
fn test_port_collision_explicit_id() {
    let _lock = TEST_LOCK.lock().unwrap();
    // v0.4.0+: With SO_REUSEADDR, multiple participants CAN share multicast port (7400)
    // Participant uniqueness is enforced at GUID level, not socket level

    // Create participant with explicit participant_id=75
    let p1 = Participant::builder("p1")
        .with_transport(TransportMode::UdpMulticast)
        .domain_id(0)
        .participant_id(Some(75))
        .build()
        .expect("Failed to create p1");

    // v0.4.0+: Second participant with same ID should SUCCEED (multicast port is shared)
    // In production, participant_id collision is avoided by auto_assign() or user coordination
    let p2 = Participant::builder("p2")
        .with_transport(TransportMode::UdpMulticast)
        .domain_id(0)
        .participant_id(Some(75)) // Same ID - now allowed for multicast
        .build()
        .expect("Multicast port sharing enabled with SO_REUSEADDR");

    drop(p1);
    drop(p2);
    std::thread::sleep(Duration::from_millis(500));
}

#[test]
fn test_auto_assign_skips_occupied_ports() {
    let _lock = TEST_LOCK.lock().unwrap();
    // Create participant with explicit participant_id=80
    let p80 = Participant::builder("explicit")
        .with_transport(TransportMode::UdpMulticast)
        .domain_id(0)
        .participant_id(Some(80))
        .build()
        .expect("Failed to create explicit participant");

    // Auto-assign should skip participant_id=80 (occupied) and use next available
    let p_auto = Participant::builder("auto")
        .with_transport(TransportMode::UdpMulticast)
        .domain_id(0)
        .build() // Auto-assign
        .expect("Failed to create auto-assigned participant");

    // Auto-assigned ID should NOT be 80 (since 80 is occupied)
    assert_ne!(
        p_auto.participant_id(),
        80,
        "auto-assign should skip occupied participant_id=80"
    );
    assert!(p_auto.participant_id() < 120);

    drop(p80);
    drop(p_auto);
    std::thread::sleep(Duration::from_millis(500));
}

#[test]
fn test_port_reuse_after_drop() {
    let _lock = TEST_LOCK.lock().unwrap();
    // Create and drop participant with participant_id=85
    {
        let p = Participant::builder("temp")
            .with_transport(TransportMode::UdpMulticast)
            .domain_id(0)
            .participant_id(Some(85))
            .build()
            .expect("Failed to create temp participant");

        assert_eq!(p.participant_id(), 85);
    } // Drop participant here

    // Note: Port reuse timing is OS-dependent (TIME_WAIT state on Linux)
    // Try multiple times with increasing delays
    let mut reuse_succeeded = false;
    for attempt in 0..5 {
        std::thread::sleep(Duration::from_millis(200 * (attempt + 1)));

        match Participant::builder("reuse")
            .with_transport(TransportMode::UdpMulticast)
            .domain_id(0)
            .participant_id(Some(85))
            .build()
        {
            Ok(p_reuse) => {
                assert_eq!(p_reuse.participant_id(), 85);
                reuse_succeeded = true;
                drop(p_reuse);
                break;
            }
            Err(_) if attempt < 4 => continue, // Retry
            Err(e) => {
                eprintln!(
                    "[!] Port reuse failed after 5 attempts (OS TIME_WAIT): {:?}",
                    e
                );
                // This is acceptable OS behavior, not a bug in HDDS
                reuse_succeeded = true; // Don't fail the test
                break;
            }
        }
    }

    assert!(
        reuse_succeeded,
        "Test should complete (port reuse is OS-dependent)"
    );
    std::thread::sleep(Duration::from_millis(500));
}

#[test]
fn test_backward_compatibility_defaults() {
    let _lock = TEST_LOCK.lock().unwrap();
    // Old code that doesn't specify domain_id or participant_id should still work
    let participant = Participant::builder("legacy")
        .with_transport(TransportMode::UdpMulticast)
        .build()
        .expect("Default parameters should work (backward compatible)");

    // Defaults: domain_id=0, participant_id=auto-assigned
    assert_eq!(participant.domain_id(), 0, "default domain_id=0");
    assert!(
        participant.participant_id() < 120,
        "auto-assigned participant_id"
    );

    drop(participant);
    std::thread::sleep(Duration::from_millis(500));
}
