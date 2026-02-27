// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! # HDDS Sample: Manual Liveliness QoS
//!
//! Demonstrates **MANUAL_BY_PARTICIPANT** liveliness - the application must
//! explicitly assert liveliness (by writing data or calling assert_liveliness).
//!
//! ## AUTOMATIC vs MANUAL Liveliness
//!
//! | Aspect    | AUTOMATIC              | MANUAL_BY_PARTICIPANT      |
//! |-----------|------------------------|----------------------------|
//! | Assertion | DDS heartbeats         | Application writes/asserts |
//! | Detects   | Process crash          | Application-level hang     |
//! | Use case  | Infrastructure health  | Business logic health      |
//!
//! ## Why MANUAL Liveliness?
//!
//! AUTOMATIC only proves the DDS stack is running. MANUAL proves the
//! application is functioning:
//!
//! ```text
//! Scenario: App stuck in infinite loop, DDS still running
//!
//! AUTOMATIC:  ✓ Heartbeats continue - no alert
//! MANUAL:     ✗ No write() calls - LIVELINESS_LOST triggered
//! ```
//!
//! ## Running the Sample
//!
//! ```bash
//! # Terminal 1 - Subscriber
//! cargo run --bin liveliness_manual
//!
//! # Terminal 2 - Publisher (simulates slow processing)
//! cargo run --bin liveliness_manual -- pub
//! ```

use std::env;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

#[allow(dead_code)]
mod generated {
    include!("../../../../01_basics/rust/generated/hello_world.rs");
}

use generated::hdds_samples::HelloWorld;

/// Liveliness lease duration
const LEASE_MS: u64 = 2000;
const NUM_MESSAGES: u32 = 6;

// =============================================================================
// Publisher
// =============================================================================

fn run_publisher(participant: &Arc<hdds::Participant>) -> Result<(), hdds::Error> {
    // -------------------------------------------------------------------------
    // MANUAL_BY_PARTICIPANT Writer
    // -------------------------------------------------------------------------
    //
    // Liveliness is only asserted when:
    // 1. write() is called, OR
    // 2. writer.assert_liveliness() is called explicitly

    let qos = hdds::QoS::reliable().liveliness_manual_participant_millis(LEASE_MS);
    let writer = participant.create_writer::<HelloWorld>("ManualLivenessTopic", qos)?;

    println!(
        "Publishing with MANUAL_BY_PARTICIPANT liveliness (lease: {}ms)",
        LEASE_MS
    );
    println!("Application must assert liveliness by writing data.\n");

    let start = Instant::now();

    for i in 0..NUM_MESSAGES {
        let msg = HelloWorld::new(format!("Manual update #{}", i + 1), i + 1);
        writer.write(&msg)?;

        let elapsed = start.elapsed().as_millis();
        println!("  [{}ms] Sent #{} (liveliness asserted)", elapsed, i + 1);

        // First 3: normal rate. Last 3: slow (simulates processing delay)
        if i < 3 {
            thread::sleep(Duration::from_millis(500)); // Within lease
        } else {
            println!("  (simulating slow processing - will miss liveliness!)");
            thread::sleep(Duration::from_millis(2500)); // Exceeds lease!
        }
    }

    println!("\nPublisher done. Some liveliness violations occurred.");
    Ok(())
}

// =============================================================================
// Subscriber
// =============================================================================

fn run_subscriber(participant: &Arc<hdds::Participant>) -> Result<(), hdds::Error> {
    let qos = hdds::QoS::reliable().liveliness_manual_participant_millis(LEASE_MS);
    let reader = participant.create_reader::<HelloWorld>("ManualLivenessTopic", qos)?;

    let waitset = hdds::dds::WaitSet::new();
    waitset.attach_condition(reader.get_status_condition())?;

    println!(
        "Monitoring MANUAL_BY_PARTICIPANT liveliness (lease: {}ms)...",
        LEASE_MS
    );
    println!("Writer must assert liveliness explicitly.\n");

    let mut received = 0u32;
    let mut liveliness_events = 0u32;
    let start = Instant::now();
    let mut last_msg = start;

    while received < NUM_MESSAGES || liveliness_events < 3 {
        match waitset.wait(Some(Duration::from_millis(LEASE_MS))) {
            Ok(triggered) if !triggered.is_empty() => {
                while let Some(msg) = reader.take().ok().flatten() {
                    let now = Instant::now();
                    let elapsed = start.elapsed().as_millis();
                    let delta = (now - last_msg).as_millis();

                    let status = if delta > LEASE_MS as u128 && received > 0 {
                        " [LIVELINESS WAS LOST]"
                    } else {
                        ""
                    };

                    println!(
                        "  [{}ms] Received #{} (delta={}ms){}",
                        elapsed, msg.count, delta, status
                    );

                    last_msg = now;
                    received += 1;
                }
            }
            Ok(_) | Err(hdds::Error::WouldBlock) => {
                let elapsed = start.elapsed().as_millis();
                let since_last = (Instant::now() - last_msg).as_millis();

                if since_last > LEASE_MS as u128 && received > 0 {
                    println!(
                        "  [{}ms] LIVELINESS LOST! (no assertion for {}ms)",
                        elapsed, since_last
                    );
                    liveliness_events += 1;
                }

                if liveliness_events >= 3 {
                    break;
                }
            }
            Err(e) => eprintln!("Wait error: {:?}", e),
        }
    }

    // -------------------------------------------------------------------------
    // Summary
    // -------------------------------------------------------------------------

    println!("\n{}", "-".repeat(50));
    println!(
        "Summary: {} messages, {} liveliness events",
        received, liveliness_events
    );
    println!("MANUAL liveliness detects application-level issues.");
    println!("{}", "-".repeat(50));

    Ok(())
}

// =============================================================================
// Main
// =============================================================================

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let is_publisher = args.get(1).map(|s| s == "pub").unwrap_or(false);

    println!("{}", "=".repeat(60));
    println!("HDDS Manual Liveliness QoS Sample");
    println!("Application must explicitly assert liveliness");
    println!("{}\n", "=".repeat(60));

    let participant = hdds::Participant::builder("LivelinessManualDemo")
        .with_transport(hdds::TransportMode::IntraProcess)
        .build()?;

    if is_publisher {
        run_publisher(&participant)?;
    } else {
        run_subscriber(&participant)?;
    }

    Ok(())
}
