// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! # HDDS Sample: Transport Priority QoS
//!
//! Demonstrates **TRANSPORT_PRIORITY** QoS - assigns network priority levels
//! to data flows, enabling quality-of-service differentiation at the
//! transport layer.
//!
//! ## How TRANSPORT_PRIORITY Works
//!
//! ```text
//!                     Priority Queues
//!                   +------------------+
//! Alarm (pri=10) -->| HIGH  [A][A][A]  |---> Network (DSCP EF)
//!                   +------------------+
//!                   |                  |
//! Telemetry (0)  -->| LOW   [T][T][T]  |---> Network (DSCP BE)
//!                   +------------------+
//!
//! Under congestion, high-priority traffic is sent first.
//! OS and NIC must support traffic classification for full effect.
//! ```
//!
//! ## Use Cases
//!
//! - **Emergency data**: Alarms and safety signals get priority
//! - **DSCP marking**: Map DDS priority to IP DiffServ code points
//! - **Traffic class separation**: Isolate critical from bulk traffic
//! - **QoS-aware networks**: Leverage network-level prioritization
//!
//! ## Running the Sample
//!
//! ```bash
//! # Single-process mode (recommended):
//! cargo run --bin transport_priority
//!
//! # Two-terminal mode:
//! # Terminal 1 - Subscriber
//! cargo run --bin transport_priority -- sub
//!
//! # Terminal 2 - Publisher
//! cargo run --bin transport_priority -- pub
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

/// Number of messages per priority level
const NUM_MESSAGES: u32 = 5;
/// High priority value (maps to DSCP Expedited Forwarding)
const PRIORITY_HIGH: i32 = 10;
/// Low priority value (maps to DSCP Best Effort)
const PRIORITY_LOW: i32 = 0;

// =============================================================================
// Publisher
// =============================================================================

fn run_publisher(participant: &Arc<hdds::Participant>) -> Result<(), hdds::Error> {
    // -------------------------------------------------------------------------
    // High-Priority Writer (Alarms)
    // -------------------------------------------------------------------------
    //
    // Transport priority = 10. On supported networks, this maps to higher
    // DSCP values, giving these packets preferential treatment.

    let alarm_qos = hdds::QoS::reliable().transport_priority(PRIORITY_HIGH);

    let alarm_writer = participant.create_writer::<HelloWorld>("AlarmTopic", alarm_qos)?;

    // -------------------------------------------------------------------------
    // Low-Priority Writer (Telemetry)
    // -------------------------------------------------------------------------
    //
    // Transport priority = 0. Standard best-effort network treatment.

    let telemetry_qos = hdds::QoS::reliable().transport_priority(PRIORITY_LOW);

    let telemetry_writer =
        participant.create_writer::<HelloWorld>("TelemetryTopic", telemetry_qos)?;

    println!(
        "Publishing {} messages on each priority level...\n",
        NUM_MESSAGES
    );

    let start = Instant::now();

    // Send a burst of interleaved high and low priority messages
    for i in 0..NUM_MESSAGES {
        let elapsed = start.elapsed().as_millis();

        // High-priority alarm
        let alarm_msg = HelloWorld::new(format!("ALARM #{}", i + 1), i + 1);
        alarm_writer.write(&alarm_msg)?;
        println!(
            "  [{:5}ms] Sent ALARM     #{} (priority={})",
            elapsed,
            i + 1,
            PRIORITY_HIGH
        );

        // Low-priority telemetry
        let telem_msg = HelloWorld::new(format!("Telemetry #{}", i + 1), i + 1);
        telemetry_writer.write(&telem_msg)?;
        println!(
            "  [{:5}ms] Sent TELEMETRY #{} (priority={})",
            elapsed,
            i + 1,
            PRIORITY_LOW
        );

        thread::sleep(Duration::from_millis(100));
    }

    println!("\nPublisher finished.");
    Ok(())
}

// =============================================================================
// Subscriber
// =============================================================================

fn run_subscriber(participant: &Arc<hdds::Participant>) -> Result<(), hdds::Error> {
    // -------------------------------------------------------------------------
    // Alarm Reader (high priority)
    // -------------------------------------------------------------------------

    let alarm_qos = hdds::QoS::reliable().transport_priority(PRIORITY_HIGH);

    let alarm_reader = participant.create_reader::<HelloWorld>("AlarmTopic", alarm_qos)?;

    // -------------------------------------------------------------------------
    // Telemetry Reader (low priority)
    // -------------------------------------------------------------------------

    let telemetry_qos = hdds::QoS::reliable().transport_priority(PRIORITY_LOW);

    let telemetry_reader =
        participant.create_reader::<HelloWorld>("TelemetryTopic", telemetry_qos)?;

    let waitset = hdds::dds::WaitSet::new();
    waitset.attach_condition(alarm_reader.get_status_condition())?;
    waitset.attach_condition(telemetry_reader.get_status_condition())?;

    println!("Listening for alarm and telemetry data...\n");

    let mut alarm_count = 0u32;
    let mut telemetry_count = 0u32;
    let mut arrival_order: Vec<String> = Vec::new();
    let start = Instant::now();
    let mut timeouts = 0;

    while (alarm_count + telemetry_count) < NUM_MESSAGES * 2 && timeouts < 3 {
        match waitset.wait(Some(Duration::from_secs(2))) {
            Ok(triggered) if !triggered.is_empty() => {
                let elapsed = start.elapsed().as_millis();

                // Check alarms first (higher priority)
                while let Some(msg) = alarm_reader.take().ok().flatten() {
                    alarm_count += 1;
                    arrival_order.push(format!("ALARM#{}", msg.count));
                    println!(
                        "  [{:5}ms] Received ALARM     #{} (priority={})",
                        elapsed, msg.count, PRIORITY_HIGH
                    );
                }

                // Check telemetry
                while let Some(msg) = telemetry_reader.take().ok().flatten() {
                    telemetry_count += 1;
                    arrival_order.push(format!("TELEM#{}", msg.count));
                    println!(
                        "  [{:5}ms] Received TELEMETRY #{} (priority={})",
                        elapsed, msg.count, PRIORITY_LOW
                    );
                }

                timeouts = 0;
            }
            Ok(_) | Err(hdds::Error::WouldBlock) => {
                timeouts += 1;
            }
            Err(e) => eprintln!("Wait error: {:?}", e),
        }
    }

    // -------------------------------------------------------------------------
    // Summary
    // -------------------------------------------------------------------------

    println!("\n{}", "-".repeat(50));
    println!(
        "Alarms received    (priority={}): {}",
        PRIORITY_HIGH, alarm_count
    );
    println!(
        "Telemetry received (priority={}):  {}",
        PRIORITY_LOW, telemetry_count
    );
    println!("{}", "-".repeat(50));
    println!("Arrival order: {:?}", arrival_order);
    println!("{}", "-".repeat(50));
    println!("Note: On a congested network with DSCP-aware switches,");
    println!("high-priority alarms would arrive before telemetry.");
    println!("In IntraProcess mode, ordering depends on write order.");
    println!("{}", "-".repeat(50));

    Ok(())
}

// =============================================================================
// Single-Process Demo
// =============================================================================

fn run_single_process(participant: &Arc<hdds::Participant>) -> Result<(), hdds::Error> {
    // -------------------------------------------------------------------------
    // Setup: two writers (alarm + telemetry), two readers
    // -------------------------------------------------------------------------

    let alarm_qos = hdds::QoS::reliable().transport_priority(PRIORITY_HIGH);

    let telemetry_qos = hdds::QoS::reliable().transport_priority(PRIORITY_LOW);

    let alarm_writer = participant.create_writer::<HelloWorld>("AlarmTopic", alarm_qos.clone())?;
    let telemetry_writer =
        participant.create_writer::<HelloWorld>("TelemetryTopic", telemetry_qos.clone())?;

    let alarm_reader = participant.create_reader::<HelloWorld>("AlarmTopic", alarm_qos)?;
    let telemetry_reader =
        participant.create_reader::<HelloWorld>("TelemetryTopic", telemetry_qos)?;

    let waitset = hdds::dds::WaitSet::new();
    waitset.attach_condition(alarm_reader.get_status_condition())?;
    waitset.attach_condition(telemetry_reader.get_status_condition())?;

    // Allow time for discovery
    thread::sleep(Duration::from_millis(100));

    // -------------------------------------------------------------------------
    // Send burst of interleaved messages
    // -------------------------------------------------------------------------

    println!(
        "Sending burst of {} messages per priority level...\n",
        NUM_MESSAGES
    );

    let start = Instant::now();

    for i in 0..NUM_MESSAGES {
        let elapsed = start.elapsed().as_millis();

        // Interleave: telemetry first, then alarm (to see if priority reorders)
        let telem_msg = HelloWorld::new(format!("Telemetry #{}", i + 1), i + 1);
        telemetry_writer.write(&telem_msg)?;

        let alarm_msg = HelloWorld::new(format!("ALARM #{}", i + 1), i + 1);
        alarm_writer.write(&alarm_msg)?;

        println!(
            "  [{:5}ms] Sent TELEMETRY #{} then ALARM #{}",
            elapsed,
            i + 1,
            i + 1
        );
    }

    // Read back and track arrival order
    thread::sleep(Duration::from_millis(100));

    let mut alarm_count = 0u32;
    let mut telemetry_count = 0u32;
    let mut arrival_order: Vec<String> = Vec::new();
    let mut timeouts = 0;

    while (alarm_count + telemetry_count) < NUM_MESSAGES * 2 && timeouts < 3 {
        match waitset.wait(Some(Duration::from_secs(2))) {
            Ok(triggered) if !triggered.is_empty() => {
                let elapsed = start.elapsed().as_millis();

                while let Some(msg) = alarm_reader.take().ok().flatten() {
                    alarm_count += 1;
                    arrival_order.push(format!("ALARM#{}", msg.count));
                    println!("  [{:5}ms] Received ALARM     #{}", elapsed, msg.count);
                }

                while let Some(msg) = telemetry_reader.take().ok().flatten() {
                    telemetry_count += 1;
                    arrival_order.push(format!("TELEM#{}", msg.count));
                    println!("  [{:5}ms] Received TELEMETRY #{}", elapsed, msg.count);
                }

                timeouts = 0;
            }
            Ok(_) | Err(hdds::Error::WouldBlock) => {
                timeouts += 1;
            }
            Err(e) => eprintln!("Wait error: {:?}", e),
        }
    }

    // -------------------------------------------------------------------------
    // Summary
    // -------------------------------------------------------------------------

    println!("\n{}", "-".repeat(50));
    println!(
        "Alarms received    (priority={}): {}",
        PRIORITY_HIGH, alarm_count
    );
    println!(
        "Telemetry received (priority={}):  {}",
        PRIORITY_LOW, telemetry_count
    );
    println!("{}", "-".repeat(50));
    println!("Arrival order: {:?}", arrival_order);
    println!("{}", "-".repeat(50));
    println!("Note: Transport priority affects DSCP/TOS bits in IP packets.");
    println!("For actual prioritization, configure your OS and network:");
    println!("  - Linux: tc qdisc, SO_PRIORITY socket option");
    println!("  - Switches: DSCP-to-queue mapping");
    println!("In IntraProcess mode, no network prioritization occurs.");
    println!("{}", "-".repeat(50));

    Ok(())
}

// =============================================================================
// Main
// =============================================================================

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let mode = args.get(1).map(|s| s.as_str());

    println!("{}", "=".repeat(60));
    println!("HDDS Transport Priority QoS Sample");
    println!("Network priority levels for traffic differentiation");
    println!("{}\n", "=".repeat(60));

    let participant = hdds::Participant::builder("TransportPriorityDemo")
        .with_transport(hdds::TransportMode::IntraProcess)
        .build()?;

    match mode {
        Some("pub") => run_publisher(&participant)?,
        Some("sub") => run_subscriber(&participant)?,
        _ => run_single_process(&participant)?,
    }

    Ok(())
}
