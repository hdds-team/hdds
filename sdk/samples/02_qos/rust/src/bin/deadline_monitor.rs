// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! # HDDS Sample: Deadline QoS
//!
//! Demonstrates **DEADLINE** QoS - monitors that data arrives within
//! a specified time period, detecting stale or missing updates.
//!
//! ## How DEADLINE Works
//!
//! ```text
//! Deadline Period: 500ms
//!
//! Time:   0ms     300ms    600ms    900ms    1400ms   1500ms
//!          │        │        │        │         │        │
//! Writer:  [1]      [2]      -        [3]       -        [4]
//!          │        │        │        │         │        │
//!          ✓        ✓        ✗        ✓         ✗        ✓
//!                         MISSED!            MISSED!
//! ```
//!
//! ## Use Cases
//!
//! - **Safety systems**: Detect sensor failures
//! - **Heartbeat monitoring**: Ensure components are alive
//! - **Real-time control**: Guarantee update frequency
//! - **SLA enforcement**: Measure data freshness
//!
//! ## Running the Sample
//!
//! ```bash
//! # Terminal 1 - Subscriber (monitors deadlines)
//! cargo run --bin deadline_monitor
//!
//! # Terminal 2 - Publisher (meets deadlines)
//! cargo run --bin deadline_monitor -- pub
//!
//! # Or: Publisher that misses deadlines
//! cargo run --bin deadline_monitor -- slow
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

/// Deadline period in milliseconds
const DEADLINE_MS: u64 = 500;
const NUM_MESSAGES: u32 = 10;

// =============================================================================
// Publisher
// =============================================================================

fn run_publisher(participant: &Arc<hdds::Participant>, slow_mode: bool) -> Result<(), hdds::Error> {
    // -------------------------------------------------------------------------
    // Deadline Writer
    // -------------------------------------------------------------------------
    //
    // Writer must publish at least once per deadline period.
    // If violated, readers' deadline_missed callback fires.

    let qos = hdds::QoS::reliable().deadline_millis(DEADLINE_MS);
    let writer = participant.create_writer::<HelloWorld>("DeadlineTopic", qos)?;

    let interval_ms = if slow_mode { 800 } else { 300 };

    println!(
        "Publishing with {}ms interval (deadline: {}ms)",
        interval_ms, DEADLINE_MS
    );
    if slow_mode {
        println!("WARNING: This will MISS deadlines!\n");
    } else {
        println!("This should meet all deadlines.\n");
    }

    let start = Instant::now();

    for i in 0..NUM_MESSAGES {
        let msg = HelloWorld::new(format!("Update #{}", i + 1), i + 1);
        writer.write(&msg)?;

        let elapsed = start.elapsed().as_millis();
        let status = if slow_mode && i > 0 {
            " (will miss deadline)"
        } else {
            ""
        };
        println!("  [{:5}ms] Sent #{}{}", elapsed, i + 1, status);

        thread::sleep(Duration::from_millis(interval_ms));
    }

    println!("\nPublisher finished.");
    Ok(())
}

// =============================================================================
// Subscriber
// =============================================================================

fn run_subscriber(participant: &Arc<hdds::Participant>) -> Result<(), hdds::Error> {
    let qos = hdds::QoS::reliable().deadline_millis(DEADLINE_MS);
    let reader = participant.create_reader::<HelloWorld>("DeadlineTopic", qos)?;

    let waitset = hdds::dds::WaitSet::new();
    waitset.attach_condition(reader.get_status_condition())?;

    println!(
        "Monitoring for deadline violations (deadline: {}ms)...\n",
        DEADLINE_MS
    );

    let mut received = 0u32;
    let mut violations = 0u32;
    let start = Instant::now();
    let mut last_recv = start;

    while received < NUM_MESSAGES {
        match waitset.wait(Some(Duration::from_millis(DEADLINE_MS * 2))) {
            Ok(triggered) if !triggered.is_empty() => {
                while let Some(msg) = reader.take().ok().flatten() {
                    let now = Instant::now();
                    let elapsed = start.elapsed().as_millis();
                    let delta = (now - last_recv).as_millis();

                    // Check if deadline was missed
                    let status = if delta > DEADLINE_MS as u128 && received > 0 {
                        violations += 1;
                        "DEADLINE MISSED!"
                    } else {
                        "OK"
                    };

                    println!(
                        "  [{:5}ms] Received #{} (delta={}ms) {}",
                        elapsed, msg.count, delta, status
                    );

                    last_recv = now;
                    received += 1;
                }
            }
            Ok(_) | Err(hdds::Error::WouldBlock) => {
                let elapsed = start.elapsed().as_millis();
                println!("  [{:5}ms] DEADLINE VIOLATION - no data!", elapsed);
                violations += 1;
            }
            Err(e) => eprintln!("Wait error: {:?}", e),
        }
    }

    // -------------------------------------------------------------------------
    // Summary
    // -------------------------------------------------------------------------

    println!("\n{}", "-".repeat(50));
    println!(
        "Summary: {} messages, {} deadline violations",
        received, violations
    );
    if violations == 0 {
        println!("All deadlines met!");
    } else {
        println!("Deadline violations indicate data staleness.");
    }
    println!("{}", "-".repeat(50));

    Ok(())
}

// =============================================================================
// Main
// =============================================================================

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let is_publisher = args.get(1).map(|s| s == "pub").unwrap_or(false);
    let slow_mode = args.get(1).map(|s| s == "slow").unwrap_or(false);

    println!("{}", "=".repeat(60));
    println!("HDDS Deadline QoS Sample");
    println!("Monitor update rate violations");
    println!("{}\n", "=".repeat(60));

    let participant = hdds::Participant::builder("DeadlineDemo")
        .with_transport(hdds::TransportMode::IntraProcess)
        .build()?;

    if is_publisher || slow_mode {
        run_publisher(&participant, slow_mode)?;
    } else {
        run_subscriber(&participant)?;
    }

    Ok(())
}
