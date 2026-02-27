// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! # HDDS Sample: Time-Based Filter QoS
//!
//! Demonstrates **TIME_BASED_FILTER** QoS - reader-side minimum separation
//! between received samples, effectively downsampling high-frequency data.
//!
//! ## How TIME_BASED_FILTER Works
//!
//! ```text
//! Publisher sends at 100ms intervals (20 messages over ~2s):
//!
//!   [1][2][3][4][5][6][7][8][9][10][11][12][13][14][15][16][17][18][19][20]
//!    |  |  |  |  |  |  |  |  |   |   |   |   |   |   |   |   |   |   |  |
//!    v                          v                             v          v
//!
//! Reader A (no filter):     receives ALL 20 messages
//!
//! Reader B (filter=500ms):  receives ~4 messages
//!    [1]----skip----[6]----skip----[11]----skip----[16]----skip----[20]
//!    |<-- 500ms -->|<-- 500ms -->|<--- 500ms --->|<--- 500ms --->|
//! ```
//!
//! ## Use Cases
//!
//! - **Reduce CPU load**: Slow consumers skip excess updates
//! - **Downsample high-frequency data**: 1000Hz sensor to 10Hz display
//! - **Bandwidth conservation**: Network-limited subscribers
//! - **UI refresh rate**: No need to redraw faster than display rate
//!
//! ## Running the Sample
//!
//! ```bash
//! # Single-process mode (recommended - shows both readers side by side):
//! cargo run --bin time_based_filter
//!
//! # Two-terminal mode:
//! # Terminal 1 - Subscriber
//! cargo run --bin time_based_filter -- sub
//!
//! # Terminal 2 - Publisher
//! cargo run --bin time_based_filter -- pub
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

/// Number of messages to publish
const NUM_MESSAGES: u32 = 20;
/// Publish interval in milliseconds
const PUBLISH_INTERVAL_MS: u64 = 100;
/// Time-based filter minimum separation in milliseconds
const FILTER_INTERVAL_MS: u64 = 500;

// =============================================================================
// Publisher
// =============================================================================

fn run_publisher(participant: &Arc<hdds::Participant>) -> Result<(), hdds::Error> {
    // -------------------------------------------------------------------------
    // High-Frequency Writer
    // -------------------------------------------------------------------------
    //
    // Publishes at 100ms intervals. Readers decide how often they want data.

    let qos = hdds::QoS::reliable();
    let writer = participant.create_writer::<HelloWorld>("FilteredTopic", qos)?;

    println!(
        "Publishing {} messages at {}ms intervals...\n",
        NUM_MESSAGES, PUBLISH_INTERVAL_MS
    );

    let start = Instant::now();

    for i in 0..NUM_MESSAGES {
        let msg = HelloWorld::new(format!("Sample #{}", i + 1), i + 1);
        writer.write(&msg)?;

        let elapsed = start.elapsed().as_millis();
        println!("  [{:5}ms] Sent #{}", elapsed, i + 1);

        thread::sleep(Duration::from_millis(PUBLISH_INTERVAL_MS));
    }

    println!("\nPublisher finished ({} messages sent).", NUM_MESSAGES);
    Ok(())
}

// =============================================================================
// Subscriber
// =============================================================================

fn run_subscriber(participant: &Arc<hdds::Participant>) -> Result<(), hdds::Error> {
    // -------------------------------------------------------------------------
    // Reader A: No filter (receives all messages)
    // -------------------------------------------------------------------------

    let qos_all = hdds::QoS::reliable();
    let reader_all = participant.create_reader::<HelloWorld>("FilteredTopic", qos_all)?;

    // -------------------------------------------------------------------------
    // Reader B: Time-based filter (minimum 500ms separation)
    // -------------------------------------------------------------------------
    //
    // The middleware will suppress samples that arrive within 500ms of the
    // previous delivered sample.

    let qos_filtered = hdds::QoS::best_effort().time_based_filter_millis(FILTER_INTERVAL_MS);

    let reader_filtered = participant.create_reader::<HelloWorld>("FilteredTopic", qos_filtered)?;

    let waitset = hdds::dds::WaitSet::new();
    waitset.attach_condition(reader_all.get_status_condition())?;
    waitset.attach_condition(reader_filtered.get_status_condition())?;

    println!(
        "Reader A: No filter (expects all {} messages)",
        NUM_MESSAGES
    );
    println!(
        "Reader B: time_based_filter={}ms (expects ~{} messages)\n",
        FILTER_INTERVAL_MS,
        (NUM_MESSAGES as u64 * PUBLISH_INTERVAL_MS) / FILTER_INTERVAL_MS + 1
    );

    let mut count_all = 0u32;
    let mut count_filtered = 0u32;
    let start = Instant::now();
    let mut timeouts = 0;

    while timeouts < 3 {
        match waitset.wait(Some(Duration::from_secs(2))) {
            Ok(triggered) if !triggered.is_empty() => {
                let elapsed = start.elapsed().as_millis();

                while let Some(msg) = reader_all.take().ok().flatten() {
                    count_all += 1;
                    println!("  [{:5}ms] Reader A (all):      #{}", elapsed, msg.count);
                }

                while let Some(msg) = reader_filtered.take().ok().flatten() {
                    count_filtered += 1;
                    println!(
                        "  [{:5}ms] Reader B (filtered): #{} <-- passed filter",
                        elapsed, msg.count
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
        "Reader A (no filter):       {} messages received",
        count_all
    );
    println!(
        "Reader B (filter={}ms):  {} messages received",
        FILTER_INTERVAL_MS, count_filtered
    );
    println!("{}", "-".repeat(50));
    if count_filtered < count_all {
        println!(
            "Time-based filter reduced delivery by {:.0}%!",
            (1.0 - count_filtered as f64 / count_all.max(1) as f64) * 100.0
        );
    }
    println!("{}", "-".repeat(50));

    Ok(())
}

// =============================================================================
// Single-Process Demo
// =============================================================================

fn run_single_process(participant: &Arc<hdds::Participant>) -> Result<(), hdds::Error> {
    // -------------------------------------------------------------------------
    // Setup: one writer, two readers with different filters
    // -------------------------------------------------------------------------

    let writer_qos = hdds::QoS::reliable();
    let writer = participant.create_writer::<HelloWorld>("FilteredTopic", writer_qos)?;

    // Reader A: receives everything
    let qos_all = hdds::QoS::reliable();
    let reader_all = participant.create_reader::<HelloWorld>("FilteredTopic", qos_all)?;

    // Reader B: time-based filter at 500ms
    let qos_filtered = hdds::QoS::best_effort().time_based_filter_millis(FILTER_INTERVAL_MS);
    let reader_filtered = participant.create_reader::<HelloWorld>("FilteredTopic", qos_filtered)?;

    let waitset = hdds::dds::WaitSet::new();
    waitset.attach_condition(reader_all.get_status_condition())?;
    waitset.attach_condition(reader_filtered.get_status_condition())?;

    // Allow time for discovery
    thread::sleep(Duration::from_millis(100));

    println!("Reader A: No filter (receives all)");
    println!("Reader B: time_based_filter={}ms\n", FILTER_INTERVAL_MS);

    let start = Instant::now();
    let mut count_all = 0u32;
    let mut count_filtered = 0u32;

    // Publish all messages
    for i in 0..NUM_MESSAGES {
        let msg = HelloWorld::new(format!("Sample #{}", i + 1), i + 1);
        writer.write(&msg)?;

        let elapsed = start.elapsed().as_millis();
        println!("  [{:5}ms] Sent #{}", elapsed, i + 1);

        // Brief pause to allow delivery
        thread::sleep(Duration::from_millis(PUBLISH_INTERVAL_MS));

        // Drain available messages
        if let Ok(triggered) = waitset.wait(Some(Duration::from_millis(50))) {
            if !triggered.is_empty() {
                while let Some(_msg) = reader_all.take().ok().flatten() {
                    count_all += 1;
                }
                while let Some(msg) = reader_filtered.take().ok().flatten() {
                    count_filtered += 1;
                    let elapsed = start.elapsed().as_millis();
                    println!("  [{:5}ms]   -> Reader B accepted #{}", elapsed, msg.count);
                }
            }
        }
    }

    // Final drain
    thread::sleep(Duration::from_millis(200));
    if let Ok(triggered) = waitset.wait(Some(Duration::from_millis(500))) {
        if !triggered.is_empty() {
            while let Some(_msg) = reader_all.take().ok().flatten() {
                count_all += 1;
            }
            while let Some(_msg) = reader_filtered.take().ok().flatten() {
                count_filtered += 1;
            }
        }
    }

    // -------------------------------------------------------------------------
    // Summary
    // -------------------------------------------------------------------------

    println!("\n{}", "-".repeat(50));
    println!(
        "Reader A (no filter):       {} of {} messages",
        count_all, NUM_MESSAGES
    );
    println!(
        "Reader B (filter={}ms):  {} of {} messages",
        FILTER_INTERVAL_MS, count_filtered, NUM_MESSAGES
    );
    println!("{}", "-".repeat(50));
    if count_filtered < count_all {
        println!(
            "Time-based filter reduced delivery by {:.0}%!",
            (1.0 - count_filtered as f64 / count_all.max(1) as f64) * 100.0
        );
    } else {
        println!("Both readers received the same count.");
        println!("Filter may not reduce count at this publish rate.");
    }
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
    println!("HDDS Time-Based Filter QoS Sample");
    println!("Reader-side minimum separation between samples");
    println!("{}\n", "=".repeat(60));

    let participant = hdds::Participant::builder("TimeFilterDemo")
        .with_transport(hdds::TransportMode::IntraProcess)
        .build()?;

    match mode {
        Some("pub") => run_publisher(&participant)?,
        Some("sub") => run_subscriber(&participant)?,
        _ => run_single_process(&participant)?,
    }

    Ok(())
}
