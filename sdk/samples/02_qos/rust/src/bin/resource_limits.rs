// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! # HDDS Sample: Resource Limits QoS
//!
//! Demonstrates **RESOURCE_LIMITS** QoS - bounds memory usage for samples,
//! instances, and samples-per-instance in the data reader cache.
//!
//! ## How RESOURCE_LIMITS Works
//!
//! ```text
//! resource_limits(max_samples=5, max_instances=1, max_samples_per_instance=5)
//!
//! Publisher sends 20 messages:
//!
//!   [1][2][3][4][5][6][7][8][9][10]...[20]
//!
//! Reader A (limited to 5 samples):
//!
//!   Cache: [1][2][3][4][5]  -- FULL, new samples rejected/dropped
//!   or:    [16][17][18][19][20]  -- depending on history policy
//!
//! Reader B (no limits):
//!
//!   Cache: [1][2][3][4][5]...[18][19][20]  -- all 20 retained
//! ```
//!
//! ## Use Cases
//!
//! - **Embedded systems**: Strict memory budgets
//! - **Memory-constrained environments**: Prevent unbounded cache growth
//! - **Bounded queues**: Cap the maximum pending samples
//! - **Multi-instance control**: Limit per-key storage
//!
//! ## Running the Sample
//!
//! ```bash
//! # Single-process mode (recommended - shows both readers):
//! cargo run --bin resource_limits
//!
//! # Two-terminal mode:
//! # Terminal 1 - Subscriber
//! cargo run --bin resource_limits -- sub
//!
//! # Terminal 2 - Publisher
//! cargo run --bin resource_limits -- pub
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

/// Total messages to publish
const NUM_MESSAGES: u32 = 20;
/// Resource limit: max samples for the limited reader
const MAX_SAMPLES: usize = 5;
/// Resource limit: max instances
const MAX_INSTANCES: usize = 1;
/// Resource limit: max samples per instance
const MAX_SAMPLES_PER_INSTANCE: usize = 5;

// =============================================================================
// Publisher
// =============================================================================

fn run_publisher(participant: &Arc<hdds::Participant>) -> Result<(), hdds::Error> {
    // -------------------------------------------------------------------------
    // Publisher with TRANSIENT_LOCAL + large history
    // -------------------------------------------------------------------------
    //
    // Sends many messages so we can observe how resource limits on the
    // reader side cap the number of retained samples.

    let qos = hdds::QoS::reliable().transient_local().keep_last(100);

    let writer = participant.create_writer::<HelloWorld>("ResourceTopic", qos)?;

    println!("Publishing {} messages rapidly...\n", NUM_MESSAGES);

    let start = Instant::now();

    for i in 0..NUM_MESSAGES {
        let msg = HelloWorld::new(format!("Data #{}", i + 1), i + 1);
        writer.write(&msg)?;

        let elapsed = start.elapsed().as_millis();
        println!("  [{:5}ms] Sent #{}", elapsed, i + 1);

        // Small delay between messages
        thread::sleep(Duration::from_millis(50));
    }

    println!("\nAll {} messages published.", NUM_MESSAGES);
    println!("Waiting for subscribers...\n");

    // Keep writer alive for late-join
    for i in 0..10 {
        println!("  Waiting... {} seconds remaining", 10 - i);
        thread::sleep(Duration::from_secs(1));
    }

    println!("\nPublisher shutting down.");
    Ok(())
}

// =============================================================================
// Subscriber
// =============================================================================

fn run_subscriber(participant: &Arc<hdds::Participant>) -> Result<(), hdds::Error> {
    // -------------------------------------------------------------------------
    // Reader A: Resource-limited (max 5 samples)
    // -------------------------------------------------------------------------
    //
    // This reader can hold at most MAX_SAMPLES samples in its cache.
    // Once full, additional samples are either dropped or replace old ones
    // depending on the history QoS.

    let mut limited_qos = hdds::QoS::reliable().transient_local();
    limited_qos.resource_limits = hdds::qos::ResourceLimits {
        max_samples: MAX_SAMPLES,
        max_instances: MAX_INSTANCES,
        max_samples_per_instance: MAX_SAMPLES_PER_INSTANCE,
        max_quota_bytes: 1_000_000,
    };

    let reader_limited = participant.create_reader::<HelloWorld>("ResourceTopic", limited_qos)?;

    // -------------------------------------------------------------------------
    // Reader B: No resource limits
    // -------------------------------------------------------------------------

    let unlimited_qos = hdds::QoS::reliable().transient_local().keep_last(100);

    let reader_unlimited =
        participant.create_reader::<HelloWorld>("ResourceTopic", unlimited_qos)?;

    let waitset = hdds::dds::WaitSet::new();
    waitset.attach_condition(reader_limited.get_status_condition())?;
    waitset.attach_condition(reader_unlimited.get_status_condition())?;

    println!(
        "Reader A: resource_limits(max_samples={}, max_instances={}, max_spi={})",
        MAX_SAMPLES, MAX_INSTANCES, MAX_SAMPLES_PER_INSTANCE
    );
    println!("Reader B: no resource limits (history_depth=100)\n");

    let mut count_limited = 0u32;
    let mut count_unlimited = 0u32;
    let mut limited_ids: Vec<u32> = Vec::new();
    let mut unlimited_ids: Vec<u32> = Vec::new();
    let start = Instant::now();
    let mut timeouts = 0;

    while timeouts < 3 {
        match waitset.wait(Some(Duration::from_secs(2))) {
            Ok(triggered) if !triggered.is_empty() => {
                let elapsed = start.elapsed().as_millis();

                while let Some(msg) = reader_limited.take().ok().flatten() {
                    count_limited += 1;
                    limited_ids.push(msg.count);
                    println!("  [{:5}ms] Reader A (limited):   #{}", elapsed, msg.count);
                }

                while let Some(msg) = reader_unlimited.take().ok().flatten() {
                    count_unlimited += 1;
                    unlimited_ids.push(msg.count);
                    println!("  [{:5}ms] Reader B (unlimited): #{}", elapsed, msg.count);
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
        "Reader A (limited):   {} messages (limit={})",
        count_limited, MAX_SAMPLES
    );
    println!("  Sample IDs: {:?}", limited_ids);
    println!("Reader B (unlimited): {} messages", count_unlimited);
    println!("  Sample IDs: {:?}", unlimited_ids);
    println!("{}", "-".repeat(50));
    if count_limited < count_unlimited {
        println!(
            "Resource limits capped Reader A at {} samples.",
            count_limited
        );
        println!(
            "Reader B received all {} available samples.",
            count_unlimited
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
    // Setup: one writer, two readers with different resource limits
    // -------------------------------------------------------------------------

    let writer_qos = hdds::QoS::reliable().transient_local().keep_last(100);

    let writer = participant.create_writer::<HelloWorld>("ResourceTopic", writer_qos)?;

    // Reader A: resource-limited
    let mut limited_qos = hdds::QoS::reliable().transient_local();
    limited_qos.resource_limits = hdds::qos::ResourceLimits {
        max_samples: MAX_SAMPLES,
        max_instances: MAX_INSTANCES,
        max_samples_per_instance: MAX_SAMPLES_PER_INSTANCE,
        max_quota_bytes: 1_000_000,
    };

    let reader_limited = participant.create_reader::<HelloWorld>("ResourceTopic", limited_qos)?;

    // Reader B: unlimited
    let unlimited_qos = hdds::QoS::reliable().transient_local().keep_last(100);

    let reader_unlimited =
        participant.create_reader::<HelloWorld>("ResourceTopic", unlimited_qos)?;

    let waitset = hdds::dds::WaitSet::new();
    waitset.attach_condition(reader_limited.get_status_condition())?;
    waitset.attach_condition(reader_unlimited.get_status_condition())?;

    // Allow time for discovery
    thread::sleep(Duration::from_millis(100));

    println!(
        "Reader A: resource_limits(max_samples={}, max_instances={}, max_spi={})",
        MAX_SAMPLES, MAX_INSTANCES, MAX_SAMPLES_PER_INSTANCE
    );
    println!("Reader B: no resource limits\n");

    // -------------------------------------------------------------------------
    // Publish all messages
    // -------------------------------------------------------------------------

    println!("Publishing {} messages...\n", NUM_MESSAGES);

    let start = Instant::now();

    for i in 0..NUM_MESSAGES {
        let msg = HelloWorld::new(format!("Data #{}", i + 1), i + 1);
        writer.write(&msg)?;

        let elapsed = start.elapsed().as_millis();
        println!("  [{:5}ms] Sent #{}", elapsed, i + 1);

        thread::sleep(Duration::from_millis(50));
    }

    // Allow time for delivery
    println!("\nWaiting for delivery...\n");
    thread::sleep(Duration::from_millis(500));

    // -------------------------------------------------------------------------
    // Read from both readers
    // -------------------------------------------------------------------------

    let mut count_limited = 0u32;
    let mut count_unlimited = 0u32;
    let mut limited_ids: Vec<u32> = Vec::new();
    let mut unlimited_ids: Vec<u32> = Vec::new();
    let mut timeouts = 0;

    while timeouts < 2 {
        match waitset.wait(Some(Duration::from_secs(2))) {
            Ok(triggered) if !triggered.is_empty() => {
                let elapsed = start.elapsed().as_millis();

                while let Some(msg) = reader_limited.take().ok().flatten() {
                    count_limited += 1;
                    limited_ids.push(msg.count);
                    println!("  [{:5}ms] Reader A (limited):   #{}", elapsed, msg.count);
                }

                while let Some(msg) = reader_unlimited.take().ok().flatten() {
                    count_unlimited += 1;
                    unlimited_ids.push(msg.count);
                    println!("  [{:5}ms] Reader B (unlimited): #{}", elapsed, msg.count);
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
    println!("Published:  {} messages", NUM_MESSAGES);
    println!("{}", "-".repeat(50));
    println!("Reader A (limited to {} samples):", MAX_SAMPLES);
    println!("  Received: {} messages", count_limited);
    println!("  IDs:      {:?}", limited_ids);
    println!("Reader B (no limits):");
    println!("  Received: {} messages", count_unlimited);
    println!("  IDs:      {:?}", unlimited_ids);
    println!("{}", "-".repeat(50));
    if count_limited < count_unlimited {
        let dropped = count_unlimited - count_limited;
        println!(
            "Resource limits caused {} samples to be dropped for Reader A.",
            dropped
        );
    } else {
        println!("Both readers received the same number of samples.");
        println!("Try increasing NUM_MESSAGES to exceed the resource limit.");
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
    println!("HDDS Resource Limits QoS Sample");
    println!("Memory bounds for samples, instances, and samples-per-instance");
    println!("{}\n", "=".repeat(60));

    let participant = hdds::Participant::builder("ResourceLimitsDemo")
        .with_transport(hdds::TransportMode::IntraProcess)
        .build()?;

    match mode {
        Some("pub") => run_publisher(&participant)?,
        Some("sub") => run_subscriber(&participant)?,
        _ => run_single_process(&participant)?,
    }

    Ok(())
}
