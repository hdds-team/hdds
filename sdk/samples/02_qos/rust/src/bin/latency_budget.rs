// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! # HDDS Sample: Latency Budget QoS
//!
//! Demonstrates **LATENCY_BUDGET** QoS - provides delivery latency hints
//! to the middleware, allowing it to optimize batching and scheduling.
//!
//! ## How LATENCY_BUDGET Works
//!
//! ```text
//! Budget = 0ms (immediate delivery):
//!
//!   Writer:  [msg]----->  Middleware  ----->  Reader
//!                         (send now)         (instant)
//!
//! Budget = 100ms (batching allowed):
//!
//!   Writer:  [msg1]--+
//!            [msg2]--+--> Middleware  ------> Reader
//!            [msg3]--+   (batch up            (receives batch
//!                         to 100ms)            within 100ms)
//! ```
//!
//! ## Use Cases
//!
//! - **Real-time control vs analytics**: Control loops need budget=0,
//!   analytics can tolerate batched delivery
//! - **Trading vs reporting**: Order execution needs minimal latency,
//!   position reports can be batched
//! - **Bandwidth optimization**: Higher budgets allow more efficient
//!   network utilization through batching
//!
//! ## Running the Sample
//!
//! ```bash
//! # Single-process mode (recommended):
//! cargo run --bin latency_budget
//!
//! # Two-terminal mode:
//! # Terminal 1 - Subscriber
//! cargo run --bin latency_budget -- sub
//!
//! # Terminal 2 - Publisher
//! cargo run --bin latency_budget -- pub
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

/// Number of messages per topic
const NUM_MESSAGES: u32 = 5;
/// Publish interval in milliseconds
const PUBLISH_INTERVAL_MS: u64 = 200;

// =============================================================================
// Publisher
// =============================================================================

fn run_publisher(participant: &Arc<hdds::Participant>) -> Result<(), hdds::Error> {
    // -------------------------------------------------------------------------
    // Low-Latency Writer (budget = 0ms)
    // -------------------------------------------------------------------------
    //
    // Middleware should deliver immediately, no batching allowed.

    let low_latency_qos = hdds::QoS::reliable().latency_budget_millis(0);

    let low_writer = participant.create_writer::<HelloWorld>("LowLatencyTopic", low_latency_qos)?;

    // -------------------------------------------------------------------------
    // Batched Writer (budget = 100ms)
    // -------------------------------------------------------------------------
    //
    // Middleware may batch messages within the 100ms window for efficiency.

    let batched_qos = hdds::QoS::reliable().latency_budget_millis(100);

    let batch_writer = participant.create_writer::<HelloWorld>("BatchedTopic", batched_qos)?;

    println!(
        "Publishing {} messages on each topic at {}ms intervals...\n",
        NUM_MESSAGES, PUBLISH_INTERVAL_MS
    );

    let start = Instant::now();

    for i in 0..NUM_MESSAGES {
        let elapsed = start.elapsed().as_millis();

        // Send on low-latency topic
        let low_msg = HelloWorld::new(format!("LowLatency #{}", i + 1), i + 1);
        low_writer.write(&low_msg)?;
        println!(
            "  [{:5}ms] Sent LowLatency  #{} (budget=0ms)",
            elapsed,
            i + 1
        );

        // Send on batched topic
        let batch_msg = HelloWorld::new(format!("Batched #{}", i + 1), i + 1);
        batch_writer.write(&batch_msg)?;
        println!(
            "  [{:5}ms] Sent Batched     #{} (budget=100ms)",
            elapsed,
            i + 1
        );

        thread::sleep(Duration::from_millis(PUBLISH_INTERVAL_MS));
    }

    println!("\nPublisher finished.");
    Ok(())
}

// =============================================================================
// Subscriber
// =============================================================================

fn run_subscriber(participant: &Arc<hdds::Participant>) -> Result<(), hdds::Error> {
    // -------------------------------------------------------------------------
    // Low-Latency Reader
    // -------------------------------------------------------------------------

    let low_latency_qos = hdds::QoS::reliable().latency_budget_millis(0);

    let low_reader = participant.create_reader::<HelloWorld>("LowLatencyTopic", low_latency_qos)?;

    // -------------------------------------------------------------------------
    // Batched Reader
    // -------------------------------------------------------------------------

    let batched_qos = hdds::QoS::reliable().latency_budget_millis(100);

    let batch_reader = participant.create_reader::<HelloWorld>("BatchedTopic", batched_qos)?;

    let waitset = hdds::dds::WaitSet::new();
    waitset.attach_condition(low_reader.get_status_condition())?;
    waitset.attach_condition(batch_reader.get_status_condition())?;

    println!("Listening on both topics...\n");

    let mut low_received = 0u32;
    let mut batch_received = 0u32;
    let mut low_total_latency_us: u128 = 0;
    let mut batch_total_latency_us: u128 = 0;
    let start = Instant::now();
    let mut timeouts = 0;

    let target = NUM_MESSAGES * 2;

    while (low_received + batch_received) < target && timeouts < 3 {
        match waitset.wait(Some(Duration::from_secs(2))) {
            Ok(triggered) if !triggered.is_empty() => {
                let recv_time = start.elapsed();

                // Check low-latency reader
                while let Some(msg) = low_reader.take().ok().flatten() {
                    let elapsed = recv_time.as_millis();
                    println!("  [{:5}ms] Received LowLatency  #{}", elapsed, msg.count);
                    low_received += 1;
                    low_total_latency_us += recv_time.as_micros();
                }

                // Check batched reader
                while let Some(msg) = batch_reader.take().ok().flatten() {
                    let elapsed = recv_time.as_millis();
                    println!("  [{:5}ms] Received Batched     #{}", elapsed, msg.count);
                    batch_received += 1;
                    batch_total_latency_us += recv_time.as_micros();
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
        "Low-Latency (budget=0ms):   {} messages received",
        low_received
    );
    if low_received > 0 {
        let avg = low_total_latency_us / low_received as u128;
        println!("Low-Latency avg latency:  {} us", avg);
    }
    println!(
        "Batched     (budget=100ms): {} messages received",
        batch_received
    );
    if batch_received > 0 {
        let avg = batch_total_latency_us / batch_received as u128;
        println!("Batched avg latency:      {} us", avg);
    }
    println!("{}", "-".repeat(50));
    println!("Note: Actual latency differences depend on middleware");
    println!("implementation and network conditions.");
    println!("{}", "-".repeat(50));

    Ok(())
}

// =============================================================================
// Single-Process Demo
// =============================================================================

fn run_single_process(participant: &Arc<hdds::Participant>) -> Result<(), hdds::Error> {
    // -------------------------------------------------------------------------
    // Setup writers and readers for both latency profiles
    // -------------------------------------------------------------------------

    let low_latency_qos = hdds::QoS::reliable().latency_budget_millis(0);

    let batched_qos = hdds::QoS::reliable().latency_budget_millis(100);

    let low_writer =
        participant.create_writer::<HelloWorld>("LowLatencyTopic", low_latency_qos.clone())?;
    let batch_writer =
        participant.create_writer::<HelloWorld>("BatchedTopic", batched_qos.clone())?;

    let low_reader = participant.create_reader::<HelloWorld>("LowLatencyTopic", low_latency_qos)?;
    let batch_reader = participant.create_reader::<HelloWorld>("BatchedTopic", batched_qos)?;

    let waitset = hdds::dds::WaitSet::new();
    waitset.attach_condition(low_reader.get_status_condition())?;
    waitset.attach_condition(batch_reader.get_status_condition())?;

    // Allow time for discovery
    thread::sleep(Duration::from_millis(100));

    println!("Sending {} messages on each topic...\n", NUM_MESSAGES);

    let start = Instant::now();
    let mut low_arrivals: Vec<u128> = Vec::new();
    let mut batch_arrivals: Vec<u128> = Vec::new();

    for i in 0..NUM_MESSAGES {
        let send_time = start.elapsed().as_millis();

        // Publish on both topics simultaneously
        let low_msg = HelloWorld::new(format!("LowLatency #{}", i + 1), i + 1);
        low_writer.write(&low_msg)?;

        let batch_msg = HelloWorld::new(format!("Batched #{}", i + 1), i + 1);
        batch_writer.write(&batch_msg)?;

        println!("  [{:5}ms] Sent #{} on both topics", send_time, i + 1);

        // Brief wait to allow delivery
        thread::sleep(Duration::from_millis(10));

        // Check for arrivals
        match waitset.wait(Some(Duration::from_millis(200))) {
            Ok(triggered) if !triggered.is_empty() => {
                while let Some(_msg) = low_reader.take().ok().flatten() {
                    let arrival = start.elapsed().as_millis();
                    low_arrivals.push(arrival);
                    println!(
                        "  [{:5}ms]   -> LowLatency arrived (delta={}ms)",
                        arrival,
                        arrival - send_time
                    );
                }
                while let Some(_msg) = batch_reader.take().ok().flatten() {
                    let arrival = start.elapsed().as_millis();
                    batch_arrivals.push(arrival);
                    println!(
                        "  [{:5}ms]   -> Batched arrived (delta={}ms)",
                        arrival,
                        arrival - send_time
                    );
                }
            }
            Ok(_) | Err(hdds::Error::WouldBlock) => {}
            Err(e) => eprintln!("Wait error: {:?}", e),
        }

        thread::sleep(Duration::from_millis(PUBLISH_INTERVAL_MS));
    }

    // Drain any remaining messages
    thread::sleep(Duration::from_millis(200));
    if let Ok(triggered) = waitset.wait(Some(Duration::from_millis(500))) {
        if !triggered.is_empty() {
            while let Some(_msg) = low_reader.take().ok().flatten() {
                low_arrivals.push(start.elapsed().as_millis());
            }
            while let Some(_msg) = batch_reader.take().ok().flatten() {
                batch_arrivals.push(start.elapsed().as_millis());
            }
        }
    }

    // -------------------------------------------------------------------------
    // Summary
    // -------------------------------------------------------------------------

    println!("\n{}", "-".repeat(50));
    println!(
        "LowLatency (budget=0ms):   {} of {} delivered",
        low_arrivals.len(),
        NUM_MESSAGES
    );
    println!(
        "Batched    (budget=100ms): {} of {} delivered",
        batch_arrivals.len(),
        NUM_MESSAGES
    );
    println!("{}", "-".repeat(50));
    println!("Note: With budget=0ms the middleware attempts immediate");
    println!("delivery. With budget=100ms, batching may occur.");
    println!("Actual behavior depends on the transport layer.");
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
    println!("HDDS Latency Budget QoS Sample");
    println!("Delivery latency hints for middleware optimization");
    println!("{}\n", "=".repeat(60));

    let participant = hdds::Participant::builder("LatencyBudgetDemo")
        .with_transport(hdds::TransportMode::IntraProcess)
        .build()?;

    match mode {
        Some("pub") => run_publisher(&participant)?,
        Some("sub") => run_subscriber(&participant)?,
        _ => run_single_process(&participant)?,
    }

    Ok(())
}
