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

/// Reliable QoS demonstration
///
/// Shows gap detection, NACK scheduling, and Heartbeat transmission.
///
/// Run two instances:
/// Terminal 1: cargo run --example reliable_qos_demo writer
/// Terminal 2: cargo run --example reliable_qos_demo reader
use hdds::{Participant, QoS, TransportMode};
use std::env;
use std::thread;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, hdds::DDS)]
struct SensorData {
    sensor_id: i32,
    temperature: f32,
    timestamp_ms: u64,
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let mode = args.get(1).map(|s| s.as_str()).unwrap_or("writer");

    match mode {
        "writer" => run_writer(),
        "reader" => run_reader(),
        _ => {
            eprintln!("Usage: reliable_qos_demo [writer|reader]");
            std::process::exit(1);
        }
    }
}

fn run_writer() {
    println!("Starting Reliable Writer...");

    let participant = Participant::builder("reliable_writer")
        .with_transport(TransportMode::UdpMulticast)
        .build()
        .expect("Failed to create participant");

    let writer = participant
        .create_writer::<SensorData>("rt/sensors/temp", QoS::reliable())
        .expect("Failed to create writer");

    println!("Writer ready. Sending messages with Reliable QoS...");
    println!("Heartbeat TX enabled (every ~100ms)");

    let mut seq = 0u64;
    loop {
        seq += 1;

        let data = SensorData {
            sensor_id: 42,
            temperature: 20.0 + (seq as f32 * 0.1),
            timestamp_ms: seq * 1000,
        };

        match writer.write(&data) {
            Ok(()) => {
                println!("[SENT seq={}] temp={:.1} degC", seq, data.temperature);
            }
            Err(e) => {
                eprintln!("[ERROR] Failed to write: {:?}", e);
            }
        }

        // Simulate occasional packet "loss" by skipping sequence
        if seq % 10 == 5 {
            println!("[SKIP seq={}] Simulating packet loss", seq + 1);
            seq += 1; // Skip one message
        }

        thread::sleep(Duration::from_millis(500));
    }
}

fn run_reader() {
    println!("Starting Reliable Reader...");

    let participant = Participant::builder("reliable_reader")
        .with_transport(TransportMode::UdpMulticast)
        .build()
        .expect("Failed to create participant");

    let reader = participant
        .create_reader::<SensorData>("rt/sensors/temp", QoS::reliable())
        .expect("Failed to create reader");

    println!("Reader ready. Waiting for messages...");
    println!("NACK TX enabled (will request retransmission on gaps)");

    loop {
        match reader.take() {
            Ok(Some(data)) => {
                println!(
                    "[RECV] sensor={} temp={:.1} degC ts={}ms",
                    data.sensor_id, data.temperature, data.timestamp_ms
                );
            }
            Ok(None) => {
                // No data available
            }
            Err(e) => {
                eprintln!("[ERROR] Failed to read: {:?}", e);
            }
        }

        thread::sleep(Duration::from_millis(100));
    }
}
