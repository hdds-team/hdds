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

/// Web Debugger Demo (Port 4244 - Alternative)
///
/// Demonstrates:
/// - Admin API startup for mesh introspection
/// - Multiple participants publishing/subscribing
/// - Real-time visualization via Web Debugger
///
/// Usage:
/// 1. Run this demo: `cargo run --example debugger_demo_alt`
/// 2. In another terminal: `HDDS_ADMIN_ADDR=127.0.0.1:4244 cargo run --bin hdds-debugger`
/// 3. Open browser: http://localhost:8080
/// 4. Observe mesh graph with 3 participants + metrics updating
use hdds::{AdminApi, Participant, QoS, TransportMode, DDS};
use std::thread;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, DDS)]
struct SensorData {
    sensor_id: u32,
    temperature: f32,
    pressure: f32,
    timestamp_ms: u64,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== HDDS Web Debugger Demo (Port 4244) ===\n");

    // Step 1: Create participants FIRST (initializes global MetricsCollector)
    // Use UdpMulticast transport for real discovery (required for topic visibility)
    println!("[*] Creating 3 participants with UDP multicast discovery...");

    let participant1 = Participant::builder("sensor_node_1")
        .with_transport(TransportMode::UdpMulticast)
        .domain_id(0)
        .build()?;
    println!("[OK] Created participant: sensor_node_1");

    let participant2 = Participant::builder("sensor_node_2")
        .with_transport(TransportMode::UdpMulticast)
        .domain_id(0)
        .build()?;
    println!("[OK] Created participant: sensor_node_2");

    let participant3 = Participant::builder("dashboard_node")
        .with_transport(TransportMode::UdpMulticast)
        .domain_id(0)
        .build()?;
    println!("[OK] Created participant: dashboard_node\n");

    // Step 2: Start Admin API with discovery FSM for topic/writer/reader visibility
    println!("[*] Starting Admin API on 127.0.0.1:4244");
    let discovery_fsm = participant1.discovery(); // Get FSM from first participant
    let mut admin = AdminApi::bind("127.0.0.1", 4244, discovery_fsm)?;
    println!("[OK] Admin API running (Tier 1 mode with discovery)\n");

    // Share global MetricsCollector with Admin API
    let metrics = hdds::telemetry::get_metrics();
    admin.set_metrics(metrics);
    println!("[OK] Shared MetricsCollector with Admin API\n");

    // Register all 3 participants in Admin API
    admin.set_local_participant("sensor_node_1".to_string());
    admin.set_local_participant("sensor_node_2".to_string());
    admin.set_local_participant("dashboard_node".to_string());
    println!("[OK] Registered 3 participants in Admin API\n");

    // Step 3: Create topics
    println!("[*] Creating topics...");

    let topic1 = participant1.topic::<SensorData>("sensor/temperature")?;
    let topic2 = participant2.topic::<SensorData>("sensor/pressure")?;
    let topic3 = participant3.topic::<SensorData>("sensor/temperature")?;

    println!("[OK] Created topic: sensor/temperature (node 1 -> node 3)");
    println!("[OK] Created topic: sensor/pressure (node 2 -> node 3)\n");

    // Step 4: Create writers and readers
    let writer1 = topic1
        .writer()
        .qos(QoS::best_effort().keep_last(10))
        .build()?;

    let writer2 = topic2
        .writer()
        .qos(QoS::best_effort().keep_last(10))
        .build()?;

    let reader3 = topic3
        .reader()
        .qos(QoS::best_effort().keep_last(100))
        .build()?;

    // Bind reader to writer (in-process communication)
    reader3.bind_to_writer(writer1.merger());

    println!("[OK] Created writers and readers");
    println!("[OK] Bound dashboard_node reader to sensor_node_1 writer\n");

    // Step 5: Instruct user to start debugger
    println!("+---------------------------------------------------+");
    println!("|  Web Debugger Instructions (PORT 4244)            |");
    println!("+---------------------------------------------------+");
    println!("|  1. Open a new terminal                           |");
    println!("|  2. Run: HDDS_ADMIN_ADDR=127.0.0.1:4244 \\        |");
    println!("|          cargo run -p hdds-gateway                |");
    println!("|  3. Open browser: http://localhost:8080           |");
    println!("|                                                   |");
    println!("|  You should see:                                  |");
    println!("|  - Mesh graph with 3 participant nodes            |");
    println!("|  - Active Topics section with discovered topics   |");
    println!("|  - Writers/Readers endpoints                      |");
    println!("|  - Metrics updating every 100ms (10 Hz)           |");
    println!("|  - Status bar: Connected (green)                  |");
    println!("+---------------------------------------------------+\n");

    println!("[>] Publishing messages (Press Ctrl+C to stop)...\n");

    // Step 6: Publish loop
    let mut seq = 0u64;
    loop {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        // Sensor 1: Temperature readings
        let temp_data = SensorData {
            sensor_id: 1,
            temperature: 20.0 + (seq as f32 * 0.1) % 10.0,
            pressure: 1013.25,
            timestamp_ms: timestamp,
        };
        if let Err(e) = writer1.write(&temp_data) {
            if !matches!(e, hdds::Error::WouldBlock) {
                return Err(e.into());
            }
            // Skip this message if buffer full (WouldBlock)
        }

        // Sensor 2: Pressure readings
        let pressure_data = SensorData {
            sensor_id: 2,
            temperature: 22.0,
            pressure: 1010.0 + (seq as f32 * 0.5) % 20.0,
            timestamp_ms: timestamp,
        };
        if let Err(e) = writer2.write(&pressure_data) {
            if !matches!(e, hdds::Error::WouldBlock) {
                return Err(e.into());
            }
            // Skip this message if buffer full (WouldBlock)
        }

        seq += 1;

        // Print progress every 10 messages
        if seq.is_multiple_of(10) {
            println!(
                "[i] Published {} messages | Temperature: {:.1} C | Pressure: {:.2} hPa",
                seq, temp_data.temperature, pressure_data.pressure
            );
        }

        // Read messages (dashboard subscriber)
        loop {
            match reader3.take() {
                Ok(Some(sample)) => {
                    // Process received data (silent to reduce console spam)
                    let _data: SensorData = sample;
                }
                Ok(None) => break,                     // No more data
                Err(hdds::Error::WouldBlock) => break, // No data available, continue
                Err(e) => {
                    eprintln!("[!] Reader error: {:?}", e);
                    break;
                }
            }
        }

        // Publish at ~10 Hz
        thread::sleep(Duration::from_millis(100));
    }
}
