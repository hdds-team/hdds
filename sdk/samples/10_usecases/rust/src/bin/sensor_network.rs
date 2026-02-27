// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! # HDDS Sample: IoT Sensor Network
//!
//! This sample demonstrates an **Industrial IoT use case**: distributed
//! sensor data collection using DDS publish-subscribe.
//!
//! ## IoT Architecture with DDS
//!
//! ```text
//! ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
//! │  Sensor 1   │     │  Sensor 2   │     │  Sensor N   │
//! │ (Publisher) │     │ (Publisher) │     │ (Publisher) │
//! └──────┬──────┘     └──────┬──────┘     └──────┬──────┘
//!        │                   │                   │
//!        └───────────────────┼───────────────────┘
//!                            │ DDS Topic: sensors/readings
//!                            ▼
//!                   ┌────────────────┐
//!                   │   Collector    │
//!                   │  (Subscriber)  │
//!                   └────────────────┘
//!                            │
//!                   ┌────────┴────────┐
//!                   ▼                 ▼
//!              Dashboard        Time-Series DB
//! ```
//!
//! ## Why DDS for IoT?
//!
//! - **Decoupled**: Sensors don't need to know about collectors
//! - **Scalable**: Add sensors without reconfiguring the system
//! - **QoS**: Choose reliability vs throughput per use case
//! - **Discovery**: Automatic peer detection, no broker needed
//!
//! ## Message Design
//!
//! ```idl
//! struct SensorReading {
//!     unsigned long sensor_id;      // Unique sensor ID
//!     unsigned long long timestamp; // Nanosecond timestamp
//!     float temperature;            // Temperature in Celsius
//!     float humidity;               // Relative humidity %
//!     float pressure;               // Atmospheric pressure hPa
//!     float battery_voltage;        // Battery voltage
//!     octet signal_strength;        // RSSI (0-100)
//! };
//! ```
//!
//! ## Running the Sample
//!
//! ```bash
//! # Terminal 1 - Start data collector
//! cargo run --bin sensor_network
//!
//! # Terminal 2 - Start sensor simulator (ID: 1)
//! cargo run --bin sensor_network -- sensor 1
//!
//! # Terminal 3 - Start another sensor (ID: 2)
//! cargo run --bin sensor_network -- sensor 2
//! ```

use std::env;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

// =============================================================================
// Generated Types
// =============================================================================

#[allow(dead_code)]
mod generated {
    include!("../../generated/usecases.rs");
}

use generated::iot::SensorReading;

// =============================================================================
// Utility Functions
// =============================================================================

/// Get current timestamp as nanoseconds since Unix epoch.
fn get_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}

// =============================================================================
// Sensor Simulator
// =============================================================================

/// Simulates a sensor node publishing environmental readings.
///
/// Each sensor publishes:
/// - Temperature, humidity, pressure (with realistic noise)
/// - Battery voltage (slowly draining)
/// - Signal strength (fluctuating)
///
/// The sensor ID allows the collector to distinguish between devices.
fn run_sensor(participant: &Arc<hdds::Participant>, sensor_id: u32) -> Result<(), hdds::Error> {
    println!("Starting sensor #{} simulator...\n", sensor_id);

    // -------------------------------------------------------------------------
    // QoS Selection for Sensor Data
    // -------------------------------------------------------------------------
    //
    // BEST_EFFORT is ideal for sensor data because:
    // - High frequency updates (missing one sample isn't critical)
    // - Lower latency (no acknowledgment overhead)
    // - Reduced network traffic
    //
    // Use RELIABLE for alarm/event topics where every message matters.

    let qos = hdds::QoS::best_effort();
    let writer = participant.create_writer::<SensorReading>("sensors/readings", qos)?;

    println!("Publishing sensor data at 2 Hz");
    println!("QoS: BEST_EFFORT (optimal for sensor streams)\n");

    let start = Instant::now();

    for seq in 0..60 {
        let t = start.elapsed().as_secs_f32();

        // ---------------------------------------------------------------------
        // Simulate Sensor Readings
        // ---------------------------------------------------------------------
        //
        // Real sensors have noise. We simulate this with sinusoidal variation
        // plus small random-like perturbations (using deterministic functions).

        let noise = (t * 10.0).sin() * 0.3;

        // Each sensor has slightly different base readings (using sensor_id)
        let reading = SensorReading {
            sensor_id,
            timestamp: get_timestamp(),

            // Temperature: 22°C base + sensor offset + noise
            temperature: 22.0 + noise * 3.0 + (sensor_id as f32) * 0.5,

            // Humidity: 45% base + larger variation
            humidity: 45.0 + noise * 10.0,

            // Pressure: 1013 hPa + slow drift
            pressure: 1013.0 + (t * 0.1).sin() * 5.0,

            // Battery: slowly draining over time
            battery_voltage: 3.3 - (seq as f32) * 0.01,

            // Signal strength: fluctuating 70-90
            signal_strength: (80 + (noise * 20.0) as i8) as u8,
        };

        writer.write(&reading)?;

        println!(
            "  [Sensor#{}] T={:.1}°C H={:.1}% P={:.1}hPa Bat={:.2}V RSSI={}",
            reading.sensor_id,
            reading.temperature,
            reading.humidity,
            reading.pressure,
            reading.battery_voltage,
            reading.signal_strength
        );

        thread::sleep(Duration::from_millis(500)); // 2 Hz
    }

    println!("\nSensor #{} finished. Published 60 readings.", sensor_id);
    Ok(())
}

// =============================================================================
// Data Collector
// =============================================================================

/// Central collector that receives data from all sensors.
///
/// In a production system, this would:
/// - Store readings in a time-series database (InfluxDB, TimescaleDB)
/// - Compute aggregates (min, max, avg per sensor)
/// - Trigger alerts on threshold violations
/// - Forward to cloud services
fn run_collector(participant: &Arc<hdds::Participant>) -> Result<(), hdds::Error> {
    println!("Starting sensor data collector...\n");

    let qos = hdds::QoS::best_effort();
    let reader = participant.create_reader::<SensorReading>("sensors/readings", qos)?;

    let status_condition = reader.get_status_condition();
    let waitset = hdds::dds::WaitSet::new();
    waitset.attach_condition(status_condition)?;

    println!("Subscribed to: sensors/readings");
    println!("Collecting data from all sensors...\n");

    // Dashboard-style header
    println!(
        "{:>6} {:>8} {:>8} {:>10} {:>6} {:>4}",
        "Sensor", "Temp(°C)", "Hum(%)", "Press(hPa)", "Bat(V)", "RSSI"
    );
    println!("{}", "-".repeat(55));

    let mut count = 0;
    let timeout = Duration::from_secs(60);
    let start = Instant::now();

    // -------------------------------------------------------------------------
    // Collection Loop
    // -------------------------------------------------------------------------
    //
    // The collector runs until timeout, aggregating data from all sensors.
    // With BEST_EFFORT QoS, some samples may be missed under high load.

    while start.elapsed() < timeout {
        match waitset.wait(Some(Duration::from_secs(2))) {
            Ok(triggered) => {
                if !triggered.is_empty() {
                    // Process all available readings
                    while let Some(reading) = reader.take()? {
                        println!(
                            "{:>6} {:>8.1} {:>8.1} {:>10.1} {:>6.2} {:>4}",
                            reading.sensor_id,
                            reading.temperature,
                            reading.humidity,
                            reading.pressure,
                            reading.battery_voltage,
                            reading.signal_strength
                        );

                        // Alert on anomalies
                        if reading.temperature > 30.0 {
                            println!("  ⚠️  HIGH TEMP: Sensor #{}", reading.sensor_id);
                        }
                        if reading.battery_voltage < 3.0 {
                            println!("  ⚠️  LOW BATTERY: Sensor #{}", reading.sensor_id);
                        }

                        count += 1;
                    }
                }
            }
            Err(hdds::Error::WouldBlock) => {
                println!("  (waiting for sensor data...)");
            }
            Err(e) => {
                eprintln!("Error: {:?}", e);
            }
        }
    }

    // Summary
    println!("\n{}", "-".repeat(55));
    println!("Collection complete.");
    println!("Total readings received: {}", count);
    println!("Collection duration: {} seconds", timeout.as_secs());

    Ok(())
}

// =============================================================================
// Main
// =============================================================================

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    let mode = args.get(1).map(|s| s.as_str());
    let sensor_id: u32 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(1);

    println!("{}", "=".repeat(60));
    println!("HDDS IoT Sensor Network");
    println!("Topic: sensors/readings");
    println!("Use Case: Distributed environmental monitoring");
    println!("{}\n", "=".repeat(60));

    let participant = hdds::Participant::builder("SensorNetwork")
        .with_transport(hdds::TransportMode::UdpMulticast)
        .domain_id(0)
        .build()?;

    println!("Participant: {}", participant.name());
    println!("Domain ID: {}\n", participant.domain_id());

    match mode {
        Some("sensor") => run_sensor(&participant, sensor_id)?,
        _ => run_collector(&participant)?,
    }

    Ok(())
}
