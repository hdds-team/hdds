// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! # HDDS Sample: Robot Telemetry System
//!
//! This sample demonstrates a **real-world robotics use case**: streaming
//! robot state telemetry over DDS for monitoring and control.
//!
//! ## Robotics Telemetry Overview
//!
//! In robotics, telemetry is essential for:
//! - **Fleet monitoring**: Track multiple robots from a central dashboard
//! - **Diagnostics**: Monitor battery, temperatures, error states
//! - **Logging**: Record robot behavior for later analysis
//! - **Safety**: Detect anomalies and trigger emergency stops
//!
//! ## Message Design
//!
//! ```idl
//! struct RobotState {
//!     unsigned long robot_id;      // Unique robot identifier
//!     unsigned long long timestamp_ns;  // Nanosecond timestamp
//!     float position_x, position_y, position_z;  // Position in meters
//!     float orientation_w, x, y, z;  // Orientation quaternion
//!     float battery_percent;       // Battery level (0-100)
//!     octet status;                // 0=IDLE, 1=MOVING, 2=CHARGING
//! };
//! ```
//!
//! ## QoS Considerations
//!
//! - **RELIABLE**: Use for critical state updates (errors, low battery)
//! - **BEST_EFFORT**: Use for high-frequency position updates where
//!   occasional loss is acceptable
//!
//! ## Running the Sample
//!
//! ```bash
//! # Terminal 1 - Start monitoring dashboard
//! cargo run --bin robot_telemetry
//!
//! # Terminal 2 - Start robot simulator
//! cargo run --bin robot_telemetry -- sim
//!
//! # Multiple robots: run multiple simulators with different IDs
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

use generated::robotics::RobotState;

// =============================================================================
// Status Constants
// =============================================================================
//
// Using explicit constants makes code more readable than magic numbers.
// In a larger system, you might use an enum generated from IDL.

/// Robot is stationary, waiting for commands
const STATUS_IDLE: u8 = 0;
/// Robot is executing a movement command
const STATUS_MOVING: u8 = 1;
/// Robot is at charging station, recharging battery
const STATUS_CHARGING: u8 = 2;

/// Convert status code to human-readable string
fn status_to_string(status: u8) -> &'static str {
    match status {
        STATUS_IDLE => "IDLE",
        STATUS_MOVING => "MOVING",
        STATUS_CHARGING => "CHARGING",
        _ => "UNKNOWN",
    }
}

// =============================================================================
// Utility Functions
// =============================================================================

/// Get current time as nanoseconds since Unix epoch.
///
/// This provides a consistent timestamp format across all robots,
/// enabling time synchronization and latency measurement.
fn get_timestamp_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}

// =============================================================================
// Robot Simulator
// =============================================================================

/// Simulates a robot moving in a figure-8 pattern while publishing telemetry.
///
/// The simulator demonstrates:
/// - High-frequency state updates (10 Hz)
/// - Realistic position and orientation data
/// - Battery drain simulation
/// - Automatic status transitions (MOVING → CHARGING when battery low)
fn run_robot_simulator(participant: &Arc<hdds::Participant>) -> Result<(), hdds::Error> {
    println!("Starting robot simulator...\n");

    // -------------------------------------------------------------------------
    // Telemetry QoS
    // -------------------------------------------------------------------------
    //
    // For robot telemetry, RELIABLE QoS ensures:
    // - No state updates are lost
    // - Battery warnings always reach the monitor
    // - Emergency states are guaranteed delivery
    //
    // Trade-off: slightly higher latency due to acknowledgments.

    let qos = hdds::QoS::reliable();
    let writer = participant.create_writer::<RobotState>("robot/state", qos)?;

    println!("Publishing telemetry at 10 Hz to: robot/state");
    println!("Simulating figure-8 motion pattern\n");

    // -------------------------------------------------------------------------
    // Simulation State
    // -------------------------------------------------------------------------

    let start = Instant::now();
    let mut battery = 100.0_f32;

    for seq in 0..200 {
        let t = start.elapsed().as_secs_f32();

        // ---------------------------------------------------------------------
        // Position: Figure-8 (Lissajous curve)
        // ---------------------------------------------------------------------
        //
        // Parametric equations:
        //   x(t) = A * sin(2t)
        //   y(t) = A * sin(t) * cos(t) = A/2 * sin(2t)
        //
        // This creates a smooth, continuous path.

        let scale = 3.0_f32;
        let x = scale * (2.0 * t).sin();
        let y = scale * t.sin() * t.cos();

        // ---------------------------------------------------------------------
        // Orientation: Face direction of motion
        // ---------------------------------------------------------------------
        //
        // Compute velocity vector and derive yaw angle.
        // This makes the robot "look where it's going".

        let vx = scale * 2.0 * (2.0 * t).cos();
        let vy = scale * (t.cos().powi(2) - t.sin().powi(2));
        let yaw = vy.atan2(vx);

        // Quaternion from yaw (rotation around Z-axis only)
        let half_yaw = yaw / 2.0;

        // ---------------------------------------------------------------------
        // Battery & Status Simulation
        // ---------------------------------------------------------------------
        //
        // Realistic scenarios:
        // - Battery drains during operation
        // - Robot switches to CHARGING when battery is low
        // - Status affects operational decisions

        battery = (battery - 0.05).max(10.0); // Drain, but never below 10%
        let status = if battery < 20.0 {
            STATUS_CHARGING
        } else {
            STATUS_MOVING
        };

        // ---------------------------------------------------------------------
        // Build & Publish State
        // ---------------------------------------------------------------------

        let state = RobotState {
            robot_id: 1,
            timestamp_ns: get_timestamp_ns(),
            position_x: x,
            position_y: y,
            position_z: 0.0,
            orientation_w: half_yaw.cos(),
            orientation_x: 0.0,
            orientation_y: 0.0,
            orientation_z: half_yaw.sin(),
            battery_percent: battery,
            status,
        };

        writer.write(&state)?;

        // Log every 10th sample (1 Hz console output)
        if seq % 10 == 0 {
            println!(
                "  [Robot#{}] pos=({:+6.2}, {:+6.2}) battery={:5.1}% status={}",
                state.robot_id,
                state.position_x,
                state.position_y,
                state.battery_percent,
                status_to_string(state.status)
            );
        }

        thread::sleep(Duration::from_millis(100)); // 10 Hz
    }

    println!("\nSimulator finished. Published 200 state updates.");
    Ok(())
}

// =============================================================================
// Monitoring Dashboard
// =============================================================================

/// Monitoring dashboard that displays incoming robot telemetry.
///
/// In a real system, this might:
/// - Display on a web dashboard
/// - Store to a time-series database
/// - Trigger alerts on anomalies
/// - Send commands back to robots
fn run_monitor(participant: &Arc<hdds::Participant>) -> Result<(), hdds::Error> {
    println!("Starting robot monitor...\n");

    let qos = hdds::QoS::reliable();
    let reader = participant.create_reader::<RobotState>("robot/state", qos)?;

    let status_condition = reader.get_status_condition();
    let waitset = hdds::dds::WaitSet::new();
    waitset.attach_condition(status_condition)?;

    println!("Subscribed to: robot/state");
    println!("Monitoring robot telemetry...\n");

    // Dashboard header
    println!(
        "{:>8} {:>10} {:>10} {:>8} {:>10}",
        "Robot", "X", "Y", "Battery", "Status"
    );
    println!("{}", "-".repeat(50));

    let mut count = 0;
    while count < 200 {
        match waitset.wait(Some(Duration::from_secs(5))) {
            Ok(triggered) => {
                if !triggered.is_empty() {
                    while let Some(state) = reader.take()? {
                        // Display every 10th update
                        if count % 10 == 0 {
                            println!(
                                "{:>8} {:>10.2} {:>10.2} {:>7.1}% {:>10}",
                                state.robot_id,
                                state.position_x,
                                state.position_y,
                                state.battery_percent,
                                status_to_string(state.status)
                            );

                            // Alert on low battery
                            if state.battery_percent < 25.0 {
                                println!("  ⚠️  LOW BATTERY WARNING: Robot #{}", state.robot_id);
                            }
                        }
                        count += 1;
                    }
                }
            }
            Err(hdds::Error::WouldBlock) => {
                println!("  (waiting for robot data...)");
            }
            Err(e) => {
                eprintln!("Error: {:?}", e);
            }
        }
    }

    println!("{}", "-".repeat(50));
    println!("\nMonitor finished. Received {} state updates.", count);
    Ok(())
}

// =============================================================================
// Main
// =============================================================================

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let is_simulator = args.get(1).map(|s| s == "sim").unwrap_or(false);

    println!("{}", "=".repeat(60));
    println!("HDDS Robot Telemetry System");
    println!("Topic: robot/state");
    println!("Use Case: Fleet monitoring and diagnostics");
    println!("{}\n", "=".repeat(60));

    let participant = hdds::Participant::builder("RobotTelemetry")
        .with_transport(hdds::TransportMode::UdpMulticast)
        .domain_id(0)
        .build()?;

    println!("Participant: {}", participant.name());
    println!("Domain ID: {}\n", participant.domain_id());

    if is_simulator {
        run_robot_simulator(&participant)?;
    } else {
        run_monitor(&participant)?;
    }

    Ok(())
}
