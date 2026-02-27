// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! # HDDS Sample: ROS2-Style Talker/Listener
//!
//! This sample demonstrates **ROS2-compatible communication** using HDDS.
//! It implements the classic ROS2 "talker/listener" pattern using DDS directly.
//!
//! ## ROS2 and DDS
//!
//! ROS2 is built on top of DDS. When you use `rclcpp` or `rclpy`, you're actually
//! using DDS underneath. HDDS can communicate directly with ROS2 nodes by:
//!
//! - Using the same topic naming convention (`rt/<topic>` prefix)
//! - Using compatible message types (matching field layout)
//! - Using the same domain ID (default: 0)
//!
//! ## Topic Naming Convention
//!
//! ROS2 maps topic names to DDS topics with prefixes:
//! - `/chatter` in ROS2 → `rt/chatter` in DDS
//! - `/cmd_vel` in ROS2 → `rt/cmd_vel` in DDS
//!
//! The `rt/` prefix stands for "ROS Topic".
//!
//! ## Running the Sample
//!
//! ```bash
//! # Terminal 1 - Start listener (subscriber)
//! cargo run --bin string_talker_listener
//!
//! # Terminal 2 - Start talker (publisher)
//! cargo run --bin string_talker_listener -- talk
//!
//! # Alternative: Run with a ROS2 node
//! # ros2 run demo_nodes_cpp talker  # Publishes to /chatter
//! ```
//!
//! ## Message Type
//!
//! We use `Int32` instead of `String` to avoid Rust naming conflicts.
//! The ROS2 equivalent is `std_msgs/msg/Int32`.

use std::env;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

// =============================================================================
// Generated Types from IDL
// =============================================================================
//
// ROS2 message types are defined in IDL format. Our ROS2Types.idl contains
// equivalents of common std_msgs and geometry_msgs types.
//
// Note: We use Int32 here because naming a struct "String" in Rust conflicts
// with std::String. In real ROS2 interop, you'd need careful type mapping.

#[allow(dead_code)]
mod generated {
    include!("../../generated/ros2_types.rs");
}

use generated::ros2_msgs::Int32;

// =============================================================================
// Talker (Publisher)
// =============================================================================

/// Implements the "talker" node - publishes incrementing integers.
///
/// This mirrors the behavior of `ros2 run demo_nodes_cpp talker` but uses
/// Int32 instead of String for simplicity.
fn run_talker(participant: &Arc<hdds::Participant>) -> Result<(), hdds::Error> {
    println!("Starting ROS2-style talker node...\n");

    // -------------------------------------------------------------------------
    // QoS for ROS2 Compatibility
    // -------------------------------------------------------------------------
    //
    // ROS2 uses RELIABLE QoS by default for most topics. This ensures:
    // - Messages are acknowledged
    // - Lost messages are retransmitted
    //
    // For sensor data or video streams, ROS2 often uses BEST_EFFORT.

    let qos = hdds::QoS::reliable();

    // -------------------------------------------------------------------------
    // Topic Naming
    // -------------------------------------------------------------------------
    //
    // "rt/counter" in DDS corresponds to "/counter" in ROS2.
    // To communicate with ROS2's /chatter topic, you'd use "rt/chatter".

    let writer = participant.create_writer::<Int32>("rt/counter", qos)?;

    println!("Publishing to topic: rt/counter (ROS2: /counter)");
    println!("Message type: std_msgs/msg/Int32 equivalent\n");

    // -------------------------------------------------------------------------
    // Publish Loop
    // -------------------------------------------------------------------------
    //
    // Classic ROS2 talker pattern: publish incrementing values at fixed rate.

    for i in 0..50 {
        let msg = Int32 { data: i };

        writer.write(&msg)?;
        println!("  [Talker] Publishing: {}", msg.data);

        // 2 Hz publish rate (similar to default ROS2 talker)
        thread::sleep(Duration::from_millis(500));
    }

    println!("\nTalker finished. Published 50 messages.");
    Ok(())
}

// =============================================================================
// Listener (Subscriber)
// =============================================================================

/// Implements the "listener" node - receives and prints messages.
///
/// This mirrors the behavior of `ros2 run demo_nodes_cpp listener`.
fn run_listener(participant: &Arc<hdds::Participant>) -> Result<(), hdds::Error> {
    println!("Starting ROS2-style listener node...\n");

    let qos = hdds::QoS::reliable();
    let reader = participant.create_reader::<Int32>("rt/counter", qos)?;

    // -------------------------------------------------------------------------
    // WaitSet Setup
    // -------------------------------------------------------------------------
    //
    // In ROS2 (rclcpp), you'd use spin() or executors.
    // At the DDS level, WaitSet provides the same functionality.

    let status_condition = reader.get_status_condition();
    let waitset = hdds::dds::WaitSet::new();
    waitset.attach_condition(status_condition)?;

    println!("Subscribed to topic: rt/counter (ROS2: /counter)");
    println!("Waiting for messages...\n");

    // -------------------------------------------------------------------------
    // Receive Loop
    // -------------------------------------------------------------------------

    let mut count = 0;
    while count < 50 {
        match waitset.wait(Some(Duration::from_secs(10))) {
            Ok(triggered) => {
                if !triggered.is_empty() {
                    // Process all available messages
                    while let Some(msg) = reader.take()? {
                        println!("  [Listener] I heard: {}", msg.data);
                        count += 1;
                    }
                }
            }
            Err(hdds::Error::WouldBlock) => {
                println!("  (waiting for talker node...)");
            }
            Err(e) => {
                eprintln!("Error: {:?}", e);
            }
        }
    }

    println!("\nListener finished. Received {} messages.", count);
    Ok(())
}

// =============================================================================
// Main
// =============================================================================

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let is_talker = args.get(1).map(|s| s == "talk").unwrap_or(false);

    println!("{}", "=".repeat(60));
    println!("HDDS ROS2 Talker/Listener Sample");
    println!("Topic: rt/counter (ROS2: /counter)");
    println!("Type: std_msgs/msg/Int32 equivalent");
    println!("{}\n", "=".repeat(60));

    // -------------------------------------------------------------------------
    // Participant Configuration
    // -------------------------------------------------------------------------
    //
    // ROS2 defaults:
    // - Domain ID: 0 (configurable via ROS_DOMAIN_ID env var)
    // - Discovery: UDP Multicast (standard DDS SPDP/SEDP)
    //
    // To communicate with ROS2 nodes, use the same domain ID.

    let participant = hdds::Participant::builder("ros2_demo")
        .with_transport(hdds::TransportMode::UdpMulticast)
        .domain_id(0) // Match ROS_DOMAIN_ID (default: 0)
        .build()?;

    println!("Node Configuration:");
    println!("  Participant: {}", participant.name());
    println!(
        "  Domain ID: {} (matches ROS2 default)",
        participant.domain_id()
    );
    println!();

    if is_talker {
        run_talker(&participant)?;
    } else {
        run_listener(&participant)?;
    }

    Ok(())
}
