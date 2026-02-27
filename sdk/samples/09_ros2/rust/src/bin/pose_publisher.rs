// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! # HDDS Sample: ROS2-Style Pose Publisher
//!
//! This sample demonstrates publishing **geometry_msgs/Pose** messages,
//! commonly used in ROS2 for robot localization and navigation.
//!
//! ## Use Cases for Pose Messages
//!
//! - **Robot localization**: Publishing estimated robot position
//! - **SLAM**: Sharing pose estimates from mapping algorithms
//! - **Motion planning**: Communicating goal poses
//! - **Visualization**: Sending poses to RViz for display
//!
//! ## Message Structure
//!
//! ```idl
//! // geometry_msgs/msg/Pose equivalent
//! struct Pose {
//!     Point position;      // x, y, z coordinates
//!     Quaternion orientation;  // rotation as quaternion (x, y, z, w)
//! };
//!
//! struct Point {
//!     double x, y, z;
//! };
//!
//! struct Quaternion {
//!     double x, y, z, w;  // Note: w is the scalar component
//! };
//! ```
//!
//! ## Running the Sample
//!
//! ```bash
//! # Terminal 1 - Start subscriber
//! cargo run --bin pose_publisher
//!
//! # Terminal 2 - Start publisher (simulates robot movement)
//! cargo run --bin pose_publisher -- pub
//!
//! # Visualize in RViz (if ROS2 is installed):
//! # ros2 topic echo /robot_pose geometry_msgs/msg/Pose
//! ```

use std::env;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

// =============================================================================
// Generated Types
// =============================================================================
//
// These types match ROS2 geometry_msgs:
// - Point: 3D position (x, y, z as f64)
// - Quaternion: 3D orientation (x, y, z, w as f64)
// - Pose: Combined position + orientation

#[allow(dead_code)]
mod generated {
    include!("../../generated/ros2_types.rs");
}

use generated::ros2_msgs::{Point, Pose, Quaternion};

// =============================================================================
// Pose Publisher
// =============================================================================

/// Simulates a robot moving in a circle, publishing its pose at 10 Hz.
///
/// This demonstrates:
/// - Creating nested struct messages (Pose contains Point and Quaternion)
/// - Computing quaternion from yaw angle
/// - High-frequency pose updates
fn run_publisher(participant: &Arc<hdds::Participant>) -> Result<(), hdds::Error> {
    println!("Starting pose publisher (robot simulation)...\n");

    let qos = hdds::QoS::reliable();
    let writer = participant.create_writer::<Pose>("rt/robot_pose", qos)?;

    println!("Publishing to: rt/robot_pose (ROS2: /robot_pose)");
    println!("Simulating circular motion at 10 Hz\n");

    // -------------------------------------------------------------------------
    // Simulation Parameters
    // -------------------------------------------------------------------------

    let radius = 2.0_f64; // Circle radius in meters
    let angular_velocity = 0.1; // rad/iteration

    for i in 0..100 {
        let angle = (i as f64) * angular_velocity;

        // ---------------------------------------------------------------------
        // Compute Position
        // ---------------------------------------------------------------------
        // Robot moves in a circle: x = r*cos(θ), y = r*sin(θ)

        let position = Point {
            x: radius * angle.cos(),
            y: radius * angle.sin(),
            z: 0.0, // Ground plane
        };

        // ---------------------------------------------------------------------
        // Compute Orientation (Quaternion from Yaw)
        // ---------------------------------------------------------------------
        //
        // For 2D navigation, we typically only care about yaw (rotation around Z).
        // Quaternion from yaw: q = (0, 0, sin(θ/2), cos(θ/2))
        //
        // The robot faces tangent to the circle (perpendicular to radius).

        let yaw = angle + std::f64::consts::FRAC_PI_2; // Face direction of motion
        let half_yaw = yaw / 2.0;

        let orientation = Quaternion {
            x: 0.0,
            y: 0.0,
            z: half_yaw.sin(),
            w: half_yaw.cos(),
        };

        // ---------------------------------------------------------------------
        // Publish Pose
        // ---------------------------------------------------------------------

        let pose = Pose {
            position,
            orientation,
        };

        writer.write(&pose)?;

        // Print every 10th pose to avoid flooding console
        if i % 10 == 0 {
            println!(
                "  [Pose {:03}] pos=({:+.2}, {:+.2}, {:+.2}) yaw={:.1}°",
                i,
                pose.position.x,
                pose.position.y,
                pose.position.z,
                yaw.to_degrees()
            );
        }

        thread::sleep(Duration::from_millis(100)); // 10 Hz
    }

    println!("\nPublisher finished. Sent 100 pose messages.");
    Ok(())
}

// =============================================================================
// Pose Subscriber
// =============================================================================

/// Receives and displays pose messages.
///
/// In a real application, you might:
/// - Feed poses to a state estimator
/// - Visualize in a custom GUI
/// - Log to a file for later analysis
fn run_subscriber(participant: &Arc<hdds::Participant>) -> Result<(), hdds::Error> {
    println!("Starting pose subscriber...\n");

    let qos = hdds::QoS::reliable();
    let reader = participant.create_reader::<Pose>("rt/robot_pose", qos)?;

    let status_condition = reader.get_status_condition();
    let waitset = hdds::dds::WaitSet::new();
    waitset.attach_condition(status_condition)?;

    println!("Subscribed to: rt/robot_pose (ROS2: /robot_pose)");
    println!("Waiting for pose messages...\n");

    // Table header
    println!(
        "{:>6} {:>10} {:>10} {:>10} {:>10}",
        "Seq", "X", "Y", "Z", "Yaw(°)"
    );
    println!("{}", "-".repeat(50));

    let mut count = 0;
    while count < 100 {
        match waitset.wait(Some(Duration::from_secs(5))) {
            Ok(triggered) => {
                if !triggered.is_empty() {
                    while let Some(pose) = reader.take()? {
                        // Extract yaw from quaternion for display
                        // yaw = atan2(2*(w*z + x*y), 1 - 2*(y² + z²))
                        // Simplified for pure yaw: yaw = 2 * atan2(z, w)
                        let yaw = 2.0 * pose.orientation.z.atan2(pose.orientation.w);

                        if count % 10 == 0 {
                            println!(
                                "{:>6} {:>10.2} {:>10.2} {:>10.2} {:>10.1}",
                                count,
                                pose.position.x,
                                pose.position.y,
                                pose.position.z,
                                yaw.to_degrees()
                            );
                        }
                        count += 1;
                    }
                }
            }
            Err(hdds::Error::WouldBlock) => {
                println!("  (waiting for pose data...)");
            }
            Err(e) => {
                eprintln!("Error: {:?}", e);
            }
        }
    }

    println!("{}", "-".repeat(50));
    println!("\nSubscriber finished. Received {} poses.", count);
    Ok(())
}

// =============================================================================
// Main
// =============================================================================

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let is_publisher = args.get(1).map(|s| s == "pub").unwrap_or(false);

    println!("{}", "=".repeat(60));
    println!("HDDS ROS2 Pose Publisher Sample");
    println!("Topic: rt/robot_pose (ROS2: /robot_pose)");
    println!("Type: geometry_msgs/msg/Pose equivalent");
    println!("{}\n", "=".repeat(60));

    let participant = hdds::Participant::builder("pose_demo")
        .with_transport(hdds::TransportMode::UdpMulticast)
        .domain_id(0)
        .build()?;

    println!("Participant: {}", participant.name());
    println!("Domain ID: {}\n", participant.domain_id());

    if is_publisher {
        run_publisher(&participant)?;
    } else {
        run_subscriber(&participant)?;
    }

    Ok(())
}
