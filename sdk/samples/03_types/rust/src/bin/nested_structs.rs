// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! # HDDS Sample: Nested Struct Types
//!
//! Demonstrates **nested/composite** type support in DDS/IDL - building complex
//! data structures from simpler types.
//!
//! ## Type Hierarchy
//!
//! ```text
//! Robot
//! ├── name: string
//! ├── pose: Pose
//! │   ├── position: Point
//! │   │   ├── x: double
//! │   │   ├── y: double
//! │   │   └── z: double
//! │   └── orientation: Point
//! │       ├── x: double (roll)
//! │       ├── y: double (pitch)
//! │       └── z: double (yaw)
//! └── trajectory: sequence<Point>
//!     ├── [0] Point { x, y, z }
//!     ├── [1] Point { x, y, z }
//!     └── ...
//! ```
//!
//! ## Composition Benefits
//!
//! ```text
//! Reuse:                      Type Safety:
//! ┌───────────────────────┐  ┌───────────────────────────────────┐
//! │ Point is used in:     │  │ pose.position vs pose.orientation │
//! │ - Pose.position       │  │ are both Point, but semantically  │
//! │ - Pose.orientation    │  │ different.                        │
//! │ - Robot.trajectory[]  │  └───────────────────────────────────┘
//! └───────────────────────┘
//! ```
//!
//! ## IDL Definition
//!
//! ```idl
//! struct Point {
//!     double x, y, z;
//! };
//!
//! struct Pose {
//!     Point position;     // Where the robot is
//!     Point orientation;  // How it's rotated (Euler angles)
//! };
//!
//! struct Robot {
//!     string name;
//!     Pose pose;
//!     sequence<Point> trajectory;  // Planned waypoints
//! };
//! ```
//!
//! ## Use Cases
//!
//! - **Robotics**: Pose, trajectory, sensor readings
//! - **Geometry**: Points, vectors, transforms
//! - **Domain objects**: Complex business entities
//!
//! ## Running the Sample
//!
//! ```bash
//! # Terminal 1 - Subscriber
//! cargo run --bin nested_structs
//!
//! # Terminal 2 - Publisher
//! cargo run --bin nested_structs -- pub
//! ```

use std::env;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

// Include generated type
#[allow(dead_code)]
mod generated {
    include!("../../generated/nested.rs");
}

use generated::hdds_samples::{Point, Pose, Robot};

#[allow(clippy::useless_vec)]
fn run_publisher(participant: &Arc<hdds::Participant>) -> Result<(), hdds::Error> {
    println!("Creating writer...");
    let writer = participant.create_writer::<Robot>("RobotTopic", hdds::QoS::reliable())?;

    println!("Publishing robot samples...\n");

    let samples = vec![
        Robot::builder()
            .name("Robot-Alpha")
            .pose(
                Pose::builder()
                    .position(Point::builder().x(0.0).y(0.0).z(0.0).build().unwrap())
                    .orientation(Point::builder().x(0.0).y(0.0).z(0.0).build().unwrap())
                    .build()
                    .unwrap(),
            )
            .trajectory(vec![
                Point::builder().x(1.0).y(0.0).z(0.0).build().unwrap(),
                Point::builder().x(2.0).y(1.0).z(0.0).build().unwrap(),
                Point::builder().x(3.0).y(2.0).z(0.0).build().unwrap(),
            ])
            .build()
            .expect("build"),
        Robot::builder()
            .name("Robot-Beta")
            .pose(
                Pose::builder()
                    .position(Point::builder().x(10.0).y(20.0).z(0.0).build().unwrap())
                    .orientation(Point::builder().x(0.0).y(0.0).z(1.57).build().unwrap())
                    .build()
                    .unwrap(),
            )
            .trajectory(vec![])
            .build()
            .expect("build"),
        Robot::builder()
            .name("Robot-Gamma")
            .pose(
                Pose::builder()
                    .position(Point::builder().x(-5.0).y(-5.0).z(1.0).build().unwrap())
                    .orientation(Point::builder().x(0.1).y(0.2).z(0.3).build().unwrap())
                    .build()
                    .unwrap(),
            )
            .trajectory(vec![
                Point::builder().x(0.0).y(0.0).z(0.0).build().unwrap(),
                Point::builder().x(5.0).y(5.0).z(1.0).build().unwrap(),
            ])
            .build()
            .expect("build"),
    ];

    for (i, data) in samples.iter().enumerate() {
        writer.write(data)?;
        println!("Published sample {}:", i);
        println!("  name: \"{}\"", data.name);
        println!(
            "  pose.position: ({:.1}, {:.1}, {:.1})",
            data.pose.position.x, data.pose.position.y, data.pose.position.z
        );
        println!(
            "  pose.orientation: ({:.2}, {:.2}, {:.2})",
            data.pose.orientation.x, data.pose.orientation.y, data.pose.orientation.z
        );
        println!("  trajectory: {} waypoints", data.trajectory.len());
        println!();
        thread::sleep(Duration::from_millis(500));
    }

    println!("Done publishing.");
    Ok(())
}

fn run_subscriber(participant: &Arc<hdds::Participant>) -> Result<(), hdds::Error> {
    println!("Creating reader...");
    let reader = participant.create_reader::<Robot>("RobotTopic", hdds::QoS::reliable())?;

    let status_condition = reader.get_status_condition();
    let waitset = hdds::dds::WaitSet::new();
    waitset.attach_condition(status_condition)?;

    println!("Waiting for robot samples...\n");

    let mut received = 0;
    while received < 3 {
        match waitset.wait(Some(Duration::from_secs(5))) {
            Ok(triggered) => {
                if !triggered.is_empty() {
                    while let Some(data) = reader.take()? {
                        received += 1;
                        println!("Received sample {}:", received);
                        println!("  name: \"{}\"", data.name);
                        println!("  pose:");
                        println!(
                            "    position: ({:.1}, {:.1}, {:.1})",
                            data.pose.position.x, data.pose.position.y, data.pose.position.z
                        );
                        println!(
                            "    orientation: ({:.2}, {:.2}, {:.2})",
                            data.pose.orientation.x,
                            data.pose.orientation.y,
                            data.pose.orientation.z
                        );
                        println!("  trajectory ({} waypoints):", data.trajectory.len());
                        for (j, wp) in data.trajectory.iter().enumerate() {
                            println!("    [{}] ({:.1}, {:.1}, {:.1})", j, wp.x, wp.y, wp.z);
                        }
                        println!();
                    }
                }
            }
            Err(hdds::Error::WouldBlock) => {
                println!("  (timeout - no data)");
            }
            Err(e) => {
                eprintln!("Wait error: {:?}", e);
            }
        }
    }

    println!("Done receiving.");
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let is_publisher = args.get(1).map(|s| s == "pub").unwrap_or(false);

    println!("{}", "=".repeat(60));
    println!("Nested Struct Types Demo");
    println!("Demonstrates: Point, Pose, Robot with nested structs");
    println!("{}", "=".repeat(60));

    let participant = hdds::Participant::builder("NestedStructsDemo")
        .with_transport(hdds::TransportMode::UdpMulticast)
        .build()?;

    if is_publisher {
        run_publisher(&participant)?;
    } else {
        run_subscriber(&participant)?;
    }

    Ok(())
}
