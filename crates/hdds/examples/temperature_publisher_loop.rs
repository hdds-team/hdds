// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Continuous Temperature Publisher
//!
//! Publishes Temperature samples every second in an infinite loop.
//! Useful for testing live capture, discovery, and monitoring tools.
//!
//! # Usage
//!
//! Terminal 1 - Start this publisher:
//! ```bash
//! cargo run --example temperature_publisher_loop
//! ```
//!
//! Terminal 2 - Test with hdds-viewer Live Capture:
//! ```bash
//! cd ../../../hdds_viewer
//! cargo run --release
//! # Then: View -> Live Capture -> Connect -> Discover Topics -> Subscribe to "Temperature"
//! ```
//!
//! Or test with the live_capture example:
//! ```bash
//! cargo run --example live_capture
//! ```

use hdds::generated::temperature::Temperature;
use hdds::{Participant, QoS, Result};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn main() -> Result<()> {
    println!("=== HDDS Temperature Publisher (Continuous) ===\n");

    // Create participant
    println!("[1/2] Creating participant 'temperature-publisher'...");
    let participant = Participant::builder("temperature-publisher")
        .domain_id(0)
        .with_transport(hdds::TransportMode::UdpMulticast)
        .build()?;

    println!("      [OK] Participant created\n");

    // Create topic and writer
    println!("[2/2] Creating Temperature topic and writer...");
    let topic = participant.topic::<Temperature>("Temperature")?;
    let writer = topic.writer().qos(QoS::reliable()).build()?;

    println!("      [OK] Topic and writer ready\n");

    println!("Publishing Temperature samples every 1 second...");
    println!("Press Ctrl+C to stop\n");
    println!("-------------------------------------------------");

    let mut counter = 0u32;
    let start_time = SystemTime::now();

    loop {
        // Generate temperature value (20-30 degC sine wave)
        let elapsed_secs = start_time.elapsed().unwrap().as_secs_f32();
        let temp_value = 25.0 + 5.0 * (elapsed_secs / 10.0).sin();

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;

        let sample = Temperature {
            value: temp_value,
            timestamp: timestamp as i32,
        };

        // Publish
        writer.write(&sample)?;

        println!(
            "[{:>6}] Published: {:.2} degC (timestamp: {})",
            counter, sample.value, sample.timestamp
        );

        counter += 1;

        // Wait 1 second
        std::thread::sleep(Duration::from_secs(1));
    }
}
