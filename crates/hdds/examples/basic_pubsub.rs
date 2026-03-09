// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/// Basic Pub/Sub Example for HDDS
///
/// Demonstrates:
/// - Using #[derive(DDS)] macro
/// - Creating a Participant
/// - Creating DataWriter and DataReader
/// - Publishing and subscribing to messages
/// - Simple in-process communication
use hdds::{Participant, QoS, DDS};

// Define a simple message type using the DDS derive macro
#[derive(Debug, Clone, Copy, PartialEq, DDS)]
struct Temperature {
    sensor_id: u32,
    celsius: f32,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== HDDS Basic Pub/Sub Example ===\n");

    // Create a participant (represents a DDS application)
    let participant = Participant::builder("basic_pubsub_example").build()?;
    println!("[OK] Created participant");

    // Create a topic for Temperature messages
    let topic = participant.topic::<Temperature>("TemperatureTopic")?;
    println!("[OK] Created topic: TemperatureTopic");

    // Create a DataWriter (publisher) with best-effort QoS
    let writer = topic
        .writer()
        .qos(QoS::best_effort().keep_last(10))
        .build()?;
    println!("[OK] Created DataWriter with KeepLast(10)");

    // Create a DataReader (subscriber) with best-effort QoS
    let reader = topic
        .reader()
        .qos(QoS::best_effort().keep_last(10))
        .build()?;
    println!("[OK] Created DataReader with KeepLast(10)");

    // Bind reader to writer (for in-process communication)
    reader.bind_to_writer(writer.merger());
    println!("[OK] Bound reader to writer");

    println!("\n--- Publishing Messages ---");

    // Publish some temperature readings
    for i in 1..=5 {
        let temp = Temperature {
            sensor_id: 101,
            celsius: 20.0 + (i as f32 * 0.5),
        };

        writer.write(&temp)?;
        println!(
            "Published: sensor_id={}, celsius={:.1} C",
            temp.sensor_id, temp.celsius
        );

        // Small delay to simulate real-world publishing
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    println!("\n--- Receiving Messages ---");

    // Read messages from the DataReader
    let mut received_count = 0;
    while let Some(temp) = reader.take()? {
        println!(
            "Received:  sensor_id={}, celsius={:.1} C",
            temp.sensor_id, temp.celsius
        );
        received_count += 1;
    }

    println!("\n--- Summary ---");
    println!("Messages published: 5");
    println!("Messages received:  {}", received_count);

    if received_count == 5 {
        println!("[OK] All messages delivered successfully!");
    } else {
        println!("[!] Some messages were lost (expected with best-effort QoS)");
    }

    Ok(())
}
