// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/// Multi-Node Communication Example for HDDS
///
/// Demonstrates:
/// - Multiple publishers and subscribers
/// - Topic-based routing
/// - Fan-out communication pattern
/// - Message distribution across multiple readers
///
/// Note: This example simulates multi-node communication within a single process.
/// Full multi-process discovery will be integrated in future phases.
use hdds::{Participant, QoS, DDS};

// Simple sensor data message
#[derive(Debug, Clone, Copy, PartialEq, DDS)]
struct SensorData {
    node_id: u32,
    value: f32,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== HDDS Multi-Node Communication Example ===\n");
    println!("Simulating 1 publisher -> 3 subscribers\n");

    // Create participant
    let participant = Participant::builder("multi_node_example").build()?;
    println!("[OK] Created participant");

    // Create topic
    let topic = participant.topic::<SensorData>("SensorTopic")?;
    println!("[OK] Created topic: SensorTopic");

    // Create ONE writer (publisher node)
    let writer = topic
        .writer()
        .qos(QoS::best_effort().keep_last(5))
        .build()?;
    println!("\n[OK] Created Publisher (Writer)");

    // Create THREE readers (subscriber nodes)
    let reader1 = topic
        .reader()
        .qos(QoS::best_effort().keep_last(5))
        .build()?;

    let reader2 = topic
        .reader()
        .qos(QoS::best_effort().keep_last(5))
        .build()?;

    let reader3 = topic
        .reader()
        .qos(QoS::best_effort().keep_last(5))
        .build()?;

    println!("[OK] Created 3 Subscribers (Readers)");

    // Bind all readers to the writer (simulates discovery)
    reader1.bind_to_writer(writer.merger());
    reader2.bind_to_writer(writer.merger());
    reader3.bind_to_writer(writer.merger());
    println!("[OK] Bound all readers to writer (discovery complete)");

    println!("\n--- Publishing Sensor Data ---");

    // Publish 5 messages from the publisher
    for i in 1..=5 {
        let data = SensorData {
            node_id: 100,
            value: 20.0 + (i as f32),
        };

        writer.write(&data)?;
        println!(
            "Published: node_id={}, value={:.1}",
            data.node_id, data.value
        );

        // Small delay to simulate real-world timing
        std::thread::sleep(std::time::Duration::from_millis(50));
    }

    println!("\n--- Subscribers Receiving Data ---");

    // Each reader should receive all 5 messages
    println!("\nSubscriber 1:");
    let mut count1 = 0;
    while let Some(data) = reader1.take()? {
        println!(
            "  Received: node_id={}, value={:.1}",
            data.node_id, data.value
        );
        count1 += 1;
    }

    println!("\nSubscriber 2:");
    let mut count2 = 0;
    while let Some(data) = reader2.take()? {
        println!(
            "  Received: node_id={}, value={:.1}",
            data.node_id, data.value
        );
        count2 += 1;
    }

    println!("\nSubscriber 3:");
    let mut count3 = 0;
    while let Some(data) = reader3.take()? {
        println!(
            "  Received: node_id={}, value={:.1}",
            data.node_id, data.value
        );
        count3 += 1;
    }

    println!("\n--- Summary ---");
    println!("Messages published:  5");
    println!("Subscriber 1 received: {}", count1);
    println!("Subscriber 2 received: {}", count2);
    println!("Subscriber 3 received: {}", count3);

    if count1 == 5 && count2 == 5 && count3 == 5 {
        println!("\n[OK] SUCCESS: All subscribers received all messages!");
        println!("[OK] Fan-out pattern working correctly (1 -> N communication)");
    } else {
        println!("\n[!] Some messages were not delivered to all subscribers");
    }

    println!("\nNote: This example demonstrates in-process multi-reader communication.");
    println!("Full multi-process node discovery will be integrated in future phases.");

    Ok(())
}
