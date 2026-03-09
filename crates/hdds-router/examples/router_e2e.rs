// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! End-to-end router test: publish on domain 0, receive on domain 1.
//!
//! Flow:
//!   1. Create publisher on domain 0 ("Sensor/Temperature")
//!   2. Start router: domain 0 -> domain 1, remap Sensor/* -> Vehicle/*
//!   3. Router discovers the topic, creates relay endpoints
//!   4. Create subscriber on domain 1 ("Vehicle/Temperature")
//!   5. Publish 10 messages
//!   6. Verify they arrive on domain 1 with the remapped topic
//!
//! Note: on localhost, multicast loopback can cause duplicate delivery.
//! This is normal DDS behavior on a single machine. The example deduplicates
//! by sequence number to show the logical message flow.
//!
//! Run: cargo run -p hdds-router --example router_e2e

use hdds::{Participant, TransportMode};
use hdds_router::{RouteConfig, Router, RouterConfig};
use std::collections::BTreeMap;
use std::time::Duration;

const DOMAIN_SRC: u32 = 0;
const DOMAIN_DST: u32 = 1;
const MSG_COUNT: usize = 10;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_target(false)
        .init();

    println!("=== Router End-to-End Test ===");
    println!(
        "  Domain {} (Sensor/Temperature)  -->  Router  -->  Domain {} (Vehicle/Temperature)",
        DOMAIN_SRC, DOMAIN_DST
    );
    println!();

    // ---------------------------------------------------------------
    // 1. Publisher on domain 0
    // ---------------------------------------------------------------
    let pub_participant = Participant::builder("e2e-publisher")
        .with_transport(TransportMode::UdpMulticast)
        .domain_id(DOMAIN_SRC)
        .participant_id(Some(10))
        .build()?;

    let pub_writer = pub_participant.create_raw_writer("Sensor/Temperature", None)?;

    println!(
        "[1/5] Publisher created on domain {} topic \"Sensor/Temperature\"",
        DOMAIN_SRC
    );

    // ---------------------------------------------------------------
    // 2. Start the router
    // ---------------------------------------------------------------
    let mut config = RouterConfig {
        name: "e2e-router".into(),
        ..Default::default()
    };
    config.add_route(
        RouteConfig::new(DOMAIN_SRC, DOMAIN_DST)
            .topics(hdds_router::config::TopicSelection::Pattern(
                "Sensor/*".into(),
            ))
            .remap("Sensor/*", "Vehicle/*"),
    );

    let mut router = Router::new(config)?;
    let handle = router.run().await?;
    println!(
        "[2/5] Router started (domain {} -> domain {})",
        DOMAIN_SRC, DOMAIN_DST
    );

    // ---------------------------------------------------------------
    // 3. Wait for discovery (router polls every 1s)
    // ---------------------------------------------------------------
    println!("[3/5] Waiting for topic discovery...");
    tokio::time::sleep(Duration::from_secs(3)).await;

    // ---------------------------------------------------------------
    // 4. Subscriber on domain 1
    // ---------------------------------------------------------------
    let sub_participant = Participant::builder("e2e-subscriber")
        .with_transport(TransportMode::UdpMulticast)
        .domain_id(DOMAIN_DST)
        .participant_id(Some(20))
        .build()?;

    let sub_reader = sub_participant.create_raw_reader("Vehicle/Temperature", None)?;

    println!(
        "[4/5] Subscriber created on domain {} topic \"Vehicle/Temperature\"",
        DOMAIN_DST
    );

    // Give the subscriber time to match with the router's writer
    tokio::time::sleep(Duration::from_secs(2)).await;

    // ---------------------------------------------------------------
    // 5. Publish messages
    // ---------------------------------------------------------------
    println!("[5/5] Publishing {} messages...\n", MSG_COUNT);

    for i in 0..MSG_COUNT {
        // Simple payload: 4-byte CDR2-LE encapsulation header + u32 seq + f32 value
        let seq = i as u32;
        let value: f32 = 20.0 + (i as f32) * 0.5;

        let mut payload = Vec::with_capacity(12);
        // CDR2 little-endian encapsulation header
        payload.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]);
        payload.extend_from_slice(&seq.to_le_bytes());
        payload.extend_from_slice(&value.to_le_bytes());

        pub_writer.write_raw(&payload)?;
        println!(
            "  TX [domain {}] seq={:2}, temp={:.1}C",
            DOMAIN_SRC, seq, value
        );

        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // Let the router forward everything
    tokio::time::sleep(Duration::from_secs(1)).await;

    // ---------------------------------------------------------------
    // 6. Read and dedup on the subscriber side
    // ---------------------------------------------------------------
    println!();
    let samples = sub_reader.try_take_raw()?;
    let total_received = samples.len();

    // Dedup by sequence number (multicast loopback can cause duplicates on localhost)
    let mut unique: BTreeMap<u32, f32> = BTreeMap::new();
    for sample in &samples {
        if sample.payload.len() >= 12 {
            let seq = u32::from_le_bytes(sample.payload[4..8].try_into().unwrap());
            let value = f32::from_le_bytes(sample.payload[8..12].try_into().unwrap());
            unique.entry(seq).or_insert(value);
        }
    }

    for (&seq, &value) in &unique {
        println!(
            "  RX [domain {}] seq={:2}, temp={:.1}C",
            DOMAIN_DST, seq, value
        );
    }

    // ---------------------------------------------------------------
    // Results
    // ---------------------------------------------------------------
    println!();

    if let Ok(stats) = handle.get_stats().await {
        for s in &stats {
            println!(
                "  Stats domain {} -> {}: {} msgs routed, {} bytes",
                s.from_domain, s.to_domain, s.messages_routed, s.bytes_routed
            );
        }
    }

    let unique_count = unique.len();
    println!();
    println!(
        "  Sent:     {:2} messages on Sensor/Temperature  (domain {})",
        MSG_COUNT, DOMAIN_SRC
    );
    println!(
        "  Received: {:2} unique messages on Vehicle/Temperature (domain {})",
        unique_count, DOMAIN_DST
    );
    if total_received > unique_count {
        println!(
            "            ({} total with multicast loopback duplicates)",
            total_received
        );
    }

    if unique_count == MSG_COUNT {
        println!("\n  ALL {} MESSAGES ROUTED SUCCESSFULLY!", MSG_COUNT);
    } else if unique_count > 0 {
        println!(
            "\n  PARTIAL: {}/{} unique messages received (best-effort QoS)",
            unique_count, MSG_COUNT
        );
    } else {
        println!("\n  NO DATA received. Discovery may need more time on this network.");
    }

    handle.stop();
    Ok(())
}
