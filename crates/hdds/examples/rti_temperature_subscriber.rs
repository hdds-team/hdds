// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

#![allow(clippy::uninlined_format_args)]
#![allow(clippy::missing_panics_doc)]

//! RTI Interop Temperature Subscriber
//! Subscribes to "Temperature" topic to receive data from RTI Connext publisher

use hdds::api::{Participant, QoS, TransportMode};
use hdds::generated::temperature::Temperature;
use std::thread;
use std::time::Duration;

fn main() {
    println!("+===========================================================+");
    println!("|   HDDS Subscriber - RTI Temperature Interop Test         |");
    println!("+===========================================================+");
    println!();
    println!("Configuration:");
    println!("  - Topic: Example TemperatureData_Temperature (RTI default)");
    println!("  - Type: TemperatureData::Temperature");
    println!("  - QoS: RTI defaults (Reliable, Volatile, KeepLast(10)) [v60]");
    println!("  - Domain: 0");
    println!("  - Transport: UDP Multicast");
    println!();

    // Create participant with UDP transport
    let participant = Participant::builder("rti_temperature_sub")
        .with_transport(TransportMode::UdpMulticast)
        .build()
        .expect("Failed to create participant");

    println!("[OK] Participant created");

    // Create subscriber - MUST match RTI publisher's topic name exactly!
    // RTI uses: dds::topic::Topic<TemperatureData::Temperature> topic(participant, "Example TemperatureData_Temperature");
    // v60: Use QoS::rti_defaults() which loads RTI-compatible QoS profile
    let reader = participant
        .create_reader::<Temperature>(
            "Example TemperatureData_Temperature", // <- Match RTI topic name EXACTLY
            QoS::rti_defaults(),                   // v60: Use RTI default QoS profile!
        )
        .expect("Failed to create reader");

    println!("[OK] Temperature reader created");
    println!();
    println!("[*] Waiting for RTI Temperature samples...");
    println!("   (Press Ctrl+C to stop)");
    println!();

    let mut sample_count = 0u64;

    loop {
        thread::sleep(Duration::from_millis(100));

        // Try to read samples
        match reader.take() {
            Ok(Some(sample)) => {
                sample_count += 1;
                println!(
                    "[<] Sample #{}: Temperature = {:.2}  degC (timestamp: {})",
                    sample_count, sample.value, sample.timestamp
                );
            }
            Ok(None) => {
                // No data available yet
            }
            Err(e) => {
                eprintln!("[X] Error reading sample: {:?}", e);
            }
        }
    }
}
