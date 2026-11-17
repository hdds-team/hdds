// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Interop Temperature Subscriber (Generated from IDL)
//! Uses the Temperature type idl-gen generates from Temperature.idl, for a
//! publisher you run on your own RTI Connext installation (or any DDS
//! publisher of the same type). Subscribes to "Example TemperatureData_Temperature".

mod temperature_rti;

use hdds::{Participant, QoS, TransportMode};
use std::thread;
use std::time::Duration;
use temperature_rti::TemperatureData::Temperature;

fn main() {
    println!("+===========================================================+");
    println!("|   HDDS Subscriber - Temperature Interop                 |");
    println!("|   Using type generated from IDL by idl-gen              |");
    println!("+===========================================================+");
    println!();
    println!("Configuration:");
    println!("  - Topic: Example TemperatureData_Temperature (use your publisher's topic name)");
    println!("  - Type: TemperatureData::Temperature (FQN from IDL)");
    println!("  - Fields: value:f32, timestamp:i32 (matches Temperature.idl)");
    println!("  - QoS: Reliable, Volatile, KeepLast(10)");
    println!("  - Domain: 0");
    println!("  - Transport: UDP Multicast");
    println!();

    // Create participant with UDP transport
    let participant = Participant::builder("rti_temperature_sub_v65")
        .with_transport(TransportMode::UdpMulticast)
        .build()
        .expect("Failed to create participant");

    println!("[OK] Participant created");

    // Create subscriber; the type matches Temperature.idl:
    // module TemperatureData { struct Temperature { float value; long timestamp; }; };
    let reader = participant
        .topic::<Temperature>("Example TemperatureData_Temperature") // <- must match the publisher's topic name
        .expect("Failed to create topic")
        .reader()
        .qos(QoS::reliable().keep_last(10)) // Reliable, Volatile, KeepLast(10)
        .build()
        .expect("Failed to create reader");

    println!("[OK] Temperature reader created");
    println!();
    println!("[*] Waiting for Temperature samples...");
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
