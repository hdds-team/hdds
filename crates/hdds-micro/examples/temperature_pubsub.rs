// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Temperature Publisher/Subscriber Example
//!
//! Demonstrates HDDS Micro with WiFi UDP transport.
//!
//! ## Usage
//!
//! Terminal 1 (subscriber):
//! ```sh
//! cargo run --example temperature_pubsub --features std -- sub
//! ```
//!
//! Terminal 2 (publisher):
//! ```sh
//! cargo run --example temperature_pubsub --features std -- pub
//! ```

use hdds_micro::cdr::{CdrDecoder, CdrEncoder};
use hdds_micro::core::{MicroParticipant, MicroReader, MicroWriter};
use hdds_micro::rtps::Locator;
use hdds_micro::transport::udp::{StdUdpSocket, WifiUdpTransport};
use hdds_micro::Result;

/// Temperature sensor data
#[derive(Debug)]
struct Temperature {
    sensor_id: u32,
    value: f32,
    timestamp: u64,
}

impl Temperature {
    fn new(sensor_id: u32, value: f32, timestamp: u64) -> Self {
        Self {
            sensor_id,
            value,
            timestamp,
        }
    }

    /// Encode to CDR
    fn encode(&self, encoder: &mut CdrEncoder) -> Result<()> {
        encoder.encode_u32(self.sensor_id)?;
        encoder.encode_f32(self.value)?;
        encoder.encode_u64(self.timestamp)?;
        Ok(())
    }

    /// Decode from CDR
    fn decode(decoder: &mut CdrDecoder) -> Result<Self> {
        let sensor_id = decoder.decode_u32()?;
        let value = decoder.decode_f32()?;
        let timestamp = decoder.decode_u64()?;

        Ok(Self {
            sensor_id,
            value,
            timestamp,
        })
    }
}

/// Publisher example
fn run_publisher() -> Result<()> {
    println!("[T]  HDDS Micro - Temperature Publisher");
    println!("=====================================\n");

    // Create UDP socket and transport (use port 0 = OS assigns available port)
    let socket = StdUdpSocket::new();
    let transport = WifiUdpTransport::new(socket, 0)?;

    // Create participant
    let mut participant = MicroParticipant::new(0, transport)?;
    println!("[OK] Participant created");
    println!("   GUID: {:?}", participant.guid());
    println!("   Locator: {:?}\n", participant.local_locator());

    // Create writer
    let writer_id = participant.allocate_entity_id(true);

    // Get destination from env or use default (broadcast on local subnet)
    let dest_ip: [u8; 4] = std::env::var("HDDS_DEST_IP")
        .ok()
        .and_then(|s| {
            let parts: Vec<u8> = s.split('.').filter_map(|p| p.parse().ok()).collect();
            if parts.len() == 4 {
                Some([parts[0], parts[1], parts[2], parts[3]])
            } else {
                None
            }
        })
        .unwrap_or([192, 168, 0, 255]); // default: broadcast

    let dest_locator = Locator::udpv4(dest_ip, 17401);

    let mut writer = MicroWriter::new(
        participant.guid_prefix(),
        writer_id,
        "Temperature",
        dest_locator,
    )?;

    println!("[OK] Writer created for topic 'Temperature'");
    println!("   Destination: {:?}", dest_locator);
    println!("   (Set HDDS_DEST_IP env to change)\n");

    // Publish loop
    println!("[*] Publishing temperature samples...\n");

    for i in 0..10 {
        // Create temperature sample
        let temp = Temperature::new(
            42,                      // sensor_id
            20.0 + (i as f32 * 0.5), // value (increasing)
            std::time::SystemTime::now() // timestamp
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        );

        // Encode
        let mut buf = [0u8; 256];
        let mut encoder = CdrEncoder::new(&mut buf);
        temp.encode(&mut encoder)?;
        let payload = encoder.finish();

        // Write
        writer.write(payload, participant.transport_mut())?;

        println!(
            "[OK] Published sample #{}: sensor_id={}, temp={:.1} degC, seq={}",
            i + 1,
            temp.sensor_id,
            temp.value,
            writer.sequence_number().value() - 1
        );

        // Sleep
        std::thread::sleep(std::time::Duration::from_secs(1));
    }

    println!("\n[OK] Published 10 samples successfully!");

    Ok(())
}

/// Subscriber example
fn run_subscriber() -> Result<()> {
    println!("[T]  HDDS Micro - Temperature Subscriber");
    println!("========================================\n");

    // Create UDP socket and transport (fixed port for receiving)
    let socket = StdUdpSocket::new();
    let transport = WifiUdpTransport::new(socket, 17401)?;

    // Create participant
    let mut participant = MicroParticipant::new(0, transport)?;
    println!("[OK] Participant created");
    println!("   GUID: {:?}", participant.guid());
    println!("   Locator: {:?}\n", participant.local_locator());

    // Create reader
    let reader_id = participant.allocate_entity_id(false);
    let mut reader = MicroReader::new(participant.guid_prefix(), reader_id, "Temperature")?;

    println!("[OK] Reader created for topic 'Temperature'");
    println!("[<] Waiting for samples...\n");

    // Read loop
    let mut count = 0;
    while count < 10 {
        // Try to read (non-blocking with timeout simulation)
        match reader.read(participant.transport_mut()) {
            Ok(Some(sample)) => {
                // Decode
                let mut decoder = CdrDecoder::new(sample.payload);
                let temp = Temperature::decode(&mut decoder)?;

                count += 1;
                println!(
                    "[OK] Received sample #{}: sensor_id={}, temp={:.1} degC, seq={}, from={:?}",
                    count, temp.sensor_id, temp.value, sample.sequence_number, sample.writer_guid
                );
            }
            Ok(None) => {
                // No data, sleep briefly
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            Err(e) => {
                eprintln!("[X] Read error: {:?}", e);
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        }
    }

    println!("\n[OK] Received 10 samples successfully!");

    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: {} [pub|sub]", args[0]);
        eprintln!();
        eprintln!("Examples:");
        eprintln!("  {} pub    # Run publisher", args[0]);
        eprintln!("  {} sub    # Run subscriber", args[0]);
        std::process::exit(1);
    }

    match args[1].as_str() {
        "pub" => run_publisher(),
        "sub" => run_subscriber(),
        _ => {
            eprintln!("Invalid argument. Use 'pub' or 'sub'");
            std::process::exit(1);
        }
    }
}
