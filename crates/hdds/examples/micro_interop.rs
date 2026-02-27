// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! HDDS-std to HDDS-micro Interoperability Example
//!
//! Demonstrates sending from full hdds stack to hdds-micro (RTPS Lite).
//!
//! Usage:
//!   # Start micro subscriber on Pi Zero:
//!   /tmp/temperature_pubsub sub
//!
//!   # Run this publisher:
//!   cargo run --example micro_interop -- 192.168.0.29:17401

use std::env;
use std::net::UdpSocket;
use std::time::Duration;

// RTPS constants
#[allow(dead_code)]
const RTPS_HEADER_SIZE: usize = 20;
#[allow(dead_code)]
const DATA_SUBMSG_HEADER_SIZE: usize = 24;

/// Temperature sample - ALIGNED with hdds-micro format
/// hdds-micro expects: sensor_id (u32) + value (f32) + timestamp (u64)
#[repr(C)]
struct MicroTemperature {
    sensor_id: u32,
    value: f32,
    timestamp: u64,
}

fn main() -> std::io::Result<()> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("HDDS-std to HDDS-micro Interoperability Test");
        eprintln!();
        eprintln!("Usage: {} <micro_addr:port>", args[0]);
        eprintln!();
        eprintln!("Example: {} 192.168.0.29:17401", args[0]);
        std::process::exit(1);
    }

    let target = &args[1];

    println!("+==========================================================+");
    println!("|     HDDS-std -> HDDS-micro Interoperability Test          |");
    println!("+==========================================================+\n");

    // Create UDP socket
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    println!("Local:  {}", socket.local_addr()?);
    println!("Target: {} (hdds-micro)", target);
    println!();

    // Generate GUID prefix (based on local IP)
    let local_addr = socket.local_addr()?;
    let guid_prefix = generate_guid_prefix(&local_addr);
    println!("GUID Prefix: {:02x?}", guid_prefix);

    // Writer entity ID (0x000001c2 = user writer)
    let writer_entity_id: [u8; 4] = [0x00, 0x00, 0x01, 0xc2];

    println!("\n[*] Sending 10 Temperature samples to hdds-micro...\n");

    let mut sequence_number: i64 = 1;

    for i in 0..10 {
        let temp = MicroTemperature {
            sensor_id: 42,
            value: 20.0 + (i as f32 * 0.5),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        // Build RTPS packet
        let packet =
            build_rtps_data_packet(&guid_prefix, &writer_entity_id, sequence_number, &temp);

        // Send to micro subscriber
        socket.send_to(&packet, target)?;

        println!(
            "[OK] Sent sample #{}: sensor_id={}, temp={:.1} degC, seq={}",
            i + 1,
            temp.sensor_id,
            temp.value,
            sequence_number
        );

        sequence_number += 1;
        std::thread::sleep(Duration::from_secs(1));
    }

    println!("\n+==========================================================+");
    println!("| [OK] Sent 10 samples from hdds-std to hdds-micro           |");
    println!("+==========================================================+");

    Ok(())
}

/// Generate GUID prefix from socket address (matches hdds-micro format)
fn generate_guid_prefix(addr: &std::net::SocketAddr) -> [u8; 12] {
    let mut prefix = [0u8; 12];

    // Format: 00 00 ff ff IP[0] IP[1] IP[2] IP[3] PID[0..4]
    prefix[0] = 0x00;
    prefix[1] = 0x00;
    prefix[2] = 0xff;
    prefix[3] = 0xff;

    if let std::net::SocketAddr::V4(v4) = addr {
        let octets = v4.ip().octets();
        prefix[4] = octets[0];
        prefix[5] = octets[1];
        prefix[6] = octets[2];
        prefix[7] = octets[3];
    }

    // Use process ID for uniqueness
    let pid = std::process::id();
    prefix[8] = ((pid >> 24) & 0xff) as u8;
    prefix[9] = ((pid >> 16) & 0xff) as u8;
    prefix[10] = ((pid >> 8) & 0xff) as u8;
    prefix[11] = (pid & 0xff) as u8;

    prefix
}

/// Build RTPS DATA packet compatible with hdds-micro
fn build_rtps_data_packet(
    guid_prefix: &[u8; 12],
    writer_entity_id: &[u8; 4],
    sequence_number: i64,
    temp: &MicroTemperature,
) -> Vec<u8> {
    let mut packet = Vec::with_capacity(128);

    // === RTPS Header (20 bytes) ===
    // Protocol ID: "RTPS"
    packet.extend_from_slice(b"RTPS");

    // Protocol version: 2.5
    packet.push(2); // major
    packet.push(5); // minor

    // Vendor ID: HDDS (0x01AA)
    packet.push(0x01);
    packet.push(0xAA);

    // GUID Prefix (12 bytes)
    packet.extend_from_slice(guid_prefix);

    // === DATA Submessage ===
    // Submessage header (4 bytes)
    packet.push(0x15); // submessageId = DATA (0x15)
    packet.push(0x05); // flags: E=1 (little endian), D=1 (data present), Q=0

    // octetsToNextHeader (placeholder - will update later)
    let octets_pos = packet.len();
    packet.push(0x00);
    packet.push(0x00);

    // Extra flags (2 bytes)
    packet.push(0x00);
    packet.push(0x00);

    // Octets to inline QoS (2 bytes) - 0x0010 = 16 bytes to skip to data
    packet.push(0x10);
    packet.push(0x00);

    // Reader Entity ID (4 bytes) - UNKNOWN for multicast
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

    // Writer Entity ID (4 bytes)
    packet.extend_from_slice(writer_entity_id);

    // Sequence Number (8 bytes) - RTPS format: [high][low], each in little-endian
    packet.extend_from_slice(&((sequence_number >> 32) as i32).to_le_bytes()); // high first
    packet.extend_from_slice(&(sequence_number as i32).to_le_bytes()); // low second

    // === CDR Payload (NO encapsulation header for hdds-micro) ===
    // Temperature struct (CDR little-endian, raw)
    packet.extend_from_slice(&temp.sensor_id.to_le_bytes()); // u32
    packet.extend_from_slice(&temp.value.to_le_bytes()); // f32
    packet.extend_from_slice(&temp.timestamp.to_le_bytes()); // u64

    // Update octetsToNextHeader
    let data_section_len = packet.len() - octets_pos - 2; // exclude the 2-byte length field
    packet[octets_pos] = (data_section_len & 0xff) as u8;
    packet[octets_pos + 1] = ((data_section_len >> 8) & 0xff) as u8;

    packet
}
