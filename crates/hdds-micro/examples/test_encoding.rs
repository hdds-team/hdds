// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

// Test RTPS encoding to verify correct bytes
// Run with: cargo run --example test_encoding

use hdds_micro::cdr::CdrEncoder;
use hdds_micro::core::{MicroParticipant, MicroWriter};
use hdds_micro::rtps::{EntityId, Locator};
use hdds_micro::transport::NullTransport;

fn main() {
    println!("=== HDDS Micro Encoding Test ===\n");

    // Create a null transport (captures sent data)
    let transport = NullTransport::default();

    // Create participant
    let mut participant = MicroParticipant::new(0, transport).unwrap();
    let guid_prefix = participant.guid_prefix();
    let entity_id = participant.allocate_entity_id(true);

    println!("GUID Prefix: {:02X?}", guid_prefix.as_bytes());
    println!("Entity ID: {:02X?}", entity_id.as_bytes());

    // Create writer (for demonstration, not used in this encoding test)
    let dest = Locator::udpv4([239, 255, 0, 1], 7400);
    let _writer = MicroWriter::new(guid_prefix, entity_id, "test/topic", dest).unwrap();

    // Encode temperature-like payload: sensor_id(4) + value(4) + timestamp(8)
    let mut buf = [0u8; 32];
    let mut encoder = CdrEncoder::new(&mut buf);
    encoder.encode_u32(0x42).unwrap(); // sensor_id
    encoder.encode_f32(25.5).unwrap(); // temperature
    encoder.encode_u64(12345678).unwrap(); // timestamp
    let payload = encoder.finish();

    println!("Payload ({} bytes): {:02X?}", payload.len(), payload);

    // Build the packet manually to inspect bytes
    let mut packet = [0u8; 256];

    // RTPS Header (20 bytes)
    let header = hdds_micro::rtps::RtpsHeader::new(
        hdds_micro::rtps::ProtocolVersion::RTPS_2_5,
        hdds_micro::rtps::VendorId::HDDS,
        guid_prefix,
    );
    let header_len = header.encode(&mut packet).unwrap();

    // DATA submessage
    let data = hdds_micro::rtps::submessages::Data::new(
        EntityId::UNKNOWN,
        entity_id,
        hdds_micro::rtps::SequenceNumber::new(1),
    );
    let data_len = data.encode_header(&mut packet[header_len..]).unwrap();

    // Copy payload
    let payload_offset = header_len + data_len;
    packet[payload_offset..payload_offset + payload.len()].copy_from_slice(payload);

    let total_len = payload_offset + payload.len();

    // Update octets_to_next
    let octets_to_next = (20 + payload.len()) as u16;
    packet[header_len + 2] = (octets_to_next & 0xff) as u8;
    packet[header_len + 3] = ((octets_to_next >> 8) & 0xff) as u8;

    println!("\n=== Complete RTPS Packet ({} bytes) ===", total_len);

    // Print in rows of 16
    for i in (0..total_len).step_by(16) {
        print!("{:04X}  ", i);
        for &byte in &packet[i..std::cmp::min(i + 16, total_len)] {
            print!("{:02X} ", byte);
        }
        println!();
    }

    println!("\n=== Key Bytes Analysis ===");
    println!(
        "Bytes 0-3 (RTPS magic): {:02X} {:02X} {:02X} {:02X} = '{}'",
        packet[0],
        packet[1],
        packet[2],
        packet[3],
        std::str::from_utf8(&packet[0..4]).unwrap_or("???")
    );
    println!("Bytes 4-5 (version): {:02X} {:02X}", packet[4], packet[5]);
    println!("Bytes 6-7 (vendor): {:02X} {:02X}", packet[6], packet[7]);
    println!("Bytes 8-19 (GUID prefix): {:02X?}", &packet[8..20]);
    println!(
        "Byte 20 (submsg kind): {:02X} (expected: 0x15 for DATA)",
        packet[20]
    );
    println!(
        "Byte 21 (submsg flags): {:02X} (expected: 0x05)",
        packet[21]
    );
    println!(
        "Bytes 22-23 (octetsToNext): {:02X} {:02X} = {} bytes",
        packet[22],
        packet[23],
        u16::from_le_bytes([packet[22], packet[23]])
    );

    // Verify
    if packet[20] == 0x15 {
        println!("\n✓ Submessage kind is correct (0x15)");
    } else {
        println!(
            "\n✗ ERROR: Submessage kind is wrong: 0x{:02X} instead of 0x15",
            packet[20]
        );
    }
}
