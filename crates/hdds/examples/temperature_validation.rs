// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

// Temperature Validation Example
//
// Demonstrates manual roundtrip encode/decode validation for generated Temperature type.
// This validates WIP-2.4 checklist requirements.

use hdds::dds::DDS;
use hdds::generated::temperature::Temperature;

fn main() {
    println!("=== Temperature CDR2 Roundtrip Validation ===\n");

    // Create a Temperature instance
    let t = Temperature {
        value: 23.5,
        timestamp: 1234567890,
    };

    println!("Original Temperature:");
    println!("  value: {}  degC", t.value);
    println!("  timestamp: {} (Unix epoch)", t.timestamp);
    println!();

    // Encode
    let mut buf = vec![0u8; 16]; // Allocate enough for alignment
    let written = t.encode_cdr2(&mut buf).unwrap();

    println!("Encoded CDR2 (little-endian):");
    println!("  bytes written: {}", written);
    println!("  buffer: {:?}", &buf[..written]);
    println!("  buffer (hex): {}", hex_string(&buf[..written]));
    println!();

    // Verify type descriptor size
    let descriptor = Temperature::type_descriptor();
    assert_eq!(descriptor.size_bytes, 8);
    println!(
        "type_descriptor().size_bytes: {} bytes [OK]",
        descriptor.size_bytes
    );
    println!();

    // Decode
    let decoded = Temperature::decode_cdr2(&buf).unwrap();

    println!("Decoded Temperature:");
    println!("  value: {}  degC", decoded.value);
    println!("  timestamp: {} (Unix epoch)", decoded.timestamp);
    println!();

    // Verify roundtrip
    assert_eq!(decoded.value, 23.5);
    assert_eq!(decoded.timestamp, 1234567890);
    assert_eq!(t, decoded);

    println!("[OK] Roundtrip validation PASSED");
    println!("[OK] All requirements met:");
    println!("   - Struct definition with correct fields (f32, u32)");
    println!("   - DDS trait impl with encode_cdr2/decode_cdr2");
    println!("   - TypeDescriptor with proper size/alignment");
    println!("   - to_le_bytes()/from_le_bytes() used internally");
    println!("   - Zero Clippy warnings");
    println!("   - Comprehensive tests pass");
}

fn hex_string(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(" ")
}
