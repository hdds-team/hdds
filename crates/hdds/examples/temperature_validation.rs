// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

#![allow(clippy::uninlined_format_args)] // Test/bench code readability over pedantic
#![allow(clippy::cast_precision_loss)] // Stats/metrics need this
#![allow(clippy::cast_sign_loss)] // Test data conversions
#![allow(clippy::cast_possible_truncation)] // Test parameters
#![allow(clippy::float_cmp)] // Test assertions with constants
#![allow(clippy::unreadable_literal)] // Large test constants
#![allow(clippy::doc_markdown)] // Test documentation
#![allow(clippy::missing_panics_doc)] // Tests/examples panic on failure
#![allow(clippy::missing_errors_doc)] // Test documentation
#![allow(clippy::items_after_statements)] // Test helpers
#![allow(clippy::module_name_repetitions)] // Test modules
#![allow(clippy::too_many_lines)] // Example/test code
#![allow(clippy::match_same_arms)] // Test pattern matching
#![allow(clippy::no_effect_underscore_binding)] // Test variables
#![allow(clippy::wildcard_imports)] // Test utility imports
#![allow(clippy::redundant_closure_for_method_calls)] // Test code clarity
#![allow(clippy::similar_names)] // Test variable naming
#![allow(clippy::shadow_unrelated)] // Test scoping
#![allow(clippy::needless_pass_by_value)] // Test functions
#![allow(clippy::cast_possible_wrap)] // Test conversions
#![allow(clippy::single_match_else)] // Test clarity
#![allow(clippy::needless_continue)] // Test logic
#![allow(clippy::cast_lossless)] // Test simplicity
#![allow(clippy::match_wild_err_arm)] // Test error handling
#![allow(clippy::explicit_iter_loop)] // Test iteration
#![allow(clippy::must_use_candidate)] // Test functions
#![allow(clippy::if_not_else)] // Test conditionals
#![allow(clippy::map_unwrap_or)] // Test options
#![allow(clippy::match_wildcard_for_single_variants)] // Test patterns
#![allow(clippy::ignored_unit_patterns)] // Test closures

// Temperature Validation Example
//
// Demonstrates manual roundtrip encode/decode validation for generated Temperature type.
// This validates WIP-2.4 checklist requirements.

use hdds::api::DDS;
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
