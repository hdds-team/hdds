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

use hdds::telemetry::export::decode_frame;
use hdds::telemetry::metrics::{
    DType, Frame, TAG_BYTES_SENT, TAG_LATENCY_P50, TAG_LATENCY_P99, TAG_LATENCY_P999,
    TAG_MERGE_FULL_COUNT, TAG_MESSAGES_DROPPED, TAG_MESSAGES_RECEIVED, TAG_MESSAGES_SENT,
    TAG_WOULD_BLOCK_COUNT,
};
use std::io::Read;
use std::net::TcpStream;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    let addr = if args.len() > 1 {
        &args[1]
    } else {
        "127.0.0.1:4242"
    };

    println!("hddsctl: HDDS CLI Metrics Viewer");
    println!("Connecting to telemetry server at {}...", addr);
    println!();

    match TcpStream::connect(addr) {
        Ok(mut stream) => {
            println!("[OK] Connected! Reading metrics...");
            println!("---");
            println!();

            let mut buf = vec![0u8; 4096];

            loop {
                match stream.read(&mut buf) {
                    Ok(0) => {
                        println!("Connection closed by server");
                        break;
                    }
                    Ok(n) => {
                        // Try to decode frame
                        match decode_frame(&buf[..n]) {
                            Ok(frame) => {
                                display_frame(&frame);
                            }
                            Err(e) => {
                                eprintln!("Frame decode error: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("Read error: {}", e);
                        break;
                    }
                }
            }
        }
        Err(e) => {
            eprintln!("[FAIL] Connection failed: {}", e);
            eprintln!();
            eprintln!("Make sure HDDS participant is running with telemetry export enabled.");
            eprintln!("Default telemetry port: 4242");
            std::process::exit(1);
        }
    }
}

/// Display telemetry frame in human-readable format
fn display_frame(frame: &Frame) {
    // Print timestamp if available
    if frame.ts_ns > 0 {
        println!("Timestamp: {} ns", frame.ts_ns);
    }

    // Display all fields
    for field in &frame.fields {
        let (name, unit) = tag_info(field.tag);

        match field.dtype {
            DType::U64 | DType::U32 => {
                if field.tag >= 20 && field.tag <= 29 {
                    // Latency metrics (format as nanoseconds)
                    println!("{:20} = {:>12} {}", name, format_ns(field.value_u64), unit);
                } else {
                    // Counters (format with thousands separators)
                    println!(
                        "{:20} = {:>12} {}",
                        name,
                        format_count(field.value_u64),
                        unit
                    );
                }
            }
            DType::I64 => {
                let value = field.value_u64 as i64;
                println!("{:20} = {:>12} {}", name, value, unit);
            }
            DType::F64 => {
                let value = f64::from_bits(field.value_u64);
                println!("{:20} = {:>12.2} {}", name, value, unit);
            }
            DType::Bytes => {
                println!("{:20} = {:>12} {}", name, field.value_u64, unit);
            }
        }
    }

    println!("---");
    println!();
}

/// Get human-readable name and unit for a metric tag
// @audit-ok: Simple pattern matching (cyclo 11, cogni 1) - tag ID to (name, unit) lookup table
fn tag_info(tag: u16) -> (&'static str, &'static str) {
    match tag {
        TAG_MESSAGES_SENT => ("Messages Sent", "msgs"),
        TAG_MESSAGES_RECEIVED => ("Messages Received", "msgs"),
        TAG_MESSAGES_DROPPED => ("Messages Dropped", "msgs"),
        TAG_BYTES_SENT => ("Bytes Sent", "bytes"),
        TAG_LATENCY_P50 => ("Latency p50", ""),
        TAG_LATENCY_P99 => ("Latency p99", ""),
        TAG_LATENCY_P999 => ("Latency p999", ""),
        TAG_MERGE_FULL_COUNT => ("Merge Full Count", "events"),
        TAG_WOULD_BLOCK_COUNT => ("Would Block Count", "events"),
        _ => ("Unknown", ""),
    }
}

/// Format count with thousands separators
fn format_count(count: u64) -> String {
    let s = count.to_string();
    let mut result = String::new();

    for (i, ch) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.push(',');
        }
        result.push(ch);
    }

    result.chars().rev().collect()
}

/// Format nanoseconds with unit suffix
fn format_ns(ns: u64) -> String {
    if ns < 1_000 {
        format!("{} ns", ns)
    } else if ns < 1_000_000 {
        format!("{:.1} us", ns as f64 / 1_000.0)
    } else if ns < 1_000_000_000 {
        format!("{:.1} ms", ns as f64 / 1_000_000.0)
    } else {
        format!("{:.1} s", ns as f64 / 1_000_000_000.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_count() {
        assert_eq!(format_count(0), "0");
        assert_eq!(format_count(123), "123");
        assert_eq!(format_count(1234), "1,234");
        assert_eq!(format_count(1234567), "1,234,567");
        assert_eq!(format_count(1000000), "1,000,000");
    }

    #[test]
    fn test_format_ns() {
        assert_eq!(format_ns(0), "0 ns");
        assert_eq!(format_ns(500), "500 ns");
        assert_eq!(format_ns(1_000), "1.0 us");
        assert_eq!(format_ns(1_500), "1.5 us");
        assert_eq!(format_ns(1_000_000), "1.0 ms");
        assert_eq!(format_ns(1_500_000), "1.5 ms");
        assert_eq!(format_ns(1_000_000_000), "1.0 s");
        assert_eq!(format_ns(2_500_000_000), "2.5 s");
    }

    #[test]
    fn test_tag_info() {
        let (name, unit) = tag_info(TAG_MESSAGES_SENT);
        assert_eq!(name, "Messages Sent");
        assert_eq!(unit, "msgs");

        let (name, unit) = tag_info(TAG_LATENCY_P50);
        assert_eq!(name, "Latency p50");
        assert_eq!(unit, "");
    }
}
