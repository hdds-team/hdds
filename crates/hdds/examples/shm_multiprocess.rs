// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! SHM Multi-Process Test Example
//!
//! This example demonstrates inter-process communication using shared memory.
//!
//! # Usage
//!
//! Terminal 1 (Writer):
//! ```bash
//! cargo run --example shm_multiprocess -- write
//! ```
//!
//! Terminal 2 (Reader):
//! ```bash
//! cargo run --example shm_multiprocess -- read
//! ```
//!
//! The writer creates an SHM ring buffer and writes messages.
//! The reader attaches to the same ring buffer and reads messages.

#[cfg(target_os = "linux")]
use hdds::transport::shm::ShmSegment;
#[cfg(target_os = "linux")]
use hdds::transport::shm::{cleanup_domain_segments, ShmRingReader, ShmRingWriter};
#[cfg(target_os = "linux")]
use std::time::{Duration, Instant};

#[cfg(target_os = "linux")]
const DOMAIN_ID: u32 = 42;
#[cfg(target_os = "linux")]
const SEGMENT_NAME: &str = "/hdds_d42_wtest_multiprocess";
#[cfg(target_os = "linux")]
const RING_CAPACITY: usize = 256;

#[cfg(target_os = "linux")]
fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        println!("Usage: {} <write|read <nonce>|cleanup>", args[0]);
        println!();
        println!("  write        - Start writer process (prints the nonce to use)");
        println!("  read <nonce> - Start reader process with the writer's nonce");
        println!("  cleanup      - Clean up stale segments");
        println!();
        println!("The nonce authenticates the segment: the name alone proves nothing");
        println!("about who created it, since /dev/shm is world-writable and the name");
        println!("is derivable. In a real deployment the nonce travels in discovery;");
        println!("this example has no discovery, so you pass it by hand.");
        return;
    }

    match args[1].as_str() {
        "write" => run_writer(),
        "read" => {
            let Some(nonce) = args
                .get(2)
                .and_then(|a| u64::from_str_radix(a.trim_start_matches("0x"), 16).ok())
            else {
                println!("read needs the writer's nonce, as printed by the writer process.");
                println!("Usage: {} read <nonce>", args[0]);
                return;
            };
            run_reader(nonce);
        }
        "cleanup" => run_cleanup(),
        _ => {
            println!("Unknown command: {}", args[1]);
            println!("Use 'write', 'read', or 'cleanup'");
        }
    }
}

/// The writer GUID this demo uses on both sides. Fixed, because the two
/// processes have no discovery to learn it from; a real deployment gets it
/// from SEDP.
#[cfg(target_os = "linux")]
fn guid_for_demo() -> [u8; 16] {
    [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10,
    ]
}

#[cfg(target_os = "linux")]
fn run_writer() {
    println!("=== SHM Writer Process ===");
    println!("Creating SHM ring buffer: {}", SEGMENT_NAME);

    // Clean up any existing segment
    let _ = ShmSegment::unlink(SEGMENT_NAME);

    // Create writer
    let guid = guid_for_demo();
    let mut writer = ShmRingWriter::create(SEGMENT_NAME, RING_CAPACITY, &guid)
        .expect("Failed to create SHM writer");

    let nonce = hdds::transport::shm::local_nonce();
    println!("Writer ready. Press Ctrl+C to stop.");
    println!(
        "Start reader in another terminal: cargo run --example shm_multiprocess -- read {nonce:016x}"
    );
    println!("(that hex value is this writer's nonce; the reader refuses the segment without it)");
    println!();

    let mut seq = 0u64;
    loop {
        let msg = format!("Message #{} from PID {}", seq, std::process::id());

        match writer.push(msg.as_bytes()) {
            Ok(()) => {
                println!("[TX] {}", msg);
                seq += 1;
            }
            Err(e) => {
                println!("[TX] Error: {:?}", e);
            }
        }

        std::thread::sleep(Duration::from_millis(500));
    }
}

#[cfg(target_os = "linux")]
fn run_reader(expected_nonce: u64) {
    println!("=== SHM Reader Process ===");
    println!("Attaching to SHM ring buffer: {}", SEGMENT_NAME);

    // Wait for segment to exist
    let timeout = Instant::now();
    while !ShmSegment::exists(SEGMENT_NAME) {
        if timeout.elapsed() > Duration::from_secs(10) {
            println!("Timeout waiting for segment. Is the writer running?");
            return;
        }
        println!("Waiting for writer to create segment...");
        std::thread::sleep(Duration::from_millis(500));
    }

    // Attach reader
    let bucket = 0; // Simple bucket for demo
                    // The owner check: the writer's GUID plus the nonce it announced. Pass a
                    // wrong nonce here and the attach is refused, which is the whole point --
                    // any local process can create this segment name.
    let expected_owner = Some((guid_for_demo(), expected_nonce));
    let mut reader = ShmRingReader::attach(SEGMENT_NAME, RING_CAPACITY, bucket, expected_owner)
        .expect("Failed to attach SHM reader (wrong nonce, or not the writer's segment)");

    println!("Reader attached. Waiting for messages...");
    println!();

    let mut buf = [0u8; 4096];
    let mut total_received = 0u64;
    let start = Instant::now();

    loop {
        match reader.try_pop(&mut buf) {
            Some(len) => {
                let msg = String::from_utf8_lossy(&buf[..len]);
                println!("[RX] {}", msg);
                total_received += 1;
            }
            None => {
                // No data, wait a bit
                std::thread::sleep(Duration::from_millis(10));
            }
        }

        // Print stats every 5 seconds
        if start.elapsed().as_secs().is_multiple_of(5) && total_received > 0 {
            let rate = total_received as f64 / start.elapsed().as_secs_f64();
            println!(
                "--- Stats: {} messages, {:.1} msg/s ---",
                total_received, rate
            );
        }
    }
}

#[cfg(target_os = "linux")]
fn run_cleanup() {
    println!("=== SHM Cleanup ===");

    // Clean specific segment
    if ShmSegment::exists(SEGMENT_NAME) {
        println!("Removing segment: {}", SEGMENT_NAME);
        if let Err(e) = ShmSegment::unlink(SEGMENT_NAME) {
            println!("Failed to remove segment: {:?}", e);
        } else {
            println!("Segment removed successfully");
        }
    } else {
        println!("Segment {} does not exist", SEGMENT_NAME);
    }

    // Clean all domain segments
    let cleaned = cleanup_domain_segments(DOMAIN_ID);
    println!("Cleaned {} segments for domain {}", cleaned, DOMAIN_ID);

    // List remaining HDDS segments
    println!();
    println!("Remaining HDDS segments in /dev/shm:");
    if let Ok(entries) = std::fs::read_dir("/dev/shm") {
        let mut found = false;
        for entry in entries.flatten() {
            let name = entry.file_name();
            if let Some(name_str) = name.to_str() {
                if name_str.starts_with("hdds_") {
                    println!("  {}", name_str);
                    found = true;
                }
            }
        }
        if !found {
            println!("  (none)");
        }
    }
}

/// The SHM transport is Linux-only (see `hdds::transport::shm` stub for other
/// platforms). Keep the example buildable everywhere and honest about it.
#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!(
        "shm_multiprocess: the HDDS shared-memory transport is Linux-only; nothing to run on this platform"
    );
    std::process::exit(2);
}
