// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! # HDDS Sample: ARM64 Hello World
//!
//! Minimal HDDS sample optimized for **embedded ARM64 platforms** like:
//! - Owasys OWA5X
//! - Raspberry Pi 4/5
//! - NVIDIA Jetson
//! - BeagleBone AI-64
//!
//! ## Cross-Compilation
//!
//! ```bash
//! # Install target
//! rustup target add aarch64-unknown-linux-gnu
//!
//! # Install cross-compiler (Ubuntu/Debian)
//! sudo apt install gcc-aarch64-linux-gnu
//!
//! # Build
//! cargo build --release --target aarch64-unknown-linux-gnu --bin arm64_hello
//!
//! # Copy to device
//! scp target/aarch64-unknown-linux-gnu/release/arm64_hello user@device:/tmp/
//! ```
//!
//! ## Running on OWA5X
//!
//! ```bash
//! # On the OWA5X device:
//! chmod +x /tmp/arm64_hello
//!
//! # Terminal 1 - Subscriber
//! /tmp/arm64_hello
//!
//! # Terminal 2 - Publisher
//! /tmp/arm64_hello pub
//! ```
//!
//! ## Memory Footprint
//!
//! HDDS is designed to be lightweight:
//! - Static binary: ~2-4 MB (release, stripped)
//! - Runtime heap: ~1-2 MB typical
//! - No external dependencies (pure Rust)

use std::env;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use hdds::core::types::TypeDescriptor;
use hdds::DdsTrait;

/// Simple message for testing - implements DDS trait for typed pub/sub
#[derive(Clone, Debug, Default)]
struct HelloMsg {
    counter: u32,
    message: String,
}

// Static type descriptor (minimal - empty fields for simplicity)
static HELLO_MSG_DESCRIPTOR: TypeDescriptor = TypeDescriptor::new(
    0x48656C6C, // "Hell" as u32
    "HelloMsg",
    0,    // variable size
    4,    // alignment
    true, // is_variable_size (contains String)
    &[],  // fields (empty for embedded sample simplicity)
);

// Implement DDS trait
impl DdsTrait for HelloMsg {
    fn type_descriptor() -> &'static TypeDescriptor {
        &HELLO_MSG_DESCRIPTOR
    }

    fn encode_cdr2(&self, buf: &mut [u8]) -> hdds::dds::Result<usize> {
        let mut offset: usize = 0;

        // counter (u32) - already aligned
        if buf.len() < offset + 4 {
            return Err(hdds::dds::Error::BufferTooSmall);
        }
        buf[offset..offset + 4].copy_from_slice(&self.counter.to_le_bytes());
        offset += 4;

        // message (string: length + bytes + null terminator)
        let bytes = self.message.as_bytes();
        let str_len = bytes.len() as u32 + 1; // +1 for null terminator

        if buf.len() < offset + 4 {
            return Err(hdds::dds::Error::BufferTooSmall);
        }
        buf[offset..offset + 4].copy_from_slice(&str_len.to_le_bytes());
        offset += 4;

        if buf.len() < offset + bytes.len() + 1 {
            return Err(hdds::dds::Error::BufferTooSmall);
        }
        buf[offset..offset + bytes.len()].copy_from_slice(bytes);
        offset += bytes.len();
        buf[offset] = 0; // null terminator
        offset += 1;

        // Padding to 4-byte boundary
        let padding = (4 - (offset % 4)) % 4;
        if buf.len() < offset + padding {
            return Err(hdds::dds::Error::BufferTooSmall);
        }
        for i in 0..padding {
            buf[offset + i] = 0;
        }
        offset += padding;

        Ok(offset)
    }

    fn decode_cdr2(buf: &[u8]) -> hdds::dds::Result<Self> {
        let mut offset: usize = 0;

        // counter
        if buf.len() < offset + 4 {
            return Err(hdds::dds::Error::SerializationError);
        }
        let counter = u32::from_le_bytes(
            buf[offset..offset + 4]
                .try_into()
                .map_err(|_| hdds::dds::Error::SerializationError)?,
        );
        offset += 4;

        // message length
        if buf.len() < offset + 4 {
            return Err(hdds::dds::Error::SerializationError);
        }
        let len = u32::from_le_bytes(
            buf[offset..offset + 4]
                .try_into()
                .map_err(|_| hdds::dds::Error::SerializationError)?,
        ) as usize;
        offset += 4;

        // message bytes (including null terminator)
        if buf.len() < offset + len {
            return Err(hdds::dds::Error::SerializationError);
        }
        let msg_bytes = &buf[offset..offset + len];
        // Remove null terminator
        let message = if !msg_bytes.is_empty() && msg_bytes[msg_bytes.len() - 1] == 0 {
            String::from_utf8_lossy(&msg_bytes[..msg_bytes.len() - 1]).to_string()
        } else {
            String::from_utf8_lossy(msg_bytes).to_string()
        };

        Ok(Self { counter, message })
    }
}

fn run_publisher(participant: &Arc<hdds::Participant>) -> Result<(), hdds::Error> {
    println!("[ARM64] Creating publisher...");

    let qos = hdds::QoS::reliable();
    let writer = participant.create_writer::<HelloMsg>("HelloTopic", qos)?;

    println!("[ARM64] Publishing 20 messages...\n");

    for i in 0..20 {
        let msg = HelloMsg {
            counter: i,
            message: format!("Hello from ARM64 #{}", i),
        };

        writer.write(&msg)?;
        println!("  [PUB] counter={}, msg=\"{}\"", msg.counter, msg.message);
        thread::sleep(Duration::from_millis(500));
    }

    println!("\n[ARM64] Publisher done. Sent 20 messages.");
    Ok(())
}

fn run_subscriber(participant: &Arc<hdds::Participant>) -> Result<(), hdds::Error> {
    println!("[ARM64] Creating subscriber...");

    let qos = hdds::QoS::reliable();
    let reader = participant.create_reader::<HelloMsg>("HelloTopic", qos)?;

    let status_condition = reader.get_status_condition();
    let waitset = hdds::dds::WaitSet::new();
    waitset.attach_condition(status_condition)?;

    println!("[ARM64] Waiting for messages...\n");

    let mut received = 0;
    while received < 20 {
        match waitset.wait(Some(Duration::from_secs(5))) {
            Ok(triggered) => {
                if !triggered.is_empty() {
                    while let Some(msg) = reader.take()? {
                        println!("  [SUB] counter={}, msg=\"{}\"", msg.counter, msg.message);
                        received += 1;
                    }
                }
            }
            Err(hdds::Error::WouldBlock) => {
                println!("  (waiting for publisher...)");
            }
            Err(e) => {
                eprintln!("Error: {:?}", e);
                break;
            }
        }
    }

    println!("\n[ARM64] Subscriber done. Received {} messages.", received);
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let is_publisher = args.get(1).map(|s| s == "pub").unwrap_or(false);

    // Parse domain_id from args (default: 42 to avoid conflicts with other DDS apps)
    let domain_id = args
        .iter()
        .position(|s| s == "--domain" || s == "-d")
        .and_then(|i| args.get(i + 1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(42u32);

    println!("{}", "=".repeat(50));
    println!("HDDS ARM64 Hello World");
    println!(
        "Platform: {} / {}",
        std::env::consts::OS,
        std::env::consts::ARCH
    );
    println!("{}\n", "=".repeat(50));

    // Create participant with UDP multicast
    let participant = hdds::Participant::builder("ARM64Demo")
        .with_transport(hdds::TransportMode::UdpMulticast)
        .domain_id(domain_id)
        .build()?;

    println!("[OK] Participant created: {}", participant.name());
    println!("[OK] Domain ID: {}\n", participant.domain_id());

    if is_publisher {
        run_publisher(&participant)?;
    } else {
        run_subscriber(&participant)?;
    }

    println!("\n=== ARM64 Sample Complete ===");
    Ok(())
}
