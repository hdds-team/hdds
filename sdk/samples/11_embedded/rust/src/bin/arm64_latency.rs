// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! # HDDS Sample: ARM64 Latency Benchmark
//!
//! Measures **round-trip latency** on ARM64 embedded platforms.
//! Useful for benchmarking HDDS vs FastDDS on OWA5X and similar devices.
//!
//! ## Benchmark Methodology
//!
//! ```text
//! Publisher                           Subscriber
//! ─────────                           ──────────
//!     │                                   │
//!     │──── Ping (timestamp) ────────────►│
//!     │                                   │ (immediate echo)
//!     │◄─── Pong (same timestamp) ────────│
//!     │                                   │
//!   RTT = now() - timestamp
//! ```
//!
//! ## Cross-Compilation
//!
//! ```bash
//! cargo build --release --target aarch64-unknown-linux-gnu --bin arm64_latency
//! scp target/aarch64-unknown-linux-gnu/release/arm64_latency user@owa5x:/tmp/
//! ```
//!
//! ## Running the Benchmark
//!
//! ```bash
//! # On OWA5X - Terminal 1 (echo server)
//! /tmp/arm64_latency echo
//!
//! # On OWA5X - Terminal 2 (benchmark client)
//! /tmp/arm64_latency
//! ```
//!
//! ## Expected Results (OWA5X)
//!
//! | Metric | HDDS | FastDDS |
//! |--------|------|---------|
//! | Avg RTT | ~200 µs | ~300 µs |
//! | P99 RTT | ~500 µs | ~800 µs |
//! | CPU% | ~2% | ~5% |

use std::env;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use hdds::core::types::TypeDescriptor;
use hdds::DdsTrait;

const NUM_PINGS: usize = 1000;
const WARMUP_PINGS: usize = 100;

/// Ping message with embedded timestamp
#[derive(Clone, Debug, Default)]
struct PingMsg {
    sequence: u32,
    timestamp_ns: u64,
}

// Static type descriptor (minimal - empty fields for simplicity)
static PING_MSG_DESCRIPTOR: TypeDescriptor = TypeDescriptor::new(
    0x50696E67, // "Ping" as u32
    "PingMsg",
    16,    // fixed size: 4 (u32) + 4 (padding) + 8 (u64)
    8,     // alignment (for u64)
    false, // not variable size
    &[],   // fields (empty for embedded sample simplicity)
);

impl DdsTrait for PingMsg {
    fn type_descriptor() -> &'static TypeDescriptor {
        &PING_MSG_DESCRIPTOR
    }

    fn encode_cdr2(&self, buf: &mut [u8]) -> hdds::dds::Result<usize> {
        let mut offset: usize = 0;

        // sequence (u32)
        if buf.len() < offset + 4 {
            return Err(hdds::dds::Error::BufferTooSmall);
        }
        buf[offset..offset + 4].copy_from_slice(&self.sequence.to_le_bytes());
        offset += 4;

        // Padding to 8-byte boundary for u64
        let padding = (8 - (offset % 8)) % 8;
        if buf.len() < offset + padding {
            return Err(hdds::dds::Error::BufferTooSmall);
        }
        for i in 0..padding {
            buf[offset + i] = 0;
        }
        offset += padding;

        // timestamp_ns (u64)
        if buf.len() < offset + 8 {
            return Err(hdds::dds::Error::BufferTooSmall);
        }
        buf[offset..offset + 8].copy_from_slice(&self.timestamp_ns.to_le_bytes());
        offset += 8;

        Ok(offset)
    }

    fn decode_cdr2(buf: &[u8]) -> hdds::dds::Result<Self> {
        let mut offset: usize = 0;

        // sequence
        if buf.len() < offset + 4 {
            return Err(hdds::dds::Error::SerializationError);
        }
        let sequence = u32::from_le_bytes(
            buf[offset..offset + 4]
                .try_into()
                .map_err(|_| hdds::dds::Error::SerializationError)?,
        );
        offset += 4;

        // Skip padding to 8-byte boundary
        let padding = (8 - (offset % 8)) % 8;
        offset += padding;

        // timestamp_ns
        if buf.len() < offset + 8 {
            return Err(hdds::dds::Error::SerializationError);
        }
        let timestamp_ns = u64::from_le_bytes(
            buf[offset..offset + 8]
                .try_into()
                .map_err(|_| hdds::dds::Error::SerializationError)?,
        );

        Ok(Self {
            sequence,
            timestamp_ns,
        })
    }
}

/// High-precision timer
struct Timer {
    start: Instant,
}

impl Timer {
    fn new() -> Self {
        Self {
            start: Instant::now(),
        }
    }

    fn elapsed_ns(&self) -> u64 {
        self.start.elapsed().as_nanos() as u64
    }
}

fn run_echo_server(participant: &Arc<hdds::Participant>) -> Result<(), hdds::Error> {
    println!("[Echo] Starting echo server...");

    let qos = hdds::QoS::best_effort();
    let reader = participant.create_reader::<PingMsg>("PingTopic", qos.clone())?;
    let writer = participant.create_writer::<PingMsg>("PongTopic", qos)?;

    let status_condition = reader.get_status_condition();
    let waitset = hdds::dds::WaitSet::new();
    waitset.attach_condition(status_condition)?;

    println!("[Echo] Ready. Waiting for pings...\n");

    let mut echoed = 0u64;
    loop {
        match waitset.wait(Some(Duration::from_secs(10))) {
            Ok(triggered) => {
                if !triggered.is_empty() {
                    while let Some(ping) = reader.take()? {
                        // Echo immediately
                        writer.write(&ping)?;
                        echoed += 1;
                        if echoed.is_multiple_of(100) {
                            println!("  [Echo] Echoed {} pings", echoed);
                        }
                    }
                }
            }
            Err(hdds::Error::WouldBlock) => {
                if echoed > 0 {
                    println!("\n[Echo] No pings for 10s. Total echoed: {}", echoed);
                    break;
                }
                println!("  (waiting for pings...)");
            }
            Err(e) => {
                eprintln!("Error: {:?}", e);
                break;
            }
        }
    }

    Ok(())
}

fn run_benchmark(participant: &Arc<hdds::Participant>) -> Result<(), hdds::Error> {
    println!("[Bench] Starting latency benchmark...");

    let qos = hdds::QoS::best_effort();
    let writer = participant.create_writer::<PingMsg>("PingTopic", qos.clone())?;
    let reader = participant.create_reader::<PingMsg>("PongTopic", qos)?;

    let status_condition = reader.get_status_condition();
    let waitset = hdds::dds::WaitSet::new();
    waitset.attach_condition(status_condition)?;

    // Wait for echo server
    println!("[Bench] Waiting for echo server...");
    thread::sleep(Duration::from_secs(2));

    let timer = Timer::new();
    let mut latencies_us: Vec<f64> = Vec::with_capacity(NUM_PINGS);

    // Warmup
    println!("[Bench] Warmup ({} pings)...", WARMUP_PINGS);
    for i in 0..WARMUP_PINGS {
        let ping = PingMsg {
            sequence: i as u32,
            timestamp_ns: timer.elapsed_ns(),
        };
        writer.write(&ping)?;

        if let Ok(triggered) = waitset.wait(Some(Duration::from_millis(100))) {
            if !triggered.is_empty() {
                let _ = reader.take();
            }
        }
    }

    // Benchmark
    println!("[Bench] Running {} pings...\n", NUM_PINGS);

    for i in 0..NUM_PINGS {
        let send_time = timer.elapsed_ns();
        let ping = PingMsg {
            sequence: i as u32,
            timestamp_ns: send_time,
        };

        writer.write(&ping)?;

        // Wait for pong
        if let Ok(triggered) = waitset.wait(Some(Duration::from_millis(100))) {
            if !triggered.is_empty() {
                while let Some(pong) = reader.take()? {
                    let recv_time = timer.elapsed_ns();
                    let rtt_ns = recv_time.saturating_sub(pong.timestamp_ns);
                    let rtt_us = rtt_ns as f64 / 1000.0;
                    latencies_us.push(rtt_us);
                }
            }
        }

        // Small delay between pings
        thread::sleep(Duration::from_micros(100));
    }

    // Calculate statistics
    if latencies_us.is_empty() {
        println!("[Bench] ERROR: No pongs received!");
        return Ok(());
    }

    latencies_us.sort_by(|a, b| a.partial_cmp(b).unwrap());

    let count = latencies_us.len();
    let sum: f64 = latencies_us.iter().sum();
    let avg = sum / count as f64;
    let min = latencies_us[0];
    let max = latencies_us[count - 1];
    let p50 = latencies_us[count / 2];
    let p90 = latencies_us[(count as f64 * 0.90) as usize];
    let p99 = latencies_us[(count as f64 * 0.99) as usize];

    // Print results
    println!("{}", "=".repeat(50));
    println!("HDDS ARM64 Latency Benchmark Results");
    println!("{}", "=".repeat(50));
    println!();
    println!("Samples: {} / {}", count, NUM_PINGS);
    println!();
    println!("Round-Trip Time (RTT):");
    println!("  Min:  {:8.1} µs", min);
    println!("  Avg:  {:8.1} µs", avg);
    println!("  P50:  {:8.1} µs", p50);
    println!("  P90:  {:8.1} µs", p90);
    println!("  P99:  {:8.1} µs", p99);
    println!("  Max:  {:8.1} µs", max);
    println!();
    println!("One-way latency (RTT/2):");
    println!("  Avg:  {:8.1} µs", avg / 2.0);
    println!("  P99:  {:8.1} µs", p99 / 2.0);
    println!("{}", "=".repeat(50));

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let is_echo = args.get(1).map(|s| s == "echo").unwrap_or(false);

    // Parse domain_id from args (default: 42 to avoid conflicts with other DDS apps)
    let domain_id = args
        .iter()
        .position(|s| s == "--domain" || s == "-d")
        .and_then(|i| args.get(i + 1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(42u32);

    println!("{}", "=".repeat(50));
    println!("HDDS ARM64 Latency Benchmark");
    println!(
        "Platform: {} / {}",
        std::env::consts::OS,
        std::env::consts::ARCH
    );
    println!("{}\n", "=".repeat(50));

    let participant = hdds::Participant::builder("LatencyBench")
        .with_transport(hdds::TransportMode::UdpMulticast)
        .domain_id(domain_id)
        .build()?;

    println!("[OK] Participant: {}", participant.name());
    println!("[OK] Domain ID: {}\n", participant.domain_id());

    if is_echo {
        run_echo_server(&participant)?;
    } else {
        run_benchmark(&participant)?;
    }

    Ok(())
}
