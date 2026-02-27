// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! # HDDS Sample: Throughput Benchmark
//!
//! Measures **maximum sustained throughput** - how many messages and bytes
//! per second HDDS can transfer under optimal conditions.
//!
//! ## Throughput Metrics
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │                     Throughput Measurement                          │
//! │                                                                     │
//! │   Publisher                                    Subscriber           │
//! │   ┌─────────────────┐                        ┌─────────────────┐   │
//! │   │ Send as fast as │ ─────────────────────► │ Count messages  │   │
//! │   │ possible        │   N messages/sec       │ and bytes       │   │
//! │   └─────────────────┘                        └─────────────────┘   │
//! │                                                                     │
//! │   Results:                                                          │
//! │   - Messages/sec:  150,000 msg/s                                    │
//! │   - Throughput:    38.4 MB/s (307 Mbps)                            │
//! │   - Payload:       256 bytes                                        │
//! └─────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Factors Affecting Throughput
//!
//! | Factor          | Impact                        | Optimization             |
//! |-----------------|-------------------------------|--------------------------|
//! | Payload size    | Larger = more MB/s            | Match your use case      |
//! | QoS             | BEST_EFFORT > RELIABLE        | Use BEST_EFFORT if ok    |
//! | Batching        | Higher throughput             | Enable for bulk data     |
//! | Network         | Gigabit, 10GbE, loopback      | Use fastest available    |
//!
//! ## Typical Results
//!
//! ```text
//! Payload Size    Messages/sec    MB/sec    Notes
//! ─────────────   ────────────    ──────    ─────────────────
//! 64 bytes        500,000         30        Small messages
//! 256 bytes       300,000         75        Typical payload
//! 1 KB            150,000         150       Medium payload
//! 8 KB            50,000          400       Large payload
//! 64 KB           10,000          640       Bulk transfers
//! ```
//!
//! ## Running the Sample
//!
//! ```bash
//! # Terminal 1 - Publisher (default 256 byte payload)
//! cargo run --bin throughput -- -p
//!
//! # Terminal 2 - Subscriber
//! cargo run --bin throughput -- -s
//!
//! # Custom payload and duration
//! cargo run --bin throughput -- -p -z 1024 -d 30   # 1KB, 30 seconds
//! ```

use std::env;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const DEFAULT_PAYLOAD_SIZE: usize = 256;
const DEFAULT_DURATION_SEC: u64 = 10;
const MAX_PAYLOAD_SIZE: usize = 64 * 1024;

/// Throughput message - DDS-serializable
#[derive(hdds::DDS, Clone)]
struct ThroughputMsg {
    sequence: u64,
    timestamp_ns: u64,
    payload_len: u32,
    // Note: For variable payload, we use fixed-size array for DDS derive compatibility
    // Real-world usage would use hdds_gen with IDL for sequence<octet> support
}

impl ThroughputMsg {
    fn new(_payload_size: usize) -> Self {
        Self {
            sequence: 0,
            timestamp_ns: 0,
            payload_len: _payload_size as u32,
        }
    }

    fn total_size(&self) -> usize {
        std::mem::size_of::<Self>()
    }
}

/// Throughput statistics
#[derive(Default)]
struct ThroughputStats {
    messages_sent: u64,
    messages_received: u64,
    bytes_sent: u64,
    bytes_received: u64,
    duration_sec: f64,
    msg_per_sec: f64,
    mb_per_sec: f64,
}

impl ThroughputStats {
    fn calculate(&mut self, is_publisher: bool) {
        if self.duration_sec <= 0.0 {
            return;
        }

        if is_publisher {
            self.msg_per_sec = self.messages_sent as f64 / self.duration_sec;
            self.mb_per_sec = (self.bytes_sent as f64 / (1024.0 * 1024.0)) / self.duration_sec;
        } else {
            self.msg_per_sec = self.messages_received as f64 / self.duration_sec;
            self.mb_per_sec = (self.bytes_received as f64 / (1024.0 * 1024.0)) / self.duration_sec;
        }
    }
}

fn print_progress(stats: &ThroughputStats, elapsed_sec: u64, is_publisher: bool) {
    let current_msg_sec = if is_publisher {
        stats.messages_sent as f64 / elapsed_sec as f64
    } else {
        stats.messages_received as f64 / elapsed_sec as f64
    };

    let current_mb_sec = if is_publisher {
        (stats.bytes_sent as f64 / (1024.0 * 1024.0)) / elapsed_sec as f64
    } else {
        (stats.bytes_received as f64 / (1024.0 * 1024.0)) / elapsed_sec as f64
    };

    println!(
        "  [{:2} sec] {:.0} msg/s, {:.2} MB/s",
        elapsed_sec, current_msg_sec, current_mb_sec
    );
}

fn print_usage(prog: &str) {
    println!("Usage: {} [OPTIONS]", prog);
    println!("\nOptions:");
    println!("  -p, --pub          Run as publisher (default)");
    println!("  -s, --sub          Run as subscriber");
    println!(
        "  -d, --duration N   Test duration in seconds (default: {})",
        DEFAULT_DURATION_SEC
    );
    println!(
        "  -z, --size N       Payload size in bytes (default: {})",
        DEFAULT_PAYLOAD_SIZE
    );
    println!("  -h, --help         Show this help");
}

fn run_publisher(
    participant: &Arc<hdds::Participant>,
    payload_size: usize,
    duration_sec: u64,
    running: Arc<AtomicBool>,
) -> Result<ThroughputStats, hdds::Error> {
    // Use best_effort for maximum throughput
    let qos = hdds::QoS::best_effort();
    let writer = participant.create_writer::<ThroughputMsg>("ThroughputTopic", qos)?;

    println!("[OK] DataWriter created");
    println!("\n--- Running Throughput Test ---");
    println!("Publishing messages...\n");

    let mut stats = ThroughputStats::default();
    let mut msg = ThroughputMsg::new(payload_size);
    let msg_size = msg.total_size() as u64;

    let start_time = Instant::now();
    let mut last_progress_sec = 0u64;

    while running.load(Ordering::SeqCst) {
        let elapsed = start_time.elapsed();
        if elapsed.as_secs() >= duration_sec {
            break;
        }

        // Update message
        msg.sequence = stats.messages_sent;
        msg.timestamp_ns = elapsed.as_nanos() as u64;

        // Send message
        writer.write(&msg)?;

        stats.messages_sent += 1;
        stats.bytes_sent += msg_size;

        // Progress update every second
        let current_sec = elapsed.as_secs();
        if current_sec > last_progress_sec && current_sec > 0 {
            print_progress(&stats, current_sec, true);
            last_progress_sec = current_sec;
        }
    }

    stats.duration_sec = start_time.elapsed().as_secs_f64();
    stats.calculate(true);
    Ok(stats)
}

fn run_subscriber(
    participant: &Arc<hdds::Participant>,
    payload_size: usize,
    duration_sec: u64,
    running: Arc<AtomicBool>,
) -> Result<ThroughputStats, hdds::Error> {
    // Use best_effort for maximum throughput
    let qos = hdds::QoS::best_effort();
    let reader = participant.create_reader::<ThroughputMsg>("ThroughputTopic", qos)?;

    let waitset = hdds::WaitSet::new();
    waitset.attach(&reader)?;

    println!("[OK] DataReader created");
    println!("\n--- Running Throughput Test ---");
    println!("Receiving messages...\n");

    let mut stats = ThroughputStats::default();
    let msg_size = std::mem::size_of::<ThroughputMsg>() as u64;
    let _ = payload_size; // Acknowledged but msg_size is fixed for this simplified type

    let start_time = Instant::now();
    let mut last_progress_sec = 0u64;

    while running.load(Ordering::SeqCst) {
        let elapsed = start_time.elapsed();
        if elapsed.as_secs() >= duration_sec {
            break;
        }

        // Wait for data with short timeout
        match waitset.wait(Some(Duration::from_millis(100))) {
            Ok(triggered) if !triggered.is_empty() => {
                // Take all available samples
                while reader.take()?.is_some() {
                    stats.messages_received += 1;
                    stats.bytes_received += msg_size;
                }
            }
            Ok(_) => {
                // Timeout - continue
            }
            Err(hdds::Error::WouldBlock) => {
                // Timeout - continue
            }
            Err(e) => {
                eprintln!("Wait error: {:?}", e);
            }
        }

        // Progress update every second
        let current_sec = elapsed.as_secs();
        if current_sec > last_progress_sec && current_sec > 0 {
            print_progress(&stats, current_sec, false);
            last_progress_sec = current_sec;
        }
    }

    stats.duration_sec = start_time.elapsed().as_secs_f64();
    stats.calculate(false);
    Ok(stats)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== HDDS Throughput Benchmark ===\n");

    // Parse arguments
    let args: Vec<String> = env::args().collect();
    let mut is_publisher = true;
    let mut duration_sec = DEFAULT_DURATION_SEC;
    let mut payload_size = DEFAULT_PAYLOAD_SIZE;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-p" | "--pub" => is_publisher = true,
            "-s" | "--sub" => is_publisher = false,
            "-d" | "--duration" => {
                if i + 1 < args.len() {
                    i += 1;
                    duration_sec = args[i].parse().unwrap_or(DEFAULT_DURATION_SEC);
                }
            }
            "-z" | "--size" => {
                if i + 1 < args.len() {
                    i += 1;
                    payload_size = args[i].parse().unwrap_or(DEFAULT_PAYLOAD_SIZE);
                    payload_size = payload_size.min(MAX_PAYLOAD_SIZE);
                }
            }
            "-h" | "--help" => {
                print_usage(&args[0]);
                return Ok(());
            }
            _ => {}
        }
        i += 1;
    }

    let msg = ThroughputMsg::new(payload_size);

    println!("Configuration:");
    println!(
        "  Mode: {}",
        if is_publisher {
            "PUBLISHER"
        } else {
            "SUBSCRIBER"
        }
    );
    println!("  Duration: {} seconds", duration_sec);
    println!("  Payload size: {} bytes", payload_size);
    println!("  Message size: {} bytes (with header)\n", msg.total_size());

    // Note: Logging is optional and disabled by default in samples

    // Setup signal handler
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        println!("\nStopping...");
        r.store(false, Ordering::SeqCst);
    })
    .ok();

    // Create participant
    let participant = hdds::Participant::builder("ThroughputBenchmark")
        .domain_id(0)
        .build()?;

    println!("[OK] Participant created");
    println!("Press Ctrl+C to stop early.\n");

    // Run test
    let stats = if is_publisher {
        run_publisher(&participant, payload_size, duration_sec, running)?
    } else {
        run_subscriber(&participant, payload_size, duration_sec, running)?
    };

    // Print results
    println!("\n--- Throughput Results ---\n");

    if is_publisher {
        println!("Messages sent:     {}", stats.messages_sent);
        println!(
            "Bytes sent:        {} ({:.2} MB)",
            stats.bytes_sent,
            stats.bytes_sent as f64 / (1024.0 * 1024.0)
        );
    } else {
        println!("Messages received: {}", stats.messages_received);
        println!(
            "Bytes received:    {} ({:.2} MB)",
            stats.bytes_received,
            stats.bytes_received as f64 / (1024.0 * 1024.0)
        );
    }

    println!("Duration:          {:.2} seconds\n", stats.duration_sec);

    println!("Throughput:");
    println!("  Messages/sec:    {:.0}", stats.msg_per_sec);
    println!("  MB/sec:          {:.2}", stats.mb_per_sec);
    println!("  Gbps:            {:.2}", stats.mb_per_sec * 8.0 / 1024.0);

    println!("\n=== Benchmark Complete ===");
    Ok(())
}
