// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! hdds-latency-probe - DDS latency benchmark tool
//!
//! Measures round-trip latency using ping-pong pattern between two participants.

use clap::{Parser, Subcommand};
use colored::*;
use hdds::{Participant, QoS, TransportMode};
use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const PING_TOPIC: &str = "hdds_latency_ping";
const PONG_TOPIC: &str = "hdds_latency_pong";

/// DDS latency benchmark tool
#[derive(Parser, Debug)]
#[command(name = "hdds-latency-probe")]
#[command(version = "0.1.0")]
#[command(about = "Measure DDS round-trip latency")]
struct Args {
    #[command(subcommand)]
    mode: Mode,

    /// DDS domain ID
    #[arg(short, long, default_value = "0", global = true)]
    domain: u32,

    /// QoS profile: best-effort, reliable
    #[arg(short, long, default_value = "reliable", global = true)]
    qos: QoSProfile,
}

#[derive(Subcommand, Debug)]
enum Mode {
    /// Send ping messages and measure RTT
    Ping {
        /// Payload size in bytes
        #[arg(short = 's', long, default_value = "64")]
        size: usize,

        /// Number of iterations (0 = unlimited)
        #[arg(short = 'n', long, default_value = "1000")]
        count: u64,

        /// Warmup iterations before measurement
        #[arg(short, long, default_value = "10")]
        warmup: u64,

        /// Interval between pings in microseconds
        #[arg(short, long, default_value = "1000")]
        interval: u64,

        /// Output JSON results
        #[arg(long)]
        json: bool,

        /// Quiet mode - only output final results
        #[arg(long)]
        quiet: bool,
    },
    /// Echo back ping messages (run on remote host)
    Pong {
        /// Quiet mode
        #[arg(long)]
        quiet: bool,
    },
}

#[derive(Clone, Debug)]
enum QoSProfile {
    BestEffort,
    Reliable,
}

impl std::str::FromStr for QoSProfile {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "best-effort" | "besteffort" | "be" => Ok(QoSProfile::BestEffort),
            "reliable" | "rel" | "r" => Ok(QoSProfile::Reliable),
            _ => Err(format!("Unknown QoS: {}", s)),
        }
    }
}

fn main() {
    // Initialize logger for RUST_LOG-based debug output
    env_logger::init();

    let args = Args::parse();

    if let Err(e) = run(&args) {
        eprintln!("{}: {}", "Error".red().bold(), e);
        std::process::exit(1);
    }
}

fn run(args: &Args) -> Result<(), Box<dyn std::error::Error>> {
    // Setup Ctrl+C handler
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })?;

    match &args.mode {
        Mode::Ping {
            size,
            count,
            warmup,
            interval,
            json,
            quiet,
        } => run_ping(
            args, *size, *count, *warmup, *interval, *json, *quiet, running,
        ),
        Mode::Pong { quiet } => run_pong(args, *quiet, running),
    }
}

#[allow(clippy::too_many_arguments)]
fn run_ping(
    args: &Args,
    size: usize,
    count: u64,
    warmup: u64,
    interval_us: u64,
    json: bool,
    quiet: bool,
    running: Arc<AtomicBool>,
) -> Result<(), Box<dyn std::error::Error>> {
    let qos = match args.qos {
        QoSProfile::BestEffort => QoS::best_effort(),
        QoSProfile::Reliable => QoS::reliable(),
    };

    if !quiet && !json {
        eprintln!("{} Latency probe (ping mode)", ">>>".green().bold());
        eprintln!(
            "    domain={}, qos={:?}, size={} bytes, count={}, warmup={}",
            args.domain, args.qos, size, count, warmup
        );
        eprintln!("{}", "    Waiting for pong responder...".dimmed());
    }

    // Create participant with UDP transport for network benchmarks
    let participant = Participant::builder("hdds-latency-ping")
        .domain_id(args.domain)
        .with_transport(TransportMode::UdpMulticast)
        .build()?;
    let participant = Arc::new(participant);

    // Create writer for ping, reader for pong
    let writer = participant.create_raw_writer(PING_TOPIC, Some(qos.clone()))?;
    let reader = participant.create_raw_reader(PONG_TOPIC, Some(qos))?;

    // Create payload with sequence number at start
    let mut payload = vec![0u8; size.max(16)];

    // Statistics
    let mut latencies: Vec<f64> = Vec::with_capacity(count as usize);
    let mut lost = 0u64;
    let total_iterations = warmup + count;

    // Warmup phase
    if !quiet && !json && warmup > 0 {
        eprintln!("{}", "    Warmup...".dimmed());
    }

    let start_time = Instant::now();

    for i in 0..total_iterations {
        if !running.load(Ordering::SeqCst) {
            break;
        }

        let is_warmup = i < warmup;
        let seq = i;

        // Encode sequence number
        payload[0..8].copy_from_slice(&seq.to_le_bytes());

        // Send ping
        let send_time = Instant::now();
        writer.write_raw(&payload)?;

        // Wait for pong with timeout
        let timeout = Duration::from_millis(1000);
        let deadline = send_time + timeout;
        let mut received = false;

        while Instant::now() < deadline {
            if let Ok(samples) = reader.try_take_raw() {
                for sample in samples {
                    if sample.payload.len() >= 8 {
                        let recv_seq = u64::from_le_bytes(sample.payload[0..8].try_into().unwrap());
                        if recv_seq == seq {
                            let rtt = send_time.elapsed();
                            if !is_warmup {
                                latencies.push(rtt.as_secs_f64() * 1_000_000.0);
                                // microseconds
                            }
                            received = true;
                            break;
                        }
                    }
                }
                if received {
                    break;
                }
            }
            std::thread::sleep(Duration::from_micros(10));
        }

        if !received && !is_warmup {
            lost += 1;
        }

        // Progress indicator
        if !quiet && !json && !is_warmup {
            let measured = i - warmup + 1;
            if measured.is_multiple_of(100) || measured == count {
                eprint!("\r    Progress: {}/{}", measured, count);
                let _ = io::stderr().flush();
            }
        }

        // Inter-ping interval
        if interval_us > 0 {
            std::thread::sleep(Duration::from_micros(interval_us));
        }
    }

    let total_time = start_time.elapsed();

    if !quiet && !json {
        eprintln!();
    }

    // Calculate statistics
    let stats = calculate_stats(&latencies, lost);

    if json {
        print_json_results(&stats, size, count, total_time);
    } else {
        print_results(&stats, size, count, total_time, quiet);
    }

    Ok(())
}

fn run_pong(
    args: &Args,
    quiet: bool,
    running: Arc<AtomicBool>,
) -> Result<(), Box<dyn std::error::Error>> {
    let qos = match args.qos {
        QoSProfile::BestEffort => QoS::best_effort(),
        QoSProfile::Reliable => QoS::reliable(),
    };

    if !quiet {
        eprintln!("{} Latency probe (pong mode)", ">>>".green().bold());
        eprintln!("    domain={}, qos={:?}", args.domain, args.qos);
        eprintln!("{}", "    Press Ctrl+C to stop".dimmed());
        eprintln!();
    }

    // Create participant with UDP transport for network benchmarks
    let participant = Participant::builder("hdds-latency-pong")
        .domain_id(args.domain)
        .with_transport(TransportMode::UdpMulticast)
        .build()?;
    let participant = Arc::new(participant);

    // Create reader for ping, writer for pong
    let reader = participant.create_raw_reader(PING_TOPIC, Some(qos.clone()))?;
    let writer = participant.create_raw_writer(PONG_TOPIC, Some(qos))?;

    let count = AtomicU64::new(0);

    while running.load(Ordering::SeqCst) {
        match reader.try_take_raw() {
            Ok(samples) => {
                let is_empty = samples.is_empty();

                for sample in samples {
                    // Echo back immediately
                    if let Err(e) = writer.write_raw(&sample.payload) {
                        if !quiet {
                            eprintln!("{}: {}", "Warning".yellow(), e);
                        }
                    } else {
                        let n = count.fetch_add(1, Ordering::SeqCst) + 1;
                        if !quiet && n.is_multiple_of(100) {
                            eprint!("\r    Echoed: {} samples", n);
                            let _ = io::stderr().flush();
                        }
                    }
                }

                if is_empty {
                    std::thread::sleep(Duration::from_micros(100));
                }
            }
            Err(_) => {
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }

    let total = count.load(Ordering::SeqCst);
    if !quiet {
        eprintln!("\n\n{} Echoed {} total samples", "---".dimmed(), total);
    }

    Ok(())
}

#[derive(Debug)]
struct Stats {
    count: usize,
    lost: u64,
    min: f64,
    max: f64,
    mean: f64,
    stddev: f64,
    p50: f64,
    p90: f64,
    p99: f64,
    p999: f64,
}

fn calculate_stats(latencies: &[f64], lost: u64) -> Stats {
    if latencies.is_empty() {
        return Stats {
            count: 0,
            lost,
            min: 0.0,
            max: 0.0,
            mean: 0.0,
            stddev: 0.0,
            p50: 0.0,
            p90: 0.0,
            p99: 0.0,
            p999: 0.0,
        };
    }

    let mut sorted = latencies.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());

    let n = sorted.len();
    let min = sorted[0];
    let max = sorted[n - 1];
    let mean: f64 = latencies.iter().sum::<f64>() / n as f64;

    let variance: f64 = latencies.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / n as f64;
    let stddev = variance.sqrt();

    let percentile = |p: f64| -> f64 {
        let idx = ((p / 100.0) * (n - 1) as f64).round() as usize;
        sorted[idx.min(n - 1)]
    };

    Stats {
        count: n,
        lost,
        min,
        max,
        mean,
        stddev,
        p50: percentile(50.0),
        p90: percentile(90.0),
        p99: percentile(99.0),
        p999: percentile(99.9),
    }
}

fn print_results(stats: &Stats, size: usize, _requested: u64, total_time: Duration, quiet: bool) {
    let loss_pct = if stats.count > 0 || stats.lost > 0 {
        (stats.lost as f64 / (stats.count + stats.lost as usize) as f64) * 100.0
    } else {
        0.0
    };

    if quiet {
        println!(
            "min={:.1} max={:.1} avg={:.1} p99={:.1} us",
            stats.min, stats.max, stats.mean, stats.p99
        );
        return;
    }

    println!();
    println!("{}", "=== HDDS Latency Probe Results ===".bold());
    println!();
    println!("  {} {} bytes", "Payload size:".cyan(), size);
    println!("  {} {}", "Samples:".cyan(), stats.count);
    println!("  {} {} ({:.2}%)", "Lost:".cyan(), stats.lost, loss_pct);
    println!("  {} {:.2}s", "Duration:".cyan(), total_time.as_secs_f64());
    println!();
    println!("{}", "--- Latency (microseconds) ---".dimmed());
    println!("  {} {:>10.2} us", "Min:".green(), stats.min);
    println!("  {} {:>10.2} us", "Max:".red(), stats.max);
    println!("  {} {:>10.2} us", "Mean:".yellow(), stats.mean);
    println!("  {} {:>10.2} us", "Stddev:".yellow(), stats.stddev);
    println!();
    println!("{}", "--- Percentiles ---".dimmed());
    println!("  {} {:>10.2} us", "p50:".white(), stats.p50);
    println!("  {} {:>10.2} us", "p90:".white(), stats.p90);
    println!("  {} {:>10.2} us", "p99:".white(), stats.p99);
    println!("  {} {:>10.2} us", "p99.9:".white(), stats.p999);
    println!();

    // Throughput
    if stats.count > 0 {
        let throughput = stats.count as f64 / total_time.as_secs_f64();
        println!("  {} {:.0} msg/s", "Throughput:".cyan(), throughput);
    }
    println!();
}

fn print_json_results(stats: &Stats, size: usize, _requested: u64, total_time: Duration) {
    println!(
        r#"{{"payload_size":{},"samples":{},"lost":{},"duration_secs":{:.3},"latency_us":{{"min":{:.2},"max":{:.2},"mean":{:.2},"stddev":{:.2},"p50":{:.2},"p90":{:.2},"p99":{:.2},"p999":{:.2}}}}}"#,
        size,
        stats.count,
        stats.lost,
        total_time.as_secs_f64(),
        stats.min,
        stats.max,
        stats.mean,
        stats.stddev,
        stats.p50,
        stats.p90,
        stats.p99,
        stats.p999
    );
}
