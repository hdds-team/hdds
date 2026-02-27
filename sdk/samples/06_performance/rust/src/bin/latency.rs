// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! # HDDS Sample: Latency Benchmark
//!
//! Measures **round-trip latency** using a ping-pong pattern - the time
//! from message send to receiving the echo response.
//!
//! ## Ping-Pong Pattern
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │                        Latency Measurement                          │
//! │                                                                     │
//! │   Ping (Publisher)               Pong (Subscriber)                  │
//! │   ┌──────────────────┐          ┌──────────────────┐               │
//! │   │ t0: Send message │ ────────►│ Receive message  │               │
//! │   │                  │          │        │         │               │
//! │   │ t1: Receive echo │◄──────── │ Echo back        │               │
//! │   │                  │          └──────────────────┘               │
//! │   │ RTT = t1 - t0    │                                             │
//! │   │ One-way ≈ RTT/2  │                                             │
//! │   └──────────────────┘                                             │
//! └─────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Latency Percentiles
//!
//! ```text
//! ┌────────────────────────────────────────────────────────────────┐
//! │                   Latency Distribution                         │
//! │                                                                │
//! │  Count                                                         │
//! │    │                                                           │
//! │ 500├──█───                                                     │
//! │    │  █                                                        │
//! │ 300├──█──█──                                                   │
//! │    │  █  █                                                     │
//! │ 100├──█──█──█──█───────█──                                     │
//! │    └──┼──┼──┼──┼───────┼──────► Latency (μs)                   │
//! │      p50 p90 p99      p99.9                                    │
//! │      (median)     (tail latency)                               │
//! └────────────────────────────────────────────────────────────────┘
//!
//! p50  (median): 50% of samples are faster
//! p99:           99% of samples are faster
//! p99.9:         99.9% of samples are faster (tail latency)
//! ```
//!
//! ## Use Cases
//!
//! - **Baseline measurement**: Establish system performance
//! - **Regression testing**: Detect latency increases
//! - **Capacity planning**: Understand system limits
//!
//! ## Running the Sample
//!
//! ```bash
//! # Terminal 1 - Pong responder (must start first)
//! cargo run --bin latency -- --pong
//!
//! # Terminal 2 - Ping initiator (measures latency)
//! cargo run --bin latency
//!
//! # Custom sample count
//! cargo run --bin latency -- -n 5000   # 5000 samples
//! ```

use std::env;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

const MAX_SAMPLES: usize = 10000;
const WARMUP_SAMPLES: usize = 100;
const PAYLOAD_SIZE: usize = 64; // Simulated via 8 x u64 fields = 64 bytes

/// Latency message structure - DDS-serializable (primitives only)
#[derive(hdds::DDS, Clone)]
struct LatencyMsg {
    sequence: u64,
    timestamp_ns: u64,
    // Simulated payload via multiple fields (DDS derive doesn't support arrays)
    p0: u64,
    p1: u64,
    p2: u64,
    p3: u64,
    p4: u64,
    p5: u64,
    p6: u64,
    p7: u64,
}

impl LatencyMsg {
    fn new(sequence: u64, timestamp_ns: u64) -> Self {
        Self {
            sequence,
            timestamp_ns,
            p0: 0,
            p1: 0,
            p2: 0,
            p3: 0,
            p4: 0,
            p5: 0,
            p6: 0,
            p7: 0,
        }
    }
}

/// Latency statistics
struct LatencyStats {
    samples: Vec<f64>,
    min: f64,
    max: f64,
    mean: f64,
    std_dev: f64,
    p50: f64,
    p90: f64,
    p99: f64,
    p999: f64,
}

impl LatencyStats {
    fn new() -> Self {
        Self {
            samples: Vec::with_capacity(MAX_SAMPLES),
            min: 0.0,
            max: 0.0,
            mean: 0.0,
            std_dev: 0.0,
            p50: 0.0,
            p90: 0.0,
            p99: 0.0,
            p999: 0.0,
        }
    }

    fn add_sample(&mut self, latency_us: f64) {
        self.samples.push(latency_us);
    }

    fn calculate(&mut self) {
        if self.samples.is_empty() {
            return;
        }

        // Sort for percentiles
        self.samples.sort_by(|a, b| a.partial_cmp(b).unwrap());

        // Min/Max
        self.min = self.samples[0];
        self.max = *self.samples.last().unwrap();

        // Mean
        let sum: f64 = self.samples.iter().sum();
        self.mean = sum / self.samples.len() as f64;

        // Standard deviation
        let sq_sum: f64 = self.samples.iter().map(|s| (s - self.mean).powi(2)).sum();
        self.std_dev = (sq_sum / self.samples.len() as f64).sqrt();

        // Percentiles
        self.p50 = percentile(&self.samples, 50.0);
        self.p90 = percentile(&self.samples, 90.0);
        self.p99 = percentile(&self.samples, 99.0);
        self.p999 = percentile(&self.samples, 99.9);
    }
}

fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = (p / 100.0) * (sorted.len() - 1) as f64;
    let lo = idx as usize;
    let hi = (lo + 1).min(sorted.len() - 1);
    let frac = idx - lo as f64;
    sorted[lo] * (1.0 - frac) + sorted[hi] * frac
}

fn print_histogram(samples: &[f64]) {
    if samples.is_empty() {
        return;
    }

    let num_buckets = 20;
    let min_val = samples[0];
    let max_val = *samples.last().unwrap();
    let range = if max_val == min_val {
        1.0
    } else {
        max_val - min_val
    };

    let mut buckets = vec![0usize; num_buckets];
    for &s in samples {
        let bucket = ((s - min_val) / range * (num_buckets - 1) as f64) as usize;
        let bucket = bucket.min(num_buckets - 1);
        buckets[bucket] += 1;
    }

    let max_count = *buckets.iter().max().unwrap_or(&1);

    println!("\nLatency Distribution:");
    for (i, &count) in buckets.iter().enumerate() {
        let bucket_min = min_val + (range * i as f64 / num_buckets as f64);
        let bucket_max = min_val + (range * (i + 1) as f64 / num_buckets as f64);
        let bar_len = if max_count > 0 {
            count * 40 / max_count
        } else {
            0
        };

        print!("{:7.1}-{:7.1} us |", bucket_min, bucket_max);
        for _ in 0..bar_len {
            print!("#");
        }
        println!(" {}", count);
    }
}

/// Run as ping (publisher) - sends messages and waits for echo
fn run_ping(
    participant: &Arc<hdds::Participant>,
    num_samples: usize,
) -> Result<LatencyStats, hdds::Error> {
    // Create writer for ping and reader for pong
    let qos = hdds::QoS::reliable();
    let ping_writer = participant.create_writer::<LatencyMsg>("LatencyPing", qos.clone())?;
    let pong_reader = participant.create_reader::<LatencyMsg>("LatencyPong", qos)?;

    let waitset = hdds::WaitSet::new();
    waitset.attach(&pong_reader)?;

    println!("[OK] Ping endpoints created");
    println!("\n--- Running Latency Test ---");
    println!("Waiting for pong peer...\n");

    // Give time for discovery
    thread::sleep(Duration::from_millis(500));

    let mut stats = LatencyStats::new();
    let start_time = Instant::now();

    // Warmup
    println!("Running warmup ({} samples)...", WARMUP_SAMPLES);
    for i in 0..WARMUP_SAMPLES {
        let msg = LatencyMsg::new(i as u64, 0);
        ping_writer.write(&msg)?;

        // Wait for pong with timeout
        match waitset.wait(Some(Duration::from_millis(100))) {
            Ok(triggered) if !triggered.is_empty() => {
                while pong_reader.take()?.is_some() {
                    // Discard warmup responses
                }
            }
            _ => {}
        }
    }

    // Measurement
    println!("Running measurement ({} samples)...\n", num_samples);

    for i in 0..num_samples {
        let send_time = Instant::now();
        let timestamp_ns = send_time.duration_since(start_time).as_nanos() as u64;

        let msg = LatencyMsg::new((WARMUP_SAMPLES + i) as u64, timestamp_ns);
        ping_writer.write(&msg)?;

        // Wait for pong
        match waitset.wait(Some(Duration::from_secs(1))) {
            Ok(triggered) if !triggered.is_empty() => {
                while let Some(response) = pong_reader.take()? {
                    if response.sequence == msg.sequence {
                        let rtt_us = send_time.elapsed().as_nanos() as f64 / 1000.0;
                        stats.add_sample(rtt_us);
                        break;
                    }
                }
            }
            _ => {}
        }

        if (i + 1) % (num_samples / 10).max(1) == 0 {
            println!("  Progress: {}/{} samples", i + 1, num_samples);
        }
    }

    stats.calculate();
    Ok(stats)
}

/// Run as pong (subscriber) - echoes messages back
fn run_pong(participant: &Arc<hdds::Participant>) -> Result<(), hdds::Error> {
    // Create reader for ping and writer for pong
    let qos = hdds::QoS::reliable();
    let ping_reader = participant.create_reader::<LatencyMsg>("LatencyPing", qos.clone())?;
    let pong_writer = participant.create_writer::<LatencyMsg>("LatencyPong", qos)?;

    let waitset = hdds::WaitSet::new();
    waitset.attach(&ping_reader)?;

    println!("[OK] Pong endpoints created");
    println!("\n--- Running Pong Responder ---");
    println!("Waiting for ping messages (Ctrl+C to exit)...\n");

    let mut count = 0u64;
    loop {
        match waitset.wait(Some(Duration::from_secs(5))) {
            Ok(triggered) if !triggered.is_empty() => {
                while let Some(msg) = ping_reader.take()? {
                    // Echo the message back immediately
                    pong_writer.write(&msg)?;
                    count += 1;

                    if count.is_multiple_of(1000) {
                        println!("  Echoed {} messages", count);
                    }
                }
            }
            Ok(_) => {
                if count > 0 {
                    println!("  (idle - {} total echoed)", count);
                }
            }
            Err(hdds::Error::WouldBlock) => {
                if count > 0 {
                    println!("  (idle - {} total echoed)", count);
                }
            }
            Err(e) => {
                eprintln!("Wait error: {:?}", e);
                break;
            }
        }
    }

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== HDDS Latency Benchmark ===\n");

    let args: Vec<String> = env::args().collect();
    let num_samples = args
        .iter()
        .position(|s| s == "-n" || s == "--samples")
        .and_then(|i| args.get(i + 1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(1000)
        .min(MAX_SAMPLES);

    let is_pong = args.iter().any(|s| s == "--pong" || s == "-s");

    println!("Configuration:");
    println!("  Samples: {} (+ {} warmup)", num_samples, WARMUP_SAMPLES);
    println!("  Payload: {} bytes", PAYLOAD_SIZE);
    println!(
        "  Mode: {}",
        if is_pong {
            "PONG (responder)"
        } else {
            "PING (initiator)"
        }
    );
    println!();

    // Note: Logging is optional and disabled by default in samples

    // Create participant
    let participant = hdds::Participant::builder("LatencyBenchmark")
        .domain_id(0)
        .build()?;

    println!("[OK] Participant created");

    if is_pong {
        run_pong(&participant)?;
    } else {
        let stats = run_ping(&participant, num_samples)?;

        // Print results
        println!("\n--- Latency Results ---\n");
        println!("Round-trip latency (microseconds):");
        println!("  Min:    {:8.2} us", stats.min);
        println!("  Max:    {:8.2} us", stats.max);
        println!("  Mean:   {:8.2} us", stats.mean);
        println!("  StdDev: {:8.2} us", stats.std_dev);
        println!();
        println!("Percentiles:");
        println!("  p50:    {:8.2} us (median)", stats.p50);
        println!("  p90:    {:8.2} us", stats.p90);
        println!("  p99:    {:8.2} us", stats.p99);
        println!("  p99.9:  {:8.2} us", stats.p999);

        // Print histogram
        print_histogram(&stats.samples);

        // One-way latency estimate
        println!("\n--- One-Way Latency Estimate ---");
        println!("  Estimated: {:.2} us (RTT/2)", stats.p50 / 2.0);
    }

    println!("\n=== Benchmark Complete ===");
    Ok(())
}
