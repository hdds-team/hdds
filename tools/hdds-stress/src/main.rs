// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! hdds-stress - Stress testing tool for HDDS
//!
//! Tests scalability with many topics, participants, and sustained load.

use clap::{Parser, Subcommand};
use hdds::{Participant, QoS, TransportMode};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// HDDS stress testing tool
#[derive(Parser, Debug)]
#[command(name = "hdds-stress")]
#[command(version = "0.1.0")]
#[command(about = "Stress test HDDS with many topics/participants")]
struct Args {
    #[command(subcommand)]
    mode: Mode,

    /// DDS domain ID
    #[arg(short, long, default_value = "0", global = true)]
    domain: u32,
}

#[derive(Subcommand, Debug)]
enum Mode {
    /// Test with many topics (default: 1000)
    Topics {
        /// Number of topics to create
        #[arg(short = 'n', long, default_value = "1000")]
        count: usize,

        /// Create writers for each topic
        #[arg(short, long)]
        writers: bool,

        /// Create readers for each topic
        #[arg(short, long)]
        readers: bool,

        /// Send messages on each topic
        #[arg(short, long)]
        send: bool,

        /// Number of messages per topic (if --send)
        #[arg(short, long, default_value = "10")]
        messages: usize,
    },

    /// Test with many participants
    Participants {
        /// Number of participants to create
        #[arg(short = 'n', long, default_value = "100")]
        count: usize,

        /// Topics per participant
        #[arg(short, long, default_value = "10")]
        topics: usize,
    },

    /// Long duration test
    Endurance {
        /// Duration in seconds
        #[arg(short, long, default_value = "3600")]
        duration: u64,

        /// Message rate (msg/s)
        #[arg(short, long, default_value = "100")]
        rate: u64,
    },

    /// Reconnection cycles test
    Reconnect {
        /// Number of reconnection cycles
        #[arg(short = 'n', long, default_value = "1000")]
        cycles: usize,

        /// Send messages per cycle
        #[arg(short, long, default_value = "10")]
        messages: usize,
    },
}

fn main() {
    env_logger::init();
    let args = Args::parse();

    if let Err(e) = run(&args) {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

fn run(args: &Args) -> Result<(), Box<dyn std::error::Error>> {
    match &args.mode {
        Mode::Topics {
            count,
            writers,
            readers,
            send,
            messages,
        } => run_topics_test(args.domain, *count, *writers, *readers, *send, *messages),
        Mode::Participants { count, topics } => run_participants_test(args.domain, *count, *topics),
        Mode::Endurance { duration, rate } => run_endurance_test(args.domain, *duration, *rate),
        Mode::Reconnect { cycles, messages } => run_reconnect_test(args.domain, *cycles, *messages),
    }
}

fn run_topics_test(
    domain: u32,
    count: usize,
    create_writers: bool,
    create_readers: bool,
    send: bool,
    messages: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("=== HDDS Stress Test: {} Topics ===\n", count);

    let start = Instant::now();

    // Create participant
    println!("[1/4] Creating participant...");
    let participant = Participant::builder("hdds-stress-topics")
        .domain_id(domain)
        .with_transport(TransportMode::UdpMulticast)
        .build()?;
    let participant = Arc::new(participant);
    println!("      Done in {:?}", start.elapsed());

    // Create topics with writers/readers
    let qos = QoS::best_effort(); // Use best-effort for stress test
    let mut writers = Vec::new();
    let mut readers = Vec::new();

    println!("[2/4] Creating {} topics...", count);
    let topics_start = Instant::now();

    for i in 0..count {
        let topic_name = format!("stress_topic_{:05}", i);

        if create_writers || send {
            let writer = participant.create_raw_writer(&topic_name, Some(qos.clone()))?;
            writers.push(writer);
        }

        if create_readers {
            let reader = participant.create_raw_reader(&topic_name, Some(qos.clone()))?;
            readers.push(reader);
        }

        // Progress every 100 topics
        if (i + 1) % 100 == 0 {
            print!("\r      Progress: {}/{}", i + 1, count);
            std::io::Write::flush(&mut std::io::stdout())?;
        }
    }
    println!(
        "\r      Created {} topics in {:?}",
        count,
        topics_start.elapsed()
    );

    // Memory stats
    println!("[3/4] Memory usage...");
    #[cfg(target_os = "linux")]
    {
        if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
            for line in status.lines() {
                if line.starts_with("VmRSS:") || line.starts_with("VmHWM:") {
                    println!("      {}", line.trim());
                }
            }
        }
    }

    // Send messages if requested
    if send && !writers.is_empty() {
        println!("[4/4] Sending {} messages per topic...", messages);
        let send_start = Instant::now();
        let payload = vec![0u8; 64];
        let mut total_sent = 0u64;

        for (i, writer) in writers.iter().enumerate() {
            for _ in 0..messages {
                writer.write_raw(&payload)?;
                total_sent += 1;
            }

            if (i + 1) % 100 == 0 {
                print!("\r      Progress: {}/{} topics", i + 1, writers.len());
                std::io::Write::flush(&mut std::io::stdout())?;
            }
        }

        let send_elapsed = send_start.elapsed();
        println!(
            "\r      Sent {} messages in {:?} ({:.0} msg/s)",
            total_sent,
            send_elapsed,
            total_sent as f64 / send_elapsed.as_secs_f64()
        );
    } else {
        println!("[4/4] Skipping send (use --send to enable)");
    }

    // Summary
    let total_elapsed = start.elapsed();
    println!("\n=== Results ===");
    println!("  Topics created: {}", count);
    println!("  Writers: {}", writers.len());
    println!("  Readers: {}", readers.len());
    println!("  Total time: {:?}", total_elapsed);
    println!(
        "  Topics/sec: {:.0}",
        count as f64 / topics_start.elapsed().as_secs_f64()
    );

    // Hold for a moment to let discovery complete
    println!("\n  Holding 2s for discovery to settle...");
    std::thread::sleep(Duration::from_secs(2));

    println!("  Done. Cleaning up...");
    Ok(())
}

fn run_participants_test(
    domain: u32,
    count: usize,
    topics_per_participant: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("=== HDDS Stress Test: {} Participants ===\n", count);

    let start = Instant::now();
    let mut participants = Vec::new();

    println!(
        "[1/2] Creating {} participants with {} topics each...",
        count, topics_per_participant
    );

    for i in 0..count {
        let name = format!("hdds-stress-p{:04}", i);
        let participant = Participant::builder(&name)
            .domain_id(domain)
            .with_transport(TransportMode::UdpMulticast)
            .build()?;
        let participant = Arc::new(participant);

        // Create topics for this participant
        let qos = QoS::best_effort();
        for t in 0..topics_per_participant {
            let topic = format!("p{}_topic_{}", i, t);
            let _ = participant.create_raw_writer(&topic, Some(qos.clone()))?;
        }

        participants.push(participant);

        if (i + 1) % 10 == 0 {
            print!("\r      Progress: {}/{}", i + 1, count);
            std::io::Write::flush(&mut std::io::stdout())?;
        }
    }

    println!(
        "\r      Created {} participants in {:?}",
        count,
        start.elapsed()
    );

    // Memory stats
    println!("[2/2] Memory usage...");
    #[cfg(target_os = "linux")]
    {
        if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
            for line in status.lines() {
                if line.starts_with("VmRSS:") || line.starts_with("VmHWM:") {
                    println!("      {}", line.trim());
                }
            }
        }
    }

    // Hold for discovery
    println!("\n  Waiting 5s for cross-participant discovery...");
    std::thread::sleep(Duration::from_secs(5));

    println!("\n=== Results ===");
    println!("  Participants: {}", participants.len());
    println!(
        "  Total topics: {}",
        participants.len() * topics_per_participant
    );
    println!("  Total time: {:?}", start.elapsed());

    Ok(())
}

fn run_endurance_test(
    domain: u32,
    duration_secs: u64,
    rate: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    println!(
        "=== HDDS Endurance Test: {}s @ {} msg/s ===\n",
        duration_secs, rate
    );

    let participant = Participant::builder("hdds-stress-endurance")
        .domain_id(domain)
        .with_transport(TransportMode::UdpMulticast)
        .build()?;
    let participant = Arc::new(participant);

    let qos = QoS::reliable();
    let writer = participant.create_raw_writer("endurance_test", Some(qos))?;

    let payload = vec![0u8; 256];
    let interval = Duration::from_micros(1_000_000 / rate);
    let start = Instant::now();
    let end_time = start + Duration::from_secs(duration_secs);

    let sent = Arc::new(AtomicU64::new(0));
    let running = Arc::new(AtomicBool::new(true));

    // Ctrl+C handler
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })?;

    println!("  Press Ctrl+C to stop early\n");

    let mut last_report = Instant::now();
    let mut last_count = 0u64;

    while running.load(Ordering::SeqCst) && Instant::now() < end_time {
        writer.write_raw(&payload)?;
        sent.fetch_add(1, Ordering::Relaxed);

        // Report every 5 seconds
        if last_report.elapsed() >= Duration::from_secs(5) {
            let current = sent.load(Ordering::Relaxed);
            let delta = current - last_count;
            let elapsed = last_report.elapsed().as_secs_f64();
            println!(
                "  [{:>6}s] Sent: {} total, {:.0} msg/s (last 5s)",
                start.elapsed().as_secs(),
                current,
                delta as f64 / elapsed
            );
            last_report = Instant::now();
            last_count = current;
        }

        spin_sleep::sleep(interval);
    }

    let total = sent.load(Ordering::Relaxed);
    let elapsed = start.elapsed();

    println!("\n=== Results ===");
    println!("  Duration: {:?}", elapsed);
    println!("  Messages sent: {}", total);
    println!(
        "  Average rate: {:.1} msg/s",
        total as f64 / elapsed.as_secs_f64()
    );

    Ok(())
}

fn run_reconnect_test(
    domain: u32,
    cycles: usize,
    messages_per_cycle: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("=== HDDS Reconnection Test: {} cycles ===\n", cycles);

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })?;

    println!("  Press Ctrl+C to stop early\n");

    let start = Instant::now();
    let mut successful_cycles = 0usize;
    let mut total_messages = 0u64;
    let mut errors = Vec::new();

    for cycle in 0..cycles {
        if !running.load(Ordering::SeqCst) {
            println!("\n  Interrupted by user");
            break;
        }

        // Create participant
        let name = format!("hdds-reconnect-{}", cycle);
        let participant = match Participant::builder(&name)
            .domain_id(domain)
            .with_transport(TransportMode::UdpMulticast)
            .build()
        {
            Ok(p) => Arc::new(p),
            Err(e) => {
                errors.push(format!("Cycle {}: create participant failed: {}", cycle, e));
                continue;
            }
        };

        // Create writer and send messages
        let qos = QoS::best_effort();
        match participant.create_raw_writer("reconnect_test", Some(qos)) {
            Ok(writer) => {
                let payload = vec![0u8; 64];
                for _ in 0..messages_per_cycle {
                    if writer.write_raw(&payload).is_ok() {
                        total_messages += 1;
                    }
                }
            }
            Err(e) => {
                errors.push(format!("Cycle {}: create writer failed: {}", cycle, e));
                continue;
            }
        }

        // Drop participant (implicit reconnection test)
        drop(participant);
        successful_cycles += 1;

        // Progress every 100 cycles
        if (cycle + 1) % 100 == 0 {
            let rate = (cycle + 1) as f64 / start.elapsed().as_secs_f64();
            print!("\r  [{:>5}/{}] {:.1} cycles/s", cycle + 1, cycles, rate);
            std::io::Write::flush(&mut std::io::stdout())?;
        }
    }

    let elapsed = start.elapsed();
    println!("\n\n=== Results ===");
    println!("  Cycles completed: {}/{}", successful_cycles, cycles);
    println!("  Messages sent: {}", total_messages);
    println!("  Duration: {:?}", elapsed);
    println!(
        "  Rate: {:.1} cycles/s",
        successful_cycles as f64 / elapsed.as_secs_f64()
    );

    if !errors.is_empty() {
        println!("\n  Errors ({}):", errors.len());
        for e in errors.iter().take(10) {
            println!("    - {}", e);
        }
        if errors.len() > 10 {
            println!("    ... and {} more", errors.len() - 10);
        }
    }

    // Memory stats
    #[cfg(target_os = "linux")]
    {
        println!("\n  Memory usage:");
        if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
            for line in status.lines() {
                if line.starts_with("VmRSS:") || line.starts_with("VmHWM:") {
                    println!("    {}", line.trim());
                }
            }
        }
    }

    if successful_cycles == cycles {
        println!("\n  All cycles completed successfully!");
    }

    Ok(())
}
