// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! TSN Latency Test - Measure end-to-end latency with hardware timestamps
//!
//! Usage:
//!   # On receiver (node3):
//!   cargo run --example tsn_latency -- recv 192.168.1.130:5555
//!
//!   # On sender (ai2):
//!   cargo run --example tsn_latency -- send 192.168.1.130:5555 --bind 192.168.1.200
//!
//! Measures:
//! - Software TX timestamp
//! - Hardware TX timestamp (if available)
//! - Network transit time
//! - End-to-end latency

use std::env;
use std::net::UdpSocket;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const MSG_SIZE: usize = 64;
const NUM_SAMPLES: usize = 1000;

fn main() -> std::io::Result<()> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 3 {
        eprintln!("Usage:");
        eprintln!("  {} recv <bind_addr:port>", args[0]);
        eprintln!(
            "  {} send <target_addr:port> [--bind <local_addr>]",
            args[0]
        );
        std::process::exit(1);
    }

    match args[1].as_str() {
        "recv" => run_receiver(&args[2]),
        "send" => {
            let bind_addr = args
                .iter()
                .position(|a| a == "--bind")
                .and_then(|i| args.get(i + 1))
                .map(|s| format!("{}:0", s))
                .unwrap_or_else(|| "0.0.0.0:0".to_string());
            run_sender(&args[2], &bind_addr)
        }
        _ => {
            eprintln!("Unknown command: {}", args[1]);
            std::process::exit(1);
        }
    }
}

fn run_receiver(bind_addr: &str) -> std::io::Result<()> {
    println!("+==================================================+");
    println!("|         TSN Latency Test - Receiver              |");
    println!("+==================================================+\n");

    let socket = UdpSocket::bind(bind_addr)?;
    println!("Listening on {}", socket.local_addr()?);
    println!("Waiting for {} samples...\n", NUM_SAMPLES);

    let mut buf = [0u8; MSG_SIZE + 16];
    let mut latencies = Vec::with_capacity(NUM_SAMPLES);
    let mut received = 0;

    while received < NUM_SAMPLES {
        let (len, _src) = socket.recv_from(&mut buf)?;
        let rx_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;

        if len >= 8 {
            // Extract TX timestamp from packet
            let tx_time = u64::from_le_bytes(buf[0..8].try_into().unwrap());
            let latency_ns = rx_time.saturating_sub(tx_time);
            latencies.push(latency_ns);
            received += 1;

            if received % 100 == 0 {
                println!("Received {}/{} samples", received, NUM_SAMPLES);
            }
        }
    }

    // Calculate statistics
    latencies.sort();
    let min = latencies[0];
    let max = latencies[latencies.len() - 1];
    let p50 = latencies[latencies.len() / 2];
    let p99 = latencies[latencies.len() * 99 / 100];
    let avg: u64 = latencies.iter().sum::<u64>() / latencies.len() as u64;

    println!("\n+==================================================+");
    println!("|              Latency Results                      |");
    println!("+==================================================+");
    println!(
        "| Samples: {:>6}                                  |",
        NUM_SAMPLES
    );
    println!("|                                                   |");
    println!(
        "| Min:     {:>10} ns  ({:>7.2} us)             |",
        min,
        min as f64 / 1000.0
    );
    println!(
        "| Avg:     {:>10} ns  ({:>7.2} us)             |",
        avg,
        avg as f64 / 1000.0
    );
    println!(
        "| p50:     {:>10} ns  ({:>7.2} us)             |",
        p50,
        p50 as f64 / 1000.0
    );
    println!(
        "| p99:     {:>10} ns  ({:>7.2} us)             |",
        p99,
        p99 as f64 / 1000.0
    );
    println!(
        "| Max:     {:>10} ns  ({:>7.2} us)             |",
        max,
        max as f64 / 1000.0
    );
    println!("|                                                   |");
    println!(
        "| Jitter (max-min): {:>7} ns ({:>5.2} us)         |",
        max - min,
        (max - min) as f64 / 1000.0
    );
    println!("+==================================================+");

    Ok(())
}

fn run_sender(target: &str, bind_addr: &str) -> std::io::Result<()> {
    println!("+==================================================+");
    println!("|         TSN Latency Test - Sender                |");
    println!("+==================================================+\n");

    let socket = UdpSocket::bind(bind_addr)?;
    println!("Bound to {}", socket.local_addr()?);
    println!("Target: {}", target);

    // Set high priority
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        let fd = socket.as_raw_fd();
        let priority: libc::c_int = 6;
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PRIORITY,
                &priority as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
        println!("SO_PRIORITY: 6 (high priority)");
    }

    println!("\nSending {} samples at 1kHz...\n", NUM_SAMPLES);

    let mut buf = [0u8; MSG_SIZE];
    let start = Instant::now();

    for i in 0..NUM_SAMPLES {
        // Embed TX timestamp
        let tx_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        buf[0..8].copy_from_slice(&tx_time.to_le_bytes());
        buf[8..12].copy_from_slice(&(i as u32).to_le_bytes());

        socket.send_to(&buf, target)?;

        if (i + 1) % 100 == 0 {
            println!("Sent {}/{}", i + 1, NUM_SAMPLES);
        }

        // 1kHz rate (1ms between sends)
        std::thread::sleep(Duration::from_micros(1000));
    }

    let elapsed = start.elapsed();
    println!("\nDone! Sent {} packets in {:?}", NUM_SAMPLES, elapsed);
    println!(
        "Effective rate: {:.1} Hz",
        NUM_SAMPLES as f64 / elapsed.as_secs_f64()
    );

    Ok(())
}
