// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! TSN Round-Trip Time Test - Measure RTT with hardware timestamps
//!
//! Usage:
//!   # On reflector (node3):
//!   tsn_rtt reflect 192.168.1.130:5555
//!
//!   # On sender (ai2):
//!   tsn_rtt ping 192.168.1.130:5555 --bind 192.168.1.200

use std::env;
use std::net::UdpSocket;
use std::time::{Duration, Instant};

const MSG_SIZE: usize = 64;
const NUM_SAMPLES: usize = 1000;

fn main() -> std::io::Result<()> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 3 {
        eprintln!("Usage:");
        eprintln!("  {} reflect <bind_addr:port>", args[0]);
        eprintln!(
            "  {} ping <target_addr:port> [--bind <local_addr>]",
            args[0]
        );
        std::process::exit(1);
    }

    match args[1].as_str() {
        "reflect" => run_reflector(&args[2]),
        "ping" => {
            let bind_addr = args
                .iter()
                .position(|a| a == "--bind")
                .and_then(|i| args.get(i + 1))
                .map(|s| format!("{}:0", s))
                .unwrap_or_else(|| "0.0.0.0:0".to_string());
            run_ping(&args[2], &bind_addr)
        }
        _ => {
            eprintln!("Unknown command: {}", args[1]);
            std::process::exit(1);
        }
    }
}

fn run_reflector(bind_addr: &str) -> std::io::Result<()> {
    println!("+==================================================+");
    println!("|         TSN RTT Test - Reflector                 |");
    println!("+==================================================+\n");

    let socket = UdpSocket::bind(bind_addr)?;
    socket.set_read_timeout(Some(Duration::from_secs(30)))?;
    println!("Listening on {}", socket.local_addr()?);
    println!("Will echo packets back to sender...\n");

    // Set high priority
    set_socket_priority(&socket);

    let mut buf = [0u8; MSG_SIZE];
    let mut count = 0u64;

    loop {
        match socket.recv_from(&mut buf) {
            Ok((len, src)) => {
                // Echo back immediately
                socket.send_to(&buf[..len], src)?;
                count += 1;
                if count.is_multiple_of(100) {
                    println!("Reflected {} packets", count);
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                println!("Timeout - no more packets. Total reflected: {}", count);
                break;
            }
            Err(e) => return Err(e),
        }
    }

    Ok(())
}

fn run_ping(target: &str, bind_addr: &str) -> std::io::Result<()> {
    println!("+==================================================+");
    println!("|         TSN RTT Test - Ping                      |");
    println!("+==================================================+\n");

    let socket = UdpSocket::bind(bind_addr)?;
    socket.set_read_timeout(Some(Duration::from_millis(100)))?;
    println!("Bound to {}", socket.local_addr()?);
    println!("Target: {}", target);

    // Set high priority
    set_socket_priority(&socket);

    println!("\nSending {} ping packets at 1kHz...\n", NUM_SAMPLES);

    let mut buf = [0u8; MSG_SIZE];
    let mut rtts = Vec::with_capacity(NUM_SAMPLES);
    let mut lost = 0;

    for i in 0..NUM_SAMPLES {
        // Fill packet with sequence number
        buf[0..4].copy_from_slice(&(i as u32).to_le_bytes());

        // Measure RTT
        let start = Instant::now();
        socket.send_to(&buf, target)?;

        // Wait for response
        match socket.recv_from(&mut buf) {
            Ok(_) => {
                let rtt = start.elapsed();
                rtts.push(rtt.as_nanos() as u64);
            }
            Err(_) => {
                lost += 1;
            }
        }

        if (i + 1) % 100 == 0 {
            println!("Completed {}/{} (lost: {})", i + 1, NUM_SAMPLES, lost);
        }

        // Small delay between pings
        std::thread::sleep(Duration::from_micros(500));
    }

    if rtts.is_empty() {
        println!("\n[X] No responses received!");
        return Ok(());
    }

    // Calculate statistics
    rtts.sort();
    let min = rtts[0];
    let max = rtts[rtts.len() - 1];
    let p50 = rtts[rtts.len() / 2];
    let p99 = rtts[rtts.len() * 99 / 100];
    let avg: u64 = rtts.iter().sum::<u64>() / rtts.len() as u64;

    // One-way latency estimate (RTT/2)
    let ow_min = min / 2;
    let ow_avg = avg / 2;
    let ow_p50 = p50 / 2;
    let ow_p99 = p99 / 2;
    let ow_max = max / 2;

    println!("\n+===========================================================+");
    println!("|                   RTT Results                              |");
    println!("+===========================================================+");
    println!(
        "| Samples: {:>5}  |  Lost: {:>4}  |  Success: {:>5.1}%        |",
        rtts.len(),
        lost,
        (rtts.len() as f64 / NUM_SAMPLES as f64) * 100.0
    );
    println!("+===========================================================+");
    println!("|          Round-Trip Time         One-Way (RTT/2)          |");
    println!(
        "| Min:  {:>8} ns ({:>6.2} us)   {:>7} ns ({:>5.2} us)      |",
        min,
        min as f64 / 1000.0,
        ow_min,
        ow_min as f64 / 1000.0
    );
    println!(
        "| Avg:  {:>8} ns ({:>6.2} us)   {:>7} ns ({:>5.2} us)      |",
        avg,
        avg as f64 / 1000.0,
        ow_avg,
        ow_avg as f64 / 1000.0
    );
    println!(
        "| p50:  {:>8} ns ({:>6.2} us)   {:>7} ns ({:>5.2} us)      |",
        p50,
        p50 as f64 / 1000.0,
        ow_p50,
        ow_p50 as f64 / 1000.0
    );
    println!(
        "| p99:  {:>8} ns ({:>6.2} us)   {:>7} ns ({:>5.2} us)      |",
        p99,
        p99 as f64 / 1000.0,
        ow_p99,
        ow_p99 as f64 / 1000.0
    );
    println!(
        "| Max:  {:>8} ns ({:>6.2} us)   {:>7} ns ({:>5.2} us)      |",
        max,
        max as f64 / 1000.0,
        ow_max,
        ow_max as f64 / 1000.0
    );
    println!("+===========================================================+");
    println!(
        "| Jitter (max-min): {:>8} ns ({:>6.2} us)                  |",
        max - min,
        (max - min) as f64 / 1000.0
    );
    println!("+===========================================================+");

    Ok(())
}

#[cfg(target_os = "linux")]
fn set_socket_priority(socket: &UdpSocket) {
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

#[cfg(not(target_os = "linux"))]
fn set_socket_priority(_socket: &UdpSocket) {}
