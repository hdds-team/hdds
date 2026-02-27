// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! TSN Pub/Sub Example - DDS-style pub/sub with TSN scheduling
//!
//! Demonstrates deterministic pub/sub using TSN features:
//! - SO_PRIORITY for traffic class prioritization
//! - SO_TXTIME for scheduled transmission (LaunchTime)
//! - Latency measurement with TSN vs regular mode
//!
//! Usage:
//!   # On subscriber (start first):
//!   cargo run --example tsn_pubsub -- sub 192.168.1.130:5555
//!
//!   # On publisher:
//!   cargo run --example tsn_pubsub -- pub 192.168.1.130:5555 --bind 192.168.1.200
//!
//!   # Enable TSN scheduling (requires ETF qdisc configured):
//!   cargo run --example tsn_pubsub -- pub 192.168.1.130:5555 --bind 192.168.1.200 --tsn
//!
//! Prerequisites for TSN mode:
//!   sudo tc qdisc replace dev enp1s0 parent root handle 100 mqprio \
//!        num_tc 3 map 2 2 1 0 2 2 2 2 2 2 2 2 2 2 2 2 \
//!        queues 1@0 1@1 2@2 hw 0
//!   sudo tc qdisc add dev enp1s0 parent 100:1 etf clockid CLOCK_TAI delta 500000

use std::env;
use std::net::UdpSocket;
use std::os::unix::io::AsRawFd;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Temperature sample (matches HDDS Temperature type)
#[repr(C, packed)]
struct TemperatureSample {
    /// TX timestamp (nanoseconds since epoch)
    tx_timestamp: u64,
    /// Sequence number
    seq: u32,
    /// Temperature value
    value: f32,
    /// Sensor ID
    sensor_id: [u8; 16],
}

const SAMPLE_SIZE: usize = std::mem::size_of::<TemperatureSample>();
const NUM_SAMPLES: usize = 1000;
const PUBLISH_RATE_HZ: u64 = 100; // 100 Hz = 10ms period

// Linux constants
const SO_TXTIME: libc::c_int = 61;
const SCM_TXTIME: libc::c_int = 61;
const CLOCK_TAI: libc::clockid_t = 11;
const SOF_TXTIME_DEADLINE_MODE: u32 = 1 << 0;
const SOF_TXTIME_REPORT_ERRORS: u32 = 1 << 1;

fn main() -> std::io::Result<()> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 3 {
        eprintln!("TSN Pub/Sub Example - DDS-style messaging with TSN scheduling\n");
        eprintln!("Usage:");
        eprintln!("  {} sub <bind_addr:port>", args[0]);
        eprintln!(
            "  {} pub <target_addr:port> [--bind <local_addr>] [--tsn]",
            args[0]
        );
        eprintln!("\nOptions:");
        eprintln!("  --tsn     Enable SO_TXTIME scheduling (requires ETF qdisc)");
        eprintln!("  --bind    Bind to specific local address");
        eprintln!("\nExample:");
        eprintln!("  # Subscriber on 192.168.1.130:");
        eprintln!("  {} sub 0.0.0.0:5555", args[0]);
        eprintln!("\n  # Publisher on 192.168.1.200 with TSN:");
        eprintln!(
            "  {} pub 192.168.1.130:5555 --bind 192.168.1.200 --tsn",
            args[0]
        );
        std::process::exit(1);
    }

    match args[1].as_str() {
        "sub" => run_subscriber(&args[2]),
        "pub" => {
            let bind_addr = args
                .iter()
                .position(|a| a == "--bind")
                .and_then(|i| args.get(i + 1))
                .map(|s| format!("{}:0", s))
                .unwrap_or_else(|| "0.0.0.0:0".to_string());
            let tsn_enabled = args.iter().any(|a| a == "--tsn");
            run_publisher(&args[2], &bind_addr, tsn_enabled)
        }
        _ => {
            eprintln!("Unknown command: {}", args[1]);
            std::process::exit(1);
        }
    }
}

fn run_subscriber(bind_addr: &str) -> std::io::Result<()> {
    println!("+==========================================================+");
    println!("|           TSN Pub/Sub - Subscriber                       |");
    println!("+==========================================================+\n");

    let socket = UdpSocket::bind(bind_addr)?;
    socket.set_read_timeout(Some(Duration::from_secs(30)))?;
    println!("Listening on {}", socket.local_addr()?);
    println!("Topic: sensor/temperature");
    println!("Waiting for {} samples...\n", NUM_SAMPLES);

    let mut buf = [0u8; SAMPLE_SIZE + 64]; // Extra space for alignment
    let mut latencies = Vec::with_capacity(NUM_SAMPLES);
    let mut inter_arrival = Vec::with_capacity(NUM_SAMPLES);
    let mut received = 0;
    let mut last_rx_time = None;
    let mut last_seq = None;
    let mut out_of_order = 0;
    let mut duplicates = 0;

    while received < NUM_SAMPLES {
        match socket.recv_from(&mut buf) {
            Ok((len, _src)) => {
                let rx_time = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos() as u64;

                if len >= SAMPLE_SIZE {
                    // Parse sample
                    let tx_time = u64::from_le_bytes(buf[0..8].try_into().unwrap());
                    let seq = u32::from_le_bytes(buf[8..12].try_into().unwrap());
                    let value = f32::from_le_bytes(buf[12..16].try_into().unwrap());

                    // Calculate latency
                    let latency_ns = rx_time.saturating_sub(tx_time);
                    latencies.push(latency_ns);

                    // Calculate inter-arrival time
                    if let Some(last_rx) = last_rx_time {
                        inter_arrival.push(rx_time - last_rx);
                    }
                    last_rx_time = Some(rx_time);

                    // Check sequence
                    if let Some(last) = last_seq {
                        if seq <= last {
                            if seq == last {
                                duplicates += 1;
                            } else {
                                out_of_order += 1;
                            }
                        }
                    }
                    last_seq = Some(seq);

                    received += 1;

                    if received % 100 == 0 {
                        println!(
                            "Received {}/{} | Last: seq={}, temp={:.1} degC, latency={:.2}us",
                            received,
                            NUM_SAMPLES,
                            seq,
                            value,
                            latency_ns as f64 / 1000.0
                        );
                    }
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                println!("Timeout waiting for samples. Received: {}", received);
                break;
            }
            Err(e) => return Err(e),
        }
    }

    if latencies.is_empty() {
        println!("\n[X] No samples received!");
        return Ok(());
    }

    // Calculate latency statistics
    latencies.sort();
    let lat_min = latencies[0];
    let lat_max = latencies[latencies.len() - 1];
    let lat_p50 = latencies[latencies.len() / 2];
    let lat_p99 = latencies[latencies.len() * 99 / 100];
    let lat_avg: u64 = latencies.iter().sum::<u64>() / latencies.len() as u64;

    // Calculate jitter (inter-arrival variance)
    let (jitter_avg, jitter_max) = if !inter_arrival.is_empty() {
        inter_arrival.sort();
        let expected_interval = 1_000_000_000 / PUBLISH_RATE_HZ; // Expected ns between samples
        let jitters: Vec<i64> = inter_arrival
            .iter()
            .map(|&t| (t as i64 - expected_interval as i64).abs())
            .collect();
        let jitter_sum: i64 = jitters.iter().sum();
        let jitter_max = *jitters.iter().max().unwrap_or(&0);
        (jitter_sum / jitters.len() as i64, jitter_max)
    } else {
        (0, 0)
    };

    println!("\n+===============================================================+");
    println!("|                 Subscriber Statistics                         |");
    println!("+===============================================================+");
    println!(
        "| Samples received: {:>5}  | Out-of-order: {:>3} | Dups: {:>3}     |",
        latencies.len(),
        out_of_order,
        duplicates
    );
    println!("+===============================================================+");
    println!("|                    End-to-End Latency                         |");
    println!(
        "| Min:  {:>10} ns  ({:>8.2} us)                           |",
        lat_min,
        lat_min as f64 / 1000.0
    );
    println!(
        "| Avg:  {:>10} ns  ({:>8.2} us)                           |",
        lat_avg,
        lat_avg as f64 / 1000.0
    );
    println!(
        "| p50:  {:>10} ns  ({:>8.2} us)                           |",
        lat_p50,
        lat_p50 as f64 / 1000.0
    );
    println!(
        "| p99:  {:>10} ns  ({:>8.2} us)                           |",
        lat_p99,
        lat_p99 as f64 / 1000.0
    );
    println!(
        "| Max:  {:>10} ns  ({:>8.2} us)                           |",
        lat_max,
        lat_max as f64 / 1000.0
    );
    println!("+===============================================================+");
    println!("|                         Jitter                                |");
    println!(
        "| Avg jitter:  {:>10} ns  ({:>8.2} us)                    |",
        jitter_avg,
        jitter_avg as f64 / 1000.0
    );
    println!(
        "| Max jitter:  {:>10} ns  ({:>8.2} us)                    |",
        jitter_max,
        jitter_max as f64 / 1000.0
    );
    println!(
        "| Latency range: {:>8} ns  ({:>6.2} us)                      |",
        lat_max - lat_min,
        (lat_max - lat_min) as f64 / 1000.0
    );
    println!("+===============================================================+");

    Ok(())
}

fn run_publisher(target: &str, bind_addr: &str, tsn_enabled: bool) -> std::io::Result<()> {
    println!("+==========================================================+");
    println!("|           TSN Pub/Sub - Publisher                        |");
    println!("+==========================================================+\n");

    let socket = UdpSocket::bind(bind_addr)?;
    println!("Bound to: {}", socket.local_addr()?);
    println!("Target:   {}", target);
    println!("Topic:    sensor/temperature");
    println!("Rate:     {} Hz", PUBLISH_RATE_HZ);
    println!("Samples:  {}", NUM_SAMPLES);
    println!(
        "TSN:      {}",
        if tsn_enabled { "ENABLED" } else { "disabled" }
    );

    // Set high priority (PCP 6)
    set_socket_priority(&socket, 6)?;
    println!("SO_PRIORITY: 6 (high priority)");

    // Enable TSN if requested
    let txtime_enabled = if tsn_enabled {
        match enable_so_txtime(&socket) {
            Ok(()) => {
                println!("SO_TXTIME: enabled (CLOCK_TAI, deadline mode)");
                true
            }
            Err(e) => {
                println!("SO_TXTIME: FAILED - {} (falling back to regular send)", e);
                false
            }
        }
    } else {
        false
    };

    println!(
        "\nPublishing {} samples at {} Hz...\n",
        NUM_SAMPLES, PUBLISH_RATE_HZ
    );

    let period = Duration::from_nanos(1_000_000_000 / PUBLISH_RATE_HZ);
    let lead_time_ns: u64 = 500_000; // 500us lead time for ETF qdisc

    let mut buf = [0u8; SAMPLE_SIZE];
    let sensor_id = b"temp_sensor_001\0";
    let mut txtime_sends = 0;
    let mut regular_sends = 0;
    let mut send_errors = 0;

    let start = Instant::now();
    let mut next_send = Instant::now();

    for seq in 0..NUM_SAMPLES as u32 {
        // Wait for next scheduled send time
        let now = Instant::now();
        if next_send > now {
            std::thread::sleep(next_send - now);
        }
        next_send += period;

        // Get TX timestamp
        let tx_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;

        // Build sample
        let value = 20.0 + (seq as f32 * 0.1); // Simulated temperature
        buf[0..8].copy_from_slice(&tx_time.to_le_bytes());
        buf[8..12].copy_from_slice(&seq.to_le_bytes());
        buf[12..16].copy_from_slice(&value.to_le_bytes());
        buf[16..32].copy_from_slice(sensor_id);

        // Send with or without txtime
        let result = if txtime_enabled {
            // Calculate txtime: TAI clock now + lead_time
            let txtime = get_tai_time()? + lead_time_ns;
            send_with_txtime(&socket, &buf, target, txtime)
        } else {
            socket.send_to(&buf, target).map(|_| ())
        };

        match result {
            Ok(()) => {
                if txtime_enabled {
                    txtime_sends += 1;
                } else {
                    regular_sends += 1;
                }
            }
            Err(e) => {
                send_errors += 1;
                if send_errors <= 5 {
                    eprintln!("Send error: {}", e);
                }
            }
        }

        if (seq + 1) % 100 == 0 {
            println!(
                "Published {}/{} | temp={:.1} degC",
                seq + 1,
                NUM_SAMPLES,
                value
            );
        }
    }

    let elapsed = start.elapsed();
    let actual_rate = NUM_SAMPLES as f64 / elapsed.as_secs_f64();

    println!("\n+===============================================================+");
    println!("|                 Publisher Statistics                          |");
    println!("+===============================================================+");
    println!(
        "| Samples sent:     {:>6}                                      |",
        NUM_SAMPLES
    );
    println!(
        "| TSN txtime sends: {:>6}                                      |",
        txtime_sends
    );
    println!(
        "| Regular sends:    {:>6}                                      |",
        regular_sends
    );
    println!(
        "| Send errors:      {:>6}                                      |",
        send_errors
    );
    println!(
        "| Elapsed time:     {:>6.2} s                                    |",
        elapsed.as_secs_f64()
    );
    println!(
        "| Actual rate:      {:>6.1} Hz                                   |",
        actual_rate
    );
    println!("+===============================================================+");

    Ok(())
}

fn set_socket_priority(socket: &UdpSocket, priority: u8) -> std::io::Result<()> {
    let prio = priority as libc::c_int;
    let ret = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PRIORITY,
            &prio as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn enable_so_txtime(socket: &UdpSocket) -> std::io::Result<()> {
    #[repr(C)]
    struct SockTxtime {
        clockid: libc::clockid_t,
        flags: u32,
    }

    let txtime = SockTxtime {
        clockid: CLOCK_TAI,
        flags: SOF_TXTIME_DEADLINE_MODE | SOF_TXTIME_REPORT_ERRORS,
    };

    let ret = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            SO_TXTIME,
            &txtime as *const _ as *const libc::c_void,
            std::mem::size_of::<SockTxtime>() as libc::socklen_t,
        )
    };

    if ret < 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ENOPROTOOPT) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "SO_TXTIME not supported - configure ETF qdisc first",
            ));
        }
        return Err(err);
    }
    Ok(())
}

fn get_tai_time() -> std::io::Result<u64> {
    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    let ret = unsafe { libc::clock_gettime(CLOCK_TAI, &mut ts) };
    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64)
}

fn send_with_txtime(
    socket: &UdpSocket,
    buf: &[u8],
    target: &str,
    txtime_ns: u64,
) -> std::io::Result<()> {
    use std::net::ToSocketAddrs;

    let addr = target.to_socket_addrs()?.next().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "Invalid target address")
    })?;

    // Prepare destination address
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let socklen = match addr {
        std::net::SocketAddr::V4(v4) => {
            let sa = &mut storage as *mut _ as *mut libc::sockaddr_in;
            unsafe {
                (*sa).sin_family = libc::AF_INET as libc::sa_family_t;
                (*sa).sin_port = v4.port().to_be();
                (*sa).sin_addr.s_addr = u32::from_ne_bytes(v4.ip().octets());
            }
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t
        }
        std::net::SocketAddr::V6(v6) => {
            let sa = &mut storage as *mut _ as *mut libc::sockaddr_in6;
            unsafe {
                (*sa).sin6_family = libc::AF_INET6 as libc::sa_family_t;
                (*sa).sin6_port = v6.port().to_be();
                (*sa).sin6_flowinfo = v6.flowinfo();
                (*sa).sin6_addr.s6_addr = v6.ip().octets();
                (*sa).sin6_scope_id = v6.scope_id();
            }
            std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t
        }
    };

    // Prepare iovec
    let iov = libc::iovec {
        iov_base: buf.as_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };

    // Prepare cmsg buffer for SCM_TXTIME
    let cmsg_space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<u64>() as u32) };
    let mut cmsg_buf = vec![0u8; cmsg_space as usize];

    // Prepare msghdr
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = &storage as *const _ as *mut libc::c_void;
    msg.msg_namelen = socklen;
    msg.msg_iov = &iov as *const _ as *mut libc::iovec;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = cmsg_space as usize;

    // Set up cmsg header for txtime
    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if !cmsg.is_null() {
            (*cmsg).cmsg_level = libc::SOL_SOCKET;
            (*cmsg).cmsg_type = SCM_TXTIME;
            (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<u64>() as u32) as usize;
            let data = libc::CMSG_DATA(cmsg) as *mut u64;
            *data = txtime_ns;
        }
    }

    // Send with sendmsg
    let ret = unsafe { libc::sendmsg(socket.as_raw_fd(), &msg, 0) };
    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }

    Ok(())
}
