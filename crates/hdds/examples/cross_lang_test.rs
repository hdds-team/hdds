// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Cross-language test helper: Rust pub/sub.
//!
//! Usage:
//!     cargo run --release --example cross_lang_test -- pub <topic> <count>
//!     cargo run --release --example cross_lang_test -- sub <topic> <count>

#![allow(clippy::uninlined_format_args)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]

use hdds::{Participant, QoS, TransportMode};
use std::time::{Duration, Instant};

fn run_pub(topic: &str, count: usize) -> Result<(), Box<dyn std::error::Error>> {
    let participant = Participant::builder("xtest_rs_pub")
        .with_transport(TransportMode::UdpMulticast)
        .domain_id(0)
        .build()?;

    let qos = QoS::reliable()
        .transient_local()
        .keep_last((count + 5) as u32);

    let writer = participant.create_raw_writer(topic, Some(qos))?;

    // Let discovery happen
    std::thread::sleep(Duration::from_millis(300));

    for i in 0..count {
        let payload = format!("XTEST-{}", i);
        writer.write_raw(payload.as_bytes())?;
    }

    // Keep alive for late joiners
    std::thread::sleep(Duration::from_secs(2));
    Ok(())
}

fn run_sub(topic: &str, count: usize) -> Result<(), Box<dyn std::error::Error>> {
    let participant = Participant::builder("xtest_rs_sub")
        .with_transport(TransportMode::UdpMulticast)
        .domain_id(0)
        .build()?;

    let qos = QoS::reliable()
        .transient_local()
        .keep_last((count + 5) as u32);

    let reader = participant.create_raw_reader(topic, Some(qos))?;

    let mut received: Vec<Vec<u8>> = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(10);

    while received.len() < count && Instant::now() < deadline {
        let samples = reader.try_take_raw()?;
        if samples.is_empty() {
            std::thread::sleep(Duration::from_millis(50));
        } else {
            for s in samples {
                received.push(s.payload);
            }
        }
    }

    // Validate
    let mut ok = true;
    for i in 0..count {
        let expected = format!("XTEST-{}", i);
        if i < received.len() {
            if received[i] != expected.as_bytes() {
                eprintln!(
                    "MISMATCH at {}: got {:?}, want {:?}",
                    i,
                    String::from_utf8_lossy(&received[i]),
                    expected
                );
                ok = false;
            }
        } else {
            eprintln!("MISSING sample {}", i);
            ok = false;
        }
    }

    if ok && received.len() == count {
        println!("OK: received {}/{} samples", count, count);
        Ok(())
    } else {
        eprintln!("FAIL: received {}/{} samples", received.len(), count);
        std::process::exit(1);
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        eprintln!("Usage: {} pub|sub <topic> <count>", args[0]);
        std::process::exit(1);
    }

    let mode = &args[1];
    let topic = &args[2];
    let count: usize = args[3].parse().expect("count must be integer");

    let result = match mode.as_str() {
        "pub" => run_pub(topic, count),
        "sub" => run_sub(topic, count),
        _ => {
            eprintln!("Unknown mode: {}", mode);
            std::process::exit(1);
        }
    };

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}
