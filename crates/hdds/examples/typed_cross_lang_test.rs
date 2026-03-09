// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Typed cross-language test: Rust pub/sub with generated CDR2 types.
//!
//! Usage:
//!     cargo run --release --example typed_cross_lang_test -- pub <topic> <count>
//!     cargo run --release --example typed_cross_lang_test -- sub <topic> <count>
//!
//! The publisher creates SensorReading with deterministic values, encodes to
//! CDR2, prepends the 4-byte encapsulation header (CDR2 LE), and writes the
//! raw payload. The subscriber reads raw, strips the encap header, decodes
//! CDR2, and validates all fields.

#![allow(clippy::uninlined_format_args)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]

use hdds::{Participant, QoS, TransportMode};
use std::time::{Duration, Instant};

// Include generated types (path set relative to crate root, via include!)
// The generated file brings its own use hdds::{Cdr2Encode, Cdr2Decode, CdrError};
include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../target/typed-test/interop_types.rs"
));

/// CDR2 LE encapsulation header: [0x00, 0x01, 0x00, 0x00]
const ENCAP_CDR2_LE: [u8; 4] = [0x00, 0x01, 0x00, 0x00];

fn create_test_message() -> SensorReading {
    SensorReading {
        sensor_id: 42,
        kind: SensorKind::PRESSURE,
        value: 3.15_f32,
        label: "test-sensor".to_string(),
        timestamp_ns: 1_700_000_000_000_000_000_i64,
        history: vec![1.0_f32, 2.0_f32, 3.0_f32],
        error_code: Some(7),
        location: GeoPoint {
            latitude: 48.8566_f64,
            longitude: 2.3522_f64,
        },
    }
}

fn validate_message(msg: &SensorReading) -> Vec<String> {
    let mut errs = Vec::new();

    if msg.sensor_id != 42 {
        errs.push(format!("sensor_id: got {}, want 42", msg.sensor_id));
    }
    if msg.kind != SensorKind::PRESSURE {
        errs.push(format!("kind: got {:?}, want PRESSURE", msg.kind));
    }
    if msg.value.to_le_bytes() != 3.15_f32.to_le_bytes() {
        errs.push(format!("value: got {}, want 3.15", msg.value));
    }
    if msg.label != "test-sensor" {
        errs.push(format!("label: got {:?}, want test-sensor", msg.label));
    }
    if msg.timestamp_ns != 1_700_000_000_000_000_000 {
        errs.push(format!("timestamp_ns: got {}", msg.timestamp_ns));
    }
    if msg.history.len() != 3 {
        errs.push(format!("history len: got {}, want 3", msg.history.len()));
    } else {
        let expected = [1.0_f32, 2.0_f32, 3.0_f32];
        for (i, (got, want)) in msg.history.iter().zip(&expected).enumerate() {
            if got.to_le_bytes() != want.to_le_bytes() {
                errs.push(format!("history[{}]: got {}, want {}", i, got, want));
            }
        }
    }
    if msg.error_code != Some(7) {
        errs.push(format!(
            "error_code: got {:?}, want Some(7)",
            msg.error_code
        ));
    }
    if (msg.location.latitude - 48.8566_f64).abs() > 1e-10 {
        errs.push(format!("latitude: got {}", msg.location.latitude));
    }
    if (msg.location.longitude - 2.3522_f64).abs() > 1e-10 {
        errs.push(format!("longitude: got {}", msg.location.longitude));
    }

    errs
}

fn run_pub(topic: &str, count: usize) -> Result<(), Box<dyn std::error::Error>> {
    let participant = Participant::builder("typed_rs_pub")
        .with_transport(TransportMode::UdpMulticast)
        .domain_id(0)
        .build()?;

    let qos = QoS::reliable()
        .transient_local()
        .keep_last((count + 5) as u32);

    let writer = participant.create_raw_writer(topic, Some(qos))?;

    std::thread::sleep(Duration::from_millis(300));

    for _i in 0..count {
        let msg = create_test_message();
        let mut cdr2_buf = vec![0u8; 4096];
        let enc = msg.encode_cdr2_le(&mut cdr2_buf)?;

        // Build payload: encap header + CDR2 bytes
        let mut payload = Vec::with_capacity(4 + enc);
        payload.extend_from_slice(&ENCAP_CDR2_LE);
        payload.extend_from_slice(&cdr2_buf[..enc]);

        writer.write_raw(&payload)?;
    }

    std::thread::sleep(Duration::from_secs(2));
    Ok(())
}

fn run_sub(topic: &str, count: usize) -> Result<(), Box<dyn std::error::Error>> {
    let participant = Participant::builder("typed_rs_sub")
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
    for (i, raw) in received.iter().enumerate() {
        if raw.len() < 4 {
            eprintln!("FAIL: sample {} too short ({} bytes)", i, raw.len());
            ok = false;
            continue;
        }

        // Strip 4-byte encap header, decode CDR2
        let cdr2_data = &raw[4..];
        match SensorReading::decode_cdr2_le(cdr2_data) {
            Ok((msg, _bytes_read)) => {
                let errs = validate_message(&msg);
                if !errs.is_empty() {
                    for e in &errs {
                        eprintln!("FAIL: sample {}: {}", i, e);
                    }
                    ok = false;
                }
            }
            Err(e) => {
                eprintln!("FAIL: decode error at sample {}: {:?}", i, e);
                ok = false;
            }
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
