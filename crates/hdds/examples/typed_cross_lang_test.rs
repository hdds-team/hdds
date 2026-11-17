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
//!
//! `pub-default` / `sub-default`: a typed `DataWriter<SensorReading>` /
//! `DataReader<SensorReading>` that set no DATA_REPRESENTATION, as an
//! application creates them. The writer offers XCDR (DDS-XTypes 1.3
//! 7.6.3.1.1, the generated type encodes XCDR1 natively) and encodes every
//! sample in it; the reader requests XCDR and XCDR2 and decodes either.
//!
//! The extensibility lanes (topic `ExtFinal*`, `ExtAppendable*`,
//! `ExtMutable*`: `FinalProbe`, `SensorReading`, `MutableProbe`):
//! `probe` receives the DATA an SDK writer sends to it (an hdds-c built
//! with `test-support`, `HDDS_TEST_CAPTURE_DATA=127.0.0.1:<port>`; the port
//! is the first line it prints), checks the encapsulation identifier names
//! the type's extensibility (DDS-XTypes 1.3 Table 60: `CDR2_LE`,
//! `D_CDR2_LE`, `PL_CDR2_LE`) and decodes the body; `sub-ext` is a typed
//! reader of the type.

use hdds::{Cdr2Decode, Cdr2Encode, Participant, QoS, TransportMode};
use std::time::{Duration, Instant};

// build.rs stages either the hddsgen output or a compile-only stub in OUT_DIR.
// Generated code is linted where it is generated (hdds_gen), not here: the
// real file trips clippy::useless_conversion and clippy::let_and_return,
// and this driver uses a fraction of its API (dead_code).
#[allow(unused, clippy::all, clippy::pedantic)]
mod interop_types {
    include!(concat!(env!("OUT_DIR"), "/typed-test/interop_types.rs"));
}
use interop_types::*;

/// CDR2 LE encapsulation header: [0x00, 0x01, 0x00, 0x00]
const ENCAP_CDR2_LE: [u8; 4] = [0x00, 0x01, 0x00, 0x00];

fn is_keyed_topic(topic: &str) -> bool {
    topic.starts_with("Keyed")
}

fn create_keyed_message() -> KeyedSample {
    KeyedSample {
        id: 99,
        active: true,
        kind: SensorKind::HUMIDITY,
        name: "device-alpha".to_string(),
        origin: GeoPoint {
            latitude: 37.7749_f64,
            longitude: -122.4194_f64,
        },
        reading: 1.618_f32,
    }
}

fn validate_keyed_message(msg: &KeyedSample) -> Vec<String> {
    let mut errs = Vec::new();
    if msg.id != 99 {
        errs.push(format!("id: got {}, want 99", msg.id));
    }
    if !msg.active {
        errs.push("active: got false, want true".to_string());
    }
    if msg.kind != SensorKind::HUMIDITY {
        errs.push(format!("kind: got {:?}, want HUMIDITY", msg.kind));
    }
    if msg.name != "device-alpha" {
        errs.push(format!("name: got {:?}, want device-alpha", msg.name));
    }
    if (msg.origin.latitude - 37.7749_f64).abs() > 1e-10 {
        errs.push(format!("origin.latitude: got {}", msg.origin.latitude));
    }
    if (msg.origin.longitude - (-122.4194_f64)).abs() > 1e-10 {
        errs.push(format!("origin.longitude: got {}", msg.origin.longitude));
    }
    if msg.reading.to_le_bytes() != 1.618_f32.to_le_bytes() {
        errs.push(format!("reading: got {}, want 1.618", msg.reading));
    }
    errs
}

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

fn run_vector(topic: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut buf = vec![0u8; 4096];
    let len = if is_keyed_topic(topic) {
        create_keyed_message().encode_cdr2_le(&mut buf)?
    } else {
        create_test_message().encode_cdr2_le(&mut buf)?
    };
    for byte in &buf[..len] {
        print!("{byte:02x}");
    }
    println!();
    Ok(())
}

fn run_pub(topic: &str, count: usize) -> Result<(), Box<dyn std::error::Error>> {
    let participant = Participant::builder("typed_rs_pub")
        .with_transport(TransportMode::UdpMulticast)
        .domain_id(0)
        .build()?;

    // The bytes are XCDR2: say so. A raw writer that sets no list offers
    // XCDR (DDS-XTypes 1.3 7.6.3.1.1) and would label them XCDR1.
    let qos = QoS::reliable()
        .transient_local()
        .keep_last((count + 5) as u32)
        .data_representation_xcdr2();

    let writer = participant.create_raw_writer(topic, Some(qos))?;

    std::thread::sleep(Duration::from_millis(300));

    let keyed = is_keyed_topic(topic);
    for _i in 0..count {
        let mut cdr2_buf = vec![0u8; 4096];
        let enc = if keyed {
            let msg = create_keyed_message();
            msg.encode_cdr2_le(&mut cdr2_buf)?
        } else {
            let msg = create_test_message();
            msg.encode_cdr2_le(&mut cdr2_buf)?
        };

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
    let keyed = is_keyed_topic(topic);
    let mut ok = true;
    for (i, raw) in received.iter().enumerate() {
        if raw.len() < 4 {
            eprintln!("FAIL: sample {} too short ({} bytes)", i, raw.len());
            ok = false;
            continue;
        }

        // Strip 4-byte encap header, decode CDR2
        let cdr2_data = &raw[4..];
        let decode_errs: Vec<String> = if keyed {
            match KeyedSample::decode_cdr2_le(cdr2_data) {
                Ok((msg, _)) => validate_keyed_message(&msg),
                Err(e) => vec![format!("decode error: {:?}", e)],
            }
        } else {
            match SensorReading::decode_cdr2_le(cdr2_data) {
                Ok((msg, _)) => validate_message(&msg),
                Err(e) => vec![format!("decode error: {:?}", e)],
            }
        };
        if !decode_errs.is_empty() {
            for e in &decode_errs {
                eprintln!("FAIL: sample {}: {}", i, e);
            }
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

fn run_pub_default(topic: &str, count: usize) -> Result<(), Box<dyn std::error::Error>> {
    let participant = Participant::builder("typed_rs_pub_default")
        .with_transport(TransportMode::UdpMulticast)
        .domain_id(0)
        .build()?;
    let qos = QoS::reliable()
        .transient_local()
        .keep_last((count + 5) as u32);
    let writer = participant
        .topic::<SensorReading>(topic)?
        .writer()
        .qos(qos)
        .build()?;
    if writer.qos().data_representation != [0x0000] {
        return Err(format!(
            "a default writer offers XCDR, this one {:?}",
            writer.qos().data_representation
        )
        .into());
    }
    std::thread::sleep(Duration::from_millis(300));
    for _ in 0..count {
        writer.write(&create_test_message())?;
    }
    std::thread::sleep(Duration::from_secs(2));
    Ok(())
}

fn run_sub_default(topic: &str, count: usize) -> Result<(), Box<dyn std::error::Error>> {
    let participant = Participant::builder("typed_rs_sub_default")
        .with_transport(TransportMode::UdpMulticast)
        .domain_id(0)
        .build()?;
    let qos = QoS::reliable()
        .transient_local()
        .keep_last((count + 5) as u32);
    let reader = participant
        .topic::<SensorReading>(topic)?
        .reader()
        .qos(qos)
        .build()?;
    let mut received = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(10);
    while received.len() < count && Instant::now() < deadline {
        match reader.take()? {
            Some(msg) => received.push(msg),
            None => std::thread::sleep(Duration::from_millis(50)),
        }
    }
    let mut ok = true;
    for (i, msg) in received.iter().enumerate() {
        for e in validate_message(msg) {
            eprintln!("FAIL: sample {i}: {e}");
            ok = false;
        }
    }
    if ok && received.len() == count {
        println!("OK: received {count}/{count} samples");
        Ok(())
    } else {
        eprintln!("FAIL: received {}/{} samples", received.len(), count);
        std::process::exit(1);
    }
}

/// The type of an extensibility lane and the identifier its samples carry.
#[derive(Clone, Copy, PartialEq)]
enum ExtLane {
    Final,
    Appendable,
    Mutable,
}

fn ext_lane(topic: &str) -> Option<(ExtLane, u16)> {
    if topic.starts_with("ExtFinal") {
        Some((ExtLane::Final, 0x0007))
    } else if topic.starts_with("ExtAppendable") {
        Some((ExtLane::Appendable, 0x0009))
    } else if topic.starts_with("ExtMutable") {
        Some((ExtLane::Mutable, 0x000b))
    } else {
        None
    }
}

const PROBE_ID: u32 = 7;
const PROBE_LABEL: &str = "ext-probe";

/// The errors of an extensibility lane's body (XCDR2), decoded as its type.
fn validate_ext_body(lane: ExtLane, body: &[u8]) -> Vec<String> {
    let probe = |id: u32, label: &str| {
        let mut errs = Vec::new();
        if id != PROBE_ID {
            errs.push(format!("id: got {id}, want {PROBE_ID}"));
        }
        if label != PROBE_LABEL {
            errs.push(format!("label: got {label:?}, want {PROBE_LABEL:?}"));
        }
        errs
    };
    let decoded = match lane {
        ExtLane::Final => FinalProbe::decode_cdr2_le(body).map(|(m, n)| (probe(m.id, &m.label), n)),
        ExtLane::Mutable => {
            MutableProbe::decode_cdr2_le(body).map(|(m, n)| (probe(m.id, &m.label), n))
        }
        ExtLane::Appendable => {
            SensorReading::decode_cdr2_le(body).map(|(m, n)| (validate_message(&m), n))
        }
    };
    match decoded {
        Ok((mut errs, n)) => {
            if n != body.len() {
                errs.push(format!("decoded {n} of {} bytes", body.len()));
            }
            errs
        }
        Err(e) => vec![format!("decode error: {e:?}")],
    }
}

/// Receive the DATA an SDK writer sends here, check its encapsulation
/// identifier and decode its body.
fn run_probe(topic: &str, count: usize) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Write as _;
    let (lane, want) = ext_lane(topic).ok_or("probe: not an Ext* topic")?;
    let socket = std::net::UdpSocket::bind("127.0.0.1:0")?;
    socket.set_read_timeout(Some(Duration::from_millis(500)))?;
    println!("PORT {}", socket.local_addr()?.port());
    std::io::stdout().flush()?;
    let mut payloads = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut buf = vec![0u8; 65536];
    while payloads.len() < count && Instant::now() < deadline {
        if let Ok((n, _)) = socket.recv_from(&mut buf) {
            payloads.extend(hdds::test_support::wire::data_payloads(&buf[..n]));
        }
    }
    let mut ok = payloads.len() >= count;
    for (i, (id, body)) in payloads.iter().enumerate() {
        if *id != want {
            eprintln!("FAIL: DATA {i}: encapsulation 0x{id:04x}, want 0x{want:04x}");
            ok = false;
        }
        for e in validate_ext_body(lane, body) {
            eprintln!("FAIL: DATA {i}: {e}");
            ok = false;
        }
    }
    if ok {
        println!(
            "OK: {} DATA on the wire, encap=0x{want:04x}, bodies decoded",
            payloads.len()
        );
        Ok(())
    } else {
        eprintln!(
            "FAIL: {} DATA received ({count} expected), each checked above",
            payloads.len()
        );
        std::process::exit(1);
    }
}

/// A typed reader of an extensibility lane's type.
fn run_sub_ext(topic: &str, count: usize) -> Result<(), Box<dyn std::error::Error>> {
    let (lane, _) = ext_lane(topic).ok_or("sub-ext: not an Ext* topic")?;
    let participant = Participant::builder("typed_rs_sub_ext")
        .with_transport(TransportMode::UdpMulticast)
        .domain_id(0)
        .build()?;
    let qos = QoS::reliable()
        .transient_local()
        .keep_last((count + 5) as u32);
    let mut errs = Vec::new();
    let mut received = 0usize;
    let deadline = Instant::now() + Duration::from_secs(10);
    macro_rules! take_all {
        ($t:ty, $check:expr) => {{
            let reader = participant
                .topic::<$t>(topic)?
                .reader()
                .qos(qos.clone())
                .build()?;
            while received < count && Instant::now() < deadline {
                match reader.take()? {
                    Some(msg) => {
                        received += 1;
                        let check: &dyn Fn(&$t) -> Vec<String> = &$check;
                        errs.extend(check(&msg));
                    }
                    None => std::thread::sleep(Duration::from_millis(50)),
                }
            }
        }};
    }
    let probe = |id: u32, label: &str| {
        let mut e = Vec::new();
        if id != PROBE_ID || label != PROBE_LABEL {
            e.push(format!("got ({id}, {label:?})"));
        }
        e
    };
    match lane {
        ExtLane::Final => take_all!(FinalProbe, |m: &FinalProbe| probe(m.id, &m.label)),
        ExtLane::Mutable => take_all!(MutableProbe, |m: &MutableProbe| probe(m.id, &m.label)),
        ExtLane::Appendable => take_all!(SensorReading, validate_message),
    }
    for e in &errs {
        eprintln!("FAIL: {e}");
    }
    if errs.is_empty() && received == count {
        println!("OK: received {count}/{count} samples");
        Ok(())
    } else {
        eprintln!("FAIL: received {received}/{count} samples");
        std::process::exit(1);
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        eprintln!("Usage: {} pub|sub|vector <topic> <count>", args[0]);
        std::process::exit(1);
    }

    let mode = &args[1];
    let topic = &args[2];
    let count: usize = args[3].parse().expect("count must be integer");

    let result = match mode.as_str() {
        "pub" => run_pub(topic, count),
        "sub" => run_sub(topic, count),
        "vector" => run_vector(topic),
        "pub-default" => run_pub_default(topic, count),
        "sub-default" => run_sub_default(topic, count),
        "probe" => run_probe(topic, count),
        "sub-ext" => run_sub_ext(topic, count),
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
