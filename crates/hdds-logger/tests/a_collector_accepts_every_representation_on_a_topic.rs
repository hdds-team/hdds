// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Item 6's QoS-cloning pattern, found a fourth time in
//! `LogCollector::run_with_processor`: the raw reader's QoS was built by
//! cloning the first discovered WRITER's resolved (single-element)
//! `data_representation` onto the READER. That field is directional (a
//! writer announces one offer, a reader its whole acceptance list), so
//! the reader ended up restricted to whichever representation the first
//! log writer discovered on the topic happened to offer, and silently
//! never matched a second log writer on the same topic offering the
//! other one.
//!
//! Two raw writers on the SAME topic, one offering XCDR1 and one XCDR2
//! (DDS-XTypes v1.3 Sec.7.6.3.1.1: a writer offers and encodes exactly
//! one representation), each publishing one `rcl_interfaces/msg/Log`
//! shaped sample. The collector must receive both.

use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use hdds::dds::{Participant, QoS, TransportMode};
use hdds_logger::{LogCollector, LogConfig};

/// This crate's own DDS domain.
const DOMAIN: u32 = 144;
const TOPIC: &str = "rt/logger_mixed_representation";
const TYPE_NAME: &str = "rcl_interfaces/msg/Log";

/// Encode one `rcl_interfaces/msg/Log` sample. Every member here is at
/// most 4 bytes (no i64/u64/f64), so XCDR1 and XCDR2 produce the exact
/// same bytes for this type -- this test is about QoS matching, not
/// decode correctness (the decode-version case is covered where it can
/// actually differ, in hdds-influx-sink's tests).
fn encode_log(msg: &str) -> Vec<u8> {
    fn align4(buf: &mut Vec<u8>) {
        while !buf.len().is_multiple_of(4) {
            buf.push(0);
        }
    }
    fn push_str(buf: &mut Vec<u8>, s: &str) {
        align4(buf);
        let bytes = s.as_bytes();
        buf.extend_from_slice(&((bytes.len() + 1) as u32).to_le_bytes());
        buf.extend_from_slice(bytes);
        buf.push(0);
    }

    let mut buf = Vec::new();
    // A realistic nonzero Unix timestamp, NOT 0: strip_cdr_encapsulation
    // peeks the first two bytes as a big-endian representation_id and
    // strips them as a (fake) encapsulation header when they land in
    // 0x0000..=0x0003. sec=0 encodes as four zero bytes, which reads as
    // rep_id 0x0000 (CDR_BE) and corrupts this payload's own parse.
    buf.extend_from_slice(&1_700_000_000i32.to_le_bytes()); // sec
    buf.extend_from_slice(&0u32.to_le_bytes()); // nanosec
    buf.push(20); // level: INFO
    push_str(&mut buf, "test-node"); // name (aligns to 4 first)
    push_str(&mut buf, msg); // msg
    push_str(&mut buf, ""); // file
    push_str(&mut buf, ""); // function
    align4(&mut buf);
    buf.extend_from_slice(&0u32.to_le_bytes()); // line
    buf
}

fn wait_for(timeout: Duration, mut done: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if done() {
            return true;
        }
        thread::sleep(Duration::from_millis(20));
    }
    done()
}

#[test]
fn the_collector_receives_both_an_xcdr1_and_an_xcdr2_writer_on_one_topic() {
    let config = LogConfig::builder()
        .domain_id(DOMAIN)
        .topic_pattern(TOPIC)
        .build();
    let mut collector = LogCollector::new(config).expect("collector should build");
    let stop_handle = collector.stop_handle();

    let messages: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let messages_for_callback = Arc::clone(&messages);

    let collector_thread = thread::spawn(move || {
        collector
            .run_with_callback(move |entry| {
                messages_for_callback
                    .lock()
                    .unwrap()
                    .push(entry.message.clone());
            })
            .expect("collector run should not error");
    });

    let publisher = Participant::builder("logger-mixed-repr-publisher")
        .domain_id(DOMAIN)
        .with_transport(TransportMode::UdpMulticast)
        .build()
        .expect("publisher participant");
    let w1 = publisher
        .create_raw_writer_with_type(
            TOPIC,
            TYPE_NAME,
            Some(QoS::reliable().data_representation_xcdr1()),
            None,
            None,
        )
        .expect("xcdr1 writer");
    let w2 = publisher
        .create_raw_writer_with_type(
            TOPIC,
            TYPE_NAME,
            Some(QoS::reliable().data_representation_xcdr2()),
            None,
            None,
        )
        .expect("xcdr2 writer");

    // Let the collector discover the topic (its own 1s discovery tick)
    // before the first writer exists, same as its production startup.
    thread::sleep(Duration::from_millis(1500));

    w1.write_raw(&encode_log("from-xcdr1")).expect("w1 write");
    thread::sleep(Duration::from_millis(1500));
    w2.write_raw(&encode_log("from-xcdr2")).expect("w2 write");

    let settled = wait_for(Duration::from_secs(10), || {
        let got = messages.lock().unwrap();
        got.iter().any(|m| m == "from-xcdr1") && got.iter().any(|m| m == "from-xcdr2")
    });

    stop_handle.stop();
    let _ = collector_thread.join();

    let got = messages.lock().unwrap();
    assert!(
        settled,
        "collector must receive both the XCDR1 and the XCDR2 writer's sample; got {got:?}"
    );
}
