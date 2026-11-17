// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! A DDS sample published by a native HDDS writer arrives at InfluxDB as
//! Line Protocol, with a fake InfluxDB standing in for the database.
//!
//! Needs a multicast-capable interface (HDDS refuses loopback as the primary
//! interface), so it is a host test, run by the service-crates gate.

#![cfg(feature = "hdds")]

use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use hdds::dds::{Participant, TransportMode};
use hdds_influx_sink::config::SinkConfig;
use hdds_influx_sink::runner::SinkRunner;

/// This crate's own DDS domain.
const DOMAIN: u32 = 143;

/// Accept `count` requests, hand back the bodies, always answer 204.
fn spawn_fake_influx(count: usize) -> (u16, mpsc::Receiver<String>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind fake influx");
    let port = listener.local_addr().expect("addr").port();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        for _ in 0..count {
            let (mut stream, _) = match listener.accept() {
                Ok(v) => v,
                Err(_) => return,
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("timeout");
            let mut raw = Vec::new();
            let mut chunk = [0u8; 4096];
            loop {
                match stream.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => {
                        raw.extend_from_slice(&chunk[..n]);
                        let text = String::from_utf8_lossy(&raw).to_string();
                        if let Some(head_end) = text.find("\r\n\r\n") {
                            let len: usize = text[..head_end]
                                .lines()
                                .find_map(|l| {
                                    l.strip_prefix("Content-Length: ")
                                        .and_then(|v| v.trim().parse().ok())
                                })
                                .unwrap_or(0);
                            if text.len() >= head_end + 4 + len {
                                break;
                            }
                        }
                    }
                    Err(_) => break,
                }
            }
            let text = String::from_utf8_lossy(&raw).to_string();
            let body = text.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
            let _ = tx.send(body);
            let _ = stream.write_all(
                b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            );
        }
    });
    (port, rx)
}

fn config_yaml(port: u16, topic: &str) -> String {
    format!(
        r#"
influxdb:
  url: "http://127.0.0.1:{port}"
  org: "naskel"
  bucket: "telemetry"
  token: "sink-token"
sinks:
  - topic: "{topic}"
    measurement: "chatter"
    tags: []
    fields:
      - data
    flush_interval_ms: 100
"#
    )
}

#[test]
fn native_raw_write_lands_as_line_protocol_on_fake_influx() {
    const TOPIC: &str = "InfluxChatter";
    let (port, rx) = spawn_fake_influx(4);

    let config = SinkConfig::from_yaml(&config_yaml(port, TOPIC)).expect("config");
    let mut runner = SinkRunner::new(config, DOMAIN, "influx-sink-test").expect("runner");
    assert_eq!(runner.topics(), vec![TOPIC]);

    let publisher = Participant::builder("influx-sink-publisher")
        .domain_id(DOMAIN)
        .with_transport(TransportMode::UdpMulticast)
        .build()
        .expect("publisher participant");
    let writer = publisher
        .create_raw_writer(TOPIC, None)
        .expect("raw writer");

    // Discovery, with the runner already polling.
    let discovery_end = Instant::now() + Duration::from_millis(800);
    while Instant::now() < discovery_end {
        runner.tick().expect("tick");
        thread::sleep(Duration::from_millis(20));
    }

    // A ROS2 std_msgs/String-shaped payload: length, bytes, NUL. Without a
    // TypeObject the runner projects it through the raw fallback, which
    // yields {"data": "..."} - exactly the field the sink is configured on.
    let text = b"from-dds";
    let mut cdr = Vec::new();
    cdr.extend_from_slice(&((text.len() + 1) as u32).to_le_bytes());
    cdr.extend_from_slice(text);
    cdr.push(0);

    let mut body = None;
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline && body.is_none() {
        writer.write_raw(&cdr).expect("write");
        for _ in 0..20 {
            runner.tick().expect("tick");
            thread::sleep(Duration::from_millis(10));
        }
        if let Ok(received) = rx.recv_timeout(Duration::from_millis(50)) {
            body = Some(received);
        }
    }

    let body = body.expect("the fake InfluxDB never received a write");
    assert!(
        body.starts_with("chatter "),
        "expected the configured measurement, got {:?}",
        body
    );
    assert!(
        body.contains("data=\"from-dds\""),
        "expected the sample's field, got {:?}",
        body
    );
    // Line Protocol ends with a nanosecond timestamp.
    let timestamp = body.rsplit(' ').next().expect("timestamp");
    let ts: u64 = timestamp.trim().parse().expect("numeric timestamp");
    assert!(ts > 1_600_000_000_000_000_000, "timestamp {} is not ns", ts);
    assert!(runner.samples_recorded() >= 1);
    assert!(runner.lines_written() >= 1);
}

#[test]
fn an_unconfigured_topic_is_not_subscribed() {
    let (port, _rx) = spawn_fake_influx(1);
    let config = SinkConfig::from_yaml(&config_yaml(port, "OnlyThisTopic")).expect("config");
    let runner = SinkRunner::new(config, DOMAIN, "influx-sink-scope").expect("runner");
    assert_eq!(runner.topics(), vec!["OnlyThisTopic"]);
    assert_eq!(runner.samples_recorded(), 0);
}
