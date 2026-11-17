// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! "A restarting InfluxDB does not eat samples", end to end.
//!
//! The write client keeps its `&[String]` on a 5xx, but the runner drains the
//! sink buffers BEFORE it writes, so without somewhere to hold the drained
//! lines the promise was false the moment it left the HTTP layer.
//!
//! Its own test binary: several DDS participants created in ONE process on
//! the same domain interfere.
//!
//! Needs a multicast-capable interface (HDDS refuses loopback as the primary
//! interface), so it is a host test, run by the service-crates gate.

#![cfg(feature = "hdds")]

mod common;

use std::thread;
use std::time::{Duration, Instant};

use hdds::dds::{Participant, TransportMode};
use hdds_influx_sink::config::SinkConfig;
use hdds_influx_sink::runner::SinkRunner;

/// This crate's own DDS domain.
const DOMAIN: u32 = 143;
const TOPIC: &str = "InfluxOutageChatter";

fn config_yaml(port: u16) -> String {
    format!(
        r#"
influxdb:
  url: "http://127.0.0.1:{port}"
  org: "naskel"
  bucket: "telemetry"
  token: "sink-token"
sinks:
  - topic: "{TOPIC}"
    measurement: "chatter"
    tags: []
    fields:
      - data
    flush_interval_ms: 100
"#
    )
}

#[test]
fn a_server_outage_keeps_the_batch_for_the_next_flush() {
    // Three failing attempts (the client's retry budget), then a success.
    let (port, rx) = common::spawn_fake_influx_statuses(vec![503, 503, 503, 204]);

    let config = SinkConfig::from_yaml(&config_yaml(port)).expect("config");
    let mut runner = SinkRunner::new(config, DOMAIN, "influx-sink-outage").expect("runner");

    let publisher = Participant::builder("influx-sink-outage-publisher")
        .domain_id(DOMAIN)
        .with_transport(TransportMode::UdpMulticast)
        .build()
        .expect("publisher participant");
    let writer = publisher
        .create_raw_writer(TOPIC, None)
        .expect("raw writer");

    let text = b"survives-the-outage";
    let mut cdr = Vec::new();
    cdr.extend_from_slice(&((text.len() + 1) as u32).to_le_bytes());
    cdr.extend_from_slice(text);
    cdr.push(0);

    // Get one sample into the buffers, without letting the flush interval
    // fire against the failing server yet.
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline && runner.samples_recorded() == 0 {
        writer.write_raw(&cdr).expect("write");
        let _ = runner.tick();
        thread::sleep(Duration::from_millis(20));
    }
    assert!(
        runner.samples_recorded() >= 1,
        "no sample reached the sink to lose"
    );

    // The outage: the flush fails and the lines must NOT be gone.
    match runner.flush() {
        Err(e) => assert!(
            format!("{}", e).contains("unavailable"),
            "expected a server-unavailable flush, got {}",
            e
        ),
        Ok(n) => panic!("the flush claimed to write {} lines through a 503", n),
    }
    assert!(
        runner.pending_lines() >= 1,
        "the drained batch was dropped on the floor by a 503"
    );

    // The server comes back: the SAME lines arrive.
    let written = runner.flush().expect("the recovered flush");
    assert!(written >= 1);
    assert_eq!(runner.pending_lines(), 0);
    let mut body = None;
    for _ in 0..4 {
        if let Ok(received) = rx.recv_timeout(Duration::from_secs(5)) {
            if received.contains("survives-the-outage") {
                body = Some(received);
                break;
            }
        }
    }
    assert!(
        body.is_some(),
        "the batch that survived the outage never reached the recovered server"
    );
}
