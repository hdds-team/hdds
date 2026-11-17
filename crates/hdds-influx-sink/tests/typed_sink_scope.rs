// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! A TYPED DDS writer reaching the sink.
//!
//! The raw-to-raw proof next door publishes through an untyped writer, which
//! says nothing about the typed application writer a Grafana user actually
//! has. This test closes that scope: the sink is configured with the writer's
//! type name and the writer is a typed endpoint.
//!
//! Worth stating: an
//! untyped sink reader ALSO receives this typed writer on HDDS today - the
//! test passes with the `type_name` line ignored. So `type_name` is not a fix
//! for a broken match here; it exists so the sink announces the type name the
//! application uses, which is what a peer that does enforce type-name
//! matching will require.
//!
//! Its own test binary: several DDS participants created in ONE process on
//! the same domain interfere, and this proof is about matching.
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
const TOPIC: &str = "InfluxTypedChatter";
const TYPE_NAME: &str = "std_msgs::String";

fn typed_config_yaml(port: u16) -> String {
    format!(
        r#"
influxdb:
  url: "http://127.0.0.1:{port}"
  org: "naskel"
  bucket: "telemetry"
  token: "sink-token"
sinks:
  - topic: "{TOPIC}"
    type_name: "{TYPE_NAME}"
    measurement: "chatter"
    tags: []
    fields:
      - data
    flush_interval_ms: 100
"#
    )
}

#[test]
fn a_sink_configured_with_a_type_name_receives_a_typed_writer() {
    let (port, rx) = common::spawn_fake_influx(4);

    let config = SinkConfig::from_yaml(&typed_config_yaml(port)).expect("config");
    let mut runner = SinkRunner::new(config, DOMAIN, "influx-sink-typed").expect("runner");

    let publisher = Participant::builder("influx-sink-typed-publisher")
        .domain_id(DOMAIN)
        .with_transport(TransportMode::UdpMulticast)
        .build()
        .expect("publisher participant");
    let writer = publisher
        .create_raw_writer_with_type(TOPIC, TYPE_NAME, None, None, None)
        .expect("typed raw writer");

    let discovery_end = Instant::now() + Duration::from_millis(800);
    while Instant::now() < discovery_end {
        runner.tick().expect("tick");
        thread::sleep(Duration::from_millis(20));
    }

    // A ROS2 std_msgs/String-shaped payload: length, bytes, NUL.
    let text = b"typed-dds";
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
    let body = body.expect("a typed writer never reached the sink");
    assert!(
        body.contains("data=\"typed-dds\""),
        "expected the sample's field, got {:?}",
        body
    );
}
