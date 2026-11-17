// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! An XRCE client over a real UDP socket, bridged onto a real DDS domain.
//!
//! This is the announcement end to end: a constrained device speaking XRCE
//! appears on the DDS network, and a native HDDS reader receives its samples
//! with the client's own type name.
//!
//! Needs a multicast-capable interface (HDDS refuses loopback as the primary
//! interface), so it is a host test, run by the service-crates gate.

#![cfg(feature = "hdds")]

use std::net::{Ipv4Addr, UdpSocket};
use std::sync::Arc;
use std::thread::sleep;
use std::time::{Duration, Instant};

use hdds::dds::{Participant, QoS, TransportMode};
use hdds_xrce::bridge_hdds::HddsBridge;
use hdds_xrce::transport::UdpTransport;
use hdds_xrce::{ObjectKind, XrceAgent, XrceAgentConfig};
use hdds_xrce_client::{ClientEvent, ObjectKind as ClientObjectKind, XrceClient};

/// A domain of this suite's own, away from the engine tests.
const DOMAIN: u32 = 141;
const TOPIC: &str = "XrceChatter";
const TYPE_NAME: &str = "std_msgs::String";
const CLIENT_KEY: [u8; 4] = [0x5E, 0x50, 0x01, 0x02];

fn agent() -> XrceAgent {
    let config = XrceAgentConfig {
        accepted_client_keys: vec![CLIENT_KEY],
        max_message_size: 1024,
        ..XrceAgentConfig::default()
    };
    XrceAgent::new(
        config,
        Arc::new(HddsBridge::with_domain("hdds-xrce-agent-test", DOMAIN)),
    )
    .expect("agent")
}

/// Drive the agent until `done` or the deadline.
fn pump<F: FnMut() -> bool>(
    agent: &mut XrceAgent,
    transport: &mut UdpTransport,
    timeout: Duration,
    mut done: F,
) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        agent.tick(transport).expect("tick");
        if done() {
            return true;
        }
        sleep(Duration::from_millis(10));
    }
    done()
}

#[test]
fn an_xrce_client_publishes_onto_a_dds_topic_and_reads_back() {
    // A native participant that plays the rest of the DDS network.
    let native = Participant::builder("xrce-native-peer")
        .domain_id(DOMAIN)
        .with_transport(TransportMode::UdpMulticast)
        .build()
        .expect("native participant");
    let native_reader = native
        .create_raw_reader_with_type(TOPIC, TYPE_NAME, None, None, None)
        .expect("native reader");
    // DDS-XRCE v1.0 Sec.7.7.1: every payload an agent forwards to a client
    // is XCDR version 2. The bridge's reader (see HddsBridge::create_reader)
    // now requests XCDR2 only, so this writer must actually offer XCDR2 --
    // a default (XCDR1) writer would simply not match it, by design; see
    // `a_bridge_reader_only_accepts_xcdr2_per_xrce_spec.rs` for that case.
    let native_writer = native
        .create_raw_writer_with_type(
            TOPIC,
            TYPE_NAME,
            Some(QoS::default().data_representation_xcdr2()),
            None,
            None,
        )
        .expect("native writer");

    let mut transport = UdpTransport::bind(0).expect("agent socket");
    let agent_addr = transport.local_addr().expect("agent addr");
    let mut agent = agent();

    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("client socket");
    socket
        .set_read_timeout(Some(Duration::from_millis(200)))
        .expect("timeout");
    let mut client = XrceClient::new(CLIENT_KEY);
    let mut buf = [0u8; 1024];
    let mut rx = [0u8; 1024];

    // A tiny request/response helper: send, pump the agent, read the answer.
    let mut exchange = |agent: &mut XrceAgent,
                        transport: &mut UdpTransport,
                        client: &mut XrceClient,
                        frame: &[u8]|
     -> Vec<u8> {
        socket.send_to(frame, agent_addr).expect("send");
        let mut answer = Vec::new();
        pump(agent, transport, Duration::from_secs(10), || {
            match socket.recv_from(&mut rx) {
                Ok((n, _)) => {
                    answer = rx[..n].to_vec();
                    true
                }
                Err(_) => false,
            }
        });
        let _ = client;
        answer
    };

    // CREATE_CLIENT
    let n = client.create_client(&mut buf).expect("create_client");
    let reply = exchange(&mut agent, &mut transport, &mut client, &buf[..n]);
    assert!(!reply.is_empty(), "no STATUS for CREATE_CLIENT");
    match client.process(&reply).expect("status") {
        ClientEvent::Status { status, .. } => {
            assert!(
                hdds_xrce_client::status_is_ok(status),
                "status {:#x}",
                status
            )
        }
        other => panic!("expected STATUS, got {:?}", other),
    }

    // participant / topic / writer / reader
    let mut strings = [0u8; 128];
    let mut len = hdds_xrce_client::encode_string(&mut strings, TOPIC).expect("topic name");
    len += hdds_xrce_client::encode_string(&mut strings[len..], TYPE_NAME).expect("type name");

    for (object_id, kind, payload) in [
        (1u16, ClientObjectKind::Participant, 0..0),
        (2, ClientObjectKind::Topic, 0..len),
        (3, ClientObjectKind::DataWriter, 0..0),
        (4, ClientObjectKind::DataReader, 0..0),
    ] {
        let n = client
            .create_object(&mut buf, object_id, kind, 1, &strings[payload])
            .expect("create_object");
        let reply = exchange(&mut agent, &mut transport, &mut client, &buf[..n]);
        match client.process(&reply).expect("status") {
            ClientEvent::Status { status, .. } => assert!(
                hdds_xrce_client::status_is_ok(status),
                "object {} refused with {:#x}",
                object_id,
                status
            ),
            other => panic!("expected STATUS, got {:?}", other),
        }
    }

    // Let SEDP match the bridge's endpoints with the native peer's.
    let match_deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < match_deadline {
        agent.tick(&mut transport).expect("tick");
        sleep(Duration::from_millis(20));
    }

    // Client -> DDS.
    let sample = [0x11u8, 0x22, 0x33, 0x44, 0x55];
    let n = client
        .write_data(&mut buf, 0, 3, &sample)
        .expect("write_data");
    exchange(&mut agent, &mut transport, &mut client, &buf[..n]);

    let mut received: Option<Vec<u8>> = None;
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline && received.is_none() {
        agent.tick(&mut transport).expect("tick");
        for s in native_reader.try_take_raw().expect("take") {
            received = Some(s.payload);
        }
        sleep(Duration::from_millis(20));
    }
    assert_eq!(
        received.as_deref(),
        Some(&sample[..]),
        "the native DDS reader never saw the MCU's sample"
    );

    // DDS -> client: the native peer writes, the client asks for the sample.
    let answer = [0xAAu8, 0xBB, 0xCC];
    native_writer.write_raw(&answer).expect("native write");

    // The bridge participant owns both the writer and the reader for this
    // topic, so the client's own sample comes back on its reader too. Keep
    // reading until the native peer's sample shows up.
    let mut seen: Vec<Vec<u8>> = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline && !seen.iter().any(|s| s.as_slice() == answer) {
        let n = client.read_data(&mut buf, 4, 1).expect("read_data");
        let reply = exchange(&mut agent, &mut transport, &mut client, &buf[..n]);
        if reply.is_empty() {
            continue;
        }
        if let ClientEvent::Data { reader_id, payload } = client.process(&reply).expect("event") {
            assert_eq!(reader_id, 4);
            seen.push(payload.to_vec());
        }
        sleep(Duration::from_millis(20));
    }
    assert!(
        seen.iter().any(|s| s.as_slice() == answer),
        "the MCU never received the native peer's sample; it saw {:?}",
        seen
    );

    // The XRCE object kinds and the DDS entities line up.
    assert_eq!(ObjectKind::DataWriter.as_u8(), 0x05);
}
