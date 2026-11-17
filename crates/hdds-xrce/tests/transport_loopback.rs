// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Socket-level transport tests: the agent behind a real UDP socket and a
//! real TCP connection on loopback, plus the fail-closed bind policy.
//!
//! Hermetic: every socket binds 127.0.0.1 with port 0 and the test reads the
//! port back, so nothing depends on the host's interfaces or on a fixed port.

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, TcpStream, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant};

use hdds_xrce::protocol::{
    parse_message, serialize_message, CreateClientPayload, MessageHeader, StatusCode, Submessage,
    XrceMessage,
};
use hdds_xrce::transport::{tcp_frame, TcpTransport, UdpTransport, TCP_LENGTH_PREFIX_SIZE};
use hdds_xrce::{NullBridge, XrceAgent, XrceAgentConfig};

const CLIENT_KEY: [u8; 4] = [0xC0, 0xFF, 0xEE, 0x01];

fn agent() -> XrceAgent {
    let config = XrceAgentConfig {
        accepted_client_keys: vec![CLIENT_KEY],
        ..XrceAgentConfig::default()
    };
    XrceAgent::new(config, Arc::new(NullBridge)).expect("agent")
}

fn create_client_message(key: [u8; 4]) -> Vec<u8> {
    let msg = XrceMessage {
        header: MessageHeader::with_key(0, 0, 0, key),
        submessages: vec![Submessage::CreateClient(CreateClientPayload {
            client_key: key,
            properties: 0,
        })],
    };
    serialize_message(&msg).expect("serialize")
}

#[test]
fn udp_loopback_create_client_roundtrip() {
    let mut transport = UdpTransport::bind(0).expect("bind agent socket");
    let agent_addr = transport.local_addr().expect("agent addr");
    assert_eq!(agent_addr.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));

    let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("client socket");
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    client
        .send_to(&create_client_message(CLIENT_KEY), agent_addr)
        .expect("send CREATE_CLIENT");

    let mut agent = agent();
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline && agent.session_count() == 0 {
        agent.tick(&mut transport).expect("tick");
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(agent.session_count(), 1, "agent never opened the session");

    let mut buf = [0u8; 256];
    let (n, _) = client.recv_from(&mut buf).expect("STATUS reply");
    let reply = parse_message(&buf[..n]).expect("parse STATUS");
    // The agent hands out session ids in the range that carries no ClientKey.
    assert!(reply.header.session_id >= 0x80);
    assert!(reply.header.client_key.is_none());
    match &reply.submessages[0] {
        Submessage::Status(s) => assert_eq!(s.status, StatusCode::Ok),
        other => panic!("expected STATUS, got {:?}", other),
    }
}

#[test]
fn udp_unlisted_client_key_is_denied() {
    let mut transport = UdpTransport::bind(0).expect("bind agent socket");
    let agent_addr = transport.local_addr().expect("agent addr");

    let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("client socket");
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    client
        .send_to(&create_client_message([1, 2, 3, 4]), agent_addr)
        .expect("send CREATE_CLIENT");

    let mut agent = agent();
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut buf = [0u8; 256];
    loop {
        agent.tick(&mut transport).expect("tick");
        if let Ok((n, _)) = client.recv_from(&mut buf) {
            let reply = parse_message(&buf[..n]).expect("parse STATUS");
            match &reply.submessages[0] {
                Submessage::Status(s) => assert_eq!(s.status, StatusCode::ErrDenied),
                other => panic!("expected STATUS, got {:?}", other),
            }
            break;
        }
        assert!(Instant::now() < deadline, "no reply from the agent");
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(agent.session_count(), 0, "denied client got a session");
}

#[test]
fn tcp_length_framing_survives_a_split_stream() {
    let mut transport = TcpTransport::bind(0).expect("bind agent listener");
    let agent_addr = transport.local_addr().expect("agent addr");

    let mut client = TcpStream::connect(agent_addr).expect("connect");
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");

    // Send the framed message in two writes, splitting it inside the payload:
    // the pre-framing transport treated every read() as a datagram and would have
    // handed the agent half a message.
    let framed = tcp_frame(&create_client_message(CLIENT_KEY)).expect("frame");
    assert_eq!(
        u16::from_le_bytes([framed[0], framed[1]]) as usize,
        framed.len() - TCP_LENGTH_PREFIX_SIZE
    );
    let split = framed.len() / 2;
    client.write_all(&framed[..split]).expect("write head");
    std::thread::sleep(Duration::from_millis(20));
    client.write_all(&framed[split..]).expect("write tail");

    let mut agent = agent();
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline && agent.session_count() == 0 {
        agent.tick(&mut transport).expect("tick");
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(
        agent.session_count(),
        1,
        "agent never reassembled the frame"
    );

    // The reply is framed too.
    let mut prefix = [0u8; TCP_LENGTH_PREFIX_SIZE];
    client.read_exact(&mut prefix).expect("reply prefix");
    let len = u16::from_le_bytes(prefix) as usize;
    let mut body = vec![0u8; len];
    client.read_exact(&mut body).expect("reply body");
    let reply = parse_message(&body).expect("parse STATUS");
    match &reply.submessages[0] {
        Submessage::Status(s) => assert_eq!(s.status, StatusCode::Ok),
        other => panic!("expected STATUS, got {:?}", other),
    }
}

#[test]
fn wildcard_bind_is_refused_unless_asked_for() {
    match UdpTransport::bind_on(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0) {
        Ok(_) => panic!("UDP wildcard bind was accepted implicitly"),
        Err(e) => assert!(format!("{}", e).contains("wildcard"), "{}", e),
    }
    match TcpTransport::bind_on(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0) {
        Ok(_) => panic!("TCP wildcard bind was accepted implicitly"),
        Err(e) => assert!(format!("{}", e).contains("wildcard"), "{}", e),
    }
    // Explicit is allowed.
    let any = UdpTransport::bind_any(0).expect("explicit wildcard bind");
    assert!(any.local_addr().expect("addr").ip().is_unspecified());
}
