// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Admission is not only a door.
//!
//! The ClientKey list decides who may OPEN a session. These tests pin what
//! happens afterwards: every later submessage is bound to the address that
//! opened the session, a replayed sequence number is not executed twice, a
//! session that times out gives its DDS entities back, and a frame that does
//! not fit the agent's buffer is reported instead of silently truncated.

use std::collections::HashSet;
use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread::sleep;
use std::time::Duration;

use hdds_xrce::protocol::{
    parse_message, serialize_message, CreateClientPayload, CreatePayload, MessageHeader,
    ObjectKind, StatusCode, Submessage, WriteDataPayload, XrceError, XrceMessage,
};
use hdds_xrce::transport::{TcpTransport, XrceTransport};
use hdds_xrce::{ProxyBridge, TransportAddr, XrceAgent, XrceAgentConfig};

const CLIENT_KEY: [u8; 4] = [0x0A, 0x0B, 0x0C, 0x0D];
const STRANGER_KEY: [u8; 4] = [0xDE, 0xAD, 0xBE, 0xEF];

/// A bridge that records writes and tracks which entity handles are still
/// live, so a leak is visible instead of merely suspected.
#[derive(Default)]
struct CountingBridge {
    writes: Mutex<Vec<Vec<u8>>>,
    live: Mutex<HashSet<u32>>,
    next_handle: Mutex<u32>,
}

impl CountingBridge {
    fn mint(&self) -> u32 {
        let mut next = self.next_handle.lock().expect("lock");
        *next += 1;
        self.live.lock().expect("lock").insert(*next);
        *next
    }

    fn live_entities(&self) -> usize {
        self.live.lock().expect("lock").len()
    }

    fn writes(&self) -> Vec<Vec<u8>> {
        self.writes.lock().expect("lock").clone()
    }
}

impl ProxyBridge for CountingBridge {
    fn create_participant(&self, _domain_id: u16) -> Result<u32, XrceError> {
        Ok(self.mint())
    }
    fn create_topic(&self, _p: u32, _n: &str, _t: &str) -> Result<u32, XrceError> {
        Ok(self.mint())
    }
    fn create_writer(&self, _p: u32, _t: u32) -> Result<u32, XrceError> {
        Ok(self.mint())
    }
    fn create_reader(&self, _p: u32, _t: u32) -> Result<u32, XrceError> {
        Ok(self.mint())
    }
    fn write_data(&self, _writer_id: u32, data: &[u8]) -> Result<(), XrceError> {
        self.writes.lock().expect("lock").push(data.to_vec());
        Ok(())
    }
    fn read_data(&self, _reader_id: u32) -> Result<Option<Vec<u8>>, XrceError> {
        Ok(None)
    }
    fn delete_entity(&self, entity_id: u32) -> Result<(), XrceError> {
        self.live.lock().expect("lock").remove(&entity_id);
        Ok(())
    }
}

fn agent_with(bridge: Arc<dyn ProxyBridge>, session_timeout_ms: u64) -> XrceAgent {
    let config = XrceAgentConfig {
        accepted_client_keys: vec![CLIENT_KEY],
        session_timeout_ms,
        ..XrceAgentConfig::default()
    };
    XrceAgent::new(config, bridge).expect("agent")
}

fn addr(port: u16) -> TransportAddr {
    TransportAddr::Udp(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))
}

fn open_session(agent: &mut XrceAgent, from: &TransportAddr, key: [u8; 4]) -> Option<u8> {
    let msg = XrceMessage {
        header: MessageHeader::with_key(0, 0, 0, key),
        submessages: vec![Submessage::CreateClient(CreateClientPayload {
            client_key: key,
            properties: 0,
        })],
    };
    let replies = agent.process_incoming(from, &serialize_message(&msg).expect("serialize"));
    let reply = parse_message(&replies.first()?.1).expect("parse STATUS");
    match reply.submessages.first() {
        Some(Submessage::Status(s)) if s.status == StatusCode::Ok => Some(reply.header.session_id),
        _ => None,
    }
}

/// Build the participant + topic + writer chain a client needs before it can
/// publish, and return the writer's object id.
fn create_writer_chain(agent: &mut XrceAgent, from: &TransportAddr, session: u8, seq: &mut u16) {
    let mut send = |kind: ObjectKind, object_id: u16, parent_id: u16, string_data: Vec<u8>| {
        let msg = XrceMessage {
            header: MessageHeader::new(session, 0, *seq),
            submessages: vec![Submessage::Create(CreatePayload {
                object_id,
                kind,
                parent_id,
                string_data,
            })],
        };
        *seq = seq.wrapping_add(1);
        agent.process_incoming(from, &serialize_message(&msg).expect("serialize"));
    };
    send(ObjectKind::Participant, 1, 0, Vec::new());
    let mut strings = hdds_xrce::encode_string("Chatter").expect("topic name");
    strings.extend_from_slice(&hdds_xrce::encode_string("String").expect("type name"));
    send(ObjectKind::Topic, 2, 1, strings);
    send(ObjectKind::DataWriter, 10, 1, Vec::new());
}

fn write_data_message(session: u8, seq: u16, writer_id: u16, data: &[u8]) -> Vec<u8> {
    let msg = XrceMessage {
        header: MessageHeader::new(session, 0, seq),
        submessages: vec![Submessage::WriteData(WriteDataPayload {
            writer_id,
            data: data.to_vec(),
        })],
    };
    serialize_message(&msg).expect("serialize")
}

#[test]
fn an_unlisted_stranger_cannot_write_into_an_existing_session() {
    let bridge = Arc::new(CountingBridge::default());
    let mut agent = agent_with(bridge.clone(), 30_000);

    let client = addr(41001);
    let session = open_session(&mut agent, &client, CLIENT_KEY).expect("session");
    let mut seq = 0u16;
    create_writer_chain(&mut agent, &client, session, &mut seq);

    // The legitimate client publishes.
    agent.process_incoming(
        &client,
        &write_data_message(session, seq, 10, b"legitimate"),
    );
    assert_eq!(bridge.writes(), vec![b"legitimate".to_vec()]);

    // A stranger from another address, carrying no accepted ClientKey, aims
    // at the session id and the object id the legitimate client is using.
    // Session ids are handed out from a known base, so guessing is free.
    let stranger = addr(41002);
    assert!(
        open_session(&mut agent, &stranger, STRANGER_KEY).is_none(),
        "the admission list let an unlisted key open a session"
    );
    let denied_before = agent.denied_submessages();
    let replies = agent.process_incoming(
        &stranger,
        &write_data_message(session, seq + 1, 10, b"forged"),
    );

    assert_eq!(
        bridge.writes(),
        vec![b"legitimate".to_vec()],
        "an unauthenticated stranger published onto DDS through somebody else's session"
    );
    assert!(
        replies.is_empty(),
        "the stranger got an answer: {:?}",
        replies
    );
    assert_eq!(agent.denied_submessages(), denied_before + 1);

    // And the legitimate client is unharmed.
    agent.process_incoming(
        &client,
        &write_data_message(session, seq + 1, 10, b"still here"),
    );
    assert_eq!(
        bridge.writes(),
        vec![b"legitimate".to_vec(), b"still here".to_vec()]
    );
}

#[test]
fn a_stranger_cannot_delete_another_clients_objects() {
    let bridge = Arc::new(CountingBridge::default());
    let mut agent = agent_with(bridge.clone(), 30_000);

    let client = addr(41003);
    let session = open_session(&mut agent, &client, CLIENT_KEY).expect("session");
    let mut seq = 0u16;
    create_writer_chain(&mut agent, &client, session, &mut seq);
    let live = bridge.live_entities();
    assert_eq!(live, 3, "participant + topic + writer");

    let stranger = addr(41004);
    let msg = XrceMessage {
        header: MessageHeader::new(session, 0, seq),
        submessages: vec![Submessage::Delete(hdds_xrce::protocol::DeletePayload {
            object_id: 10,
        })],
    };
    agent.process_incoming(&stranger, &serialize_message(&msg).expect("serialize"));
    assert_eq!(
        bridge.live_entities(),
        live,
        "a stranger deleted another client's DDS entity"
    );
}

#[test]
fn a_timed_out_session_releases_its_dds_entities() {
    let bridge = Arc::new(CountingBridge::default());
    let mut agent = agent_with(bridge.clone(), 50);

    let client = addr(41005);
    let session = open_session(&mut agent, &client, CLIENT_KEY).expect("session");
    let mut seq = 0u16;
    create_writer_chain(&mut agent, &client, session, &mut seq);
    assert_eq!(bridge.live_entities(), 3, "participant + topic + writer");

    sleep(Duration::from_millis(120));
    let expired = agent.evict_expired();
    assert_eq!(expired, vec![session]);
    assert_eq!(
        bridge.live_entities(),
        0,
        "the session expired but its DDS entities are still live in the bridge"
    );
    assert_eq!(agent.session_count(), 0);
}

#[test]
fn a_replayed_write_data_is_executed_once() {
    let bridge = Arc::new(CountingBridge::default());
    let mut agent = agent_with(bridge.clone(), 30_000);

    let client = addr(41006);
    let session = open_session(&mut agent, &client, CLIENT_KEY).expect("session");
    let mut seq = 0u16;
    create_writer_chain(&mut agent, &client, session, &mut seq);

    // Reliable stream 1: the frame is captured once and replayed twice.
    let msg = XrceMessage {
        header: MessageHeader::new(session, 1, 0),
        submessages: vec![Submessage::WriteData(WriteDataPayload {
            writer_id: 10,
            data: b"once".to_vec(),
        })],
    };
    let frame = serialize_message(&msg).expect("serialize");
    agent.process_incoming(&client, &frame);
    agent.process_incoming(&client, &frame);
    agent.process_incoming(&client, &frame);

    assert_eq!(
        bridge.writes(),
        vec![b"once".to_vec()],
        "a replayed reliable WRITE_DATA was published more than once"
    );
}

#[test]
fn a_tcp_frame_larger_than_the_receive_buffer_is_reported_not_truncated() {
    let mut transport = TcpTransport::bind(0).expect("bind");
    let port = transport.local_addr().expect("addr").port();

    let mut client = TcpStream::connect(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))
        .expect("connect to the agent");
    // A correctly framed 600-byte message, sent to a 512-byte reader.
    let body = vec![0x5Au8; 600];
    let mut framed = (body.len() as u16).to_le_bytes().to_vec();
    framed.extend_from_slice(&body);
    client.write_all(&framed).expect("write");
    client.flush().expect("flush");

    let mut buf = [0u8; 512];
    let mut outcome = None;
    for _ in 0..200 {
        match transport.recv(&mut buf) {
            Ok((n, _)) => {
                outcome = Some(Ok(n));
                break;
            }
            Err(XrceError::Io(_)) => sleep(Duration::from_millis(5)),
            Err(e) => {
                outcome = Some(Err(e));
                break;
            }
        }
    }
    match outcome {
        Some(Err(XrceError::PayloadTooLarge(len))) => assert_eq!(len, 600),
        Some(Ok(n)) => panic!("the transport truncated a 600-byte frame to {} bytes", n),
        other => panic!("expected PayloadTooLarge, got {:?}", other),
    }
}

#[test]
fn a_submessage_payload_that_does_not_fit_the_length_field_is_refused() {
    let msg = XrceMessage {
        header: MessageHeader::new(0x80, 0, 0),
        submessages: vec![Submessage::WriteData(WriteDataPayload {
            writer_id: 10,
            // Two bytes of writer id plus this is one past u16::MAX.
            data: vec![0u8; u16::MAX as usize - 1],
        })],
    };
    match serialize_message(&msg) {
        Err(XrceError::PayloadTooLarge(len)) => assert_eq!(len, u16::MAX as usize + 1),
        other => panic!("expected PayloadTooLarge, got {:?}", other.map(|b| b.len())),
    }

    // One byte less fits, so the boundary is where it says it is.
    let ok = XrceMessage {
        header: MessageHeader::new(0x80, 0, 0),
        submessages: vec![Submessage::WriteData(WriteDataPayload {
            writer_id: 10,
            data: vec![0u8; u16::MAX as usize - 2],
        })],
    };
    assert!(serialize_message(&ok).is_ok());
}
