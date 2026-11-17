// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Reliable-stream behaviour of the agent: retransmission driven by ACKNACK,
//! periodic HEARTBEAT, and FRAGMENT reassembly.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::thread::sleep;
use std::time::Duration;

use hdds_xrce::protocol::{
    fragment_message, parse_message, serialize_message, serialize_submessage, AcknackPayload,
    CreateClientPayload, CreatePayload, MessageHeader, ObjectKind, StatusCode, Submessage,
    WriteDataPayload, XrceError, XrceMessage,
};
use hdds_xrce::{ProxyBridge, TransportAddr, XrceAgent, XrceAgentConfig};

const CLIENT_KEY: [u8; 4] = [0x0A, 0x0B, 0x0C, 0x0D];
const RELIABLE_STREAM: u8 = 1;

/// Bridge that records the payloads handed to write_data.
#[derive(Default)]
struct WriteRecorder {
    writes: Mutex<Vec<Vec<u8>>>,
}

impl ProxyBridge for WriteRecorder {
    fn create_participant(&self, _domain_id: u16) -> Result<u32, XrceError> {
        Ok(1)
    }
    fn create_topic(&self, _p: u32, _n: &str, _t: &str) -> Result<u32, XrceError> {
        Ok(2)
    }
    fn create_writer(&self, _p: u32, _t: u32) -> Result<u32, XrceError> {
        Ok(3)
    }
    fn create_reader(&self, _p: u32, _t: u32) -> Result<u32, XrceError> {
        Ok(4)
    }
    fn write_data(&self, _writer_id: u32, data: &[u8]) -> Result<(), XrceError> {
        self.writes.lock().expect("lock").push(data.to_vec());
        Ok(())
    }
    fn read_data(&self, _reader_id: u32) -> Result<Option<Vec<u8>>, XrceError> {
        Ok(None)
    }
    fn delete_entity(&self, _entity_id: u32) -> Result<(), XrceError> {
        Ok(())
    }
}

fn peer() -> TransportAddr {
    TransportAddr::Udp(SocketAddr::from((Ipv4Addr::LOCALHOST, 40001)))
}

fn open_session(agent: &mut XrceAgent, from: &TransportAddr) -> u8 {
    let msg = XrceMessage {
        header: MessageHeader::with_key(0, 0, 0, CLIENT_KEY),
        submessages: vec![Submessage::CreateClient(CreateClientPayload {
            client_key: CLIENT_KEY,
            properties: 0,
        })],
    };
    let replies = agent.process_incoming(from, &serialize_message(&msg).expect("serialize"));
    let reply = parse_message(&replies[0].1).expect("parse STATUS");
    reply.header.session_id
}

fn agent_with(bridge: Arc<dyn ProxyBridge>, heartbeat_ms: u64) -> XrceAgent {
    let config = XrceAgentConfig {
        accepted_client_keys: vec![CLIENT_KEY],
        heartbeat_period_ms: heartbeat_ms,
        ..XrceAgentConfig::default()
    };
    XrceAgent::new(config, bridge).expect("agent")
}

#[test]
fn acknack_retransmits_the_frames_the_client_is_missing() {
    let mut agent = agent_with(Arc::new(WriteRecorder::default()), 1_000);
    let from = peer();
    let session_id = open_session(&mut agent, &from);

    // Three CREATE requests on a reliable stream produce three STATUS frames
    // with sequence numbers 0, 1, 2, all held for retransmission.
    let mut sent = Vec::new();
    for object_id in 0..3u16 {
        let msg = XrceMessage {
            header: MessageHeader::new(session_id, RELIABLE_STREAM, object_id),
            submessages: vec![Submessage::Create(CreatePayload {
                object_id,
                kind: ObjectKind::Participant,
                parent_id: 0,
                string_data: Vec::new(),
            })],
        };
        let replies = agent.process_incoming(&from, &serialize_message(&msg).expect("serialize"));
        assert_eq!(replies.len(), 1);
        sent.push(replies[0].1.clone());
    }
    let seqs: Vec<u16> = sent
        .iter()
        .map(|f| parse_message(f).expect("parse").header.sequence_nr)
        .collect();
    assert_eq!(seqs, vec![0, 1, 2]);

    // The client acknowledges 0 and reports 1 missing (bit 0 of the bitmap,
    // relative to first_unacked_seq = 1).
    let acknack = XrceMessage {
        header: MessageHeader::new(session_id, RELIABLE_STREAM, 9),
        submessages: vec![Submessage::Acknack(AcknackPayload {
            first_unacked_seq: 1,
            nack_bitmap: 0b01,
        })],
    };
    let replies = agent.process_incoming(&from, &serialize_message(&acknack).expect("serialize"));
    assert_eq!(replies.len(), 1, "the missing frame was not retransmitted");
    assert_eq!(
        replies[0].1, sent[1],
        "retransmission is not byte-identical"
    );

    // Sequence 0 was acknowledged, so it is gone and a second ACKNACK for it
    // retransmits nothing.
    let acknack = XrceMessage {
        header: MessageHeader::new(session_id, RELIABLE_STREAM, 10),
        submessages: vec![Submessage::Acknack(AcknackPayload {
            first_unacked_seq: 0,
            nack_bitmap: 0b1,
        })],
    };
    let replies = agent.process_incoming(&from, &serialize_message(&acknack).expect("serialize"));
    assert!(replies.is_empty(), "an acknowledged frame came back");
}

#[test]
fn heartbeat_is_emitted_only_while_frames_are_outstanding() {
    let mut agent = agent_with(Arc::new(WriteRecorder::default()), 20);
    let from = peer();
    let session_id = open_session(&mut agent, &from);

    // Nothing outstanding on a reliable stream yet: silence.
    sleep(Duration::from_millis(30));
    assert!(agent.due_heartbeats().is_empty());

    let msg = XrceMessage {
        header: MessageHeader::new(session_id, RELIABLE_STREAM, 0),
        submessages: vec![Submessage::Create(CreatePayload {
            object_id: 7,
            kind: ObjectKind::Participant,
            parent_id: 0,
            string_data: Vec::new(),
        })],
    };
    agent.process_incoming(&from, &serialize_message(&msg).expect("serialize"));

    sleep(Duration::from_millis(30));
    let beats = agent.due_heartbeats();
    assert_eq!(beats.len(), 1, "no HEARTBEAT for an outstanding frame");
    let beat = parse_message(&beats[0].1).expect("parse HEARTBEAT");
    assert_eq!(beat.header.stream_id, RELIABLE_STREAM);
    match &beat.submessages[0] {
        Submessage::Heartbeat(h) => {
            assert_eq!(h.first_unacked_seq, 0);
            assert_eq!(h.last_seq, 0);
        }
        other => panic!("expected HEARTBEAT, got {:?}", other),
    }

    // The period has just been reset, so an immediate second call is silent.
    assert!(agent.due_heartbeats().is_empty());
}

#[test]
fn fragmented_write_data_is_reassembled_and_delivered() {
    let bridge = Arc::new(WriteRecorder::default());
    let mut agent = agent_with(bridge.clone(), 1_000);
    let from = peer();
    let session_id = open_session(&mut agent, &from);

    // participant -> topic -> writer, so WRITE_DATA has somewhere to land.
    for (object_id, kind) in [
        (1u16, ObjectKind::Participant),
        (2, ObjectKind::Topic),
        (3, ObjectKind::DataWriter),
    ] {
        let msg = XrceMessage {
            header: MessageHeader::new(session_id, 0, 0),
            submessages: vec![Submessage::Create(CreatePayload {
                object_id,
                kind,
                parent_id: 1,
                string_data: if kind == ObjectKind::Topic {
                    let mut d = hdds_xrce::encode_string("Chatter").expect("topic name");
                    d.extend_from_slice(&hdds_xrce::encode_string("String").expect("type name"));
                    d
                } else {
                    Vec::new()
                },
            })],
        };
        let replies = agent.process_incoming(&from, &serialize_message(&msg).expect("serialize"));
        let reply = parse_message(&replies[0].1).expect("parse");
        match &reply.submessages[0] {
            Submessage::Status(s) => assert_eq!(s.status, StatusCode::Ok, "create {}", object_id),
            other => panic!("expected STATUS, got {:?}", other),
        }
    }

    // A WRITE_DATA far larger than one 64-byte fragment.
    let payload: Vec<u8> = (0..300u32).map(|i| (i % 251) as u8).collect();
    let body = serialize_submessage(&Submessage::WriteData(WriteDataPayload {
        writer_id: 3,
        data: payload.clone(),
    }))
    .expect("serialize WRITE_DATA");
    let header = MessageHeader::new(session_id, RELIABLE_STREAM, 0);
    let frames = fragment_message(&header, &body, 64).expect("fragment");
    assert!(frames.len() > 4, "expected several fragments");

    for (i, frame) in frames.iter().enumerate() {
        let replies = agent.process_incoming(&from, frame);
        if i + 1 < frames.len() {
            assert!(replies.is_empty(), "fragment {} answered early", i);
            assert!(
                bridge.writes.lock().expect("lock").is_empty(),
                "partial message reached DDS"
            );
        }
    }

    let writes = bridge.writes.lock().expect("lock");
    assert_eq!(writes.len(), 1, "reassembled sample never reached DDS");
    assert_eq!(writes[0], payload);
}

#[test]
fn an_oversized_reassembly_is_dropped_not_buffered() {
    let config = XrceAgentConfig {
        accepted_client_keys: vec![CLIENT_KEY],
        max_reassembled_size: 512,
        ..XrceAgentConfig::default()
    };
    let mut agent = XrceAgent::new(config, Arc::new(WriteRecorder::default())).expect("agent");
    let from = peer();
    let session_id = open_session(&mut agent, &from);

    let body = vec![0xAAu8; 4096];
    let header = MessageHeader::new(session_id, RELIABLE_STREAM, 0);
    let frames = fragment_message(&header, &body, 256).expect("fragment");
    for frame in &frames {
        agent.process_incoming(&from, frame);
    }
    // The session survives; the oversized message does not.
    assert_eq!(agent.session_count(), 1);
    let pending = agent
        .sessions()
        .get(session_id)
        .expect("session")
        .stream_states
        .get(&RELIABLE_STREAM)
        .map(|s| s.pending_fragment_bytes())
        .unwrap_or(0);
    assert!(pending <= 512, "buffer grew past the cap: {}", pending);
}
