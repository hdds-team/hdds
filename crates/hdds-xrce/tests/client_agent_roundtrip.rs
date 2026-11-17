// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! The no_std client crate driven against the real agent, in memory.
//!
//! This is the proof behind "DDS-XRCE: agent/client protocol": before this
//! test there was an agent and no client at all.

use std::sync::{Arc, Mutex};

use hdds_xrce::protocol as agent_wire;
use hdds_xrce::{ProxyBridge, TransportAddr, XrceAgent, XrceAgentConfig, XrceError};
use hdds_xrce_client::{ClientEvent, ObjectKind, XrceClient, CLIENT_STATE_BYTES};

const CLIENT_KEY: [u8; 4] = [0xC1, 0xE7, 0x00, 0x11];
const MTU: usize = 512;

/// A bridge that records writes and returns a canned sample on read.
struct LoopbackBridge {
    writes: Mutex<Vec<Vec<u8>>>,
    sample: Vec<u8>,
}

impl ProxyBridge for LoopbackBridge {
    fn create_participant(&self, _domain_id: u16) -> Result<u32, XrceError> {
        Ok(10)
    }
    fn create_topic(&self, _p: u32, _n: &str, _t: &str) -> Result<u32, XrceError> {
        Ok(11)
    }
    fn create_writer(&self, _p: u32, _t: u32) -> Result<u32, XrceError> {
        Ok(12)
    }
    fn create_reader(&self, _p: u32, _t: u32) -> Result<u32, XrceError> {
        Ok(13)
    }
    fn write_data(&self, _writer_id: u32, data: &[u8]) -> Result<(), XrceError> {
        self.writes.lock().expect("lock").push(data.to_vec());
        Ok(())
    }
    fn read_data(&self, _reader_id: u32) -> Result<Option<Vec<u8>>, XrceError> {
        Ok(Some(self.sample.clone()))
    }
    fn delete_entity(&self, _entity_id: u32) -> Result<(), XrceError> {
        Ok(())
    }
}

#[test]
fn wire_constants_match_the_agent() {
    assert_eq!(
        hdds_xrce_client::SUBMSG_CREATE_CLIENT,
        agent_wire::SUBMSG_CREATE_CLIENT
    );
    assert_eq!(hdds_xrce_client::SUBMSG_CREATE, agent_wire::SUBMSG_CREATE);
    assert_eq!(hdds_xrce_client::SUBMSG_DELETE, agent_wire::SUBMSG_DELETE);
    assert_eq!(hdds_xrce_client::SUBMSG_STATUS, agent_wire::SUBMSG_STATUS);
    assert_eq!(
        hdds_xrce_client::SUBMSG_WRITE_DATA,
        agent_wire::SUBMSG_WRITE_DATA
    );
    assert_eq!(
        hdds_xrce_client::SUBMSG_READ_DATA,
        agent_wire::SUBMSG_READ_DATA
    );
    assert_eq!(hdds_xrce_client::SUBMSG_DATA, agent_wire::SUBMSG_DATA);
    assert_eq!(hdds_xrce_client::SUBMSG_ACKNACK, agent_wire::SUBMSG_ACKNACK);
    assert_eq!(
        hdds_xrce_client::SUBMSG_HEARTBEAT,
        agent_wire::SUBMSG_HEARTBEAT
    );
    assert_eq!(
        hdds_xrce_client::SUBMSG_FRAGMENT,
        agent_wire::SUBMSG_FRAGMENT
    );
    assert_eq!(
        hdds_xrce_client::FLAG_LAST_FRAGMENT,
        agent_wire::FLAG_LAST_FRAGMENT
    );
    assert_eq!(
        hdds_xrce_client::SESSION_ID_WITHOUT_CLIENT_KEY,
        agent_wire::SESSION_ID_WITHOUT_CLIENT_KEY
    );
    assert_eq!(
        hdds_xrce_client::MAX_MESSAGE_HEADER_SIZE,
        agent_wire::MAX_MESSAGE_HEADER_SIZE
    );
    assert_eq!(hdds_xrce_client::STATUS_OK, agent_wire::STATUS_OK);
    assert_eq!(
        hdds_xrce_client::STATUS_ERR_DENIED,
        agent_wire::STATUS_ERR_DENIED
    );
    assert_eq!(hdds_xrce_client::OBJ_DATAWRITER, agent_wire::OBJ_DATAWRITER);
}

#[test]
fn client_full_session_against_agent_in_memory() {
    let bridge = Arc::new(LoopbackBridge {
        writes: Mutex::new(Vec::new()),
        sample: vec![0x51, 0x52, 0x53],
    });
    let config = XrceAgentConfig {
        accepted_client_keys: vec![CLIENT_KEY],
        ..XrceAgentConfig::default()
    };
    let mut agent = XrceAgent::new(config, bridge.clone()).expect("agent");
    let from = TransportAddr::Serial("/dev/null".to_string());

    let mut buf = [0u8; MTU];
    let mut client = XrceClient::new(CLIENT_KEY);

    // 1. CREATE_CLIENT -> STATUS, and the client adopts the session id.
    let n = client.create_client(&mut buf).expect("create_client");
    let replies = agent.process_incoming(&from, &buf[..n]);
    assert_eq!(replies.len(), 1);
    match client.process(&replies[0].1).expect("status") {
        ClientEvent::Status { status, .. } => {
            assert!(
                hdds_xrce_client::status_is_ok(status),
                "status {:#x}",
                status
            )
        }
        other => panic!("expected STATUS, got {:?}", other),
    }
    assert!(client.is_connected());
    assert!(client.session_id() >= 0x80);

    // 2. participant, topic, writer, reader.
    let mut strings = [0u8; 64];
    let mut len = hdds_xrce_client::encode_string(&mut strings, "Chatter").expect("topic name");
    len += hdds_xrce_client::encode_string(&mut strings[len..], "String").expect("type name");

    for (object_id, kind, payload) in [
        (1u16, ObjectKind::Participant, &strings[..0]),
        (2, ObjectKind::Topic, &strings[..len]),
        (3, ObjectKind::DataWriter, &strings[..0]),
        (4, ObjectKind::DataReader, &strings[..0]),
    ] {
        let n = client
            .create_object(&mut buf, object_id, kind, 1, payload)
            .expect("create_object");
        let replies = agent.process_incoming(&from, &buf[..n]);
        match client.process(&replies[0].1).expect("status") {
            ClientEvent::Status {
                object_id: id,
                status,
            } => {
                assert_eq!(id, object_id);
                assert!(
                    hdds_xrce_client::status_is_ok(status),
                    "object {} status {:#x}",
                    object_id,
                    status
                );
            }
            other => panic!("expected STATUS, got {:?}", other),
        }
    }

    // 3. WRITE_DATA reaches the DDS side byte for byte.
    let sample = [0xAAu8, 0xBB, 0xCC, 0xDD];
    let n = client
        .write_data(&mut buf, 0, 3, &sample)
        .expect("write_data");
    let replies = agent.process_incoming(&from, &buf[..n]);
    assert_eq!(replies.len(), 1);
    assert_eq!(bridge.writes.lock().expect("lock")[0], sample.to_vec());

    // 4. READ_DATA brings the sample back to the client.
    let n = client.read_data(&mut buf, 4, 1).expect("read_data");
    let replies = agent.process_incoming(&from, &buf[..n]);
    match client.process(&replies[0].1).expect("data") {
        ClientEvent::Data { reader_id, payload } => {
            assert_eq!(reader_id, 4);
            assert_eq!(payload, &[0x51, 0x52, 0x53]);
        }
        other => panic!("expected DATA, got {:?}", other),
    }

    // 5. DELETE.
    let n = client.delete_object(&mut buf, 3).expect("delete");
    let replies = agent.process_incoming(&from, &buf[..n]);
    match client.process(&replies[0].1).expect("status") {
        ClientEvent::Status { object_id, status } => {
            assert_eq!(object_id, 3);
            assert!(hdds_xrce_client::status_is_ok(status));
        }
        other => panic!("expected STATUS, got {:?}", other),
    }

    // The whole client session cost this much RAM, buffer included.
    let footprint = CLIENT_STATE_BYTES + MTU;
    assert!(
        footprint < 20 * 1024,
        "client footprint {} bytes",
        footprint
    );
}

#[test]
fn an_unlisted_client_key_is_denied_end_to_end() {
    let bridge = Arc::new(LoopbackBridge {
        writes: Mutex::new(Vec::new()),
        sample: Vec::new(),
    });
    let config = XrceAgentConfig {
        accepted_client_keys: vec![CLIENT_KEY],
        ..XrceAgentConfig::default()
    };
    let mut agent = XrceAgent::new(config, bridge).expect("agent");
    let from = TransportAddr::Serial("/dev/null".to_string());

    let mut buf = [0u8; MTU];
    let mut client = XrceClient::new([0xFF, 0xFF, 0xFF, 0xFF]);
    let n = client.create_client(&mut buf).expect("create_client");
    let replies = agent.process_incoming(&from, &buf[..n]);
    assert_eq!(replies.len(), 1);
    match client.process(&replies[0].1).expect("status") {
        ClientEvent::Status { status, .. } => {
            assert_eq!(status, hdds_xrce_client::STATUS_ERR_DENIED)
        }
        other => panic!("expected STATUS, got {:?}", other),
    }
    assert!(!client.is_connected());
    assert_eq!(agent.session_count(), 0);
}
