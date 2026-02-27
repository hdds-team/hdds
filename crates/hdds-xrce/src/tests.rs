// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

// Tests for hdds-xrce.
//
// 22+ tests covering protocol parsing/building, sessions, reliable streams,
// object CRUD, data paths, fragmentation, transport addresses, config, and
// full roundtrip scenarios.

use std::sync::{Arc, Mutex};

use crate::agent::XrceAgent;
use crate::config::XrceAgentConfig;
use crate::protocol::*;
use crate::proxy::{NullBridge, ProxyBridge};
use crate::session::*;
use crate::transport::TransportAddr;

// -----------------------------------------------------------------------
// 1. Protocol parsing: parse all submessage types from bytes
// -----------------------------------------------------------------------
#[test]
fn test_parse_all_submessage_types() {
    let submessages: Vec<Submessage> = vec![
        Submessage::CreateClient(CreateClientPayload {
            client_key: [0xDE, 0xAD, 0xBE, 0xEF],
            properties: 0x01,
        }),
        Submessage::Create(CreatePayload {
            object_id: 42,
            kind: ObjectKind::Participant,
            parent_id: 0,
            string_data: vec![],
        }),
        Submessage::Delete(DeletePayload { object_id: 42 }),
        Submessage::WriteData(WriteDataPayload {
            writer_id: 10,
            data: vec![1, 2, 3, 4],
        }),
        Submessage::ReadData(ReadDataPayload {
            reader_id: 20,
            max_samples: 5,
        }),
        Submessage::Data(DataPayload {
            reader_id: 20,
            data: vec![0xAA, 0xBB],
        }),
        Submessage::Status(StatusPayload {
            related_object_id: 42,
            status: StatusCode::Ok,
        }),
        Submessage::Heartbeat(HeartbeatPayload {
            first_unacked_seq: 1,
            last_seq: 5,
        }),
        Submessage::Acknack(AcknackPayload {
            first_unacked_seq: 3,
            nack_bitmap: 0x0005,
        }),
    ];

    for original in &submessages {
        let bytes = serialize_submessage(original);
        let (parsed, consumed) = parse_submessage(&bytes).unwrap();
        assert_eq!(&parsed, original);
        assert_eq!(consumed, bytes.len());
    }
}

// -----------------------------------------------------------------------
// 2. Protocol building: serialize all submessage types to bytes
// -----------------------------------------------------------------------
#[test]
fn test_serialize_all_submessage_types() {
    let msg = XrceMessage {
        header: MessageHeader {
            session_id: 1,
            stream_id: 0,
            sequence_nr: 100,
        },
        submessages: vec![
            Submessage::CreateClient(CreateClientPayload {
                client_key: [1, 2, 3, 4],
                properties: 0,
            }),
            Submessage::Status(StatusPayload {
                related_object_id: 0,
                status: StatusCode::Ok,
            }),
        ],
    };
    let bytes = serialize_message(&msg);
    let parsed = parse_message(&bytes).unwrap();
    assert_eq!(parsed.header, msg.header);
    assert_eq!(parsed.submessages.len(), 2);
    assert_eq!(parsed.submessages[0], msg.submessages[0]);
    assert_eq!(parsed.submessages[1], msg.submessages[1]);
}

// -----------------------------------------------------------------------
// 3. Session: create client, assign session_id
// -----------------------------------------------------------------------
#[test]
fn test_session_create_client() {
    let mut table = SessionTable::new(128, 30_000);
    let sid = table.create_session([1, 2, 3, 4]).unwrap();
    assert!(sid >= 1);
    assert_eq!(table.len(), 1);
    let session = table.get(sid).unwrap();
    assert_eq!(session.client_key, [1, 2, 3, 4]);
}

// -----------------------------------------------------------------------
// 4. Session: timeout expired client
// -----------------------------------------------------------------------
#[test]
fn test_session_timeout() {
    let mut table = SessionTable::new(128, 0); // 0ms timeout = immediate expiry
    let sid = table.create_session([1, 2, 3, 4]).unwrap();
    assert_eq!(table.len(), 1);
    // Sleep a tiny bit to ensure elapsed > 0
    std::thread::sleep(std::time::Duration::from_millis(1));
    let expired = table.evict_expired();
    assert!(expired.contains(&sid));
    assert_eq!(table.len(), 0);
}

// -----------------------------------------------------------------------
// 5. Session: max clients reached
// -----------------------------------------------------------------------
#[test]
fn test_session_max_clients() {
    let mut table = SessionTable::new(2, 30_000);
    table.create_session([1, 0, 0, 0]).unwrap();
    table.create_session([2, 0, 0, 0]).unwrap();
    let err = table.create_session([3, 0, 0, 0]).unwrap_err();
    assert_eq!(err, XrceError::SessionFull);
}

// -----------------------------------------------------------------------
// 6. Reliable stream: sequence number tracking
// -----------------------------------------------------------------------
#[test]
fn test_reliable_stream_sequence_tracking() {
    let mut stream = StreamState::new(StreamKind::Reliable);
    assert_eq!(stream.alloc_send_seq(), 0);
    assert_eq!(stream.alloc_send_seq(), 1);
    assert_eq!(stream.alloc_send_seq(), 2);
    assert_eq!(stream.next_send_seq, 3);
}

// -----------------------------------------------------------------------
// 7. Reliable stream: HEARTBEAT generation
// -----------------------------------------------------------------------
#[test]
fn test_reliable_stream_heartbeat() {
    let mut stream = StreamState::new(StreamKind::Reliable);
    let seq0 = stream.alloc_send_seq();
    stream.record_sent(seq0, vec![1, 2, 3]);
    let seq1 = stream.alloc_send_seq();
    stream.record_sent(seq1, vec![4, 5, 6]);

    let hb = stream.make_heartbeat();
    assert_eq!(hb.first_unacked_seq, 0);
    assert_eq!(hb.last_seq, 1);
}

// -----------------------------------------------------------------------
// 8. Reliable stream: ACKNACK processing
// -----------------------------------------------------------------------
#[test]
fn test_reliable_stream_acknack_processing() {
    let mut stream = StreamState::new(StreamKind::Reliable);
    for i in 0..5 {
        let seq = stream.alloc_send_seq();
        stream.record_sent(seq, vec![i]);
    }
    assert_eq!(stream.unacked.len(), 5);

    // Acknowledge everything before seq 3
    let ack = AcknackPayload {
        first_unacked_seq: 3,
        nack_bitmap: 0,
    };
    let retransmit = stream.process_acknack(&ack);
    assert!(retransmit.is_empty());
    // Sequences 0, 1, 2 should be removed
    assert!(!stream.unacked.contains_key(&0));
    assert!(!stream.unacked.contains_key(&1));
    assert!(!stream.unacked.contains_key(&2));
    assert!(stream.unacked.contains_key(&3));
    assert!(stream.unacked.contains_key(&4));
}

// -----------------------------------------------------------------------
// 9. Reliable stream: retransmission on gap (NACK bitmap)
// -----------------------------------------------------------------------
#[test]
fn test_reliable_stream_retransmission_on_gap() {
    let mut stream = StreamState::new(StreamKind::Reliable);
    for i in 0..5 {
        let seq = stream.alloc_send_seq();
        stream.record_sent(seq, vec![i]);
    }

    // NACK bitmap: bit 0 = seq 2 missing, bit 2 = seq 4 missing
    let ack = AcknackPayload {
        first_unacked_seq: 2,
        nack_bitmap: 0b0101, // bits 0 and 2
    };
    let retransmit = stream.process_acknack(&ack);
    assert!(retransmit.contains(&2));
    assert!(retransmit.contains(&4));
    assert_eq!(retransmit.len(), 2);
}

// -----------------------------------------------------------------------
// 10. Object creation: PARTICIPANT, TOPIC, WRITER, READER
// -----------------------------------------------------------------------
#[test]
fn test_object_creation() {
    let mut session = ClientSession::new(1, [0; 4]);
    session.add_object(XrceObject {
        object_id: 1,
        kind: ObjectKind::Participant,
        bridge_handle: 100,
    });
    session.add_object(XrceObject {
        object_id: 2,
        kind: ObjectKind::Topic,
        bridge_handle: 200,
    });
    session.add_object(XrceObject {
        object_id: 3,
        kind: ObjectKind::DataWriter,
        bridge_handle: 300,
    });
    session.add_object(XrceObject {
        object_id: 4,
        kind: ObjectKind::DataReader,
        bridge_handle: 400,
    });

    assert_eq!(session.objects.len(), 4);
    assert_eq!(session.get_object(1).unwrap().kind, ObjectKind::Participant);
    assert_eq!(session.get_object(2).unwrap().kind, ObjectKind::Topic);
    assert_eq!(session.get_object(3).unwrap().kind, ObjectKind::DataWriter);
    assert_eq!(session.get_object(4).unwrap().kind, ObjectKind::DataReader);
}

// -----------------------------------------------------------------------
// 11. Object deletion
// -----------------------------------------------------------------------
#[test]
fn test_object_deletion() {
    let mut session = ClientSession::new(1, [0; 4]);
    session.add_object(XrceObject {
        object_id: 42,
        kind: ObjectKind::Topic,
        bridge_handle: 999,
    });
    assert!(session.get_object(42).is_some());
    let removed = session.remove_object(42);
    assert!(removed.is_some());
    assert_eq!(removed.unwrap().bridge_handle, 999);
    assert!(session.get_object(42).is_none());
}

// -----------------------------------------------------------------------
// 12. Write data through proxy
// -----------------------------------------------------------------------
#[test]
fn test_write_data_through_proxy() {
    let bridge = RecordingBridge::new();
    let mut agent = make_agent(bridge.clone());

    // Create client
    let create_client_msg = make_create_client_msg();
    let from = TransportAddr::Udp("127.0.0.1:5000".parse().unwrap());
    let replies = agent.process_incoming(&from, &create_client_msg);
    assert!(!replies.is_empty());

    // Extract session_id from reply
    let reply = parse_message(&replies[0].1).unwrap();
    let session_id = reply.header.session_id;

    // Create a participant object (object_id=1)
    let create_part = make_create_msg(session_id, 1, ObjectKind::Participant, 0, &[]);
    agent.process_incoming(&from, &create_part);

    // Create a topic object (object_id=2)
    let topic_data = {
        let mut d = encode_string("TestTopic");
        d.extend_from_slice(&encode_string("TestType"));
        d
    };
    let create_topic = make_create_msg(session_id, 2, ObjectKind::Topic, 1, &topic_data);
    agent.process_incoming(&from, &create_topic);

    // Create a writer object (object_id=10)
    let create_writer = make_create_msg(session_id, 10, ObjectKind::DataWriter, 2, &[]);
    agent.process_incoming(&from, &create_writer);

    // Write data
    let write_msg = make_write_data_msg(session_id, 10, &[0xCA, 0xFE]);
    let replies = agent.process_incoming(&from, &write_msg);
    assert!(!replies.is_empty());

    // Verify bridge received the write
    let calls = bridge.calls.lock().unwrap();
    assert!(calls.contains(&"write_data".to_string()));
}

// -----------------------------------------------------------------------
// 13. Read data through proxy
// -----------------------------------------------------------------------
#[test]
fn test_read_data_through_proxy() {
    let bridge = DataBridge::new(vec![0xBE, 0xEF]);
    let mut agent = make_agent_with(bridge);

    let from = TransportAddr::Udp("127.0.0.1:5000".parse().unwrap());

    // Create client
    let create_client_msg = make_create_client_msg();
    let replies = agent.process_incoming(&from, &create_client_msg);
    let reply = parse_message(&replies[0].1).unwrap();
    let session_id = reply.header.session_id;

    // Create participant + topic + reader
    let create_part = make_create_msg(session_id, 1, ObjectKind::Participant, 0, &[]);
    agent.process_incoming(&from, &create_part);
    let topic_data = {
        let mut d = encode_string("TestTopic");
        d.extend_from_slice(&encode_string("TestType"));
        d
    };
    let create_topic = make_create_msg(session_id, 2, ObjectKind::Topic, 1, &topic_data);
    agent.process_incoming(&from, &create_topic);
    let create_reader = make_create_msg(session_id, 20, ObjectKind::DataReader, 2, &[]);
    agent.process_incoming(&from, &create_reader);

    // Read data
    let read_msg = make_read_data_msg(session_id, 20, 1);
    let replies = agent.process_incoming(&from, &read_msg);
    assert!(!replies.is_empty());

    // The reply should contain DATA submessage with our data
    let reply = parse_message(&replies[0].1).unwrap();
    match &reply.submessages[0] {
        Submessage::Data(dp) => {
            assert_eq!(dp.data, vec![0xBE, 0xEF]);
            assert_eq!(dp.reader_id, 20);
        }
        other => panic!("expected Data, got {:?}", other),
    }
}

// -----------------------------------------------------------------------
// 14. Status response codes
// -----------------------------------------------------------------------
#[test]
fn test_status_response_codes() {
    // Parse all status codes
    for &(code, expected) in &[
        (0x00, StatusCode::Ok),
        (0x01, StatusCode::ErrUnknownRef),
        (0x02, StatusCode::ErrInvalidData),
        (0x03, StatusCode::ErrIncompatible),
        (0x04, StatusCode::ErrResources),
    ] {
        assert_eq!(StatusCode::from_u8(code).unwrap(), expected);
        assert_eq!(expected.as_u8(), code);
    }
    // Unknown code
    assert!(StatusCode::from_u8(0xFF).is_err());
}

// -----------------------------------------------------------------------
// 15. Fragmentation: fragment large message
// -----------------------------------------------------------------------
#[test]
fn test_fragment_large_message() {
    let data = vec![0xAA; 100];
    let fragments = fragment_payload(&data, 30).unwrap();
    // 100 / 30 = 4 fragments (30 + 30 + 30 + 10)
    assert_eq!(fragments.len(), 4);

    for (i, frag) in fragments.iter().enumerate() {
        let fh = FragmentHeader::parse(frag).unwrap();
        assert_eq!(fh.fragment_nr, i as u16);
        assert_eq!(fh.total_fragments, 4);
    }
}

// -----------------------------------------------------------------------
// 16. Fragmentation: reassemble fragments
// -----------------------------------------------------------------------
#[test]
fn test_fragment_reassembly() {
    let original = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    let fragments = fragment_payload(&original, 3).unwrap();
    // 10 / 3 = 4 fragments

    let fh0 = FragmentHeader::parse(&fragments[0]).unwrap();
    let mut buf = ReassemblyBuffer::new(fh0.total_fragments);

    for frag in &fragments {
        let fh = FragmentHeader::parse(frag).unwrap();
        let payload = &frag[FRAGMENT_HEADER_SIZE..];
        let complete = buf.insert(fh.fragment_nr, payload.to_vec()).unwrap();
        if fh.fragment_nr < fh.total_fragments - 1 {
            assert!(!complete);
        }
    }

    let reassembled = buf.assemble().unwrap();
    assert_eq!(reassembled, original);
}

// -----------------------------------------------------------------------
// 17. Fragmentation: missing fragment detection
// -----------------------------------------------------------------------
#[test]
fn test_fragment_missing_detection() {
    let mut buf = ReassemblyBuffer::new(3);
    buf.insert(0, vec![1, 2, 3]).unwrap();
    buf.insert(2, vec![7, 8, 9]).unwrap();
    // Fragment 1 is missing
    assert!(!buf.has_fragment(1));
    assert!(buf.has_fragment(0));
    assert!(buf.has_fragment(2));
    assert_eq!(buf.received_count(), 2);

    // Attempt to assemble should fail
    let err = buf.assemble().unwrap_err();
    match err {
        XrceError::FragmentError(msg) => {
            assert!(msg.contains("missing"));
        }
        _ => panic!("expected FragmentError"),
    }
}

// -----------------------------------------------------------------------
// 18. Transport: UDP address parsing
// -----------------------------------------------------------------------
#[test]
fn test_transport_udp_address() {
    let addr = TransportAddr::Udp("192.168.1.100:2019".parse().unwrap());
    match &addr {
        TransportAddr::Udp(sa) => {
            assert_eq!(sa.port(), 2019);
            assert_eq!(sa.ip().to_string(), "192.168.1.100");
        }
        _ => panic!("expected Udp"),
    }

    // Test equality
    let addr2 = TransportAddr::Udp("192.168.1.100:2019".parse().unwrap());
    assert_eq!(addr, addr2);

    let addr3 = TransportAddr::Udp("192.168.1.100:2020".parse().unwrap());
    assert_ne!(addr, addr3);
}

// -----------------------------------------------------------------------
// 19. Transport: message routing (address map)
// -----------------------------------------------------------------------
#[test]
fn test_transport_message_routing() {
    let bridge = NullBridge;
    let mut agent = XrceAgent::new(
        XrceAgentConfig::default(),
        Arc::new(bridge),
    )
    .unwrap();

    let addr1 = TransportAddr::Udp("127.0.0.1:5001".parse().unwrap());
    let addr2 = TransportAddr::Udp("127.0.0.1:5002".parse().unwrap());

    // Client 1 connects
    let msg1 = make_create_client_msg();
    let replies1 = agent.process_incoming(&addr1, &msg1);
    assert!(!replies1.is_empty());
    assert_eq!(replies1[0].0, addr1);

    // Client 2 connects
    let msg2 = make_create_client_msg_with_key([9, 8, 7, 6]);
    let replies2 = agent.process_incoming(&addr2, &msg2);
    assert!(!replies2.is_empty());
    assert_eq!(replies2[0].0, addr2);

    // Both have different session ids
    let r1 = parse_message(&replies1[0].1).unwrap();
    let r2 = parse_message(&replies2[0].1).unwrap();
    assert_ne!(r1.header.session_id, r2.header.session_id);
}

// -----------------------------------------------------------------------
// 20. Config: defaults and validation
// -----------------------------------------------------------------------
#[test]
fn test_config_defaults_and_validation() {
    let cfg = XrceAgentConfig::default();
    assert_eq!(cfg.udp_port, 2019);
    assert_eq!(cfg.serial_baud, 115200);
    assert_eq!(cfg.max_clients, 128);
    assert_eq!(cfg.session_timeout_ms, 30_000);
    assert_eq!(cfg.heartbeat_period_ms, 200);
    assert_eq!(cfg.max_message_size, 512);
    assert!(cfg.serial_device.is_none());
    cfg.validate().unwrap();

    // Invalid: max_clients = 0
    let bad = XrceAgentConfig { max_clients: 0, ..XrceAgentConfig::default() };
    assert!(bad.validate().is_err());

    // Invalid: max_clients > 255
    let bad = XrceAgentConfig { max_clients: 300, ..XrceAgentConfig::default() };
    assert!(bad.validate().is_err());

    // Invalid: session_timeout = 0
    let bad2 = XrceAgentConfig { session_timeout_ms: 0, ..XrceAgentConfig::default() };
    assert!(bad2.validate().is_err());

    // Invalid: heartbeat_period = 0
    let bad3 = XrceAgentConfig { heartbeat_period_ms: 0, ..XrceAgentConfig::default() };
    assert!(bad3.validate().is_err());

    // Invalid: max_message_size too small
    let bad4 = XrceAgentConfig { max_message_size: 4, ..XrceAgentConfig::default() };
    assert!(bad4.validate().is_err());

    // Invalid: serial_baud = 0
    let bad5 = XrceAgentConfig { serial_baud: 0, ..XrceAgentConfig::default() };
    assert!(bad5.validate().is_err());
}

// -----------------------------------------------------------------------
// 21. Full roundtrip: CREATE_CLIENT -> CREATE -> WRITE_DATA -> DATA
// -----------------------------------------------------------------------
#[test]
fn test_full_roundtrip() {
    let bridge = DataBridge::new(vec![0x42, 0x43]);
    let mut agent = make_agent_with(bridge);
    let from = TransportAddr::Udp("127.0.0.1:6000".parse().unwrap());

    // Step 1: CREATE_CLIENT
    let msg = make_create_client_msg();
    let replies = agent.process_incoming(&from, &msg);
    assert_eq!(replies.len(), 1);
    let status_reply = parse_message(&replies[0].1).unwrap();
    let session_id = status_reply.header.session_id;
    assert!(session_id > 0);
    match &status_reply.submessages[0] {
        Submessage::Status(s) => assert_eq!(s.status, StatusCode::Ok),
        _ => panic!("expected Status"),
    }

    // Step 2: CREATE participant (object_id=1)
    let msg = make_create_msg(session_id, 1, ObjectKind::Participant, 0, &[]);
    let replies = agent.process_incoming(&from, &msg);
    assert_eq!(replies.len(), 1);
    let r = parse_message(&replies[0].1).unwrap();
    match &r.submessages[0] {
        Submessage::Status(s) => {
            assert_eq!(s.status, StatusCode::Ok);
            assert_eq!(s.related_object_id, 1);
        }
        _ => panic!("expected Status"),
    }

    // Step 3: CREATE topic (object_id=2)
    let topic_data = {
        let mut d = encode_string("HelloTopic");
        d.extend_from_slice(&encode_string("HelloType"));
        d
    };
    let msg = make_create_msg(session_id, 2, ObjectKind::Topic, 1, &topic_data);
    let replies = agent.process_incoming(&from, &msg);
    assert_eq!(replies.len(), 1);

    // Step 4: CREATE writer (object_id=10)
    let msg = make_create_msg(session_id, 10, ObjectKind::DataWriter, 2, &[]);
    let replies = agent.process_incoming(&from, &msg);
    assert_eq!(replies.len(), 1);

    // Step 5: CREATE reader (object_id=20)
    let msg = make_create_msg(session_id, 20, ObjectKind::DataReader, 2, &[]);
    let replies = agent.process_incoming(&from, &msg);
    assert_eq!(replies.len(), 1);

    // Step 6: WRITE_DATA through writer
    let msg = make_write_data_msg(session_id, 10, &[0xCA, 0xFE]);
    let replies = agent.process_incoming(&from, &msg);
    assert_eq!(replies.len(), 1);
    let r = parse_message(&replies[0].1).unwrap();
    match &r.submessages[0] {
        Submessage::Status(s) => assert_eq!(s.status, StatusCode::Ok),
        _ => panic!("expected Status"),
    }

    // Step 7: READ_DATA from reader -> should get DATA back
    let msg = make_read_data_msg(session_id, 20, 1);
    let replies = agent.process_incoming(&from, &msg);
    assert_eq!(replies.len(), 1);
    let r = parse_message(&replies[0].1).unwrap();
    match &r.submessages[0] {
        Submessage::Data(dp) => {
            assert_eq!(dp.reader_id, 20);
            assert_eq!(dp.data, vec![0x42, 0x43]);
        }
        _ => panic!("expected Data"),
    }
}

// -----------------------------------------------------------------------
// 22. Multiple concurrent sessions
// -----------------------------------------------------------------------
#[test]
fn test_multiple_concurrent_sessions() {
    let bridge = NullBridge;
    let mut agent = XrceAgent::new(
        XrceAgentConfig::default(),
        Arc::new(bridge),
    )
    .unwrap();

    let mut session_ids = Vec::new();
    for i in 0..10u8 {
        let from = TransportAddr::Udp(
            format!("127.0.0.1:{}", 5000 + i as u16).parse().unwrap(),
        );
        let msg = make_create_client_msg_with_key([i, 0, 0, 0]);
        let replies = agent.process_incoming(&from, &msg);
        let r = parse_message(&replies[0].1).unwrap();
        let sid = r.header.session_id;
        assert!(!session_ids.contains(&sid), "duplicate session_id: {}", sid);
        session_ids.push(sid);
    }
    assert_eq!(agent.session_count(), 10);
}

// -----------------------------------------------------------------------
// Additional tests
// -----------------------------------------------------------------------

// 23. Parse malformed input - buffer too short
#[test]
fn test_parse_malformed_short_buffer() {
    assert!(parse_message(&[]).is_err());
    assert!(parse_message(&[0x01]).is_err());
    assert!(parse_message(&[0x01, 0x02, 0x03]).is_err());
    // Header OK but no submessage
    assert!(parse_message(&[0x01, 0x00, 0x00, 0x00]).is_err());
}

// 24. Parse malformed input - unknown submessage id
#[test]
fn test_parse_unknown_submessage_id() {
    let mut buf = Vec::new();
    // Valid message header
    MessageHeader {
        session_id: 1,
        stream_id: 0,
        sequence_nr: 0,
    }
    .write_to(&mut buf);
    // Submessage with bogus id
    SubmessageHeader {
        submessage_id: 0xFF,
        flags: 0,
        length: 0,
    }
    .write_to(&mut buf);

    let err = parse_message(&buf).unwrap_err();
    match err {
        XrceError::UnknownSubmessageId(0xFF) => {}
        other => panic!("expected UnknownSubmessageId, got {:?}", other),
    }
}

// 25. MessageHeader roundtrip
#[test]
fn test_message_header_roundtrip() {
    let hdr = MessageHeader {
        session_id: 42,
        stream_id: 7,
        sequence_nr: 0x1234,
    };
    let bytes = hdr.to_bytes();
    assert_eq!(bytes.len(), 4);
    let parsed = MessageHeader::parse(&bytes).unwrap();
    assert_eq!(parsed, hdr);
}

// 26. FragmentHeader roundtrip
#[test]
fn test_fragment_header_roundtrip() {
    let fh = FragmentHeader {
        fragment_nr: 99,
        total_fragments: 200,
    };
    let bytes = fh.to_bytes();
    assert_eq!(bytes.len(), FRAGMENT_HEADER_SIZE);
    let parsed = FragmentHeader::parse(&bytes).unwrap();
    assert_eq!(parsed, fh);
}

// 27. ObjectKind from_u8 / as_u8 roundtrip
#[test]
fn test_object_kind_roundtrip() {
    let kinds = [
        ObjectKind::Participant,
        ObjectKind::Topic,
        ObjectKind::Publisher,
        ObjectKind::Subscriber,
        ObjectKind::DataWriter,
        ObjectKind::DataReader,
    ];
    for kind in &kinds {
        let v = kind.as_u8();
        let back = ObjectKind::from_u8(v).unwrap();
        assert_eq!(&back, kind);
    }
    assert!(ObjectKind::from_u8(0xFF).is_err());
}

// 28. String encode/decode roundtrip
#[test]
fn test_string_encode_decode() {
    let original = "HelloWorld/TestTopic";
    let encoded = encode_string(original);
    let (decoded, consumed) = decode_string(&encoded).unwrap();
    assert_eq!(decoded, original);
    assert_eq!(consumed, 2 + original.len());
}

// 29. Session removal
#[test]
fn test_session_removal() {
    let mut table = SessionTable::new(128, 30_000);
    let sid = table.create_session([1, 2, 3, 4]).unwrap();
    assert_eq!(table.len(), 1);
    let removed = table.remove(sid);
    assert!(removed.is_some());
    assert_eq!(table.len(), 0);
    assert!(table.get(sid).is_none());
}

// 30. DELETE non-existent object returns ErrUnknownRef
#[test]
fn test_delete_nonexistent_object() {
    let bridge = NullBridge;
    let mut agent = XrceAgent::new(
        XrceAgentConfig::default(),
        Arc::new(bridge),
    )
    .unwrap();
    let from = TransportAddr::Udp("127.0.0.1:5000".parse().unwrap());

    // Create client
    let msg = make_create_client_msg();
    let replies = agent.process_incoming(&from, &msg);
    let r = parse_message(&replies[0].1).unwrap();
    let session_id = r.header.session_id;

    // Try to delete object 999 which doesn't exist
    let del_submsg = Submessage::Delete(DeletePayload { object_id: 999 });
    let del_msg = XrceMessage {
        header: MessageHeader {
            session_id,
            stream_id: 0,
            sequence_nr: 1,
        },
        submessages: vec![del_submsg],
    };
    let del_bytes = serialize_message(&del_msg);
    let replies = agent.process_incoming(&from, &del_bytes);
    assert_eq!(replies.len(), 1);
    let r = parse_message(&replies[0].1).unwrap();
    match &r.submessages[0] {
        Submessage::Status(s) => {
            assert_eq!(s.status, StatusCode::ErrUnknownRef);
            assert_eq!(s.related_object_id, 999);
        }
        _ => panic!("expected Status"),
    }
}

// 31. Best-effort stream skips sequence checking
#[test]
fn test_best_effort_stream_no_sequence_check() {
    let mut stream = StreamState::new(StreamKind::BestEffort);
    // Any sequence should be accepted
    assert!(stream.check_recv_seq(42));
    assert!(stream.check_recv_seq(0));
    assert!(stream.check_recv_seq(100));
}

// 32. Reliable stream rejects out-of-order sequence
#[test]
fn test_reliable_stream_rejects_out_of_order() {
    let mut stream = StreamState::new(StreamKind::Reliable);
    // Expect seq 0 first
    assert!(!stream.check_recv_seq(5)); // out of order
    assert!(stream.check_recv_seq(0)); // correct
    assert!(stream.check_recv_seq(1)); // correct
    assert!(!stream.check_recv_seq(5)); // gap
}

// 33. Fragment with zero max_payload
#[test]
fn test_fragment_zero_max_payload() {
    let err = fragment_payload(&[1, 2, 3], 0).unwrap_err();
    match err {
        XrceError::FragmentError(msg) => assert!(msg.contains("must be > 0")),
        _ => panic!("expected FragmentError"),
    }
}

// 34. Fragment empty payload
#[test]
fn test_fragment_empty_payload() {
    let err = fragment_payload(&[], 10).unwrap_err();
    match err {
        XrceError::FragmentError(msg) => assert!(msg.contains("empty")),
        _ => panic!("expected FragmentError"),
    }
}

// -----------------------------------------------------------------------
// Test helpers
// -----------------------------------------------------------------------

fn make_agent(bridge: Arc<RecordingBridge>) -> XrceAgent {
    XrceAgent::new(XrceAgentConfig::default(), bridge).unwrap()
}

fn make_agent_with(bridge: impl ProxyBridge + 'static) -> XrceAgent {
    XrceAgent::new(XrceAgentConfig::default(), Arc::new(bridge)).unwrap()
}

fn make_create_client_msg() -> Vec<u8> {
    make_create_client_msg_with_key([0xDE, 0xAD, 0xBE, 0xEF])
}

fn make_create_client_msg_with_key(key: [u8; 4]) -> Vec<u8> {
    let msg = XrceMessage {
        header: MessageHeader {
            session_id: 0,
            stream_id: 0,
            sequence_nr: 0,
        },
        submessages: vec![Submessage::CreateClient(CreateClientPayload {
            client_key: key,
            properties: 0,
        })],
    };
    serialize_message(&msg)
}

fn make_create_msg(
    session_id: u8,
    object_id: u16,
    kind: ObjectKind,
    parent_id: u16,
    string_data: &[u8],
) -> Vec<u8> {
    let msg = XrceMessage {
        header: MessageHeader {
            session_id,
            stream_id: 0,
            sequence_nr: 0,
        },
        submessages: vec![Submessage::Create(CreatePayload {
            object_id,
            kind,
            parent_id,
            string_data: string_data.to_vec(),
        })],
    };
    serialize_message(&msg)
}

fn make_write_data_msg(session_id: u8, writer_id: u16, data: &[u8]) -> Vec<u8> {
    let msg = XrceMessage {
        header: MessageHeader {
            session_id,
            stream_id: 0,
            sequence_nr: 0,
        },
        submessages: vec![Submessage::WriteData(WriteDataPayload {
            writer_id,
            data: data.to_vec(),
        })],
    };
    serialize_message(&msg)
}

fn make_read_data_msg(session_id: u8, reader_id: u16, max_samples: u16) -> Vec<u8> {
    let msg = XrceMessage {
        header: MessageHeader {
            session_id,
            stream_id: 0,
            sequence_nr: 0,
        },
        submessages: vec![Submessage::ReadData(ReadDataPayload {
            reader_id,
            max_samples,
        })],
    };
    serialize_message(&msg)
}

// -----------------------------------------------------------------------
// Test bridges
// -----------------------------------------------------------------------

/// A bridge that records all calls for assertion.
#[derive(Clone)]
struct RecordingBridge {
    calls: Arc<Mutex<Vec<String>>>,
    next_handle: Arc<Mutex<u32>>,
}

impl RecordingBridge {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            calls: Arc::new(Mutex::new(Vec::new())),
            next_handle: Arc::new(Mutex::new(100)),
        })
    }
}

impl ProxyBridge for RecordingBridge {
    fn create_participant(&self, _domain_id: u16) -> Result<u32, XrceError> {
        self.calls.lock().unwrap().push("create_participant".into());
        let mut h = self.next_handle.lock().unwrap();
        let id = *h;
        *h += 1;
        Ok(id)
    }
    fn create_topic(&self, _pid: u32, _name: &str, _tn: &str) -> Result<u32, XrceError> {
        self.calls.lock().unwrap().push("create_topic".into());
        let mut h = self.next_handle.lock().unwrap();
        let id = *h;
        *h += 1;
        Ok(id)
    }
    fn create_writer(&self, _pid: u32, _tid: u32) -> Result<u32, XrceError> {
        self.calls.lock().unwrap().push("create_writer".into());
        let mut h = self.next_handle.lock().unwrap();
        let id = *h;
        *h += 1;
        Ok(id)
    }
    fn create_reader(&self, _pid: u32, _tid: u32) -> Result<u32, XrceError> {
        self.calls.lock().unwrap().push("create_reader".into());
        let mut h = self.next_handle.lock().unwrap();
        let id = *h;
        *h += 1;
        Ok(id)
    }
    fn write_data(&self, _wid: u32, _data: &[u8]) -> Result<(), XrceError> {
        self.calls.lock().unwrap().push("write_data".into());
        Ok(())
    }
    fn read_data(&self, _rid: u32) -> Result<Option<Vec<u8>>, XrceError> {
        self.calls.lock().unwrap().push("read_data".into());
        Ok(None)
    }
    fn delete_entity(&self, _eid: u32) -> Result<(), XrceError> {
        self.calls.lock().unwrap().push("delete_entity".into());
        Ok(())
    }
}

/// A bridge that returns pre-set data on read.
struct DataBridge {
    data: Vec<u8>,
    next_handle: Mutex<u32>,
}

impl DataBridge {
    fn new(data: Vec<u8>) -> Self {
        Self {
            data,
            next_handle: Mutex::new(100),
        }
    }
}

impl ProxyBridge for DataBridge {
    fn create_participant(&self, _domain_id: u16) -> Result<u32, XrceError> {
        let mut h = self.next_handle.lock().unwrap();
        let id = *h;
        *h += 1;
        Ok(id)
    }
    fn create_topic(&self, _pid: u32, _name: &str, _tn: &str) -> Result<u32, XrceError> {
        let mut h = self.next_handle.lock().unwrap();
        let id = *h;
        *h += 1;
        Ok(id)
    }
    fn create_writer(&self, _pid: u32, _tid: u32) -> Result<u32, XrceError> {
        let mut h = self.next_handle.lock().unwrap();
        let id = *h;
        *h += 1;
        Ok(id)
    }
    fn create_reader(&self, _pid: u32, _tid: u32) -> Result<u32, XrceError> {
        let mut h = self.next_handle.lock().unwrap();
        let id = *h;
        *h += 1;
        Ok(id)
    }
    fn write_data(&self, _wid: u32, _data: &[u8]) -> Result<(), XrceError> {
        Ok(())
    }
    fn read_data(&self, _rid: u32) -> Result<Option<Vec<u8>>, XrceError> {
        Ok(Some(self.data.clone()))
    }
    fn delete_entity(&self, _eid: u32) -> Result<(), XrceError> {
        Ok(())
    }
}
