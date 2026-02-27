// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

// HDDS WASM SDK - Comprehensive test suite

use crate::cdr::{CdrDecoder, CdrEncoder};
use crate::error::WasmError;
use crate::participant::WasmParticipant;
use crate::protocol::{self, MessageHeader, RelayMessage, HEADER_SIZE};
use crate::qos::{WasmDurability, WasmQos, WasmReliability};
use crate::relay::RelayHandler;

// ============================================================
// Protocol tests
// ============================================================

#[test]
fn test_parse_connect_message() {
    let msg = protocol::build_connect(42, 1);
    let parsed = protocol::parse_message(&msg).unwrap();
    match parsed {
        RelayMessage::Connect { domain_id } => {
            assert_eq!(domain_id, 42);
        }
        other => panic!("expected Connect, got {:?}", other),
    }
}

#[test]
fn test_parse_connect_ack_message() {
    let msg = protocol::build_connect_ack(1234, 5);
    let parsed = protocol::parse_message(&msg).unwrap();
    match parsed {
        RelayMessage::ConnectAck { participant_id } => {
            assert_eq!(participant_id, 1234);
        }
        other => panic!("expected ConnectAck, got {:?}", other),
    }
}

#[test]
fn test_parse_create_topic_message() {
    let msg = protocol::build_create_topic("sensor/temp", "SensorData", 2);
    let parsed = protocol::parse_message(&msg).unwrap();
    match parsed {
        RelayMessage::CreateTopic {
            topic_name,
            type_name,
        } => {
            assert_eq!(topic_name, "sensor/temp");
            assert_eq!(type_name, "SensorData");
        }
        other => panic!("expected CreateTopic, got {:?}", other),
    }
}

#[test]
fn test_parse_topic_ack_message() {
    let msg = protocol::build_topic_ack(7, "sensor/temp", 3);
    let parsed = protocol::parse_message(&msg).unwrap();
    match parsed {
        RelayMessage::TopicAck {
            topic_id,
            topic_name,
        } => {
            assert_eq!(topic_id, 7);
            assert_eq!(topic_name, "sensor/temp");
        }
        other => panic!("expected TopicAck, got {:?}", other),
    }
}

#[test]
fn test_parse_subscribe_unsubscribe_messages() {
    // Subscribe
    let msg = protocol::build_subscribe(5, 10);
    let parsed = protocol::parse_message(&msg).unwrap();
    match parsed {
        RelayMessage::Subscribe { topic_id } => {
            assert_eq!(topic_id, 5);
        }
        other => panic!("expected Subscribe, got {:?}", other),
    }

    // Unsubscribe
    let msg = protocol::build_unsubscribe(5, 11);
    let parsed = protocol::parse_message(&msg).unwrap();
    match parsed {
        RelayMessage::Unsubscribe { topic_id } => {
            assert_eq!(topic_id, 5);
        }
        other => panic!("expected Unsubscribe, got {:?}", other),
    }
}

#[test]
fn test_parse_publish_message_with_payload() {
    let payload = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03];
    let msg = protocol::build_publish(3, 42, &payload);
    let parsed = protocol::parse_message(&msg).unwrap();
    match parsed {
        RelayMessage::Publish {
            topic_id,
            sequence_nr,
            payload: p,
        } => {
            assert_eq!(topic_id, 3);
            assert_eq!(sequence_nr, 42);
            assert_eq!(p, payload);
        }
        other => panic!("expected Publish, got {:?}", other),
    }
}

#[test]
fn test_parse_data_message() {
    let payload = vec![0x01, 0x02, 0x03, 0x04];
    let msg = protocol::build_data(10, 99, &payload);
    let parsed = protocol::parse_message(&msg).unwrap();
    match parsed {
        RelayMessage::Data {
            topic_id,
            sequence_nr,
            payload: p,
        } => {
            assert_eq!(topic_id, 10);
            assert_eq!(sequence_nr, 99);
            assert_eq!(p, payload);
        }
        other => panic!("expected Data, got {:?}", other),
    }
}

#[test]
fn test_parse_ping_pong() {
    // Ping
    let msg = protocol::build_ping(55);
    let parsed = protocol::parse_message(&msg).unwrap();
    match parsed {
        RelayMessage::Ping { sequence_nr } => {
            assert_eq!(sequence_nr, 55);
        }
        other => panic!("expected Ping, got {:?}", other),
    }

    // Pong
    let msg = protocol::build_pong(55);
    let parsed = protocol::parse_message(&msg).unwrap();
    match parsed {
        RelayMessage::Pong { sequence_nr } => {
            assert_eq!(sequence_nr, 55);
        }
        other => panic!("expected Pong, got {:?}", other),
    }
}

#[test]
fn test_parse_disconnect() {
    let msg = protocol::build_disconnect(0);
    let parsed = protocol::parse_message(&msg).unwrap();
    assert_eq!(parsed, RelayMessage::Disconnected);
}

#[test]
fn test_parse_error_message_with_reason() {
    let msg = protocol::build_error("something went wrong", 0);
    let parsed = protocol::parse_message(&msg).unwrap();
    match parsed {
        RelayMessage::Error { reason } => {
            assert_eq!(reason, "something went wrong");
        }
        other => panic!("expected Error, got {:?}", other),
    }
}

#[test]
fn test_unknown_message_type() {
    let mut msg = [0u8; HEADER_SIZE];
    msg[0] = 0xFF; // unknown type
    let result = protocol::parse_message(&msg);
    match result {
        Err(WasmError::UnknownMessageType(0xFF)) => {}
        other => panic!("expected UnknownMessageType, got {:?}", other),
    }
}

#[test]
fn test_truncated_message_handling() {
    // Too short for header
    let result = protocol::parse_message(&[0x01, 0x02]);
    assert!(result.is_err());
    match result {
        Err(WasmError::MessageTooShort { expected, actual }) => {
            assert_eq!(expected, HEADER_SIZE);
            assert_eq!(actual, 2);
        }
        other => panic!("expected MessageTooShort, got {:?}", other),
    }

    // Header OK but payload too short for CONNECT (needs 2 more bytes)
    let mut msg = [0u8; HEADER_SIZE];
    msg[0] = protocol::MSG_CONNECT;
    let result = protocol::parse_message(&msg);
    assert!(result.is_err());

    // Empty data
    let result = protocol::parse_message(&[]);
    assert!(result.is_err());
}

// ============================================================
// CDR tests
// ============================================================

#[test]
fn test_cdr_encode_decode_all_primitives() {
    let mut enc = CdrEncoder::new();
    enc.encode_bool(true);
    enc.encode_bool(false);
    enc.encode_u8(0xFF);
    enc.encode_i8(-42);
    enc.encode_u16(0xBEEF);
    enc.encode_i16(-12345);
    enc.encode_u32(0xDEADBEEF);
    enc.encode_i32(-999999);
    enc.encode_u64(0x0102030405060708);
    enc.encode_i64(-1234567890123);
    enc.encode_f32(std::f32::consts::PI);
    enc.encode_f64(std::f64::consts::E);

    let buf = enc.finish();
    let mut dec = CdrDecoder::new(&buf);

    assert!(dec.decode_bool().unwrap());
    assert!(!dec.decode_bool().unwrap());
    assert_eq!(dec.decode_u8().unwrap(), 0xFF);
    assert_eq!(dec.decode_i8().unwrap(), -42);
    assert_eq!(dec.decode_u16().unwrap(), 0xBEEF);
    assert_eq!(dec.decode_i16().unwrap(), -12345);
    assert_eq!(dec.decode_u32().unwrap(), 0xDEADBEEF);
    assert_eq!(dec.decode_i32().unwrap(), -999999);
    assert_eq!(dec.decode_u64().unwrap(), 0x0102030405060708);
    assert_eq!(dec.decode_i64().unwrap(), -1234567890123);

    let f32_val = dec.decode_f32().unwrap();
    assert!((f32_val - std::f32::consts::PI).abs() < 1e-6);

    let f64_val = dec.decode_f64().unwrap();
    assert!((f64_val - std::f64::consts::E).abs() < 1e-12);
}

#[test]
fn test_cdr_encode_decode_strings() {
    let mut enc = CdrEncoder::new();
    enc.encode_string("hello world");
    enc.encode_string("");
    enc.encode_string("DDS is great!");

    let buf = enc.finish();
    let mut dec = CdrDecoder::new(&buf);

    assert_eq!(dec.decode_string().unwrap(), "hello world");
    assert_eq!(dec.decode_string().unwrap(), "");
    assert_eq!(dec.decode_string().unwrap(), "DDS is great!");
}

#[test]
fn test_cdr_encode_decode_bytes() {
    let mut enc = CdrEncoder::new();
    enc.encode_bytes(&[1, 2, 3, 4, 5]);
    enc.encode_bytes(&[]);
    enc.encode_bytes(&[0xFF; 100]);

    let buf = enc.finish();
    let mut dec = CdrDecoder::new(&buf);

    assert_eq!(dec.decode_bytes().unwrap(), vec![1, 2, 3, 4, 5]);
    assert_eq!(dec.decode_bytes().unwrap(), Vec::<u8>::new());
    assert_eq!(dec.decode_bytes().unwrap(), vec![0xFF; 100]);
}

#[test]
fn test_cdr_alignment() {
    let mut enc = CdrEncoder::new();
    // Write a u8 (pos=1), then a u32 (should align to 4)
    enc.encode_u8(0xAA);
    enc.encode_u32(0x12345678);

    let buf = enc.finish();
    // Expected: [0xAA, 0x00, 0x00, 0x00, 0x78, 0x56, 0x34, 0x12]
    assert_eq!(buf.len(), 8);
    assert_eq!(buf[0], 0xAA);
    // Padding bytes
    assert_eq!(buf[1], 0x00);
    assert_eq!(buf[2], 0x00);
    assert_eq!(buf[3], 0x00);
    // u32 LE at offset 4
    assert_eq!(buf[4], 0x78);
    assert_eq!(buf[5], 0x56);
    assert_eq!(buf[6], 0x34);
    assert_eq!(buf[7], 0x12);

    let mut dec = CdrDecoder::new(&buf);
    assert_eq!(dec.decode_u8().unwrap(), 0xAA);
    assert_eq!(dec.decode_u32().unwrap(), 0x12345678);
}

#[test]
fn test_cdr_empty_buffer_decode_error() {
    let buf: &[u8] = &[];
    let mut dec = CdrDecoder::new(buf);

    assert!(dec.decode_bool().is_err());
    assert!(dec.decode_u8().is_err());
    assert!(dec.decode_u16().is_err());
    assert!(dec.decode_u32().is_err());
    assert!(dec.decode_u64().is_err());
    assert!(dec.decode_string().is_err());
}

#[test]
fn test_cdr_alignment_u16_after_u8() {
    let mut enc = CdrEncoder::new();
    enc.encode_u8(1);
    enc.encode_u16(0x0203);

    let buf = enc.finish();
    // u8 at 0, padding at 1, u16 LE at 2-3
    assert_eq!(buf.len(), 4);
    assert_eq!(buf[0], 1);
    assert_eq!(buf[1], 0); // padding
    assert_eq!(buf[2], 0x03);
    assert_eq!(buf[3], 0x02);

    let mut dec = CdrDecoder::new(&buf);
    assert_eq!(dec.decode_u8().unwrap(), 1);
    assert_eq!(dec.decode_u16().unwrap(), 0x0203);
}

#[test]
fn test_cdr_alignment_u64_after_u8() {
    let mut enc = CdrEncoder::new();
    enc.encode_u8(0xFF);
    enc.encode_u64(0x0102030405060708);

    let buf = enc.finish();
    // u8 at 0, 7 bytes padding, u64 at 8
    assert_eq!(buf.len(), 16);

    let mut dec = CdrDecoder::new(&buf);
    assert_eq!(dec.decode_u8().unwrap(), 0xFF);
    assert_eq!(dec.decode_u64().unwrap(), 0x0102030405060708);
}

// ============================================================
// Participant tests
// ============================================================

#[test]
fn test_participant_connect_flow() {
    let mut participant = WasmParticipant::new(0);
    assert!(!participant.connected);

    // Build CONNECT
    let connect_msg = participant.build_connect();
    let parsed = protocol::parse_message(&connect_msg).unwrap();
    match parsed {
        RelayMessage::Connect { domain_id } => assert_eq!(domain_id, 0),
        other => panic!("expected Connect, got {:?}", other),
    }

    // Simulate CONNECT_ACK from relay
    let ack = protocol::build_connect_ack(42, 0);
    participant.handle_connect_ack(&ack).unwrap();
    assert!(participant.connected);
    assert_eq!(participant.participant_id, 42);
}

#[test]
fn test_participant_topic_creation() {
    let mut participant = WasmParticipant::new(0);

    // Connect first
    let ack = protocol::build_connect_ack(1, 0);
    participant.handle_connect_ack(&ack).unwrap();

    // Create topic
    let create_msg = participant.build_create_topic("test_topic", "TestType");
    let parsed = protocol::parse_message(&create_msg).unwrap();
    match parsed {
        RelayMessage::CreateTopic {
            topic_name,
            type_name,
        } => {
            assert_eq!(topic_name, "test_topic");
            assert_eq!(type_name, "TestType");
        }
        other => panic!("expected CreateTopic, got {:?}", other),
    }

    // Simulate TOPIC_ACK
    let topic_ack = protocol::build_topic_ack(5, "test_topic", 0);
    let topic_id = participant.handle_topic_ack(&topic_ack).unwrap();
    assert_eq!(topic_id, 5);
    assert_eq!(participant.topics.get("test_topic"), Some(&5));
}

#[test]
fn test_participant_publish_data_roundtrip() {
    let mut participant = WasmParticipant::new(0);

    // Setup: connect and create topic
    let ack = protocol::build_connect_ack(1, 0);
    participant.handle_connect_ack(&ack).unwrap();
    let topic_ack = protocol::build_topic_ack(1, "data_topic", 0);
    participant.handle_topic_ack(&topic_ack).unwrap();

    // Create writer
    participant.create_writer(1).unwrap();

    // Publish
    let cdr_data = vec![0x01, 0x02, 0x03, 0x04];
    let pub_msg = participant.build_publish(1, &cdr_data).unwrap();

    // Verify the published message can be parsed
    let parsed = protocol::parse_message(&pub_msg).unwrap();
    match parsed {
        RelayMessage::Publish {
            topic_id,
            payload,
            ..
        } => {
            assert_eq!(topic_id, 1);
            assert_eq!(payload, cdr_data);
        }
        other => panic!("expected Publish, got {:?}", other),
    }

    // Check writer stats
    assert_eq!(participant.writers.get(&1).unwrap().samples_written, 1);
}

#[test]
fn test_participant_subscribe_and_receive_data() {
    let mut participant = WasmParticipant::new(0);

    // Setup
    let ack = protocol::build_connect_ack(1, 0);
    participant.handle_connect_ack(&ack).unwrap();
    let topic_ack = protocol::build_topic_ack(2, "sub_topic", 0);
    participant.handle_topic_ack(&topic_ack).unwrap();

    // Create reader and subscribe
    participant.create_reader(2).unwrap();
    let sub_msg = participant.build_subscribe(2);
    let parsed = protocol::parse_message(&sub_msg).unwrap();
    match parsed {
        RelayMessage::Subscribe { topic_id } => assert_eq!(topic_id, 2),
        other => panic!("expected Subscribe, got {:?}", other),
    }

    // Check reader is marked subscribed
    assert!(participant.readers.get(&2).unwrap().subscribed);

    // Simulate incoming DATA
    let data_msg = protocol::build_data(2, 1, &[0xAA, 0xBB]);
    let (topic_id, payload) = participant.handle_data(&data_msg).unwrap();
    assert_eq!(topic_id, 2);
    assert_eq!(payload, vec![0xAA, 0xBB]);
    assert_eq!(participant.readers.get(&2).unwrap().samples_received, 1);
}

#[test]
fn test_participant_multiple_topics() {
    let mut participant = WasmParticipant::new(0);

    let ack = protocol::build_connect_ack(1, 0);
    participant.handle_connect_ack(&ack).unwrap();

    // Create two topics
    let _ = participant.build_create_topic("topic_a", "TypeA");
    let ack_a = protocol::build_topic_ack(10, "topic_a", 0);
    participant.handle_topic_ack(&ack_a).unwrap();

    let _ = participant.build_create_topic("topic_b", "TypeB");
    let ack_b = protocol::build_topic_ack(20, "topic_b", 0);
    participant.handle_topic_ack(&ack_b).unwrap();

    assert_eq!(participant.topics.len(), 2);
    assert_eq!(participant.topics.get("topic_a"), Some(&10));
    assert_eq!(participant.topics.get("topic_b"), Some(&20));

    // Create writers for both
    participant.create_writer(10).unwrap();
    participant.create_writer(20).unwrap();
    assert_eq!(participant.writers.len(), 2);
}

#[test]
fn test_participant_disconnect_clean() {
    let mut participant = WasmParticipant::new(0);

    let ack = protocol::build_connect_ack(1, 0);
    participant.handle_connect_ack(&ack).unwrap();
    assert!(participant.connected);

    // Build disconnect
    let disc_msg = participant.build_disconnect();
    let parsed = protocol::parse_message(&disc_msg).unwrap();
    assert_eq!(parsed, RelayMessage::Disconnected);

    // Process disconnect via process_message
    let disc_msg2 = protocol::build_disconnect(0);
    let result = participant.process_message(&disc_msg2).unwrap();
    assert_eq!(result, RelayMessage::Disconnected);
    assert!(!participant.connected);
}

#[test]
fn test_participant_publish_not_connected() {
    let mut participant = WasmParticipant::new(0);
    let result = participant.build_publish(1, &[0x01]);
    assert!(result.is_err());
    match result {
        Err(WasmError::NotConnected) => {}
        other => panic!("expected NotConnected, got {:?}", other),
    }
}

#[test]
fn test_participant_process_message_variants() {
    let mut participant = WasmParticipant::new(0);

    // ConnectAck via process_message
    let ack = protocol::build_connect_ack(99, 0);
    let msg = participant.process_message(&ack).unwrap();
    match msg {
        RelayMessage::ConnectAck { participant_id } => assert_eq!(participant_id, 99),
        other => panic!("expected ConnectAck, got {:?}", other),
    }
    assert!(participant.connected);
    assert_eq!(participant.participant_id, 99);

    // Pong via process_message
    let pong = protocol::build_pong(123);
    let msg = participant.process_message(&pong).unwrap();
    match msg {
        RelayMessage::Pong { sequence_nr } => assert_eq!(sequence_nr, 123),
        other => panic!("expected Pong, got {:?}", other),
    }

    // Error via process_message
    let err = protocol::build_error("test error", 0);
    let msg = participant.process_message(&err).unwrap();
    match msg {
        RelayMessage::Error { reason } => assert_eq!(reason, "test error"),
        other => panic!("expected Error, got {:?}", other),
    }
}

// ============================================================
// Relay tests
// ============================================================

#[test]
fn test_relay_accept_client_assign_id() {
    let mut relay = RelayHandler::new();
    let (id1, ack1) = relay.accept_client();
    let (id2, _ack2) = relay.accept_client();

    assert_eq!(id1, 1);
    assert_eq!(id2, 2);

    // Verify the ACK can be parsed
    let parsed = protocol::parse_message(&ack1).unwrap();
    match parsed {
        RelayMessage::ConnectAck { participant_id } => {
            assert_eq!(participant_id, 1);
        }
        other => panic!("expected ConnectAck, got {:?}", other),
    }
}

#[test]
fn test_relay_process_connect_and_create_topic() {
    let mut relay = RelayHandler::new();
    let (client_id, _) = relay.accept_client();

    // Send CONNECT
    let connect = protocol::build_connect(0, 0);
    let responses = relay.process_client_message(client_id, &connect).unwrap();
    assert_eq!(responses.len(), 1);

    // Parse the CONNECT_ACK response
    let parsed = protocol::parse_message(&responses[0]).unwrap();
    match parsed {
        RelayMessage::ConnectAck { participant_id } => {
            assert_eq!(participant_id, client_id);
        }
        other => panic!("expected ConnectAck, got {:?}", other),
    }

    // Send CREATE_TOPIC
    let create = protocol::build_create_topic("my_topic", "MyType", 1);
    let responses = relay.process_client_message(client_id, &create).unwrap();
    assert_eq!(responses.len(), 1);

    // Parse TOPIC_ACK
    let parsed = protocol::parse_message(&responses[0]).unwrap();
    match parsed {
        RelayMessage::TopicAck {
            topic_id,
            topic_name,
        } => {
            assert!(topic_id > 0);
            assert_eq!(topic_name, "my_topic");
        }
        other => panic!("expected TopicAck, got {:?}", other),
    }
}

#[test]
fn test_relay_route_publication_to_subscribed_clients() {
    let mut relay = RelayHandler::new();

    // Client 1: publisher
    let (pub_id, _) = relay.accept_client();
    let connect1 = protocol::build_connect(0, 0);
    relay.process_client_message(pub_id, &connect1).unwrap();

    // Create topic from client 1
    let create = protocol::build_create_topic("shared_topic", "SharedType", 1);
    let responses = relay.process_client_message(pub_id, &create).unwrap();
    let topic_id = match protocol::parse_message(&responses[0]).unwrap() {
        RelayMessage::TopicAck { topic_id, .. } => topic_id,
        _ => panic!("expected TopicAck"),
    };

    // Client 2: subscriber
    let (sub_id, _) = relay.accept_client();
    let connect2 = protocol::build_connect(0, 0);
    relay.process_client_message(sub_id, &connect2).unwrap();

    // Client 2 creates same topic (gets same ID)
    let create2 = protocol::build_create_topic("shared_topic", "SharedType", 2);
    relay.process_client_message(sub_id, &create2).unwrap();

    // Client 2 subscribes
    let sub = protocol::build_subscribe(topic_id, 3);
    relay.process_client_message(sub_id, &sub).unwrap();

    // Route publication from client 1
    let payload = vec![0x01, 0x02, 0x03];
    let routed = relay.route_publication(topic_id, &payload, pub_id);
    assert_eq!(routed.len(), 1);
    assert_eq!(routed[0].0, sub_id);

    // Verify the routed message
    let parsed = protocol::parse_message(&routed[0].1).unwrap();
    match parsed {
        RelayMessage::Data {
            topic_id: tid,
            payload: p,
            ..
        } => {
            assert_eq!(tid, topic_id);
            assert_eq!(p, payload);
        }
        other => panic!("expected Data, got {:?}", other),
    }
}

#[test]
fn test_relay_route_dds_data_to_wasm_clients() {
    let mut relay = RelayHandler::new();

    // Client subscribes to a topic
    let (client_id, _) = relay.accept_client();
    let connect = protocol::build_connect(0, 0);
    relay.process_client_message(client_id, &connect).unwrap();

    let create = protocol::build_create_topic("dds_topic", "DdsType", 1);
    let responses = relay.process_client_message(client_id, &create).unwrap();
    let topic_id = match protocol::parse_message(&responses[0]).unwrap() {
        RelayMessage::TopicAck { topic_id, .. } => topic_id,
        _ => panic!("expected TopicAck"),
    };

    let sub = protocol::build_subscribe(topic_id, 2);
    relay.process_client_message(client_id, &sub).unwrap();

    // Route DDS data
    let dds_payload = vec![0xAA, 0xBB, 0xCC];
    let routed = relay.route_dds_data("dds_topic", &dds_payload);
    assert_eq!(routed.len(), 1);
    assert_eq!(routed[0].0, client_id);

    // Route for unknown topic
    let empty = relay.route_dds_data("nonexistent_topic", &dds_payload);
    assert_eq!(empty.len(), 0);
}

#[test]
fn test_relay_remove_client_cleans_up() {
    let mut relay = RelayHandler::new();

    let (client_id, _) = relay.accept_client();
    let connect = protocol::build_connect(0, 0);
    relay.process_client_message(client_id, &connect).unwrap();

    assert!(relay.has_client(client_id));
    assert_eq!(relay.client_count(), 1);

    relay.remove_client(client_id);

    assert!(!relay.has_client(client_id));
    assert_eq!(relay.client_count(), 0);
}

#[test]
fn test_relay_multiple_clients_isolation() {
    let mut relay = RelayHandler::new();

    // Create 3 clients
    let (id1, _) = relay.accept_client();
    let (id2, _) = relay.accept_client();
    let (id3, _) = relay.accept_client();

    // Connect all
    for &id in &[id1, id2, id3] {
        let connect = protocol::build_connect(0, 0);
        relay.process_client_message(id, &connect).unwrap();
    }
    assert_eq!(relay.client_count(), 3);

    // Client 1 creates topic
    let create = protocol::build_create_topic("topic1", "Type1", 0);
    let responses = relay.process_client_message(id1, &create).unwrap();
    let topic_id = match protocol::parse_message(&responses[0]).unwrap() {
        RelayMessage::TopicAck { topic_id, .. } => topic_id,
        _ => panic!("expected TopicAck"),
    };

    // Only client 2 subscribes
    let create2 = protocol::build_create_topic("topic1", "Type1", 0);
    relay.process_client_message(id2, &create2).unwrap();
    let sub = protocol::build_subscribe(topic_id, 0);
    relay.process_client_message(id2, &sub).unwrap();

    // Route from client 1 - only client 2 should receive
    let routed = relay.route_publication(topic_id, &[0x01], id1);
    assert_eq!(routed.len(), 1);
    assert_eq!(routed[0].0, id2);

    // Remove client 2 - routing should give 0 results
    relay.remove_client(id2);
    let routed = relay.route_publication(topic_id, &[0x01], id1);
    assert_eq!(routed.len(), 0);
}

#[test]
fn test_relay_ping_pong_response() {
    let mut relay = RelayHandler::new();

    let (client_id, _) = relay.accept_client();
    let connect = protocol::build_connect(0, 0);
    relay.process_client_message(client_id, &connect).unwrap();

    let ping = protocol::build_ping(77);
    let responses = relay.process_client_message(client_id, &ping).unwrap();
    assert_eq!(responses.len(), 1);

    let parsed = protocol::parse_message(&responses[0]).unwrap();
    match parsed {
        RelayMessage::Pong { sequence_nr } => assert_eq!(sequence_nr, 77),
        other => panic!("expected Pong, got {:?}", other),
    }
}

#[test]
fn test_relay_disconnect_removes_client() {
    let mut relay = RelayHandler::new();

    let (client_id, _) = relay.accept_client();
    let connect = protocol::build_connect(0, 0);
    relay.process_client_message(client_id, &connect).unwrap();
    assert!(relay.has_client(client_id));

    let disconnect = protocol::build_disconnect(0);
    relay
        .process_client_message(client_id, &disconnect)
        .unwrap();
    assert!(!relay.has_client(client_id));
}

// ============================================================
// QoS tests
// ============================================================

#[test]
fn test_qos_default() {
    let qos = WasmQos::default();
    assert_eq!(qos.reliability, WasmReliability::BestEffort);
    assert_eq!(qos.durability, WasmDurability::Volatile);
    assert_eq!(qos.history_depth, 1);
}

#[test]
fn test_qos_reliable_profile() {
    let qos = WasmQos::reliable();
    assert_eq!(qos.reliability, WasmReliability::Reliable);
    assert_eq!(qos.durability, WasmDurability::Volatile);
}

#[test]
fn test_qos_encode_decode() {
    let qos = WasmQos::reliable_transient_local(10);
    let encoded = qos.encode();
    let decoded = WasmQos::decode(&encoded).unwrap();
    assert_eq!(decoded, qos);
}

#[test]
fn test_qos_decode_invalid() {
    assert!(WasmQos::decode(&[0xFF, 0, 0, 0, 0, 0]).is_none());
    assert!(WasmQos::decode(&[0, 0xFF, 0, 0, 0, 0]).is_none());
    assert!(WasmQos::decode(&[0, 0]).is_none()); // too short
}

// ============================================================
// Message header tests
// ============================================================

#[test]
fn test_header_encode_decode_roundtrip() {
    let header = MessageHeader::new(0x07, 0x01, 1234, 5678);
    let bytes = header.encode();
    let decoded = MessageHeader::decode(&bytes).unwrap();
    assert_eq!(decoded, header);
}

#[test]
fn test_header_decode_too_short() {
    let result = MessageHeader::decode(&[0x01, 0x02, 0x03]);
    assert!(result.is_err());
}

// ============================================================
// Integration test: full roundtrip
// ============================================================

#[test]
fn test_full_roundtrip_connect_create_subscribe_publish_receive() {
    // Setup relay
    let mut relay = RelayHandler::new();

    // === Client A (publisher) ===
    let mut client_a = WasmParticipant::new(0);

    // A connects
    let connect_a = client_a.build_connect();
    // Relay processes connect from A
    // First, accept_client gives us an ID
    let (a_id, _pre_ack) = relay.accept_client();
    let responses = relay.process_client_message(a_id, &connect_a).unwrap();
    // A processes the CONNECT_ACK
    client_a.handle_connect_ack(&responses[0]).unwrap();
    assert!(client_a.connected);
    assert_eq!(client_a.participant_id, a_id);

    // A creates a topic
    let create_a = client_a.build_create_topic("roundtrip", "RoundtripType");
    let responses = relay.process_client_message(a_id, &create_a).unwrap();
    let topic_id = client_a.handle_topic_ack(&responses[0]).unwrap();

    // A creates a writer
    client_a.create_writer(topic_id).unwrap();

    // === Client B (subscriber) ===
    let mut client_b = WasmParticipant::new(0);

    // B connects
    let connect_b = client_b.build_connect();
    let (b_id, _pre_ack) = relay.accept_client();
    let responses = relay.process_client_message(b_id, &connect_b).unwrap();
    client_b.handle_connect_ack(&responses[0]).unwrap();
    assert!(client_b.connected);

    // B creates same topic
    let create_b = client_b.build_create_topic("roundtrip", "RoundtripType");
    let responses = relay.process_client_message(b_id, &create_b).unwrap();
    let topic_id_b = client_b.handle_topic_ack(&responses[0]).unwrap();
    assert_eq!(topic_id, topic_id_b); // same global topic

    // B creates a reader and subscribes
    client_b.create_reader(topic_id).unwrap();
    let sub_msg = client_b.build_subscribe(topic_id);
    relay.process_client_message(b_id, &sub_msg).unwrap();

    // === A publishes data ===
    let mut enc = CdrEncoder::new();
    enc.encode_u32(42);
    enc.encode_string("hello from WASM");
    let cdr_payload = enc.finish();

    let pub_msg = client_a.build_publish(topic_id, &cdr_payload).unwrap();

    // Relay processes the publish (extract payload from the PUBLISH message)
    let parsed_pub = protocol::parse_message(&pub_msg).unwrap();
    let pub_payload = match parsed_pub {
        RelayMessage::Publish { payload, .. } => payload,
        _ => panic!("expected Publish"),
    };

    // Relay routes to subscribers
    let routed = relay.route_publication(topic_id, &pub_payload, a_id);
    assert_eq!(routed.len(), 1);
    assert_eq!(routed[0].0, b_id);

    // === B receives data ===
    let (recv_topic, recv_payload) = client_b.handle_data(&routed[0].1).unwrap();
    assert_eq!(recv_topic, topic_id);
    assert_eq!(recv_payload, pub_payload);

    // Decode the CDR payload
    let mut dec = CdrDecoder::new(&recv_payload);
    assert_eq!(dec.decode_u32().unwrap(), 42);
    assert_eq!(dec.decode_string().unwrap(), "hello from WASM");

    // Verify stats
    assert_eq!(client_a.writers.get(&topic_id).unwrap().samples_written, 1);
    assert_eq!(
        client_b.readers.get(&topic_id).unwrap().samples_received,
        1
    );
}

// ============================================================
// Edge case tests
// ============================================================

#[test]
fn test_create_writer_unknown_topic() {
    let mut participant = WasmParticipant::new(0);
    let ack = protocol::build_connect_ack(1, 0);
    participant.handle_connect_ack(&ack).unwrap();

    let result = participant.create_writer(999);
    match result {
        Err(WasmError::UnknownTopic(999)) => {}
        other => panic!("expected UnknownTopic, got {:?}", other),
    }
}

#[test]
fn test_create_reader_unknown_topic() {
    let mut participant = WasmParticipant::new(0);
    let ack = protocol::build_connect_ack(1, 0);
    participant.handle_connect_ack(&ack).unwrap();

    let result = participant.create_reader(999);
    match result {
        Err(WasmError::UnknownTopic(999)) => {}
        other => panic!("expected UnknownTopic, got {:?}", other),
    }
}

#[test]
fn test_duplicate_writer() {
    let mut participant = WasmParticipant::new(0);
    let ack = protocol::build_connect_ack(1, 0);
    participant.handle_connect_ack(&ack).unwrap();
    let topic_ack = protocol::build_topic_ack(1, "t", 0);
    participant.handle_topic_ack(&topic_ack).unwrap();

    participant.create_writer(1).unwrap();
    let result = participant.create_writer(1);
    match result {
        Err(WasmError::WriterAlreadyExists(1)) => {}
        other => panic!("expected WriterAlreadyExists, got {:?}", other),
    }
}

#[test]
fn test_duplicate_reader() {
    let mut participant = WasmParticipant::new(0);
    let ack = protocol::build_connect_ack(1, 0);
    participant.handle_connect_ack(&ack).unwrap();
    let topic_ack = protocol::build_topic_ack(1, "t", 0);
    participant.handle_topic_ack(&topic_ack).unwrap();

    participant.create_reader(1).unwrap();
    let result = participant.create_reader(1);
    match result {
        Err(WasmError::ReaderAlreadyExists(1)) => {}
        other => panic!("expected ReaderAlreadyExists, got {:?}", other),
    }
}

#[test]
fn test_relay_unknown_client_error() {
    let mut relay = RelayHandler::new();
    let create = protocol::build_create_topic("topic", "Type", 0);
    let result = relay.process_client_message(999, &create);
    // CONNECT would register the client, but CREATE_TOPIC requires existing client
    match result {
        Err(WasmError::UnknownClient(999)) => {}
        other => panic!("expected UnknownClient, got {:?}", other),
    }
}

#[test]
fn test_cdr_mixed_types_complex() {
    // Simulate a complex struct: u8 + u32 + string + f64 + bytes
    let mut enc = CdrEncoder::new();
    enc.encode_u8(7);
    enc.encode_u32(12345);
    enc.encode_string("sensor_reading");
    enc.encode_f64(98.6);
    enc.encode_bytes(&[0xDE, 0xAD]);

    let buf = enc.finish();
    let mut dec = CdrDecoder::new(&buf);

    assert_eq!(dec.decode_u8().unwrap(), 7);
    assert_eq!(dec.decode_u32().unwrap(), 12345);
    assert_eq!(dec.decode_string().unwrap(), "sensor_reading");
    let f = dec.decode_f64().unwrap();
    assert!((f - 98.6).abs() < 1e-10);
    assert_eq!(dec.decode_bytes().unwrap(), vec![0xDE, 0xAD]);
    assert_eq!(dec.remaining(), 0);
}

#[test]
fn test_error_display() {
    let err = WasmError::NotConnected;
    assert_eq!(format!("{}", err), "not connected to relay");

    let err = WasmError::UnknownMessageType(0xFE);
    assert_eq!(format!("{}", err), "unknown message type: 0xFE");

    let err = WasmError::MessageTooShort {
        expected: 8,
        actual: 3,
    };
    assert_eq!(
        format!("{}", err),
        "message too short: expected 8 bytes, got 3"
    );
}

#[test]
fn test_publish_empty_payload() {
    let msg = protocol::build_publish(1, 0, &[]);
    let parsed = protocol::parse_message(&msg).unwrap();
    match parsed {
        RelayMessage::Publish {
            topic_id, payload, ..
        } => {
            assert_eq!(topic_id, 1);
            assert!(payload.is_empty());
        }
        other => panic!("expected Publish, got {:?}", other),
    }
}

#[test]
fn test_relay_same_topic_shared_id() {
    let mut relay = RelayHandler::new();

    // Two clients create the same topic
    let (id1, _) = relay.accept_client();
    let (id2, _) = relay.accept_client();

    let connect1 = protocol::build_connect(0, 0);
    let connect2 = protocol::build_connect(0, 0);
    relay.process_client_message(id1, &connect1).unwrap();
    relay.process_client_message(id2, &connect2).unwrap();

    let create1 = protocol::build_create_topic("shared", "SharedType", 0);
    let resp1 = relay.process_client_message(id1, &create1).unwrap();
    let tid1 = match protocol::parse_message(&resp1[0]).unwrap() {
        RelayMessage::TopicAck { topic_id, .. } => topic_id,
        _ => panic!("expected TopicAck"),
    };

    let create2 = protocol::build_create_topic("shared", "SharedType", 0);
    let resp2 = relay.process_client_message(id2, &create2).unwrap();
    let tid2 = match protocol::parse_message(&resp2[0]).unwrap() {
        RelayMessage::TopicAck { topic_id, .. } => topic_id,
        _ => panic!("expected TopicAck"),
    };

    // Same topic name -> same topic ID
    assert_eq!(tid1, tid2);
}
