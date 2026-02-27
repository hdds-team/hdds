// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

// HDDS WASM SDK - Wire protocol between WASM client and relay

use crate::error::WasmError;

// --- Message type constants ---

pub const MSG_CONNECT: u8 = 0x01;
pub const MSG_CONNECT_ACK: u8 = 0x02;
pub const MSG_CREATE_TOPIC: u8 = 0x03;
pub const MSG_TOPIC_ACK: u8 = 0x04;
pub const MSG_SUBSCRIBE: u8 = 0x05;
pub const MSG_UNSUBSCRIBE: u8 = 0x06;
pub const MSG_PUBLISH: u8 = 0x07;
pub const MSG_DATA: u8 = 0x08;
pub const MSG_DISCONNECT: u8 = 0x09;
pub const MSG_PING: u8 = 0x0A;
pub const MSG_PONG: u8 = 0x0B;
pub const MSG_ERROR: u8 = 0x0F;

/// Size of the message header in bytes.
pub const HEADER_SIZE: usize = 8;

/// Message header (8 bytes):
///   message_type: u8
///   flags: u8
///   topic_id: u16 (LE)
///   sequence_nr: u32 (LE)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageHeader {
    pub message_type: u8,
    pub flags: u8,
    pub topic_id: u16,
    pub sequence_nr: u32,
}

impl MessageHeader {
    /// Create a new header.
    pub fn new(message_type: u8, flags: u8, topic_id: u16, sequence_nr: u32) -> Self {
        Self {
            message_type,
            flags,
            topic_id,
            sequence_nr,
        }
    }

    /// Encode header to bytes (8 bytes).
    pub fn encode(&self) -> [u8; HEADER_SIZE] {
        let mut buf = [0u8; HEADER_SIZE];
        buf[0] = self.message_type;
        buf[1] = self.flags;
        buf[2..4].copy_from_slice(&self.topic_id.to_le_bytes());
        buf[4..8].copy_from_slice(&self.sequence_nr.to_le_bytes());
        buf
    }

    /// Decode header from bytes.
    pub fn decode(data: &[u8]) -> Result<Self, WasmError> {
        if data.len() < HEADER_SIZE {
            return Err(WasmError::MessageTooShort {
                expected: HEADER_SIZE,
                actual: data.len(),
            });
        }
        Ok(Self {
            message_type: data[0],
            flags: data[1],
            topic_id: u16::from_le_bytes([data[2], data[3]]),
            sequence_nr: u32::from_le_bytes([data[4], data[5], data[6], data[7]]),
        })
    }
}

/// Parsed relay message with payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayMessage {
    /// Connection acknowledged by relay.
    ConnectAck {
        participant_id: u32,
    },
    /// Topic created and assigned an ID.
    TopicAck {
        topic_id: u16,
        topic_name: String,
    },
    /// Incoming data on a topic.
    Data {
        topic_id: u16,
        sequence_nr: u32,
        payload: Vec<u8>,
    },
    /// Pong keepalive response.
    Pong {
        sequence_nr: u32,
    },
    /// Error from relay.
    Error {
        reason: String,
    },
    /// Disconnect acknowledged.
    Disconnected,
    /// Connect request (relay-side).
    Connect {
        domain_id: u16,
    },
    /// Create topic request (relay-side).
    CreateTopic {
        topic_name: String,
        type_name: String,
    },
    /// Subscribe request (relay-side).
    Subscribe {
        topic_id: u16,
    },
    /// Unsubscribe request (relay-side).
    Unsubscribe {
        topic_id: u16,
    },
    /// Publish request (relay-side).
    Publish {
        topic_id: u16,
        sequence_nr: u32,
        payload: Vec<u8>,
    },
    /// Ping keepalive.
    Ping {
        sequence_nr: u32,
    },
}

// --- Payload builders (encode) ---

/// Build a CONNECT message. Payload: domain_id (u16 LE).
pub fn build_connect(domain_id: u16, sequence_nr: u32) -> Vec<u8> {
    let header = MessageHeader::new(MSG_CONNECT, 0, 0, sequence_nr);
    let mut msg = Vec::with_capacity(HEADER_SIZE + 2);
    msg.extend_from_slice(&header.encode());
    msg.extend_from_slice(&domain_id.to_le_bytes());
    msg
}

/// Build a CONNECT_ACK message. Payload: participant_id (u32 LE).
pub fn build_connect_ack(participant_id: u32, sequence_nr: u32) -> Vec<u8> {
    let header = MessageHeader::new(MSG_CONNECT_ACK, 0, 0, sequence_nr);
    let mut msg = Vec::with_capacity(HEADER_SIZE + 4);
    msg.extend_from_slice(&header.encode());
    msg.extend_from_slice(&participant_id.to_le_bytes());
    msg
}

/// Build a CREATE_TOPIC message.
/// Payload: name_len (u16 LE) + name_bytes + type_name_len (u16 LE) + type_name_bytes.
pub fn build_create_topic(
    topic_name: &str,
    type_name: &str,
    sequence_nr: u32,
) -> Vec<u8> {
    let name_bytes = topic_name.as_bytes();
    let type_bytes = type_name.as_bytes();
    let payload_len = 2 + name_bytes.len() + 2 + type_bytes.len();
    let header = MessageHeader::new(MSG_CREATE_TOPIC, 0, 0, sequence_nr);
    let mut msg = Vec::with_capacity(HEADER_SIZE + payload_len);
    msg.extend_from_slice(&header.encode());
    msg.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
    msg.extend_from_slice(name_bytes);
    msg.extend_from_slice(&(type_bytes.len() as u16).to_le_bytes());
    msg.extend_from_slice(type_bytes);
    msg
}

/// Build a TOPIC_ACK message.
/// Payload: topic_id (u16 LE) + name_len (u16 LE) + name_bytes.
pub fn build_topic_ack(
    topic_id: u16,
    topic_name: &str,
    sequence_nr: u32,
) -> Vec<u8> {
    let name_bytes = topic_name.as_bytes();
    let header = MessageHeader::new(MSG_TOPIC_ACK, 0, topic_id, sequence_nr);
    let mut msg = Vec::with_capacity(HEADER_SIZE + 2 + 2 + name_bytes.len());
    msg.extend_from_slice(&header.encode());
    msg.extend_from_slice(&topic_id.to_le_bytes());
    msg.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
    msg.extend_from_slice(name_bytes);
    msg
}

/// Build a SUBSCRIBE message. No extra payload beyond header.
pub fn build_subscribe(topic_id: u16, sequence_nr: u32) -> Vec<u8> {
    let header = MessageHeader::new(MSG_SUBSCRIBE, 0, topic_id, sequence_nr);
    header.encode().to_vec()
}

/// Build an UNSUBSCRIBE message. No extra payload beyond header.
pub fn build_unsubscribe(topic_id: u16, sequence_nr: u32) -> Vec<u8> {
    let header = MessageHeader::new(MSG_UNSUBSCRIBE, 0, topic_id, sequence_nr);
    header.encode().to_vec()
}

/// Build a PUBLISH message. Payload: CDR data bytes.
pub fn build_publish(topic_id: u16, sequence_nr: u32, cdr_data: &[u8]) -> Vec<u8> {
    let header = MessageHeader::new(MSG_PUBLISH, 0, topic_id, sequence_nr);
    let mut msg = Vec::with_capacity(HEADER_SIZE + cdr_data.len());
    msg.extend_from_slice(&header.encode());
    msg.extend_from_slice(cdr_data);
    msg
}

/// Build a DATA message (relay to client). Payload: CDR data bytes.
pub fn build_data(topic_id: u16, sequence_nr: u32, cdr_data: &[u8]) -> Vec<u8> {
    let header = MessageHeader::new(MSG_DATA, 0, topic_id, sequence_nr);
    let mut msg = Vec::with_capacity(HEADER_SIZE + cdr_data.len());
    msg.extend_from_slice(&header.encode());
    msg.extend_from_slice(cdr_data);
    msg
}

/// Build a DISCONNECT message. No payload.
pub fn build_disconnect(sequence_nr: u32) -> Vec<u8> {
    let header = MessageHeader::new(MSG_DISCONNECT, 0, 0, sequence_nr);
    header.encode().to_vec()
}

/// Build a PING message. No payload.
pub fn build_ping(sequence_nr: u32) -> Vec<u8> {
    let header = MessageHeader::new(MSG_PING, 0, 0, sequence_nr);
    header.encode().to_vec()
}

/// Build a PONG message. No payload.
pub fn build_pong(sequence_nr: u32) -> Vec<u8> {
    let header = MessageHeader::new(MSG_PONG, 0, 0, sequence_nr);
    header.encode().to_vec()
}

/// Build an ERROR message. Payload: reason string bytes.
pub fn build_error(reason: &str, sequence_nr: u32) -> Vec<u8> {
    let reason_bytes = reason.as_bytes();
    let header = MessageHeader::new(MSG_ERROR, 0, 0, sequence_nr);
    let mut msg = Vec::with_capacity(HEADER_SIZE + 2 + reason_bytes.len());
    msg.extend_from_slice(&header.encode());
    msg.extend_from_slice(&(reason_bytes.len() as u16).to_le_bytes());
    msg.extend_from_slice(reason_bytes);
    msg
}

// --- Message parsing (decode) ---

/// Parse any relay message from raw bytes.
pub fn parse_message(data: &[u8]) -> Result<RelayMessage, WasmError> {
    let header = MessageHeader::decode(data)?;
    let payload = &data[HEADER_SIZE..];

    match header.message_type {
        MSG_CONNECT => parse_connect(payload),
        MSG_CONNECT_ACK => parse_connect_ack(payload),
        MSG_CREATE_TOPIC => parse_create_topic(payload),
        MSG_TOPIC_ACK => parse_topic_ack(payload, &header),
        MSG_SUBSCRIBE => Ok(RelayMessage::Subscribe {
            topic_id: header.topic_id,
        }),
        MSG_UNSUBSCRIBE => Ok(RelayMessage::Unsubscribe {
            topic_id: header.topic_id,
        }),
        MSG_PUBLISH => Ok(RelayMessage::Publish {
            topic_id: header.topic_id,
            sequence_nr: header.sequence_nr,
            payload: payload.to_vec(),
        }),
        MSG_DATA => Ok(RelayMessage::Data {
            topic_id: header.topic_id,
            sequence_nr: header.sequence_nr,
            payload: payload.to_vec(),
        }),
        MSG_DISCONNECT => Ok(RelayMessage::Disconnected),
        MSG_PING => Ok(RelayMessage::Ping {
            sequence_nr: header.sequence_nr,
        }),
        MSG_PONG => Ok(RelayMessage::Pong {
            sequence_nr: header.sequence_nr,
        }),
        MSG_ERROR => parse_error(payload),
        unknown => Err(WasmError::UnknownMessageType(unknown)),
    }
}

fn parse_connect(payload: &[u8]) -> Result<RelayMessage, WasmError> {
    if payload.len() < 2 {
        return Err(WasmError::MessageTooShort {
            expected: HEADER_SIZE + 2,
            actual: HEADER_SIZE + payload.len(),
        });
    }
    let domain_id = u16::from_le_bytes([payload[0], payload[1]]);
    Ok(RelayMessage::Connect { domain_id })
}

fn parse_connect_ack(payload: &[u8]) -> Result<RelayMessage, WasmError> {
    if payload.len() < 4 {
        return Err(WasmError::MessageTooShort {
            expected: HEADER_SIZE + 4,
            actual: HEADER_SIZE + payload.len(),
        });
    }
    let participant_id =
        u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
    Ok(RelayMessage::ConnectAck { participant_id })
}

fn parse_create_topic(payload: &[u8]) -> Result<RelayMessage, WasmError> {
    if payload.len() < 2 {
        return Err(WasmError::MessageTooShort {
            expected: HEADER_SIZE + 2,
            actual: HEADER_SIZE + payload.len(),
        });
    }
    let name_len = u16::from_le_bytes([payload[0], payload[1]]) as usize;
    if payload.len() < 2 + name_len + 2 {
        return Err(WasmError::MessageTooShort {
            expected: HEADER_SIZE + 2 + name_len + 2,
            actual: HEADER_SIZE + payload.len(),
        });
    }
    let topic_name = String::from_utf8_lossy(&payload[2..2 + name_len]).to_string();
    let offset = 2 + name_len;
    let type_len = u16::from_le_bytes([payload[offset], payload[offset + 1]]) as usize;
    if payload.len() < offset + 2 + type_len {
        return Err(WasmError::MessageTooShort {
            expected: HEADER_SIZE + offset + 2 + type_len,
            actual: HEADER_SIZE + payload.len(),
        });
    }
    let type_name =
        String::from_utf8_lossy(&payload[offset + 2..offset + 2 + type_len]).to_string();
    Ok(RelayMessage::CreateTopic {
        topic_name,
        type_name,
    })
}

fn parse_topic_ack(payload: &[u8], header: &MessageHeader) -> Result<RelayMessage, WasmError> {
    // payload: topic_id (u16 LE) + name_len (u16 LE) + name_bytes
    if payload.len() < 4 {
        return Err(WasmError::MessageTooShort {
            expected: HEADER_SIZE + 4,
            actual: HEADER_SIZE + payload.len(),
        });
    }
    let topic_id = u16::from_le_bytes([payload[0], payload[1]]);
    let name_len = u16::from_le_bytes([payload[2], payload[3]]) as usize;
    if payload.len() < 4 + name_len {
        return Err(WasmError::MessageTooShort {
            expected: HEADER_SIZE + 4 + name_len,
            actual: HEADER_SIZE + payload.len(),
        });
    }
    let topic_name = String::from_utf8_lossy(&payload[4..4 + name_len]).to_string();
    // Use topic_id from payload (authoritative), header.topic_id is also set but payload wins
    let _ = header;
    Ok(RelayMessage::TopicAck {
        topic_id,
        topic_name,
    })
}

fn parse_error(payload: &[u8]) -> Result<RelayMessage, WasmError> {
    if payload.len() < 2 {
        return Err(WasmError::MessageTooShort {
            expected: HEADER_SIZE + 2,
            actual: HEADER_SIZE + payload.len(),
        });
    }
    let reason_len = u16::from_le_bytes([payload[0], payload[1]]) as usize;
    if payload.len() < 2 + reason_len {
        return Err(WasmError::MessageTooShort {
            expected: HEADER_SIZE + 2 + reason_len,
            actual: HEADER_SIZE + payload.len(),
        });
    }
    let reason = String::from_utf8_lossy(&payload[2..2 + reason_len]).to_string();
    Ok(RelayMessage::Error { reason })
}
