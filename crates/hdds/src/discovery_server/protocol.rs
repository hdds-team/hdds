// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Discovery Server wire protocol (client-side).
//!
//! Compatible with hdds-discovery-server protocol.

use std::io;
use std::net::SocketAddr;

/// GUID prefix (12 bytes).
pub type GuidPrefix = [u8; 12];

/// Entity ID (4 bytes).
pub type EntityId = [u8; 4];

/// Messages sent by the client to the server.
#[derive(Debug, Clone)]
pub enum ClientMessage {
    /// Announce this participant to the server.
    ParticipantAnnounce {
        guid_prefix: GuidPrefix,
        domain_id: u32,
        name: Option<String>,
        unicast_locators: Vec<SocketAddr>,
        builtin_endpoints: u32,
    },

    /// Announce an endpoint (writer/reader).
    EndpointAnnounce {
        guid_prefix: GuidPrefix,
        entity_id: EntityId,
        topic_name: String,
        type_name: String,
        is_writer: bool,
        reliable: bool,
        durability: u8,
        unicast_locators: Vec<SocketAddr>,
    },

    /// Keep-alive heartbeat.
    Heartbeat { guid_prefix: GuidPrefix },

    /// Participant is leaving.
    ParticipantLeave { guid_prefix: GuidPrefix },
}

/// Messages received from the server.
#[derive(Debug, Clone)]
pub enum ServerMessage {
    /// Server acknowledges participant registration.
    ParticipantAck { guid_prefix: GuidPrefix },

    /// Another participant announced (from server broadcast).
    ParticipantAnnounce {
        guid_prefix: GuidPrefix,
        domain_id: u32,
        name: Option<String>,
        unicast_locators: Vec<SocketAddr>,
        builtin_endpoints: u32,
    },

    /// Participant left.
    ParticipantLeave { guid_prefix: GuidPrefix },

    /// Endpoint announced by another participant.
    EndpointAnnounce {
        guid_prefix: GuidPrefix,
        entity_id: EntityId,
        topic_name: String,
        type_name: String,
        is_writer: bool,
        reliable: bool,
        durability: u8,
        unicast_locators: Vec<SocketAddr>,
    },

    /// Error from server.
    Error { code: u32, message: String },
}

// ============================================================================
// Wire format encoding/decoding (JSON with length prefix)
// ============================================================================

impl ClientMessage {
    /// Encode message to wire format.
    pub fn encode(&self) -> io::Result<Vec<u8>> {
        let json = self.to_json()?;
        let len = json.len() as u32;

        let mut buf = Vec::with_capacity(4 + json.len());
        buf.extend_from_slice(&len.to_be_bytes());
        buf.extend_from_slice(json.as_bytes());
        Ok(buf)
    }

    fn to_json(&self) -> io::Result<String> {
        match self {
            Self::ParticipantAnnounce {
                guid_prefix,
                domain_id,
                name,
                unicast_locators,
                builtin_endpoints,
            } => {
                let json = format!(
                    r#"{{"type":"participant_announce","guid_prefix":"{}","domain_id":{},"name":{},"unicast_locators":[{}],"vendor_id":[1,16],"protocol_version":[2,4],"builtin_endpoints":{}}}"#,
                    hex_encode(guid_prefix),
                    domain_id,
                    name.as_ref()
                        .map(|n| format!("\"{}\"", n))
                        .unwrap_or_else(|| "null".to_string()),
                    unicast_locators
                        .iter()
                        .map(|a| format!("\"{}\"", a))
                        .collect::<Vec<_>>()
                        .join(","),
                    builtin_endpoints,
                );
                Ok(json)
            }

            Self::EndpointAnnounce {
                guid_prefix,
                entity_id,
                topic_name,
                type_name,
                is_writer,
                reliable,
                durability,
                unicast_locators,
            } => {
                let json = format!(
                    r#"{{"type":"endpoint_announce","guid_prefix":"{}","entity_id":"{}","topic_name":"{}","type_name":"{}","is_writer":{},"reliable":{},"durability":{},"unicast_locators":[{}]}}"#,
                    hex_encode(guid_prefix),
                    hex_encode(entity_id),
                    topic_name,
                    type_name,
                    is_writer,
                    reliable,
                    durability,
                    unicast_locators
                        .iter()
                        .map(|a| format!("\"{}\"", a))
                        .collect::<Vec<_>>()
                        .join(","),
                );
                Ok(json)
            }

            Self::Heartbeat { guid_prefix } => {
                let json = format!(
                    r#"{{"type":"heartbeat","guid_prefix":"{}"}}"#,
                    hex_encode(guid_prefix),
                );
                Ok(json)
            }

            Self::ParticipantLeave { guid_prefix } => {
                let json = format!(
                    r#"{{"type":"participant_leave","guid_prefix":"{}"}}"#,
                    hex_encode(guid_prefix),
                );
                Ok(json)
            }
        }
    }
}

impl ServerMessage {
    /// Decode message from wire format (without length prefix).
    pub fn decode(data: &[u8]) -> io::Result<Self> {
        // Simple JSON parsing (minimal, no serde dependency in core)
        let s =
            std::str::from_utf8(data).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        Self::from_json(s)
    }

    // @audit-ok: Simple pattern matching (cyclo 15, cogni 1) - JSON message type dispatch
    fn from_json(s: &str) -> io::Result<Self> {
        // Extract message type
        let msg_type = extract_string_field(s, "type")?;

        match msg_type.as_str() {
            "participant_ack" => {
                let guid_prefix = extract_guid_prefix(s, "guid_prefix")?;
                Ok(Self::ParticipantAck { guid_prefix })
            }

            "participant_announce" => {
                let guid_prefix = extract_guid_prefix(s, "guid_prefix")?;
                let domain_id = extract_u32_field(s, "domain_id").unwrap_or(0);
                let name = extract_string_field(s, "name").ok();
                let unicast_locators = extract_locators(s, "unicast_locators");
                let builtin_endpoints = extract_u32_field(s, "builtin_endpoints").unwrap_or(0);

                Ok(Self::ParticipantAnnounce {
                    guid_prefix,
                    domain_id,
                    name,
                    unicast_locators,
                    builtin_endpoints,
                })
            }

            "participant_leave" => {
                let guid_prefix = extract_guid_prefix(s, "guid_prefix")?;
                Ok(Self::ParticipantLeave { guid_prefix })
            }

            "endpoint_announce" => {
                let guid_prefix = extract_guid_prefix(s, "guid_prefix")?;
                let entity_id = extract_entity_id(s, "entity_id")?;
                let topic_name = extract_string_field(s, "topic_name")?;
                let type_name = extract_string_field(s, "type_name")?;
                let is_writer = extract_bool_field(s, "is_writer").unwrap_or(false);
                let reliable = extract_bool_field(s, "reliable").unwrap_or(false);
                let durability = extract_u32_field(s, "durability").unwrap_or(0) as u8;
                let unicast_locators = extract_locators(s, "unicast_locators");

                Ok(Self::EndpointAnnounce {
                    guid_prefix,
                    entity_id,
                    topic_name,
                    type_name,
                    is_writer,
                    reliable,
                    durability,
                    unicast_locators,
                })
            }

            "error" => {
                let code = extract_u32_field(s, "code").unwrap_or(0);
                let message = extract_string_field(s, "message").unwrap_or_default();
                Ok(Self::Error { code, message })
            }

            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Unknown message type: {}", msg_type),
            )),
        }
    }
}

// ============================================================================
// JSON parsing helpers (minimal, no serde)
// ============================================================================

fn extract_string_field(json: &str, field: &str) -> io::Result<String> {
    let pattern = format!("\"{}\":\"", field);
    if let Some(start) = json.find(&pattern) {
        let value_start = start + pattern.len();
        if let Some(end) = json[value_start..].find('"') {
            return Ok(json[value_start..value_start + end].to_string());
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        format!("Field '{}' not found", field),
    ))
}

fn extract_u32_field(json: &str, field: &str) -> Option<u32> {
    let pattern = format!("\"{}\":", field);
    if let Some(start) = json.find(&pattern) {
        let value_start = start + pattern.len();
        let remaining = &json[value_start..];
        // Skip whitespace
        let remaining = remaining.trim_start();
        // Extract digits
        let end = remaining
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(remaining.len());
        if end > 0 {
            return remaining[..end].parse().ok();
        }
    }
    None
}

fn extract_bool_field(json: &str, field: &str) -> Option<bool> {
    let pattern = format!("\"{}\":", field);
    if let Some(start) = json.find(&pattern) {
        let value_start = start + pattern.len();
        let remaining = &json[value_start..].trim_start();
        if remaining.starts_with("true") {
            return Some(true);
        } else if remaining.starts_with("false") {
            return Some(false);
        }
    }
    None
}

fn extract_guid_prefix(json: &str, field: &str) -> io::Result<GuidPrefix> {
    let hex = extract_string_field(json, field)?;
    let bytes = hex_decode(&hex)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid GUID prefix hex"))?;
    if bytes.len() != 12 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "GUID prefix must be 12 bytes",
        ));
    }
    let mut gp = [0u8; 12];
    gp.copy_from_slice(&bytes);
    Ok(gp)
}

fn extract_entity_id(json: &str, field: &str) -> io::Result<EntityId> {
    let hex = extract_string_field(json, field)?;
    let bytes = hex_decode(&hex)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid entity ID hex"))?;
    if bytes.len() != 4 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Entity ID must be 4 bytes",
        ));
    }
    let mut eid = [0u8; 4];
    eid.copy_from_slice(&bytes);
    Ok(eid)
}

fn extract_locators(json: &str, field: &str) -> Vec<SocketAddr> {
    let pattern = format!("\"{}\":[", field);
    if let Some(start) = json.find(&pattern) {
        let array_start = start + pattern.len();
        if let Some(end) = json[array_start..].find(']') {
            let array_content = &json[array_start..array_start + end];
            return array_content
                .split(',')
                .filter_map(|s| {
                    let s = s.trim().trim_matches('"');
                    s.parse().ok()
                })
                .collect();
        }
    }
    Vec::new()
}

// ============================================================================
// Hex utilities
// ============================================================================

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hex_decode(s: &str) -> Result<Vec<u8>, ()> {
    if !s.len().is_multiple_of(2) {
        return Err(());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| ()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_message_encode_participant_announce() {
        let msg = ClientMessage::ParticipantAnnounce {
            guid_prefix: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
            domain_id: 0,
            name: Some("TestParticipant".into()),
            unicast_locators: vec!["192.168.1.1:7400".parse().unwrap()],
            builtin_endpoints: 0x3f,
        };

        let encoded = msg.encode().unwrap();
        assert!(encoded.len() > 4);

        // Check length prefix
        let len = u32::from_be_bytes([encoded[0], encoded[1], encoded[2], encoded[3]]);
        assert_eq!(len as usize, encoded.len() - 4);

        // Check JSON content
        let json = std::str::from_utf8(&encoded[4..]).unwrap();
        assert!(json.contains("participant_announce"));
        assert!(json.contains("TestParticipant"));
    }

    #[test]
    fn test_client_message_encode_heartbeat() {
        let msg = ClientMessage::Heartbeat {
            guid_prefix: [0xaa; 12],
        };

        let encoded = msg.encode().unwrap();
        let json = std::str::from_utf8(&encoded[4..]).unwrap();
        assert!(json.contains("heartbeat"));
        assert!(json.contains("aaaaaaaaaaaaaaaaaaaaaaaa"));
    }

    #[test]
    fn test_server_message_decode_participant_ack() {
        let json = r#"{"type":"participant_ack","guid_prefix":"0102030405060708090a0b0c"}"#;
        let msg = ServerMessage::decode(json.as_bytes()).unwrap();

        match msg {
            ServerMessage::ParticipantAck { guid_prefix } => {
                assert_eq!(guid_prefix, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
            }
            other => assert!(
                matches!(other, ServerMessage::ParticipantAck { .. }),
                "Expected ParticipantAck, got {:?}",
                other
            ),
        }
    }

    #[test]
    fn test_server_message_decode_error() {
        let json = r#"{"type":"error","code":1,"message":"Max participants reached"}"#;
        let msg = ServerMessage::decode(json.as_bytes()).unwrap();

        match msg {
            ServerMessage::Error { code, message } => {
                assert_eq!(code, 1);
                assert_eq!(message, "Max participants reached");
            }
            other => assert!(
                matches!(other, ServerMessage::Error { .. }),
                "Expected Error, got {:?}",
                other
            ),
        }
    }

    #[test]
    fn test_server_message_decode_participant_announce() {
        let json = r#"{"type":"participant_announce","guid_prefix":"aabbccddeeff001122334455","domain_id":0,"name":"RemoteParticipant","unicast_locators":["10.0.0.1:7400"],"builtin_endpoints":63}"#;
        let msg = ServerMessage::decode(json.as_bytes()).unwrap();

        match msg {
            ServerMessage::ParticipantAnnounce {
                domain_id,
                name,
                unicast_locators,
                builtin_endpoints,
                ..
            } => {
                assert_eq!(domain_id, 0);
                assert_eq!(name, Some("RemoteParticipant".into()));
                assert_eq!(unicast_locators.len(), 1);
                assert_eq!(builtin_endpoints, 63);
            }
            other => assert!(
                matches!(other, ServerMessage::ParticipantAnnounce { .. }),
                "Expected ParticipantAnnounce, got {:?}",
                other
            ),
        }
    }

    #[test]
    fn test_hex_roundtrip() {
        let data = [0xde, 0xad, 0xbe, 0xef];
        let hex = hex_encode(&data);
        assert_eq!(hex, "deadbeef");

        let decoded = hex_decode(&hex).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_extract_u32_field() {
        let json = r#"{"domain_id":42,"other":"value"}"#;
        assert_eq!(extract_u32_field(json, "domain_id"), Some(42));
        assert_eq!(extract_u32_field(json, "missing"), None);
    }

    #[test]
    fn test_extract_bool_field() {
        let json = r#"{"is_writer":true,"reliable":false}"#;
        assert_eq!(extract_bool_field(json, "is_writer"), Some(true));
        assert_eq!(extract_bool_field(json, "reliable"), Some(false));
        assert_eq!(extract_bool_field(json, "missing"), None);
    }
}
