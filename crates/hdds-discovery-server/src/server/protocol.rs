// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Discovery Server wire protocol.
//!
//! Simple length-prefixed JSON protocol for discovery messages.
//! This is a custom protocol for HDDS discovery server, not interoperable
//! with other DDS vendors' discovery servers.
//!
//! Wire format:
//! ```text
//! +----------------+-------------------+
//! | Length (4B BE) | JSON payload      |
//! +----------------+-------------------+
//! ```

use super::registry::{EndpointInfo, EntityId, Guid, GuidPrefix, ParticipantInfo};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

/// Discovery protocol message types.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum DiscoveryMessage {
    /// Participant announces itself to the server.
    #[serde(rename = "participant_announce")]
    ParticipantAnnounce(ParticipantInfoWire),

    /// Server acknowledges participant registration.
    #[serde(rename = "participant_ack")]
    ParticipantAck { guid_prefix: GuidPrefixWire },

    /// Participant is leaving.
    #[serde(rename = "participant_leave")]
    ParticipantLeave { guid_prefix: GuidPrefixWire },

    /// Endpoint (writer/reader) announcement.
    #[serde(rename = "endpoint_announce")]
    EndpointAnnounce(EndpointInfoWire),

    /// Heartbeat to keep lease alive.
    #[serde(rename = "heartbeat")]
    Heartbeat { guid_prefix: GuidPrefixWire },

    /// Error message.
    #[serde(rename = "error")]
    Error { code: u32, message: String },

    /// Data relay (when relay mode enabled).
    #[serde(rename = "data")]
    Data {
        destination: GuidPrefixWire,
        payload: Vec<u8>,
    },
}

/// Wire format for GUID prefix (hex string for JSON compatibility).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(transparent)]
pub struct GuidPrefixWire(pub String);

impl From<GuidPrefix> for GuidPrefixWire {
    fn from(gp: GuidPrefix) -> Self {
        Self(hex::encode(gp))
    }
}

impl From<&GuidPrefix> for GuidPrefixWire {
    fn from(gp: &GuidPrefix) -> Self {
        Self(hex::encode(gp))
    }
}

impl TryFrom<GuidPrefixWire> for GuidPrefix {
    type Error = ProtocolError;

    fn try_from(wire: GuidPrefixWire) -> Result<Self, Self::Error> {
        let bytes = hex::decode(&wire.0).map_err(|_| ProtocolError::InvalidGuidPrefix)?;
        if bytes.len() != 12 {
            return Err(ProtocolError::InvalidGuidPrefix);
        }
        let mut gp = [0u8; 12];
        gp.copy_from_slice(&bytes);
        Ok(gp)
    }
}

/// Wire format for Entity ID (hex string).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(transparent)]
pub struct EntityIdWire(pub String);

impl From<EntityId> for EntityIdWire {
    fn from(eid: EntityId) -> Self {
        Self(hex::encode(eid))
    }
}

impl TryFrom<EntityIdWire> for EntityId {
    type Error = ProtocolError;

    fn try_from(wire: EntityIdWire) -> Result<Self, Self::Error> {
        let bytes = hex::decode(&wire.0).map_err(|_| ProtocolError::InvalidEntityId)?;
        if bytes.len() != 4 {
            return Err(ProtocolError::InvalidEntityId);
        }
        let mut eid = [0u8; 4];
        eid.copy_from_slice(&bytes);
        Ok(eid)
    }
}

/// Wire format for participant info.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParticipantInfoWire {
    pub guid_prefix: GuidPrefixWire,
    pub domain_id: u32,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub unicast_locators: Vec<String>,
    #[serde(default)]
    pub default_unicast_locators: Vec<String>,
    #[serde(default = "default_vendor_id")]
    pub vendor_id: [u8; 2],
    #[serde(default = "default_protocol_version")]
    pub protocol_version: (u8, u8),
    #[serde(default)]
    pub builtin_endpoints: u32,
}

fn default_vendor_id() -> [u8; 2] {
    [0x01, 0x10]
}

fn default_protocol_version() -> (u8, u8) {
    (2, 4)
}

impl From<ParticipantInfo> for ParticipantInfoWire {
    fn from(info: ParticipantInfo) -> Self {
        Self {
            guid_prefix: info.guid_prefix.into(),
            domain_id: info.domain_id,
            name: info.name,
            unicast_locators: info
                .unicast_locators
                .iter()
                .map(|a| a.to_string())
                .collect(),
            default_unicast_locators: info
                .default_unicast_locators
                .iter()
                .map(|a| a.to_string())
                .collect(),
            vendor_id: info.vendor_id,
            protocol_version: info.protocol_version,
            builtin_endpoints: info.builtin_endpoints,
        }
    }
}

impl TryFrom<ParticipantInfoWire> for ParticipantInfo {
    type Error = ProtocolError;

    fn try_from(wire: ParticipantInfoWire) -> Result<Self, Self::Error> {
        let guid_prefix: GuidPrefix = wire.guid_prefix.try_into()?;

        let unicast_locators: Vec<SocketAddr> = wire
            .unicast_locators
            .iter()
            .filter_map(|s| s.parse().ok())
            .collect();

        let default_unicast_locators: Vec<SocketAddr> = wire
            .default_unicast_locators
            .iter()
            .filter_map(|s| s.parse().ok())
            .collect();

        let mut info = ParticipantInfo::new(guid_prefix, wire.domain_id);
        info.name = wire.name;
        info.unicast_locators = unicast_locators;
        info.default_unicast_locators = default_unicast_locators;
        info.vendor_id = wire.vendor_id;
        info.protocol_version = wire.protocol_version;
        info.builtin_endpoints = wire.builtin_endpoints;

        Ok(info)
    }
}

/// Wire format for endpoint info.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointInfoWire {
    pub guid_prefix: GuidPrefixWire,
    pub entity_id: EntityIdWire,
    pub topic_name: String,
    pub type_name: String,
    pub is_writer: bool,
    #[serde(default)]
    pub reliable: bool,
    #[serde(default)]
    pub durability: u8,
    #[serde(default)]
    pub unicast_locators: Vec<String>,
}

impl From<EndpointInfo> for EndpointInfoWire {
    fn from(info: EndpointInfo) -> Self {
        Self {
            guid_prefix: info.guid.prefix.into(),
            entity_id: info.guid.entity_id.into(),
            topic_name: info.topic_name,
            type_name: info.type_name,
            is_writer: info.is_writer,
            reliable: info.reliable,
            durability: info.durability,
            unicast_locators: info
                .unicast_locators
                .iter()
                .map(|a| a.to_string())
                .collect(),
        }
    }
}

impl TryFrom<EndpointInfoWire> for EndpointInfo {
    type Error = ProtocolError;

    fn try_from(wire: EndpointInfoWire) -> Result<Self, Self::Error> {
        let guid_prefix: GuidPrefix = wire.guid_prefix.try_into()?;
        let entity_id: EntityId = wire.entity_id.try_into()?;

        let unicast_locators: Vec<SocketAddr> = wire
            .unicast_locators
            .iter()
            .filter_map(|s| s.parse().ok())
            .collect();

        Ok(Self {
            guid: Guid {
                prefix: guid_prefix,
                entity_id,
            },
            topic_name: wire.topic_name,
            type_name: wire.type_name,
            is_writer: wire.is_writer,
            reliable: wire.reliable,
            durability: wire.durability,
            unicast_locators,
        })
    }
}

/// Protocol error types.
#[derive(Debug, Clone)]
pub enum ProtocolError {
    InvalidGuidPrefix,
    InvalidEntityId,
    InvalidMessage(String),
    IoError(String),
}

impl std::fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidGuidPrefix => write!(f, "Invalid GUID prefix"),
            Self::InvalidEntityId => write!(f, "Invalid entity ID"),
            Self::InvalidMessage(s) => write!(f, "Invalid message: {}", s),
            Self::IoError(s) => write!(f, "I/O error: {}", s),
        }
    }
}

impl std::error::Error for ProtocolError {}

/// Hex encoding/decoding utilities.
mod hex {
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        bytes
            .as_ref()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect()
    }

    pub fn decode(s: &str) -> Result<Vec<u8>, ()> {
        if !s.len().is_multiple_of(2) {
            return Err(());
        }
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| ()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_guid_prefix_wire_roundtrip() {
        let gp: GuidPrefix = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let wire: GuidPrefixWire = gp.into();
        let back: GuidPrefix = wire.try_into().unwrap();
        assert_eq!(gp, back);
    }

    #[test]
    fn test_entity_id_wire_roundtrip() {
        let eid: EntityId = [0x00, 0x00, 0x01, 0xc2];
        let wire: EntityIdWire = eid.into();
        let back: EntityId = wire.try_into().unwrap();
        assert_eq!(eid, back);
    }

    #[test]
    fn test_participant_announce_serialize() {
        let msg = DiscoveryMessage::ParticipantAnnounce(ParticipantInfoWire {
            guid_prefix: GuidPrefixWire("010203040506070809101112".into()),
            domain_id: 0,
            name: Some("TestParticipant".into()),
            unicast_locators: vec!["192.168.1.1:7400".into()],
            default_unicast_locators: vec![],
            vendor_id: [0x01, 0x10],
            protocol_version: (2, 4),
            builtin_endpoints: 0,
        });

        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("participant_announce"));
        assert!(json.contains("TestParticipant"));

        let parsed: DiscoveryMessage = serde_json::from_str(&json).unwrap();
        match parsed {
            DiscoveryMessage::ParticipantAnnounce(info) => {
                assert_eq!(info.domain_id, 0);
                assert_eq!(info.name, Some("TestParticipant".into()));
            }
            _ => panic!("Wrong message type"),
        }
    }

    #[test]
    fn test_heartbeat_serialize() {
        let msg = DiscoveryMessage::Heartbeat {
            guid_prefix: GuidPrefixWire("aabbccddeeff001122334455".into()),
        };

        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("heartbeat"));

        let parsed: DiscoveryMessage = serde_json::from_str(&json).unwrap();
        match parsed {
            DiscoveryMessage::Heartbeat { guid_prefix } => {
                assert_eq!(guid_prefix.0, "aabbccddeeff001122334455");
            }
            _ => panic!("Wrong message type"),
        }
    }

    #[test]
    fn test_error_serialize() {
        let msg = DiscoveryMessage::Error {
            code: 1,
            message: "Max participants reached".into(),
        };

        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("error"));
        assert!(json.contains("Max participants"));
    }

    #[test]
    fn test_endpoint_announce_serialize() {
        let msg = DiscoveryMessage::EndpointAnnounce(EndpointInfoWire {
            guid_prefix: GuidPrefixWire("010203040506070809101112".into()),
            entity_id: EntityIdWire("000001c2".into()),
            topic_name: "sensor/temperature".into(),
            type_name: "Temperature".into(),
            is_writer: true,
            reliable: true,
            durability: 0,
            unicast_locators: vec![],
        });

        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("endpoint_announce"));
        assert!(json.contains("sensor/temperature"));
    }

    #[test]
    fn test_hex_encode_decode() {
        let data = [0xde, 0xad, 0xbe, 0xef];
        let encoded = hex::encode(data);
        assert_eq!(encoded, "deadbeef");

        let decoded = hex::decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_hex_decode_invalid() {
        assert!(hex::decode("xyz").is_err());
        assert!(hex::decode("abc").is_err()); // Odd length
    }
}
