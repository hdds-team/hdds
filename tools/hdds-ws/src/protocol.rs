// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! WebSocket protocol messages for DDS bridge.
//!
//! JSON-based protocol for browser ↔ DDS communication.

use serde::{Deserialize, Serialize};

/// Client → Server messages
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientMessage {
    /// Subscribe to a topic
    Subscribe {
        topic: String,
        #[serde(default, rename = "qos")]
        _qos: Option<QosConfig>,
    },

    /// Unsubscribe from a topic
    Unsubscribe { topic: String },

    /// Publish data to a topic
    Publish {
        topic: String,
        data: serde_json::Value,
    },

    /// List available topics
    ListTopics,

    /// Ping (keepalive)
    Ping {
        #[serde(default)]
        id: Option<u64>,
    },
}

/// Server → Client messages
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMessage {
    /// Subscription confirmed
    Subscribed {
        topic: String,
        subscription_id: String,
    },

    /// Unsubscription confirmed
    Unsubscribed { topic: String },

    /// Data received from topic
    Data {
        topic: String,
        subscription_id: String,
        sample: serde_json::Value,
        #[serde(skip_serializing_if = "Option::is_none")]
        info: Option<SampleInfo>,
    },

    /// Publish confirmed
    Published { topic: String, sequence: u64 },

    /// Topic list
    Topics { topics: Vec<TopicInfo> },

    /// Pong response
    Pong {
        #[serde(skip_serializing_if = "Option::is_none")]
        id: Option<u64>,
    },

    /// Error occurred
    Error {
        code: ErrorCode,
        message: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        topic: Option<String>,
    },

    /// Welcome message on connection
    Welcome { version: String, domain: u32 },
}

/// Sample metadata
#[derive(Debug, Clone, Serialize)]
pub struct SampleInfo {
    /// Source timestamp (milliseconds since epoch)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_timestamp_ms: Option<u64>,

    /// Reception timestamp (milliseconds since epoch)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reception_timestamp_ms: Option<u64>,

    /// Sample sequence number
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sequence: Option<u64>,

    /// Writer GUID (hex string)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub writer_guid: Option<String>,
}

/// Topic information
#[derive(Debug, Clone, Serialize)]
pub struct TopicInfo {
    pub name: String,
    pub type_name: String,
    pub subscribers: u32,
    pub publishers: u32,
}

/// Simplified QoS configuration for web clients
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct QosConfig {
    /// Reliability: "reliable" or "best_effort"
    #[serde(default)]
    pub reliability: Option<String>,

    /// History depth (for reliable)
    #[serde(default)]
    pub history_depth: Option<u32>,
}

/// Error codes
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[allow(dead_code)] // Some variants reserved for future use
pub enum ErrorCode {
    /// Invalid message format
    InvalidMessage,
    /// Topic not found
    TopicNotFound,
    /// Already subscribed to topic
    AlreadySubscribed,
    /// Not subscribed to topic
    NotSubscribed,
    /// Publish failed
    PublishFailed,
    /// Internal error
    InternalError,
    /// Rate limit exceeded
    RateLimited,
}

impl ServerMessage {
    /// Create a welcome message
    pub fn welcome(domain: u32) -> Self {
        Self::Welcome {
            version: env!("CARGO_PKG_VERSION").to_string(),
            domain,
        }
    }

    /// Create an error message
    pub fn error(code: ErrorCode, message: impl Into<String>) -> Self {
        Self::Error {
            code,
            message: message.into(),
            topic: None,
        }
    }

    /// Create a topic-specific error message
    pub fn topic_error(
        code: ErrorCode,
        message: impl Into<String>,
        topic: impl Into<String>,
    ) -> Self {
        Self::Error {
            code,
            message: message.into(),
            topic: Some(topic.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_subscribe() {
        let json = r#"{"type": "subscribe", "topic": "temperature"}"#;
        let msg: ClientMessage = serde_json::from_str(json).unwrap();
        match msg {
            ClientMessage::Subscribe { topic, _qos } => {
                assert_eq!(topic, "temperature");
                assert!(_qos.is_none());
            }
            _ => panic!("Expected Subscribe"),
        }
    }

    #[test]
    fn parse_publish() {
        let json = r#"{"type": "publish", "topic": "commands", "data": {"action": "start"}}"#;
        let msg: ClientMessage = serde_json::from_str(json).unwrap();
        match msg {
            ClientMessage::Publish { topic, data } => {
                assert_eq!(topic, "commands");
                assert_eq!(data["action"], "start");
            }
            _ => panic!("Expected Publish"),
        }
    }

    #[test]
    fn serialize_data_message() {
        let msg = ServerMessage::Data {
            topic: "temperature".into(),
            subscription_id: "sub_123".into(),
            sample: serde_json::json!({"value": 23.5}),
            info: Some(SampleInfo {
                source_timestamp_ms: Some(1704567890123),
                reception_timestamp_ms: None,
                sequence: Some(42),
                writer_guid: None,
            }),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("temperature"));
        assert!(json.contains("23.5"));
    }
}
