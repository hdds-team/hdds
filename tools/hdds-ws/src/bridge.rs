// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! DDS Bridge - Connects WebSocket clients to DDS topics.
//!
//! Manages a DomainParticipant and creates dynamic readers/writers
//! for topics requested by WebSocket clients.

use crate::protocol::{SampleInfo, TopicInfo};
use dashmap::DashMap;
use hdds::dds::{Participant, RawDataReader, RawDataWriter, TransportMode};
use hdds::dynamic::{decode_dynamic, type_descriptor_from_xtypes, DynamicValue, TypeDescriptor};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::SystemTime;
use tokio::sync::{broadcast, Mutex};
use tracing::{debug, info, warn};

/// A sample received from DDS
#[derive(Debug, Clone)]
pub struct BridgeSample {
    pub topic: String,
    pub data: serde_json::Value,
    pub info: Option<SampleInfo>,
}

/// Active subscription state
struct Subscription {
    /// Kept alive for proper shutdown (reader dropped = DDS reader unregistered).
    _reader: Arc<RawDataReader>,
    sender: broadcast::Sender<BridgeSample>,
    /// TypeDescriptor for dynamic CDR decoding (discovered via XTypes)
    /// Stored here to keep the Arc alive for the subscription's lifetime.
    _type_descriptor: Option<Arc<TypeDescriptor>>,
}

/// DDS Bridge - manages participant and topic subscriptions
pub struct DdsBridge {
    domain_id: u32,
    participant: Arc<Participant>,
    /// Active subscriptions: topic_name -> Subscription
    subscriptions: DashMap<String, Subscription>,
    /// Writers for publishing: topic_name -> RawDataWriter (wrapped in Mutex for thread safety)
    writers: DashMap<String, Arc<Mutex<RawDataWriter>>>,
    /// Sequence counter for published messages
    publish_seq: AtomicU64,
}

impl DdsBridge {
    /// Create a new DDS bridge
    pub async fn new(
        domain_id: u32,
        name: &str,
        transport: &str,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let transport_mode = match transport {
            "udp" | "multicast" => TransportMode::UdpMulticast,
            "intra" | "intraprocess" => TransportMode::IntraProcess,
            other => {
                warn!("Unknown transport '{}', defaulting to UDP multicast", other);
                TransportMode::UdpMulticast
            }
        };

        info!(
            "Creating DDS participant '{}' on domain {} with {:?} transport",
            name, domain_id, transport_mode
        );

        let participant = Participant::builder(name)
            .domain_id(domain_id)
            .with_transport(transport_mode)
            .build()?;

        Ok(Self {
            domain_id,
            participant,
            subscriptions: DashMap::new(),
            writers: DashMap::new(),
            publish_seq: AtomicU64::new(0),
        })
    }

    /// Get domain ID
    pub fn domain_id(&self) -> u32 {
        self.domain_id
    }

    /// Subscribe to a topic, returns a receiver for samples
    pub async fn subscribe(
        &self,
        topic_name: &str,
    ) -> Result<broadcast::Receiver<BridgeSample>, Box<dyn std::error::Error + Send + Sync>> {
        // Check if already subscribed
        if let Some(sub) = self.subscriptions.get(topic_name) {
            debug!("Reusing existing subscription for topic '{}'", topic_name);
            return Ok(sub.sender.subscribe());
        }

        info!("Creating subscription for topic '{}'", topic_name);

        // Try to discover TypeObject for this topic (XTypes dynamic decoding)
        let type_descriptor = self.discover_type_descriptor(topic_name);
        if type_descriptor.is_some() {
            info!(
                "Discovered TypeObject for '{}' - enabling dynamic CDR decoding",
                topic_name
            );
        } else {
            debug!(
                "No TypeObject found for '{}' - using fallback decoding",
                topic_name
            );
        }

        // Create DDS raw reader
        let reader = self.participant.create_raw_reader(topic_name, None)?;
        let reader = Arc::new(reader);

        // Create broadcast channel for this topic
        let (tx, rx) = broadcast::channel(256);

        // Store subscription
        self.subscriptions.insert(
            topic_name.to_string(),
            Subscription {
                _reader: reader.clone(),
                sender: tx.clone(),
                _type_descriptor: type_descriptor.clone(),
            },
        );

        // Spawn task to read from DDS and forward to broadcast
        let topic = topic_name.to_string();
        let tx_clone = tx;
        let reader_clone = reader;
        let desc_clone = type_descriptor;
        let participant_clone = self.participant.clone();

        tokio::spawn(async move {
            Self::reader_task(topic, reader_clone, tx_clone, desc_clone, participant_clone).await;
        });

        Ok(rx)
    }

    /// Try to discover TypeObject for a topic and convert to TypeDescriptor
    fn discover_type_descriptor(&self, topic_name: &str) -> Option<Arc<TypeDescriptor>> {
        match self.participant.discover_topics() {
            Ok(topics) => {
                for topic in topics {
                    if topic.name == topic_name {
                        if let Some(ref type_obj) = topic.type_object {
                            return Some(type_descriptor_from_xtypes(type_obj));
                        }
                    }
                }
                None
            }
            Err(e) => {
                warn!("Failed to discover topics: {}", e);
                None
            }
        }
    }

    /// Reader task - reads from DDS and forwards to broadcast channel.
    ///
    /// If `type_descriptor` is `None` on startup (TypeObject not yet discovered),
    /// the task retries discovery on each poll until successful.
    async fn reader_task(
        topic_name: String,
        reader: Arc<RawDataReader>,
        tx: broadcast::Sender<BridgeSample>,
        initial_descriptor: Option<Arc<TypeDescriptor>>,
        participant: Arc<Participant>,
    ) {
        info!(
            "Reader for '{}' started (dynamic decoding: {})",
            topic_name,
            initial_descriptor.is_some()
        );

        let mut type_descriptor = initial_descriptor;

        loop {
            // Lazy TypeObject discovery: retry until we find it
            if type_descriptor.is_none() {
                if let Ok(topics) = participant.discover_topics() {
                    for topic in &topics {
                        if topic.name == topic_name {
                            if let Some(ref type_obj) = topic.type_object {
                                info!(
                                    "Late-discovered TypeObject for '{}' - enabling dynamic CDR decoding",
                                    topic_name
                                );
                                type_descriptor = Some(type_descriptor_from_xtypes(type_obj));
                            }
                        }
                    }
                }
            }

            // Poll for data
            match reader.try_take_raw() {
                Ok(samples) => {
                    for raw_sample in samples {
                        // Convert raw CDR to JSON
                        let json_value = if let Some(ref desc) = type_descriptor {
                            // Use XTypes dynamic decoding
                            cdr_to_json_dynamic(&raw_sample.payload, desc)
                        } else {
                            // Fallback to basic decoding
                            raw_cdr_to_json(&raw_sample.payload)
                        };

                        let sample = BridgeSample {
                            topic: topic_name.clone(),
                            data: json_value,
                            info: Some(SampleInfo {
                                source_timestamp_ms: system_time_to_ms(raw_sample.source_timestamp),
                                reception_timestamp_ms: system_time_to_ms(
                                    raw_sample.reception_timestamp,
                                ),
                                sequence: raw_sample.sequence_number,
                                writer_guid: Some(format!("{:?}", raw_sample.writer_guid)),
                            }),
                        };

                        // Send to all WebSocket clients (ignore if no receivers)
                        let _ = tx.send(sample);
                    }
                }
                Err(e) => {
                    warn!("Read error on '{}': {}", topic_name, e);
                }
            }

            // Small delay to avoid busy-wait
            tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        }
    }

    /// Publish data to a topic
    pub async fn publish(
        &self,
        topic_name: &str,
        data: serde_json::Value,
    ) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
        // Get or create writer
        let writer = if let Some(w) = self.writers.get(topic_name) {
            w.clone()
        } else {
            info!("Creating writer for topic '{}'", topic_name);
            let writer = self.participant.create_raw_writer(topic_name, None)?;
            let writer = Arc::new(Mutex::new(writer));
            self.writers.insert(topic_name.to_string(), writer.clone());
            writer
        };

        // Convert JSON to CDR bytes
        let cdr_bytes = json_to_raw_cdr(&data)?;

        // Publish (lock the writer)
        {
            let writer_guard = writer.lock().await;
            writer_guard.write_raw(&cdr_bytes)?;
        }

        let seq = self.publish_seq.fetch_add(1, Ordering::Relaxed);
        debug!("Published to '{}' (seq={})", topic_name, seq);

        Ok(seq)
    }

    /// Unsubscribe from a topic
    #[allow(dead_code)] // Used by session when client unsubscribes
    pub fn unsubscribe(&self, topic_name: &str) {
        if self.subscriptions.remove(topic_name).is_some() {
            info!("Unsubscribed from topic '{}'", topic_name);
        }
    }

    /// List discovered topics
    pub fn list_topics(&self) -> Vec<TopicInfo> {
        match self.participant.discover_topics() {
            Ok(topics) => topics
                .into_iter()
                .map(|t| TopicInfo {
                    name: t.name,
                    type_name: t.type_name,
                    subscribers: t.subscriber_count as u32,
                    publishers: t.publisher_count as u32,
                })
                .collect(),
            Err(e) => {
                warn!("Failed to discover topics: {}", e);
                Vec::new()
            }
        }
    }
}

/// Convert CDR bytes to JSON using XTypes TypeDescriptor
///
/// Uses dynamic decoding based on discovered TypeObject metadata.
fn cdr_to_json_dynamic(cdr_bytes: &[u8], descriptor: &Arc<TypeDescriptor>) -> serde_json::Value {
    match decode_dynamic(cdr_bytes, descriptor) {
        Ok(dynamic_data) => dynamic_value_to_json(dynamic_data.value()),
        Err(e) => {
            warn!("Dynamic CDR decode failed: {}, falling back to raw", e);
            raw_cdr_to_json(cdr_bytes)
        }
    }
}

/// Convert DynamicValue to JSON
fn dynamic_value_to_json(value: &DynamicValue) -> serde_json::Value {
    match value {
        DynamicValue::Bool(b) => serde_json::Value::Bool(*b),
        DynamicValue::U8(n) => serde_json::json!(*n),
        DynamicValue::U16(n) => serde_json::json!(*n),
        DynamicValue::U32(n) => serde_json::json!(*n),
        DynamicValue::U64(n) => serde_json::json!(*n),
        DynamicValue::I8(n) => serde_json::json!(*n),
        DynamicValue::I16(n) => serde_json::json!(*n),
        DynamicValue::I32(n) => serde_json::json!(*n),
        DynamicValue::I64(n) => serde_json::json!(*n),
        DynamicValue::F32(n) => serde_json::json!(*n),
        DynamicValue::F64(n) => serde_json::json!(*n),
        DynamicValue::LongDouble(_) => serde_json::json!(0.0), // Simplified
        DynamicValue::Char(c) => serde_json::json!(c.to_string()),
        DynamicValue::String(s) => serde_json::Value::String(s.clone()),
        DynamicValue::WString(s) => serde_json::Value::String(s.clone()),
        DynamicValue::Struct(fields) => {
            let mut obj = serde_json::Map::new();
            for (name, val) in fields {
                obj.insert(name.clone(), dynamic_value_to_json(val));
            }
            serde_json::Value::Object(obj)
        }
        DynamicValue::Sequence(items) => {
            let arr: Vec<serde_json::Value> = items.iter().map(dynamic_value_to_json).collect();
            serde_json::Value::Array(arr)
        }
        DynamicValue::Array(items) => {
            let arr: Vec<serde_json::Value> = items.iter().map(dynamic_value_to_json).collect();
            serde_json::Value::Array(arr)
        }
        DynamicValue::Enum(_, name) => serde_json::Value::String(name.clone()),
        DynamicValue::Union(_, _, value) => dynamic_value_to_json(value),
        DynamicValue::Null => serde_json::Value::Null,
    }
}

/// Convert raw CDR bytes to JSON (fallback)
///
/// Basic best-effort conversion for when TypeObject is not available.
fn raw_cdr_to_json(cdr_bytes: &[u8]) -> serde_json::Value {
    if cdr_bytes.is_empty() {
        return serde_json::Value::Null;
    }

    // For now, return the raw bytes as base64 + attempt to decode as string
    // This is a pragmatic approach for the demo
    let base64_payload = base64_encode(cdr_bytes);

    // Try to extract a string if payload looks like one (ROS2 std_msgs/String)
    // Format: 4-byte length (LE) + string bytes + null terminator
    if cdr_bytes.len() >= 4 {
        let str_len =
            u32::from_le_bytes([cdr_bytes[0], cdr_bytes[1], cdr_bytes[2], cdr_bytes[3]]) as usize;
        if str_len > 0 && str_len + 4 <= cdr_bytes.len() {
            if let Ok(s) = std::str::from_utf8(&cdr_bytes[4..4 + str_len.saturating_sub(1)]) {
                return serde_json::json!({
                    "data": s,
                    "_raw": base64_payload
                });
            }
        }
    }

    // Fallback: return raw bytes
    serde_json::json!({
        "_raw": base64_payload,
        "_bytes": cdr_bytes.len()
    })
}

/// Convert JSON to raw CDR bytes
///
/// Simple conversion for demo purposes.
fn json_to_raw_cdr(
    value: &serde_json::Value,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    // If the value has a "data" field (ROS2 std_msgs/String style)
    if let Some(data) = value.get("data") {
        if let Some(s) = data.as_str() {
            // Encode as ROS2 string: 4-byte length + string + null terminator
            let bytes = s.as_bytes();
            let len = (bytes.len() + 1) as u32; // +1 for null terminator
            let mut cdr = Vec::with_capacity(4 + bytes.len() + 1);
            cdr.extend_from_slice(&len.to_le_bytes());
            cdr.extend_from_slice(bytes);
            cdr.push(0); // null terminator
            return Ok(cdr);
        }
    }

    // If there's a _raw field with base64, decode it
    if let Some(raw) = value.get("_raw") {
        if let Some(b64) = raw.as_str() {
            return base64_decode(b64);
        }
    }

    // Fallback: serialize JSON as string
    let json_str = serde_json::to_string(value)?;
    let bytes = json_str.as_bytes();
    let len = (bytes.len() + 1) as u32;
    let mut cdr = Vec::with_capacity(4 + bytes.len() + 1);
    cdr.extend_from_slice(&len.to_le_bytes());
    cdr.extend_from_slice(bytes);
    cdr.push(0);
    Ok(cdr)
}

/// Convert SystemTime to milliseconds since epoch
fn system_time_to_ms(time: SystemTime) -> Option<u64> {
    time.duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|d| d.as_millis() as u64)
}

/// Simple base64 encoding
fn base64_encode(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();

    for chunk in data.chunks(3) {
        let b0 = chunk[0] as usize;
        let b1 = chunk.get(1).copied().unwrap_or(0) as usize;
        let b2 = chunk.get(2).copied().unwrap_or(0) as usize;

        result.push(CHARS[b0 >> 2] as char);
        result.push(CHARS[((b0 & 0x03) << 4) | (b1 >> 4)] as char);

        if chunk.len() > 1 {
            result.push(CHARS[((b1 & 0x0F) << 2) | (b2 >> 6)] as char);
        } else {
            result.push('=');
        }

        if chunk.len() > 2 {
            result.push(CHARS[b2 & 0x3F] as char);
        } else {
            result.push('=');
        }
    }

    result
}

/// Simple base64 decoding
fn base64_decode(input: &str) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    const DECODE: [i8; 128] = [
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1,
        -1, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1, -1, 0, 1, 2, 3, 4,
        5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1,
        -1, -1, -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45,
        46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1,
    ];

    let input = input.trim_end_matches('=');
    let mut result = Vec::new();

    let chars: Vec<u8> = input.bytes().collect();
    for chunk in chars.chunks(4) {
        if chunk.len() < 2 {
            break;
        }

        let b0 = DECODE[chunk[0] as usize] as u8;
        let b1 = DECODE[chunk[1] as usize] as u8;
        result.push((b0 << 2) | (b1 >> 4));

        if chunk.len() > 2 && chunk[2] != b'=' {
            let b2 = DECODE[chunk[2] as usize] as u8;
            result.push((b1 << 4) | (b2 >> 2));

            if chunk.len() > 3 && chunk[3] != b'=' {
                let b3 = DECODE[chunk[3] as usize] as u8;
                result.push((b2 << 6) | b3);
            }
        }
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64_roundtrip() {
        let data = b"Hello, DDS!";
        let encoded = base64_encode(data);
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(data.as_slice(), decoded.as_slice());
    }

    #[test]
    fn test_ros2_string_encoding() {
        let json = serde_json::json!({"data": "Hello"});
        let cdr = json_to_raw_cdr(&json).unwrap();

        // Should be: 6 (length with null) + "Hello" + null
        assert_eq!(cdr.len(), 4 + 5 + 1);
        assert_eq!(&cdr[0..4], &6u32.to_le_bytes());
        assert_eq!(&cdr[4..9], b"Hello");
        assert_eq!(cdr[9], 0);
    }

    #[test]
    fn test_ros2_string_decoding() {
        // ROS2 std_msgs/String: length + "test" + null
        let cdr = [5, 0, 0, 0, b't', b'e', b's', b't', 0];
        let json = raw_cdr_to_json(&cdr);

        assert_eq!(json["data"], "test");
    }
}
