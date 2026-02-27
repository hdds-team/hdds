// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Message routing and topic extraction

use std::collections::HashMap;

/// RTPS message header constants
const RTPS_MAGIC: [u8; 4] = [b'R', b'T', b'P', b'S'];

/// Submessage IDs
#[allow(dead_code)]
mod submsg {
    pub const DATA: u8 = 0x15;
    pub const DATA_FRAG: u8 = 0x16;
    pub const HEARTBEAT: u8 = 0x07;
    pub const ACKNACK: u8 = 0x06;
}

/// Routing table entry
#[derive(Debug, Clone)]
pub struct RouteEntry {
    /// Source node ID (LoRa) or IP hash (WiFi)
    pub source_id: u32,
    /// Topic name
    pub topic_name: String,
    /// Last seen timestamp (epoch seconds)
    pub last_seen: u64,
    /// Message count
    pub message_count: u64,
}

/// Message router
///
/// Maintains routing tables and makes forwarding decisions.
pub struct Router {
    /// LoRa node ID -> topics mapping
    lora_nodes: HashMap<u8, Vec<String>>,

    /// Topic -> LoRa node IDs (for reverse routing)
    topic_to_lora: HashMap<String, Vec<u8>>,

    /// Known topic names (extracted from RTPS DATA)
    known_topics: HashMap<String, RouteEntry>,

    /// Topics to bridge LoRa -> WiFi
    lora_to_wifi_filter: Option<Vec<String>>,

    /// Topics to bridge WiFi -> LoRa
    wifi_to_lora_filter: Option<Vec<String>>,
}

impl Router {
    /// Create a new router
    pub fn new() -> Self {
        Self {
            lora_nodes: HashMap::new(),
            topic_to_lora: HashMap::new(),
            known_topics: HashMap::new(),
            lora_to_wifi_filter: None,
            wifi_to_lora_filter: None,
        }
    }

    /// Set topic filter for LoRa -> WiFi
    pub fn set_lora_to_wifi_filter(&mut self, topics: Vec<String>) {
        self.lora_to_wifi_filter = Some(topics);
    }

    /// Set topic filter for WiFi -> LoRa
    pub fn set_wifi_to_lora_filter(&mut self, topics: Vec<String>) {
        self.wifi_to_lora_filter = Some(topics);
    }

    /// Clear all filters (bridge everything)
    pub fn clear_filters(&mut self) {
        self.lora_to_wifi_filter = None;
        self.wifi_to_lora_filter = None;
    }

    /// Check if message from LoRa should be forwarded to WiFi
    pub fn should_forward_to_wifi(&self, topic: Option<&str>) -> bool {
        match (&self.lora_to_wifi_filter, topic) {
            (None, _) => true,
            (Some(_), None) => true,
            (Some(filter), Some(t)) => filter.iter().any(|f| f == t),
        }
    }

    /// Check if message from WiFi should be forwarded to LoRa
    pub fn should_forward_to_lora(&self, topic: Option<&str>) -> bool {
        match (&self.wifi_to_lora_filter, topic) {
            (None, _) => true,
            (Some(_), None) => true,
            (Some(filter), Some(t)) => filter.iter().any(|f| f == t),
        }
    }

    /// Register a LoRa node with its topics
    pub fn register_lora_node(&mut self, node_id: u8, topic: &str) {
        self.lora_nodes
            .entry(node_id)
            .or_default()
            .push(topic.to_string());

        self.topic_to_lora
            .entry(topic.to_string())
            .or_default()
            .push(node_id);
    }

    /// Get LoRa nodes subscribed to a topic
    pub fn get_lora_nodes_for_topic(&self, topic: &str) -> Vec<u8> {
        self.topic_to_lora.get(topic).cloned().unwrap_or_default()
    }

    /// Update topic statistics
    pub fn update_topic_stats(&mut self, topic: &str, source_id: u32) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        self.known_topics
            .entry(topic.to_string())
            .and_modify(|e| {
                e.last_seen = now;
                e.message_count += 1;
            })
            .or_insert(RouteEntry {
                source_id,
                topic_name: topic.to_string(),
                last_seen: now,
                message_count: 1,
            });
    }

    /// Get all known topics
    pub fn known_topics(&self) -> Vec<&RouteEntry> {
        self.known_topics.values().collect()
    }

    /// Try to extract topic name from RTPS message
    pub fn extract_topic_from_rtps(&self, data: &[u8]) -> Option<String> {
        if data.len() < 20 || data[0..4] != RTPS_MAGIC {
            return None;
        }

        let mut pos = 20;

        while pos + 4 <= data.len() {
            let submsg_id = data[pos];
            let submsg_len = u16::from_le_bytes([data[pos + 2], data[pos + 3]]) as usize;

            if submsg_id == submsg::DATA && pos + 4 + submsg_len <= data.len() {
                let submsg_data = &data[pos + 4..pos + 4 + submsg_len];
                if let Some(topic) = self.find_topic_string(submsg_data) {
                    return Some(topic);
                }
            }

            pos += 4 + submsg_len;
            pos = (pos + 3) & !3;
        }

        None
    }

    /// Find a topic name string in data
    fn find_topic_string(&self, data: &[u8]) -> Option<String> {
        let known_prefixes = [
            "Temperature",
            "Humidity",
            "Pressure",
            "GPS",
            "Command",
            "Config",
            "Status",
            "Sensor",
            "Data",
        ];

        for prefix in known_prefixes {
            if let Some(pos) = data
                .windows(prefix.len())
                .position(|w| w == prefix.as_bytes())
            {
                let start = pos;
                let mut end = start;

                while end < data.len() && data[end] >= 0x20 && data[end] < 0x7F {
                    end += 1;
                }

                if end > start {
                    if let Ok(s) = std::str::from_utf8(&data[start..end]) {
                        return Some(s.to_string());
                    }
                }
            }
        }

        None
    }
}

impl Default for Router {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_router_creation() {
        let router = Router::new();
        assert!(router.known_topics().is_empty());
    }

    #[test]
    fn test_filter_lora_to_wifi() {
        let mut router = Router::new();

        assert!(router.should_forward_to_wifi(Some("Temperature")));

        router.set_lora_to_wifi_filter(vec!["Temperature".to_string()]);
        assert!(router.should_forward_to_wifi(Some("Temperature")));
        assert!(!router.should_forward_to_wifi(Some("Humidity")));
        assert!(router.should_forward_to_wifi(None));
    }

    #[test]
    fn test_lora_node_registration() {
        let mut router = Router::new();

        router.register_lora_node(1, "Temperature");
        router.register_lora_node(2, "Humidity");

        let nodes = router.get_lora_nodes_for_topic("Temperature");
        assert_eq!(nodes, vec![1]);
    }

    #[test]
    fn test_topic_stats() {
        let mut router = Router::new();

        router.update_topic_stats("Temperature", 1);
        router.update_topic_stats("Temperature", 1);

        let topics = router.known_topics();
        assert_eq!(topics.len(), 1);

        let temp = topics
            .iter()
            .find(|e| e.topic_name == "Temperature")
            .unwrap();
        assert_eq!(temp.message_count, 2);
    }
}
