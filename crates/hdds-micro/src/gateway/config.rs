// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Gateway configuration

use std::collections::HashSet;

/// Gateway configuration
#[derive(Debug, Clone)]
pub struct GatewayConfig {
    /// UDP port for HDDS
    pub udp_port: u16,

    /// HDDS domain ID
    pub domain_id: u32,

    /// Gateway node ID (used in LoRa addressing)
    pub node_id: u8,

    /// Topics to bridge from LoRa to WiFi
    pub lora_to_wifi_topics: HashSet<String>,

    /// Topics to bridge from WiFi to LoRa
    pub wifi_to_lora_topics: HashSet<String>,

    /// Bridge all topics (if true, ignores topic filters)
    pub bridge_all_topics: bool,

    /// Maximum messages per second to forward (rate limiting)
    pub max_messages_per_second: u32,

    /// Multicast address for HDDS discovery
    pub multicast_address: String,

    /// Enable statistics logging
    pub enable_stats: bool,

    /// Statistics logging interval in seconds
    pub stats_interval_secs: u64,
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            udp_port: 7400,
            domain_id: 0,
            node_id: 254,
            lora_to_wifi_topics: HashSet::new(),
            wifi_to_lora_topics: HashSet::new(),
            bridge_all_topics: true,
            max_messages_per_second: 100,
            multicast_address: "239.255.0.1".to_string(),
            enable_stats: true,
            stats_interval_secs: 60,
        }
    }
}

impl GatewayConfig {
    /// Create default configuration
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if a topic should be bridged from LoRa to WiFi
    pub fn should_bridge_lora_to_wifi(&self, topic: &str) -> bool {
        if self.bridge_all_topics {
            return true;
        }
        self.lora_to_wifi_topics.contains(topic)
    }

    /// Check if a topic should be bridged from WiFi to LoRa
    pub fn should_bridge_wifi_to_lora(&self, topic: &str) -> bool {
        if self.bridge_all_topics {
            return true;
        }
        self.wifi_to_lora_topics.contains(topic)
    }

    /// Add topic to LoRa->WiFi filter
    pub fn add_lora_to_wifi_topic(&mut self, topic: &str) {
        self.lora_to_wifi_topics.insert(topic.to_string());
    }

    /// Add topic to WiFi->LoRa filter
    pub fn add_wifi_to_lora_topic(&mut self, topic: &str) {
        self.wifi_to_lora_topics.insert(topic.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = GatewayConfig::default();
        assert_eq!(config.udp_port, 7400);
        assert!(config.bridge_all_topics);
    }

    #[test]
    fn test_topic_filtering_bridge_all() {
        let config = GatewayConfig {
            bridge_all_topics: true,
            ..Default::default()
        };

        assert!(config.should_bridge_lora_to_wifi("Temperature"));
        assert!(config.should_bridge_lora_to_wifi("AnyTopic"));
        assert!(config.should_bridge_wifi_to_lora("Command"));
    }

    #[test]
    fn test_topic_filtering_specific() {
        let mut config = GatewayConfig {
            bridge_all_topics: false,
            ..Default::default()
        };
        config.add_lora_to_wifi_topic("Temperature");
        config.add_wifi_to_lora_topic("Command");

        assert!(config.should_bridge_lora_to_wifi("Temperature"));
        assert!(!config.should_bridge_lora_to_wifi("Humidity"));
        assert!(config.should_bridge_wifi_to_lora("Command"));
        assert!(!config.should_bridge_wifi_to_lora("Data"));
    }
}
