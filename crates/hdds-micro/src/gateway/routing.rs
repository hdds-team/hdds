// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Message routing and topic extraction

use crate::rtps::submessages::SubmessageHeader;
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
    ///
    /// The framing of each submessage comes from [`SubmessageHeader::framing`],
    /// which is the crate's ONE reader of a submessage header, rather than
    /// from a private copy of the same arithmetic. A reader that took
    /// `octetsToNextHeader` little-endian unconditionally would read a
    /// conforming big-endian peer's 20-octet body as 5120 and step over the
    /// DATA: no topic would come out for ANY such peer. An unknown topic
    /// bypasses `should_forward_to_lora`, so that misread would not lose the
    /// traffic - it would put it on the radio, past the only filter that
    /// protects a LoRa link's duty cycle.
    pub fn extract_topic_from_rtps(&self, data: &[u8]) -> Option<String> {
        if data.len() < 20 || data[0..4] != RTPS_MAGIC {
            return None;
        }

        let mut pos = 20;

        while pos + 4 <= data.len() {
            let submsg_id = data[pos];
            let Ok((_, declared)) = SubmessageHeader::framing(&data[pos..]) else {
                break;
            };

            // RTPS v2.5 Sec.8.3.3.3: zero means this submessage runs to the
            // END of the message, which is how any body longer than a u16 is
            // framed - HDDS's own encoder emits it for a large TypeObject.
            // Taken literally as a four-octet body it would hide every such
            // sample and then walk the rest of the packet four bytes at a time.
            let body_len = if declared == 0 {
                data.len() - (pos + 4)
            } else {
                declared as usize
            };

            if submsg_id == submsg::DATA && pos + 4 + body_len <= data.len() {
                let submsg_data = &data[pos + 4..pos + 4 + body_len];
                if let Some(topic) = self.find_topic_string(submsg_data) {
                    return Some(topic);
                }
            }

            pos += 4 + body_len;
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

    /// An RTPS datagram carrying one INFO_TS and then one DATA whose body
    /// holds `topic`, framed in the endianness the E flag declares.
    ///
    /// The INFO_TS is not decoration: it is there so the walk really has to
    /// STEP OVER a submessage before reaching the DATA, and the stride it
    /// steps by is the field under test. With only a DATA in the packet, a
    /// reader that mis-frames every header would still land on the payload.
    ///
    /// `declared_len` lets a caller override what the DATA claims, to reach
    /// the `octetsToNextHeader == 0` form.
    fn datagram_with_topic(topic: &str, little_endian: bool, declared_len: Option<u16>) -> Vec<u8> {
        let e_flag = u8::from(little_endian);
        let framed = |n: u16| {
            if little_endian {
                n.to_le_bytes()
            } else {
                n.to_be_bytes()
            }
        };

        let mut p = Vec::new();
        p.extend_from_slice(&RTPS_MAGIC);
        p.extend_from_slice(&[0x02, 0x04, 0x01, 0x1A]);
        p.extend_from_slice(&[0x11; 12]);
        assert_eq!(p.len(), 20, "the RTPS header is 20 octets");

        p.push(0x09); // INFO_TS
        p.push(e_flag);
        p.extend_from_slice(&framed(8));
        p.extend_from_slice(&[0u8; 8]);

        // DATA: the 20 fixed octets of Sec.8.3.8.2, then the topic name.
        let mut body = vec![0u8; 20];
        body.extend_from_slice(topic.as_bytes());
        body.push(0x00); // ends the printable run find_topic_string walks
        let data_at = p.len();
        p.push(0x15); // DATA
        p.push(e_flag);
        p.extend_from_slice(&framed(declared_len.unwrap_or(body.len() as u16)));
        p.extend_from_slice(&body);

        assert_eq!(
            &p[data_at + 4 + 20..p.len() - 1],
            topic.as_bytes(),
            "the topic must really sit inside the DATA body"
        );
        p
    }

    /// A conforming big-endian peer is routed like any other.
    ///
    /// The two halves are one test on purpose: the little-endian datagram is
    /// the control that proves the fixture, the walk and the topic search all
    /// work, so that the big-endian failure can only be the endianness. A
    /// reader that read every length little-endian would see a conforming
    /// 20-octet body (`0x0014`) as 5120, step over the DATA, and never
    /// extract a topic from such a peer.
    ///
    /// What that costs is not a lost packet. `should_forward_to_lora` returns
    /// TRUE for an unknown topic, so every big-endian peer on the multicast
    /// group bypassed the topic filter and went out over the radio - the one
    /// link in this product where bandwidth is the scarce resource.
    #[test]
    fn a_conforming_big_endian_peer_is_routed_by_topic_like_any_other() {
        let router = Router::new();

        let little = datagram_with_topic("Temperature", true, None);
        assert_eq!(
            router.extract_topic_from_rtps(&little).as_deref(),
            Some("Temperature"),
            "the little-endian control must pass, or the big-endian half proves nothing"
        );

        let big = datagram_with_topic("Temperature", false, None);
        assert_eq!(
            router.extract_topic_from_rtps(&big).as_deref(),
            Some("Temperature"),
            "octetsToNextHeader is read in the endianness the E flag of that same \
             submessage declares (RTPS v2.5 Sec.8.3.3.3)"
        );
    }

    /// A body longer than a u16 is framed with the sentinel, and that is OUR
    /// own encoder's doing.
    ///
    /// RTPS v2.5 Sec.8.3.3.3: `octetsToNextHeader == 0` means the submessage
    /// runs to the end of the message. HDDS emits exactly that for a sample
    /// too large for the field - a TypeObject, say - so this is inside the
    /// HDDS-to-HDDS perimeter the gateway documents for itself, not an
    /// interop edge case. Read as a four-octet body it would hide the sample
    /// and then walk the rest of the packet four bytes at a time.
    #[test]
    fn a_last_submessage_framed_with_the_sentinel_is_read_to_the_end() {
        let router = Router::new();
        let packet = datagram_with_topic("Pressure", true, Some(0));
        assert_eq!(
            router.extract_topic_from_rtps(&packet).as_deref(),
            Some("Pressure"),
            "a zero octetsToNextHeader means 'to the end of the message', not 'empty'"
        );
    }

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
