// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Participant and Endpoint registries for discovery server.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// GUID prefix (12 bytes) - unique participant identifier.
pub type GuidPrefix = [u8; 12];

/// Entity ID (4 bytes) - unique endpoint identifier within a participant.
pub type EntityId = [u8; 4];

/// Full GUID = GuidPrefix + EntityId.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Guid {
    pub prefix: GuidPrefix,
    pub entity_id: EntityId,
}

/// Information about a registered participant.
#[derive(Debug, Clone)]
pub struct ParticipantInfo {
    /// Unique GUID prefix
    pub guid_prefix: GuidPrefix,

    /// Domain ID
    pub domain_id: u32,

    /// Participant name (optional)
    pub name: Option<String>,

    /// Unicast locators (TCP addresses)
    pub unicast_locators: Vec<SocketAddr>,

    /// Default unicast locators for data
    pub default_unicast_locators: Vec<SocketAddr>,

    /// Vendor ID
    pub vendor_id: [u8; 2],

    /// Protocol version
    pub protocol_version: (u8, u8),

    /// Built-in endpoint set (bitmask)
    pub builtin_endpoints: u32,

    /// Last activity timestamp
    pub last_seen: Instant,

    /// Registration timestamp
    #[allow(dead_code)]
    pub registered_at: Instant,
}

impl ParticipantInfo {
    /// Create a new participant info.
    pub fn new(guid_prefix: GuidPrefix, domain_id: u32) -> Self {
        let now = Instant::now();
        Self {
            guid_prefix,
            domain_id,
            name: None,
            unicast_locators: Vec::new(),
            default_unicast_locators: Vec::new(),
            vendor_id: [0x01, 0x10],  // HDDS vendor ID
            protocol_version: (2, 4), // RTPS 2.4
            builtin_endpoints: 0,
            last_seen: now,
            registered_at: now,
        }
    }

    /// Check if lease has expired.
    pub fn is_expired(&self, lease_duration: Duration) -> bool {
        self.last_seen.elapsed() > lease_duration
    }

    /// Update last seen timestamp.
    pub fn touch(&mut self) {
        self.last_seen = Instant::now();
    }
}

/// Information about a registered endpoint (writer or reader).
#[derive(Debug, Clone)]
pub struct EndpointInfo {
    /// Full GUID (prefix + entity_id)
    pub guid: Guid,

    /// Topic name
    pub topic_name: String,

    /// Type name
    pub type_name: String,

    /// Is this a writer (true) or reader (false)?
    pub is_writer: bool,

    /// Reliability QoS (true = reliable, false = best-effort)
    pub reliable: bool,

    /// Durability kind (0 = volatile, 1 = transient_local, etc.)
    pub durability: u8,

    /// Unicast locators for this endpoint
    pub unicast_locators: Vec<SocketAddr>,
}

/// Registry of all participants and their endpoints.
#[derive(Debug)]
pub struct ParticipantRegistry {
    /// Participants indexed by GUID prefix
    participants: HashMap<GuidPrefix, ParticipantInfo>,

    /// Endpoints indexed by full GUID
    endpoints: HashMap<Guid, EndpointInfo>,

    /// Topic index: topic_name -> list of endpoint GUIDs
    topic_index: HashMap<String, Vec<Guid>>,

    /// Domain index: domain_id -> list of participant GUID prefixes
    domain_index: HashMap<u32, Vec<GuidPrefix>>,
}

impl ParticipantRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self {
            participants: HashMap::new(),
            endpoints: HashMap::new(),
            topic_index: HashMap::new(),
            domain_index: HashMap::new(),
        }
    }

    /// Add or update a participant.
    pub fn add_participant(&mut self, info: ParticipantInfo) {
        let guid_prefix = info.guid_prefix;
        let domain_id = info.domain_id;

        // Update domain index
        self.domain_index
            .entry(domain_id)
            .or_default()
            .retain(|gp| *gp != guid_prefix);
        self.domain_index
            .entry(domain_id)
            .or_default()
            .push(guid_prefix);

        self.participants.insert(guid_prefix, info);
    }

    /// Remove a participant and all its endpoints.
    pub fn remove_participant(&mut self, guid_prefix: &GuidPrefix) -> Option<ParticipantInfo> {
        if let Some(info) = self.participants.remove(guid_prefix) {
            // Remove from domain index
            if let Some(domain_list) = self.domain_index.get_mut(&info.domain_id) {
                domain_list.retain(|gp| gp != guid_prefix);
            }

            // Remove all endpoints belonging to this participant
            let endpoints_to_remove: Vec<Guid> = self
                .endpoints
                .keys()
                .filter(|g| g.prefix == *guid_prefix)
                .copied()
                .collect();

            for guid in endpoints_to_remove {
                self.remove_endpoint(&guid);
            }

            Some(info)
        } else {
            None
        }
    }

    /// Get a participant by GUID prefix.
    #[cfg(test)]
    fn get_participant(&self, guid_prefix: &GuidPrefix) -> Option<&ParticipantInfo> {
        self.participants.get(guid_prefix)
    }

    /// Update last_seen timestamp for a participant.
    pub fn touch_participant(&mut self, guid_prefix: &GuidPrefix) {
        if let Some(info) = self.participants.get_mut(guid_prefix) {
            info.touch();
        }
    }

    /// Get all participants.
    pub fn participants(&self) -> impl Iterator<Item = (&GuidPrefix, &ParticipantInfo)> {
        self.participants.iter()
    }

    /// Get participant count.
    pub fn participant_count(&self) -> usize {
        self.participants.len()
    }

    /// Get participants in a specific domain.
    #[cfg(test)]
    fn participants_in_domain(&self, domain_id: u32) -> Vec<&ParticipantInfo> {
        self.domain_index
            .get(&domain_id)
            .map(|prefixes| {
                prefixes
                    .iter()
                    .filter_map(|gp| self.participants.get(gp))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Remove expired participants and return their GUID prefixes.
    pub fn remove_expired(&mut self, lease_duration: Duration) -> Vec<GuidPrefix> {
        let expired: Vec<GuidPrefix> = self
            .participants
            .iter()
            .filter(|(_, info)| info.is_expired(lease_duration))
            .map(|(gp, _)| *gp)
            .collect();

        for gp in &expired {
            self.remove_participant(gp);
        }

        expired
    }

    /// Add an endpoint for a participant.
    pub fn add_endpoint(&mut self, participant_guid_prefix: GuidPrefix, info: EndpointInfo) {
        let guid = info.guid;
        let topic_name = info.topic_name.clone();

        // Verify participant exists
        if !self.participants.contains_key(&participant_guid_prefix) {
            return;
        }

        // Update topic index
        self.topic_index
            .entry(topic_name)
            .or_default()
            .retain(|g| *g != guid);
        self.topic_index
            .entry(info.topic_name.clone())
            .or_default()
            .push(guid);

        self.endpoints.insert(guid, info);
    }

    /// Remove an endpoint.
    pub fn remove_endpoint(&mut self, guid: &Guid) -> Option<EndpointInfo> {
        if let Some(info) = self.endpoints.remove(guid) {
            // Remove from topic index
            if let Some(topic_list) = self.topic_index.get_mut(&info.topic_name) {
                topic_list.retain(|g| g != guid);
            }
            Some(info)
        } else {
            None
        }
    }

    /// Get an endpoint by GUID.
    #[allow(dead_code)]
    pub fn get_endpoint(&self, guid: &Guid) -> Option<&EndpointInfo> {
        self.endpoints.get(guid)
    }

    /// Get all endpoints.
    #[allow(dead_code)]
    pub fn endpoints(&self) -> impl Iterator<Item = (&Guid, &EndpointInfo)> {
        self.endpoints.iter()
    }

    /// Get endpoint count.
    #[cfg(test)]
    fn endpoint_count(&self) -> usize {
        self.endpoints.len()
    }

    /// Get endpoints for a specific topic.
    #[cfg(test)]
    fn endpoints_for_topic(&self, topic_name: &str) -> Vec<&EndpointInfo> {
        self.topic_index
            .get(topic_name)
            .map(|guids| guids.iter().filter_map(|g| self.endpoints.get(g)).collect())
            .unwrap_or_default()
    }

    /// Get writers for a specific topic.
    #[cfg(test)]
    fn writers_for_topic(&self, topic_name: &str) -> Vec<&EndpointInfo> {
        self.endpoints_for_topic(topic_name)
            .into_iter()
            .filter(|e| e.is_writer)
            .collect()
    }

    /// Get readers for a specific topic.
    #[cfg(test)]
    fn readers_for_topic(&self, topic_name: &str) -> Vec<&EndpointInfo> {
        self.endpoints_for_topic(topic_name)
            .into_iter()
            .filter(|e| !e.is_writer)
            .collect()
    }

    /// Get all topic names.
    #[cfg(test)]
    fn topic_names(&self) -> impl Iterator<Item = &String> {
        self.topic_index.keys()
    }

    /// Clear all data.
    #[cfg(test)]
    fn clear(&mut self) {
        self.participants.clear();
        self.endpoints.clear();
        self.topic_index.clear();
        self.domain_index.clear();
    }
}

impl Default for ParticipantRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_guid_prefix(id: u8) -> GuidPrefix {
        let mut gp = [0u8; 12];
        gp[0] = id;
        gp
    }

    fn make_entity_id(id: u8) -> EntityId {
        [0, 0, id, 0]
    }

    #[test]
    fn test_registry_new() {
        let reg = ParticipantRegistry::new();
        assert_eq!(reg.participant_count(), 0);
        assert_eq!(reg.endpoint_count(), 0);
    }

    #[test]
    fn test_add_participant() {
        let mut reg = ParticipantRegistry::new();
        let info = ParticipantInfo::new(make_guid_prefix(1), 0);

        reg.add_participant(info);

        assert_eq!(reg.participant_count(), 1);
        assert!(reg.get_participant(&make_guid_prefix(1)).is_some());
    }

    #[test]
    fn test_remove_participant() {
        let mut reg = ParticipantRegistry::new();
        let info = ParticipantInfo::new(make_guid_prefix(1), 0);
        reg.add_participant(info);

        let removed = reg.remove_participant(&make_guid_prefix(1));

        assert!(removed.is_some());
        assert_eq!(reg.participant_count(), 0);
    }

    #[test]
    fn test_remove_participant_removes_endpoints() {
        let mut reg = ParticipantRegistry::new();
        let gp = make_guid_prefix(1);
        reg.add_participant(ParticipantInfo::new(gp, 0));

        let endpoint = EndpointInfo {
            guid: Guid {
                prefix: gp,
                entity_id: make_entity_id(1),
            },
            topic_name: "test".into(),
            type_name: "TestType".into(),
            is_writer: true,
            reliable: true,
            durability: 0,
            unicast_locators: vec![],
        };
        reg.add_endpoint(gp, endpoint);

        assert_eq!(reg.endpoint_count(), 1);

        reg.remove_participant(&gp);

        assert_eq!(reg.endpoint_count(), 0);
    }

    #[test]
    fn test_participants_in_domain() {
        let mut reg = ParticipantRegistry::new();

        let mut info1 = ParticipantInfo::new(make_guid_prefix(1), 0);
        info1.domain_id = 0;
        reg.add_participant(info1);

        let mut info2 = ParticipantInfo::new(make_guid_prefix(2), 1);
        info2.domain_id = 1;
        reg.add_participant(info2);

        let mut info3 = ParticipantInfo::new(make_guid_prefix(3), 0);
        info3.domain_id = 0;
        reg.add_participant(info3);

        let domain0 = reg.participants_in_domain(0);
        assert_eq!(domain0.len(), 2);

        let domain1 = reg.participants_in_domain(1);
        assert_eq!(domain1.len(), 1);
    }

    #[test]
    fn test_touch_participant() {
        let mut reg = ParticipantRegistry::new();
        let info = ParticipantInfo::new(make_guid_prefix(1), 0);
        let initial_time = info.last_seen;
        reg.add_participant(info);

        std::thread::sleep(Duration::from_millis(10));
        reg.touch_participant(&make_guid_prefix(1));

        let updated = reg.get_participant(&make_guid_prefix(1)).unwrap();
        assert!(updated.last_seen > initial_time);
    }

    #[test]
    fn test_remove_expired() {
        let mut reg = ParticipantRegistry::new();

        // Add participant with old timestamp
        let mut info = ParticipantInfo::new(make_guid_prefix(1), 0);
        info.last_seen = Instant::now() - Duration::from_secs(100);
        reg.add_participant(info);

        // Add fresh participant
        reg.add_participant(ParticipantInfo::new(make_guid_prefix(2), 0));

        let expired = reg.remove_expired(Duration::from_secs(30));

        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0], make_guid_prefix(1));
        assert_eq!(reg.participant_count(), 1);
    }

    #[test]
    fn test_add_endpoint() {
        let mut reg = ParticipantRegistry::new();
        let gp = make_guid_prefix(1);
        reg.add_participant(ParticipantInfo::new(gp, 0));

        let endpoint = EndpointInfo {
            guid: Guid {
                prefix: gp,
                entity_id: make_entity_id(1),
            },
            topic_name: "sensor/temperature".into(),
            type_name: "Temperature".into(),
            is_writer: true,
            reliable: true,
            durability: 0,
            unicast_locators: vec![],
        };
        reg.add_endpoint(gp, endpoint);

        assert_eq!(reg.endpoint_count(), 1);
    }

    #[test]
    fn test_endpoints_for_topic() {
        let mut reg = ParticipantRegistry::new();
        let gp = make_guid_prefix(1);
        reg.add_participant(ParticipantInfo::new(gp, 0));

        // Add writer
        reg.add_endpoint(
            gp,
            EndpointInfo {
                guid: Guid {
                    prefix: gp,
                    entity_id: make_entity_id(1),
                },
                topic_name: "test".into(),
                type_name: "T".into(),
                is_writer: true,
                reliable: true,
                durability: 0,
                unicast_locators: vec![],
            },
        );

        // Add reader
        reg.add_endpoint(
            gp,
            EndpointInfo {
                guid: Guid {
                    prefix: gp,
                    entity_id: make_entity_id(2),
                },
                topic_name: "test".into(),
                type_name: "T".into(),
                is_writer: false,
                reliable: true,
                durability: 0,
                unicast_locators: vec![],
            },
        );

        let endpoints = reg.endpoints_for_topic("test");
        assert_eq!(endpoints.len(), 2);

        let writers = reg.writers_for_topic("test");
        assert_eq!(writers.len(), 1);

        let readers = reg.readers_for_topic("test");
        assert_eq!(readers.len(), 1);
    }

    #[test]
    fn test_topic_names() {
        let mut reg = ParticipantRegistry::new();
        let gp = make_guid_prefix(1);
        reg.add_participant(ParticipantInfo::new(gp, 0));

        reg.add_endpoint(
            gp,
            EndpointInfo {
                guid: Guid {
                    prefix: gp,
                    entity_id: make_entity_id(1),
                },
                topic_name: "topic_a".into(),
                type_name: "T".into(),
                is_writer: true,
                reliable: true,
                durability: 0,
                unicast_locators: vec![],
            },
        );

        reg.add_endpoint(
            gp,
            EndpointInfo {
                guid: Guid {
                    prefix: gp,
                    entity_id: make_entity_id(2),
                },
                topic_name: "topic_b".into(),
                type_name: "T".into(),
                is_writer: true,
                reliable: true,
                durability: 0,
                unicast_locators: vec![],
            },
        );

        let topics: Vec<_> = reg.topic_names().collect();
        assert_eq!(topics.len(), 2);
    }

    #[test]
    fn test_clear() {
        let mut reg = ParticipantRegistry::new();
        let gp = make_guid_prefix(1);
        reg.add_participant(ParticipantInfo::new(gp, 0));
        reg.add_endpoint(
            gp,
            EndpointInfo {
                guid: Guid {
                    prefix: gp,
                    entity_id: make_entity_id(1),
                },
                topic_name: "test".into(),
                type_name: "T".into(),
                is_writer: true,
                reliable: true,
                durability: 0,
                unicast_locators: vec![],
            },
        );

        reg.clear();

        assert_eq!(reg.participant_count(), 0);
        assert_eq!(reg.endpoint_count(), 0);
    }

    #[test]
    fn test_participant_info_expired() {
        let mut info = ParticipantInfo::new(make_guid_prefix(1), 0);
        info.last_seen = Instant::now() - Duration::from_secs(100);

        assert!(info.is_expired(Duration::from_secs(30)));
        assert!(!info.is_expired(Duration::from_secs(200)));
    }
}
