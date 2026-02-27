// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Local Endpoint Registry for automatic endpoint matching.
//!
//! Tracks local DataReaders and DataWriters, enabling automatic
//! binding when compatible remote endpoints are discovered via SEDP.

/// Local Endpoint Registry
///
/// Tracks local DataReaders and DataWriters for automatic endpoint matching.
///
/// # Purpose
///
/// When a remote endpoint is discovered via SEDP, this registry enables:
/// 1. Finding compatible local endpoints (topic/type/QoS match)
/// 2. Auto-binding readers to writers without manual `bind_to_writer()` calls
/// 3. Symmetric discovery (both intra-process and inter-process)
///
/// # Design
///
/// - Keyed by topic name for O(1) lookup
/// - Stores both Readers and Writers
/// - Thread-safe via RwLock
///
/// # Example Flow
///
/// ```text
/// 1. User creates local Reader on "sensor/temp"
/// 2. Registry stores Reader metadata
/// 3. Remote participant announces Writer on "sensor/temp" (SEDP)
/// 4. DiscoveryFsm calls on_endpoint_discovered()
/// 5. Registry finds local Reader
/// 6. Matcher validates compatibility
/// 7. Auto-bind: reader.bind_to_writer(merger)
/// ```
use crate::core::discovery::GUID;
use crate::core::rt::{IndexRing, TopicMerger};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Kind of local endpoint
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalEndpointKind {
    Reader,
    Writer,
}

/// Local endpoint metadata
#[derive(Clone)]
pub struct LocalEndpointInfo {
    /// Endpoint GUID (generated locally)
    pub guid: GUID,
    /// Topic name
    pub topic: String,
    /// Type ID (FNV-1a hash of type name)
    pub type_id: u32,
    /// Type name
    pub type_name: String,
    /// Endpoint kind (Reader or Writer)
    pub kind: LocalEndpointKind,
    /// TopicMerger handle (for writers)
    ///
    /// - For Writers: merger to share with readers
    /// - For Readers: None
    pub merger: Option<Arc<TopicMerger>>,
    /// IndexRing handle (for readers)
    ///
    /// - For Readers: ring to receive data
    /// - For Writers: None
    pub ring: Option<Arc<IndexRing>>,
}

impl std::fmt::Debug for LocalEndpointInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalEndpointInfo")
            .field("guid", &self.guid)
            .field("topic", &self.topic)
            .field("type_id", &self.type_id)
            .field("type_name", &self.type_name)
            .field("kind", &self.kind)
            .field("merger", &self.merger.as_ref().map(|_| "Arc<TopicMerger>"))
            .field("ring", &self.ring.as_ref().map(|_| "Arc<IndexRing>"))
            .finish()
    }
}

/// Local endpoint registry
///
/// Thread-safe registry of local DataReaders and DataWriters.
pub struct LocalEndpointRegistry {
    /// Endpoints grouped by topic name
    ///
    /// HashMap<topic_name, Vec<LocalEndpointInfo>>
    endpoints: RwLock<HashMap<String, Vec<LocalEndpointInfo>>>,
}

impl LocalEndpointRegistry {
    /// Create new empty registry
    pub fn new() -> Self {
        Self {
            endpoints: RwLock::new(HashMap::new()),
        }
    }

    /// Register a local endpoint
    ///
    /// # Arguments
    /// - `info`: Local endpoint metadata
    ///
    /// # Thread Safety
    /// Uses write lock, safe for concurrent access.
    pub fn register(&self, info: LocalEndpointInfo) {
        let mut endpoints = self.endpoints.write().unwrap_or_else(|e| e.into_inner());
        endpoints.entry(info.topic.clone()).or_default().push(info);
    }

    /// Find local endpoints matching a topic
    ///
    /// # Arguments
    /// - `topic`: Topic name to search
    ///
    /// # Returns
    /// Vec of matching local endpoints (cloned)
    ///
    /// # Thread Safety
    /// Uses read lock, safe for concurrent access.
    pub fn find_by_topic(&self, topic: &str) -> Vec<LocalEndpointInfo> {
        let endpoints = self.endpoints.read().unwrap_or_else(|e| e.into_inner());
        endpoints.get(topic).cloned().unwrap_or_default()
    }

    /// Get all registered endpoints
    ///
    /// # Returns
    /// Vec of all local endpoints (cloned)
    pub fn get_all(&self) -> Vec<LocalEndpointInfo> {
        let endpoints = self.endpoints.read().unwrap_or_else(|e| e.into_inner());
        endpoints.values().flat_map(|v| v.clone()).collect()
    }
}

impl Default for LocalEndpointRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_local_registry_register() {
        let registry = LocalEndpointRegistry::new();

        let info = LocalEndpointInfo {
            guid: GUID::zero(),
            topic: "test/topic".to_string(),
            type_id: 12345,
            type_name: "TestType".to_string(),
            kind: LocalEndpointKind::Writer,
            merger: None,
            ring: None,
        };

        registry.register(info.clone());

        let found = registry.find_by_topic("test/topic");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].type_id, 12345);
    }

    #[test]
    fn test_local_registry_multiple_endpoints_same_topic() {
        let registry = LocalEndpointRegistry::new();

        let writer = LocalEndpointInfo {
            guid: GUID::zero(),
            topic: "sensor/temp".to_string(),
            type_id: 123,
            type_name: "Temperature".to_string(),
            kind: LocalEndpointKind::Writer,
            merger: None,
            ring: None,
        };

        let reader = LocalEndpointInfo {
            guid: GUID::zero(),
            topic: "sensor/temp".to_string(),
            type_id: 123,
            type_name: "Temperature".to_string(),
            kind: LocalEndpointKind::Reader,
            merger: None,
            ring: None,
        };

        registry.register(writer);
        registry.register(reader);

        let found = registry.find_by_topic("sensor/temp");
        assert_eq!(found.len(), 2);
    }

    #[test]
    fn test_local_registry_empty_topic() {
        let registry = LocalEndpointRegistry::new();
        let found = registry.find_by_topic("nonexistent");
        assert_eq!(found.len(), 0);
    }
}
