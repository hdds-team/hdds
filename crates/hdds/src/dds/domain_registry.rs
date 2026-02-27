// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Domain Registry for Intra-Process Auto-Binding
//!
//!
//! This module provides automatic endpoint matching within the same process.
//! When a Reader and Writer share the same (topic, type_id), they are
//! automatically bound for zero-copy intra-process communication.
//!
//! # Architecture
//!
//! ```text
//! DomainRegistry (static global)
//! +-- domains: Mutex<HashMap<DomainId, Weak<DomainState>>>
//!
//! DomainState (one per domain, per process)
//! +-- domain_id: u32
//! +-- endpoints: RwLock<HashMap<MatchKey, Vec<LocalEndpointEntry>>>
//! +-- [strong ref held by Participant]
//!
//! MatchKey
//! +-- topic_name: Arc<str>
//! +-- type_id: TypeId  (MD5-14 or simple hash)
//! ```
//!
//! # Auto-Binding Flow
//!
//! 1. Writer created -> registers in DomainState
//! 2. Reader created -> registers, finds matching Writers, auto-binds
//! 3. Reader destroyed -> unbinds, unregisters
//! 4. Writer destroyed -> unbinds all readers, unregisters
//!
//! # Thread Safety
//!
//! - DomainRegistry: Mutex for domain map access
//! - DomainState.endpoints: RwLock (many readers, few writers)
//! - All operations are lock-free for the data path (only registration/lookup locks)

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock, Weak};

use crate::core::discovery::GUID;
use crate::core::rt::{IndexRing, TopicMerger};
use crate::dds::qos::Reliability;

/// Domain ID type (0-232 per DDS spec)
pub type DomainId = u32;

/// Type identifier for matching endpoints
///
/// For intra-process, we use a simple approach:
/// - MD5 hash of type_name (14 bytes, truncated for EquivalenceHash compat)
/// - Stored as [u8; 14] for HashMap key efficiency
///
/// This is simpler than full XTypes TypeIdentifier for intra-process use.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct TypeId([u8; 14]);

impl TypeId {
    /// Create TypeId from type name using MD5
    pub fn from_type_name(type_name: &str) -> Self {
        use md5::{Digest, Md5};
        let mut hasher = Md5::new();
        hasher.update(type_name.as_bytes());
        let result = hasher.finalize();
        let mut bytes = [0u8; 14];
        bytes.copy_from_slice(&result[..14]);
        Self(bytes)
    }

    /// Create from raw bytes
    pub const fn from_bytes(bytes: [u8; 14]) -> Self {
        Self(bytes)
    }

    /// Get raw bytes
    pub const fn as_bytes(&self) -> &[u8; 14] {
        &self.0
    }

    /// Zero TypeId (for testing)
    pub const fn zero() -> Self {
        Self([0u8; 14])
    }
}

impl std::fmt::Debug for TypeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TypeId(")?;
        for byte in &self.0[..4] {
            write!(f, "{:02x}", byte)?;
        }
        write!(f, "...)")
    }
}

impl std::fmt::Display for TypeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in &self.0 {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

/// Match key for endpoint lookup
///
/// Two endpoints match if they have the same (topic_name, type_id).
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct MatchKey {
    /// Topic name
    pub topic_name: Arc<str>,
    /// Type identifier (MD5 of type name)
    pub type_id: TypeId,
}

impl MatchKey {
    /// Create new match key
    pub fn new(topic_name: impl Into<Arc<str>>, type_id: TypeId) -> Self {
        Self {
            topic_name: topic_name.into(),
            type_id,
        }
    }

    /// Create match key from topic and type names
    pub fn from_names(topic_name: &str, type_name: &str) -> Self {
        Self {
            topic_name: Arc::from(topic_name),
            type_id: TypeId::from_type_name(type_name),
        }
    }
}

impl std::fmt::Debug for MatchKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MatchKey")
            .field("topic", &self.topic_name)
            .field("type_id", &self.type_id)
            .finish()
    }
}

/// Kind of local endpoint
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointKind {
    Reader,
    Writer,
}

/// Local endpoint entry in the registry
pub struct LocalEndpointEntry {
    /// Endpoint GUID
    pub guid: GUID,
    /// Endpoint kind
    pub kind: EndpointKind,
    /// QoS Reliability policy
    pub reliability: Reliability,
    /// TopicMerger (writers only) - used by readers to bind
    pub merger: Option<Arc<TopicMerger>>,
    /// IndexRing (readers only) - receives data from merger
    pub ring: Option<Arc<IndexRing>>,
    /// Callback to bind reader to writer's merger
    ///
    /// For readers: called when a matching writer is found
    /// For writers: None
    pub bind_callback: Option<Box<dyn Fn(Arc<TopicMerger>) + Send + Sync>>,
}

/// Check QoS compatibility between writer and reader
///
/// Per DDS spec:
/// - Reliable writer -> any reader: compatible
/// - BestEffort writer + BestEffort reader: compatible
/// - BestEffort writer + Reliable reader: INCOMPATIBLE
fn qos_compatible(writer_reliability: Reliability, reader_reliability: Reliability) -> bool {
    match (writer_reliability, reader_reliability) {
        (Reliability::Reliable, _) => true,
        (Reliability::BestEffort, Reliability::BestEffort) => true,
        (Reliability::BestEffort, Reliability::Reliable) => false,
    }
}

impl std::fmt::Debug for LocalEndpointEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalEndpointEntry")
            .field("guid", &self.guid)
            .field("kind", &self.kind)
            .field("reliability", &self.reliability)
            .field("has_merger", &self.merger.is_some())
            .field("has_ring", &self.ring.is_some())
            .field("has_bind_callback", &self.bind_callback.is_some())
            .finish()
    }
}

/// Token returned when registering an endpoint
///
/// When dropped, automatically unregisters the endpoint from the domain.
/// This ensures cleanup even on panic/early return.
pub struct BindToken {
    domain: Weak<DomainState>,
    key: MatchKey,
    guid: GUID,
}

impl BindToken {
    /// Create new bind token (internal)
    fn new(domain: &Arc<DomainState>, key: MatchKey, guid: GUID) -> Self {
        Self {
            domain: Arc::downgrade(domain),
            key,
            guid,
        }
    }
}

impl Drop for BindToken {
    fn drop(&mut self) {
        if let Some(domain) = self.domain.upgrade() {
            domain.unregister(&self.key, self.guid);
        }
    }
}

impl std::fmt::Debug for BindToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BindToken")
            .field("key", &self.key)
            .field("guid", &self.guid)
            .finish()
    }
}

/// Domain state - holds all endpoints for a single domain
pub struct DomainState {
    /// Domain ID
    pub domain_id: DomainId,
    /// Endpoints grouped by (topic, type_id)
    endpoints: RwLock<HashMap<MatchKey, Vec<LocalEndpointEntry>>>,
}

impl DomainState {
    /// Create new domain state
    pub fn new(domain_id: DomainId) -> Self {
        Self {
            domain_id,
            endpoints: RwLock::new(HashMap::new()),
        }
    }

    /// Register a writer endpoint
    ///
    /// Returns a BindToken that unregisters on drop.
    /// Also triggers auto-binding with any existing matching readers (QoS compatible only).
    pub fn register_writer(
        self: &Arc<Self>,
        key: MatchKey,
        guid: GUID,
        merger: Arc<TopicMerger>,
        reliability: Reliability,
    ) -> BindToken {
        let mut endpoints = self.endpoints.write().unwrap_or_else(|e| e.into_inner());

        let entry = LocalEndpointEntry {
            guid,
            kind: EndpointKind::Writer,
            reliability,
            merger: Some(merger.clone()),
            ring: None,
            bind_callback: None,
        };

        // Get or create endpoint list for this key
        let entries = endpoints.entry(key.clone()).or_default();

        // Auto-bind: notify all existing QoS-compatible readers about this new writer
        for existing in entries.iter() {
            if existing.kind == EndpointKind::Reader {
                // QoS check: writer reliability must be compatible with reader
                if !qos_compatible(reliability, existing.reliability) {
                    log::debug!(
                        "[DomainRegistry] Skipping bind: writer {:?} incompatible with reader {:?}",
                        reliability,
                        existing.reliability
                    );
                    continue;
                }

                if let Some(ref callback) = existing.bind_callback {
                    log::debug!(
                        "[DomainRegistry] Auto-binding reader {} to new writer {}",
                        existing.guid,
                        guid
                    );
                    callback(merger.clone());
                }
            }
        }

        entries.push(entry);

        BindToken::new(self, key, guid)
    }

    /// Register a reader endpoint
    ///
    /// Returns a BindToken that unregisters on drop.
    /// Also triggers auto-binding with any existing matching writers (QoS compatible only).
    pub fn register_reader<F>(
        self: &Arc<Self>,
        key: MatchKey,
        guid: GUID,
        ring: Arc<IndexRing>,
        reliability: Reliability,
        bind_callback: F,
    ) -> BindToken
    where
        F: Fn(Arc<TopicMerger>) + Send + Sync + 'static,
    {
        let mut endpoints = self.endpoints.write().unwrap_or_else(|e| e.into_inner());

        // Get or create endpoint list for this key
        let entries = endpoints.entry(key.clone()).or_default();

        // Auto-bind: find all existing QoS-compatible writers and bind to them
        for existing in entries.iter() {
            if existing.kind == EndpointKind::Writer {
                // QoS check: writer reliability must be compatible with reader
                if !qos_compatible(existing.reliability, reliability) {
                    log::debug!(
                        "[DomainRegistry] Skipping bind: writer {:?} incompatible with reader {:?}",
                        existing.reliability,
                        reliability
                    );
                    continue;
                }

                if let Some(ref merger) = existing.merger {
                    log::debug!(
                        "[DomainRegistry] Auto-binding new reader {} to writer {}",
                        guid,
                        existing.guid
                    );
                    bind_callback(merger.clone());
                }
            }
        }

        let entry = LocalEndpointEntry {
            guid,
            kind: EndpointKind::Reader,
            reliability,
            merger: None,
            ring: Some(ring),
            bind_callback: Some(Box::new(bind_callback)),
        };

        entries.push(entry);

        BindToken::new(self, key, guid)
    }

    /// Unregister an endpoint (called by BindToken::drop)
    fn unregister(&self, key: &MatchKey, guid: GUID) {
        let mut endpoints = self.endpoints.write().unwrap_or_else(|e| e.into_inner());

        if let Some(entries) = endpoints.get_mut(key) {
            entries.retain(|e| e.guid != guid);

            // Clean up empty entry lists
            if entries.is_empty() {
                endpoints.remove(key);
            }
        }

        log::debug!(
            "[DomainRegistry] Unregistered endpoint {} from topic '{}'",
            guid,
            key.topic_name
        );
    }

    /// Find all writers matching a key
    pub fn find_writers(&self, key: &MatchKey) -> Vec<Arc<TopicMerger>> {
        let endpoints = self.endpoints.read().unwrap_or_else(|e| e.into_inner());

        endpoints
            .get(key)
            .map(|entries| {
                entries
                    .iter()
                    .filter(|e| e.kind == EndpointKind::Writer)
                    .filter_map(|e| e.merger.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Find all readers matching a key
    pub fn find_readers(&self, key: &MatchKey) -> Vec<Arc<IndexRing>> {
        let endpoints = self.endpoints.read().unwrap_or_else(|e| e.into_inner());

        endpoints
            .get(key)
            .map(|entries| {
                entries
                    .iter()
                    .filter(|e| e.kind == EndpointKind::Reader)
                    .filter_map(|e| e.ring.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get count of endpoints
    pub fn endpoint_count(&self) -> usize {
        let endpoints = self.endpoints.read().unwrap_or_else(|e| e.into_inner());
        endpoints.values().map(|v| v.len()).sum()
    }

    /// Get count of endpoints for a specific key
    pub fn endpoint_count_for_key(&self, key: &MatchKey) -> usize {
        let endpoints = self.endpoints.read().unwrap_or_else(|e| e.into_inner());
        endpoints.get(key).map(|v| v.len()).unwrap_or(0)
    }
}

impl std::fmt::Debug for DomainState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DomainState")
            .field("domain_id", &self.domain_id)
            .field("endpoint_count", &self.endpoint_count())
            .finish()
    }
}

/// Global domain registry (singleton)
///
/// Thread-safe access to domain states across the process.
pub struct DomainRegistry {
    domains: Mutex<HashMap<DomainId, Weak<DomainState>>>,
}

impl DomainRegistry {
    /// Create new registry
    fn new() -> Self {
        Self {
            domains: Mutex::new(HashMap::new()),
        }
    }

    /// Get the global registry instance
    pub fn global() -> &'static DomainRegistry {
        use std::sync::OnceLock;
        static REGISTRY: OnceLock<DomainRegistry> = OnceLock::new();
        REGISTRY.get_or_init(DomainRegistry::new)
    }

    /// Get or create domain state for a domain ID
    ///
    /// Returns an Arc to the DomainState. The caller (Participant) should
    /// hold this Arc to keep the domain alive.
    pub fn get_or_create(&self, domain_id: DomainId) -> Arc<DomainState> {
        let mut domains = self.domains.lock().unwrap_or_else(|e| e.into_inner());

        // Check if domain exists and is still alive
        if let Some(weak) = domains.get(&domain_id) {
            if let Some(strong) = weak.upgrade() {
                return strong;
            }
        }

        // Create new domain state
        let state = Arc::new(DomainState::new(domain_id));
        domains.insert(domain_id, Arc::downgrade(&state));

        log::info!(
            "[DomainRegistry] Created domain state for domain_id={}",
            domain_id
        );

        state
    }

    /// Try to get existing domain state (for testing/debugging)
    pub fn get(&self, domain_id: DomainId) -> Option<Arc<DomainState>> {
        let domains = self.domains.lock().unwrap_or_else(|e| e.into_inner());
        domains.get(&domain_id).and_then(|w| w.upgrade())
    }

    /// Clean up expired domain references (for testing)
    pub fn cleanup_expired(&self) {
        let mut domains = self.domains.lock().unwrap_or_else(|e| e.into_inner());
        domains.retain(|_, weak| weak.strong_count() > 0);
    }

    /// Get count of active domains (for testing)
    pub fn active_domain_count(&self) -> usize {
        let domains = self.domains.lock().unwrap_or_else(|e| e.into_inner());
        domains.values().filter(|w| w.strong_count() > 0).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_type_id_from_name() {
        let id1 = TypeId::from_type_name("Temperature");
        let id2 = TypeId::from_type_name("Temperature");
        let id3 = TypeId::from_type_name("Humidity");

        assert_eq!(id1, id2);
        assert_ne!(id1, id3);
    }

    #[test]
    fn test_match_key() {
        let key1 = MatchKey::from_names("sensor/temp", "Temperature");
        let key2 = MatchKey::from_names("sensor/temp", "Temperature");
        let key3 = MatchKey::from_names("sensor/temp", "Humidity");
        let key4 = MatchKey::from_names("sensor/humidity", "Temperature");

        assert_eq!(key1, key2);
        assert_ne!(key1, key3); // different type
        assert_ne!(key1, key4); // different topic
    }

    #[test]
    fn test_domain_state_register_writer() {
        let domain = Arc::new(DomainState::new(0));
        let key = MatchKey::from_names("test/topic", "TestType");
        let guid = GUID::zero();
        let merger = Arc::new(TopicMerger::new());

        let token = domain.register_writer(key.clone(), guid, merger, Reliability::BestEffort);

        assert_eq!(domain.endpoint_count(), 1);
        assert_eq!(domain.endpoint_count_for_key(&key), 1);
        assert_eq!(domain.find_writers(&key).len(), 1);
        assert_eq!(domain.find_readers(&key).len(), 0);

        drop(token);

        assert_eq!(domain.endpoint_count(), 0);
    }

    #[test]
    fn test_domain_state_register_reader() {
        let domain = Arc::new(DomainState::new(0));
        let key = MatchKey::from_names("test/topic", "TestType");
        let guid = GUID::zero();
        let ring = Arc::new(IndexRing::with_capacity(1024));

        let token = domain.register_reader(
            key.clone(),
            guid,
            ring,
            Reliability::BestEffort,
            |_merger| {
                // Bind callback (not called since no writers)
            },
        );

        assert_eq!(domain.endpoint_count(), 1);
        assert_eq!(domain.endpoint_count_for_key(&key), 1);
        assert_eq!(domain.find_writers(&key).len(), 0);
        assert_eq!(domain.find_readers(&key).len(), 1);

        drop(token);

        assert_eq!(domain.endpoint_count(), 0);
    }

    #[test]
    fn test_auto_bind_writer_first() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let domain = Arc::new(DomainState::new(0));
        let key = MatchKey::from_names("test/topic", "TestType");

        // Register writer first (Reliable)
        let writer_guid = GUID::zero();
        let merger = Arc::new(TopicMerger::new());
        let _writer_token =
            domain.register_writer(key.clone(), writer_guid, merger, Reliability::Reliable);

        // Register reader (BestEffort) - should auto-bind (Reliable writer -> any reader OK)
        let bound = Arc::new(AtomicBool::new(false));
        let bound_clone = bound.clone();
        let reader_guid = GUID::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], [0, 0, 0, 1]);
        let ring = Arc::new(IndexRing::with_capacity(1024));

        let _reader_token = domain.register_reader(
            key.clone(),
            reader_guid,
            ring,
            Reliability::BestEffort,
            move |_| {
                bound_clone.store(true, Ordering::SeqCst);
            },
        );

        assert!(
            bound.load(Ordering::SeqCst),
            "Reader should auto-bind to existing writer"
        );
    }

    #[test]
    fn test_auto_bind_reader_first() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let domain = Arc::new(DomainState::new(0));
        let key = MatchKey::from_names("test/topic", "TestType");

        // Register reader first (BestEffort)
        let bound = Arc::new(AtomicBool::new(false));
        let bound_clone = bound.clone();
        let reader_guid = GUID::zero();
        let ring = Arc::new(IndexRing::with_capacity(1024));

        let _reader_token = domain.register_reader(
            key.clone(),
            reader_guid,
            ring,
            Reliability::BestEffort,
            move |_| {
                bound_clone.store(true, Ordering::SeqCst);
            },
        );

        assert!(
            !bound.load(Ordering::SeqCst),
            "Reader should not bind yet (no writer)"
        );

        // Register writer (BestEffort) - should trigger auto-bind callback
        let writer_guid = GUID::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], [0, 0, 0, 1]);
        let merger = Arc::new(TopicMerger::new());
        let _writer_token =
            domain.register_writer(key.clone(), writer_guid, merger, Reliability::BestEffort);

        assert!(
            bound.load(Ordering::SeqCst),
            "Reader should auto-bind when writer appears"
        );
    }

    /// Test: BestEffort writer + Reliable reader = NO BIND (QoS incompatible)
    #[test]
    fn test_qos_besteffort_writer_reliable_reader_no_bind() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let domain = Arc::new(DomainState::new(0));
        let key = MatchKey::from_names("test/topic", "TestType");

        // Register BestEffort writer first
        let writer_guid = GUID::zero();
        let merger = Arc::new(TopicMerger::new());
        let _writer_token =
            domain.register_writer(key.clone(), writer_guid, merger, Reliability::BestEffort);

        // Register Reliable reader - should NOT auto-bind (incompatible QoS)
        let bound = Arc::new(AtomicBool::new(false));
        let bound_clone = bound.clone();
        let reader_guid = GUID::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], [0, 0, 0, 1]);
        let ring = Arc::new(IndexRing::with_capacity(1024));

        let _reader_token = domain.register_reader(
            key.clone(),
            reader_guid,
            ring,
            Reliability::Reliable,
            move |_| {
                bound_clone.store(true, Ordering::SeqCst);
            },
        );

        assert!(
            !bound.load(Ordering::SeqCst),
            "Reliable reader should NOT bind to BestEffort writer"
        );
    }

    /// Test: Reliable writer + BestEffort reader = BIND (QoS compatible)
    #[test]
    fn test_qos_reliable_writer_besteffort_reader_binds() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let domain = Arc::new(DomainState::new(0));
        let key = MatchKey::from_names("test/topic", "TestType");

        // Register Reliable writer first
        let writer_guid = GUID::zero();
        let merger = Arc::new(TopicMerger::new());
        let _writer_token =
            domain.register_writer(key.clone(), writer_guid, merger, Reliability::Reliable);

        // Register BestEffort reader - should auto-bind (Reliable writer compatible with any reader)
        let bound = Arc::new(AtomicBool::new(false));
        let bound_clone = bound.clone();
        let reader_guid = GUID::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], [0, 0, 0, 1]);
        let ring = Arc::new(IndexRing::with_capacity(1024));

        let _reader_token = domain.register_reader(
            key.clone(),
            reader_guid,
            ring,
            Reliability::BestEffort,
            move |_| {
                bound_clone.store(true, Ordering::SeqCst);
            },
        );

        assert!(
            bound.load(Ordering::SeqCst),
            "BestEffort reader should bind to Reliable writer"
        );
    }

    /// Test: Reader first, then BestEffort writer - Reliable reader should NOT bind
    #[test]
    fn test_qos_reader_first_besteffort_writer_no_bind() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let domain = Arc::new(DomainState::new(0));
        let key = MatchKey::from_names("test/topic", "TestType");

        // Register Reliable reader first
        let bound = Arc::new(AtomicBool::new(false));
        let bound_clone = bound.clone();
        let reader_guid = GUID::zero();
        let ring = Arc::new(IndexRing::with_capacity(1024));

        let _reader_token = domain.register_reader(
            key.clone(),
            reader_guid,
            ring,
            Reliability::Reliable,
            move |_| {
                bound_clone.store(true, Ordering::SeqCst);
            },
        );

        // Register BestEffort writer - should NOT trigger auto-bind (incompatible QoS)
        let writer_guid = GUID::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], [0, 0, 0, 1]);
        let merger = Arc::new(TopicMerger::new());
        let _writer_token =
            domain.register_writer(key.clone(), writer_guid, merger, Reliability::BestEffort);

        assert!(
            !bound.load(Ordering::SeqCst),
            "Reliable reader should NOT bind when BestEffort writer appears"
        );
    }

    #[test]
    fn test_domain_registry_get_or_create() {
        let registry = DomainRegistry::global();

        let domain1 = registry.get_or_create(42);
        let domain2 = registry.get_or_create(42);

        assert!(Arc::ptr_eq(&domain1, &domain2));
        assert_eq!(domain1.domain_id, 42);
    }

    #[test]
    fn test_domain_registry_cleanup() {
        // Use a local registry for isolated test
        let registry = DomainRegistry::new();

        {
            let _domain = registry.get_or_create(99);
            assert_eq!(registry.active_domain_count(), 1);
        }

        // Domain dropped, weak ref should be dead
        registry.cleanup_expired();
        assert_eq!(registry.active_domain_count(), 0);
    }

    #[test]
    fn test_bind_token_unregisters_on_drop() {
        let domain = Arc::new(DomainState::new(0));
        let key = MatchKey::from_names("test/topic", "TestType");
        let guid = GUID::zero();
        let merger = Arc::new(TopicMerger::new());

        {
            let _token = domain.register_writer(key.clone(), guid, merger, Reliability::BestEffort);
            assert_eq!(domain.endpoint_count(), 1);
        }

        // Token dropped - endpoint should be unregistered
        assert_eq!(domain.endpoint_count(), 0);
    }

    #[test]
    fn test_multiple_writers_same_topic() {
        let domain = Arc::new(DomainState::new(0));
        let key = MatchKey::from_names("test/topic", "TestType");

        let guid1 = GUID::zero();
        let guid2 = GUID::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], [0, 0, 0, 1]);
        let merger1 = Arc::new(TopicMerger::new());
        let merger2 = Arc::new(TopicMerger::new());

        let _token1 = domain.register_writer(key.clone(), guid1, merger1, Reliability::BestEffort);
        let _token2 = domain.register_writer(key.clone(), guid2, merger2, Reliability::Reliable);

        assert_eq!(domain.endpoint_count_for_key(&key), 2);
        assert_eq!(domain.find_writers(&key).len(), 2);
    }

    /// Integration test: verify end-to-end intra-process data flow
    ///
    /// This test verifies that:
    /// 1. Writer registration populates the merger
    /// 2. Reader auto-binds to writer via callback
    /// 3. Data written to merger reaches the reader's ring
    #[test]
    fn test_intra_process_data_flow() {
        use crate::core::rt::{get_slab_pool, IndexEntry};

        // Initialize slab pool for data allocation
        let _ = crate::core::rt::init_slab_pool();

        let domain = Arc::new(DomainState::new(42));
        let key = MatchKey::from_names("sensor/temp", "Temperature");

        // Create writer's merger
        let writer_merger = Arc::new(TopicMerger::new());
        let writer_guid = GUID::zero();

        // Register writer (Reliable for this test)
        let _writer_token = domain.register_writer(
            key.clone(),
            writer_guid,
            writer_merger.clone(),
            Reliability::Reliable,
        );

        // Create reader's ring
        let reader_ring = Arc::new(IndexRing::with_capacity(16));
        let reader_guid = GUID::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], [0, 0, 0, 1]);

        // Track binding
        use std::sync::atomic::{AtomicUsize, Ordering};
        let bind_count = Arc::new(AtomicUsize::new(0));
        let bind_count_clone = bind_count.clone();

        // Clone ring for callback
        let ring_for_callback = reader_ring.clone();

        // Register reader (BestEffort) - should auto-bind to existing Reliable writer
        let _reader_token = domain.register_reader(
            key.clone(),
            reader_guid,
            reader_ring.clone(),
            Reliability::BestEffort,
            move |merger| {
                bind_count_clone.fetch_add(1, Ordering::SeqCst);

                // Create notification (no-op for test)
                let notify: Arc<dyn Fn() + Send + Sync> = Arc::new(|| {});

                // Register with merger
                let registration =
                    crate::core::rt::MergerReader::new(ring_for_callback.clone(), notify);
                merger.add_reader(registration);
            },
        );

        assert_eq!(
            bind_count.load(Ordering::SeqCst),
            1,
            "Reader should bind once to writer"
        );
        assert_eq!(
            writer_merger.reader_count(),
            1,
            "Writer merger should have 1 reader"
        );

        // Write data through merger
        let slab_pool = get_slab_pool();
        let data = b"Hello intra-process!";
        let (handle, buf) = slab_pool.reserve(data.len()).expect("slab reserve");
        buf[..data.len()].copy_from_slice(data);
        slab_pool.commit(handle, data.len());

        let entry = IndexEntry {
            seq: 1,
            handle,
            len: data.len() as u32,
            flags: 0x01,
            timestamp_ns: 0,
        };

        let push_ok = writer_merger.push(entry);
        assert!(push_ok, "Merger push should succeed");

        // Read data from reader's ring
        let received = reader_ring.pop();
        assert!(received.is_some(), "Reader should receive data");

        let received_entry = received.unwrap();
        assert_eq!(received_entry.seq, 1);
        assert_eq!(received_entry.len, data.len() as u32);

        // Verify data content
        let received_buf = slab_pool.get_buffer(received_entry.handle);
        assert_eq!(&received_buf[..data.len()], data);

        // Cleanup
        slab_pool.release(received_entry.handle);
    }
}
