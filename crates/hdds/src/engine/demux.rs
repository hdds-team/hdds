// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Topic-based demultiplexing and fanout
//!
//! Manages topic registration, subscriber lists, and data delivery.
//! Provides GUID->topic mapping for RTI/Cyclone/FastDDS interoperability.

use crate::engine::subscriber::Subscriber;
use std::collections::HashMap;
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};

// ============================================================================
// Handler Traits
// ============================================================================

/// Handler trait for Heartbeat messages (Reliable QoS control)
///
/// Implemented by DataReader to receive periodic liveness messages from writers.
pub trait HeartbeatHandler: Send + Sync {
    /// Called when a Heartbeat message is received.
    ///
    /// # Arguments
    /// - `heartbeat_bytes`: Raw Heartbeat message payload (CDR2 encoded)
    fn on_heartbeat(&self, heartbeat_bytes: &[u8]);
}

/// Handler trait for NACK messages (Reliable QoS control)
///
/// Implemented by DataWriter to receive retransmission requests from readers.
pub trait NackHandler: Send + Sync {
    /// Called when a NACK message is received.
    ///
    /// # Arguments
    /// - `nack_bytes`: Raw NACK message payload (CDR2 encoded)
    fn on_nack(&self, nack_bytes: &[u8]);
}

/// Handler trait for NACK_FRAG messages (Fragment retransmission)
///
/// Implemented by DataWriter to receive fragment retransmission requests from readers.
pub trait NackFragHandler: Send + Sync {
    /// Called when a NACK_FRAG message is received.
    ///
    /// # Arguments
    /// - `writer_entity_id`: Entity ID of the target writer
    /// - `writer_sn`: Sequence number of the fragmented message
    /// - `missing_fragments`: List of missing fragment numbers (1-based)
    fn on_nack_frag(&self, writer_entity_id: &[u8; 4], writer_sn: u64, missing_fragments: &[u32]);
}

// ============================================================================
// Topic
// ============================================================================

/// Topic metadata and subscriber list.
///
/// Represents a single topic with its registered subscribers and ensures panic
/// isolation when delivering data.
#[derive(Clone)]
pub struct Topic {
    name: String,
    pub(crate) type_name: Option<String>,
    subscribers: Vec<Arc<dyn Subscriber>>,
}

impl Topic {
    #[must_use]
    pub fn new(name: String, type_name: Option<String>) -> Self {
        Self {
            name,
            type_name,
            subscribers: Vec::new(),
        }
    }

    #[must_use]
    #[inline]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub fn type_name(&self) -> Option<&str> {
        self.type_name.as_deref()
    }

    pub fn add_subscriber(&mut self, sub: Arc<dyn Subscriber>) -> bool {
        let sub_ptr = Arc::as_ptr(&sub) as *const () as usize;
        if self
            .subscribers
            .iter()
            .any(|existing| Arc::as_ptr(existing) as *const () as usize == sub_ptr)
        {
            return false;
        }

        self.subscribers.push(sub);
        true
    }

    pub fn remove_subscriber(&mut self, topic_name: &str) -> bool {
        if let Some(index) = self
            .subscribers
            .iter()
            .position(|s| s.topic_name() == topic_name)
        {
            self.subscribers.remove(index);
            true
        } else {
            false
        }
    }

    #[must_use]
    #[inline]
    pub fn subscriber_count(&self) -> usize {
        self.subscribers.len()
    }

    /// Deliver payload to all subscribers with panic isolation.
    ///
    /// Returns number of delivery errors (panic count).
    ///
    /// # Performance
    /// HOT PATH: Called for every DATA packet delivery.
    #[inline]
    pub fn deliver(&self, seq: u64, data: &[u8]) -> usize {
        let mut errors = 0;

        for sub in &self.subscribers {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                sub.on_data(&self.name, seq, data);
            }));

            if result.is_err() {
                errors += 1;
                log::debug!(
                    "[demux] Subscriber '{}' panicked during delivery",
                    sub.topic_name()
                );
            }
        }

        errors
    }
}

// ============================================================================
// Topic Registry
// ============================================================================

/// Thread-safe registry for demultiplexed topics and auxiliary reliability handlers.
///
/// The registry guards access to topic definitions and multicast heartbeat/NACK callbacks
/// with `RwLock`s so readers never block each other while still allowing synchronous
/// updates during discovery.
///
/// # GUID-based Routing (RTI Interop Fix)
///
/// RTI/Cyclone/FastDDS often send DATA packets WITHOUT inline QoS (flag=0) to save bandwidth.
/// Instead, they rely on the writer GUID (guidPrefix + writerEntityId) announced via SEDP.
/// We maintain a GUID->topic mapping populated during SEDP discovery to route these packets.
pub struct TopicRegistry {
    pub(crate) topics: RwLock<HashMap<String, Topic>>,
    pub(crate) heartbeat_handlers: RwLock<Vec<Arc<dyn HeartbeatHandler>>>,
    pub(crate) nack_handlers: RwLock<Vec<Arc<dyn NackHandler>>>,
    pub(crate) nack_frag_handlers: RwLock<Vec<Arc<dyn NackFragHandler>>>,
    /// Writer GUID -> topic name mapping for DATA routing (RTI interop)
    writer_guid_to_topic: RwLock<HashMap<[u8; 16], String>>,
}

#[inline]
fn recover_write<'a, T>(lock: &'a RwLock<T>, context: &str) -> RwLockWriteGuard<'a, T> {
    match lock.write() {
        Ok(guard) => guard,
        Err(poisoned) => {
            log::debug!("[demux] WARNING: {} poisoned, recovering", context);
            poisoned.into_inner()
        }
    }
}

#[inline]
fn recover_read<'a, T>(lock: &'a RwLock<T>, context: &str) -> RwLockReadGuard<'a, T> {
    match lock.read() {
        Ok(guard) => guard,
        Err(poisoned) => {
            log::debug!("[demux] WARNING: {} poisoned, recovering", context);
            poisoned.into_inner()
        }
    }
}

impl TopicRegistry {
    pub fn new() -> Self {
        Self {
            topics: RwLock::new(HashMap::new()),
            heartbeat_handlers: RwLock::new(Vec::new()),
            nack_handlers: RwLock::new(Vec::new()),
            nack_frag_handlers: RwLock::new(Vec::new()),
            writer_guid_to_topic: RwLock::new(HashMap::new()),
        }
    }

    pub fn register_topic(
        &self,
        name: String,
        type_name: Option<String>,
    ) -> Result<(), RegistryError> {
        let mut topics = recover_write(&self.topics, "TopicRegistry::topics.write()");

        if topics.contains_key(&name) {
            log::debug!("[REGISTRY] register_topic skip (exists) topic='{}'", name);
            return Ok(());
        }

        let type_display = type_name
            .as_deref()
            .map(|s| s.to_string())
            .unwrap_or_else(|| "<none>".to_string());

        topics.insert(name.clone(), Topic::new(name.clone(), type_name));
        log::debug!(
            "[REGISTRY] register_topic inserted topic='{}' type={}",
            name,
            type_display
        );
        Ok(())
    }

    pub fn register_subscriber(&self, sub: Arc<dyn Subscriber>) -> Result<(), RegistryError> {
        let topic_name = sub.topic_name().to_string();

        let mut topics = recover_write(&self.topics, "TopicRegistry::topics.write()");

        let topic = topics
            .entry(topic_name.clone())
            .or_insert_with(|| Topic::new(topic_name, None));

        if !topic.add_subscriber(sub) {
            log::debug!(
                "[REGISTRY] register_subscriber skip (duplicate handle) topic='{}'",
                topic.name()
            );
            return Ok(());
        }
        log::debug!(
            "[REGISTRY] register_subscriber topic='{}' subscriber_count={}",
            topic.name(),
            topic.subscriber_count()
        );
        Ok(())
    }

    pub fn unregister_subscriber(&self, topic_name: &str) -> Result<bool, RegistryError> {
        let mut topics = recover_write(&self.topics, "TopicRegistry::topics.write()");

        if let Some(topic) = topics.get_mut(topic_name) {
            Ok(topic.remove_subscriber(topic_name))
        } else {
            Ok(false)
        }
    }

    #[must_use]
    #[inline]
    pub fn get_topic(&self, name: &str) -> Option<Topic> {
        let topics = recover_read(&self.topics, "TopicRegistry::topics.read()");
        topics.get(name).cloned()
    }

    #[must_use]
    pub fn topic_count(&self) -> usize {
        let topics = recover_read(&self.topics, "TopicRegistry::topics.read()");
        topics.len()
    }

    pub fn register_heartbeat_handler(&self, handler: Arc<dyn HeartbeatHandler>) {
        let mut handlers = recover_write(
            &self.heartbeat_handlers,
            "TopicRegistry::heartbeat_handlers.write()",
        );
        handlers.push(handler);
    }

    pub fn register_nack_handler(&self, handler: Arc<dyn NackHandler>) {
        let mut handlers =
            recover_write(&self.nack_handlers, "TopicRegistry::nack_handlers.write()");
        handlers.push(handler);
    }

    pub fn register_nack_frag_handler(&self, handler: Arc<dyn NackFragHandler>) {
        let mut handlers = recover_write(
            &self.nack_frag_handlers,
            "TopicRegistry::nack_frag_handlers.write()",
        );
        handlers.push(handler);
    }

    /// Register a writer GUID -> topic name mapping for DATA packet routing.
    ///
    /// Called during SEDP discovery when a remote writer is announced.
    /// Enables routing of DATA packets without inline QoS (RTI/Cyclone/FastDDS).
    pub fn register_writer_guid(&self, guid: [u8; 16], topic_name: String) {
        let mut mapping = recover_write(
            &self.writer_guid_to_topic,
            "TopicRegistry::writer_guid_to_topic.write()",
        );
        mapping.insert(guid, topic_name.clone());
        log::debug!(
            "[REGISTRY] register_writer_guid guid={:02x?} topic='{}'",
            &guid[..],
            topic_name
        );
    }

    /// Lookup topic name by writer GUID for DATA packet routing.
    ///
    /// Returns `None` if the GUID is unknown (writer not announced via SEDP yet).
    ///
    /// # Performance
    /// HOT PATH: Called for every DATA packet without inline QoS.
    #[must_use]
    #[inline]
    pub fn get_topic_by_guid(&self, guid: &[u8; 16]) -> Option<String> {
        let mapping = recover_read(
            &self.writer_guid_to_topic,
            "TopicRegistry::writer_guid_to_topic.read()",
        );
        mapping.get(guid).cloned()
    }

    /// Fallback GUID->topic mapping for interop scenarios where remote writers
    /// do not announce SEDP Publications, but there is a single local topic
    /// with active subscribers.
    ///
    /// Enabled via `HDDS_ROUTE_UNKNOWN_WRITER_TO_SINGLE_TOPIC=1` environment variable.
    /// When enabled, if there is exactly one topic with subscribers, unknown writer
    /// GUIDs will be automatically bound to that topic and future DATA packets will
    /// be routed correctly.
    ///
    /// This is useful for:
    /// - Multi-machine setups where SEDP may not be delivered reliably
    /// - Testing scenarios with minimal discovery
    /// - Interop with stacks that don't send SEDP Publications
    pub fn fallback_map_unknown_writer_to_single_topic(&self, guid: [u8; 16]) -> Option<String> {
        // Check if fallback is enabled via environment variable
        if std::env::var("HDDS_ROUTE_UNKNOWN_WRITER_TO_SINGLE_TOPIC").is_err() {
            return None;
        }

        let topics = recover_read(&self.topics, "TopicRegistry::topics.read()");

        // Find topics with at least one subscriber
        let topics_with_subs: Vec<_> = topics
            .values()
            .filter(|t| t.subscriber_count() > 0)
            .collect();

        if topics_with_subs.len() == 1 {
            let topic_name = topics_with_subs[0].name().to_string();
            drop(topics); // Release read lock before acquiring write lock

            // Register this GUID -> topic mapping for future packets
            self.register_writer_guid(guid, topic_name.clone());

            log::debug!(
                "[REGISTRY] fallback_route: bound unknown writer GUID {:02x?} -> topic '{}'",
                &guid[..],
                topic_name
            );
            Some(topic_name)
        } else {
            log::debug!(
                "[REGISTRY] fallback_route: cannot bind GUID {:02x?}, {} topics with subscribers",
                &guid[..],
                topics_with_subs.len()
            );
            None
        }
    }

    #[must_use]
    #[inline]
    pub fn deliver_heartbeat(&self, heartbeat_bytes: &[u8]) -> usize {
        let handlers = recover_read(
            &self.heartbeat_handlers,
            "TopicRegistry::heartbeat_handlers.read()",
        );
        let mut errors = 0;

        for handler in handlers.iter() {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                handler.on_heartbeat(heartbeat_bytes);
            }));

            if result.is_err() {
                errors += 1;
                log::debug!("[demux] Heartbeat handler panicked");
            }
        }

        errors
    }

    #[must_use]
    #[inline]
    pub fn deliver_nack(&self, nack_bytes: &[u8]) -> usize {
        let handlers = recover_read(&self.nack_handlers, "TopicRegistry::nack_handlers.read()");
        let mut errors = 0;

        // v206: Log handler count to track registration issues
        log::debug!(
            "[demux] v206: deliver_nack called with {} bytes, {} handlers registered",
            nack_bytes.len(),
            handlers.len()
        );

        for handler in handlers.iter() {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                handler.on_nack(nack_bytes);
            }));

            if result.is_err() {
                errors += 1;
                log::debug!("[demux] NACK handler panicked");
            }
        }

        errors
    }

    #[must_use]
    #[inline]
    pub fn deliver_nack_frag(
        &self,
        writer_entity_id: &[u8; 4],
        writer_sn: u64,
        missing_fragments: &[u32],
    ) -> usize {
        let handlers = recover_read(
            &self.nack_frag_handlers,
            "TopicRegistry::nack_frag_handlers.read()",
        );
        let mut errors = 0;

        log::debug!(
            "[demux] deliver_nack_frag: writer_eid={:02x?} sn={} frags={:?}, {} handlers",
            writer_entity_id,
            writer_sn,
            missing_fragments,
            handlers.len()
        );

        for handler in handlers.iter() {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                handler.on_nack_frag(writer_entity_id, writer_sn, missing_fragments);
            }));

            if result.is_err() {
                errors += 1;
                log::debug!("[demux] NACK_FRAG handler panicked");
            }
        }

        errors
    }
}

impl Default for TopicRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Error Types
// ============================================================================

use std::fmt;

/// Registry operation errors
#[derive(Debug, Clone)]
pub enum RegistryError {
    TopicNotFound { name: String },
    OperationFailed { reason: String },
}

impl fmt::Display for RegistryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RegistryError::TopicNotFound { name } => write!(f, "Topic not found: {}", name),
            RegistryError::OperationFailed { reason } => write!(f, "Operation failed: {}", reason),
        }
    }
}

impl std::error::Error for RegistryError {}
