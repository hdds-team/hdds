// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Topic-based demultiplexing and fanout
//!
//! Manages topic registration, subscriber lists, and data delivery.
//! Provides GUID->topic mapping for RTI/Cyclone/FastDDS interoperability.

use crate::engine::subscriber::DisposeKind;
use crate::engine::subscriber::Subscriber;
use std::collections::HashMap;
use std::net::SocketAddr;
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
    /// - `heartbeat_bytes`: Raw Heartbeat message payload (CDR2 encoded).
    /// - `source_addr`: UDP source address of the HEARTBEAT sender.
    ///   Used to route ACKNACK responses back to the writer's unicast
    ///   metatraffic endpoint instead of multicast (required for
    ///   cross-vendor RELIABLE interop, e.g. FastDDS).
    fn on_heartbeat(&self, heartbeat_bytes: &[u8], source_addr: Option<SocketAddr>);
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
    pub fn deliver(&self, seq: u64, data: &[u8], version: crate::dds::CdrVersion) -> usize {
        let mut errors = 0;

        for sub in &self.subscribers {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                sub.on_data_with_version(&self.name, seq, data, version);
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

    /// Deliver payload along with the originating writer GUID.
    ///
    /// Same contract as [`Self::deliver`] but routes through the
    /// `Subscriber::on_data_with_writer` overload so subscribers that need
    /// per-writer state (e.g. TRANSIENT_LOCAL late-joiner reordering) can
    /// see which writer the sample came from.
    #[inline]
    pub fn deliver_with_writer(
        &self,
        writer_guid: [u8; 16],
        seq: u64,
        data: &[u8],
        version: crate::dds::CdrVersion,
    ) -> usize {
        let mut errors = 0;

        for sub in &self.subscribers {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                sub.on_data_with_writer(&self.name, writer_guid, seq, data, version);
            }));

            if result.is_err() {
                errors += 1;
                log::debug!(
                    "[demux] Subscriber '{}' panicked during writer-tagged delivery",
                    sub.topic_name()
                );
            }
        }

        errors
    }

    /// Notify all subscribers of this topic that a HEARTBEAT was received
    /// from the given writer advertising the given `first_seq`. Lets
    /// non-Volatile readers seed their late-joiner reordering buffer
    /// (DDS-RTPS v2.5 §8.3.7.5 `firstSN`).
    #[inline]
    pub fn deliver_writer_heartbeat(&self, writer_guid: [u8; 16], first_seq: u64) -> usize {
        let mut errors = 0;
        for sub in &self.subscribers {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                sub.on_writer_heartbeat(writer_guid, first_seq);
            }));
            if result.is_err() {
                errors += 1;
                log::debug!(
                    "[demux] Subscriber '{}' panicked during writer-heartbeat hook",
                    sub.topic_name()
                );
            }
        }
        errors
    }

    /// Deliver a dispose/unregister lifecycle notification to all subscribers.
    ///
    /// Returns number of delivery errors (panic count).
    ///
    /// # Arguments
    /// - `seq`: RTPS writer sequence number
    /// - `key_hash`: 16-byte instance key hash from PID_KEY_HASH
    /// - `kind`: Dispose, Unregister, or both
    #[inline]
    pub fn deliver_dispose(&self, seq: u64, key_hash: [u8; 16], kind: DisposeKind) -> usize {
        let mut errors = 0;

        for sub in &self.subscribers {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                sub.on_dispose(&self.name, seq, key_hash, kind);
            }));

            if result.is_err() {
                errors += 1;
                log::debug!(
                    "[demux] Subscriber '{}' panicked during dispose delivery",
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
    /// Writer GUID -> ownership strength (for EXCLUSIVE ownership filtering)
    writer_ownership_strengths: RwLock<HashMap<[u8; 16], i32>>,
    /// Per-instance ownership tracking: (topic_name, instance_hash) -> (current owner GUID, strength)
    #[allow(clippy::type_complexity)]
    exclusive_ownership: RwLock<HashMap<(String, u64), ([u8; 16], i32)>>,
    /// Set of topic names where exclusive ownership is enabled
    exclusive_ownership_topics: RwLock<std::collections::HashSet<String>>,
    /// v249: Writer GUIDs blocked due to QoS incompatibility with local readers.
    /// Data from these writers is dropped by the router even if the topic matches.
    /// Populated by the SEDP handler when incompatible writers are discovered.
    blocked_writers: RwLock<std::collections::HashSet<[u8; 16]>>,
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
            writer_ownership_strengths: RwLock::new(HashMap::new()),
            exclusive_ownership: RwLock::new(HashMap::new()),
            exclusive_ownership_topics: RwLock::new(std::collections::HashSet::new()),
            blocked_writers: RwLock::new(std::collections::HashSet::new()),
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

    /// Notify the subscribers of the topic bound to `writer_guid` that the
    /// writer just advertised `first_seq` in a HEARTBEAT submessage. The
    /// control-channel HEARTBEAT path uses this to seed late-joiner
    /// reorder buffers in user-data readers, since the original
    /// `deliver_heartbeat` path is bypassed for HBs that arrive via the
    /// control channel (see `core::discovery::multicast::control`).
    #[must_use]
    pub fn notify_writer_heartbeat(&self, writer_guid: [u8; 16], first_seq: u64) -> bool {
        let Some(topic_name) = self.get_topic_by_guid(&writer_guid) else {
            return false;
        };
        let Some(topic) = self.get_topic(&topic_name) else {
            return false;
        };
        let _ = topic.deliver_writer_heartbeat(writer_guid, first_seq);
        true
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

    /// Register a writer's ownership strength for exclusive ownership filtering.
    pub fn register_writer_ownership_strength(&self, guid: [u8; 16], strength: i32) {
        log::debug!(
            "[OWNERSHIP] register_strength writer={:02x}{:02x}{:02x}{:02x} strength={}",
            guid[12],
            guid[13],
            guid[14],
            guid[15],
            strength
        );
        let mut strengths = recover_write(
            &self.writer_ownership_strengths,
            "TopicRegistry::writer_ownership_strengths.write()",
        );
        strengths.insert(guid, strength);
    }

    /// v249: Block a writer GUID due to QoS incompatibility with local readers.
    ///
    /// Data from blocked writers is dropped by the router regardless of
    /// routing method (inline QoS or GUID-based).
    pub fn block_writer(&self, guid: [u8; 16]) {
        let mut blocked = recover_write(
            &self.blocked_writers,
            "TopicRegistry::blocked_writers.write()",
        );
        blocked.insert(guid);
        log::debug!(
            "[REGISTRY] v249: Blocked writer {:02x?} (QoS incompatible)",
            &guid[..]
        );
    }

    /// v222: Unblock a previously blocked writer (QoS now compatible).
    pub fn unblock_writer(&self, guid: [u8; 16]) {
        let mut blocked = recover_write(
            &self.blocked_writers,
            "TopicRegistry::blocked_writers.write()",
        );
        if blocked.remove(&guid) {
            log::debug!(
                "[REGISTRY] v222: Unblocked writer {:02x?} (QoS now compatible)",
                &guid[..]
            );
        }
    }

    /// v249: Check if a writer GUID is blocked (QoS incompatible).
    #[must_use]
    #[inline]
    pub fn is_writer_blocked(&self, guid: &[u8; 16]) -> bool {
        let blocked = recover_read(
            &self.blocked_writers,
            "TopicRegistry::blocked_writers.read()",
        );
        blocked.contains(guid)
    }

    /// Enable exclusive ownership filtering for a topic.
    pub fn enable_exclusive_ownership(&self, topic_name: &str) {
        log::debug!("[OWNERSHIP] enable_exclusive topic='{}'", topic_name);
        let mut topics = recover_write(
            &self.exclusive_ownership_topics,
            "TopicRegistry::exclusive_ownership_topics.write()",
        );
        topics.insert(topic_name.to_string());
    }

    /// Check if a writer is allowed to deliver data for a topic instance under exclusive ownership.
    ///
    /// Ownership is per-instance (DDS spec 2.2.3.11). Different instances (different keys)
    /// can have different owners. The `instance_hash` is a hash of the serialized key fields.
    ///
    /// Returns `true` if delivery is allowed (no exclusive ownership, or writer is current owner
    /// or has higher strength). Returns `false` if a higher-strength writer owns this instance.
    pub fn check_ownership(
        &self,
        topic_name: &str,
        writer_guid: &[u8; 16],
        instance_hash: u64,
    ) -> bool {
        // Fast path: check if topic has exclusive ownership enabled
        {
            let topics = recover_read(
                &self.exclusive_ownership_topics,
                "TopicRegistry::exclusive_ownership_topics.read()",
            );
            if !topics.contains(topic_name) {
                return true; // SHARED ownership, always deliver
            }
        }

        // Get writer's ownership strength
        let writer_strength = {
            let strengths = recover_read(
                &self.writer_ownership_strengths,
                "TopicRegistry::writer_ownership_strengths.read()",
            );
            strengths.get(writer_guid).copied().unwrap_or(0)
        };

        // Check current owner for this (topic, instance) pair
        let key = (topic_name.to_string(), instance_hash);
        let mut owners = recover_write(
            &self.exclusive_ownership,
            "TopicRegistry::exclusive_ownership.write()",
        );

        match owners.get(&key) {
            Some(&(ref owner_guid, owner_strength)) => {
                if writer_guid == owner_guid {
                    // Current owner — also update stored strength if it changed
                    // (SEDP may register strength after first data delivery)
                    if writer_strength != owner_strength {
                        owners.insert(key.clone(), (*writer_guid, writer_strength));
                    }
                    true
                } else if writer_strength > owner_strength {
                    // Higher strength writer takes ownership
                    owners.insert(key, (*writer_guid, writer_strength));
                    true
                } else {
                    false // Lower or equal strength, reject
                }
            }
            None => {
                // No owner yet, this writer becomes owner
                owners.insert(key, (*writer_guid, writer_strength));
                true
            }
        }
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
    pub fn deliver_heartbeat(
        &self,
        heartbeat_bytes: &[u8],
        source_addr: Option<SocketAddr>,
    ) -> usize {
        let handlers = recover_read(
            &self.heartbeat_handlers,
            "TopicRegistry::heartbeat_handlers.read()",
        );
        let mut errors = 0;

        for handler in handlers.iter() {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                handler.on_heartbeat(heartbeat_bytes, source_addr);
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
