// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Discovery FSM core: participant database and SPDP/SEDP handlers.
//!
//!
//! Implements `DiscoveryFsm` which maintains `ParticipantDB` and processes
//! incoming discovery packets from the multicast listener thread.

use super::endpoint::{EndpointInfo, EndpointKind};
use super::metrics::DiscoveryMetrics;
use super::registry::TopicRegistry;
use crate::core::discovery::multicast::ParticipantInfo;
use crate::core::discovery::{EndpointRegistry, ReplayRegistry, GUID};
use crate::dds::qos::Durability;
use crate::protocol::dialect::Dialect;
use crate::protocol::discovery::{SedpData, SpdpData};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};

/// Listener for discovery events (endpoints only).
pub trait DiscoveryListener: Send + Sync {
    /// Called when a new endpoint is discovered.
    fn on_endpoint_discovered(&self, endpoint: EndpointInfo);
}

/// Security validator for participant authentication (DDS Security v1.1).
///
/// Implement this trait to add security validation to discovery.
/// When a participant announces with an identity_token, this validator
/// is called to verify the certificate before allowing the participant.
pub trait SecurityValidator: Send + Sync {
    /// Validate a remote participant's identity token.
    ///
    /// # Arguments
    /// - `participant_guid`: GUID of the remote participant
    /// - `identity_token`: X.509 certificate (PEM-encoded) from SPDP data
    ///
    /// # Returns
    /// - `Ok(())` if the identity is valid and trusted
    /// - `Err(reason)` if the identity should be rejected
    fn validate_identity(
        &self,
        participant_guid: GUID,
        identity_token: &[u8],
    ) -> Result<(), String>;
}

/// Participant database type.
///
/// Maps participant GUID to participant metadata.
/// Wrapped in `Arc<RwLock<...>>` for concurrent access.
pub type ParticipantDB = HashMap<GUID, ParticipantInfo>;

/// v197: Select best locator from a list of announced addresses.
///
/// Preference order:
/// 1. Addresses on common DDS subnets (192.168.x.x, 10.x.x.x)
/// 2. Any non-Docker, non-localhost address
/// 3. Any non-unspecified address
///
/// This handles FastDDS which announces multiple locators including Docker bridge (172.17.x.x).
fn select_best_locator(locators: &[std::net::SocketAddr]) -> Option<&std::net::SocketAddr> {
    use std::net::IpAddr;

    // First pass: prefer addresses on common DDS subnets (192.168.x.x, 10.x.x.x)
    // These are typically the "real" network interfaces used in DDS deployments.
    let preferred = locators.iter().find(|addr| {
        if addr.ip().is_unspecified() {
            return false;
        }
        match addr.ip() {
            IpAddr::V4(ipv4) => {
                let octets = ipv4.octets();
                // Prefer 192.168.x.x (common DDS subnet) or 10.x.x.x (corporate LAN)
                (octets[0] == 192 && octets[1] == 168)
                    || octets[0] == 10
                    // Also accept 172.16-31.x.x but NOT 172.17.x.x (Docker default)
                    || (octets[0] == 172 && (16..=31).contains(&octets[1]) && octets[1] != 17)
            }
            IpAddr::V6(_) => false, // Skip IPv6 for now
        }
    });
    if preferred.is_some() {
        return preferred;
    }

    // Second pass: any non-Docker, non-localhost, non-unspecified address
    let fallback = locators.iter().find(|addr| {
        if addr.ip().is_unspecified() || addr.ip().is_loopback() {
            return false;
        }
        match addr.ip() {
            IpAddr::V4(ipv4) => {
                let octets = ipv4.octets();
                // Skip Docker bridge (172.17.x.x) and localhost
                !(octets[0] == 172 && octets[1] == 17) && octets[0] != 127
            }
            IpAddr::V6(_) => false,
        }
    });
    if fallback.is_some() {
        return fallback;
    }

    // Last resort: any non-unspecified address
    locators.iter().find(|addr| !addr.ip().is_unspecified())
}

/// Discovery Finite State Machine.
///
/// Manages participant database and handles SPDP/SEDP discovery packets.
///
/// # Architecture
/// - Concurrent access via `Arc<RwLock<ParticipantDB>>`
/// - Self-discovery prevention (ignores `local_guid`)
/// - Automatic participant insertion/refresh
///
/// # Thread Safety
/// - `handle_spdp` and `handle_sedp` can be called concurrently
/// - DB reads are lock-free (`RwLock::read`)
/// - DB writes are serialized (`RwLock::write`)
pub struct DiscoveryFsm {
    /// Participant database (GUID -> ParticipantInfo).
    db: Arc<RwLock<ParticipantDB>>,
    /// Topic registry (topic_name -> `Vec<EndpointInfo>`).
    topic_registry: Arc<RwLock<TopicRegistry>>,
    /// Endpoint registry for discovered participant unicast locators (v0.5.1+).
    /// Connects discovery -> writer for unicast DATA routing.
    endpoint_registry: EndpointRegistry,
    /// Replay registry for transient-local durability (late joiners).
    replay_registry: ReplayRegistry,
    /// Local participant GUID (for self-discovery filtering).
    local_guid: GUID,
    /// Default lease duration in milliseconds.
    #[allow(dead_code)] // Stored for potential future use
    lease_duration_ms: u64,
    /// Discovery metrics.
    pub metrics: DiscoveryMetrics,
    /// Locked dialect for vendor-specific QoS defaults (set by dialect detector).
    /// Uses AtomicU8 for lock-free thread-safe access.
    /// Value 0 = not set (use Hybrid defaults), 1+ = Dialect enum ordinal + 1.
    locked_dialect: AtomicU8,
    /// Registered discovery listeners.
    listeners: Arc<RwLock<Vec<Arc<dyn DiscoveryListener>>>>,
    /// Optional security validator for participant authentication (DDS Security v1.1).
    ///
    /// When set, incoming SPDP participants with identity_token are validated.
    /// Participants failing validation are rejected (not added to DB).
    security_validator: Option<Arc<dyn SecurityValidator>>,
    /// Whether to require security (reject participants without identity_token).
    require_authentication: bool,
}

impl DiscoveryFsm {
    /// Create new `DiscoveryFsm`.
    ///
    /// # Arguments
    /// - `local_guid`: Local participant GUID (to filter self-discovery)
    /// - `lease_duration_ms`: Default lease duration for participants (typically 100_000 ms)
    ///
    /// # Examples
    /// ```
    /// use hdds::core::discovery::GUID;
    /// use hdds::core::discovery::multicast::DiscoveryFsm;
    ///
    /// let local_guid = GUID::from_bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
    /// let fsm = DiscoveryFsm::new(local_guid, 100_000);
    /// assert_eq!(fsm.metrics.snapshot().0, 0);
    /// ```
    #[must_use]
    pub fn new(local_guid: GUID, lease_duration_ms: u64) -> Self {
        crate::trace_fn!("DiscoveryFsm::new");
        Self {
            db: Arc::new(RwLock::new(HashMap::new())),
            topic_registry: Arc::new(RwLock::new(TopicRegistry::new())),
            endpoint_registry: EndpointRegistry::new(),
            replay_registry: ReplayRegistry::new(),
            local_guid,
            lease_duration_ms,
            metrics: DiscoveryMetrics::new(),
            locked_dialect: AtomicU8::new(0), // 0 = not set, use Hybrid defaults
            listeners: Arc::new(RwLock::new(Vec::new())),
            security_validator: None,
            require_authentication: false,
        }
    }

    /// Set security validator for participant authentication.
    ///
    /// When set, incoming SPDP participants will have their identity_token
    /// validated before being added to the participant database.
    ///
    /// # Arguments
    /// - `validator`: Implementation of SecurityValidator trait
    /// - `require_authentication`: If true, reject participants without identity_token
    pub fn set_security_validator(
        &mut self,
        validator: Arc<dyn SecurityValidator>,
        require_authentication: bool,
    ) {
        self.security_validator = Some(validator);
        self.require_authentication = require_authentication;
    }

    /// Get reference to participant database (for LeaseTracker).
    #[must_use]
    pub fn db(&self) -> Arc<RwLock<ParticipantDB>> {
        crate::trace_fn!("DiscoveryFsm::db");
        Arc::clone(&self.db)
    }

    /// Get reference to endpoint registry (for Writer unicast routing, v0.5.1+).
    ///
    /// Returns clone of `EndpointRegistry` for passing to `DataWriter`.
    /// Writer uses this to send DATA packets to discovered unicast endpoints
    /// instead of blind multicast.
    #[must_use]
    pub fn endpoint_registry(&self) -> EndpointRegistry {
        crate::trace_fn!("DiscoveryFsm::endpoint_registry");
        self.endpoint_registry.clone()
    }

    /// Get reference to replay registry (for transient-local late joiners).
    #[must_use]
    pub fn replay_registry(&self) -> ReplayRegistry {
        crate::trace_fn!("DiscoveryFsm::replay_registry");
        self.replay_registry.clone()
    }

    /// Register a static peer endpoint for unicast DATA routing.
    ///
    /// Use this when the remote peer doesn't participate in SPDP discovery
    /// (e.g., hdds-micro, embedded devices, or manual network configuration).
    ///
    /// The synthetic GUID is derived from the socket address to ensure consistency
    /// across multiple calls with the same endpoint.
    ///
    /// # Arguments
    /// - `endpoint`: Socket address of the remote peer (IP:port for user data)
    ///
    /// # Example
    /// ```no_run
    /// use hdds::core::discovery::multicast::DiscoveryFsm;
    /// use hdds::core::discovery::GUID;
    ///
    /// let fsm = DiscoveryFsm::new(GUID::zero(), 100_000);
    /// fsm.register_static_peer("192.168.1.100:7411".parse().unwrap());
    /// ```
    pub fn register_static_peer(&self, endpoint: std::net::SocketAddr) {
        crate::trace_fn!("DiscoveryFsm::register_static_peer");
        // Generate a synthetic GUID from the endpoint address
        // This ensures the same endpoint always gets the same GUID
        let synthetic_guid = GUID::from_socket_addr(&endpoint);
        self.endpoint_registry.register(synthetic_guid, endpoint);
        log::info!(
            "[discovery] Registered static peer: {} (synthetic GUID: {})",
            endpoint,
            synthetic_guid
        );
    }

    /// Set the locked dialect for vendor-specific QoS defaults.
    ///
    /// Called by dialect detector when vendor is identified from SPDP.
    /// Once set, all subsequent SEDP endpoints use this dialect's default QoS
    /// when no explicit QoS PIDs are present.
    ///
    /// # Arguments
    /// - `dialect`: Detected vendor dialect (RTI, FastDDS, etc.)
    pub fn set_locked_dialect(&self, dialect: Dialect) {
        crate::trace_fn!("DiscoveryFsm::set_locked_dialect");
        // Store dialect as ordinal + 1 (0 = not set)
        let value = (dialect as u8).saturating_add(1);
        self.locked_dialect.store(value, Ordering::Release);
        log::debug!("[discovery] Locked dialect set to {:?}", dialect);
    }

    /// Get the locked dialect (if set).
    ///
    /// Returns `Some(Dialect)` if dialect has been set, `None` otherwise.
    pub fn get_locked_dialect(&self) -> Option<Dialect> {
        let value = self.locked_dialect.load(Ordering::Acquire);
        if value == 0 {
            None
        } else {
            Dialect::from_ordinal(value.saturating_sub(1))
        }
    }

    /// Register a discovery listener for new endpoint events.
    pub fn register_listener(&self, listener: Arc<dyn DiscoveryListener>) {
        let mut listeners = recover_write(
            Arc::as_ref(&self.listeners),
            "DiscoveryFsm::register_listener",
        );
        listeners.push(listener);
    }

    fn notify_endpoint_discovered(&self, endpoint: &EndpointInfo) {
        let listeners = recover_read(
            Arc::as_ref(&self.listeners),
            "DiscoveryFsm::notify_endpoint_discovered",
        );
        for listener in listeners.iter() {
            listener.on_endpoint_discovered(endpoint.clone());
        }
    }

    /// Update endpoints that match a type name with a newly received TypeObject.
    ///
    /// Returns the number of endpoints updated.
    pub fn update_type_object_for_type(
        &self,
        type_name: &str,
        type_object: crate::xtypes::CompleteTypeObject,
    ) -> usize {
        let mut registry = recover_write(
            Arc::as_ref(&self.topic_registry),
            "DiscoveryFsm::update_type_object_for_type",
        );
        registry.update_type_object_for_type(type_name, &type_object)
    }

    /// Handle SPDP (participant discovery) packet.
    ///
    /// Inserts new participant or refreshes existing one.
    /// Ignores self-discovery (`local_guid`).
    ///
    /// # Returns
    /// - `true` if this was a refresh (participant already known)
    /// - `false` if this was a new participant (or self-discovery)
    pub fn handle_spdp(&self, data: SpdpData) -> bool {
        crate::trace_fn!("DiscoveryFsm::handle_spdp");
        self.metrics.spdp_received.fetch_add(1, Ordering::Relaxed);

        // Ignore self-discovery.
        if data.participant_guid == self.local_guid {
            return false;
        }

        // DDS Security v1.1: Validate identity token if security is enabled
        if let Some(ref validator) = self.security_validator {
            match &data.identity_token {
                Some(token) => {
                    // Validate the identity token
                    if let Err(reason) = validator.validate_identity(data.participant_guid, token) {
                        log::warn!(
                            "[discovery] Security: Rejected participant {:?} - {}",
                            data.participant_guid,
                            reason
                        );
                        self.metrics.security_errors.fetch_add(1, Ordering::Relaxed);
                        return false;
                    }
                    log::debug!(
                        "[discovery] Security: Authenticated participant {:?}",
                        data.participant_guid
                    );
                }
                None if self.require_authentication => {
                    // Reject participants without identity token when authentication is required
                    log::warn!(
                        "[discovery] Security: Rejected unauthenticated participant {:?}",
                        data.participant_guid
                    );
                    self.metrics.security_errors.fetch_add(1, Ordering::Relaxed);
                    return false;
                }
                None => {
                    // No identity token, but not required (permissive mode)
                    log::debug!(
                        "[discovery] Security: Allowing unauthenticated participant {:?} (permissive mode)",
                        data.participant_guid
                    );
                }
            }
        }

        // Check if participant exists (read lock) and guard against poison.
        let exists = {
            let db = recover_read(Arc::as_ref(&self.db), "DiscoveryFsm::handle_spdp exists");
            db.contains_key(&data.participant_guid)
        };

        if exists {
            // Refresh existing participant (write lock).
            let mut db = recover_write(Arc::as_ref(&self.db), "DiscoveryFsm::handle_spdp refresh");
            if let Some(info) = db.get_mut(&data.participant_guid) {
                info.refresh();
            }
            return true; // v182: Signal this was a refresh
        } else {
            // Insert new participant (write lock).
            let info = ParticipantInfo::new(
                data.participant_guid,
                data.metatraffic_unicast_locators.clone(), // v79: use metatraffic for SEDP
                data.lease_duration_ms,
            );

            let mut db = recover_write(Arc::as_ref(&self.db), "DiscoveryFsm::handle_spdp insert");
            db.insert(data.participant_guid, info);

            // v99: FIX - Register USER DATA endpoint (port 7411) not metatraffic (port 7410)!
            // User data must be sent to default_unicast_locators per RTPS v2.3 Sec.8.5.3.1
            // v100: Filter out 0.0.0.0 addresses (FastDDS sends them meaning "use source IP")
            // v197: Prefer addresses on the same subnet over Docker/bridge interfaces.
            //       FastDDS may announce multiple locators including Docker bridge (172.17.x.x).
            //       We should prefer addresses on the same 192.168.x.x subnet as our node.
            let valid_default_unicast = select_best_locator(&data.default_unicast_locators);
            let valid_metatraffic_unicast = select_best_locator(&data.metatraffic_unicast_locators);

            if let Some(&endpoint) = valid_default_unicast {
                self.endpoint_registry
                    .register(data.participant_guid, endpoint);
                log::debug!(
                    "[discovery] v100: Registered USER DATA endpoint (port 7411): {}",
                    endpoint
                );
            } else if let Some(&fallback_endpoint) = valid_metatraffic_unicast {
                // Fallback: use metatraffic if default not available (legacy/buggy peers)
                self.endpoint_registry
                    .register(data.participant_guid, fallback_endpoint);
                log::debug!(
                    "[discovery] v100: FALLBACK - Using metatraffic endpoint (port 7410): {}",
                    fallback_endpoint
                );
            } else {
                log::warn!(
                    "[discovery] v100: No valid unicast locator found for participant {:?}",
                    data.participant_guid
                );
            }

            self.metrics
                .participants_discovered
                .fetch_add(1, Ordering::Relaxed);
        }
        false // v182: New participant (not a refresh)
    }

    /// Handle SEDP (endpoint discovery) packet.
    ///
    /// Inserts or updates endpoint in topic registry.
    /// Validates that participant exists before inserting endpoint.
    /// Performs automatic endpoint matching (Phase 1.4).
    pub fn handle_sedp(&self, data: SedpData) {
        crate::trace_fn!("DiscoveryFsm::handle_sedp");
        self.metrics.sedp_received.fetch_add(1, Ordering::Relaxed);

        // Extract participant prefix from endpoint GUID (first 12 bytes).
        let endpoint_prefix = &data.endpoint_guid.as_bytes()[..12];
        let local_prefix = &self.local_guid.as_bytes()[..12];

        // Check if endpoint is local (Phase 1.4)
        let is_local_endpoint = endpoint_prefix == local_prefix;

        // Find participant with matching prefix (read lock).
        // Skip check for local endpoints (they're not in ParticipantDB)
        let participant_exists = is_local_endpoint || {
            let db = recover_read(
                Arc::as_ref(&self.db),
                "DiscoveryFsm::handle_sedp participant",
            );
            db.keys()
                .any(|participant_guid| &participant_guid.as_bytes()[..12] == endpoint_prefix)
        };

        if !participant_exists {
            // Ignore SEDP from unknown participants (not discovered via SPDP yet).
            log::debug!(
                "[SEDP] v207: Ignoring SEDP from unknown participant (prefix={:02x?})",
                &endpoint_prefix[..4]
            );
            return;
        }

        // Create endpoint info (auto-detects Writer vs Reader from GUID).
        // Uses locked dialect for vendor-specific QoS defaults when no PIDs present.
        let dialect = self.get_locked_dialect();
        let endpoint = EndpointInfo::from_sedp(data, dialect);

        let topic_name = endpoint.topic_name.clone();
        let type_name = endpoint.type_name.clone();
        let type_object = endpoint.type_object.clone();
        let endpoint_kind = endpoint.kind;
        let endpoint_durability = endpoint.qos.durability;
        let endpoint_participant = endpoint.participant_guid;

        let is_new = {
            // Insert into topic registry (write lock).
            let mut registry = recover_write(
                Arc::as_ref(&self.topic_registry),
                "DiscoveryFsm::handle_sedp insert_endpoint",
            );
            let is_new = registry.insert(endpoint.clone());

            // Phase 1.4: Automatic endpoint matching
            // After insertion, check for compatible opposite endpoints
            log::debug!(
                "[SEDP] v207: handle_sedp topic='{}' type='{}' kind={:?} is_local={} is_new={}",
                topic_name,
                type_name,
                endpoint_kind,
                is_local_endpoint,
                is_new
            );
            match endpoint_kind {
                EndpointKind::Writer => {
                    // Writer inserted -> find compatible Readers
                    let compatible_readers = registry.find_compatible_readers(
                        &topic_name,
                        type_object.as_ref(),
                        &type_name,
                    );
                    log::debug!(
                        "[SEDP Match] Writer on '{}' type='{}': {} compatible Reader(s)",
                        topic_name,
                        type_name,
                        compatible_readers.len()
                    );
                }
                EndpointKind::Reader => {
                    // Reader inserted -> find compatible Writers
                    let compatible_writers = registry.find_compatible_writers(
                        &topic_name,
                        type_object.as_ref(),
                        &type_name,
                    );
                    log::debug!(
                        "[SEDP Match] Reader on '{}' type='{}': {} compatible Writer(s)",
                        topic_name,
                        type_name,
                        compatible_writers.len()
                    );
                    if is_new
                        && matches!(
                            endpoint_durability,
                            Durability::TransientLocal | Durability::Persistent
                        )
                    {
                        if let Some(dest) = self.endpoint_registry.get(&endpoint_participant) {
                            self.replay_registry
                                .replay_for(&topic_name, &type_name, dest);
                        } else {
                            log::debug!(
                                "[SEDP Match] No unicast endpoint for participant {:?}, skipping history replay",
                                endpoint_participant
                            );
                        }
                    }
                }
            }

            is_new
        };

        if is_new {
            self.notify_endpoint_discovered(&endpoint);
        }
    }

    /// Find all writers for a topic.
    #[must_use]
    pub fn find_writers_for_topic(&self, topic_name: &str) -> Vec<EndpointInfo> {
        crate::trace_fn!("DiscoveryFsm::find_writers_for_topic");
        let registry = recover_read(
            Arc::as_ref(&self.topic_registry),
            "DiscoveryFsm::find_writers_for_topic registry.read()",
        );
        registry.find_writers(topic_name)
    }

    /// Find all readers for a topic.
    #[must_use]
    pub fn find_readers_for_topic(&self, topic_name: &str) -> Vec<EndpointInfo> {
        crate::trace_fn!("DiscoveryFsm::find_readers_for_topic");
        let registry = recover_read(
            Arc::as_ref(&self.topic_registry),
            "DiscoveryFsm::find_readers_for_topic registry.read()",
        );
        registry.find_readers(topic_name)
    }

    /// Get snapshot of all participants.
    ///
    /// Returns cloned `Vec` for iteration without holding locks.
    #[must_use]
    pub fn get_participants(&self) -> Vec<ParticipantInfo> {
        crate::trace_fn!("DiscoveryFsm::get_participants");
        let db = recover_read(Arc::as_ref(&self.db), "DiscoveryFsm::get_participants");
        db.values().cloned().collect()
    }

    /// Get count of discovered participants.
    ///
    /// More efficient than `get_participants().len()` as it doesn't clone.
    #[must_use]
    pub fn participant_count(&self) -> usize {
        let db = recover_read(Arc::as_ref(&self.db), "DiscoveryFsm::participant_count");
        db.len()
    }

    /// Get snapshot of all discovered topics with aggregated endpoint information.
    ///
    /// Returns a map of topic names to (writers, readers) endpoint lists.
    /// Used for live topic discovery without compile-time type knowledge.
    ///
    /// # Returns
    /// HashMap mapping topic_name -> `(Vec<EndpointInfo> writers, Vec<EndpointInfo> readers)`
    #[must_use]
    pub fn get_all_topics(
        &self,
    ) -> std::collections::HashMap<String, (Vec<EndpointInfo>, Vec<EndpointInfo>)> {
        crate::trace_fn!("DiscoveryFsm::get_all_topics");
        use std::collections::HashMap;

        let registry = recover_read(
            Arc::as_ref(&self.topic_registry),
            "DiscoveryFsm::get_all_topics",
        );

        let mut result = HashMap::new();

        // Get all topic names and query each topic for its endpoints
        for topic_name in registry.get_all_topic_names() {
            let writers = registry.find_writers(&topic_name);
            let readers = registry.find_readers(&topic_name);
            result.insert(topic_name, (writers, readers));
        }

        result
    }

    /// Remove participant from database.
    ///
    /// Used by LeaseTracker to remove expired participants.
    pub fn remove_participant(&self, guid: GUID) {
        crate::trace_fn!("DiscoveryFsm::remove_participant");
        // Remove from participant DB.
        let mut db = recover_write(
            Arc::as_ref(&self.db),
            "DiscoveryFsm::remove_participant db.write()",
        );
        let removed = db.remove(&guid).is_some();
        drop(db); // Release lock before topic registry operation

        if removed {
            // Remove all endpoints for this participant.
            let mut registry = recover_write(
                Arc::as_ref(&self.topic_registry),
                "DiscoveryFsm::remove_participant registry.write()",
            );
            registry.remove_participant(&guid);

            // Remove from endpoint registry (v0.5.1+).
            self.endpoint_registry.remove(&guid);

            self.metrics
                .participants_expired
                .fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Recover from poisoned read lock by logging and taking ownership.
pub(crate) fn recover_read<'a, T>(lock: &'a RwLock<T>, context: &str) -> RwLockReadGuard<'a, T> {
    match lock.read() {
        Ok(guard) => guard,
        Err(poisoned) => {
            log::debug!("[discovery] WARNING: {} poisoned, recovering", context);
            poisoned.into_inner()
        }
    }
}

/// Recover from poisoned write lock by logging and taking ownership.
pub(crate) fn recover_write<'a, T>(lock: &'a RwLock<T>, context: &str) -> RwLockWriteGuard<'a, T> {
    match lock.write() {
        Ok(guard) => guard,
        Err(poisoned) => {
            log::debug!("[discovery] WARNING: {} poisoned, recovering", context);
            poisoned.into_inner()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::discovery::GUID;
    use crate::protocol::discovery::{SedpData, SpdpData};
    use std::convert::TryFrom;

    fn sample_remote_guid(byte: u8) -> GUID {
        let mut data = [0u8; 16];
        for (idx, slot) in data.iter_mut().enumerate() {
            let offset = u8::try_from(idx).unwrap_or(0);
            *slot = byte.wrapping_add(offset);
        }
        GUID::from_bytes(data)
    }

    #[test]
    fn test_fsm_new() {
        let local_guid = sample_remote_guid(1);
        let fsm = DiscoveryFsm::new(local_guid, 100_000);

        assert_eq!(fsm.local_guid, local_guid);
        assert_eq!(fsm.lease_duration_ms, 100_000);
        assert!(fsm.get_participants().is_empty());
    }

    #[test]
    fn test_handle_spdp_new_participant() {
        let local_guid = GUID::zero();
        let fsm = DiscoveryFsm::new(local_guid, 100_000);

        let remote_guid = sample_remote_guid(2);
        let spdp_data = SpdpData {
            participant_guid: remote_guid,
            lease_duration_ms: 100_000,
            domain_id: 0,
            metatraffic_unicast_locators: vec!["127.0.0.1:7400"
                .parse()
                .expect("Socket address parsing should succeed")],
            default_unicast_locators: vec![],
            default_multicast_locators: vec![],
            metatraffic_multicast_locators: vec![],
            identity_token: None,
        };

        fsm.handle_spdp(spdp_data);

        let participants = fsm.get_participants();
        assert_eq!(participants.len(), 1);
        assert_eq!(participants[0].guid, remote_guid);
        assert_eq!(participants[0].endpoints.len(), 1);
    }

    #[test]
    fn test_handle_spdp_duplicate_refresh() {
        let local_guid = GUID::zero();
        let fsm = DiscoveryFsm::new(local_guid, 100_000);

        let remote_guid = sample_remote_guid(3);
        let spdp_data = SpdpData {
            participant_guid: remote_guid,
            lease_duration_ms: 100_000,
            domain_id: 0,
            metatraffic_unicast_locators: vec![],
            default_unicast_locators: vec![],
            default_multicast_locators: vec![],
            metatraffic_multicast_locators: vec![],
            identity_token: None,
        };

        fsm.handle_spdp(spdp_data.clone());
        let first_seen = {
            let db = fsm.db.read().expect("RwLock read should succeed");
            db.get(&remote_guid)
                .expect("Participant should exist")
                .last_seen
        };

        std::thread::sleep(std::time::Duration::from_millis(5));

        fsm.handle_spdp(spdp_data);
        let second_seen = {
            let db = fsm.db.read().expect("RwLock read should succeed");
            db.get(&remote_guid)
                .expect("Participant should exist")
                .last_seen
        };

        assert!(second_seen > first_seen);
        assert_eq!(fsm.get_participants().len(), 1);
    }

    #[test]
    fn test_handle_spdp_ignore_self() {
        let local_guid = sample_remote_guid(4);
        let fsm = DiscoveryFsm::new(local_guid, 100_000);

        let spdp_data = SpdpData {
            participant_guid: local_guid,
            lease_duration_ms: 100_000,
            domain_id: 0,
            metatraffic_unicast_locators: vec![],
            default_unicast_locators: vec![],
            default_multicast_locators: vec![],
            metatraffic_multicast_locators: vec![],
            identity_token: None,
        };

        fsm.handle_spdp(spdp_data);
        assert!(fsm.get_participants().is_empty());
    }

    #[test]
    fn test_remove_participant() {
        let local_guid = GUID::zero();
        let fsm = DiscoveryFsm::new(local_guid, 100_000);

        let remote_guid = sample_remote_guid(5);
        let spdp_data = SpdpData {
            participant_guid: remote_guid,
            lease_duration_ms: 100_000,
            domain_id: 0,
            metatraffic_unicast_locators: vec![],
            default_unicast_locators: vec![],
            default_multicast_locators: vec![],
            metatraffic_multicast_locators: vec![],
            identity_token: None,
        };

        fsm.handle_spdp(spdp_data);
        assert_eq!(fsm.get_participants().len(), 1);

        fsm.remove_participant(remote_guid);
        assert!(fsm.get_participants().is_empty());
    }

    #[test]
    fn test_handle_sedp_ignores_unknown_participant() {
        let local_guid = GUID::zero();
        let fsm = DiscoveryFsm::new(local_guid, 100_000);

        let sedp_data = SedpData {
            topic_name: "sensor/temp".to_string(),
            type_name: "Temperature".to_string(),
            participant_guid: GUID::zero(), // Test data
            endpoint_guid: sample_remote_guid(6),
            qos_hash: 12345,
            qos: None, // Tests use default QoS values
            type_object: None,
            unicast_locators: vec![],
            user_data: None,
        };

        fsm.handle_sedp(sedp_data);
        assert!(fsm.find_writers_for_topic("sensor/temp").is_empty());
    }

    #[test]
    fn test_handle_sedp_inserts_endpoint() {
        let local_guid = GUID::zero();
        let fsm = DiscoveryFsm::new(local_guid, 100_000);

        let remote_guid = sample_remote_guid(7);
        let spdp_data = SpdpData {
            participant_guid: remote_guid,
            lease_duration_ms: 100_000,
            domain_id: 0,
            metatraffic_unicast_locators: vec![],
            default_unicast_locators: vec![],
            default_multicast_locators: vec![],
            metatraffic_multicast_locators: vec![],
            identity_token: None,
        };
        fsm.handle_spdp(spdp_data);

        let mut endpoint_guid_bytes = remote_guid.as_bytes();
        endpoint_guid_bytes[15] = 0x02; // writer
        let sedp_data = SedpData {
            topic_name: "sensor/temp".to_string(),
            type_name: "Temperature".to_string(),
            participant_guid: GUID::zero(), // Test data
            endpoint_guid: GUID::from_bytes(endpoint_guid_bytes),
            qos_hash: 123,
            qos: None, // Tests use default QoS values
            type_object: None,
            unicast_locators: vec![],
            user_data: None,
        };

        fsm.handle_sedp(sedp_data);

        let writers = fsm.find_writers_for_topic("sensor/temp");
        assert_eq!(writers.len(), 1);
        assert_eq!(writers[0].type_name, "Temperature");
    }

    #[test]
    fn test_metrics_snapshot() {
        let local_guid = GUID::zero();
        let fsm = DiscoveryFsm::new(local_guid, 100_000);

        let remote_guid = sample_remote_guid(8);
        let spdp_data = SpdpData {
            participant_guid: remote_guid,
            lease_duration_ms: 100_000,
            domain_id: 0,
            metatraffic_unicast_locators: vec![],
            default_unicast_locators: vec![],
            default_multicast_locators: vec![],
            metatraffic_multicast_locators: vec![],
            identity_token: None,
        };
        fsm.handle_spdp(spdp_data.clone());
        fsm.handle_spdp(spdp_data);

        let (spdp_rx, sedp_rx, discovered, expired, errors) = fsm.metrics.snapshot();
        assert_eq!(spdp_rx, 2);
        assert_eq!(sedp_rx, 0);
        assert_eq!(discovered, 1);
        assert_eq!(expired, 0);
        assert_eq!(errors, 0);
    }
}
