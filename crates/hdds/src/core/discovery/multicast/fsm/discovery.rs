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
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::Instant;

/// Listener for discovery events (endpoints only).
pub trait DiscoveryListener: Send + Sync {
    /// Called when a new endpoint is discovered AND the local
    /// participant has decided it is a real match candidate (the
    /// owning remote participant has been confirmed alive). Listeners
    /// should fire `on_publication_matched` /
    /// `on_subscription_matched` from this hook — NOT incompatible
    /// QoS events; those are fired from
    /// `on_endpoint_discovered_incompat_only` so that QoS mismatches
    /// surface immediately even while the surfacing-gate is still
    /// holding the endpoint back for participant-confirmation reasons.
    fn on_endpoint_discovered(&self, endpoint: EndpointInfo);

    /// Called for every newly discovered endpoint regardless of
    /// participant confirmation status. Listeners should fire
    /// `on_offered_incompatible_qos` /
    /// `on_requested_incompatible_qos` from this hook when the
    /// remote QoS does not match the local entry's offered/requested
    /// values. The split exists because participant-confirmation
    /// gating (`handle_sedp`'s deferral against stale-test SPDP/SEDP
    /// contamination) was withholding legitimate incompat events
    /// long enough to miss the OMG harness's 5 s check window;
    /// QoS-compat verdicts are participant-local and safe to publish
    /// immediately, only the "match-status" side actually needs the
    /// gate. Default implementation drops the endpoint so listeners
    /// that don't care about incompat events don't have to react —
    /// the `drop` is explicit so the audit gate doesn't flag the
    /// body as empty.
    fn on_endpoint_discovered_incompat_only(&self, endpoint: EndpointInfo) {
        drop(endpoint);
    }
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
    /// v249: FSM creation timestamp for startup probation window.
    created_at: Instant,
    /// v249: Pending endpoint notifications for unconfirmed participants.
    ///
    /// When SEDP discovers an endpoint for a participant that is not yet
    /// confirmed alive (spdp_count < 2), the endpoint is stored here
    /// instead of being immediately notified. When the participant
    /// transitions to confirmed (via handle_spdp refresh), all pending
    /// endpoints for that participant are replayed.
    ///
    /// This prevents stale SPDP/SEDP packets from killed processes from
    /// triggering false on_endpoint_discovered notifications.
    pending_notifications: Arc<RwLock<Vec<EndpointInfo>>>,
    /// Buffered SEDP data from participants not yet in the DB.
    ///
    /// When SEDP arrives before SPDP (race condition common with RTI),
    /// the SedpData is buffered here. When handle_spdp registers the
    /// new participant, all matching entries are replayed through handle_sedp.
    /// Capped at 64 entries to prevent unbounded growth.
    pending_sedp: Arc<RwLock<Vec<SedpData>>>,
    /// v250: One-shot flag for probation purge.
    /// After the startup probation window (200ms), unconfirmed participants
    /// and their endpoints are purged from the registry. This flag ensures
    /// the purge runs exactly once.
    probation_purge_done: AtomicBool,
}

/// Cap on `pending_notifications` to bound memory. Sized to cover bursty
/// SEDP traffic during the 250 ms probation window even under adversarial
/// multicast (~1 KB/packet × ~1 Gb saturated ≈ 30 k packets / 250 ms; 16 k
/// is the practical knee where any further entries are surfaced directly
/// instead of dropped silently — SEDP is reliable and non-periodic, so a
/// drop would lose a legitimate endpoint permanently).
const PENDING_NOTIFICATIONS_CAP: usize = 16384;

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
            created_at: Instant::now(),
            pending_notifications: Arc::new(RwLock::new(Vec::new())),
            pending_sedp: Arc::new(RwLock::new(Vec::new())),
            probation_purge_done: AtomicBool::new(false),
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

    /// Fire the "QoS incompat" hook on every registered listener
    /// without gating against participant confirmation. Used by
    /// `handle_sedp` so that QoS mismatches surface immediately to
    /// the application even when the surfacing-gate is still holding
    /// the endpoint back for confirmation reasons.
    fn notify_endpoint_discovered_incompat_only(&self, endpoint: &EndpointInfo) {
        let listeners = recover_read(
            Arc::as_ref(&self.listeners),
            "DiscoveryFsm::notify_endpoint_discovered_incompat_only",
        );
        for listener in listeners.iter() {
            listener.on_endpoint_discovered_incompat_only(endpoint.clone());
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

        // Probation completion. See `maybe_complete_probation` for the
        // CAS-protected purge + drain. We trigger it from both
        // `handle_spdp` and `handle_sedp` so the boundary fires even
        // in workloads where SPDPs are sparse and only SEDP traffic
        // crosses the 250 ms mark.
        self.maybe_complete_probation();
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

        // SPDP dispose: lease_duration_ms == 0 means participant is leaving
        if data.lease_duration_ms == 0 {
            log::debug!(
                "[SPDP] Dispose received for participant {:?}",
                data.participant_guid
            );
            self.remove_participant(data.participant_guid);
            return true;
        }

        // Check if participant exists (read lock) and guard against poison.
        let exists = {
            let db = recover_read(Arc::as_ref(&self.db), "DiscoveryFsm::handle_spdp exists");
            db.contains_key(&data.participant_guid)
        };

        if exists {
            // Refresh existing participant (write lock).
            let mut db = recover_write(Arc::as_ref(&self.db), "DiscoveryFsm::handle_spdp refresh");
            let just_confirmed = if let Some(info) = db.get_mut(&data.participant_guid) {
                let was_unconfirmed = !info.is_confirmed_alive();
                info.refresh();
                was_unconfirmed && info.is_confirmed_alive()
            } else {
                false
            };
            drop(db); // Release lock before replaying

            // v249: When a participant transitions from unconfirmed to confirmed,
            // replay all pending SEDP endpoint notifications that were deferred.
            if just_confirmed {
                self.replay_pending_for_participant(data.participant_guid);
            }

            return true; // v182: Signal this was a refresh
        }

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

        // CRITICAL: Release the db write lock BEFORE replaying buffered SEDP.
        // replay_pending_sedp() -> handle_sedp() acquires a read lock on self.db
        // to check participant existence. Holding the write lock here would deadlock
        // on the same thread (std::sync::RwLock is not reentrant on Linux/pthreads).
        drop(db);

        // Replay any SEDP that arrived before this SPDP (race condition fix).
        self.replay_pending_sedp(&data.participant_guid);

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
        // (diagnostic removed)

        // Probation completion. We call this from both `handle_spdp`
        // and `handle_sedp` so the boundary fires even if no SPDP
        // arrives between probation start and the next SEDP. Without
        // this, entries deferred during probation could remain in
        // `pending_notifications` indefinitely under SPDP-sparse
        // workloads. The helper is one-shot via CAS, so concurrent
        // calls are safe.
        self.maybe_complete_probation();

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
            // Buffer SEDP from unknown participants (SPDP not yet processed).
            // This race is common with RTI which sends SEDP on unicast before
            // SPDP arrives on multicast. Replay when handle_spdp registers it.
            let mut pending = recover_write(
                Arc::as_ref(&self.pending_sedp),
                "DiscoveryFsm::handle_sedp pending_sedp",
            );
            if pending.len() < 64 {
                log::debug!(
                    "[SEDP] Buffering SEDP from unknown participant (prefix={:02x?}), will replay on SPDP",
                    &endpoint_prefix[..4]
                );
                pending.push(data);
            } else {
                log::warn!(
                    "[SEDP] Pending SEDP buffer full (64), dropping from prefix={:02x?}",
                    &endpoint_prefix[..4]
                );
            }
            return;
        }

        // Create endpoint info (auto-detects Writer vs Reader from GUID).
        // Uses locked dialect for vendor-specific QoS defaults when no PIDs present.
        let endpoint_unicast_locators = data.unicast_locators.clone();
        let dialect = self.get_locked_dialect();
        let endpoint = EndpointInfo::from_sedp(data, dialect);

        let topic_name = endpoint.topic_name.clone();
        let type_name = endpoint.type_name.clone();
        let type_object = endpoint.type_object.clone();
        let endpoint_kind = endpoint.kind;
        let endpoint_durability = endpoint.qos.durability;
        let endpoint_participant = endpoint.participant_guid;

        // Register reader's SEDP unicast locator for per-reader DATA routing.
        // Remote readers announce their user-data port in PID_UNICAST_LOCATOR,
        // which may differ from the participant's SPDP default_unicast (e.g. FastDDS
        // uses ephemeral ports like 33328, not the participant default port 7411).
        if endpoint_kind == EndpointKind::Reader {
            log::debug!(
                "[SEDP-READER] topic='{}' kind={:?} locators={:?} guid={}",
                topic_name,
                endpoint_kind,
                endpoint_unicast_locators,
                endpoint.endpoint_guid
            );
            if let Some(&locator) = select_best_locator(&endpoint_unicast_locators) {
                self.endpoint_registry
                    .register_reader_locator(endpoint.endpoint_guid, locator);
            } else {
                log::debug!(
                    "[SEDP-READER] NO locator for reader {} on topic '{}'",
                    endpoint.endpoint_guid,
                    topic_name
                );
            }
        }

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
                        &endpoint.qos,
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
                        &endpoint.qos,
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
                            Durability::TransientLocal
                                | Durability::Transient
                                | Durability::Persistent
                        )
                    {
                        // Use participant's registered endpoint, or fall back to the
                        // SEDP-announced unicast locator when SPDP hasn't been processed yet.
                        let replay_dest = self
                            .endpoint_registry
                            .get(&endpoint_participant)
                            .or_else(|| endpoint_unicast_locators.first().copied());
                        if let Some(dest) = replay_dest {
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
            // Phase 1 — IMMEDIATE QoS incompat fire (no gate).
            // QoS compatibility is a function of the local entry's QoS
            // and the remote endpoint's QoS as advertised in this SEDP
            // alone; it does not depend on the participant having been
            // confirmed via SPDP. Firing it here, before the
            // surfacing-gate, ensures the OMG harness (which often
            // checks `on_offered_incompatible_qos` /
            // `on_requested_incompatible_qos` within a 5 s window) sees
            // the mismatch immediately — instead of waiting up to the
            // steady-state SPDP interval (~3 s) for participant
            // confirmation. The `dispatch_incompat` path in
            // `MatchNotificationRegistry` dedups against
            // `incompat_remotes` so the eventual gate-released
            // `notify_endpoint_discovered` call below cannot fire it a
            // second time for the same `(entry, endpoint)` pair.
            self.notify_endpoint_discovered_incompat_only(&endpoint);

            // Phase 2 — MATCH surfacing, gated on participant confirmation.
            //
            // Surface the discovery to listeners ONLY when the owning
            // participant has been confirmed alive (spdp_count >= 2). Stale
            // SPDP/SEDP packets from previously-killed processes on the same
            // domain land in the new participant's discovery cache during
            // the first ~250 ms; if we surface them straight away, the
            // MatchNotifier sees them as legitimate remotes and runs the
            // full QoS compatibility check against zombie endpoints whose
            // owning participant will never reach `is_confirmed_alive()`.
            // That is the root of the OMG harness "passes in isolation,
            // fails after prior tests" symptom: the harness restarts
            // `shape_main` between tests within milliseconds, so zombies
            // from test N leak into test N+1's discovery view and fire
            // false `on_offered_incompatible_qos` events.
            //
            // The deferral path is already in place: `pending_notifications`
            // + `replay_pending_for_participant` (called on the SPDP
            // confirmation transition in handle_spdp). v249 removed the
            // enqueue side without removing the replay side, leaving the
            // mechanism dormant — this re-enables it.
            //
            // Local endpoints (no participant in `db`) bypass the gate:
            // they are co-owned by the running participant and are always
            // safe to surface.
            //
            // Stale SPDP/SEDP packets from previous-test processes arrive
            // within the first ~50 ms of this participant's lifetime; the
            // probation window (`probation_purge_done`, fired at 250 ms in
            // `handle_spdp`) is the cut-off after which any newly observed
            // participant must be live — stale bursts cannot land that
            // late. So once probation is over, skip the gate and surface
            // discoveries immediately, regardless of `spdp_count`. This
            // restores prompt `on_requested_incompatible_qos` /
            // `on_offered_incompatible_qos` firing for tests where the
            // remote pubs/subs start *after* this participant's burst
            // phase (most OMG harness scenarios) — without that fast path
            // a subscriber that joined after the publisher's aggressive
            // SPDP window had ended would need to wait up to 3 s (steady-
            // state SPDP interval) for confirmation, missing the harness's
            // incompat-detection window.
            //
            // Race-safety on the in-probation path: the naive "check db,
            // then push to pending" sequence has a window where
            // handle_spdp confirms the participant AND drains the pending
            // list BETWEEN our db read and our pending push — leaving the
            // endpoint stranded forever because `just_confirmed` only
            // fires once. We close the race with a double-check under the
            // pending write lock: optimistic notify if db says confirmed;
            // otherwise take the pending lock, re-read db (so any
            // concurrent SPDP transition has either run before us — in
            // which case we notify directly — or will run after us and
            // drain our push).
            // Trust raw wall-clock time only as a TRIGGER for
            // `maybe_complete_probation` (called at the top of
            // `handle_sedp`). The fast-path itself keys on
            // `probation_purge_done`, which is published only AFTER
            // purge + drain finish, so observing it `true` is a real
            // contract: db has no zombies, deferred entries have been
            // surfaced. Using raw elapsed time here would surface
            // endpoints while another thread is still mid-purge,
            // re-introducing the stale-endpoint bug.
            let probation_done = self.probation_purge_done.load(Ordering::Acquire);
            let optimistic_confirmed = is_local_endpoint
                || probation_done
                || self.is_participant_confirmed(endpoint_prefix);
            if optimistic_confirmed {
                self.notify_endpoint_discovered(&endpoint);
            } else {
                // Lock ordering note (no deadlock with `handle_spdp`):
                // `handle_spdp` takes its `db` write lock, releases it
                // (line ~451: `drop(db)`), and only then calls
                // `replay_pending_for_participant`, which acquires the
                // `pending_notifications` write lock without re-touching
                // `db`. Here we acquire `pending_notifications` first and
                // only re-acquire a *read* on `db` via
                // `is_participant_confirmed`. The two paths therefore
                // never hold both locks at the same time, so the
                // pending→db read here cannot cycle against a
                // db→pending writer.
                let mut pending = recover_write(
                    Arc::as_ref(&self.pending_notifications),
                    "DiscoveryFsm::handle_sedp pending_notifications",
                );
                // Re-check under the pending lock to close the
                // SPDP-confirms-between-our-checks race. If SPDP confirmed
                // the participant after our optimistic check (or the
                // probation window ended), its
                // `replay_pending_for_participant` is either pending on
                // this write lock (will drain after we release) or has
                // already run with an empty pending list (we must notify
                // directly because no future replay is scheduled).
                if self.probation_purge_done.load(Ordering::Acquire)
                    || self.is_participant_confirmed(endpoint_prefix)
                {
                    drop(pending);
                    self.notify_endpoint_discovered(&endpoint);
                } else if pending.len() < PENDING_NOTIFICATIONS_CAP {
                    log::debug!(
                        "[SEDP] Deferring notify_endpoint_discovered for unconfirmed participant (prefix={:02x?})",
                        &endpoint_prefix[..4]
                    );
                    pending.push(endpoint);
                } else {
                    // Cap is sized for adversarial scenarios where a
                    // hostile multicast source spams SEDP during the
                    // 250 ms probation window — at the typical 1 KB/SEDP
                    // and a saturated 1 Gb link, 250 ms = ~30 k packets,
                    // so PENDING_NOTIFICATIONS_CAP=16384 covers normal
                    // bursty discovery while still bounding memory.
                    // Overflow surfaces the endpoint directly rather than
                    // dropping it: SEDP is reliable and not periodic, so
                    // a silent drop here would lose a legitimate remote
                    // endpoint permanently from this participant's view.
                    // The trade-off is that the gate becomes best-effort
                    // for the few endpoints past the cap, which is
                    // acceptable because reaching the cap requires
                    // unusual traffic; an attacker who can saturate
                    // discovery already has bigger leverage at the
                    // transport layer.
                    log::warn!(
                        "[SEDP] pending_notifications cap ({}) reached for unconfirmed participant prefix={:02x?} — surfacing endpoint directly, gate degraded to best-effort for this entry",
                        PENDING_NOTIFICATIONS_CAP,
                        &endpoint_prefix[..4]
                    );
                    self.metrics
                        .sedp_pending_cap_surfaced
                        .fetch_add(1, Ordering::Relaxed);
                    drop(pending);
                    self.notify_endpoint_discovered(&endpoint);
                }
            }
        }
    }

    /// Look up whether a participant (identified by its 12-byte GUID prefix)
    /// has been confirmed alive (spdp_count >= 2). Returns false if the
    /// participant is absent from `db`, which is the safe default for the
    /// SEDP deferral path — the endpoint is held back until SPDP either
    /// registers + confirms the participant or the probation purge evicts it.
    fn is_participant_confirmed(&self, participant_prefix: &[u8]) -> bool {
        let db = recover_read(
            Arc::as_ref(&self.db),
            "DiscoveryFsm::is_participant_confirmed",
        );
        db.iter()
            .find(|(guid, _)| &guid.as_bytes()[..12] == participant_prefix)
            .map(|(_, info)| info.is_confirmed_alive())
            .unwrap_or(false)
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

    /// Check if a participant is known in the SPDP database.
    #[must_use]
    pub fn has_participant(&self, guid: &GUID) -> bool {
        let db = recover_read(Arc::as_ref(&self.db), "DiscoveryFsm::has_participant");
        db.contains_key(guid)
    }

    /// v250: Check if the participant owning this endpoint is confirmed alive.
    ///
    /// Looks up the participant by matching the first 12 bytes (GUID prefix)
    /// of the endpoint GUID against participant GUIDs in the database.
    /// Returns `false` if the participant is not found or not yet confirmed
    /// (spdp_count < 2), indicating it may be a stale entry from a killed process.
    #[must_use]
    pub fn is_endpoint_participant_confirmed(&self, endpoint_guid: &GUID) -> bool {
        let prefix = &endpoint_guid.as_bytes()[..12];
        let db = recover_read(
            Arc::as_ref(&self.db),
            "DiscoveryFsm::is_endpoint_participant_confirmed",
        );
        db.values()
            .any(|p| &p.guid.as_bytes()[..12] == prefix && p.is_confirmed_alive())
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
    /// Remove participants that are still in probation (spdp_count < 2).
    /// These are likely stale entries from killed processes whose SPDP was
    /// read from the OS socket buffer during startup.
    pub fn purge_unconfirmed_participants(&self) {
        let stale_guids: Vec<GUID> = {
            let db = recover_read(Arc::as_ref(&self.db), "DiscoveryFsm::purge_unconfirmed");
            db.values()
                .filter(|p| !p.is_confirmed_alive())
                .map(|p| p.guid)
                .collect()
        };
        for guid in &stale_guids {
            self.remove_participant(*guid);
        }
        if !stale_guids.is_empty() {
            log::debug!(
                "[SPDP] Purged {} unconfirmed (stale) participants",
                stale_guids.len()
            );
        }
    }

    /// Remove all discovered participants and their endpoints.
    ///
    /// Used at startup to clear stale SPDP/SEDP entries from previous
    /// processes that were using the same domain. Should be called BEFORE
    /// registering discovery listeners to avoid false match notifications.
    pub fn clear_all_participants(&self) {
        let guids: Vec<GUID> = {
            let db = recover_read(Arc::as_ref(&self.db), "DiscoveryFsm::clear_all");
            db.keys().copied().collect()
        };
        for guid in guids {
            self.remove_participant(guid);
        }
    }

    /// One-shot probation-completion trigger. After the 250 ms uptime
    /// mark, atomically claim the right to run the purge + drain via CAS
    /// so concurrent SPDP/SEDP handlers don't double-fire. Triggered from
    /// both `handle_spdp` and `handle_sedp` to guarantee the boundary
    /// fires under any traffic pattern (including SPDP-sparse workloads
    /// where only SEDP arrives after probation).
    fn maybe_complete_probation(&self) {
        if self.probation_purge_done.load(Ordering::Acquire) {
            return;
        }
        if (self.created_at.elapsed().as_millis() as u64) < 250 {
            return;
        }
        // Purge first (db write lock), then drain+publish. The drain
        // sets `probation_purge_done = true` under the pending write
        // lock; that interlock is what makes the
        // "deferral path re-checks the flag under pending lock"
        // protocol race-free against a thread that left the optimistic
        // check while the flag was still false (preemption between
        // the early `maybe_complete_probation` and the optimistic
        // check is real and observable). Side effects are idempotent
        // under concurrent re-execution (purge becomes a no-op once
        // the unconfirmed entries are gone; the drain function
        // observes the flag at its first action and returns
        // immediately if already true), so we do not need a CAS
        // around entry.
        self.purge_unconfirmed_participants();
        self.drain_pending_post_probation();
    }

    /// One-shot drain of `pending_notifications` at the probation-window
    /// boundary (FSM uptime ≥ 250 ms). Endpoints whose participant is
    /// still present in `db` are surfaced to listeners; endpoints whose
    /// participant was purged by `purge_unconfirmed_participants` (zombie
    /// from a prior process) are dropped. This catches entries that
    /// the per-participant `replay_pending_for_participant` could miss
    /// — notably the race where SPDP confirmation transitions BETWEEN
    /// our optimistic db read and our push to pending.
    fn drain_pending_post_probation(&self) {
        // At the probation boundary we apply the same post-250 ms
        // policy that `handle_sedp` uses for new SEDP: surface every
        // endpoint whose owning participant is present in `db`,
        // regardless of confirmation status. Entries for participants
        // purged as zombies are dropped. This is what makes the
        // 250 ms fast-path a real liveness guarantee — without it,
        // deferred entries for participants that only sent one SPDP
        // before probation would wait up to the steady-state SPDP
        // interval (~3 s) for a confirmation transition, which is
        // the exact latency the fast-path is meant to eliminate.
        //
        // The work happens under the pending write lock so that
        // `replay_pending_for_participant`, triggered by a
        // concurrent SPDP just-confirmed transition, cannot
        // interleave between our drain and our reads.
        let (to_notify, dropped) = {
            let mut pending = recover_write(
                Arc::as_ref(&self.pending_notifications),
                "DiscoveryFsm::drain_pending_post_probation",
            );
            // Idempotent re-entry guard: if some other thread already
            // completed probation while we were waiting for the lock,
            // there is nothing left to do.
            if self.probation_purge_done.load(Ordering::Acquire) {
                return;
            }
            let drained: Vec<EndpointInfo> = pending.drain(..).collect();
            let present_prefixes: std::collections::HashSet<[u8; 12]> = {
                let db = recover_read(
                    Arc::as_ref(&self.db),
                    "DiscoveryFsm::drain_pending_post_probation db",
                );
                db.keys()
                    .map(|guid| {
                        let bytes = guid.as_bytes();
                        let mut prefix = [0u8; 12];
                        prefix.copy_from_slice(&bytes[..12]);
                        prefix
                    })
                    .collect()
            };
            let mut to_notify: Vec<EndpointInfo> = Vec::new();
            let mut dropped = 0u32;
            for endpoint in drained {
                let mut prefix = [0u8; 12];
                prefix.copy_from_slice(&endpoint.endpoint_guid.as_bytes()[..12]);
                if present_prefixes.contains(&prefix) {
                    to_notify.push(endpoint);
                } else {
                    // Participant was purged as a zombie; safe to drop.
                    dropped += 1;
                }
            }
            // Publish completion UNDER the pending write lock. Any
            // deferral path that is currently waiting for this lock
            // (e.g. a thread that observed `flag == false` at its
            // optimistic check and is now blocked on the pending
            // write) will, on acquiring the lock next, re-read the
            // flag and see `true` — and skip the push, surfacing the
            // endpoint directly. This closes the window where a
            // thread preempted between its early
            // `maybe_complete_probation` (which returned because
            // elapsed < 250 at the time) and its later optimistic
            // check could otherwise push a now-stranded entry into
            // pending.
            self.probation_purge_done.store(true, Ordering::Release);
            (to_notify, dropped)
        };
        // Pending lock released. Notify outside the lock to avoid
        // holding it across listener callbacks (which may take their
        // own locks).
        for ep in &to_notify {
            self.notify_endpoint_discovered(ep);
        }
        if !to_notify.is_empty() || dropped > 0 {
            log::debug!(
                "[SEDP] Probation drain: surfaced {} endpoint(s) from present participants, dropped {} zombie(s)",
                to_notify.len(),
                dropped
            );
        }
    }

    /// v249: Replay deferred endpoint notifications for a participant that
    /// just transitioned to confirmed alive (spdp_count >= 2).
    fn replay_pending_for_participant(&self, participant_guid: GUID) {
        let participant_prefix = &participant_guid.as_bytes()[..12];
        let to_replay: Vec<EndpointInfo> = {
            let mut pending = recover_write(
                Arc::as_ref(&self.pending_notifications),
                "DiscoveryFsm::replay_pending",
            );
            let mut remaining = Vec::new();
            let mut matching = Vec::new();
            for ep in pending.drain(..) {
                if &ep.endpoint_guid.as_bytes()[..12] == participant_prefix {
                    matching.push(ep);
                } else {
                    remaining.push(ep);
                }
            }
            *pending = remaining;
            matching
        };

        if !to_replay.is_empty() {
            log::debug!(
                "[SEDP] v249: Replaying {} deferred endpoint(s) for confirmed participant {:?}",
                to_replay.len(),
                participant_guid
            );
            for endpoint in &to_replay {
                self.notify_endpoint_discovered(endpoint);
            }
        }
    }

    /// Replay buffered SEDP data that arrived before this participant's SPDP.
    /// Called from handle_spdp after inserting the new participant into the DB.
    fn replay_pending_sedp(&self, participant_guid: &GUID) {
        let participant_prefix = &participant_guid.as_bytes()[..12];
        let to_replay: Vec<SedpData> = {
            let mut pending = recover_write(
                Arc::as_ref(&self.pending_sedp),
                "DiscoveryFsm::replay_pending_sedp",
            );
            let mut remaining = Vec::new();
            let mut matching = Vec::new();
            for sd in pending.drain(..) {
                if &sd.endpoint_guid.as_bytes()[..12] == participant_prefix {
                    matching.push(sd);
                } else {
                    remaining.push(sd);
                }
            }
            *pending = remaining;
            matching
        };

        if !to_replay.is_empty() {
            log::debug!(
                "[SEDP] Replaying {} buffered SEDP(s) for newly registered participant {:?}",
                to_replay.len(),
                participant_guid
            );
            for sd in to_replay {
                self.handle_sedp(sd);
            }
        }
    }

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

            // v249: Clean up any pending notifications for this participant.
            {
                let prefix = &guid.as_bytes()[..12];
                let mut pending = recover_write(
                    Arc::as_ref(&self.pending_notifications),
                    "DiscoveryFsm::remove_participant pending",
                );
                pending.retain(|ep| &ep.endpoint_guid.as_bytes()[..12] != prefix);
            }

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
            has_explicit_reliability: false,
            has_explicit_ownership: false,
            has_ownership_strength: false,
            type_information: None,
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
            has_explicit_reliability: false,
            has_explicit_ownership: false,
            has_ownership_strength: false,
            type_information: None,
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
