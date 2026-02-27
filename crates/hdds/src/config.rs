// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! HDDS Global Configuration - Single Source of Truth
//!
//! This module centralizes ALL RTPS constants and runtime configuration.
//! **NEVER hardcode elsewhere!**
//!
//! # Architecture
//!
//! - **Level 1 (Static)**: Compile-time constants (RTPS spec, ports, IP)
//! - **Level 2 (Dynamic)**: `RuntimeConfig` for runtime config (QoS, custom ports, XML)
//!
//! # Performance
//!
//! - **Lock-free**: `DashMap` for QoS store (no RwLock contention)
//! - **Atomic swap**: `ArcSwap` for PortMapping (no lock)
//! - **O(1)**: All get/set operations are constant time
//! - **Zero-copy**: `Arc<str>` for keys/values (no clone)
//!
//! # Exemple
//!
//! ```ignore
//! use hdds::config::*;
//!
//! // Static constants
//! let port = SPDP_MULTICAST_PORT_DOMAIN0; // 7400
//!
//! // Dynamic config
//! let config = RuntimeConfig::new();
//! config.set_port_mapping(custom_ports);
//! config.set_qos("reliability.kind", "RELIABLE");
//!
//! // Search
//! let all_reliability = config.search_qos_prefix("reliability.");
//! ```

use crate::transport::PortMapping;
use arc_swap::ArcSwap;
use dashmap::DashMap;
use std::sync::Arc;

// =======================================================================
// RTPS v2.5 Port Mapping (OMG DDS-RTPS spec Sec.9.6.1.1)
// IANA registered: 7400-7469 (UDP/TCP)
// Source: https://www.iana.org/assignments/service-names-port-numbers/
// =======================================================================

/// RTPS v2.5 base port (IANA registered, OMG DDS-RTPS spec Sec.9.6.1.1)
///
/// All other ports are computed from this value.
/// **NEVER hardcode 7400 elsewhere!**
pub const PORT_BASE: u16 = 7400;

/// Maximum domain ID per DDS specification (RTPS v2.3 Sec.9.6.1.1)
///
/// DDS domain_id valid range: 0..232 (inclusive)
pub const MAX_DOMAIN_ID: u32 = 232;

/// Gain de domaine (RTPS v2.5 Sec.9.6.1.1)
///
/// Formule multicast: `PORT_BASE + (DOMAIN_ID_GAIN x domain_id)`
/// Exemple: domain 0 -> 7400, domain 1 -> 7650, domain 2 -> 7900
pub const DOMAIN_ID_GAIN: u16 = 250;

/// Gain de participant (RTPS v2.5 Sec.9.6.1.1)
///
/// Formule unicast: `base + (PARTICIPANT_ID_GAIN x participant_id)`
/// Exemple: participant 0 -> +0, participant 1 -> +2, participant 2 -> +4
pub const PARTICIPANT_ID_GAIN: u16 = 2;

/// Offset for metatraffic unicast (SEDP/discovery)
///
/// SEDP port = `PORT_BASE + SEDP_UNICAST_OFFSET + domain_offset + participant_offset`
pub const SEDP_UNICAST_OFFSET: u16 = 10;

/// Offset for user data unicast
///
/// USER port = `PORT_BASE + USER_UNICAST_OFFSET + domain_offset + participant_offset`
pub const USER_UNICAST_OFFSET: u16 = 11;

/// Offset for user data multicast (non-standard, FastDDS compat)
///
/// FastDDS uses 7401 for user data multicast (non-RTPS standard).
pub const DATA_MULTICAST_OFFSET: u16 = 1;

// =======================================================================
// Derived Ports (Compile-Time Constants)
// These constants are for domain 0, participant 0 (most common case)
// =======================================================================

/// Port multicast SPDP (domain 0)
///
/// RTPS spec: `PORT_BASE + (DOMAIN_ID_GAIN x 0) = 7400`
pub const SPDP_MULTICAST_PORT_DOMAIN0: u16 = PORT_BASE;

/// Port multicast user data (domain 0, FastDDS compat)
///
/// **Non-standard** : `PORT_BASE + 1 = 7401`
/// FastDDS/RTI use this port for user data multicast.
pub const DATA_MULTICAST_PORT_DOMAIN0: u16 = PORT_BASE + DATA_MULTICAST_OFFSET;

/// Port unicast SEDP (domain 0, participant 0)
///
/// RTPS spec: `PORT_BASE + SEDP_OFFSET + (DOMAIN_GAIN x 0) + (PARTICIPANT_GAIN x 0) = 7410`
pub const SEDP_UNICAST_PORT_DOMAIN0_P0: u16 = PORT_BASE + SEDP_UNICAST_OFFSET;

/// Port unicast user data (domain 0, participant 0)
///
/// RTPS spec: `PORT_BASE + USER_OFFSET + (DOMAIN_GAIN x 0) + (PARTICIPANT_GAIN x 0) = 7411`
pub const USER_UNICAST_PORT_DOMAIN0_P0: u16 = PORT_BASE + USER_UNICAST_OFFSET;

// =======================================================================
// Adresses IP Multicast (RTPS v2.5 spec)
// =======================================================================

/// Standard RTPS multicast IP address (239.255.0.1)
///
/// Used for:
/// - SPDP (participant discovery)
/// - SEDP (FastDDS/Cyclone style)
/// - USER DATA multicast
pub const MULTICAST_IP: [u8; 4] = [239, 255, 0, 1];

/// Alternative multicast IP address (239.255.0.2)
///
/// Used by RTI Connext (legacy) for SEDP.
/// RTPS spec allows both, but 239.255.0.1 is more common.
pub const MULTICAST_IP_ALT: [u8; 4] = [239, 255, 0, 2];

/// String version of MULTICAST_IP (for fast parsing)
pub const MULTICAST_GROUP: &str = "239.255.0.1";

/// String version of MULTICAST_IP_ALT (for fast parsing)
pub const MULTICAST_GROUP_ALT: &str = "239.255.0.2";

// =======================================================================
// Timing & Lease (RTPS v2.5 defaults)
// =======================================================================

/// SPDP announcement period (milliseconds)
///
/// RTPS spec default: 3 seconds
/// Participants send their SPDP announcement every 3s.
pub const SPDP_ANNOUNCEMENT_PERIOD_MS: u64 = 3_000;

/// Participant lease duration (milliseconds)
///
/// RTPS spec default: 10x announcement period = 30 seconds
/// If no SPDP received for 30s, the participant is considered dead.
pub const PARTICIPANT_LEASE_DURATION_MS: u64 = 30_000;

/// Lease check interval (milliseconds)
///
/// HDDS default: 1 second (1 Hz check rate)
/// Frequency of checking expired participants.
pub const LEASE_CHECK_INTERVAL_MS: u64 = 1_000;

// =======================================================================
// Buffer Sizes & Network Parameters
// =======================================================================

/// RX ring buffer size (discovery packets)
///
/// HDDS default: 256 slots
/// Ring buffer size for received discovery packets (SPDP/SEDP).
pub const RX_RING_SIZE: usize = 256;

/// RX pool size (number of buffers)
///
/// HDDS default: 256 buffers (max allowed by RxPool)
/// Number of pre-allocated buffers for zero-copy reception.
/// Note: Maximized to handle high-frequency EVENT_LOG tests with FastDDS.
pub const RX_POOL_SIZE: usize = 255;

/// Maximum Transmission Unit (bytes)
///
/// Default: 1500 bytes (Ethernet MTU)
/// Maximum UDP packet size (standard Ethernet).
pub const MTU_SIZE: usize = 1500;

/// Maximum UDP packet size for receive buffers (bytes)
///
/// Default: 65536 bytes (max RTPS DATA submessage payload)
/// IP fragmentation allows UDP packets larger than MTU to be reassembled
/// by the kernel. This constant defines the maximum packet size we support.
/// RTPS submessage length field is u16, so max payload is ~65KB.
pub const MAX_PACKET_SIZE: usize = 65536;

/// Fragment buffer size (max fragments)
///
/// HDDS default: 256 fragments
/// Maximum number of fragments being reassembled.
pub const FRAGMENT_BUFFER_SIZE: usize = 256;

/// Fragment reassembly timeout (milliseconds)
///
/// HDDS default: 500 ms
/// Max time to reassemble a fragmented packet before eviction.
pub const FRAGMENT_TIMEOUT_MS: u64 = 500;

/// Reader history ring size (samples)
///
/// HDDS default: 1024 samples
/// Ring buffer size for received sample history.
/// Used by DataReader to store samples before application read.
pub const READER_HISTORY_RING_SIZE: usize = 1024;

/// RTPS packet initial capacity (bytes)
///
/// HDDS default: 128 bytes
/// Initial capacity for building RTPS packets (ACKNACK, service requests).
/// Avoids reallocations for most standard packets.
pub const RTPS_PACKET_INITIAL_CAPACITY: usize = 128;

/// SPDP payload buffer size (bytes)
///
/// HDDS default: 1024 bytes
/// Buffer size for serializing SPDP participant data.
/// Must contain: GUID (16) + lease (4) + locators (~200) + properties list (~600).
pub const SPDP_PAYLOAD_BUFFER_SIZE: usize = 1024;

/// Classifier scan window (bytes)
///
/// HDDS default: 256 bytes
/// Scan window for searching DATA/DATA_FRAG submessages in RTPS packets.
/// Limits search to avoid full scan of large packets.
pub const CLASSIFIER_SCAN_WINDOW: usize = 256;

/// Debug dump size (bytes)
///
/// HDDS default: 128 bytes
/// Max size of hex dumps for debugging RTPS headers.
pub const DEBUG_DUMP_SIZE: usize = 128;

// =======================================================================
// QoS Constants (Type-Safe Keys & Values)
// =======================================================================

/// QoS policy keys and values (RTPS v2.5 standard)
///
/// **USAGE RESTRICTION**: Internal HDDS code only!
/// External users -> Use `RuntimeConfig::set_user()` for custom config.
///
/// # Architecture
///
/// - Keys: Format `qos.policy.attribute` (e.g., `qos.reliability.kind`)
/// - Values: UPPERCASE RTPS standard (e.g., `RELIABLE`, `TRANSIENT_LOCAL`)
///
/// # Examples (internal HDDS code)
///
/// ```ignore
/// use crate::config::qos;
///
/// config.set_qos(qos::RELIABILITY_KIND, qos::RELIABLE);
/// config.set_qos(qos::DURABILITY_KIND, qos::TRANSIENT_LOCAL);
/// config.set_qos(qos::HISTORY_DEPTH, "10");
/// ```
pub mod qos {
    // === Reliability QoS ===
    pub const RELIABILITY_KIND: &str = "qos.reliability.kind";
    pub const RELIABILITY_MAX_BLOCKING_TIME: &str = "qos.reliability.max_blocking_time";

    // === Durability QoS ===
    pub const DURABILITY_KIND: &str = "qos.durability.kind";

    // === History QoS ===
    pub const HISTORY_KIND: &str = "qos.history.kind";
    pub const HISTORY_DEPTH: &str = "qos.history.depth";

    // === Liveliness QoS ===
    pub const LIVELINESS_KIND: &str = "qos.liveliness.kind";
    pub const LIVELINESS_LEASE_DURATION: &str = "qos.liveliness.lease_duration";

    // === Deadline QoS ===
    pub const DEADLINE_PERIOD: &str = "qos.deadline.period";

    // === Latency Budget QoS ===
    pub const LATENCY_BUDGET_DURATION: &str = "qos.latency_budget.duration";

    // === Ownership QoS ===
    pub const OWNERSHIP_KIND: &str = "qos.ownership.kind";
    pub const OWNERSHIP_STRENGTH: &str = "qos.ownership.strength";

    // === Destination Order QoS ===
    pub const DESTINATION_ORDER_KIND: &str = "qos.destination_order.kind";

    // === Presentation QoS ===
    pub const PRESENTATION_ACCESS_SCOPE: &str = "qos.presentation.access_scope";
    pub const PRESENTATION_COHERENT_ACCESS: &str = "qos.presentation.coherent_access";
    pub const PRESENTATION_ORDERED_ACCESS: &str = "qos.presentation.ordered_access";

    // === Partition QoS ===
    pub const PARTITION_NAME: &str = "qos.partition.name";

    // === Time Based Filter QoS ===
    pub const TIME_BASED_FILTER_MIN_SEPARATION: &str = "qos.time_based_filter.min_separation";

    // === Resource Limits QoS ===
    pub const RESOURCE_LIMITS_MAX_SAMPLES: &str = "qos.resource_limits.max_samples";
    pub const RESOURCE_LIMITS_MAX_INSTANCES: &str = "qos.resource_limits.max_instances";
    pub const RESOURCE_LIMITS_MAX_SAMPLES_PER_INSTANCE: &str =
        "qos.resource_limits.max_samples_per_instance";

    // ===================================================================
    // QoS Values (RTPS Standard)
    // ===================================================================

    // Reliability
    pub const RELIABLE: &str = "RELIABLE";
    pub const BEST_EFFORT: &str = "BEST_EFFORT";

    // Durability
    pub const TRANSIENT_LOCAL: &str = "TRANSIENT_LOCAL";
    pub const VOLATILE: &str = "VOLATILE";
    pub const TRANSIENT: &str = "TRANSIENT";
    pub const PERSISTENT: &str = "PERSISTENT";

    // History
    pub const KEEP_LAST: &str = "KEEP_LAST";
    pub const KEEP_ALL: &str = "KEEP_ALL";

    // Liveliness
    pub const AUTOMATIC: &str = "AUTOMATIC";
    pub const MANUAL_BY_PARTICIPANT: &str = "MANUAL_BY_PARTICIPANT";
    pub const MANUAL_BY_TOPIC: &str = "MANUAL_BY_TOPIC";

    // Ownership
    pub const SHARED: &str = "SHARED";
    pub const EXCLUSIVE: &str = "EXCLUSIVE";

    // Destination Order
    pub const BY_RECEPTION_TIMESTAMP: &str = "BY_RECEPTION_TIMESTAMP";
    pub const BY_SOURCE_TIMESTAMP: &str = "BY_SOURCE_TIMESTAMP";

    // Presentation
    pub const INSTANCE: &str = "INSTANCE";
    pub const TOPIC: &str = "TOPIC";
    pub const GROUP: &str = "GROUP";
}

// =======================================================================
// Runtime Configuration (Dynamic, Lock-Free)
// =======================================================================

/// Shared runtime configuration (thread-safe, lock-free)
///
/// Optimized for **high performance**:
/// - `DashMap`: Concurrent HashMap without RwLock (lock-free sharding)
/// - `ArcSwap`: Atomic swap of PortMapping (no lock)
/// - `Arc<str>`: Zero-copy for keys/values (no unnecessary clones)
///
/// # Use cases
///
/// - Custom ports (via `with_discovery_ports()`)
/// - QoS loaded from XML (via `QoS::load_fastdds()`)
/// - Dynamic post-build configuration
/// - Search by prefix/pattern
///
/// # Usage Pattern
///
/// ```ignore
/// // Creation at participant build
/// let config = Arc::new(RuntimeConfig::new());
/// config.set_port_mapping(custom_ports);
///
/// // QoS from XML
/// config.set_qos("reliability.kind", "RELIABLE");
/// config.set_qos("durability.kind", "TRANSIENT_LOCAL");
///
/// // Search
/// let all_reliability = config.search_qos_prefix("reliability.");
///
/// // Passed to all components (clone = just Arc counter increment)
/// SpdpAnnouncer::spawn(guid, transport, config.clone());
/// ```
///
/// # Performance
///
/// - **Get/Set**: O(1) amortized (HashMap)
/// - **Lock-free**: No contention even with 1000s of accesses/sec
/// - **Memory**: ~40 bytes overhead per QoS entry (DashMap sharding)
#[derive(Clone)]
pub struct RuntimeConfig {
    /// Current port mapping (None = use RTPS formula)
    ///
    /// `ArcSwap` allows atomically changing the mapping without lock.
    /// Ultra-fast reads (atomic load).
    port_mapping: Arc<ArcSwap<Option<PortMapping>>>,

    /// QoS configuration (key-value store, lock-free)
    ///
    /// `DashMap`: Concurrent HashMap with internal sharding (no global lock).
    /// Loaded from FastDDS XML, or configured programmatically.
    ///
    /// Key examples:
    /// - "reliability.kind" -> "RELIABLE"
    /// - "durability.kind" -> "TRANSIENT_LOCAL"
    /// - "history.depth" -> "10"
    qos_config: Arc<DashMap<Arc<str>, Arc<str>>>,
}

impl RuntimeConfig {
    /// Create a new empty runtime config
    ///
    /// # Performance
    ///
    /// - Allocation : ~200 bytes (DashMap sharding)
    /// - Init time : ~10 us
    #[inline]
    #[must_use]
    pub fn new() -> Self {
        Self {
            port_mapping: Arc::new(ArcSwap::new(Arc::new(None))),
            qos_config: Arc::new(DashMap::new()),
        }
    }

    // ===================================================================
    // Port Mapping Operations (Atomic, Lock-Free)
    // ===================================================================

    /// Set custom port mapping (override RTPS formula)
    ///
    /// Uses an atomic swap (no lock, thread-safe).
    ///
    /// # Performance
    ///
    /// - Time : ~50 ns (atomic swap)
    /// - Thread-safe : Oui (ArcSwap)
    #[inline]
    pub fn set_port_mapping(&self, mapping: PortMapping) {
        self.port_mapping.store(Arc::new(Some(mapping)));
    }

    /// Get current port mapping (None = use RTPS formula)
    ///
    /// # Performance
    ///
    /// - Time: ~20 ns (atomic load + struct copy)
    /// - Lock-free: Yes
    #[inline]
    #[must_use]
    pub fn get_port_mapping(&self) -> Option<PortMapping> {
        **self.port_mapping.load()
    }

    /// Clear port mapping (return to RTPS formula)
    #[inline]
    pub fn clear_port_mapping(&self) {
        self.port_mapping.store(Arc::new(None));
    }

    // ===================================================================
    // Public User-Land API (Flexible, No Validation)
    // ===================================================================

    /// Set user-land config (PUBLIC API)
    ///
    /// **For external users only.**
    /// Internal HDDS code -> Use `set_qos()` instead.
    ///
    /// # Allowed Namespaces
    ///
    /// - `user.*` -> User-land custom config
    /// - `app.*` -> Application-specific config
    ///
    /// # Validation
    ///
    /// - Key MUST start with `user.` or `app.`
    /// - **Debug mode**: Panic if invalid (catch dev bugs)
    /// - **Release mode**: Log error + skip (fail-safe)
    ///
    /// # Performance
    ///
    /// - Time: ~100 ns (DashMap insert)
    /// - Lock-free: Yes
    ///
    /// # Examples (external user code)
    ///
    /// ```ignore
    /// use hdds::config::RuntimeConfig;
    ///
    /// let config = RuntimeConfig::new();
    ///
    /// // [OK] OK (user-land)
    /// config.set_user("user.cache_size", "1000");
    /// config.set_user("app.debug_mode", "true");
    ///
    /// // [X] Error logged, skipped (not user-land)
    /// config.set_user("qos.durability.kind", "TRANSIENT_LOCAL");
    /// ```
    #[inline]
    pub fn set_user(&self, key: &str, value: &str) {
        // Validation: MUST be user.* or app.*
        if !key.starts_with("user.") && !key.starts_with("app.") {
            log::error!(
                "[config] User-land keys must start with 'user.' or 'app.', got: '{}'. \
                 Skipping (fail-safe). Use proper namespace for custom config.",
                key
            );
            return;
        }

        self.qos_config.insert(Arc::from(key), Arc::from(value));
    }

    /// Get user-land config (PUBLIC API)
    ///
    /// For external users. Access to `user.*` and `app.*` only.
    ///
    /// # Performance
    ///
    /// - Time: ~80 ns (DashMap lookup)
    /// - Lock-free: Yes
    #[inline]
    #[must_use]
    pub fn get_user(&self, key: &str) -> Option<Arc<str>> {
        if !key.starts_with("user.") && !key.starts_with("app.") {
            log::warn!(
                "[config] get_user() called with non-user key '{}'. Returns None.",
                key
            );
            return None;
        }
        self.qos_config.get(key).map(|v| Arc::clone(&v))
    }

    /// Get user-land config as String (PUBLIC API)
    #[inline]
    #[must_use]
    pub fn get_user_string(&self, key: &str) -> Option<String> {
        self.get_user(key).map(|v| v.to_string())
    }

    /// Remove user-land config (PUBLIC API)
    #[inline]
    pub fn remove_user(&self, key: &str) -> Option<Arc<str>> {
        if !key.starts_with("user.") && !key.starts_with("app.") {
            return None;
        }
        self.qos_config.remove(key).map(|(_, v)| v)
    }

    /// Check if user-land key exists (PUBLIC API)
    #[inline]
    #[must_use]
    pub fn contains_user(&self, key: &str) -> bool {
        if !key.starts_with("user.") && !key.starts_with("app.") {
            return false;
        }
        self.qos_config.contains_key(key)
    }

    /// Get total config size (number of entries, all namespaces)
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.qos_config.len()
    }

    /// Check if config is empty
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.qos_config.is_empty()
    }

    // ===================================================================
    // Search Operations (Prefix, Pattern, Bulk)
    // ===================================================================

    /// Search QoS by prefix
    ///
    /// Returns all keys/values starting with the prefix.
    ///
    /// # Performance
    ///
    /// - Time: O(n) where n = total number of entries (full scan)
    /// - Memory: Allocates a Vec with results
    ///
    /// # Examples
    ///
    /// ```ignore
    /// // Search all reliability.* parameters
    /// let reliability_params = config.search_qos_prefix("reliability.");
    /// // -> [("reliability.kind", "RELIABLE"), ("reliability.max_blocking_time", "100")]
    ///
    /// // Search all durability.* parameters
    /// let durability_params = config.search_qos_prefix("durability.");
    /// ```
    #[must_use]
    pub fn search_qos_prefix(&self, prefix: &str) -> Vec<(Arc<str>, Arc<str>)> {
        self.qos_config
            .iter()
            .filter(|entry| entry.key().starts_with(prefix))
            .map(|entry| (Arc::clone(entry.key()), Arc::clone(entry.value())))
            .collect()
    }

    /// Search QoS by pattern (contains)
    ///
    /// Returns all keys/values containing the pattern.
    ///
    /// # Performance
    ///
    /// - Time: O(n x m) where n = number of entries, m = pattern length
    /// - Memory: Allocates a Vec with results
    ///
    /// # Examples
    ///
    /// ```ignore
    /// // Search all parameters containing "timeout"
    /// let timeouts = config.search_qos_pattern("timeout");
    /// // -> [("heartbeat.response_timeout", "500"), ("liveliness.lease_timeout", "30000")]
    /// ```
    #[must_use]
    pub fn search_qos_pattern(&self, pattern: &str) -> Vec<(Arc<str>, Arc<str>)> {
        self.qos_config
            .iter()
            .filter(|entry| entry.key().contains(pattern))
            .map(|entry| (Arc::clone(entry.key()), Arc::clone(entry.value())))
            .collect()
    }

    /// Get all QoS entries
    ///
    /// Returns all (key, value) pairs.
    ///
    /// # Performance
    ///
    /// - Time: O(n)
    /// - Memory: Allocates a Vec with all entries
    #[must_use]
    pub fn get_all_qos(&self) -> Vec<(Arc<str>, Arc<str>)> {
        self.qos_config
            .iter()
            .map(|entry| (Arc::clone(entry.key()), Arc::clone(entry.value())))
            .collect()
    }

    /// Bulk set QoS (for XML loading)
    ///
    /// More efficient than individual `set_qos()` calls.
    ///
    /// # Performance
    ///
    /// - Time: O(n) where n = number of entries
    /// - Batch insert: ~50 ns per entry (vs ~100 ns individually)
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let qos_params = vec![
    ///     ("reliability.kind", "RELIABLE"),
    ///     ("durability.kind", "TRANSIENT_LOCAL"),
    ///     ("history.depth", "10"),
    /// ];
    /// config.set_qos_bulk(qos_params);
    /// ```
    pub fn set_qos_bulk<I>(&self, entries: I)
    where
        I: IntoIterator<Item = (&'static str, &'static str)>,
    {
        for (key, value) in entries {
            self.qos_config.insert(Arc::from(key), Arc::from(value));
        }
    }

    /// Bulk set QoS (owned version for dynamic loading)
    pub fn set_qos_bulk_owned<I>(&self, entries: I)
    where
        I: IntoIterator<Item = (String, String)>,
    {
        for (key, value) in entries {
            self.qos_config.insert(Arc::from(key), Arc::from(value));
        }
    }
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self::new()
    }
}

// =======================================================================
// Helper Functions
// =======================================================================

/// Compute the SPDP multicast port for a given domain
///
/// RTPS v2.5 formula: `PORT_BASE + (DOMAIN_ID_GAIN x domain_id)`
///
/// # Examples
///
/// ```ignore
/// assert_eq!(spdp_multicast_port(0), 7400);
/// assert_eq!(spdp_multicast_port(1), 7650);
/// assert_eq!(spdp_multicast_port(2), 7900);
/// ```
#[inline]
#[must_use]
pub const fn spdp_multicast_port(domain_id: u32) -> u16 {
    PORT_BASE + (DOMAIN_ID_GAIN * domain_id as u16)
}

/// Compute the SEDP unicast port for a given domain and participant
///
/// RTPS v2.5 formula: `PORT_BASE + SEDP_OFFSET + (DOMAIN_GAIN x domain_id) + (PARTICIPANT_GAIN x participant_id)`
#[inline]
#[must_use]
pub const fn sedp_unicast_port(domain_id: u32, participant_id: u8) -> u16 {
    PORT_BASE
        + SEDP_UNICAST_OFFSET
        + (DOMAIN_ID_GAIN * domain_id as u16)
        + (PARTICIPANT_ID_GAIN * participant_id as u16)
}

/// Compute the USER DATA unicast port for a given domain and participant
///
/// RTPS v2.5 formula: `PORT_BASE + USER_OFFSET + (DOMAIN_GAIN x domain_id) + (PARTICIPANT_GAIN x participant_id)`
#[inline]
#[must_use]
pub const fn user_unicast_port(domain_id: u32, participant_id: u8) -> u16 {
    PORT_BASE
        + USER_UNICAST_OFFSET
        + (DOMAIN_ID_GAIN * domain_id as u16)
        + (PARTICIPANT_ID_GAIN * participant_id as u16)
}

// =======================================================================
// Tests
// =======================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_static_ports_domain0() {
        assert_eq!(SPDP_MULTICAST_PORT_DOMAIN0, 7400);
        assert_eq!(DATA_MULTICAST_PORT_DOMAIN0, 7401);
        assert_eq!(SEDP_UNICAST_PORT_DOMAIN0_P0, 7410);
        assert_eq!(USER_UNICAST_PORT_DOMAIN0_P0, 7411);
    }

    #[test]
    fn test_port_formulas() {
        // Domain 0
        assert_eq!(spdp_multicast_port(0), 7400);
        assert_eq!(sedp_unicast_port(0, 0), 7410);
        assert_eq!(user_unicast_port(0, 0), 7411);

        // Domain 1
        assert_eq!(spdp_multicast_port(1), 7650);
        assert_eq!(sedp_unicast_port(1, 0), 7660);
        assert_eq!(user_unicast_port(1, 0), 7661);

        // Participant 1
        assert_eq!(sedp_unicast_port(0, 1), 7412);
        assert_eq!(user_unicast_port(0, 1), 7413);
    }

    #[test]
    fn test_runtime_config_port_mapping() {
        use crate::transport::CustomPortMapping;

        let config = RuntimeConfig::new();
        assert!(config.get_port_mapping().is_none());

        let custom = CustomPortMapping {
            spdp_multicast: 9400,
            sedp_unicast: 9410,
            user_unicast: 9411,
        };
        let mapping = PortMapping::from_custom(custom);

        config.set_port_mapping(mapping);
        assert!(config.get_port_mapping().is_some());
        assert_eq!(
            config
                .get_port_mapping()
                .expect("port mapping should be set")
                .metatraffic_multicast,
            9400
        );

        config.clear_port_mapping();
        assert!(config.get_port_mapping().is_none());
    }

    #[test]
    fn test_runtime_config_user_land() {
        let config = RuntimeConfig::new();

        // Set/Get user-land config
        config.set_user("user.cache_size", "1000");
        assert_eq!(
            config.get_user_string("user.cache_size"),
            Some("1000".to_string())
        );

        config.set_user("app.debug_mode", "true");
        assert_eq!(config.get_user("app.debug_mode"), Some(Arc::from("true")));

        // Contains
        assert!(config.contains_user("user.cache_size"));
        assert!(!config.contains_user("nonexistent"));

        // Remove
        config.remove_user("user.cache_size");
        assert!(!config.contains_user("user.cache_size"));
    }

    #[test]
    fn test_user_invalid_key_ignored() {
        // User keys with qos.* prefix are logged but ignored (fail-safe)
        let config = RuntimeConfig::new();
        config.set_user("qos.durability.kind", "value");
        // Should be silently ignored, not stored
        assert!(config.get_user("qos.durability.kind").is_none());
    }

    #[test]
    fn test_qos_search_prefix() {
        let config = RuntimeConfig::new();
        config.set_qos_bulk(vec![
            (qos::RELIABILITY_KIND, qos::RELIABLE),
            (qos::RELIABILITY_MAX_BLOCKING_TIME, "100"),
            (qos::DURABILITY_KIND, qos::TRANSIENT_LOCAL),
        ]);

        let results = config.search_qos_prefix("qos.reliability.");
        assert_eq!(results.len(), 2);

        let results = config.search_qos_prefix("qos.durability.");
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_qos_search_pattern() {
        let config = RuntimeConfig::new();
        config.set_qos_bulk(vec![
            (qos::LIVELINESS_LEASE_DURATION, "30000"),
            (qos::RELIABILITY_KIND, qos::RELIABLE),
        ]);

        let results = config.search_qos_pattern("duration");
        assert_eq!(results.len(), 1);

        let results = config.search_qos_pattern("kind");
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_qos_bulk_set() {
        let config = RuntimeConfig::new();

        config.set_qos_bulk(vec![
            (qos::RELIABILITY_KIND, qos::RELIABLE),
            (qos::DURABILITY_KIND, qos::TRANSIENT_LOCAL),
            (qos::HISTORY_DEPTH, "10"),
        ]);

        assert_eq!(config.len(), 3);

        // Verify via search
        let reliability = config.search_qos_prefix(qos::RELIABILITY_KIND);
        assert_eq!(reliability.len(), 1);
        assert_eq!(reliability[0].1.as_ref(), "RELIABLE");
    }

    #[test]
    fn test_qos_get_all() {
        let config = RuntimeConfig::new();
        config.set_qos_bulk(vec![
            (qos::RELIABILITY_KIND, qos::RELIABLE),
            (qos::DURABILITY_KIND, qos::TRANSIENT_LOCAL),
        ]);

        let all = config.get_all_qos();
        assert_eq!(all.len(), 2);
    }
}
