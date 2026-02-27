// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! TSN configuration types.

use std::path::PathBuf;
use std::time::Duration;

/// TSN configuration for a Writer/Topic.
#[derive(Clone, Debug, Default)]
pub struct TsnConfig {
    /// Master switch - TSN features enabled.
    pub enabled: bool,

    /// Behavior when capabilities are missing.
    pub enforcement: TsnEnforcement,

    // === Tagging (Phase 1) ===
    /// VLAN Priority Code Point (0-7).
    /// Maps to SO_PRIORITY on the socket.
    pub pcp: Option<u8>,

    /// IP DSCP value (0-63) for L3 QoS.
    pub dscp: Option<u8>,

    /// mqprio traffic class index.
    pub traffic_class: Option<u8>,

    // === Scheduled TX (Phase 2) ===
    /// Timed send policy.
    pub tx_time: TxTimePolicy,

    /// Reference clock for txtime.
    pub clock_id: TsnClockId,

    /// Delta added to now() to compute txtime (ns).
    /// Default: 500us.
    pub lead_time_ns: u64,

    /// If true: drop if txtime is exceeded (vs best-effort).
    pub strict_deadline: bool,

    // === Future (slots reserves) ===
    /// 802.1Qat stream reservation ID.
    pub srp_stream_id: Option<u64>,

    /// 802.1CB Frame Replication config.
    pub frer: Option<FrerConfig>,
}

impl TsnConfig {
    /// Create a new TSN config with sensible defaults.
    pub fn new() -> Self {
        Self {
            enabled: false,
            enforcement: TsnEnforcement::BestEffort,
            pcp: None,
            dscp: None,
            traffic_class: None,
            tx_time: TxTimePolicy::Disabled,
            clock_id: TsnClockId::Tai,
            lead_time_ns: 500_000, // 500 us
            strict_deadline: false,
            srp_stream_id: None,
            frer: None,
        }
    }

    /// Enable TSN with the given PCP (VLAN priority).
    pub fn with_priority(mut self, pcp: u8) -> Self {
        self.enabled = true;
        self.pcp = Some(pcp.min(7));
        self
    }

    /// Enable strict enforcement (fail if TSN not available).
    pub fn strict(mut self) -> Self {
        self.enforcement = TsnEnforcement::Strict;
        self
    }

    /// Enable txtime with the given policy.
    pub fn with_txtime(mut self, policy: TxTimePolicy) -> Self {
        self.tx_time = policy;
        self
    }

    /// Set the clock ID for txtime.
    pub fn with_clock(mut self, clock: TsnClockId) -> Self {
        self.clock_id = clock;
        self
    }

    /// Set the lead time for auto-calculated txtime.
    pub fn with_lead_time(mut self, lead_time: Duration) -> Self {
        self.lead_time_ns = lead_time.as_nanos() as u64;
        self
    }

    /// Preset for high-priority traffic (P0 = commands, safety).
    pub fn high_priority() -> Self {
        Self::new().with_priority(6)
    }

    /// Preset for normal traffic (P1).
    pub fn normal_priority() -> Self {
        Self::new().with_priority(4)
    }

    /// Preset for low-priority/telemetry traffic (P2).
    pub fn low_priority() -> Self {
        Self::new().with_priority(2)
    }

    /// Check if priority tagging is configured.
    pub fn has_priority(&self) -> bool {
        self.enabled && self.pcp.is_some()
    }

    /// Check if txtime is configured.
    pub fn has_txtime(&self) -> bool {
        self.enabled && self.tx_time != TxTimePolicy::Disabled
    }

    /// Get the effective SO_PRIORITY value.
    pub fn so_priority(&self) -> Option<u8> {
        if self.enabled {
            self.pcp
        } else {
            None
        }
    }
}

/// Policy when TSN capabilities are absent.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TsnEnforcement {
    /// Degrade silently (counter + debug log).
    #[default]
    BestEffort,

    /// Error if prerequisites are missing.
    Strict,
}

/// Timed send policy (SO_TXTIME).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TxTimePolicy {
    /// Classic sendto(), no txtime.
    #[default]
    Disabled,

    /// SO_TXTIME if available, otherwise sendto().
    Opportunistic,

    /// SO_TXTIME required, error otherwise.
    Mandatory,
}

/// Reference clock for txtime.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub enum TsnClockId {
    /// CLOCK_MONOTONIC (not synced, dev/test).
    Monotonic,

    /// CLOCK_TAI (PTP-synced, recommended for prod).
    #[default]
    Tai,

    /// CLOCK_REALTIME (avoid if possible - leap seconds).
    Realtime,

    /// PHC direct (e.g., "/dev/ptp0").
    Phc(PathBuf),
}

impl TsnClockId {
    /// Convert to the Linux clockid_t value.
    #[cfg(target_os = "linux")]
    pub fn to_clockid(&self) -> Option<libc::clockid_t> {
        match self {
            Self::Monotonic => Some(libc::CLOCK_MONOTONIC),
            Self::Tai => Some(11), // CLOCK_TAI not in libc stable
            Self::Realtime => Some(libc::CLOCK_REALTIME),
            Self::Phc(_) => None, // Requires fd conversion
        }
    }
}

/// Explicit txtime specification.
#[derive(Clone, Copy, Debug)]
pub enum TsnTxtime {
    /// Absolute value in the socket's clock_id (ns).
    AbsoluteNs(u64),

    /// Delta from now() (converted to absolute).
    After(Duration),
}

impl TsnTxtime {
    /// Create from absolute nanoseconds.
    pub fn absolute(ns: u64) -> Self {
        Self::AbsoluteNs(ns)
    }

    /// Create from a duration after now.
    pub fn after(d: Duration) -> Self {
        Self::After(d)
    }

    /// Create from microseconds after now.
    pub fn after_us(us: u64) -> Self {
        Self::After(Duration::from_micros(us))
    }

    /// Create from milliseconds after now.
    pub fn after_ms(ms: u64) -> Self {
        Self::After(Duration::from_millis(ms))
    }
}

/// 802.1CB Frame Replication and Elimination (future).
#[derive(Clone, Debug, Default)]
pub struct FrerConfig {
    /// Sequence number space.
    pub seq_space: u8,
    /// Redundancy paths.
    pub paths: u8,
}

/// Socket profile for TX socket pool keying.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct SocketProfile {
    /// SO_PRIORITY value.
    pub so_priority: Option<u8>,
    /// Traffic class for mqprio.
    pub traffic_class: Option<u8>,
    /// Clock ID for txtime (simplified for hashing).
    pub clock_id_tag: u8,
    /// TxTime policy.
    pub txtime_policy: TxTimePolicy,
}

impl SocketProfile {
    /// Create from TsnConfig.
    pub fn from_config(cfg: &TsnConfig) -> Self {
        let clock_id_tag = match &cfg.clock_id {
            TsnClockId::Monotonic => 0,
            TsnClockId::Tai => 1,
            TsnClockId::Realtime => 2,
            TsnClockId::Phc(_) => 3,
        };

        Self {
            so_priority: cfg.so_priority(),
            traffic_class: cfg.traffic_class,
            clock_id_tag,
            txtime_policy: cfg.tx_time,
        }
    }

    /// Default profile (no TSN features).
    pub fn default_profile() -> Self {
        Self {
            so_priority: None,
            traffic_class: None,
            clock_id_tag: 1, // TAI
            txtime_policy: TxTimePolicy::Disabled,
        }
    }
}

impl std::hash::Hash for TxTimePolicy {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        (*self as u8).hash(state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tsn_config_default() {
        let cfg = TsnConfig::default();
        assert!(!cfg.enabled);
        assert_eq!(cfg.enforcement, TsnEnforcement::BestEffort);
        assert_eq!(cfg.tx_time, TxTimePolicy::Disabled);
        assert!(cfg.pcp.is_none());
        assert!(!cfg.has_priority());
        assert!(!cfg.has_txtime());
    }

    #[test]
    fn test_tsn_config_with_priority() {
        let cfg = TsnConfig::new().with_priority(6);
        assert!(cfg.enabled);
        assert_eq!(cfg.pcp, Some(6));
        assert!(cfg.has_priority());
        assert_eq!(cfg.so_priority(), Some(6));
    }

    #[test]
    fn test_tsn_config_priority_clamped() {
        let cfg = TsnConfig::new().with_priority(10); // Above max
        assert_eq!(cfg.pcp, Some(7)); // Clamped to max
    }

    #[test]
    fn test_tsn_config_strict() {
        let cfg = TsnConfig::new().with_priority(6).strict();
        assert_eq!(cfg.enforcement, TsnEnforcement::Strict);
    }

    #[test]
    fn test_tsn_config_with_txtime() {
        let cfg = TsnConfig::new()
            .with_priority(6)
            .with_txtime(TxTimePolicy::Mandatory);
        assert!(cfg.has_txtime());
        assert_eq!(cfg.tx_time, TxTimePolicy::Mandatory);
    }

    #[test]
    fn test_tsn_config_presets() {
        let high = TsnConfig::high_priority();
        assert_eq!(high.pcp, Some(6));

        let normal = TsnConfig::normal_priority();
        assert_eq!(normal.pcp, Some(4));

        let low = TsnConfig::low_priority();
        assert_eq!(low.pcp, Some(2));
    }

    #[test]
    fn test_tsn_clock_id_default() {
        let clock = TsnClockId::default();
        assert_eq!(clock, TsnClockId::Tai);
    }

    #[test]
    fn test_tsn_txtime_variants() {
        let abs = TsnTxtime::absolute(1_000_000_000);
        match abs {
            TsnTxtime::AbsoluteNs(ns) => assert_eq!(ns, 1_000_000_000),
            _ => panic!("Expected AbsoluteNs"),
        }

        let after = TsnTxtime::after_us(500);
        match after {
            TsnTxtime::After(d) => assert_eq!(d, Duration::from_micros(500)),
            _ => panic!("Expected After"),
        }
    }

    #[test]
    fn test_socket_profile_from_config() {
        let cfg = TsnConfig::new().with_priority(6);
        let profile = SocketProfile::from_config(&cfg);
        assert_eq!(profile.so_priority, Some(6));
        assert_eq!(profile.clock_id_tag, 1); // TAI
        assert_eq!(profile.txtime_policy, TxTimePolicy::Disabled);
    }

    #[test]
    fn test_socket_profile_hash_eq() {
        use std::collections::HashMap;

        let profile1 = SocketProfile {
            so_priority: Some(6),
            traffic_class: None,
            clock_id_tag: 1,
            txtime_policy: TxTimePolicy::Disabled,
        };

        let profile2 = SocketProfile {
            so_priority: Some(6),
            traffic_class: None,
            clock_id_tag: 1,
            txtime_policy: TxTimePolicy::Disabled,
        };

        let profile3 = SocketProfile {
            so_priority: Some(4),
            traffic_class: None,
            clock_id_tag: 1,
            txtime_policy: TxTimePolicy::Disabled,
        };

        assert_eq!(profile1, profile2);
        assert_ne!(profile1, profile3);

        let mut map: HashMap<SocketProfile, u32> = HashMap::new();
        map.insert(profile1.clone(), 1);
        assert_eq!(map.get(&profile2), Some(&1));
        assert_eq!(map.get(&profile3), None);
    }

    #[test]
    fn test_txtime_policy_hash() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        fn hash_policy(p: TxTimePolicy) -> u64 {
            let mut hasher = DefaultHasher::new();
            p.hash(&mut hasher);
            hasher.finish()
        }

        let h1 = hash_policy(TxTimePolicy::Disabled);
        let h2 = hash_policy(TxTimePolicy::Opportunistic);
        let h3 = hash_policy(TxTimePolicy::Mandatory);

        // Different policies should have different hashes
        assert_ne!(h1, h2);
        assert_ne!(h2, h3);
        assert_ne!(h1, h3);
    }

    #[test]
    fn test_frer_config_default() {
        let frer = FrerConfig::default();
        assert_eq!(frer.seq_space, 0);
        assert_eq!(frer.paths, 0);
    }

    #[test]
    fn test_tsn_config_lead_time() {
        let cfg = TsnConfig::new().with_lead_time(Duration::from_millis(1));
        assert_eq!(cfg.lead_time_ns, 1_000_000);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_clock_id_to_clockid() {
        assert_eq!(
            TsnClockId::Monotonic.to_clockid(),
            Some(libc::CLOCK_MONOTONIC)
        );
        assert_eq!(TsnClockId::Tai.to_clockid(), Some(11));
        assert_eq!(
            TsnClockId::Realtime.to_clockid(),
            Some(libc::CLOCK_REALTIME)
        );
        assert!(TsnClockId::Phc("/dev/ptp0".into()).to_clockid().is_none());
    }
}
