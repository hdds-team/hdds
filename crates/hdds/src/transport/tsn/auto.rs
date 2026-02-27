// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! QoS-to-TSN auto-mapping.
//!
//! Automatically derives TSN configuration from DDS QoS policies,
//! removing the need for manual TSN tuning in most cases.
//!
//! # Mapping Rules
//!
//! | QoS Policy | TSN Parameter | Rule |
//! |---|---|---|
//! | TransportPriority | PCP (0-7) | Scaled and clamped to max_pcp |
//! | Deadline < 1ms | DSCP=46 (EF), PCP 6-7 | Ultra-low latency path |
//! | Deadline < 10ms | DSCP=34 (AF41), PCP 4-5 | Medium-latency path |
//! | Reliable + small deadline | SO_TXTIME enabled | Deterministic TX |
//! | BestEffort + no deadline | PCP 0, no SO_TXTIME | Zero TSN overhead |
//!
//! # Usage
//!
//! ```rust,ignore
//! use hdds::transport::tsn::auto::qos_to_tsn;
//! use hdds::transport::tsn::TsnCapabilities;
//!
//! let qos = QoS::reliable();
//! let caps = TsnCapabilities::default();
//! let tsn_config = qos_to_tsn(&qos, &caps);
//! ```

use std::time::Duration;

use super::config::{TsnConfig, TsnEnforcement, TxTimePolicy};
use super::probe::{SupportLevel, TsnCapabilities};

// DSCP well-known values
const DSCP_BEST_EFFORT: u8 = 0;
const DSCP_AF41: u8 = 34;
const DSCP_EF: u8 = 46;

/// Participant-level TSN mode.
///
/// Controls how TSN is applied across all writers in a participant.
#[derive(Clone, Debug, Default)]
pub enum TsnMode {
    /// TSN disabled -- all writers use plain UDP.
    #[default]
    Off,

    /// Manual TSN configuration applied to all writers.
    Manual(TsnConfig),

    /// Auto-derive TSN config per writer from its QoS policies.
    /// Requires capabilities to be probed at participant creation.
    Auto,
}

/// Writer-level TSN override.
///
/// Allows a single writer to deviate from the participant's TSN mode.
#[derive(Clone, Debug, Default)]
pub struct WriterTsnOverride {
    /// If Some, this config replaces whatever the participant provides.
    pub config: Option<TsnConfig>,

    /// If true, force TSN off for this writer regardless of participant mode.
    pub force_off: bool,
}

impl WriterTsnOverride {
    /// No override -- use participant TSN config.
    pub fn none() -> Self {
        Self {
            config: None,
            force_off: false,
        }
    }

    /// Override with explicit config.
    pub fn with_config(config: TsnConfig) -> Self {
        Self {
            config: Some(config),
            force_off: false,
        }
    }

    /// Force TSN off for this writer.
    pub fn off() -> Self {
        Self {
            config: None,
            force_off: true,
        }
    }

    /// Resolve the effective TSN config for a writer.
    ///
    /// Priority: force_off > writer override > participant config.
    pub fn resolve(&self, participant_config: &TsnConfig) -> TsnConfig {
        if self.force_off {
            return TsnConfig::default(); // disabled
        }
        if let Some(ref cfg) = self.config {
            return cfg.clone();
        }
        participant_config.clone()
    }
}

/// Auto-derive TSN configuration from DDS QoS policies.
///
/// This is the core mapping function. It inspects the QoS fields
/// (transport_priority, deadline, reliability) and produces a `TsnConfig`
/// that is constrained by the actual hardware `capabilities`.
///
/// # Arguments
///
/// * `qos` - The DDS QoS profile for the writer/topic.
/// * `capabilities` - Runtime-probed TSN capabilities of the NIC/kernel.
///
/// # Returns
///
/// A `TsnConfig` ready to be applied to a TX socket.
pub fn qos_to_tsn(qos: &QosHints, capabilities: &TsnCapabilities) -> TsnConfig {
    // If the system has zero TSN support, return a disabled config immediately.
    if !capabilities.is_tsn_ready()
        && capabilities.so_txtime == SupportLevel::Unsupported
        && !capabilities.mqprio_configured
    {
        return TsnConfig::default();
    }

    // BestEffort + infinite deadline + normal priority => no TSN overhead
    if qos.is_best_effort() && qos.deadline_is_infinite() && qos.transport_priority_value() <= 0 {
        return TsnConfig::default();
    }

    let mut cfg = TsnConfig::new();
    cfg.enabled = true;
    cfg.enforcement = TsnEnforcement::BestEffort; // degrade gracefully

    // --- PCP mapping ---
    let raw_pcp = derive_pcp(qos);
    let max_pcp = max_pcp_from_caps(capabilities);
    cfg.pcp = Some(raw_pcp.min(max_pcp));

    // --- DSCP mapping based on deadline ---
    cfg.dscp = Some(derive_dscp(qos));

    // --- Traffic class (if mqprio available) ---
    if capabilities.mqprio_configured {
        cfg.traffic_class = Some(derive_traffic_class(qos));
    }

    // --- SO_TXTIME mapping ---
    let wants_txtime = should_enable_txtime(qos);
    if wants_txtime && capabilities.so_txtime.is_available() {
        if qos.is_reliable() {
            // Reliable + tight deadline: mandatory txtime
            cfg.tx_time = TxTimePolicy::Mandatory;
        } else {
            // BestEffort but deadline-sensitive: opportunistic
            cfg.tx_time = TxTimePolicy::Opportunistic;
        }

        // Strict deadline only if ETF qdisc is present
        cfg.strict_deadline = capabilities.etf_configured && qos.deadline_ms() < 1;

        // Lead time proportional to deadline (but at least 100us)
        cfg.lead_time_ns = derive_lead_time_ns(qos);
    }

    cfg
}

/// Lightweight QoS hints extracted from a full DDS QoS for TSN mapping.
///
/// This avoids coupling the TSN module directly to the full DDS QoS struct,
/// making testing easier and the dependency graph cleaner.
#[derive(Clone, Debug)]
pub struct QosHints {
    /// TransportPriority.value from the DDS QoS.
    pub transport_priority: i32,

    /// Deadline period. Duration::MAX means infinite.
    pub deadline: Duration,

    /// True if Reliability::Reliable.
    pub reliable: bool,
}

impl Default for QosHints {
    fn default() -> Self {
        Self {
            transport_priority: 0,
            deadline: Duration::from_secs(u64::MAX),
            reliable: false,
        }
    }
}

impl QosHints {
    /// Create hints for best-effort traffic (no special requirements).
    pub fn best_effort() -> Self {
        Self::default()
    }

    /// Create hints for reliable traffic with no deadline constraint.
    pub fn reliable_no_deadline() -> Self {
        Self {
            reliable: true,
            ..Self::default()
        }
    }

    /// Create hints with a specific deadline.
    pub fn with_deadline(mut self, deadline: Duration) -> Self {
        self.deadline = deadline;
        self
    }

    /// Create hints with a specific transport priority.
    pub fn with_priority(mut self, priority: i32) -> Self {
        self.transport_priority = priority;
        self
    }

    /// Create hints for reliable traffic.
    pub fn with_reliable(mut self) -> Self {
        self.reliable = true;
        self
    }

    /// Check if BestEffort (not reliable).
    pub fn is_best_effort(&self) -> bool {
        !self.reliable
    }

    /// Check if Reliable.
    pub fn is_reliable(&self) -> bool {
        self.reliable
    }

    /// Check if deadline is effectively infinite.
    pub fn deadline_is_infinite(&self) -> bool {
        // Anything over 1 day is "infinite" for TSN purposes
        self.deadline >= Duration::from_secs(86_400)
    }

    /// Get deadline in milliseconds (capped at u64::MAX).
    pub fn deadline_ms(&self) -> u64 {
        self.deadline.as_millis().min(u64::MAX as u128) as u64
    }

    /// Get the raw transport priority value.
    pub fn transport_priority_value(&self) -> i32 {
        self.transport_priority
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Derive PCP (0-7) from QoS hints.
///
/// Uses transport_priority as primary signal, with deadline as secondary.
fn derive_pcp(qos: &QosHints) -> u8 {
    let tp = qos.transport_priority;

    // If transport_priority is explicitly set (positive), scale to 0-7
    if tp > 0 {
        // Map [1..100] -> [1..7]
        let scaled = ((tp as u64).min(100) * 7 / 100) as u8;
        return scaled.clamp(1, 7);
    }

    // Negative priority -> PCP 0 (background)
    if tp < 0 {
        return 0;
    }

    // tp == 0: use deadline as secondary signal
    let deadline_ms = qos.deadline_ms();
    if deadline_ms < 1 {
        7 // sub-ms deadline -> highest PCP
    } else if deadline_ms < 10 {
        6 // < 10ms -> high PCP
    } else if deadline_ms < 100 {
        4 // < 100ms -> medium PCP
    } else if qos.deadline_is_infinite() {
        0 // infinite -> best effort
    } else {
        2 // > 100ms finite deadline -> low PCP
    }
}

/// Derive DSCP from QoS hints.
fn derive_dscp(qos: &QosHints) -> u8 {
    let deadline_ms = qos.deadline_ms();

    if deadline_ms < 1 {
        DSCP_EF // Expedited Forwarding for sub-ms
    } else if deadline_ms < 10 {
        DSCP_AF41 // Assured Forwarding class 4 for < 10ms
    } else {
        DSCP_BEST_EFFORT
    }
}

/// Derive traffic class from QoS hints.
fn derive_traffic_class(qos: &QosHints) -> u8 {
    let deadline_ms = qos.deadline_ms();

    if deadline_ms < 1 || qos.transport_priority > 50 {
        0 // TC0 = highest priority
    } else if deadline_ms < 10 || qos.transport_priority > 20 {
        1 // TC1 = medium
    } else {
        2 // TC2 = best effort
    }
}

/// Determine if SO_TXTIME should be enabled.
fn should_enable_txtime(qos: &QosHints) -> bool {
    // txtime makes sense only for tight-deadline or reliable traffic
    if qos.deadline_ms() < 10 {
        return true;
    }
    if qos.is_reliable() && !qos.deadline_is_infinite() {
        return true;
    }
    false
}

/// Derive lead time in nanoseconds.
///
/// Proportional to deadline, clamped between 100us and 5ms.
fn derive_lead_time_ns(qos: &QosHints) -> u64 {
    let deadline_ns = qos.deadline.as_nanos() as u64;

    // Lead time = 10% of deadline, clamped
    let lead = deadline_ns / 10;
    let min_lead = 100_000; // 100 us
    let max_lead = 5_000_000; // 5 ms

    lead.max(min_lead).min(max_lead)
}

/// Get the effective max PCP from capabilities.
///
/// If mqprio is not configured, we conservatively limit to PCP 6
/// (PCP 7 often requires CAP_NET_ADMIN).
fn max_pcp_from_caps(capabilities: &TsnCapabilities) -> u8 {
    if capabilities.mqprio_configured {
        7
    } else {
        6
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Helper: build capabilities with various features
    // -----------------------------------------------------------------------

    fn caps_none() -> TsnCapabilities {
        TsnCapabilities::default() // everything unsupported
    }

    fn caps_basic() -> TsnCapabilities {
        TsnCapabilities {
            so_txtime: SupportLevel::Supported,
            ..Default::default()
        }
    }

    fn caps_full() -> TsnCapabilities {
        TsnCapabilities {
            so_txtime: SupportLevel::SupportedWithOffload,
            etf_configured: true,
            taprio_configured: true,
            mqprio_configured: true,
            cbs_configured: true,
            hw_timestamping: SupportLevel::SupportedWithOffload,
            ..Default::default()
        }
    }

    // -----------------------------------------------------------------------
    // 1. BestEffort + no hints -> no TSN
    // -----------------------------------------------------------------------
    #[test]
    fn test_best_effort_no_hints_no_tsn() {
        let qos = QosHints::best_effort();
        let cfg = qos_to_tsn(&qos, &caps_full());

        assert!(!cfg.enabled);
        assert_eq!(cfg.pcp, None);
        assert_eq!(cfg.tx_time, TxTimePolicy::Disabled);
    }

    // -----------------------------------------------------------------------
    // 2. No capabilities -> always disabled
    // -----------------------------------------------------------------------
    #[test]
    fn test_no_capabilities_returns_disabled() {
        let qos = QosHints::default()
            .with_deadline(Duration::from_micros(500))
            .with_priority(80);

        let cfg = qos_to_tsn(&qos, &caps_none());

        // No TSN hardware at all -> disabled
        assert!(!cfg.enabled);
    }

    // -----------------------------------------------------------------------
    // 3. High priority + small deadline -> high PCP + SO_TXTIME
    // -----------------------------------------------------------------------
    #[test]
    fn test_high_priority_small_deadline() {
        let qos = QosHints::default()
            .with_deadline(Duration::from_micros(500))
            .with_priority(80)
            .with_reliable();

        let cfg = qos_to_tsn(&qos, &caps_full());

        assert!(cfg.enabled);
        // priority 80 -> PCP ~5-6, clamped to 7 max
        assert!(cfg.pcp.unwrap() >= 5);
        assert_eq!(cfg.dscp, Some(DSCP_EF)); // sub-ms -> EF
        assert_eq!(cfg.tx_time, TxTimePolicy::Mandatory); // reliable
        assert!(cfg.strict_deadline); // ETF present + sub-ms
    }

    // -----------------------------------------------------------------------
    // 4. TransportPriority clamped to max_pcp
    // -----------------------------------------------------------------------
    #[test]
    fn test_transport_priority_clamped_to_max_pcp() {
        let qos = QosHints::default()
            .with_priority(100) // would map to PCP 7
            .with_deadline(Duration::from_millis(5));

        // Without mqprio, max_pcp = 6
        let caps = TsnCapabilities {
            so_txtime: SupportLevel::Supported,
            mqprio_configured: false,
            ..Default::default()
        };

        let cfg = qos_to_tsn(&qos, &caps);

        assert!(cfg.enabled);
        assert!(
            cfg.pcp.unwrap() <= 6,
            "PCP should be clamped to 6 without mqprio"
        );
    }

    // -----------------------------------------------------------------------
    // 5. Capability fallback: no SO_TXTIME -> skip txtime
    // -----------------------------------------------------------------------
    #[test]
    fn test_no_so_txtime_skips_txtime() {
        let qos = QosHints::default()
            .with_deadline(Duration::from_micros(500))
            .with_reliable();

        // so_txtime unsupported but mqprio available
        let caps = TsnCapabilities {
            so_txtime: SupportLevel::Unsupported,
            mqprio_configured: true,
            ..Default::default()
        };

        let cfg = qos_to_tsn(&qos, &caps);

        assert!(cfg.enabled);
        assert_eq!(cfg.tx_time, TxTimePolicy::Disabled);
        // But PCP should still be set
        assert!(cfg.pcp.is_some());
    }

    // -----------------------------------------------------------------------
    // 6. Default QoS mapping (no hints at all)
    // -----------------------------------------------------------------------
    #[test]
    fn test_default_qos_mapping() {
        let qos = QosHints::default();
        let cfg = qos_to_tsn(&qos, &caps_full());

        // Default = BestEffort, infinite deadline, priority 0
        // -> should produce disabled config (no TSN overhead)
        assert!(!cfg.enabled);
    }

    // -----------------------------------------------------------------------
    // 7. Medium deadline (1-10ms) -> AF41 DSCP + medium PCP
    // -----------------------------------------------------------------------
    #[test]
    fn test_medium_deadline_mapping() {
        let qos = QosHints::default().with_deadline(Duration::from_millis(5));

        let cfg = qos_to_tsn(&qos, &caps_full());

        assert!(cfg.enabled);
        assert_eq!(cfg.dscp, Some(DSCP_AF41));
        // PCP should be in the 4-6 range for 5ms deadline
        let pcp = cfg.pcp.unwrap();
        assert!(
            (4..=7).contains(&pcp),
            "PCP {} should be 4-7 for 5ms deadline",
            pcp
        );
    }

    // -----------------------------------------------------------------------
    // 8. Reliable + finite deadline -> txtime enabled
    // -----------------------------------------------------------------------
    #[test]
    fn test_reliable_finite_deadline_enables_txtime() {
        let qos = QosHints::default()
            .with_deadline(Duration::from_millis(50))
            .with_reliable();

        let cfg = qos_to_tsn(&qos, &caps_basic());

        assert!(cfg.enabled);
        assert_ne!(cfg.tx_time, TxTimePolicy::Disabled);
    }

    // -----------------------------------------------------------------------
    // 9. Negative transport priority -> PCP 0
    // -----------------------------------------------------------------------
    #[test]
    fn test_negative_priority_maps_to_pcp_zero() {
        let qos = QosHints::default()
            .with_priority(-50)
            .with_deadline(Duration::from_millis(5)); // needs deadline to enable

        let cfg = qos_to_tsn(&qos, &caps_full());

        assert!(cfg.enabled);
        assert_eq!(cfg.pcp, Some(0));
    }

    // -----------------------------------------------------------------------
    // 10. Sub-ms deadline without ETF -> no strict_deadline
    // -----------------------------------------------------------------------
    #[test]
    fn test_sub_ms_without_etf_no_strict() {
        let qos = QosHints::default()
            .with_deadline(Duration::from_micros(500))
            .with_reliable();

        // so_txtime supported but no ETF qdisc
        let caps = TsnCapabilities {
            so_txtime: SupportLevel::Supported,
            etf_configured: false,
            ..Default::default()
        };

        let cfg = qos_to_tsn(&qos, &caps);

        assert!(cfg.enabled);
        assert!(!cfg.strict_deadline, "strict_deadline requires ETF qdisc");
    }

    // -----------------------------------------------------------------------
    // 11. Lead time proportional to deadline
    // -----------------------------------------------------------------------
    #[test]
    fn test_lead_time_proportional() {
        let qos = QosHints::default()
            .with_deadline(Duration::from_millis(5))
            .with_reliable();

        let cfg = qos_to_tsn(&qos, &caps_basic());

        // 10% of 5ms = 500us = 500_000 ns
        assert_eq!(cfg.lead_time_ns, 500_000);
    }

    // -----------------------------------------------------------------------
    // 12. Lead time clamped to minimum (100us)
    // -----------------------------------------------------------------------
    #[test]
    fn test_lead_time_minimum_clamp() {
        let qos = QosHints::default()
            .with_deadline(Duration::from_micros(100)) // 10% = 10us < 100us min
            .with_reliable();

        let cfg = qos_to_tsn(&qos, &caps_basic());

        assert!(
            cfg.lead_time_ns >= 100_000,
            "Lead time should be at least 100us"
        );
    }

    // -----------------------------------------------------------------------
    // 13. Lead time clamped to maximum (5ms)
    // -----------------------------------------------------------------------
    #[test]
    fn test_lead_time_maximum_clamp() {
        let qos = QosHints::default()
            .with_deadline(Duration::from_millis(500)) // 10% = 50ms > 5ms max
            .with_reliable();

        let cfg = qos_to_tsn(&qos, &caps_basic());

        assert!(
            cfg.lead_time_ns <= 5_000_000,
            "Lead time should be at most 5ms"
        );
    }

    // -----------------------------------------------------------------------
    // 14. TsnMode variants
    // -----------------------------------------------------------------------
    #[test]
    fn test_tsn_mode_default_is_off() {
        let mode = TsnMode::default();
        assert!(matches!(mode, TsnMode::Off));
    }

    #[test]
    fn test_tsn_mode_manual() {
        let cfg = TsnConfig::high_priority();
        let mode = TsnMode::Manual(cfg.clone());
        if let TsnMode::Manual(c) = mode {
            assert_eq!(c.pcp, Some(6));
        } else {
            panic!("Expected TsnMode::Manual");
        }
    }

    #[test]
    fn test_tsn_mode_auto() {
        let mode = TsnMode::Auto;
        assert!(matches!(mode, TsnMode::Auto));
    }

    // -----------------------------------------------------------------------
    // 15. WriterTsnOverride
    // -----------------------------------------------------------------------
    #[test]
    fn test_writer_override_none() {
        let over = WriterTsnOverride::none();
        let participant_cfg = TsnConfig::high_priority();

        let resolved = over.resolve(&participant_cfg);
        assert_eq!(resolved.pcp, Some(6));
        assert!(resolved.enabled);
    }

    #[test]
    fn test_writer_override_with_config() {
        let over = WriterTsnOverride::with_config(TsnConfig::low_priority());
        let participant_cfg = TsnConfig::high_priority();

        let resolved = over.resolve(&participant_cfg);
        assert_eq!(resolved.pcp, Some(2));
    }

    #[test]
    fn test_writer_override_force_off() {
        let over = WriterTsnOverride::off();
        let participant_cfg = TsnConfig::high_priority();

        let resolved = over.resolve(&participant_cfg);
        assert!(!resolved.enabled);
        assert_eq!(resolved.pcp, None);
    }

    // -----------------------------------------------------------------------
    // 16. QosHints builder
    // -----------------------------------------------------------------------
    #[test]
    fn test_qos_hints_default() {
        let h = QosHints::default();
        assert_eq!(h.transport_priority, 0);
        assert!(h.deadline_is_infinite());
        assert!(h.is_best_effort());
        assert!(!h.is_reliable());
    }

    #[test]
    fn test_qos_hints_reliable_no_deadline() {
        let h = QosHints::reliable_no_deadline();
        assert!(h.is_reliable());
        assert!(h.deadline_is_infinite());
    }

    #[test]
    fn test_qos_hints_deadline_ms() {
        let h = QosHints::default().with_deadline(Duration::from_millis(5));
        assert_eq!(h.deadline_ms(), 5);
        assert!(!h.deadline_is_infinite());
    }

    // -----------------------------------------------------------------------
    // 17. derive_pcp edge cases
    // -----------------------------------------------------------------------
    #[test]
    fn test_derive_pcp_priority_1_maps_to_at_least_1() {
        let qos = QosHints::default().with_priority(1);
        let pcp = derive_pcp(&qos);
        assert!(pcp >= 1, "Priority 1 should map to PCP >= 1, got {}", pcp);
    }

    #[test]
    fn test_derive_pcp_priority_100_maps_to_7() {
        let qos = QosHints::default().with_priority(100);
        let pcp = derive_pcp(&qos);
        assert_eq!(pcp, 7);
    }

    #[test]
    fn test_derive_pcp_priority_50_maps_to_3_or_4() {
        let qos = QosHints::default().with_priority(50);
        let pcp = derive_pcp(&qos);
        assert!((3..=4).contains(&pcp), "Priority 50 -> PCP {}", pcp);
    }

    // -----------------------------------------------------------------------
    // 18. derive_dscp edge cases
    // -----------------------------------------------------------------------
    #[test]
    fn test_derive_dscp_infinite_deadline() {
        let qos = QosHints::default(); // infinite deadline
        assert_eq!(derive_dscp(&qos), DSCP_BEST_EFFORT);
    }

    #[test]
    fn test_derive_dscp_sub_ms() {
        let qos = QosHints::default().with_deadline(Duration::from_micros(500));
        assert_eq!(derive_dscp(&qos), DSCP_EF);
    }

    #[test]
    fn test_derive_dscp_5ms() {
        let qos = QosHints::default().with_deadline(Duration::from_millis(5));
        assert_eq!(derive_dscp(&qos), DSCP_AF41);
    }

    #[test]
    fn test_derive_dscp_100ms() {
        let qos = QosHints::default().with_deadline(Duration::from_millis(100));
        assert_eq!(derive_dscp(&qos), DSCP_BEST_EFFORT);
    }

    // -----------------------------------------------------------------------
    // 19. BestEffort + tight deadline -> txtime opportunistic (not mandatory)
    // -----------------------------------------------------------------------
    #[test]
    fn test_best_effort_tight_deadline_opportunistic_txtime() {
        let qos = QosHints::default().with_deadline(Duration::from_micros(500));

        let cfg = qos_to_tsn(&qos, &caps_basic());

        assert!(cfg.enabled);
        assert_eq!(cfg.tx_time, TxTimePolicy::Opportunistic);
    }

    // -----------------------------------------------------------------------
    // 20. Reliable + infinite deadline + high priority -> TSN but no txtime
    // -----------------------------------------------------------------------
    #[test]
    fn test_reliable_infinite_deadline_high_prio() {
        let qos = QosHints::default().with_priority(80).with_reliable();

        let cfg = qos_to_tsn(&qos, &caps_full());

        assert!(cfg.enabled);
        // High priority -> PCP set
        assert!(cfg.pcp.unwrap() >= 5);
        // Infinite deadline + reliable -> txtime NOT enabled
        // (should_enable_txtime requires deadline < 10ms or reliable+finite)
        assert_eq!(cfg.tx_time, TxTimePolicy::Disabled);
    }

    // -----------------------------------------------------------------------
    // 21. Full integration: realistic DDS writer scenario
    // -----------------------------------------------------------------------
    #[test]
    fn test_realistic_control_loop_writer() {
        // A 1kHz control loop writer: reliable, 1ms deadline, high priority
        let qos = QosHints::default()
            .with_deadline(Duration::from_millis(1))
            .with_priority(70)
            .with_reliable();

        let cfg = qos_to_tsn(&qos, &caps_full());

        assert!(cfg.enabled);
        assert!(cfg.pcp.unwrap() >= 4);
        assert_eq!(cfg.dscp, Some(DSCP_AF41)); // 1ms is not < 1ms
        assert_eq!(cfg.tx_time, TxTimePolicy::Mandatory);
        assert!(cfg.traffic_class.is_some());
    }

    // -----------------------------------------------------------------------
    // 22. mqprio absent -> no traffic_class set
    // -----------------------------------------------------------------------
    #[test]
    fn test_no_mqprio_no_traffic_class() {
        let qos = QosHints::default().with_deadline(Duration::from_millis(5));

        let caps = TsnCapabilities {
            so_txtime: SupportLevel::Supported,
            mqprio_configured: false,
            ..Default::default()
        };

        let cfg = qos_to_tsn(&qos, &caps);

        assert!(cfg.traffic_class.is_none());
    }
}
