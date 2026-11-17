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
        // Map [1..100] -> [1..7], i.e. `tp * 7 / 100` clamped to at least 1.
        // Written as the bands that formula produces, so the PCP is computed
        // in its own width with nothing narrowed: `tp * 7` needs more than a
        // byte, and the result has to end up in one. Anything above 100 is
        // treated as 100, which is where the `u8::try_from` failure lands too.
        // `pcp_bands_match_formula` in auto_test.rs checks the two agree.
        let tp = u8::try_from(tp).unwrap_or(u8::MAX).min(100);
        return match tp {
            100 => 7,
            86..=99 => 6,
            72..=85 => 5,
            58..=71 => 4,
            43..=57 => 3,
            29..=42 => 2,
            _ => 1,
        };
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
#[path = "auto_test.rs"]
mod tests;
