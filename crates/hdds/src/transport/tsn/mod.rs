// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Time-Sensitive Networking (TSN) support for HDDS.
//!
//! This module provides TSN (IEEE 802.1) support for deterministic Ethernet communication:
//!
//! - **Priority tagging**: SO_PRIORITY -> traffic classes (mqprio) + VLAN PCP
//! - **Scheduled TX**: SO_TXTIME + SCM_TXTIME for "send-at-time" (LaunchTime)
//! - **Capability detection**: Runtime probe of TSN features (ETF, TAPRIO, HW timestamping)
//!
//! # Architecture
//!
//! ```text
//! +---------------------------------------------------------+
//! |                     Application                          |
//! |  write() / write_at(txtime) / write_with(WriteOptions)  |
//! +---------------------+-----------------------------------+
//!                       |
//! +---------------------v-----------------------------------+
//! |                  DataWriter                              |
//! |  TsnConfig (from TopicQos or WriterQos override)        |
//! +---------------------+-----------------------------------+
//!                       |
//! +---------------------v-----------------------------------+
//! |                 UdpTransport                             |
//! |  TX Socket Pool (keyed by SocketProfile)                |
//! |  TsnBackend (LinuxTsnBackend / NullTsnBackend)          |
//! +---------------------------------------------------------+
//! ```
//!
//! # Usage
//!
//! ```rust,ignore
//! use hdds::transport::tsn::{TsnConfig, TsnEnforcement, TxTimePolicy};
//!
//! // Enable TSN with priority tagging
//! let config = TsnConfig {
//!     enabled: true,
//!     pcp: Some(6),  // High priority
//!     enforcement: TsnEnforcement::BestEffort,
//!     ..Default::default()
//! };
//!
//! // Probe TSN capabilities
//! use hdds::transport::tsn::TsnProbe;
//! let caps = TsnProbe::probe("eth0").unwrap();
//! println!("SO_TXTIME supported: {:?}", caps.so_txtime);
//! ```
//!
//! # Platform Support
//!
//! - **Linux**: Full support (SO_PRIORITY, SO_TXTIME, ETF qdisc detection)
//! - **Other**: Stub backend (returns Unsupported errors)

pub mod auto;
pub mod backend;
pub mod clock;
pub mod config;
pub mod error_queue;
#[cfg(target_os = "linux")]
pub mod linux;
pub mod metrics;
pub mod null;
pub mod policy;
pub mod probe;
pub mod socket_pool;
pub mod txtime;

// Re-exports
pub use auto::{qos_to_tsn, QosHints, TsnMode, WriterTsnOverride};
pub use backend::{TsnBackend, TsnErrorStats};
pub use clock::{calculate_txtime, clock_gettime_ns, ClockSource};
pub use config::{
    FrerConfig, SocketProfile, TsnClockId, TsnConfig, TsnEnforcement, TsnTxtime, TxTimePolicy,
};
pub use error_queue::{enable_error_queue, ErrorQueueConfig, ErrorQueueDrainer, ExtendedError};
#[cfg(target_os = "linux")]
pub use linux::LinuxTsnBackend;
pub use metrics::{TsnMetrics, TsnMetricsSnapshot};
pub use null::NullTsnBackend;
pub use policy::{DropPolicy, Priority, TrafficPolicy};
pub use probe::{SupportLevel, TsnCapabilities, TsnProbe};
pub use socket_pool::{PoolStats, TxSocketPool};
pub use txtime::{PreparedSend, TxTimeCalculator, TxTimeSendResult, TxTimeSender, WriteOptions};

/// Get the default TSN backend for the current platform.
pub fn default_backend() -> Box<dyn TsnBackend> {
    #[cfg(target_os = "linux")]
    {
        Box::new(LinuxTsnBackend::new())
    }
    #[cfg(not(target_os = "linux"))]
    {
        Box::new(NullTsnBackend)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_backend_exists() {
        let backend = default_backend();
        // Should compile and return something
        assert!(std::mem::size_of_val(&backend) > 0);
    }

    #[test]
    fn test_tsn_config_default() {
        let cfg = TsnConfig::default();
        assert!(!cfg.enabled);
        assert_eq!(cfg.enforcement, TsnEnforcement::BestEffort);
        assert_eq!(cfg.tx_time, TxTimePolicy::Disabled);
    }
}
