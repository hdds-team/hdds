// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! IP Mobility support for HDDS.
//!
//! This module provides automatic detection and handling of IP address changes:
//!
//! - **Locator tracking**: Track active IP addresses with hold-down timers
//! - **Change detection**: Poll-based or Netlink-based IP change detection
//! - **Reannounce**: Burst SPDP announcements when locators change
//!
//! # Architecture
//!
//! ```text
//! +-----------------------------------------------------------------+
//! |                      IpDetector                                  |
//! |  (PollIpDetector / NetlinkDetector)                             |
//! +---------------------+-------------------------------------------+
//!                       | LocatorChange events
//! +---------------------v-------------------------------------------+
//! |                   LocatorTracker                                 |
//! |  - Tracks active locators with timestamps                       |
//! |  - Applies hold-down before removing old locators               |
//! |  - Generates change events for SPDP                             |
//! +---------------------+-------------------------------------------+
//!                       | Participant reannounce
//! +---------------------v-------------------------------------------+
//! |                DomainParticipant                                 |
//! |  - Receives locator change notifications                        |
//! |  - Triggers SPDP burst on change                                |
//! +-----------------------------------------------------------------+
//! ```
//!
//! # Usage
//!
//! ```rust,ignore
//! use hdds::transport::mobility::{MobilityConfig, LocatorTracker, PollIpDetector};
//! use std::time::Duration;
//!
//! // Configure mobility
//! let config = MobilityConfig {
//!     enabled: true,
//!     poll_interval: Duration::from_secs(5),
//!     hold_down: Duration::from_secs(30),
//!     reannounce_burst: 3,
//!     ..Default::default()
//! };
//!
//! // Create detector and tracker
//! let detector = PollIpDetector::new(config.poll_interval);
//! let tracker = LocatorTracker::new(config.hold_down);
//! ```
//!
//! # Platform Support
//!
//! - **Linux**: Netlink (RTM_NEWADDR/RTM_DELADDR) or getifaddrs polling
//! - **Other**: getifaddrs polling only

pub mod config;
pub mod detector;
#[cfg(target_os = "linux")]
pub mod detector_netlink;
pub mod detector_poll;
pub mod host_id;
pub mod locator_tracker;
pub mod manager;
pub mod metrics;
#[cfg(target_os = "linux")]
pub mod multicast_manager;
pub mod parameter;
pub mod pktinfo;
pub mod prometheus;
pub mod reannounce;

// Re-exports
pub use config::{AddressFilter, DetectorType, InterfaceFilter, MobilityConfig, MobilityMode};
pub use detector::{IpDetector, LocatorChange, LocatorChangeKind};
#[cfg(target_os = "linux")]
pub use detector_netlink::NetlinkIpDetector;
pub use detector_poll::PollIpDetector;
pub use host_id::{generate_host_id, HostIdSource, HostInfo};
pub use locator_tracker::{LocatorState, LocatorTracker, TrackedLocator};
pub use manager::{MobilityCallback, MobilityManager, MobilityManagerStats, MobilityState};
pub use metrics::{MobilityMetrics, MobilityMetricsSnapshot};
#[cfg(target_os = "linux")]
pub use multicast_manager::{
    get_interface_index, get_interface_name, MulticastManager, MulticastStats,
};
pub use parameter::{
    encode_mobility_parameter, find_mobility_parameter, MobilityParameter, ParameterHeader,
    PID_HDDS_MOBILITY,
};
pub use pktinfo::{AlignedCmsgBuf, PacketInfo, SelectedInterface};
pub use prometheus::{
    export_metrics, format_labeled_metric, format_metric, MetricType, MetricsExporter,
};
pub use reannounce::{BurstState, ReannounceBurst, ReannounceController, ReannounceStats};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mobility_config_default() {
        let cfg = MobilityConfig::default();
        assert!(!cfg.enabled);
        assert_eq!(cfg.mode, MobilityMode::Reactive);
    }
}
