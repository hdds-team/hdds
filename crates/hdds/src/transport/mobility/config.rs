// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Configuration types for IP mobility.

use std::net::IpAddr;
use std::time::Duration;

/// IP mobility configuration.
#[derive(Clone, Debug)]
pub struct MobilityConfig {
    /// Enable IP mobility detection.
    pub enabled: bool,

    /// Mobility mode.
    pub mode: MobilityMode,

    /// Detector type to use.
    pub detector: DetectorType,

    /// Poll interval for IP detection.
    pub poll_interval: Duration,

    /// Hold-down time before removing old locators.
    ///
    /// After an IP is removed, keep advertising it for this duration
    /// to allow in-flight messages to be delivered.
    pub hold_down: Duration,

    /// Number of SPDP announcements to burst on locator change.
    pub reannounce_burst: u32,

    /// Delay between burst announcements.
    pub reannounce_delay: Duration,

    /// Filter for which interfaces to track.
    pub interface_filter: InterfaceFilter,

    /// Filter for which IP addresses to track.
    pub address_filter: AddressFilter,

    /// Minimum time between reannounce bursts.
    pub min_burst_interval: Duration,
}

impl Default for MobilityConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: MobilityMode::Reactive,
            detector: DetectorType::Poll,
            poll_interval: Duration::from_secs(5),
            hold_down: Duration::from_secs(30),
            reannounce_burst: 3,
            reannounce_delay: Duration::from_millis(100),
            interface_filter: InterfaceFilter::default(),
            address_filter: AddressFilter::default(),
            min_burst_interval: Duration::from_secs(1),
        }
    }
}

impl MobilityConfig {
    /// Create a new mobility config with mobility enabled.
    pub fn new() -> Self {
        Self {
            enabled: true,
            ..Default::default()
        }
    }

    /// Set poll interval.
    pub fn with_poll_interval(mut self, interval: Duration) -> Self {
        self.poll_interval = interval;
        self
    }

    /// Set hold-down duration.
    pub fn with_hold_down(mut self, hold_down: Duration) -> Self {
        self.hold_down = hold_down;
        self
    }

    /// Set reannounce burst count.
    pub fn with_reannounce_burst(mut self, count: u32) -> Self {
        self.reannounce_burst = count;
        self
    }

    /// Set detector type.
    pub fn with_detector(mut self, detector: DetectorType) -> Self {
        self.detector = detector;
        self
    }

    /// Set mobility mode.
    pub fn with_mode(mut self, mode: MobilityMode) -> Self {
        self.mode = mode;
        self
    }

    /// Set interface filter.
    pub fn with_interface_filter(mut self, filter: InterfaceFilter) -> Self {
        self.interface_filter = filter;
        self
    }

    /// Set address filter.
    pub fn with_address_filter(mut self, filter: AddressFilter) -> Self {
        self.address_filter = filter;
        self
    }

    /// Check if an interface should be tracked.
    pub fn should_track_interface(&self, name: &str) -> bool {
        self.interface_filter.matches(name)
    }

    /// Check if an address should be tracked.
    pub fn should_track_address(&self, addr: &IpAddr) -> bool {
        self.address_filter.matches(addr)
    }
}

/// Mobility detection mode.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum MobilityMode {
    /// React to IP changes as they happen.
    #[default]
    Reactive,

    /// Proactively maintain multiple locators.
    Proactive,
}

/// Type of IP change detector to use.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum DetectorType {
    /// Poll using getifaddrs.
    #[default]
    Poll,

    /// Use Netlink (Linux only).
    #[cfg(target_os = "linux")]
    Netlink,
}

/// Filter for network interfaces.
#[derive(Clone, Debug, Default)]
pub struct InterfaceFilter {
    /// Include only these interfaces (empty = all).
    pub include: Vec<String>,

    /// Exclude these interfaces.
    pub exclude: Vec<String>,

    /// Exclude loopback interfaces.
    pub exclude_loopback: bool,

    /// Exclude virtual interfaces (docker, veth, etc.).
    pub exclude_virtual: bool,
}

impl InterfaceFilter {
    /// Create a filter that accepts all interfaces.
    pub fn all() -> Self {
        Self::default()
    }

    /// Create a filter that excludes loopback.
    pub fn no_loopback() -> Self {
        Self {
            exclude_loopback: true,
            ..Default::default()
        }
    }

    /// Create a filter for specific interfaces only.
    pub fn only(interfaces: Vec<String>) -> Self {
        Self {
            include: interfaces,
            ..Default::default()
        }
    }

    /// Add an interface to exclude.
    pub fn exclude(mut self, name: impl Into<String>) -> Self {
        self.exclude.push(name.into());
        self
    }

    /// Set exclude virtual flag.
    pub fn with_exclude_virtual(mut self, exclude: bool) -> Self {
        self.exclude_virtual = exclude;
        self
    }

    /// Check if an interface matches the filter.
    pub fn matches(&self, name: &str) -> bool {
        // Check exclusions first
        if self.exclude_loopback && name == "lo" {
            return false;
        }

        if self.exclude_virtual && is_virtual_interface(name) {
            return false;
        }

        if self.exclude.iter().any(|e| e == name) {
            return false;
        }

        // Check inclusions
        if !self.include.is_empty() {
            return self.include.iter().any(|i| i == name);
        }

        true
    }
}

/// Check if an interface name looks like a virtual interface.
fn is_virtual_interface(name: &str) -> bool {
    // Common virtual interface prefixes
    name.starts_with("docker")
        || name.starts_with("veth")
        || name.starts_with("br-")
        || name.starts_with("virbr")
        || name.starts_with("vboxnet")
        || name.starts_with("vmnet")
        || name.starts_with("tun")
        || name.starts_with("tap")
}

/// Filter for IP addresses.
#[derive(Clone, Debug, Default)]
pub struct AddressFilter {
    /// Include IPv4 addresses.
    pub ipv4: bool,

    /// Include IPv6 addresses.
    pub ipv6: bool,

    /// Exclude link-local addresses.
    pub exclude_link_local: bool,

    /// Exclude loopback addresses.
    pub exclude_loopback: bool,

    /// Exclude private/RFC1918 addresses.
    pub exclude_private: bool,
}

impl AddressFilter {
    /// Create a filter that accepts all addresses.
    pub fn all() -> Self {
        Self {
            ipv4: true,
            ipv6: true,
            exclude_link_local: false,
            exclude_loopback: false,
            exclude_private: false,
        }
    }

    /// Create a filter for IPv4 only.
    pub fn ipv4_only() -> Self {
        Self {
            ipv4: true,
            ipv6: false,
            exclude_link_local: true,
            exclude_loopback: true,
            exclude_private: false,
        }
    }

    /// Create a filter for public addresses only.
    pub fn public_only() -> Self {
        Self {
            ipv4: true,
            ipv6: true,
            exclude_link_local: true,
            exclude_loopback: true,
            exclude_private: true,
        }
    }

    /// Check if an address matches the filter.
    pub fn matches(&self, addr: &IpAddr) -> bool {
        match addr {
            IpAddr::V4(v4) => {
                if !self.ipv4 {
                    return false;
                }
                if self.exclude_loopback && v4.is_loopback() {
                    return false;
                }
                if self.exclude_link_local && v4.is_link_local() {
                    return false;
                }
                if self.exclude_private && v4.is_private() {
                    return false;
                }
                true
            }
            IpAddr::V6(v6) => {
                if !self.ipv6 {
                    return false;
                }
                if self.exclude_loopback && v6.is_loopback() {
                    return false;
                }
                // IPv6 link-local: fe80::/10
                if self.exclude_link_local && is_ipv6_link_local(v6) {
                    return false;
                }
                true
            }
        }
    }
}

/// Check if an IPv6 address is link-local (fe80::/10).
fn is_ipv6_link_local(addr: &std::net::Ipv6Addr) -> bool {
    let segments = addr.segments();
    (segments[0] & 0xffc0) == 0xfe80
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_mobility_config_default() {
        let cfg = MobilityConfig::default();
        assert!(!cfg.enabled);
        assert_eq!(cfg.mode, MobilityMode::Reactive);
        assert_eq!(cfg.detector, DetectorType::Poll);
        assert_eq!(cfg.poll_interval, Duration::from_secs(5));
        assert_eq!(cfg.hold_down, Duration::from_secs(30));
        assert_eq!(cfg.reannounce_burst, 3);
    }

    #[test]
    fn test_mobility_config_new() {
        let cfg = MobilityConfig::new();
        assert!(cfg.enabled);
    }

    #[test]
    fn test_mobility_config_builder() {
        let cfg = MobilityConfig::new()
            .with_poll_interval(Duration::from_secs(10))
            .with_hold_down(Duration::from_secs(60))
            .with_reannounce_burst(5)
            .with_mode(MobilityMode::Proactive);

        assert!(cfg.enabled);
        assert_eq!(cfg.poll_interval, Duration::from_secs(10));
        assert_eq!(cfg.hold_down, Duration::from_secs(60));
        assert_eq!(cfg.reannounce_burst, 5);
        assert_eq!(cfg.mode, MobilityMode::Proactive);
    }

    #[test]
    fn test_interface_filter_all() {
        let filter = InterfaceFilter::all();
        assert!(filter.matches("eth0"));
        assert!(filter.matches("wlan0"));
        assert!(filter.matches("lo"));
        assert!(filter.matches("docker0"));
    }

    #[test]
    fn test_interface_filter_no_loopback() {
        let filter = InterfaceFilter::no_loopback();
        assert!(filter.matches("eth0"));
        assert!(!filter.matches("lo"));
    }

    #[test]
    fn test_interface_filter_only() {
        let filter = InterfaceFilter::only(vec!["eth0".to_string(), "wlan0".to_string()]);
        assert!(filter.matches("eth0"));
        assert!(filter.matches("wlan0"));
        assert!(!filter.matches("eth1"));
        assert!(!filter.matches("lo"));
    }

    #[test]
    fn test_interface_filter_exclude() {
        let filter = InterfaceFilter::all().exclude("docker0");
        assert!(filter.matches("eth0"));
        assert!(!filter.matches("docker0"));
    }

    #[test]
    fn test_interface_filter_exclude_virtual() {
        let filter = InterfaceFilter::all().with_exclude_virtual(true);
        assert!(filter.matches("eth0"));
        assert!(filter.matches("wlan0"));
        assert!(!filter.matches("docker0"));
        assert!(!filter.matches("veth123"));
        assert!(!filter.matches("br-abc"));
        assert!(!filter.matches("virbr0"));
    }

    #[test]
    fn test_is_virtual_interface() {
        assert!(is_virtual_interface("docker0"));
        assert!(is_virtual_interface("veth123abc"));
        assert!(is_virtual_interface("br-network"));
        assert!(is_virtual_interface("virbr0"));
        assert!(is_virtual_interface("vboxnet0"));
        assert!(is_virtual_interface("vmnet1"));
        assert!(is_virtual_interface("tun0"));
        assert!(is_virtual_interface("tap0"));

        assert!(!is_virtual_interface("eth0"));
        assert!(!is_virtual_interface("wlan0"));
        assert!(!is_virtual_interface("enp0s3"));
        assert!(!is_virtual_interface("lo"));
    }

    #[test]
    fn test_address_filter_all() {
        let filter = AddressFilter::all();
        assert!(filter.matches(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert!(filter.matches(&IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(filter.matches(&IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    #[test]
    fn test_address_filter_ipv4_only() {
        let filter = AddressFilter::ipv4_only();
        assert!(filter.matches(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert!(!filter.matches(&IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(!filter.matches(&IpAddr::V6(Ipv6Addr::new(2001, 0xdb8, 0, 0, 0, 0, 0, 1))));
    }

    #[test]
    fn test_address_filter_exclude_loopback() {
        let filter = AddressFilter {
            ipv4: true,
            ipv6: true,
            exclude_loopback: true,
            exclude_link_local: false,
            exclude_private: false,
        };
        assert!(filter.matches(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert!(!filter.matches(&IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(!filter.matches(&IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    #[test]
    fn test_address_filter_exclude_link_local() {
        let filter = AddressFilter {
            ipv4: true,
            ipv6: true,
            exclude_loopback: false,
            exclude_link_local: true,
            exclude_private: false,
        };
        // IPv4 link-local: 169.254.x.x
        assert!(!filter.matches(&IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1))));
        assert!(filter.matches(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));

        // IPv6 link-local: fe80::/10
        assert!(!filter.matches(&IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1))));
        assert!(filter.matches(&IpAddr::V6(Ipv6Addr::new(2001, 0xdb8, 0, 0, 0, 0, 0, 1))));
    }

    #[test]
    fn test_address_filter_exclude_private() {
        let filter = AddressFilter {
            ipv4: true,
            ipv6: true,
            exclude_loopback: false,
            exclude_link_local: false,
            exclude_private: true,
        };
        // RFC1918 private ranges
        assert!(!filter.matches(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(!filter.matches(&IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))));
        assert!(!filter.matches(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        // Public IP
        assert!(filter.matches(&IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
    }

    #[test]
    fn test_address_filter_public_only() {
        let filter = AddressFilter::public_only();
        assert!(!filter.matches(&IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(!filter.matches(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert!(!filter.matches(&IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1))));
        assert!(filter.matches(&IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
    }

    #[test]
    fn test_is_ipv6_link_local() {
        assert!(is_ipv6_link_local(&Ipv6Addr::new(
            0xfe80, 0, 0, 0, 0, 0, 0, 1
        )));
        assert!(is_ipv6_link_local(&Ipv6Addr::new(
            0xfe80, 0, 0, 0, 1, 2, 3, 4
        )));
        assert!(is_ipv6_link_local(&Ipv6Addr::new(
            0xfebf, 0, 0, 0, 0, 0, 0, 1
        )));
        assert!(!is_ipv6_link_local(&Ipv6Addr::new(
            0xfec0, 0, 0, 0, 0, 0, 0, 1
        )));
        assert!(!is_ipv6_link_local(&Ipv6Addr::new(
            2001, 0xdb8, 0, 0, 0, 0, 0, 1
        )));
    }

    #[test]
    fn test_mobility_config_should_track() {
        let cfg = MobilityConfig::new()
            .with_interface_filter(InterfaceFilter::no_loopback())
            .with_address_filter(AddressFilter::ipv4_only());

        assert!(cfg.should_track_interface("eth0"));
        assert!(!cfg.should_track_interface("lo"));

        assert!(cfg.should_track_address(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert!(!cfg.should_track_address(&IpAddr::V4(Ipv4Addr::LOCALHOST)));
    }

    #[test]
    fn test_mobility_mode_variants() {
        assert_eq!(MobilityMode::default(), MobilityMode::Reactive);
        assert_ne!(MobilityMode::Reactive, MobilityMode::Proactive);
    }

    #[test]
    fn test_detector_type_variants() {
        assert_eq!(DetectorType::default(), DetectorType::Poll);
    }
}
