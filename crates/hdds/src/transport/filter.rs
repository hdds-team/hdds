// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Network filtering for DDS transport security and isolation.
//!
//! This module provides IP-based filtering capabilities similar to FastDDS and RTI Connext:
//! - **Interface filtering**: Control which network interfaces are used for binding/joining
//! - **Source filtering**: Control which remote peers can send data to this participant
//!
//! # Architecture
//!
//! The filtering system is split into two distinct concerns:
//!
//! 1. **`InterfaceFilter`**: Controls local network interface selection
//!    - Which interfaces to bind sockets to
//!    - Which interfaces to join multicast groups on
//!    - Useful for multi-homed hosts or network isolation
//!
//! 2. **`SourceFilter`**: Controls remote peer acceptance
//!    - Which source IP addresses are allowed to send data
//!    - Whitelist/blacklist semantics (allow/deny lists)
//!    - Applied at packet reception time
//!
//! # Examples
//!
//! ```
//! use hdds::transport::filter::{NetworkFilter, InterfaceFilter, SourceFilter, InterfaceMatcher};
//! use std::net::Ipv4Addr;
//!
//! // Allow only eth0 interface, accept from 10.0.0.0/8 subnet
//! let filter = NetworkFilter::builder()
//!     .interface_by_name("eth0")
//!     .allow_source_cidr("10.0.0.0/8")
//!     .build();
//!
//! // Check if an interface is allowed
//! assert!(filter.interfaces.allows_name("eth0"));
//! assert!(!filter.interfaces.allows_name("eth1"));
//!
//! // Check if a source IP is allowed
//! assert!(filter.sources.allows(Ipv4Addr::new(10, 1, 2, 3)));
//! assert!(!filter.sources.allows(Ipv4Addr::new(192, 168, 1, 1)));
//! ```
//!
//! # Environment Variables
//!
//! - `HDDS_INTERFACE_ALLOW` - Comma-separated list of interface names or CIDRs
//! - `HDDS_SOURCE_ALLOW` - Comma-separated list of allowed source CIDRs
//! - `HDDS_SOURCE_DENY` - Comma-separated list of denied source CIDRs

use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;

/// Combined network filter configuration.
///
/// Groups interface and source filtering into a single configuration object.
#[derive(Debug, Clone, Default)]
pub struct NetworkFilter {
    /// Filter for local network interfaces (bind/join decisions)
    pub interfaces: InterfaceFilter,
    /// Filter for remote source addresses (reception decisions)
    pub sources: SourceFilter,
}

impl NetworkFilter {
    /// Create a new filter that allows everything (no filtering).
    #[must_use]
    pub fn allow_all() -> Self {
        Self::default()
    }

    /// Create a builder for constructing filters.
    #[must_use]
    pub fn builder() -> NetworkFilterBuilder {
        NetworkFilterBuilder::new()
    }

    /// Create from environment variables.
    ///
    /// Reads:
    /// - `HDDS_INTERFACE_ALLOW` - Interface names or CIDRs (comma-separated)
    /// - `HDDS_SOURCE_ALLOW` - Allowed source CIDRs (comma-separated)
    /// - `HDDS_SOURCE_DENY` - Denied source CIDRs (comma-separated)
    #[must_use]
    pub fn from_env() -> Self {
        let interfaces = InterfaceFilter::from_env();
        let sources = SourceFilter::from_env();
        Self {
            interfaces,
            sources,
        }
    }

    /// Check if this filter allows everything (no restrictions).
    #[must_use]
    pub fn is_permissive(&self) -> bool {
        self.interfaces.is_permissive() && self.sources.is_permissive()
    }
}

/// Builder for constructing `NetworkFilter` configurations.
#[derive(Debug, Default)]
pub struct NetworkFilterBuilder {
    interfaces: Vec<InterfaceMatcher>,
    source_allow: Vec<Ipv4Network>,
    source_deny: Vec<Ipv4Network>,
}

impl NetworkFilterBuilder {
    /// Create a new builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an interface filter by name (e.g., "eth0", "ens192").
    #[must_use]
    pub fn interface_by_name(mut self, name: &str) -> Self {
        self.interfaces
            .push(InterfaceMatcher::Name(name.to_string()));
        self
    }

    /// Add an interface filter by CIDR (e.g., "10.128.0.0/16").
    #[must_use]
    pub fn interface_by_cidr(mut self, cidr: &str) -> Self {
        if let Ok(network) = cidr.parse::<Ipv4Network>() {
            self.interfaces.push(InterfaceMatcher::Cidr(network));
        }
        self
    }

    /// Add an allowed source CIDR (e.g., "10.0.0.0/8").
    #[must_use]
    pub fn allow_source_cidr(mut self, cidr: &str) -> Self {
        if let Ok(network) = cidr.parse::<Ipv4Network>() {
            self.source_allow.push(network);
        }
        self
    }

    /// Add a denied source CIDR (e.g., "10.0.0.99/32").
    #[must_use]
    pub fn deny_source_cidr(mut self, cidr: &str) -> Self {
        if let Ok(network) = cidr.parse::<Ipv4Network>() {
            self.source_deny.push(network);
        }
        self
    }

    /// Build the final `NetworkFilter`.
    #[must_use]
    pub fn build(self) -> NetworkFilter {
        NetworkFilter {
            interfaces: InterfaceFilter {
                allow: self.interfaces,
            },
            sources: SourceFilter {
                allow: self.source_allow,
                deny: self.source_deny,
            },
        }
    }
}

// ============================================================================
// Interface Filter
// ============================================================================

/// Filter for local network interface selection.
///
/// Controls which interfaces are used for:
/// - Binding UDP sockets
/// - Joining multicast groups
///
/// # Semantics
///
/// - Empty `allow` list = allow all interfaces (no filtering)
/// - Non-empty `allow` list = only allow interfaces that match at least one entry
#[derive(Debug, Clone, Default)]
pub struct InterfaceFilter {
    /// Allowed interface matchers. Empty = allow all.
    pub allow: Vec<InterfaceMatcher>,
}

impl InterfaceFilter {
    /// Create a filter that allows all interfaces.
    #[must_use]
    pub fn allow_all() -> Self {
        Self { allow: Vec::new() }
    }

    /// Create a filter that allows only the specified interface names.
    #[must_use]
    pub fn only_names(names: &[&str]) -> Self {
        Self {
            allow: names
                .iter()
                .map(|n| InterfaceMatcher::Name((*n).to_string()))
                .collect(),
        }
    }

    /// Create a filter that allows only interfaces in the specified CIDRs.
    #[must_use]
    pub fn only_cidrs(cidrs: &[Ipv4Network]) -> Self {
        Self {
            allow: cidrs.iter().map(|c| InterfaceMatcher::Cidr(*c)).collect(),
        }
    }

    /// Create from environment variable `HDDS_INTERFACE_ALLOW`.
    #[must_use]
    pub fn from_env() -> Self {
        match std::env::var("HDDS_INTERFACE_ALLOW") {
            Ok(val) => Self::parse_env(&val),
            Err(_) => Self::allow_all(),
        }
    }

    fn parse_env(val: &str) -> Self {
        let mut allow = Vec::new();
        for part in val.split(',') {
            let trimmed = part.trim();
            if trimmed.is_empty() {
                continue;
            }
            // Try to parse as CIDR first
            if let Ok(network) = trimmed.parse::<Ipv4Network>() {
                allow.push(InterfaceMatcher::Cidr(network));
            } else {
                // Treat as interface name
                allow.push(InterfaceMatcher::Name(trimmed.to_string()));
            }
        }
        Self { allow }
    }

    /// Check if this filter allows everything.
    #[must_use]
    pub fn is_permissive(&self) -> bool {
        self.allow.is_empty()
    }

    /// Check if an interface name is allowed.
    #[must_use]
    pub fn allows_name(&self, name: &str) -> bool {
        if self.allow.is_empty() {
            return true; // No filtering
        }
        self.allow.iter().any(|m| m.matches_name(name))
    }

    /// Check if an interface IP address is allowed.
    #[must_use]
    pub fn allows_ip(&self, ip: Ipv4Addr) -> bool {
        if self.allow.is_empty() {
            return true; // No filtering
        }
        self.allow.iter().any(|m| m.matches_ip(ip))
    }

    /// Check if an interface (by name and IP) is allowed.
    ///
    /// Returns true if EITHER the name OR the IP matches any allow rule.
    #[must_use]
    pub fn allows_interface(&self, name: &str, ip: Ipv4Addr) -> bool {
        if self.allow.is_empty() {
            return true; // No filtering
        }
        self.allow
            .iter()
            .any(|m| m.matches_name(name) || m.matches_ip(ip))
    }
}

/// Matcher for network interfaces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InterfaceMatcher {
    /// Match by interface name (e.g., "eth0", "ens192", "lo").
    Name(String),
    /// Match by IP address in CIDR range.
    Cidr(Ipv4Network),
}

impl InterfaceMatcher {
    /// Check if this matcher matches an interface name.
    #[must_use]
    pub fn matches_name(&self, name: &str) -> bool {
        match self {
            Self::Name(n) => n == name,
            Self::Cidr(_) => false,
        }
    }

    /// Check if this matcher matches an IP address.
    #[must_use]
    pub fn matches_ip(&self, ip: Ipv4Addr) -> bool {
        match self {
            Self::Name(_) => false,
            Self::Cidr(network) => network.contains(ip),
        }
    }
}

// ============================================================================
// Source Filter
// ============================================================================

/// Filter for remote source IP addresses.
///
/// Controls which remote peers are allowed to send data to this participant.
///
/// # Evaluation Semantics (Firewall-style)
///
/// 1. If `allow` is empty, all sources pass to step 2
/// 2. If `allow` is non-empty, source must match at least one allow entry
/// 3. If source matches any `deny` entry, it is rejected (deny overrides allow)
///
/// # Examples
///
/// ```
/// use hdds::transport::filter::SourceFilter;
/// use std::net::Ipv4Addr;
///
/// // Allow all from 10.0.0.0/8, but deny 10.0.0.99
/// let filter = SourceFilter {
///     allow: vec!["10.0.0.0/8".parse().unwrap()],
///     deny: vec!["10.0.0.99/32".parse().unwrap()],
/// };
///
/// assert!(filter.allows(Ipv4Addr::new(10, 1, 2, 3)));
/// assert!(!filter.allows(Ipv4Addr::new(10, 0, 0, 99)));  // Denied
/// assert!(!filter.allows(Ipv4Addr::new(192, 168, 1, 1))); // Not in allow list
/// ```
#[derive(Debug, Clone, Default)]
pub struct SourceFilter {
    /// Allowed source CIDRs. Empty = allow all (then apply deny).
    pub allow: Vec<Ipv4Network>,
    /// Denied source CIDRs. Applied after allow check.
    pub deny: Vec<Ipv4Network>,
}

impl SourceFilter {
    /// Create a filter that allows all sources.
    #[must_use]
    pub fn allow_all() -> Self {
        Self::default()
    }

    /// Create a filter that allows only sources from the specified CIDRs.
    #[must_use]
    pub fn only_allow(cidrs: Vec<Ipv4Network>) -> Self {
        Self {
            allow: cidrs,
            deny: Vec::new(),
        }
    }

    /// Create from environment variables.
    ///
    /// Reads:
    /// - `HDDS_SOURCE_ALLOW` - Comma-separated CIDRs
    /// - `HDDS_SOURCE_DENY` - Comma-separated CIDRs
    #[must_use]
    pub fn from_env() -> Self {
        let allow = Self::parse_cidr_list(&std::env::var("HDDS_SOURCE_ALLOW").unwrap_or_default());
        let deny = Self::parse_cidr_list(&std::env::var("HDDS_SOURCE_DENY").unwrap_or_default());
        Self { allow, deny }
    }

    fn parse_cidr_list(val: &str) -> Vec<Ipv4Network> {
        val.split(',')
            .filter_map(|s| s.trim().parse::<Ipv4Network>().ok())
            .collect()
    }

    /// Check if this filter allows everything.
    #[must_use]
    pub fn is_permissive(&self) -> bool {
        self.allow.is_empty() && self.deny.is_empty()
    }

    /// Check if a source IP address is allowed.
    ///
    /// # Evaluation order
    ///
    /// 1. If `allow` is empty, source passes to deny check
    /// 2. If `allow` is non-empty, source must match at least one entry
    /// 3. If source matches any `deny` entry, it is rejected
    #[must_use]
    pub fn allows(&self, ip: Ipv4Addr) -> bool {
        // Step 1-2: Check allow list
        if !self.allow.is_empty() {
            let in_allow = self.allow.iter().any(|net| net.contains(ip));
            if !in_allow {
                return false;
            }
        }

        // Step 3: Check deny list (overrides allow)
        let in_deny = self.deny.iter().any(|net| net.contains(ip));
        !in_deny
    }

    /// Check if a source IP address (as IpAddr) is allowed.
    #[must_use]
    pub fn allows_addr(&self, addr: IpAddr) -> bool {
        match addr {
            IpAddr::V4(ip) => self.allows(ip),
            IpAddr::V6(_) => {
                // IPv6 filtering is only applied when no IPv4 allow/deny rules are set.
                self.allow.is_empty() && self.deny.is_empty()
            }
        }
    }
}

// ============================================================================
// IPv4 Network (CIDR)
// ============================================================================

/// IPv4 network in CIDR notation.
///
/// Represents a network like "10.0.0.0/8" or "192.168.1.0/24".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Network {
    /// Network address
    pub addr: Ipv4Addr,
    /// Prefix length (0-32)
    pub prefix_len: u8,
    /// Precomputed network mask
    mask: u32,
}

impl Ipv4Network {
    /// Create a new IPv4 network.
    ///
    /// # Panics
    ///
    /// Panics if `prefix_len` > 32.
    #[must_use]
    pub fn new(addr: Ipv4Addr, prefix_len: u8) -> Self {
        assert!(prefix_len <= 32, "prefix_len must be <= 32");
        let mask = if prefix_len == 0 {
            0
        } else {
            !0u32 << (32 - prefix_len)
        };
        // Normalize the address to the network address
        let addr_bits = u32::from(addr);
        let network_addr = Ipv4Addr::from(addr_bits & mask);
        Self {
            addr: network_addr,
            prefix_len,
            mask,
        }
    }

    /// Create a single-host network (/32).
    #[must_use]
    pub fn host(addr: Ipv4Addr) -> Self {
        Self::new(addr, 32)
    }

    /// Check if an IP address is contained in this network.
    #[must_use]
    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        let ip_bits = u32::from(ip);
        let net_bits = u32::from(self.addr);
        (ip_bits & self.mask) == (net_bits & self.mask)
    }

    /// Get the broadcast address for this network.
    #[must_use]
    pub fn broadcast(&self) -> Ipv4Addr {
        let net_bits = u32::from(self.addr);
        Ipv4Addr::from(net_bits | !self.mask)
    }
}

impl FromStr for Ipv4Network {
    type Err = NetworkParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Handle single IP (treat as /32)
        if !s.contains('/') {
            let addr: Ipv4Addr = s.parse().map_err(|_| NetworkParseError::InvalidAddress)?;
            return Ok(Self::host(addr));
        }

        let parts: Vec<&str> = s.split('/').collect();
        if parts.len() != 2 {
            return Err(NetworkParseError::InvalidFormat);
        }

        let addr: Ipv4Addr = parts[0]
            .parse()
            .map_err(|_| NetworkParseError::InvalidAddress)?;
        let prefix_len: u8 = parts[1]
            .parse()
            .map_err(|_| NetworkParseError::InvalidPrefix)?;

        if prefix_len > 32 {
            return Err(NetworkParseError::InvalidPrefix);
        }

        Ok(Self::new(addr, prefix_len))
    }
}

impl std::fmt::Display for Ipv4Network {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix_len)
    }
}

/// Error parsing an IPv4 network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkParseError {
    /// Invalid CIDR format (expected "x.x.x.x/y")
    InvalidFormat,
    /// Invalid IP address
    InvalidAddress,
    /// Invalid prefix length (must be 0-32)
    InvalidPrefix,
}

impl std::fmt::Display for NetworkParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidFormat => write!(f, "invalid CIDR format (expected x.x.x.x/y)"),
            Self::InvalidAddress => write!(f, "invalid IP address"),
            Self::InvalidPrefix => write!(f, "invalid prefix length (must be 0-32)"),
        }
    }
}

impl std::error::Error for NetworkParseError {}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // Ipv4Network tests
    // ========================================================================

    #[test]
    fn test_ipv4_network_parse() {
        let net: Ipv4Network = "10.0.0.0/8".parse().expect("valid CIDR");
        assert_eq!(net.addr, Ipv4Addr::new(10, 0, 0, 0));
        assert_eq!(net.prefix_len, 8);

        let net: Ipv4Network = "192.168.1.0/24".parse().expect("valid CIDR");
        assert_eq!(net.addr, Ipv4Addr::new(192, 168, 1, 0));
        assert_eq!(net.prefix_len, 24);

        // Single IP = /32
        let net: Ipv4Network = "10.0.0.99".parse().expect("valid single IP");
        assert_eq!(net.addr, Ipv4Addr::new(10, 0, 0, 99));
        assert_eq!(net.prefix_len, 32);
    }

    #[test]
    fn test_ipv4_network_normalize() {
        // Address should be normalized to network address
        let net: Ipv4Network = "10.1.2.3/8".parse().expect("valid CIDR");
        assert_eq!(net.addr, Ipv4Addr::new(10, 0, 0, 0));
    }

    #[test]
    fn test_ipv4_network_contains() {
        let net: Ipv4Network = "10.0.0.0/8".parse().expect("valid CIDR");
        assert!(net.contains(Ipv4Addr::new(10, 0, 0, 0)));
        assert!(net.contains(Ipv4Addr::new(10, 255, 255, 255)));
        assert!(net.contains(Ipv4Addr::new(10, 1, 2, 3)));
        assert!(!net.contains(Ipv4Addr::new(11, 0, 0, 0)));
        assert!(!net.contains(Ipv4Addr::new(192, 168, 1, 1)));

        let net: Ipv4Network = "192.168.1.0/24".parse().expect("valid CIDR");
        assert!(net.contains(Ipv4Addr::new(192, 168, 1, 0)));
        assert!(net.contains(Ipv4Addr::new(192, 168, 1, 255)));
        assert!(!net.contains(Ipv4Addr::new(192, 168, 2, 0)));

        // /32 = exact match
        let net: Ipv4Network = "10.0.0.99/32".parse().expect("valid CIDR");
        assert!(net.contains(Ipv4Addr::new(10, 0, 0, 99)));
        assert!(!net.contains(Ipv4Addr::new(10, 0, 0, 98)));

        // /0 = match all
        let net: Ipv4Network = "0.0.0.0/0".parse().expect("valid CIDR");
        assert!(net.contains(Ipv4Addr::new(0, 0, 0, 0)));
        assert!(net.contains(Ipv4Addr::new(255, 255, 255, 255)));
    }

    #[test]
    fn test_ipv4_network_broadcast() {
        let net: Ipv4Network = "10.0.0.0/8".parse().expect("valid CIDR");
        assert_eq!(net.broadcast(), Ipv4Addr::new(10, 255, 255, 255));

        let net: Ipv4Network = "192.168.1.0/24".parse().expect("valid CIDR");
        assert_eq!(net.broadcast(), Ipv4Addr::new(192, 168, 1, 255));
    }

    #[test]
    fn test_ipv4_network_parse_errors() {
        assert!("not-an-ip".parse::<Ipv4Network>().is_err());
        assert!("10.0.0.0/33".parse::<Ipv4Network>().is_err());
        assert!("10.0.0.0/abc".parse::<Ipv4Network>().is_err());
        assert!("10.0.0/24".parse::<Ipv4Network>().is_err());
    }

    // ========================================================================
    // InterfaceFilter tests
    // ========================================================================

    #[test]
    fn test_interface_filter_allow_all() {
        let filter = InterfaceFilter::allow_all();
        assert!(filter.is_permissive());
        assert!(filter.allows_name("eth0"));
        assert!(filter.allows_name("any-interface"));
        assert!(filter.allows_ip(Ipv4Addr::new(10, 0, 0, 1)));
    }

    #[test]
    fn test_interface_filter_by_name() {
        let filter = InterfaceFilter::only_names(&["eth0", "eth1"]);
        assert!(!filter.is_permissive());
        assert!(filter.allows_name("eth0"));
        assert!(filter.allows_name("eth1"));
        assert!(!filter.allows_name("eth2"));
        assert!(!filter.allows_name("lo"));
    }

    #[test]
    fn test_interface_filter_by_cidr() {
        let filter = InterfaceFilter::only_cidrs(&["10.0.0.0/8".parse().expect("valid CIDR")]);
        assert!(!filter.is_permissive());
        assert!(filter.allows_ip(Ipv4Addr::new(10, 1, 2, 3)));
        assert!(!filter.allows_ip(Ipv4Addr::new(192, 168, 1, 1)));
        // Name doesn't match CIDR
        assert!(!filter.allows_name("eth0"));
    }

    #[test]
    fn test_interface_filter_mixed() {
        let filter = InterfaceFilter {
            allow: vec![
                InterfaceMatcher::Name("eth0".to_string()),
                InterfaceMatcher::Cidr("10.128.0.0/16".parse().expect("valid CIDR")),
            ],
        };

        // eth0 matches by name
        assert!(filter.allows_interface("eth0", Ipv4Addr::new(192, 168, 1, 1)));
        // eth1 with matching IP
        assert!(filter.allows_interface("eth1", Ipv4Addr::new(10, 128, 1, 1)));
        // eth1 without matching IP
        assert!(!filter.allows_interface("eth1", Ipv4Addr::new(192, 168, 1, 1)));
    }

    #[test]
    fn test_interface_filter_parse_env() {
        let filter = InterfaceFilter::parse_env("eth0, eth1, 10.0.0.0/8");
        assert_eq!(filter.allow.len(), 3);
        assert!(filter.allows_name("eth0"));
        assert!(filter.allows_name("eth1"));
        assert!(filter.allows_ip(Ipv4Addr::new(10, 1, 2, 3)));
    }

    // ========================================================================
    // SourceFilter tests
    // ========================================================================

    #[test]
    fn test_source_filter_allow_all() {
        let filter = SourceFilter::allow_all();
        assert!(filter.is_permissive());
        assert!(filter.allows(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(filter.allows(Ipv4Addr::new(192, 168, 1, 1)));
        assert!(filter.allows(Ipv4Addr::new(8, 8, 8, 8)));
    }

    #[test]
    fn test_source_filter_allow_list() {
        let filter = SourceFilter::only_allow(vec!["10.0.0.0/8".parse().expect("valid CIDR")]);

        assert!(filter.allows(Ipv4Addr::new(10, 1, 2, 3)));
        assert!(filter.allows(Ipv4Addr::new(10, 255, 255, 255)));
        assert!(!filter.allows(Ipv4Addr::new(192, 168, 1, 1)));
        assert!(!filter.allows(Ipv4Addr::new(11, 0, 0, 1)));
    }

    #[test]
    fn test_source_filter_deny_list() {
        let filter = SourceFilter {
            allow: vec![],
            deny: vec!["10.0.0.99/32".parse().expect("valid CIDR")],
        };

        // Allow all except denied
        assert!(filter.allows(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(filter.allows(Ipv4Addr::new(192, 168, 1, 1)));
        assert!(!filter.allows(Ipv4Addr::new(10, 0, 0, 99))); // Denied
    }

    #[test]
    fn test_source_filter_allow_deny_combined() {
        // Allow 10.0.0.0/8 but deny 10.0.0.99
        let filter = SourceFilter {
            allow: vec!["10.0.0.0/8".parse().expect("valid CIDR")],
            deny: vec!["10.0.0.99/32".parse().expect("valid CIDR")],
        };

        assert!(filter.allows(Ipv4Addr::new(10, 1, 2, 3)));
        assert!(!filter.allows(Ipv4Addr::new(10, 0, 0, 99))); // Denied overrides allow
        assert!(!filter.allows(Ipv4Addr::new(192, 168, 1, 1))); // Not in allow list
    }

    #[test]
    fn test_source_filter_deny_subnet() {
        // Allow 10.0.0.0/8 but deny entire 10.128.0.0/16 subnet
        let filter = SourceFilter {
            allow: vec!["10.0.0.0/8".parse().expect("valid CIDR")],
            deny: vec!["10.128.0.0/16".parse().expect("valid CIDR")],
        };

        assert!(filter.allows(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(filter.allows(Ipv4Addr::new(10, 127, 255, 255)));
        assert!(!filter.allows(Ipv4Addr::new(10, 128, 0, 1))); // In denied subnet
        assert!(!filter.allows(Ipv4Addr::new(10, 128, 255, 255))); // In denied subnet
        assert!(filter.allows(Ipv4Addr::new(10, 129, 0, 1))); // Outside denied subnet
    }

    // ========================================================================
    // NetworkFilter tests
    // ========================================================================

    #[test]
    fn test_network_filter_builder() {
        let filter = NetworkFilter::builder()
            .interface_by_name("eth0")
            .interface_by_cidr("10.0.0.0/8")
            .allow_source_cidr("192.168.0.0/16")
            .deny_source_cidr("192.168.1.99/32")
            .build();

        // Interface checks
        assert!(filter.interfaces.allows_name("eth0"));
        assert!(!filter.interfaces.allows_name("eth1"));
        assert!(filter.interfaces.allows_ip(Ipv4Addr::new(10, 1, 2, 3)));

        // Source checks
        assert!(filter.sources.allows(Ipv4Addr::new(192, 168, 0, 1)));
        assert!(!filter.sources.allows(Ipv4Addr::new(192, 168, 1, 99)));
        assert!(!filter.sources.allows(Ipv4Addr::new(10, 0, 0, 1)));
    }

    #[test]
    fn test_network_filter_allow_all() {
        let filter = NetworkFilter::allow_all();
        assert!(filter.is_permissive());
    }
}
