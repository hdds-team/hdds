// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! IP change detection trait and types.

use std::io;
use std::net::IpAddr;
use std::time::Instant;

/// Kind of locator change.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocatorChangeKind {
    /// A new IP address was added.
    Added,

    /// An IP address was removed.
    Removed,

    /// An IP address was updated (e.g., flags changed).
    Updated,
}

/// A locator change event.
#[derive(Clone, Debug)]
pub struct LocatorChange {
    /// The IP address that changed.
    pub addr: IpAddr,

    /// The interface name.
    pub interface: String,

    /// Kind of change.
    pub kind: LocatorChangeKind,

    /// When the change was detected.
    pub timestamp: Instant,

    /// Additional flags or metadata.
    pub flags: LocatorFlags,
}

impl LocatorChange {
    /// Create a new locator change event.
    pub fn new(addr: IpAddr, interface: String, kind: LocatorChangeKind) -> Self {
        Self {
            addr,
            interface,
            kind,
            timestamp: Instant::now(),
            flags: LocatorFlags::default(),
        }
    }

    /// Create an "added" change.
    pub fn added(addr: IpAddr, interface: String) -> Self {
        Self::new(addr, interface, LocatorChangeKind::Added)
    }

    /// Create a "removed" change.
    pub fn removed(addr: IpAddr, interface: String) -> Self {
        Self::new(addr, interface, LocatorChangeKind::Removed)
    }

    /// Create an "updated" change.
    pub fn updated(addr: IpAddr, interface: String) -> Self {
        Self::new(addr, interface, LocatorChangeKind::Updated)
    }

    /// Set flags.
    pub fn with_flags(mut self, flags: LocatorFlags) -> Self {
        self.flags = flags;
        self
    }

    /// Check if this is an add event.
    pub fn is_add(&self) -> bool {
        self.kind == LocatorChangeKind::Added
    }

    /// Check if this is a remove event.
    pub fn is_remove(&self) -> bool {
        self.kind == LocatorChangeKind::Removed
    }

    /// Get age of this event.
    pub fn age(&self) -> std::time::Duration {
        self.timestamp.elapsed()
    }
}

/// Flags for a locator.
#[derive(Clone, Copy, Debug, Default)]
pub struct LocatorFlags {
    /// Address is temporary (privacy extension).
    pub temporary: bool,

    /// Address is deprecated.
    pub deprecated: bool,

    /// Address is tentative (DAD in progress).
    pub tentative: bool,

    /// Prefix length (CIDR).
    pub prefix_len: u8,

    /// Scope (link, global, etc.).
    pub scope: AddressScope,
}

impl LocatorFlags {
    /// Create flags for a typical global address.
    pub fn global(prefix_len: u8) -> Self {
        Self {
            prefix_len,
            scope: AddressScope::Global,
            ..Default::default()
        }
    }

    /// Create flags for a link-local address.
    pub fn link_local(prefix_len: u8) -> Self {
        Self {
            prefix_len,
            scope: AddressScope::Link,
            ..Default::default()
        }
    }

    /// Check if address is usable (not deprecated/tentative).
    pub fn is_usable(&self) -> bool {
        !self.deprecated && !self.tentative
    }
}

/// Address scope.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AddressScope {
    /// Unknown scope.
    #[default]
    Unknown,

    /// Host-local (loopback).
    Host,

    /// Link-local.
    Link,

    /// Site-local (deprecated).
    Site,

    /// Global scope.
    Global,
}

impl AddressScope {
    /// Check if this scope is routable beyond the link.
    pub fn is_routable(&self) -> bool {
        matches!(self, AddressScope::Site | AddressScope::Global)
    }
}

/// Trait for IP address change detectors.
pub trait IpDetector: Send {
    /// Poll for IP address changes.
    ///
    /// Returns a list of changes since the last poll.
    /// Returns an empty vec if no changes.
    fn poll_changes(&mut self) -> io::Result<Vec<LocatorChange>>;

    /// Get all current IP addresses.
    ///
    /// Returns (address, interface_name) pairs.
    fn current_addresses(&self) -> io::Result<Vec<(IpAddr, String)>>;

    /// Get detector name (for logging/debugging).
    fn name(&self) -> &str;

    /// Check if detector is event-based (non-blocking poll).
    fn is_event_based(&self) -> bool {
        false
    }
}

/// Snapshot of current IP addresses.
#[derive(Clone, Debug)]
pub struct AddressSnapshot {
    /// List of addresses with their interfaces.
    pub addresses: Vec<AddressInfo>,

    /// When snapshot was taken.
    pub timestamp: Instant,
}

impl Default for AddressSnapshot {
    fn default() -> Self {
        Self {
            addresses: Vec::new(),
            timestamp: Instant::now(),
        }
    }
}

impl AddressSnapshot {
    /// Create a new snapshot.
    pub fn new(addresses: Vec<AddressInfo>) -> Self {
        Self {
            addresses,
            timestamp: Instant::now(),
        }
    }

    /// Get addresses as (IpAddr, interface) pairs.
    pub fn as_pairs(&self) -> Vec<(IpAddr, String)> {
        self.addresses
            .iter()
            .map(|a| (a.addr, a.interface.clone()))
            .collect()
    }

    /// Find address by IP.
    pub fn find(&self, addr: &IpAddr) -> Option<&AddressInfo> {
        self.addresses.iter().find(|a| &a.addr == addr)
    }

    /// Check if snapshot contains an address.
    pub fn contains(&self, addr: &IpAddr) -> bool {
        self.addresses.iter().any(|a| &a.addr == addr)
    }

    /// Get addresses on a specific interface.
    pub fn on_interface<'a>(&'a self, interface: &'a str) -> impl Iterator<Item = &'a AddressInfo> {
        self.addresses
            .iter()
            .filter(move |a| a.interface == interface)
    }

    /// Get age of this snapshot.
    pub fn age(&self) -> std::time::Duration {
        self.timestamp.elapsed()
    }
}

/// Information about an IP address.
#[derive(Clone, Debug)]
pub struct AddressInfo {
    /// The IP address.
    pub addr: IpAddr,

    /// Interface name.
    pub interface: String,

    /// Address flags.
    pub flags: LocatorFlags,
}

impl AddressInfo {
    /// Create new address info.
    pub fn new(addr: IpAddr, interface: String) -> Self {
        Self {
            addr,
            interface,
            flags: LocatorFlags::default(),
        }
    }

    /// Create with flags.
    pub fn with_flags(mut self, flags: LocatorFlags) -> Self {
        self.flags = flags;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn v4(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, last))
    }

    fn v6() -> IpAddr {
        IpAddr::V6(Ipv6Addr::new(2001, 0xdb8, 0, 0, 0, 0, 0, 1))
    }

    #[test]
    fn test_locator_change_new() {
        let change = LocatorChange::new(v4(1), "eth0".to_string(), LocatorChangeKind::Added);
        assert_eq!(change.addr, v4(1));
        assert_eq!(change.interface, "eth0");
        assert_eq!(change.kind, LocatorChangeKind::Added);
        assert!(change.is_add());
        assert!(!change.is_remove());
    }

    #[test]
    fn test_locator_change_constructors() {
        let added = LocatorChange::added(v4(1), "eth0".to_string());
        assert!(added.is_add());

        let removed = LocatorChange::removed(v4(1), "eth0".to_string());
        assert!(removed.is_remove());

        let updated = LocatorChange::updated(v4(1), "eth0".to_string());
        assert_eq!(updated.kind, LocatorChangeKind::Updated);
    }

    #[test]
    fn test_locator_change_with_flags() {
        let flags = LocatorFlags::global(24);
        let change = LocatorChange::added(v4(1), "eth0".to_string()).with_flags(flags);
        assert_eq!(change.flags.prefix_len, 24);
        assert_eq!(change.flags.scope, AddressScope::Global);
    }

    #[test]
    fn test_locator_change_age() {
        let change = LocatorChange::added(v4(1), "eth0".to_string());
        std::thread::sleep(std::time::Duration::from_millis(10));
        assert!(change.age() >= std::time::Duration::from_millis(10));
    }

    #[test]
    fn test_locator_flags_default() {
        let flags = LocatorFlags::default();
        assert!(!flags.temporary);
        assert!(!flags.deprecated);
        assert!(!flags.tentative);
        assert_eq!(flags.prefix_len, 0);
        assert_eq!(flags.scope, AddressScope::Unknown);
    }

    #[test]
    fn test_locator_flags_global() {
        let flags = LocatorFlags::global(24);
        assert_eq!(flags.prefix_len, 24);
        assert_eq!(flags.scope, AddressScope::Global);
        assert!(flags.is_usable());
    }

    #[test]
    fn test_locator_flags_link_local() {
        let flags = LocatorFlags::link_local(64);
        assert_eq!(flags.prefix_len, 64);
        assert_eq!(flags.scope, AddressScope::Link);
    }

    #[test]
    fn test_locator_flags_is_usable() {
        let mut flags = LocatorFlags::default();
        assert!(flags.is_usable());

        flags.deprecated = true;
        assert!(!flags.is_usable());

        flags.deprecated = false;
        flags.tentative = true;
        assert!(!flags.is_usable());
    }

    #[test]
    fn test_address_scope_is_routable() {
        assert!(!AddressScope::Unknown.is_routable());
        assert!(!AddressScope::Host.is_routable());
        assert!(!AddressScope::Link.is_routable());
        assert!(AddressScope::Site.is_routable());
        assert!(AddressScope::Global.is_routable());
    }

    #[test]
    fn test_address_snapshot_new() {
        let info = AddressInfo::new(v4(1), "eth0".to_string());
        let snapshot = AddressSnapshot::new(vec![info]);
        assert_eq!(snapshot.addresses.len(), 1);
    }

    #[test]
    fn test_address_snapshot_as_pairs() {
        let info1 = AddressInfo::new(v4(1), "eth0".to_string());
        let info2 = AddressInfo::new(v6(), "eth0".to_string());
        let snapshot = AddressSnapshot::new(vec![info1, info2]);

        let pairs = snapshot.as_pairs();
        assert_eq!(pairs.len(), 2);
        assert_eq!(pairs[0], (v4(1), "eth0".to_string()));
    }

    #[test]
    fn test_address_snapshot_find() {
        let info = AddressInfo::new(v4(1), "eth0".to_string());
        let snapshot = AddressSnapshot::new(vec![info]);

        assert!(snapshot.find(&v4(1)).is_some());
        assert!(snapshot.find(&v4(2)).is_none());
    }

    #[test]
    fn test_address_snapshot_contains() {
        let info = AddressInfo::new(v4(1), "eth0".to_string());
        let snapshot = AddressSnapshot::new(vec![info]);

        assert!(snapshot.contains(&v4(1)));
        assert!(!snapshot.contains(&v4(2)));
    }

    #[test]
    fn test_address_snapshot_on_interface() {
        let info1 = AddressInfo::new(v4(1), "eth0".to_string());
        let info2 = AddressInfo::new(v4(2), "eth1".to_string());
        let info3 = AddressInfo::new(v4(3), "eth0".to_string());
        let snapshot = AddressSnapshot::new(vec![info1, info2, info3]);

        let eth0_addrs: Vec<_> = snapshot.on_interface("eth0").collect();
        assert_eq!(eth0_addrs.len(), 2);
    }

    #[test]
    fn test_address_info_new() {
        let info = AddressInfo::new(v4(1), "eth0".to_string());
        assert_eq!(info.addr, v4(1));
        assert_eq!(info.interface, "eth0");
    }

    #[test]
    fn test_address_info_with_flags() {
        let flags = LocatorFlags::global(24);
        let info = AddressInfo::new(v4(1), "eth0".to_string()).with_flags(flags);
        assert_eq!(info.flags.prefix_len, 24);
    }

    #[test]
    fn test_locator_change_kind_variants() {
        assert_eq!(LocatorChangeKind::Added, LocatorChangeKind::Added);
        assert_ne!(LocatorChangeKind::Added, LocatorChangeKind::Removed);
        assert_ne!(LocatorChangeKind::Removed, LocatorChangeKind::Updated);
    }
}
