// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Poll-based IP address detector over the interface snapshot
//! (`transport::ifaddrs`, the crate's one `getifaddrs(3)` walk).

use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use super::config::{AddressFilter, InterfaceFilter};
use super::detector::{AddressInfo, AddressSnapshot, IpDetector, LocatorChange};
#[cfg(unix)]
use super::detector::{AddressScope, LocatorFlags};
#[cfg(unix)]
use crate::transport::ifaddrs::{AddressEntry, InterfaceSnapshot};

/// Poll-based IP address detector.
///
/// Captures an interface snapshot to periodically check for IP address
/// changes. Less efficient than event-based detection.
///
/// # Platform support
///
/// UNIX ONLY in substance: outside unix `get_addresses_via_getifaddrs`
/// returns an empty set, so this detector compiles and runs but never
/// observes an address and never raises a change. The Windows equivalent
/// (`GetAdaptersAddresses` / `NotifyIpInterfaceChange`) is not implemented.
/// scripts/windows-gate.sh records that under "INCOMPLETE by name": the unit
/// tests below pass vacuously under the wine lane.
pub struct PollIpDetector {
    /// Last snapshot of addresses.
    last_snapshot: Option<AddressSnapshot>,

    /// Minimum poll interval.
    poll_interval: Duration,

    /// Last poll time.
    last_poll: Option<Instant>,

    /// Interface filter.
    interface_filter: InterfaceFilter,

    /// Address filter.
    address_filter: AddressFilter,
}

impl PollIpDetector {
    /// Create a new poll-based detector.
    pub fn new(poll_interval: Duration) -> Self {
        Self {
            last_snapshot: None,
            poll_interval,
            last_poll: None,
            interface_filter: InterfaceFilter::default(),
            address_filter: AddressFilter::all(),
        }
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

    /// Check if enough time has passed since last poll.
    pub fn should_poll(&self) -> bool {
        match self.last_poll {
            Some(last) => last.elapsed() >= self.poll_interval,
            None => true,
        }
    }

    /// Force a poll regardless of interval.
    pub fn force_poll(&mut self) -> io::Result<Vec<LocatorChange>> {
        self.last_poll = Some(Instant::now());
        self.detect_changes()
    }

    /// Get current snapshot without detecting changes.
    pub fn snapshot(&self) -> io::Result<AddressSnapshot> {
        let addresses = get_system_addresses(&self.interface_filter, &self.address_filter)?;
        Ok(AddressSnapshot::new(addresses))
    }

    /// Detect changes between current state and last snapshot.
    fn detect_changes(&mut self) -> io::Result<Vec<LocatorChange>> {
        let current = self.snapshot()?;
        let changes = match &self.last_snapshot {
            Some(previous) => compute_changes(previous, &current),
            None => {
                // First poll - all addresses are "added"
                current
                    .addresses
                    .iter()
                    .map(|a| LocatorChange::added(a.addr, a.interface.clone()))
                    .collect()
            }
        };

        self.last_snapshot = Some(current);
        Ok(changes)
    }

    /// Get poll interval.
    pub fn poll_interval(&self) -> Duration {
        self.poll_interval
    }

    /// Set poll interval.
    pub fn set_poll_interval(&mut self, interval: Duration) {
        self.poll_interval = interval;
    }

    /// Get last poll time.
    pub fn last_poll(&self) -> Option<Instant> {
        self.last_poll
    }

    /// Reset detector state (clears last snapshot).
    pub fn reset(&mut self) {
        self.last_snapshot = None;
        self.last_poll = None;
    }
}

impl IpDetector for PollIpDetector {
    fn poll_changes(&mut self) -> io::Result<Vec<LocatorChange>> {
        if !self.should_poll() {
            return Ok(Vec::new());
        }

        self.last_poll = Some(Instant::now());
        self.detect_changes()
    }

    fn current_addresses(&self) -> io::Result<Vec<(IpAddr, String)>> {
        let snapshot = self.snapshot()?;
        Ok(snapshot.as_pairs())
    }

    fn name(&self) -> &str {
        "poll"
    }

    fn is_event_based(&self) -> bool {
        false
    }
}

/// Compute changes between two snapshots.
fn compute_changes(previous: &AddressSnapshot, current: &AddressSnapshot) -> Vec<LocatorChange> {
    let mut changes = Vec::new();

    // Build lookup maps
    let prev_map: HashMap<IpAddr, &AddressInfo> =
        previous.addresses.iter().map(|a| (a.addr, a)).collect();
    let curr_map: HashMap<IpAddr, &AddressInfo> =
        current.addresses.iter().map(|a| (a.addr, a)).collect();

    // Find removed addresses
    for (addr, info) in &prev_map {
        if !curr_map.contains_key(addr) {
            changes.push(LocatorChange::removed(*addr, info.interface.clone()));
        }
    }

    // Find added addresses
    for (addr, info) in &curr_map {
        if !prev_map.contains_key(addr) {
            changes.push(LocatorChange::added(*addr, info.interface.clone()));
        }
    }

    changes
}

/// Get system IP addresses from a fresh interface snapshot, filtered.
#[cfg(unix)]
fn get_system_addresses(
    iface_filter: &InterfaceFilter,
    addr_filter: &AddressFilter,
) -> io::Result<Vec<AddressInfo>> {
    let snapshot = InterfaceSnapshot::capture()?;
    Ok(addresses_from_snapshot(
        &snapshot,
        iface_filter,
        addr_filter,
    ))
}

/// The mobility view of a snapshot: every address of either family that
/// passes the interface filter and the address filter, in OS order.
///
/// `AddressInfo.interface` is the raw OS label (`eth0:1` for a labelled
/// alias), which is what the former in-module getifaddrs walk reported as
/// `ifa_name` and what the interface filter is applied to. The multicast
/// code normalises to the device name; this detector deliberately does not,
/// so its behaviour is unchanged.
#[cfg(unix)]
fn addresses_from_snapshot(
    snapshot: &InterfaceSnapshot,
    iface_filter: &InterfaceFilter,
    addr_filter: &AddressFilter,
) -> Vec<AddressInfo> {
    snapshot
        .addresses()
        .iter()
        .filter(|e| iface_filter.matches(&e.label) && addr_filter.matches(&e.addr))
        .map(|e| AddressInfo::new(e.addr, e.label.clone()).with_flags(locator_flags(e)))
        .collect()
}

/// Locator flags of a snapshot entry: the prefix length from the netmask
/// (0 when the OS reported none, as before) and the scope of the address.
#[cfg(unix)]
fn locator_flags(entry: &AddressEntry) -> LocatorFlags {
    LocatorFlags {
        prefix_len: entry.prefix_len.unwrap_or(0),
        scope: address_scope(entry.addr),
        ..LocatorFlags::default()
    }
}

/// Scope derived from the address itself: loopback is host scope,
/// link-local (169.254/16, fe80::/10) is link scope, anything else global.
#[cfg(unix)]
fn address_scope(addr: IpAddr) -> AddressScope {
    match addr {
        IpAddr::V4(v4) => {
            if v4.is_loopback() {
                AddressScope::Host
            } else if v4.is_link_local() {
                AddressScope::Link
            } else {
                AddressScope::Global
            }
        }
        IpAddr::V6(v6) => {
            if v6.is_loopback() {
                AddressScope::Host
            } else if (v6.segments()[0] & 0xffc0) == 0xfe80 {
                AddressScope::Link
            } else {
                AddressScope::Global
            }
        }
    }
}

#[cfg(not(unix))]
fn get_system_addresses(
    _iface_filter: &InterfaceFilter,
    _addr_filter: &AddressFilter,
) -> io::Result<Vec<AddressInfo>> {
    // Stub for non-Unix platforms
    Ok(Vec::new())
}

/// Get system addresses as (IpAddr, interface_name) pairs.
///
/// Public helper for other detectors that need the same functionality.
#[cfg(unix)]
pub fn get_addresses_via_getifaddrs(
    iface_filter: &InterfaceFilter,
    addr_filter: &AddressFilter,
) -> io::Result<Vec<(IpAddr, String)>> {
    let addresses = get_system_addresses(iface_filter, addr_filter)?;
    Ok(addresses
        .into_iter()
        .map(|a| (a.addr, a.interface))
        .collect())
}

#[cfg(not(unix))]
pub fn get_addresses_via_getifaddrs(
    _iface_filter: &InterfaceFilter,
    _addr_filter: &AddressFilter,
) -> io::Result<Vec<(IpAddr, String)>> {
    Ok(Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn addresses_from_snapshot_keeps_label_prefix_and_scope() {
        use std::net::{Ipv4Addr, Ipv6Addr};

        let snap = InterfaceSnapshot::from_addresses(vec![
            AddressEntry::new(
                "lo",
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                Some(8),
                0x49,
                true,
                false,
                None,
            ),
            AddressEntry::new(
                "eth0",
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
                Some(24),
                0x11043,
                false,
                false,
                None,
            ),
            AddressEntry::new(
                "eth0:1",
                IpAddr::V4(Ipv4Addr::new(192, 168, 3, 10)),
                Some(32),
                0x11043,
                false,
                false,
                None,
            ),
            AddressEntry::new(
                "eth0",
                IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
                Some(64),
                0x11043,
                false,
                false,
                None,
            ),
            AddressEntry::new(
                "eth0",
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
                None,
                0x11043,
                false,
                false,
                None,
            ),
        ]);

        let all = addresses_from_snapshot(&snap, &InterfaceFilter::all(), &AddressFilter::all());
        assert_eq!(all.len(), 5);
        // The raw label is the interface name (alias NOT normalised here).
        assert_eq!(all[2].interface, "eth0:1");
        assert_eq!(all[0].flags.prefix_len, 8);
        assert_eq!(all[0].flags.scope, AddressScope::Host);
        assert_eq!(all[1].flags.prefix_len, 24);
        assert_eq!(all[1].flags.scope, AddressScope::Global);
        assert_eq!(all[3].flags.prefix_len, 64);
        assert_eq!(all[3].flags.scope, AddressScope::Link);
        // No netmask reported: prefix 0, as the former walk produced.
        assert_eq!(all[4].flags.prefix_len, 0);
        assert_eq!(all[4].flags.scope, AddressScope::Global);

        // IPv4-only address filter (drops loopback too) and no-loopback
        // interface filter: the two eth0 IPv4 addresses, in order.
        let v4 = addresses_from_snapshot(
            &snap,
            &InterfaceFilter::no_loopback(),
            &AddressFilter::ipv4_only(),
        );
        let v4_addrs: Vec<IpAddr> = v4.iter().map(|a| a.addr).collect();
        assert_eq!(
            v4_addrs,
            vec![
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
                IpAddr::V4(Ipv4Addr::new(192, 168, 3, 10)),
            ]
        );

        // An include filter matches the label as-is: `eth0` does not admit
        // the alias `eth0:1`, exactly as the former walk behaved.
        let only = addresses_from_snapshot(
            &snap,
            &InterfaceFilter::only(vec!["eth0".to_string()]),
            &AddressFilter::all(),
        );
        assert_eq!(only.len(), 3);
        assert!(only.iter().all(|a| a.interface == "eth0"));

        // Empty snapshot: nothing, no error path involved.
        let none = addresses_from_snapshot(
            &InterfaceSnapshot::default(),
            &InterfaceFilter::all(),
            &AddressFilter::all(),
        );
        assert!(none.is_empty());
    }

    #[test]
    fn test_poll_detector_new() {
        let detector = PollIpDetector::new(Duration::from_secs(5));
        assert_eq!(detector.poll_interval(), Duration::from_secs(5));
        assert!(detector.last_poll().is_none());
    }

    #[test]
    fn test_poll_detector_should_poll() {
        let detector = PollIpDetector::new(Duration::from_secs(5));
        assert!(detector.should_poll()); // First poll always allowed

        let mut detector = PollIpDetector::new(Duration::from_millis(10));
        detector.last_poll = Some(Instant::now());
        assert!(!detector.should_poll()); // Too soon

        std::thread::sleep(Duration::from_millis(15));
        assert!(detector.should_poll()); // Enough time passed
    }

    #[test]
    fn test_poll_detector_with_filters() {
        let detector = PollIpDetector::new(Duration::from_secs(5))
            .with_interface_filter(InterfaceFilter::no_loopback())
            .with_address_filter(AddressFilter::ipv4_only());

        assert!(detector.interface_filter.matches("eth0"));
        assert!(!detector.interface_filter.matches("lo"));
    }

    #[test]
    fn test_poll_detector_set_interval() {
        let mut detector = PollIpDetector::new(Duration::from_secs(5));
        detector.set_poll_interval(Duration::from_secs(10));
        assert_eq!(detector.poll_interval(), Duration::from_secs(10));
    }

    #[test]
    fn test_poll_detector_reset() {
        let mut detector = PollIpDetector::new(Duration::from_secs(5));
        detector.last_poll = Some(Instant::now());
        detector.last_snapshot = Some(AddressSnapshot::default());

        detector.reset();
        assert!(detector.last_poll.is_none());
        assert!(detector.last_snapshot.is_none());
    }

    #[test]
    fn test_poll_detector_name() {
        let detector = PollIpDetector::new(Duration::from_secs(5));
        assert_eq!(detector.name(), "poll");
    }

    #[test]
    fn test_poll_detector_is_event_based() {
        let detector = PollIpDetector::new(Duration::from_secs(5));
        assert!(!detector.is_event_based());
    }

    #[test]
    fn test_poll_detector_snapshot() {
        let detector = PollIpDetector::new(Duration::from_secs(5));
        let snapshot = detector.snapshot();
        assert!(snapshot.is_ok());
        // Should have at least loopback on most systems
    }

    #[test]
    fn test_poll_detector_current_addresses() {
        let detector = PollIpDetector::new(Duration::from_secs(5));
        let addresses = detector.current_addresses();
        assert!(addresses.is_ok());
    }

    #[test]
    fn test_poll_detector_force_poll() {
        let mut detector = PollIpDetector::new(Duration::from_secs(5));

        // First poll
        let changes1 = detector.force_poll();
        assert!(changes1.is_ok());
        // First poll should report all addresses as added
        let changes1 = changes1.expect("should get changes");

        // Second poll - no changes expected
        let changes2 = detector.force_poll();
        assert!(changes2.is_ok());
        let changes2 = changes2.expect("should get changes");
        assert!(changes2.is_empty(), "no changes between immediate polls");

        // First poll should have found something (at least loopback on most systems)
        // Note: This may fail in minimal container environments. A first poll
        // diffs against no snapshot, so every change is an add on every platform.
        if !changes1.is_empty() {
            assert!(changes1.iter().all(|c| c.is_add()));
        }
    }

    #[test]
    fn test_compute_changes_no_change() {
        let info = AddressInfo::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1)),
            "eth0".to_string(),
        );
        let prev = AddressSnapshot::new(vec![info.clone()]);
        let curr = AddressSnapshot::new(vec![info]);

        let changes = compute_changes(&prev, &curr);
        assert!(changes.is_empty());
    }

    #[test]
    fn test_compute_changes_added() {
        let info1 = AddressInfo::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1)),
            "eth0".to_string(),
        );
        let info2 = AddressInfo::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 2)),
            "eth0".to_string(),
        );

        let prev = AddressSnapshot::new(vec![info1.clone()]);
        let curr = AddressSnapshot::new(vec![info1, info2]);

        let changes = compute_changes(&prev, &curr);
        assert_eq!(changes.len(), 1);
        assert!(changes[0].is_add());
        assert_eq!(
            changes[0].addr,
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 2))
        );
    }

    #[test]
    fn test_compute_changes_removed() {
        let info1 = AddressInfo::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1)),
            "eth0".to_string(),
        );
        let info2 = AddressInfo::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 2)),
            "eth0".to_string(),
        );

        let prev = AddressSnapshot::new(vec![info1.clone(), info2]);
        let curr = AddressSnapshot::new(vec![info1]);

        let changes = compute_changes(&prev, &curr);
        assert_eq!(changes.len(), 1);
        assert!(changes[0].is_remove());
        assert_eq!(
            changes[0].addr,
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 2))
        );
    }

    #[test]
    fn test_compute_changes_mixed() {
        let info1 = AddressInfo::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1)),
            "eth0".to_string(),
        );
        let info2 = AddressInfo::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 2)),
            "eth0".to_string(),
        );
        let info3 = AddressInfo::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 3)),
            "eth0".to_string(),
        );

        // prev: 1, 2
        // curr: 1, 3
        // => removed: 2, added: 3
        let prev = AddressSnapshot::new(vec![info1.clone(), info2]);
        let curr = AddressSnapshot::new(vec![info1, info3]);

        let changes = compute_changes(&prev, &curr);
        assert_eq!(changes.len(), 2);

        let removed: Vec<_> = changes.iter().filter(|c| c.is_remove()).collect();
        let added: Vec<_> = changes.iter().filter(|c| c.is_add()).collect();

        assert_eq!(removed.len(), 1);
        assert_eq!(added.len(), 1);
    }

    #[test]
    fn test_poll_detector_respects_interval() {
        let mut detector = PollIpDetector::new(Duration::from_secs(60));

        // First poll always happens
        let _ = detector.poll_changes().expect("should poll");
        assert!(detector.last_poll.is_some());

        // Second poll should return empty (interval not elapsed)
        let changes = detector.poll_changes().expect("should work");
        assert!(changes.is_empty());
    }
}
