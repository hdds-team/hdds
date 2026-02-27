// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Poll-based IP address detector using getifaddrs.

use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use super::config::{AddressFilter, InterfaceFilter};
use super::detector::{AddressInfo, AddressSnapshot, IpDetector, LocatorChange, LocatorFlags};

/// Poll-based IP address detector.
///
/// Uses getifaddrs (or platform equivalent) to periodically check for
/// IP address changes. Cross-platform but less efficient than event-based
/// detection.
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

/// Get system IP addresses using platform-specific APIs.
#[cfg(unix)]
fn get_system_addresses(
    iface_filter: &InterfaceFilter,
    addr_filter: &AddressFilter,
) -> io::Result<Vec<AddressInfo>> {
    use std::ffi::CStr;

    let mut addresses = Vec::new();
    let mut ifaddrs: *mut libc::ifaddrs = std::ptr::null_mut();

    // SAFETY:
    // - `ifaddrs` is a valid pointer to a null pointer, which getifaddrs will populate
    // - getifaddrs is a standard POSIX function that allocates and returns a linked list
    // - The returned list must be freed with freeifaddrs (done at end of function)
    let ret = unsafe { libc::getifaddrs(&mut ifaddrs) };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }

    let mut ifa = ifaddrs;
    while !ifa.is_null() {
        // SAFETY:
        // - `ifa` is checked to be non-null in the while condition
        // - The pointer comes from getifaddrs which returns valid ifaddrs structures
        // - The structure remains valid until freeifaddrs is called
        let entry = unsafe { &*ifa };

        // Get interface name
        // SAFETY:
        // - `entry.ifa_name` is guaranteed non-null and NUL-terminated by getifaddrs
        // - The string data is valid for the lifetime of the ifaddrs list
        // - We immediately convert to owned String, so no lifetime issues
        let iface_name = unsafe { CStr::from_ptr(entry.ifa_name) }
            .to_string_lossy()
            .into_owned();

        // Check interface filter
        if iface_filter.matches(&iface_name) {
            // Get address
            if !entry.ifa_addr.is_null() {
                // SAFETY:
                // - `entry.ifa_addr` is checked non-null above
                // - The sockaddr is allocated by getifaddrs and valid until freeifaddrs
                // - We only read sa_family to determine address type
                let addr = unsafe { &*entry.ifa_addr };

                let ip_addr = match addr.sa_family as i32 {
                    libc::AF_INET => {
                        let sockaddr_in = entry.ifa_addr as *const libc::sockaddr_in;
                        // SAFETY:
                        // - sa_family == AF_INET guarantees this is a sockaddr_in structure
                        // - The pointer is valid as it comes from getifaddrs
                        // - sockaddr_in is properly aligned (same as sockaddr)
                        let ip = unsafe { (*sockaddr_in).sin_addr.s_addr };
                        Some(IpAddr::V4(std::net::Ipv4Addr::from(u32::from_be(ip))))
                    }
                    libc::AF_INET6 => {
                        let sockaddr_in6 = entry.ifa_addr as *const libc::sockaddr_in6;
                        // SAFETY:
                        // - sa_family == AF_INET6 guarantees this is a sockaddr_in6 structure
                        // - The pointer is valid as it comes from getifaddrs
                        // - sockaddr_in6 is properly aligned (same as sockaddr)
                        let ip = unsafe { (*sockaddr_in6).sin6_addr.s6_addr };
                        Some(IpAddr::V6(std::net::Ipv6Addr::from(ip)))
                    }
                    _ => None,
                };

                if let Some(ip) = ip_addr {
                    // Check address filter
                    if addr_filter.matches(&ip) {
                        let flags = extract_flags(entry, &ip);
                        addresses.push(AddressInfo::new(ip, iface_name).with_flags(flags));
                    }
                }
            }
        }

        ifa = entry.ifa_next;
    }

    // SAFETY:
    // - `ifaddrs` is the pointer returned by getifaddrs at the start of the function
    // - The pointer is still valid (not freed yet)
    // - freeifaddrs is the correct function to free memory allocated by getifaddrs
    unsafe { libc::freeifaddrs(ifaddrs) };

    Ok(addresses)
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

/// Extract flags from ifaddrs entry.
#[cfg(unix)]
fn extract_flags(entry: &libc::ifaddrs, addr: &IpAddr) -> LocatorFlags {
    use super::detector::AddressScope;

    let mut flags = LocatorFlags::default();

    // Get netmask for prefix length
    if !entry.ifa_netmask.is_null() {
        // SAFETY:
        // - `entry.ifa_netmask` is checked non-null above
        // - The sockaddr is allocated by getifaddrs and valid until freeifaddrs
        // - We only read sa_family to determine the netmask type
        let mask = unsafe { &*entry.ifa_netmask };
        match mask.sa_family as i32 {
            libc::AF_INET => {
                let sockaddr_in = entry.ifa_netmask as *const libc::sockaddr_in;
                // SAFETY:
                // - sa_family == AF_INET guarantees this is a sockaddr_in structure
                // - The pointer is valid as it comes from getifaddrs
                // - sockaddr_in is properly aligned (same alignment as sockaddr)
                let mask_bits = unsafe { (*sockaddr_in).sin_addr.s_addr };
                flags.prefix_len = u32::from_be(mask_bits).count_ones() as u8;
            }
            libc::AF_INET6 => {
                let sockaddr_in6 = entry.ifa_netmask as *const libc::sockaddr_in6;
                // SAFETY:
                // - sa_family == AF_INET6 guarantees this is a sockaddr_in6 structure
                // - The pointer is valid as it comes from getifaddrs
                // - sockaddr_in6 is properly aligned (same alignment as sockaddr)
                let mask_bytes = unsafe { (*sockaddr_in6).sin6_addr.s6_addr };
                flags.prefix_len = mask_bytes.iter().map(|b| b.count_ones() as u8).sum();
            }
            _ => {}
        }
    }

    // Determine scope from address
    flags.scope = match addr {
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
    };

    flags
}

#[cfg(test)]
mod tests {
    use super::*;

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
        // Note: This may fail in minimal container environments
        #[cfg(unix)]
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
