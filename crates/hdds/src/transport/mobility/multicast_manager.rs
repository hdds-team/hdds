// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Multicast membership management for IP mobility.
//!
//! Handles joining and leaving multicast groups as network interfaces
//! come and go. Ensures discovery multicast is properly maintained
//! across interface changes.

use std::collections::{HashMap, HashSet};
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, UdpSocket};
#[cfg(unix)]
use std::os::unix::io::AsRawFd;

/// Multicast group membership manager.
///
/// Tracks which multicast groups are joined on which interfaces,
/// and handles automatic join/leave when interfaces change.
pub struct MulticastManager {
    /// Discovery multicast groups (IPv4).
    discovery_groups_v4: Vec<Ipv4Addr>,

    /// Discovery multicast groups (IPv6).
    discovery_groups_v6: Vec<Ipv6Addr>,

    /// Current memberships: interface_index -> groups joined.
    memberships_v4: HashMap<u32, HashSet<Ipv4Addr>>,

    /// IPv6 memberships.
    memberships_v6: HashMap<u32, HashSet<Ipv6Addr>>,

    /// Interfaces we've seen.
    known_interfaces: HashMap<String, u32>,
}

impl MulticastManager {
    /// Create a new multicast manager.
    pub fn new() -> Self {
        Self {
            discovery_groups_v4: Vec::new(),
            discovery_groups_v6: Vec::new(),
            memberships_v4: HashMap::new(),
            memberships_v6: HashMap::new(),
            known_interfaces: HashMap::new(),
        }
    }

    /// Add a discovery multicast group (IPv4).
    pub fn add_discovery_group_v4(&mut self, group: Ipv4Addr) {
        if !self.discovery_groups_v4.contains(&group) {
            self.discovery_groups_v4.push(group);
        }
    }

    /// Add a discovery multicast group (IPv6).
    pub fn add_discovery_group_v6(&mut self, group: Ipv6Addr) {
        if !self.discovery_groups_v6.contains(&group) {
            self.discovery_groups_v6.push(group);
        }
    }

    /// Set standard DDS discovery groups.
    pub fn with_dds_discovery_groups(mut self, domain_id: u32) -> Self {
        // Standard DDS multicast: 239.255.0.1 for SPDP
        self.discovery_groups_v4.push(Ipv4Addr::new(239, 255, 0, 1));

        // User traffic multicast (if enabled)
        let d0 = (domain_id / 250) as u8;
        let d1 = (domain_id % 250) as u8;
        self.discovery_groups_v4
            .push(Ipv4Addr::new(239, 255, d0, d1 + 1));

        self
    }

    /// Called when an interface is added or comes up.
    pub fn on_interface_added(&mut self, socket: &UdpSocket, iface: &str) -> io::Result<usize> {
        let if_index = get_interface_index(iface)?;
        self.known_interfaces.insert(iface.to_string(), if_index);

        let mut joined = 0;

        // Clone groups to avoid borrow conflict
        let groups_v4 = self.discovery_groups_v4.clone();
        let groups_v6 = self.discovery_groups_v6.clone();

        // Join IPv4 groups
        for group in groups_v4 {
            if self.join_multicast_v4(socket, group, if_index).is_ok() {
                joined += 1;
            }
        }

        // Join IPv6 groups
        for group in groups_v6 {
            if self.join_multicast_v6(socket, group, if_index).is_ok() {
                joined += 1;
            }
        }

        Ok(joined)
    }

    /// Called when an interface is removed or goes down.
    pub fn on_interface_removed(&mut self, socket: &UdpSocket, iface: &str) -> io::Result<usize> {
        let if_index = match self.known_interfaces.remove(iface) {
            Some(idx) => idx,
            None => return Ok(0),
        };

        let mut left = 0;

        // Leave IPv4 groups
        if let Some(groups) = self.memberships_v4.remove(&if_index) {
            for group in groups {
                if self.leave_multicast_v4(socket, group, if_index).is_ok() {
                    left += 1;
                }
            }
        }

        // Leave IPv6 groups
        if let Some(groups) = self.memberships_v6.remove(&if_index) {
            for group in groups {
                if self.leave_multicast_v6(socket, group, if_index).is_ok() {
                    left += 1;
                }
            }
        }

        Ok(left)
    }

    /// Join an IPv4 multicast group.
    fn join_multicast_v4(
        &mut self,
        socket: &UdpSocket,
        group: Ipv4Addr,
        if_index: u32,
    ) -> io::Result<()> {
        let mreqn = libc::ip_mreqn {
            imr_multiaddr: libc::in_addr {
                s_addr: u32::from_ne_bytes(group.octets()),
            },
            imr_address: libc::in_addr { s_addr: 0 },
            imr_ifindex: if_index as i32,
        };

        // SAFETY:
        // - socket.as_raw_fd() returns a valid socket file descriptor
        // - mreqn is a properly initialized ip_mreqn structure on the stack
        // - IP_ADD_MEMBERSHIP is a valid socket option for joining multicast groups
        // - The option length matches the ip_mreqn structure size
        let ret = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::IPPROTO_IP,
                libc::IP_ADD_MEMBERSHIP,
                &mreqn as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::ip_mreqn>() as libc::socklen_t,
            )
        };

        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        self.memberships_v4
            .entry(if_index)
            .or_default()
            .insert(group);

        Ok(())
    }

    /// Leave an IPv4 multicast group.
    fn leave_multicast_v4(
        &mut self,
        socket: &UdpSocket,
        group: Ipv4Addr,
        if_index: u32,
    ) -> io::Result<()> {
        let mreqn = libc::ip_mreqn {
            imr_multiaddr: libc::in_addr {
                s_addr: u32::from_ne_bytes(group.octets()),
            },
            imr_address: libc::in_addr { s_addr: 0 },
            imr_ifindex: if_index as i32,
        };

        // SAFETY:
        // - socket.as_raw_fd() returns a valid socket file descriptor
        // - mreqn is a properly initialized ip_mreqn structure on the stack
        // - IP_DROP_MEMBERSHIP is a valid socket option for leaving multicast groups
        // - The option length matches the ip_mreqn structure size
        let ret = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::IPPROTO_IP,
                libc::IP_DROP_MEMBERSHIP,
                &mreqn as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::ip_mreqn>() as libc::socklen_t,
            )
        };

        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        if let Some(groups) = self.memberships_v4.get_mut(&if_index) {
            groups.remove(&group);
        }

        Ok(())
    }

    /// Join an IPv6 multicast group.
    fn join_multicast_v6(
        &mut self,
        socket: &UdpSocket,
        group: Ipv6Addr,
        if_index: u32,
    ) -> io::Result<()> {
        let mreq = libc::ipv6_mreq {
            ipv6mr_multiaddr: libc::in6_addr {
                s6_addr: group.octets(),
            },
            ipv6mr_interface: if_index,
        };

        // SAFETY:
        // - socket.as_raw_fd() returns a valid socket file descriptor
        // - mreq is a properly initialized ipv6_mreq structure on the stack
        // - IPV6_ADD_MEMBERSHIP is a valid socket option for joining IPv6 multicast groups
        // - The option length matches the ipv6_mreq structure size
        let ret = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::IPPROTO_IPV6,
                libc::IPV6_ADD_MEMBERSHIP,
                &mreq as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::ipv6_mreq>() as libc::socklen_t,
            )
        };

        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        self.memberships_v6
            .entry(if_index)
            .or_default()
            .insert(group);

        Ok(())
    }

    /// Leave an IPv6 multicast group.
    fn leave_multicast_v6(
        &mut self,
        socket: &UdpSocket,
        group: Ipv6Addr,
        if_index: u32,
    ) -> io::Result<()> {
        let mreq = libc::ipv6_mreq {
            ipv6mr_multiaddr: libc::in6_addr {
                s6_addr: group.octets(),
            },
            ipv6mr_interface: if_index,
        };

        // SAFETY:
        // - socket.as_raw_fd() returns a valid socket file descriptor
        // - mreq is a properly initialized ipv6_mreq structure on the stack
        // - IPV6_DROP_MEMBERSHIP is a valid socket option for leaving IPv6 multicast groups
        // - The option length matches the ipv6_mreq structure size
        let ret = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::IPPROTO_IPV6,
                libc::IPV6_DROP_MEMBERSHIP,
                &mreq as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::ipv6_mreq>() as libc::socklen_t,
            )
        };

        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        if let Some(groups) = self.memberships_v6.get_mut(&if_index) {
            groups.remove(&group);
        }

        Ok(())
    }

    /// Get number of active memberships.
    pub fn membership_count(&self) -> usize {
        let v4_count: usize = self.memberships_v4.values().map(|s| s.len()).sum();
        let v6_count: usize = self.memberships_v6.values().map(|s| s.len()).sum();
        v4_count + v6_count
    }

    /// Get interfaces with memberships.
    pub fn active_interfaces(&self) -> Vec<&str> {
        self.known_interfaces.keys().map(|s| s.as_str()).collect()
    }

    /// Check if a group is joined on any interface.
    pub fn is_group_joined_v4(&self, group: &Ipv4Addr) -> bool {
        self.memberships_v4.values().any(|s| s.contains(group))
    }

    /// Check if a group is joined on a specific interface.
    pub fn is_group_joined_on_interface_v4(&self, group: &Ipv4Addr, iface: &str) -> bool {
        if let Some(if_index) = self.known_interfaces.get(iface) {
            if let Some(groups) = self.memberships_v4.get(if_index) {
                return groups.contains(group);
            }
        }
        false
    }

    /// Get statistics.
    pub fn stats(&self) -> MulticastStats {
        MulticastStats {
            groups_v4: self.discovery_groups_v4.len(),
            groups_v6: self.discovery_groups_v6.len(),
            interfaces: self.known_interfaces.len(),
            memberships_v4: self.memberships_v4.values().map(|s| s.len()).sum(),
            memberships_v6: self.memberships_v6.values().map(|s| s.len()).sum(),
        }
    }

    /// Clear all memberships (for shutdown).
    pub fn clear(&mut self) {
        self.memberships_v4.clear();
        self.memberships_v6.clear();
        self.known_interfaces.clear();
    }
}

impl Default for MulticastManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Get interface index from name.
pub fn get_interface_index(name: &str) -> io::Result<u32> {
    let c_name = std::ffi::CString::new(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid interface name"))?;

    // SAFETY:
    // - c_name is a valid NUL-terminated CString
    // - if_nametoindex is a standard POSIX function that reads the string
    // - Returns 0 on error (checked below), or valid interface index
    let index = unsafe { libc::if_nametoindex(c_name.as_ptr()) };

    if index == 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(index)
}

/// Get interface name from index.
pub fn get_interface_name(index: u32) -> io::Result<String> {
    let mut buf = [0u8; libc::IF_NAMESIZE];
    // SAFETY:
    // - index is an interface index (validity checked by kernel)
    // - buf is a properly sized buffer (IF_NAMESIZE bytes) for the interface name
    // - if_indextoname writes at most IF_NAMESIZE bytes including NUL terminator
    let result = unsafe { libc::if_indextoname(index, buf.as_mut_ptr() as *mut libc::c_char) };

    if result.is_null() {
        return Err(io::Error::last_os_error());
    }

    // SAFETY:
    // - result is non-null (checked above), pointing to buf
    // - if_indextoname guarantees NUL-terminated string on success
    // - buf is valid for the duration of this block
    let name = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr() as *const libc::c_char) }
        .to_string_lossy()
        .into_owned();

    Ok(name)
}

/// Multicast manager statistics.
#[derive(Clone, Copy, Debug, Default)]
pub struct MulticastStats {
    /// Number of IPv4 discovery groups configured.
    pub groups_v4: usize,
    /// Number of IPv6 discovery groups configured.
    pub groups_v6: usize,
    /// Number of known interfaces.
    pub interfaces: usize,
    /// Total IPv4 memberships.
    pub memberships_v4: usize,
    /// Total IPv6 memberships.
    pub memberships_v6: usize,
}

impl MulticastStats {
    /// Total memberships.
    pub fn total_memberships(&self) -> usize {
        self.memberships_v4 + self.memberships_v6
    }

    /// Total configured groups.
    pub fn total_groups(&self) -> usize {
        self.groups_v4 + self.groups_v6
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_multicast_manager_new() {
        let manager = MulticastManager::new();
        assert_eq!(manager.membership_count(), 0);
        assert!(manager.active_interfaces().is_empty());
    }

    #[test]
    fn test_multicast_manager_add_groups() {
        let mut manager = MulticastManager::new();
        manager.add_discovery_group_v4(Ipv4Addr::new(239, 255, 0, 1));
        manager.add_discovery_group_v4(Ipv4Addr::new(239, 255, 0, 2));
        manager.add_discovery_group_v6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb));

        assert_eq!(manager.discovery_groups_v4.len(), 2);
        assert_eq!(manager.discovery_groups_v6.len(), 1);
    }

    #[test]
    fn test_multicast_manager_add_duplicate_group() {
        let mut manager = MulticastManager::new();
        manager.add_discovery_group_v4(Ipv4Addr::new(239, 255, 0, 1));
        manager.add_discovery_group_v4(Ipv4Addr::new(239, 255, 0, 1)); // Duplicate

        assert_eq!(manager.discovery_groups_v4.len(), 1);
    }

    #[test]
    fn test_multicast_manager_with_dds_discovery() {
        let manager = MulticastManager::new().with_dds_discovery_groups(0);

        assert_eq!(manager.discovery_groups_v4.len(), 2);
        assert!(manager
            .discovery_groups_v4
            .contains(&Ipv4Addr::new(239, 255, 0, 1)));
    }

    #[test]
    fn test_multicast_manager_stats() {
        let mut manager = MulticastManager::new();
        manager.add_discovery_group_v4(Ipv4Addr::new(239, 255, 0, 1));
        manager.add_discovery_group_v6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1));

        let stats = manager.stats();
        assert_eq!(stats.groups_v4, 1);
        assert_eq!(stats.groups_v6, 1);
        assert_eq!(stats.total_groups(), 2);
        assert_eq!(stats.interfaces, 0);
    }

    #[test]
    fn test_multicast_manager_clear() {
        let mut manager = MulticastManager::new();
        manager.add_discovery_group_v4(Ipv4Addr::new(239, 255, 0, 1));
        manager.known_interfaces.insert("eth0".to_string(), 2);

        manager.clear();
        assert!(manager.known_interfaces.is_empty());
        assert!(manager.memberships_v4.is_empty());
    }

    #[test]
    fn test_multicast_stats_default() {
        let stats = MulticastStats::default();
        assert_eq!(stats.total_memberships(), 0);
        assert_eq!(stats.total_groups(), 0);
    }

    #[test]
    fn test_get_interface_index_loopback() {
        // Loopback should exist on all systems
        let result = get_interface_index("lo");
        assert!(result.is_ok());
        assert!(result.expect("should get index") > 0);
    }

    #[test]
    fn test_get_interface_index_invalid() {
        let result = get_interface_index("nonexistent_interface_12345");
        assert!(result.is_err());
    }

    #[test]
    fn test_get_interface_name() {
        // Get loopback index first
        let index = get_interface_index("lo").expect("should get lo index");
        let name = get_interface_name(index).expect("should get name");
        assert_eq!(name, "lo");
    }

    #[test]
    fn test_get_interface_name_invalid() {
        let result = get_interface_name(99999);
        assert!(result.is_err());
    }

    #[test]
    fn test_is_group_joined_empty() {
        let manager = MulticastManager::new();
        let group = Ipv4Addr::new(239, 255, 0, 1);
        assert!(!manager.is_group_joined_v4(&group));
    }

    #[test]
    fn test_is_group_joined_on_interface_empty() {
        let manager = MulticastManager::new();
        let group = Ipv4Addr::new(239, 255, 0, 1);
        assert!(!manager.is_group_joined_on_interface_v4(&group, "eth0"));
    }
}
