// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Netlink-based IP address detector for Linux.
//!
//! Uses rtnetlink to receive real-time notifications of IP address changes
//! (RTM_NEWADDR, RTM_DELADDR) without polling.

use std::collections::VecDeque;
use std::io;
use std::net::IpAddr;
use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Instant;

use super::config::{AddressFilter, InterfaceFilter};
use super::detector::{AddressScope, IpDetector, LocatorChange, LocatorChangeKind, LocatorFlags};

// Netlink constants
const NETLINK_ROUTE: i32 = 0;

// Netlink message types
const RTM_NEWADDR: u16 = 20;
const RTM_DELADDR: u16 = 21;
const RTM_NEWLINK: u16 = 16;
const RTM_DELLINK: u16 = 17;

// Multicast groups for rtnetlink
const RTMGRP_LINK: u32 = 1;
const RTMGRP_IPV4_IFADDR: u32 = 0x10;
const RTMGRP_IPV6_IFADDR: u32 = 0x100;

// Address attributes
const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;
const IFA_LABEL: u16 = 3;

// Address scopes
const RT_SCOPE_UNIVERSE: u8 = 0;
const RT_SCOPE_SITE: u8 = 200;
const RT_SCOPE_LINK: u8 = 253;
const RT_SCOPE_HOST: u8 = 254;

/// Netlink message header.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct NlMsgHdr {
    nlmsg_len: u32,
    nlmsg_type: u16,
    nlmsg_flags: u16,
    nlmsg_seq: u32,
    nlmsg_pid: u32,
}

/// Interface address message header.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct IfAddrMsg {
    ifa_family: u8,
    ifa_prefixlen: u8,
    ifa_flags: u8,
    ifa_scope: u8,
    ifa_index: u32,
}

/// Netlink attribute header.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct RtAttr {
    rta_len: u16,
    rta_type: u16,
}

/// Netlink-based IP detector.
///
/// Uses rtnetlink socket to receive RTM_NEWADDR and RTM_DELADDR events
/// in real-time without polling.
pub struct NetlinkIpDetector {
    /// Netlink socket file descriptor.
    socket_fd: RawFd,

    /// Thread handle for background listener.
    thread_handle: Option<JoinHandle<()>>,

    /// Stop flag for background thread.
    stop_flag: Arc<AtomicBool>,

    /// Queue of pending changes.
    pending_changes: Arc<Mutex<VecDeque<LocatorChange>>>,

    /// Interface filter.
    interface_filter: InterfaceFilter,

    /// Address filter.
    address_filter: AddressFilter,

    /// Last time we returned changes.
    last_poll: Option<Instant>,

    /// Interface index to name cache.
    if_cache: Arc<Mutex<std::collections::HashMap<u32, String>>>,
}

impl NetlinkIpDetector {
    /// Create a new netlink detector.
    pub fn new() -> io::Result<Self> {
        let socket_fd = create_netlink_socket()?;

        Ok(Self {
            socket_fd,
            thread_handle: None,
            stop_flag: Arc::new(AtomicBool::new(false)),
            pending_changes: Arc::new(Mutex::new(VecDeque::new())),
            interface_filter: InterfaceFilter::default(),
            address_filter: AddressFilter::all(),
            last_poll: None,
            if_cache: Arc::new(Mutex::new(std::collections::HashMap::new())),
        })
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

    /// Start the background listener thread.
    pub fn start(&mut self) -> io::Result<()> {
        if self.thread_handle.is_some() {
            return Ok(()); // Already running
        }

        let socket_fd = self.socket_fd;
        let stop_flag = self.stop_flag.clone();
        let pending = self.pending_changes.clone();
        let if_cache = self.if_cache.clone();
        let iface_filter = self.interface_filter.clone();
        let addr_filter = self.address_filter.clone();

        let handle = thread::Builder::new()
            .name("hdds-netlink".to_string())
            .spawn(move || {
                netlink_loop(
                    socket_fd,
                    stop_flag,
                    pending,
                    if_cache,
                    iface_filter,
                    addr_filter,
                );
            })?;

        self.thread_handle = Some(handle);
        Ok(())
    }

    /// Stop the background listener thread.
    pub fn stop(&mut self) {
        self.stop_flag.store(true, Ordering::SeqCst);

        // Interrupt the socket read
        if self.socket_fd >= 0 {
            // SAFETY:
            // - socket_fd is a valid file descriptor obtained from socket() call
            // - shutdown is safe to call on any valid socket fd
            // - SHUT_RDWR is a valid shutdown mode constant
            unsafe {
                libc::shutdown(self.socket_fd, libc::SHUT_RDWR);
            }
        }

        if let Some(handle) = self.thread_handle.take() {
            let _ = handle.join();
        }
    }

    /// Check if the listener is running.
    pub fn is_running(&self) -> bool {
        self.thread_handle.is_some() && !self.stop_flag.load(Ordering::SeqCst)
    }

    /// Get the number of pending changes.
    pub fn pending_count(&self) -> usize {
        self.pending_changes.lock().map(|q| q.len()).unwrap_or(0)
    }

    /// Drain all pending changes.
    fn drain_changes(&self) -> Vec<LocatorChange> {
        self.pending_changes
            .lock()
            .map(|mut q| q.drain(..).collect())
            .unwrap_or_default()
    }
}

// Note: No Default impl - NetlinkIpDetector::new() returns Result
// and we avoid expect() in production code.

impl Drop for NetlinkIpDetector {
    fn drop(&mut self) {
        self.stop();
        if self.socket_fd >= 0 {
            // SAFETY:
            // - socket_fd is a valid file descriptor obtained from socket() call
            // - close is safe to call on any valid file descriptor
            // - The fd is only closed once (in Drop), preventing double-close
            unsafe {
                libc::close(self.socket_fd);
            }
        }
    }
}

impl IpDetector for NetlinkIpDetector {
    fn poll_changes(&mut self) -> io::Result<Vec<LocatorChange>> {
        self.last_poll = Some(Instant::now());

        // Start listener if not running
        if !self.is_running() && !self.stop_flag.load(Ordering::SeqCst) {
            self.start()?;
        }

        Ok(self.drain_changes())
    }

    fn current_addresses(&self) -> io::Result<Vec<(IpAddr, String)>> {
        // Use getifaddrs for current state
        super::detector_poll::get_addresses_via_getifaddrs(
            &self.interface_filter,
            &self.address_filter,
        )
    }

    fn name(&self) -> &str {
        "netlink"
    }

    fn is_event_based(&self) -> bool {
        true
    }
}

/// Create and bind a netlink socket for rtnetlink events.
fn create_netlink_socket() -> io::Result<RawFd> {
    // SAFETY:
    // - AF_NETLINK, SOCK_RAW, and NETLINK_ROUTE are valid socket parameters
    // - socket() is a standard libc function that returns a valid fd or -1 on error
    // - The returned fd is owned by this function and will be managed by the caller
    let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, NETLINK_ROUTE) };

    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    // Bind to multicast groups
    let groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR;

    #[repr(C)]
    struct SockaddrNl {
        nl_family: u16,
        nl_pad: u16,
        nl_pid: u32,
        nl_groups: u32,
    }

    let addr = SockaddrNl {
        nl_family: libc::AF_NETLINK as u16,
        nl_pad: 0,
        nl_pid: 0, // Let kernel assign
        nl_groups: groups,
    };

    // SAFETY:
    // - fd is a valid netlink socket file descriptor (checked above)
    // - addr is a properly initialized SockaddrNl structure on the stack
    // - The size matches the actual structure size
    // - bind() is safe to call with valid socket and address
    let ret = unsafe {
        libc::bind(
            fd,
            &addr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<SockaddrNl>() as libc::socklen_t,
        )
    };

    if ret < 0 {
        // SAFETY: fd is a valid socket that needs cleanup on bind failure
        unsafe { libc::close(fd) };
        return Err(io::Error::last_os_error());
    }

    // Set receive timeout for graceful shutdown
    let timeout = libc::timeval {
        tv_sec: 1,
        tv_usec: 0,
    };

    // SAFETY:
    // - fd is a valid bound netlink socket
    // - timeout is a properly initialized timeval structure on the stack
    // - SO_RCVTIMEO is a valid socket option for setting receive timeout
    // - The option length matches the timeval structure size
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &timeout as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        );
    }

    Ok(fd)
}

/// Background netlink listener loop.
fn netlink_loop(
    socket_fd: RawFd,
    stop_flag: Arc<AtomicBool>,
    pending: Arc<Mutex<VecDeque<LocatorChange>>>,
    if_cache: Arc<Mutex<std::collections::HashMap<u32, String>>>,
    iface_filter: InterfaceFilter,
    addr_filter: AddressFilter,
) {
    let mut buf = vec![0u8; 8192];

    while !stop_flag.load(Ordering::SeqCst) {
        // SAFETY:
        // - socket_fd is a valid netlink socket passed from the detector
        // - buf is a valid mutable slice with known length (8192 bytes)
        // - recv() will write at most buf.len() bytes into the buffer
        // - The flags parameter 0 means no special behavior
        let n = unsafe { libc::recv(socket_fd, buf.as_mut_ptr() as *mut _, buf.len(), 0) };

        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::WouldBlock
                || err.kind() == io::ErrorKind::TimedOut
                || err.kind() == io::ErrorKind::Interrupted
            {
                continue;
            }
            // Socket closed or error
            break;
        }

        if n == 0 {
            continue;
        }

        // Parse netlink messages
        let changes =
            parse_netlink_messages(&buf[..n as usize], &if_cache, &iface_filter, &addr_filter);

        if !changes.is_empty() {
            if let Ok(mut q) = pending.lock() {
                q.extend(changes);
                // Limit queue size
                while q.len() > 1000 {
                    q.pop_front();
                }
            }
        }
    }
}

/// Parse netlink messages from buffer.
fn parse_netlink_messages(
    data: &[u8],
    if_cache: &Arc<Mutex<std::collections::HashMap<u32, String>>>,
    iface_filter: &InterfaceFilter,
    addr_filter: &AddressFilter,
) -> Vec<LocatorChange> {
    let mut changes = Vec::new();
    let mut offset = 0;

    while offset + std::mem::size_of::<NlMsgHdr>() <= data.len() {
        // SAFETY:
        // - The bounds check above ensures at least sizeof(NlMsgHdr) bytes are available
        // - read_unaligned handles any alignment issues with the netlink message
        // - NlMsgHdr is a repr(C) struct matching the kernel netlink header layout
        let hdr: NlMsgHdr =
            unsafe { std::ptr::read_unaligned(data[offset..].as_ptr() as *const NlMsgHdr) };

        if hdr.nlmsg_len < std::mem::size_of::<NlMsgHdr>() as u32 {
            break;
        }

        let msg_end = offset + hdr.nlmsg_len as usize;
        if msg_end > data.len() {
            break;
        }

        let payload_offset = offset + std::mem::size_of::<NlMsgHdr>();

        match hdr.nlmsg_type {
            RTM_NEWADDR | RTM_DELADDR => {
                if let Some(change) = parse_addr_message(
                    &data[payload_offset..msg_end],
                    hdr.nlmsg_type == RTM_NEWADDR,
                    if_cache,
                    iface_filter,
                    addr_filter,
                ) {
                    changes.push(change);
                }
            }
            RTM_NEWLINK | RTM_DELLINK => {
                // Update interface cache on link changes
                update_interface_cache(&data[payload_offset..msg_end], if_cache);
            }
            _ => {}
        }

        // Align to next message
        offset = (msg_end + 3) & !3;
    }

    changes
}

/// Parse an RTM_NEWADDR or RTM_DELADDR message.
fn parse_addr_message(
    data: &[u8],
    is_add: bool,
    if_cache: &Arc<Mutex<std::collections::HashMap<u32, String>>>,
    iface_filter: &InterfaceFilter,
    addr_filter: &AddressFilter,
) -> Option<LocatorChange> {
    if data.len() < std::mem::size_of::<IfAddrMsg>() {
        return None;
    }

    // SAFETY:
    // - The bounds check above ensures at least sizeof(IfAddrMsg) bytes are available
    // - read_unaligned handles any alignment issues with the netlink message payload
    // - IfAddrMsg is a repr(C) struct matching the kernel ifaddrmsg layout
    let msg: IfAddrMsg = unsafe { std::ptr::read_unaligned(data.as_ptr() as *const IfAddrMsg) };

    // Get interface name
    let if_name = get_interface_name(msg.ifa_index, if_cache)?;

    // Check interface filter
    if !iface_filter.matches(&if_name) {
        return None;
    }

    // Parse attributes
    let attrs_offset = std::mem::size_of::<IfAddrMsg>();
    let (addr, label) = parse_addr_attrs(&data[attrs_offset..], msg.ifa_family)?;

    // Use label if available, otherwise interface name
    let interface = if !label.is_empty() { label } else { if_name };

    // Check address filter
    if !addr_filter.matches(&addr) {
        return None;
    }

    let kind = if is_add {
        LocatorChangeKind::Added
    } else {
        LocatorChangeKind::Removed
    };

    let flags = LocatorFlags {
        prefix_len: msg.ifa_prefixlen,
        scope: scope_to_address_scope(msg.ifa_scope),
        temporary: (msg.ifa_flags & 0x01) != 0, // IFA_F_SECONDARY
        deprecated: (msg.ifa_flags & 0x20) != 0, // IFA_F_DEPRECATED
        tentative: (msg.ifa_flags & 0x40) != 0, // IFA_F_TENTATIVE
    };

    Some(LocatorChange::new(addr, interface, kind).with_flags(flags))
}

/// Parse address attributes.
fn parse_addr_attrs(data: &[u8], family: u8) -> Option<(IpAddr, String)> {
    let mut addr: Option<IpAddr> = None;
    let mut label = String::new();
    let mut offset = 0;

    while offset + std::mem::size_of::<RtAttr>() <= data.len() {
        // SAFETY:
        // - The bounds check above ensures at least sizeof(RtAttr) bytes are available
        // - read_unaligned handles any alignment issues with the rtnetlink attribute
        // - RtAttr is a repr(C) struct matching the kernel rtattr layout
        let attr: RtAttr =
            unsafe { std::ptr::read_unaligned(data[offset..].as_ptr() as *const RtAttr) };

        if attr.rta_len < std::mem::size_of::<RtAttr>() as u16 {
            break;
        }

        let attr_data_start = offset + std::mem::size_of::<RtAttr>();
        let attr_data_len = attr.rta_len as usize - std::mem::size_of::<RtAttr>();
        let attr_end = offset + attr.rta_len as usize;

        if attr_end > data.len() {
            break;
        }

        match attr.rta_type {
            IFA_ADDRESS | IFA_LOCAL => {
                // Prefer IFA_LOCAL for IPv4, IFA_ADDRESS for IPv6
                if addr.is_none() || (family == libc::AF_INET as u8 && attr.rta_type == IFA_LOCAL) {
                    addr = parse_ip_from_bytes(
                        &data[attr_data_start..attr_data_start + attr_data_len],
                        family,
                    );
                }
            }
            IFA_LABEL => {
                if let Ok(s) =
                    std::str::from_utf8(&data[attr_data_start..attr_data_start + attr_data_len])
                {
                    label = s.trim_end_matches('\0').to_string();
                }
            }
            _ => {}
        }

        // Align to 4 bytes
        offset = (attr_end + 3) & !3;
    }

    addr.map(|a| (a, label))
}

/// Parse IP address from bytes.
fn parse_ip_from_bytes(data: &[u8], family: u8) -> Option<IpAddr> {
    match family as i32 {
        libc::AF_INET if data.len() >= 4 => {
            let octets: [u8; 4] = data[..4].try_into().ok()?;
            Some(IpAddr::V4(std::net::Ipv4Addr::from(octets)))
        }
        libc::AF_INET6 if data.len() >= 16 => {
            let octets: [u8; 16] = data[..16].try_into().ok()?;
            Some(IpAddr::V6(std::net::Ipv6Addr::from(octets)))
        }
        _ => None,
    }
}

/// Convert rtnetlink scope to AddressScope.
fn scope_to_address_scope(scope: u8) -> AddressScope {
    match scope {
        RT_SCOPE_UNIVERSE => AddressScope::Global,
        RT_SCOPE_SITE => AddressScope::Site,
        RT_SCOPE_LINK => AddressScope::Link,
        RT_SCOPE_HOST => AddressScope::Host,
        _ => AddressScope::Unknown,
    }
}

/// Get interface name from index.
fn get_interface_name(
    if_index: u32,
    cache: &Arc<Mutex<std::collections::HashMap<u32, String>>>,
) -> Option<String> {
    // Check cache first
    if let Ok(c) = cache.lock() {
        if let Some(name) = c.get(&if_index) {
            return Some(name.clone());
        }
    }

    // Query via if_indextoname
    let mut buf = [0u8; libc::IF_NAMESIZE];
    // SAFETY:
    // - if_index is a valid interface index from a netlink message
    // - buf is a properly sized buffer (IF_NAMESIZE bytes) for the interface name
    // - if_indextoname writes at most IF_NAMESIZE bytes including NUL terminator
    let result = unsafe { libc::if_indextoname(if_index, buf.as_mut_ptr() as *mut libc::c_char) };

    if result.is_null() {
        return None;
    }

    // SAFETY:
    // - result is non-null (checked above), pointing to buf
    // - if_indextoname guarantees NUL-terminated string on success
    // - buf is valid for the duration of this block
    let name = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr() as *const libc::c_char) }
        .to_string_lossy()
        .into_owned();

    // Update cache
    if let Ok(mut c) = cache.lock() {
        c.insert(if_index, name.clone());
    }

    Some(name)
}

/// Update interface cache from link message.
fn update_interface_cache(
    _data: &[u8],
    _cache: &Arc<Mutex<std::collections::HashMap<u32, String>>>,
) {
    // Link messages would update the cache, but for simplicity
    // we rely on if_indextoname which is always fresh
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_netlink_detector_new() {
        let detector = NetlinkIpDetector::new();
        assert!(detector.is_ok());
    }

    #[test]
    fn test_netlink_detector_name() {
        let detector = NetlinkIpDetector::new().expect("should create detector");
        assert_eq!(detector.name(), "netlink");
    }

    #[test]
    fn test_netlink_detector_is_event_based() {
        let detector = NetlinkIpDetector::new().expect("should create detector");
        assert!(detector.is_event_based());
    }

    #[test]
    fn test_netlink_detector_with_filters() {
        let detector = NetlinkIpDetector::new()
            .expect("should create detector")
            .with_interface_filter(InterfaceFilter::no_loopback())
            .with_address_filter(AddressFilter::ipv4_only());

        assert!(!detector.interface_filter.matches("lo"));
        assert!(!detector.address_filter.ipv6);
    }

    #[test]
    fn test_netlink_detector_start_stop() {
        let mut detector = NetlinkIpDetector::new().expect("should create detector");

        // Start
        let result = detector.start();
        assert!(result.is_ok());
        assert!(detector.is_running());

        // Stop
        detector.stop();
        assert!(!detector.is_running());
    }

    #[test]
    fn test_netlink_detector_current_addresses() {
        let detector = NetlinkIpDetector::new().expect("should create detector");
        let addresses = detector.current_addresses();
        assert!(addresses.is_ok());
        // Should have at least loopback on most systems
    }

    #[test]
    fn test_netlink_detector_poll_changes() {
        let mut detector = NetlinkIpDetector::new().expect("should create detector");

        // First poll starts the listener
        let changes = detector.poll_changes();
        assert!(changes.is_ok());
        assert!(detector.is_running());

        // Cleanup
        detector.stop();
    }

    #[test]
    fn test_netlink_detector_pending_count() {
        let detector = NetlinkIpDetector::new().expect("should create detector");
        assert_eq!(detector.pending_count(), 0);
    }

    #[test]
    fn test_scope_to_address_scope() {
        assert_eq!(
            scope_to_address_scope(RT_SCOPE_UNIVERSE),
            AddressScope::Global
        );
        assert_eq!(scope_to_address_scope(RT_SCOPE_SITE), AddressScope::Site);
        assert_eq!(scope_to_address_scope(RT_SCOPE_LINK), AddressScope::Link);
        assert_eq!(scope_to_address_scope(RT_SCOPE_HOST), AddressScope::Host);
        assert_eq!(scope_to_address_scope(99), AddressScope::Unknown);
    }

    #[test]
    fn test_parse_ip_from_bytes_v4() {
        let data = [192, 168, 1, 1];
        let ip = parse_ip_from_bytes(&data, libc::AF_INET as u8);
        assert_eq!(
            ip,
            Some(IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1)))
        );
    }

    #[test]
    fn test_parse_ip_from_bytes_v6() {
        let data = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let ip = parse_ip_from_bytes(&data, libc::AF_INET6 as u8);
        assert!(ip.is_some());
        if let Some(IpAddr::V6(v6)) = ip {
            assert_eq!(v6.segments()[0], 0x2001);
            assert_eq!(v6.segments()[1], 0x0db8);
        }
    }

    #[test]
    fn test_parse_ip_from_bytes_invalid() {
        let data = [1, 2]; // Too short
        assert!(parse_ip_from_bytes(&data, libc::AF_INET as u8).is_none());
    }

    #[test]
    fn test_get_addresses_via_getifaddrs() {
        use crate::transport::mobility::detector_poll::get_addresses_via_getifaddrs;
        let filter = InterfaceFilter::all();
        let addr_filter = AddressFilter::all();
        let result = get_addresses_via_getifaddrs(&filter, &addr_filter);
        assert!(result.is_ok());
    }

    #[test]
    fn test_get_addresses_filtered() {
        use crate::transport::mobility::detector_poll::get_addresses_via_getifaddrs;
        let filter = InterfaceFilter::no_loopback();
        let addr_filter = AddressFilter::ipv4_only();
        let result = get_addresses_via_getifaddrs(&filter, &addr_filter);
        assert!(result.is_ok());

        // Should not contain loopback
        for (addr, iface) in result.expect("should get addresses") {
            assert_ne!(iface, "lo");
            assert!(addr.is_ipv4());
        }
    }

    #[test]
    fn test_nlmsghdr_size() {
        // Verify struct sizes match kernel expectations
        assert_eq!(std::mem::size_of::<NlMsgHdr>(), 16);
        assert_eq!(std::mem::size_of::<IfAddrMsg>(), 8);
        assert_eq!(std::mem::size_of::<RtAttr>(), 4);
    }
}
