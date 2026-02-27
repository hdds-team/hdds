// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! IP_PKTINFO helpers for interface-aware sending.
//!
//! This module provides helpers for setting the source IP address and
//! outgoing interface on UDP packets using socket options.
//!
//! # Linux
//!
//! Uses IP_PKTINFO for IPv4 and IPV6_PKTINFO for IPv6.
//!
//! # Other platforms
//!
//! Not yet implemented - falls back to system routing.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

#[cfg(target_os = "linux")]
use std::os::unix::io::RawFd;

/// Information for sending a packet with specific source.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PacketInfo {
    /// Source IP address to use.
    pub source_addr: IpAddr,

    /// Interface index (0 = let system choose).
    pub interface_index: u32,
}

impl PacketInfo {
    /// Create new packet info with source address.
    pub fn new(source_addr: IpAddr) -> Self {
        Self {
            source_addr,
            interface_index: 0,
        }
    }

    /// Create packet info with interface index.
    pub fn with_interface(source_addr: IpAddr, interface_index: u32) -> Self {
        Self {
            source_addr,
            interface_index,
        }
    }

    /// Create IPv4 packet info.
    pub fn ipv4(addr: Ipv4Addr, interface_index: u32) -> Self {
        Self {
            source_addr: IpAddr::V4(addr),
            interface_index,
        }
    }

    /// Create IPv6 packet info.
    pub fn ipv6(addr: Ipv6Addr, interface_index: u32) -> Self {
        Self {
            source_addr: IpAddr::V6(addr),
            interface_index,
        }
    }

    /// Check if this is IPv4.
    pub fn is_ipv4(&self) -> bool {
        self.source_addr.is_ipv4()
    }

    /// Check if this is IPv6.
    pub fn is_ipv6(&self) -> bool {
        self.source_addr.is_ipv6()
    }
}

impl Default for PacketInfo {
    fn default() -> Self {
        Self {
            source_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            interface_index: 0,
        }
    }
}

/// Enable IP_PKTINFO on a socket.
///
/// After enabling, the socket can receive packet info via recvmsg
/// and send with specific source via sendmsg.
#[cfg(target_os = "linux")]
pub fn enable_pktinfo_v4(fd: RawFd) -> io::Result<()> {
    let val: libc::c_int = 1;
    // SAFETY:
    // - fd is a valid socket file descriptor passed by the caller
    // - val is a properly initialized c_int on the stack
    // - IP_PKTINFO is a valid socket option for enabling packet info on IPv4 sockets
    // - The option length matches the c_int size
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            libc::IP_PKTINFO,
            &val as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };

    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Enable IPV6_RECVPKTINFO on a socket.
#[cfg(target_os = "linux")]
pub fn enable_pktinfo_v6(fd: RawFd) -> io::Result<()> {
    let val: libc::c_int = 1;
    // SAFETY:
    // - fd is a valid socket file descriptor passed by the caller
    // - val is a properly initialized c_int on the stack
    // - IPV6_RECVPKTINFO is a valid socket option for enabling packet info on IPv6 sockets
    // - The option length matches the c_int size
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IPV6,
            libc::IPV6_RECVPKTINFO,
            &val as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };

    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Enable pktinfo on a socket for both IPv4 and IPv6.
#[cfg(target_os = "linux")]
pub fn enable_pktinfo(fd: RawFd, is_ipv6: bool) -> io::Result<()> {
    if is_ipv6 {
        enable_pktinfo_v6(fd)
    } else {
        enable_pktinfo_v4(fd)
    }
}

/// Aligned buffer for control messages.
///
/// Uses proper alignment for cmsghdr structures.
#[repr(C, align(8))]
#[derive(Clone, Copy)]
pub struct AlignedCmsgBuf {
    data: [u8; 128],
}

impl AlignedCmsgBuf {
    /// Buffer size.
    pub const SIZE: usize = 128;

    /// Create a new zeroed buffer.
    pub fn new() -> Self {
        Self { data: [0u8; 128] }
    }

    /// Get buffer length.
    pub fn len(&self) -> usize {
        Self::SIZE
    }

    /// Check if buffer is empty (never true for this type).
    pub fn is_empty(&self) -> bool {
        false
    }

    /// Get as byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Get as mutable byte slice.
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }

    /// Get as pointer for sendmsg.
    pub fn as_ptr(&self) -> *const u8 {
        self.data.as_ptr()
    }

    /// Get as mutable pointer for cmsghdr.
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.data.as_mut_ptr()
    }
}

impl Default for AlignedCmsgBuf {
    fn default() -> Self {
        Self::new()
    }
}

/// Build control message for sendmsg with source address.
///
/// Returns the control message buffer and its length.
#[cfg(target_os = "linux")]
pub fn build_pktinfo_cmsg_v4(source: Ipv4Addr, interface_index: u32) -> (AlignedCmsgBuf, usize) {
    let mut buf = AlignedCmsgBuf::new();

    // Build in_pktinfo structure
    let pktinfo = libc::in_pktinfo {
        ipi_ifindex: interface_index as libc::c_int,
        ipi_spec_dst: libc::in_addr {
            s_addr: u32::from_ne_bytes(source.octets()),
        },
        ipi_addr: libc::in_addr { s_addr: 0 },
    };

    // Calculate sizes
    // SAFETY:
    // - CMSG_SPACE and CMSG_LEN are standard macros for calculating control message sizes
    // - The size argument is the size of in_pktinfo structure
    let cmsg_space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<libc::in_pktinfo>() as u32) };
    let cmsg_len = unsafe { libc::CMSG_LEN(std::mem::size_of::<libc::in_pktinfo>() as u32) };

    // Build cmsghdr
    let cmsg = buf.as_mut_ptr() as *mut libc::cmsghdr;
    // SAFETY:
    // - buf is an AlignedCmsgBuf with proper 8-byte alignment for cmsghdr
    // - buf has 128 bytes which is sufficient for cmsghdr + in_pktinfo
    // - cmsg_len and cmsg_level/cmsg_type are valid values for IP_PKTINFO
    // - CMSG_DATA returns a pointer to the data area after cmsghdr
    // - pktinfo is a valid in_pktinfo structure that fits in the data area
    unsafe {
        (*cmsg).cmsg_len = cmsg_len as _;
        (*cmsg).cmsg_level = libc::IPPROTO_IP;
        (*cmsg).cmsg_type = libc::IP_PKTINFO;

        // Copy pktinfo data
        let data_ptr = libc::CMSG_DATA(cmsg);
        std::ptr::copy_nonoverlapping(
            &pktinfo as *const _ as *const u8,
            data_ptr,
            std::mem::size_of::<libc::in_pktinfo>(),
        );
    }

    (buf, cmsg_space as usize)
}

/// Build control message for sendmsg with IPv6 source address.
#[cfg(target_os = "linux")]
pub fn build_pktinfo_cmsg_v6(source: Ipv6Addr, interface_index: u32) -> (AlignedCmsgBuf, usize) {
    let mut buf = AlignedCmsgBuf::new();

    // Build in6_pktinfo structure
    let pktinfo = libc::in6_pktinfo {
        ipi6_addr: libc::in6_addr {
            s6_addr: source.octets(),
        },
        ipi6_ifindex: interface_index,
    };

    // Calculate sizes
    // SAFETY:
    // - CMSG_SPACE and CMSG_LEN are standard macros for calculating control message sizes
    // - The size argument is the size of in6_pktinfo structure
    let cmsg_space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<libc::in6_pktinfo>() as u32) };
    let cmsg_len = unsafe { libc::CMSG_LEN(std::mem::size_of::<libc::in6_pktinfo>() as u32) };

    // Build cmsghdr
    let cmsg = buf.as_mut_ptr() as *mut libc::cmsghdr;
    // SAFETY:
    // - buf is an AlignedCmsgBuf with proper 8-byte alignment for cmsghdr
    // - buf has 128 bytes which is sufficient for cmsghdr + in6_pktinfo
    // - cmsg_len and cmsg_level/cmsg_type are valid values for IPV6_PKTINFO
    // - CMSG_DATA returns a pointer to the data area after cmsghdr
    // - pktinfo is a valid in6_pktinfo structure that fits in the data area
    unsafe {
        (*cmsg).cmsg_len = cmsg_len as _;
        (*cmsg).cmsg_level = libc::IPPROTO_IPV6;
        (*cmsg).cmsg_type = libc::IPV6_PKTINFO;

        // Copy pktinfo data
        let data_ptr = libc::CMSG_DATA(cmsg);
        std::ptr::copy_nonoverlapping(
            &pktinfo as *const _ as *const u8,
            data_ptr,
            std::mem::size_of::<libc::in6_pktinfo>(),
        );
    }

    (buf, cmsg_space as usize)
}

/// Build control message for sendmsg.
#[cfg(target_os = "linux")]
pub fn build_pktinfo_cmsg(info: &PacketInfo) -> (AlignedCmsgBuf, usize) {
    match info.source_addr {
        IpAddr::V4(v4) => build_pktinfo_cmsg_v4(v4, info.interface_index),
        IpAddr::V6(v6) => build_pktinfo_cmsg_v6(v6, info.interface_index),
    }
}

/// Parse pktinfo from received control message.
#[cfg(target_os = "linux")]
pub fn parse_pktinfo_v4(cmsg: &libc::cmsghdr) -> Option<PacketInfo> {
    if cmsg.cmsg_level != libc::IPPROTO_IP || cmsg.cmsg_type != libc::IP_PKTINFO {
        return None;
    }

    // SAFETY:
    // - cmsg is a valid cmsghdr reference passed by the caller
    // - CMSG_DATA returns a pointer to the data portion of the control message
    // - cmsg_level and cmsg_type have been verified to be IP_PKTINFO above
    // - read_unaligned handles any alignment issues with the pktinfo data
    let data_ptr = unsafe { libc::CMSG_DATA(cmsg as *const _ as *mut _) };
    let pktinfo: libc::in_pktinfo =
        unsafe { std::ptr::read_unaligned(data_ptr as *const libc::in_pktinfo) };

    let addr = Ipv4Addr::from(u32::from_ne_bytes(pktinfo.ipi_addr.s_addr.to_ne_bytes()));

    Some(PacketInfo {
        source_addr: IpAddr::V4(addr),
        interface_index: pktinfo.ipi_ifindex as u32,
    })
}

/// Parse pktinfo from received IPv6 control message.
#[cfg(target_os = "linux")]
pub fn parse_pktinfo_v6(cmsg: &libc::cmsghdr) -> Option<PacketInfo> {
    if cmsg.cmsg_level != libc::IPPROTO_IPV6 || cmsg.cmsg_type != libc::IPV6_PKTINFO {
        return None;
    }

    // SAFETY:
    // - cmsg is a valid cmsghdr reference passed by the caller
    // - CMSG_DATA returns a pointer to the data portion of the control message
    // - cmsg_level and cmsg_type have been verified to be IPV6_PKTINFO above
    // - read_unaligned handles any alignment issues with the pktinfo data
    let data_ptr = unsafe { libc::CMSG_DATA(cmsg as *const _ as *mut _) };
    let pktinfo: libc::in6_pktinfo =
        unsafe { std::ptr::read_unaligned(data_ptr as *const libc::in6_pktinfo) };

    let addr = Ipv6Addr::from(pktinfo.ipi6_addr.s6_addr);

    Some(PacketInfo {
        source_addr: IpAddr::V6(addr),
        interface_index: pktinfo.ipi6_ifindex,
    })
}

/// Bind a socket to a specific interface by index.
#[cfg(target_os = "linux")]
pub fn bind_to_interface(fd: RawFd, interface_index: u32) -> io::Result<()> {
    // SAFETY:
    // - fd is a valid socket file descriptor passed by the caller
    // - interface_index is a u32 on the stack
    // - SO_BINDTOIFINDEX is a valid socket option for binding to interface by index
    // - The option length matches the u32 size
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_BINDTOIFINDEX,
            &interface_index as *const _ as *const libc::c_void,
            std::mem::size_of::<u32>() as libc::socklen_t,
        )
    };

    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Bind a socket to a specific interface by name.
#[cfg(target_os = "linux")]
pub fn bind_to_interface_name(fd: RawFd, name: &str) -> io::Result<()> {
    use std::ffi::CString;

    let name_c = CString::new(name).map_err(|_| io::Error::other("invalid interface name"))?;

    // SAFETY:
    // - fd is a valid socket file descriptor passed by the caller
    // - name_c is a valid NUL-terminated CString
    // - SO_BINDTODEVICE is a valid socket option for binding to interface by name
    // - The option length includes the NUL terminator as required
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            name_c.as_ptr() as *const libc::c_void,
            name_c.as_bytes_with_nul().len() as libc::socklen_t,
        )
    };

    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Get interface index for interface name.
#[cfg(target_os = "linux")]
pub fn interface_name_to_index(name: &str) -> io::Result<u32> {
    use std::ffi::CString;

    let name_c = CString::new(name).map_err(|_| io::Error::other("invalid interface name"))?;

    // SAFETY:
    // - name_c is a valid NUL-terminated CString
    // - if_nametoindex is a standard POSIX function that reads the string
    // - Returns 0 on error (checked below), or valid interface index
    let index = unsafe { libc::if_nametoindex(name_c.as_ptr()) };

    if index == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(index)
    }
}

/// Get interface name for interface index.
#[cfg(target_os = "linux")]
pub fn interface_index_to_name(index: u32) -> io::Result<String> {
    let mut buf = [0i8; libc::IF_NAMESIZE];

    // SAFETY:
    // - index is an interface index (validity checked by kernel)
    // - buf is a properly sized buffer (IF_NAMESIZE bytes) for the interface name
    // - if_indextoname writes at most IF_NAMESIZE bytes including NUL terminator
    let ret = unsafe { libc::if_indextoname(index, buf.as_mut_ptr() as *mut libc::c_char) };

    if ret.is_null() {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY:
        // - ret is non-null (checked above), pointing to buf
        // - if_indextoname guarantees NUL-terminated string on success
        // - buf is valid for the duration of this block
        let name = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr() as *const libc::c_char) };
        Ok(name.to_string_lossy().into_owned())
    }
}

/// Result of interface selection.
#[derive(Clone, Debug)]
pub struct SelectedInterface {
    /// Interface name.
    pub name: String,

    /// Interface index.
    pub index: u32,

    /// Source address to use.
    pub source_addr: IpAddr,
}

/// Select interface for sending to a destination.
///
/// Returns the best interface and source address to use.
#[cfg(target_os = "linux")]
pub fn select_interface_for_dest(
    dest: &SocketAddr,
    available: &[(IpAddr, String, u32)], // (addr, iface_name, iface_index)
) -> Option<SelectedInterface> {
    // Simple selection: prefer same address family, prefer non-link-local

    let is_v6 = dest.is_ipv6();

    // Filter by address family
    let candidates: Vec<_> = available
        .iter()
        .filter(|(addr, _, _)| addr.is_ipv6() == is_v6)
        .collect();

    if candidates.is_empty() {
        return None;
    }

    // Prefer global scope over link-local
    let best = candidates
        .iter()
        .find(|(addr, _, _)| {
            match addr {
                IpAddr::V4(v4) => !v4.is_link_local(),
                IpAddr::V6(v6) => {
                    // Check if not link-local (fe80::/10)
                    let segments = v6.segments();
                    (segments[0] & 0xffc0) != 0xfe80
                }
            }
        })
        .or(candidates.first())?;

    Some(SelectedInterface {
        name: best.1.clone(),
        index: best.2,
        source_addr: best.0,
    })
}

// Stub implementations for non-Linux platforms

#[cfg(not(target_os = "linux"))]
pub fn enable_pktinfo_v4(_fd: i32) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "pktinfo not supported on this platform",
    ))
}

#[cfg(not(target_os = "linux"))]
pub fn enable_pktinfo_v6(_fd: i32) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "pktinfo not supported on this platform",
    ))
}

#[cfg(not(target_os = "linux"))]
pub fn enable_pktinfo(_fd: i32, _is_ipv6: bool) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "pktinfo not supported on this platform",
    ))
}

#[cfg(not(target_os = "linux"))]
pub fn build_pktinfo_cmsg(_info: &PacketInfo) -> (AlignedCmsgBuf, usize) {
    (AlignedCmsgBuf::new(), 0)
}

#[cfg(not(target_os = "linux"))]
pub fn interface_name_to_index(_name: &str) -> io::Result<u32> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "interface lookup not supported on this platform",
    ))
}

#[cfg(not(target_os = "linux"))]
pub fn interface_index_to_name(_index: u32) -> io::Result<String> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "interface lookup not supported on this platform",
    ))
}

#[cfg(not(target_os = "linux"))]
pub fn select_interface_for_dest(
    _dest: &SocketAddr,
    _available: &[(IpAddr, String, u32)],
) -> Option<SelectedInterface> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_info_new() {
        let info = PacketInfo::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(info.source_addr, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(info.interface_index, 0);
    }

    #[test]
    fn test_packet_info_with_interface() {
        let info = PacketInfo::with_interface(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 2);
        assert_eq!(info.interface_index, 2);
    }

    #[test]
    fn test_packet_info_ipv4() {
        let info = PacketInfo::ipv4(Ipv4Addr::new(10, 0, 0, 1), 1);
        assert!(info.is_ipv4());
        assert!(!info.is_ipv6());
    }

    #[test]
    fn test_packet_info_ipv6() {
        let info = PacketInfo::ipv6(Ipv6Addr::LOCALHOST, 1);
        assert!(info.is_ipv6());
        assert!(!info.is_ipv4());
    }

    #[test]
    fn test_packet_info_default() {
        let info = PacketInfo::default();
        assert_eq!(info.source_addr, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        assert_eq!(info.interface_index, 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_build_pktinfo_cmsg_v4() {
        let (buf, len) = build_pktinfo_cmsg_v4(Ipv4Addr::new(192, 168, 1, 1), 2);
        assert!(len > 0);
        assert!(len <= buf.len());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_build_pktinfo_cmsg_v6() {
        let (buf, len) = build_pktinfo_cmsg_v6(Ipv6Addr::LOCALHOST, 1);
        assert!(len > 0);
        assert!(len <= buf.len());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_build_pktinfo_cmsg() {
        let info_v4 = PacketInfo::ipv4(Ipv4Addr::new(10, 0, 0, 1), 1);
        let (_, len_v4) = build_pktinfo_cmsg(&info_v4);
        assert!(len_v4 > 0);

        let info_v6 = PacketInfo::ipv6(Ipv6Addr::LOCALHOST, 1);
        let (_, len_v6) = build_pktinfo_cmsg(&info_v6);
        assert!(len_v6 > 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_interface_name_to_index_lo() {
        // Loopback should always exist
        let result = interface_name_to_index("lo");
        assert!(result.is_ok());
        assert!(result.expect("should have index") > 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_interface_index_to_name_lo() {
        // Get loopback index first
        let index = interface_name_to_index("lo").expect("lo should exist");
        let name = interface_index_to_name(index).expect("should get name");
        assert_eq!(name, "lo");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_interface_name_to_index_invalid() {
        let result = interface_name_to_index("nonexistent_interface_xyz");
        assert!(result.is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_interface_index_to_name_invalid() {
        let result = interface_index_to_name(99999);
        assert!(result.is_err());
    }

    #[test]
    fn test_selected_interface() {
        let selected = SelectedInterface {
            name: "eth0".to_string(),
            index: 2,
            source_addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
        };

        assert_eq!(selected.name, "eth0");
        assert_eq!(selected.index, 2);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_select_interface_for_dest_ipv4() {
        let available = vec![
            (
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
                "eth0".to_string(),
                2,
            ),
            (
                IpAddr::V6(Ipv6Addr::new(2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
                "eth0".to_string(),
                2,
            ),
        ];

        let dest: SocketAddr = "192.168.1.1:7400".parse().expect("valid addr");
        let selected = select_interface_for_dest(&dest, &available);

        assert!(selected.is_some());
        let selected = selected.expect("should select");
        assert!(selected.source_addr.is_ipv4());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_select_interface_for_dest_ipv6() {
        let available = vec![
            (
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
                "eth0".to_string(),
                2,
            ),
            (
                IpAddr::V6(Ipv6Addr::new(2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
                "eth0".to_string(),
                2,
            ),
        ];

        let dest: SocketAddr = "[2001:db8::1]:7400".parse().expect("valid addr");
        let selected = select_interface_for_dest(&dest, &available);

        assert!(selected.is_some());
        let selected = selected.expect("should select");
        assert!(selected.source_addr.is_ipv6());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_select_interface_for_dest_empty() {
        let available: Vec<(IpAddr, String, u32)> = vec![];
        let dest: SocketAddr = "192.168.1.1:7400".parse().expect("valid addr");
        let selected = select_interface_for_dest(&dest, &available);
        assert!(selected.is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_select_interface_prefers_non_link_local() {
        let available = vec![
            // Link-local
            (
                IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1)),
                "eth0".to_string(),
                2,
            ),
            // Global
            (
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
                "eth0".to_string(),
                2,
            ),
        ];

        let dest: SocketAddr = "192.168.1.1:7400".parse().expect("valid addr");
        let selected = select_interface_for_dest(&dest, &available);

        assert!(selected.is_some());
        let selected = selected.expect("should select");
        // Should prefer global over link-local
        assert_eq!(
            selected.source_addr,
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))
        );
    }
}
