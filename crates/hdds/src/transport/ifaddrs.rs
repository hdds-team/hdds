// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Local interface enumeration, captured once per participant construction.
//!
//! This module is the only place in the crate that walks `getifaddrs(3)`.
//! Two consumers read the snapshot: the multicast/locator code
//! (`transport::multicast`, IPv4 only, through [`InterfaceSnapshot::entries`]
//! and the views built on it) and the mobility detectors
//! (`transport::mobility`, IPv4 and IPv6 with prefix lengths, through
//! [`InterfaceSnapshot::addresses`]).
//!
//! On Linux (glibc, musl), Android, macOS and the BSDs the primitive is
//! `getifaddrs(3)` through the `libc` crate: no process is spawned, no text
//! is parsed, and the kernel flags come with each address. Other Unix
//! flavours (Solaris/illumos, Fuchsia, Hurd, Haiku, QNX) lay `struct ifaddrs`
//! out differently in the `libc` crate (`ifa_flags` width, `ifa_ifu` versus
//! `ifa_dstaddr`) and are unsupported: a `compile_error!` below names the
//! gap instead of letting a field access fail. On Windows the
//! `local-ip-address` crate provides the (name, address) list; it carries no
//! flags and no netmask, so no entry is ever loopback-by-flag or
//! point-to-point there and every prefix length is unknown.
//!
//! # What an entry carries
//!
//! [`AddressEntry`] is one address of either family on one interface:
//!
//! - `label`: the name exactly as the OS reports it. On Linux `getifaddrs`
//!   returns `IFA_LABEL`, so a labelled alias reads `eth0:1`.
//! - `name`: the kernel device name, i.e. `label` up to the first `':'`.
//!   Allowlists and `HDDS_INTERFACE` match on `name` (a user writing `eth0`
//!   means the device) and also accept an exact `label` match, so `eth0:1`
//!   keeps working for someone who wrote it.
//! - `addr`: the local address. On a point-to-point link `getifaddrs` puts
//!   `IFA_LOCAL` in `ifa_addr` on both glibc and musl (measured), so the
//!   local side is what HDDS binds and announces; `peer` is informational.
//! - `prefix_len`: the number of leading one bits of `ifa_netmask`, when the
//!   OS reports a netmask of the address's family AND that netmask is a run
//!   of ones followed by zeros; `None` otherwise (always on Windows, and for
//!   a mask with a hole in it, which has no prefix length to report - see
//!   [`prefix_len_checked`]). On the BSD `sa_len` layout XNU stores every IPv4 netmask
//!   trimmed to its last non-zero byte (`in_ifinit` sets `sin_len` to
//!   `offsetof(sockaddr_in, sin_zero)`, then `in_socktrim` shortens it: a
//!   /24 has `sa_len` 7, a /32 has 8, never the 16 of the full struct),
//!   while IPv6 prefix masks keep the full `sizeof(sockaddr_in6)`. Such a
//!   sockaddr is copied into a zeroed buffer of `sockaddr_in6` size before
//!   it is decoded: the bytes the kernel dropped are zero by construction,
//!   so the mask is reconstructed and nothing is read past `sa_len`. A
//!   sockaddr trimmed to fewer than two bytes (a /0 mask) has no family
//!   byte and decodes to `None`.
//! - `loopback` / `point_to_point`: `IFF_LOOPBACK` / `IFF_POINTOPOINT` from
//!   `ifa_flags` (always false on Windows).
//!
//! [`InterfaceEntry`] is the IPv4 projection of an [`AddressEntry`] (same
//! fields, `Ipv4Addr` typed, no prefix length): what the multicast and
//! locator code reads.
//!
//! # Rules written down on purpose
//!
//! - **Loopback**: [`InterfaceSnapshot::pairs`] excludes an entry when the
//!   `IFF_LOOPBACK` flag is set OR the address is in 127/8. The concrete
//!   consequence: a non-127/8 address configured on the loopback device
//!   (`10.0.0.5/32 dev lo`, the anycast / k8s style) is excluded too;
//!   `HDDS_INTERFACE=lo` forces it.
//! - **No UP/RUNNING filtering**: a DOWN interface holding an address is kept
//!   (HDDS then tries the multicast join on it and logs the failure).
//!   Skipping `!IFF_UP` entries would be a separate decision; it can be taken
//!   in one place, here.
//! - **Point-to-point** links (WireGuard, OpenVPN tun, Cloudflare WARP, macOS
//!   utun) are flagged on every Unix, including the OpenVPN `local peer`
//!   form, so such tunnels are visible to the primary-IP heuristic.
//! - **Explicit names** ([`InterfaceSnapshot::resolve_name`]) may resolve to a
//!   loopback address: `HDDS_INTERFACE=lo` is an explicit user choice, so
//!   `HDDS_INTERFACE=lo` (or `lo0` on macOS, or a loopback adapter name on
//!   Windows) resolves to 127.0.0.1, with a warning logged.
//!
//! The struct is a plain snapshot: a VPN that comes up after a participant was
//! built is seen by the next participant, not by this one. There is no
//! process-lifetime cache.

use std::io;
use std::net::{IpAddr, Ipv4Addr};

/// One address, IPv4 or IPv6, on one local interface: everything the OS
/// reports for it (see the module doc for each field).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressEntry {
    /// Kernel device name: `label` up to the first `':'` (`eth0` for `eth0:1`).
    pub name: String,
    /// Name exactly as reported by the OS (`IFA_LABEL` on Linux).
    pub label: String,
    /// Local address of this entry.
    pub addr: IpAddr,
    /// Prefix length from the netmask, when the OS reports one and it is a
    /// contiguous mask (a holed mask reports `None`, not its first run).
    pub prefix_len: Option<u8>,
    /// Raw interface flags (`ifa_flags`); 0 on Windows. Debug/reporting only:
    /// the classification below is what the rest of the crate reads.
    pub flags: u32,
    /// `IFF_LOOPBACK` is set.
    pub loopback: bool,
    /// `IFF_POINTOPOINT` is set (VPN tunnels).
    pub point_to_point: bool,
    /// Peer address of a point-to-point link, when the OS reports one of the
    /// same family as `addr`.
    pub peer: Option<IpAddr>,
}

impl AddressEntry {
    /// Build an entry from a raw OS name and classification bits.
    ///
    /// `name` is derived from `label` at the first `':'`.
    #[must_use]
    pub fn new(
        label: &str,
        addr: IpAddr,
        prefix_len: Option<u8>,
        flags: u32,
        loopback: bool,
        point_to_point: bool,
        peer: Option<IpAddr>,
    ) -> Self {
        Self {
            name: device_name(label).to_string(),
            label: label.to_string(),
            addr,
            prefix_len,
            flags,
            loopback,
            point_to_point,
            peer,
        }
    }

    /// The IPv4 projection of this entry, `None` for an IPv6 address.
    #[must_use]
    pub fn to_v4(&self) -> Option<InterfaceEntry> {
        let IpAddr::V4(addr) = self.addr else {
            return None;
        };
        let peer = match self.peer {
            Some(IpAddr::V4(peer)) => Some(peer),
            _ => None,
        };
        Some(InterfaceEntry {
            name: self.name.clone(),
            label: self.label.clone(),
            addr,
            flags: self.flags,
            loopback: self.loopback,
            point_to_point: self.point_to_point,
            peer,
        })
    }
}

impl From<InterfaceEntry> for AddressEntry {
    /// Lossless widening of an IPv4 entry; the prefix length is unknown.
    fn from(entry: InterfaceEntry) -> Self {
        Self {
            name: entry.name,
            label: entry.label,
            addr: IpAddr::V4(entry.addr),
            prefix_len: None,
            flags: entry.flags,
            loopback: entry.loopback,
            point_to_point: entry.point_to_point,
            peer: entry.peer.map(IpAddr::V4),
        }
    }
}

/// One IPv4 address on one local interface: the IPv4 projection of an
/// [`AddressEntry`], read by the multicast and locator code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceEntry {
    /// Kernel device name: `label` up to the first `':'` (`eth0` for `eth0:1`).
    pub name: String,
    /// Name exactly as reported by the OS (`IFA_LABEL` on Linux).
    pub label: String,
    /// Local IPv4 address of this entry.
    pub addr: Ipv4Addr,
    /// Raw interface flags (`ifa_flags`); 0 on Windows. Debug/reporting only:
    /// the classification below is what the rest of the crate reads.
    pub flags: u32,
    /// `IFF_LOOPBACK` is set.
    pub loopback: bool,
    /// `IFF_POINTOPOINT` is set (VPN tunnels).
    pub point_to_point: bool,
    /// Peer address of a point-to-point link, when the OS reports one.
    pub peer: Option<Ipv4Addr>,
}

impl InterfaceEntry {
    /// Build an entry from a raw OS name and classification bits.
    ///
    /// `name` is derived from `label` at the first `':'`.
    #[must_use]
    pub fn new(
        label: &str,
        addr: Ipv4Addr,
        flags: u32,
        loopback: bool,
        point_to_point: bool,
        peer: Option<Ipv4Addr>,
    ) -> Self {
        Self {
            name: device_name(label).to_string(),
            label: label.to_string(),
            addr,
            flags,
            loopback,
            point_to_point,
            peer,
        }
    }

    /// True when this entry must never be announced or joined on: loopback
    /// by flag or by address range (see the module doc).
    #[must_use]
    pub fn is_loopback(&self) -> bool {
        self.loopback || self.addr.is_loopback()
    }

    /// True when `wanted` designates this entry by device name or exact label.
    #[must_use]
    pub fn matches_name(&self, wanted: &str) -> bool {
        self.name == wanted || self.label == wanted
    }
}

/// Kernel device name of an OS-reported interface name: the part before the
/// first `':'` (Linux alias labels are `dev:label`).
#[must_use]
pub fn device_name(label: &str) -> &str {
    label.split(':').next().unwrap_or(label)
}

/// Prefix length of a netmask: its number of leading one bits (24 for
/// `255.255.255.0`, 32 for `255.255.255.255`, 64 for `ffff:ffff:ffff:ffff::`).
///
/// Leading ones, not a population count: a mask with a hole in it reports the
/// length of its FIRST run and says nothing about the bits past the hole.
/// Such a mask has no prefix length at all, so the capture path asks
/// [`prefix_len_checked`] instead of this.
///
/// The count cannot escape a `u8`: it is bounded by the width of the integer
/// it counts, 32 bits for IPv4 and 128 for IPv6. Both bounds are exercised
/// over their whole domain by `prefix_len_covers_every_length_of_both_families`.
#[must_use]
pub fn prefix_len(mask: IpAddr) -> u8 {
    match mask {
        IpAddr::V4(mask) => u32::from(mask).leading_ones() as u8, // @audit-ok: 0..=32, the width counted
        IpAddr::V6(mask) => u128::from(mask).leading_ones() as u8, // @audit-ok: 0..=128, the width counted
    }
}

/// Prefix length of a netmask that IS one: `Some(n)` when the mask is `n` one
/// bits followed by zeros, `None` when it has a hole.
///
/// A holed mask such as `255.255.0.255` matches the last octet as well, which
/// no `/n` can express. [`prefix_len`] answers 16 for it - the first run - and
/// that number is worse than no number, because a consumer turns a prefix back
/// into a mask (`transport::filter::Ipv4Net::new` does exactly that) and ends
/// up filtering a different set of addresses than the kernel is routing.
///
/// Whether an OS can hand us one is a per-kernel question. Verified on Linux
/// in a network namespace: `SIOCSIFNETMASK` accepts 0.0.0.0, 128.0.0.0,
/// 255.255.254.0, 255.255.255.0 and 255.255.255.255, and refuses 255.255.0.255
/// and 255.0.255.0 with `EINVAL`; netlink (`ip addr add`) takes a prefix
/// length and cannot express a hole either. The macOS and BSD stacks this
/// module also builds for were NOT verified, so the capture path asks the
/// question rather than inheriting the Linux guarantee.
#[must_use]
pub fn prefix_len_checked(mask: IpAddr) -> Option<u8> {
    let (leading, total) = match mask {
        IpAddr::V4(mask) => {
            let bits = u32::from(mask);
            (bits.leading_ones(), bits.count_ones())
        }
        IpAddr::V6(mask) => {
            let bits = u128::from(mask);
            (bits.leading_ones(), bits.count_ones())
        }
    };
    // Every one bit is in the leading run, so there is no hole after it.
    (leading == total).then(|| prefix_len(mask))
}

/// True when both addresses are IPv4 or both are IPv6.
#[cfg(unix)]
fn same_family(a: IpAddr, b: IpAddr) -> bool {
    a.is_ipv4() == b.is_ipv4()
}

/// The local interfaces as seen at one instant.
#[derive(Debug, Clone, Default)]
pub struct InterfaceSnapshot {
    /// Every address the OS reported, both families, in OS order.
    addresses: Vec<AddressEntry>,
    /// IPv4 projection of `addresses`, same order.
    v4: Vec<InterfaceEntry>,
}

impl InterfaceSnapshot {
    /// Snapshot built from captured or synthetic entries of either family.
    #[must_use]
    pub fn from_addresses(addresses: Vec<AddressEntry>) -> Self {
        let v4 = addresses.iter().filter_map(AddressEntry::to_v4).collect();
        Self { addresses, v4 }
    }

    /// Snapshot built from already classified IPv4 entries (tests, tooling).
    #[must_use]
    pub fn from_entries(entries: Vec<InterfaceEntry>) -> Self {
        Self::from_addresses(entries.into_iter().map(AddressEntry::from).collect())
    }

    /// Capture the current interfaces, or log and return an empty snapshot.
    ///
    /// Enumeration failure (ENOMEM in practice) is never fatal for the
    /// participant; the callers fall back to `0.0.0.0` on an empty list.
    #[must_use]
    pub fn capture_or_empty() -> Self {
        match Self::capture() {
            Ok(snapshot) => snapshot,
            Err(e) => {
                log::warn!(
                    "[UDP] interface enumeration failed: {} (continuing with no interfaces)",
                    e
                );
                Self::default()
            }
        }
    }

    /// Every address of either family, loopback included, in OS order.
    #[must_use]
    pub fn addresses(&self) -> &[AddressEntry] {
        &self.addresses
    }

    /// Every IPv4 entry, loopback included, in OS order.
    #[must_use]
    pub fn entries(&self) -> &[InterfaceEntry] {
        &self.v4
    }

    /// Every non-loopback IPv4 entry, in OS order.
    pub fn non_loopback_entries(&self) -> impl Iterator<Item = &InterfaceEntry> + '_ {
        self.v4.iter().filter(|e| !e.is_loopback())
    }

    /// `(name, addr)` of every non-loopback IPv4 entry, in OS order.
    pub fn pairs(&self) -> impl Iterator<Item = (&str, Ipv4Addr)> + '_ {
        self.non_loopback_entries()
            .map(|e| (e.name.as_str(), e.addr))
    }

    /// The IPv4 entry owning `addr`, if any (first match in OS order).
    #[must_use]
    pub fn find_by_addr(&self, addr: Ipv4Addr) -> Option<&InterfaceEntry> {
        self.v4.iter().find(|e| e.addr == addr)
    }

    /// True when `addr` belongs to a point-to-point interface (VPN tunnel).
    ///
    /// Answered from this snapshot, not a process-lifetime cache, so a tunnel
    /// that came up before the participant was built is always seen, with its
    /// local address (the OpenVPN `local peer` form included).
    #[must_use]
    pub fn is_tunnel_ip(&self, addr: Ipv4Addr) -> bool {
        self.v4.iter().any(|e| e.addr == addr && e.point_to_point)
    }

    /// First IPv4 address of the interface designated by `wanted` (device
    /// name or exact label). Loopback is NOT excluded: the name is an explicit
    /// choice (logged at warn level, since remote peers cannot reach it).
    #[must_use]
    pub fn resolve_name(&self, wanted: &str) -> Option<Ipv4Addr> {
        let entry = self.v4.iter().find(|e| e.matches_name(wanted))?;
        if entry.is_loopback() {
            log::warn!(
                "[UDP] interface {} resolves to loopback {} (explicit choice honoured; remote peers cannot reach it)",
                wanted,
                entry.addr
            );
        }
        Some(entry.addr)
    }

    /// Capture the current interfaces (Unix: `getifaddrs(3)`).
    #[cfg(unix)]
    pub fn capture() -> io::Result<Self> {
        let list = unix::IfaddrsList::new()?;
        Ok(Self::from_addresses(list.addresses()))
    }

    /// Capture the current interfaces (Windows: `local-ip-address`, no flags,
    /// no netmask).
    #[cfg(windows)]
    pub fn capture() -> io::Result<Self> {
        let netifas =
            local_ip_address::list_afinet_netifas().map_err(|e| io::Error::other(e.to_string()))?;
        let addresses = netifas
            .into_iter()
            .map(|(label, ip)| {
                AddressEntry::new(&label, ip, None, 0, ip.is_loopback(), false, None)
            })
            .collect();
        Ok(Self::from_addresses(addresses))
    }
}

#[cfg(all(
    unix,
    not(any(
        target_os = "linux",
        target_os = "android",
        target_vendor = "apple",
        target_os = "freebsd",
        target_os = "dragonfly",
        target_os = "netbsd",
        target_os = "openbsd",
    ))
))]
compile_error!(
    "transport::ifaddrs handles the Linux/Android and macOS/BSD `struct ifaddrs` layouts only"
);

#[cfg(unix)]
mod unix {
    use super::{prefix_len_checked, same_family, AddressEntry};
    use std::ffi::CStr;
    use std::io;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::os::raw::{c_int, c_uint};
    use std::ptr;

    /// Bytes decoded out of any sockaddr: the larger of the two structs read.
    const SOCKADDR_DECODE_LEN: usize = std::mem::size_of::<libc::sockaddr_in6>();
    // The generic header and the IPv4 struct fit inside that image.
    const _: () = assert!(SOCKADDR_DECODE_LEN >= std::mem::size_of::<libc::sockaddr>());
    const _: () = assert!(SOCKADDR_DECODE_LEN >= std::mem::size_of::<libc::sockaddr_in>());

    /// Owner of the list returned by `getifaddrs(3)`.
    ///
    /// `freeifaddrs` runs exactly once, from `Drop`, so an early return while
    /// walking the list cannot leak it.
    pub(super) struct IfaddrsList {
        head: *mut libc::ifaddrs,
    }

    impl IfaddrsList {
        pub(super) fn new() -> io::Result<Self> {
            let mut head: *mut libc::ifaddrs = ptr::null_mut();
            // SAFETY: plain FFI call; `head` is a valid, writable out-pointer
            // that lives for the duration of the call. On success the kernel
            // list is owned by the returned guard and released in Drop.
            let rc = unsafe { libc::getifaddrs(&mut head) };
            if rc != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(Self { head })
        }

        /// Walk the list into owned entries, AF_INET and AF_INET6 nodes only.
        ///
        /// AF_PACKET (Linux) and AF_LINK (macOS/BSD) nodes are per-link
        /// entries carrying no IP address; they are skipped silently, as are
        /// nodes with a NULL `ifa_addr` or a NULL `ifa_name`.
        pub(super) fn addresses(&self) -> Vec<AddressEntry> {
            let mut out = Vec::new();
            let mut node = self.head.cast_const();
            // SAFETY: every `node` is either NULL (loop exit) or a node of the
            // list returned by getifaddrs, which stays allocated until the
            // guard is dropped; `ifa_name` is a NUL-terminated string owned by
            // that list; `ifa_addr`, `ifa_netmask` and the peer pointer are
            // read through `sockaddr_ip`, which checks NULL and the address
            // family before any cast. The `&*node` reference is to a properly
            // aligned, initialised `ifaddrs` the libc allocated.
            unsafe {
                while !node.is_null() {
                    let entry: &libc::ifaddrs = &*node;
                    node = entry.ifa_next;
                    let Some(addr) = sockaddr_ip(entry.ifa_addr) else {
                        continue;
                    };
                    if entry.ifa_name.is_null() {
                        continue;
                    }
                    let label = CStr::from_ptr(entry.ifa_name).to_string_lossy();
                    let flags = entry.ifa_flags;
                    let point_to_point = has_flag(flags, libc::IFF_POINTOPOINT);
                    let peer = if point_to_point {
                        sockaddr_ip(peer_ptr(entry)).filter(|p| same_family(*p, addr))
                    } else {
                        None
                    };
                    let prefix = sockaddr_ip(entry.ifa_netmask)
                        .filter(|m| same_family(*m, addr))
                        .and_then(prefix_len_checked);
                    out.push(AddressEntry::new(
                        &label,
                        addr,
                        prefix,
                        flags,
                        has_flag(flags, libc::IFF_LOOPBACK),
                        point_to_point,
                        peer,
                    ));
                }
            }
            out
        }
    }

    impl Drop for IfaddrsList {
        fn drop(&mut self) {
            // SAFETY: `head` was returned by a successful getifaddrs and is
            // freed exactly once, here; no entry borrows it past this point
            // (addresses() copies every field it keeps).
            unsafe { libc::freeifaddrs(self.head) };
        }
    }

    /// `ifa_flags` is `c_uint`; the `libc::IFF_*` constants are `c_int`.
    fn has_flag(flags: c_uint, flag: c_int) -> bool {
        flags & (flag as c_uint) != 0
    }

    /// The peer/broadcast union member: `ifa_ifu` on Linux and Android,
    /// `ifa_dstaddr` on macOS and the BSDs (names differ in the libc crate;
    /// the other Unix flavours named in the module doc are not built).
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn peer_ptr(entry: &libc::ifaddrs) -> *const libc::sockaddr {
        entry.ifa_ifu.cast_const()
    }

    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    fn peer_ptr(entry: &libc::ifaddrs) -> *const libc::sockaddr {
        entry.ifa_dstaddr.cast_const()
    }

    /// IP address behind a `sockaddr` pointer, or `None` when the pointer is
    /// NULL or the family is neither `AF_INET` nor `AF_INET6`.
    ///
    /// # Safety
    ///
    /// `sa` must be NULL or point to a `sockaddr` returned by getifaddrs that
    /// is still allocated. On Linux and Android every such sockaddr lives in
    /// a union at least `sockaddr_in6` large (glibc and musl alike), so it is
    /// decoded in place. On the BSD `sa_len` layout getifaddrs copies exactly
    /// `sa_len` bytes per sockaddr, and XNU trims IPv4 netmasks (module doc),
    /// so `min(sa_len, sizeof(sockaddr_in6))` bytes are first copied into a
    /// zeroed buffer and the copy is decoded: the kernel's dropped bytes are
    /// zero, nothing is read past `sa_len`, and a sockaddr shorter than two
    /// bytes decodes as family 0 (`None`).
    unsafe fn sockaddr_ip(sa: *const libc::sockaddr) -> Option<IpAddr> {
        if sa.is_null() {
            return None;
        }
        // SAFETY: `sa` is non-NULL and points into the union getifaddrs
        // allocated, which is at least SOCKADDR_DECODE_LEN bytes and outlives
        // this call. The inner block is explicit so `unsafe_op_in_unsafe_fn`
        // (warn by default from edition 2024) stays clean.
        #[cfg(any(target_os = "linux", target_os = "android"))]
        let ip = unsafe { decode_sockaddr(sa.cast::<u8>()) };
        // SAFETY: `sa` is non-NULL; its first byte is `sa_len`, the number of
        // bytes getifaddrs copied for it, which is exactly what is read (capped
        // at the buffer size). The zeroed local buffer is SOCKADDR_DECODE_LEN
        // bytes, as `decode_sockaddr` requires.
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        let ip = unsafe {
            let mut copy = [0u8; SOCKADDR_DECODE_LEN];
            let len = usize::from((*sa).sa_len).min(SOCKADDR_DECODE_LEN);
            ptr::copy_nonoverlapping(sa.cast::<u8>(), copy.as_mut_ptr(), len);
            decode_sockaddr(copy.as_ptr())
        };
        ip
    }

    /// Decode the `AF_INET` / `AF_INET6` address of the sockaddr image at
    /// `bytes`, or `None` for any other family.
    ///
    /// # Safety
    ///
    /// `bytes` must be readable for `SOCKADDR_DECODE_LEN` bytes. No alignment
    /// is required: the family and the family-specific struct are read with
    /// `read_unaligned`, never borrowed.
    unsafe fn decode_sockaddr(bytes: *const u8) -> Option<IpAddr> {
        // SAFETY: SOCKADDR_DECODE_LEN covers `sockaddr` (family header),
        // `sockaddr_in` and `sockaddr_in6`, so every read below stays within
        // the caller's guarantee.
        unsafe {
            let header: libc::sockaddr = ptr::read_unaligned(bytes.cast::<libc::sockaddr>());
            let family = c_int::from(header.sa_family);
            if family == libc::AF_INET {
                let sin: libc::sockaddr_in = ptr::read_unaligned(bytes.cast::<libc::sockaddr_in>());
                Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(
                    sin.sin_addr.s_addr,
                ))))
            } else if family == libc::AF_INET6 {
                let sin6: libc::sockaddr_in6 =
                    ptr::read_unaligned(bytes.cast::<libc::sockaddr_in6>());
                Some(IpAddr::V6(Ipv6Addr::from(sin6.sin6_addr.s6_addr)))
            } else {
                None
            }
        }
    }

    /// The BSD-layout decode on the exact byte images XNU hands out; the
    /// layout is not built on Linux, so this only runs (and only compiles) on
    /// a `sa_len` target.
    #[cfg(all(test, not(any(target_os = "linux", target_os = "android"))))]
    mod tests {
        use super::{sockaddr_ip, SOCKADDR_DECODE_LEN};
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

        fn decode(image: &[u8]) -> Option<IpAddr> {
            // SAFETY: the slice starts with its own `sa_len`, so the read
            // stays inside the slice; the test images are built that way.
            unsafe { sockaddr_ip(image.as_ptr().cast::<libc::sockaddr>()) }
        }

        #[test]
        fn trimmed_ipv4_netmasks_are_zero_extended() {
            let af = libc::AF_INET as u8;
            // /24 as in_socktrim leaves it: sa_len 7, last mask byte dropped.
            assert_eq!(
                decode(&[7, af, 0, 0, 255, 255, 255]),
                Some(IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0)))
            );
            // /32: sa_len 8, the sin_zero tail dropped.
            assert_eq!(
                decode(&[8, af, 0, 0, 255, 255, 255, 255]),
                Some(IpAddr::V4(Ipv4Addr::BROADCAST))
            );
            // /8: sa_len 5.
            assert_eq!(
                decode(&[5, af, 0, 0, 255]),
                Some(IpAddr::V4(Ipv4Addr::new(255, 0, 0, 0)))
            );
            // /0: in_socktrim sets sa_len 0, no family byte survives.
            assert_eq!(decode(&[0, af]), None);
        }

        #[test]
        fn full_length_sockaddrs_decode_in_place() {
            let mut v4 = [0u8; 16];
            v4[0] = 16;
            v4[1] = libc::AF_INET as u8;
            v4[4..8].copy_from_slice(&[10, 9, 3, 1]);
            assert_eq!(decode(&v4), Some(IpAddr::V4(Ipv4Addr::new(10, 9, 3, 1))));

            let mut v6 = [0u8; SOCKADDR_DECODE_LEN];
            v6[0] = SOCKADDR_DECODE_LEN as u8;
            v6[1] = libc::AF_INET6 as u8;
            v6[8..24].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
            assert_eq!(decode(&v6), Some(IpAddr::V6(Ipv6Addr::LOCALHOST)));

            // A longer sockaddr (AF_LINK style) is capped at the buffer size
            // and rejected on family alone.
            let mut link = [0u8; 40];
            link[0] = 40;
            link[1] = libc::AF_LINK as u8;
            assert_eq!(decode(&link), None);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    fn plain(label: &str, addr: [u8; 4]) -> InterfaceEntry {
        InterfaceEntry::new(label, Ipv4Addr::from(addr), 0x1043, false, false, None)
    }

    fn fixture() -> InterfaceSnapshot {
        InterfaceSnapshot::from_entries(vec![
            // lo: flagged loopback, 127.0.0.1
            InterfaceEntry::new("lo", Ipv4Addr::new(127, 0, 0, 1), 0x49, true, false, None),
            plain("eth0", [192, 168, 1, 10]),
            // secondary address on the same device
            plain("eth0", [192, 168, 2, 10]),
            // labelled alias: raw name carries the label
            plain("eth0:1", [192, 168, 3, 10]),
            // DOWN interface holding an address (flags without IFF_UP)
            InterfaceEntry::new(
                "dummy1",
                Ipv4Addr::new(10, 9, 2, 1),
                0x82,
                false,
                false,
                None,
            ),
            // point-to-point with a peer (OpenVPN net30 form)
            InterfaceEntry::new(
                "tun0",
                Ipv4Addr::new(10, 9, 3, 1),
                0x1091,
                false,
                true,
                Some(Ipv4Addr::new(10, 9, 3, 2)),
            ),
            // 127/8 address on a non-loopback-flagged device
            plain("odd0", [127, 5, 5, 5]),
            plain("docker0", [172, 17, 0, 1]),
            // global address on the loopback device (anycast / k8s style):
            // excluded by the flag half of the rule
            InterfaceEntry::new("lo", Ipv4Addr::new(10, 0, 0, 5), 0x49, true, false, None),
        ])
    }

    #[test]
    fn device_name_stops_at_first_colon() {
        assert_eq!(device_name("eth0"), "eth0");
        assert_eq!(device_name("eth0:1"), "eth0");
        assert_eq!(device_name("eth0:a:b"), "eth0");
        assert_eq!(device_name(""), "");
    }

    #[test]
    fn prefix_len_counts_leading_ones_v4_and_v6() {
        assert_eq!(prefix_len(IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0))), 24);
        assert_eq!(
            prefix_len(IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255))),
            32
        );
        assert_eq!(prefix_len(IpAddr::V4(Ipv4Addr::new(255, 0, 0, 0))), 8);
        assert_eq!(prefix_len(IpAddr::V4(Ipv4Addr::UNSPECIFIED)), 0);
        assert_eq!(
            prefix_len(IpAddr::V6(Ipv6Addr::new(
                0xffff, 0xffff, 0xffff, 0xffff, 0, 0, 0, 0
            ))),
            64
        );
        assert_eq!(
            prefix_len(IpAddr::V6(Ipv6Addr::new(
                0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff
            ))),
            128
        );
        // Leading ones, not a popcount: a hole ends the prefix.
        assert_eq!(prefix_len(IpAddr::V4(Ipv4Addr::new(255, 255, 0, 255))), 16);
    }

    /// The whole domain of real netmasks, both families, so the claim that the
    /// count fits a `u8` is measured and not argued: the largest value either
    /// arm can return is the width of the integer it counts.
    #[test]
    fn prefix_len_covers_every_length_of_both_families() {
        let mut worst = 0u8;
        for n in 0..=32u32 {
            let mask = if n == 0 { 0 } else { u32::MAX << (32 - n) };
            let got = prefix_len(IpAddr::V4(Ipv4Addr::from(mask)));
            assert_eq!(u32::from(got), n, "v4 mask {:#010x}", mask);
            worst = worst.max(got);
        }
        assert_eq!(worst, 32, "the widest IPv4 prefix is the width of a u32");
        for n in 0..=128u32 {
            let mask = if n == 0 { 0 } else { u128::MAX << (128 - n) };
            let got = prefix_len(IpAddr::V6(Ipv6Addr::from(mask)));
            assert_eq!(u32::from(got), n, "v6 mask {:#034x}", mask);
            worst = worst.max(got);
        }
        assert_eq!(worst, 128, "the widest IPv6 prefix is the width of a u128");
        // The bound the cast in `prefix_len` rests on, at both widths.
        assert_eq!(u32::MAX.leading_ones(), 32);
        assert_eq!(u128::MAX.leading_ones(), 128);
        assert!(u128::MAX.leading_ones() <= u32::from(u8::MAX));
    }

    /// A netmask with a hole has no prefix length, and the number
    /// `prefix_len` reports for one does not describe the mask.
    #[test]
    fn a_holed_netmask_has_no_prefix_length() {
        let holed = Ipv4Addr::new(255, 255, 0, 255);
        // What the first run says, and what it costs: rebuilding a mask from
        // that prefix gives a DIFFERENT mask, so a consumer filtering on it
        // accepts addresses the kernel's mask rejects.
        assert_eq!(prefix_len(IpAddr::V4(holed)), 16);
        let rebuilt = u32::MAX << (32 - 16);
        assert_ne!(rebuilt, u32::from(holed));
        assert_eq!(u32::from(holed) & !rebuilt, 0x0000_00ff);
        // So the capture path refuses to report a prefix for it at all.
        assert_eq!(prefix_len_checked(IpAddr::V4(holed)), None);
        assert_eq!(
            prefix_len_checked(IpAddr::V4(Ipv4Addr::new(255, 0, 255, 0))),
            None
        );
        assert_eq!(
            prefix_len_checked(IpAddr::V6(Ipv6Addr::new(0xffff, 0, 0xffff, 0, 0, 0, 0, 0))),
            None
        );
        // Contiguous masks are unaffected, over the whole domain of both
        // families: checked and unchecked agree exactly there.
        for n in 0..=32u32 {
            let mask = IpAddr::V4(Ipv4Addr::from(if n == 0 {
                0
            } else {
                u32::MAX << (32 - n)
            }));
            assert_eq!(
                prefix_len_checked(mask),
                Some(prefix_len(mask)),
                "v4 /{}",
                n
            );
        }
        for n in 0..=128u32 {
            let mask = IpAddr::V6(Ipv6Addr::from(if n == 0 {
                0
            } else {
                u128::MAX << (128 - n)
            }));
            assert_eq!(
                prefix_len_checked(mask),
                Some(prefix_len(mask)),
                "v6 /{}",
                n
            );
        }
    }

    #[test]
    fn snapshot_splits_v4_and_v6() {
        let v4_eth0 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));
        let v6_link = IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));
        let v6_global = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
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
                "lo",
                IpAddr::V6(Ipv6Addr::LOCALHOST),
                Some(128),
                0x49,
                true,
                false,
                None,
            ),
            AddressEntry::new("eth0", v4_eth0, Some(24), 0x11043, false, false, None),
            AddressEntry::new("eth0", v6_link, Some(64), 0x11043, false, false, None),
            AddressEntry::new("eth0", v6_global, None, 0x11043, false, false, None),
            // point-to-point IPv4 entry whose peer is IPv6 (bogus family
            // mix): the projection drops such a peer, the entry stays.
            AddressEntry::new(
                "tun0",
                IpAddr::V4(Ipv4Addr::new(10, 9, 3, 1)),
                Some(32),
                0x1091,
                false,
                true,
                Some(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            ),
        ]);
        // Every family in addresses(), OS order, prefix lengths carried.
        assert_eq!(snap.addresses().len(), 6);
        assert_eq!(snap.addresses()[3].addr, v6_link);
        assert_eq!(snap.addresses()[3].prefix_len, Some(64));
        assert_eq!(snap.addresses()[4].prefix_len, None);
        // Only IPv4 in entries(), same relative order.
        let v4: Vec<Ipv4Addr> = snap.entries().iter().map(|e| e.addr).collect();
        assert_eq!(
            v4,
            vec![
                Ipv4Addr::LOCALHOST,
                Ipv4Addr::new(192, 168, 1, 10),
                Ipv4Addr::new(10, 9, 3, 1)
            ]
        );
        assert_eq!(snap.pairs().count(), 2);
        assert!(snap.is_tunnel_ip(Ipv4Addr::new(10, 9, 3, 1)));
        assert_eq!(
            snap.find_by_addr(Ipv4Addr::new(10, 9, 3, 1))
                .expect("tun0")
                .peer,
            None
        );
        // An IPv6 entry has no IPv4 projection.
        assert!(snap.addresses()[3].to_v4().is_none());
        // Round trip of the IPv4 constructor: widened, prefix unknown.
        let round = InterfaceSnapshot::from_entries(vec![plain("eth0", [192, 168, 1, 10])]);
        assert_eq!(round.addresses().len(), 1);
        assert_eq!(round.addresses()[0].addr, v4_eth0);
        assert_eq!(round.addresses()[0].prefix_len, None);
        assert_eq!(round.entries().len(), 1);
    }

    #[test]
    fn alias_label_is_normalised_but_kept() {
        let snap = fixture();
        let alias = snap
            .find_by_addr(Ipv4Addr::new(192, 168, 3, 10))
            .expect("alias present");
        assert_eq!(alias.name, "eth0");
        assert_eq!(alias.label, "eth0:1");
        assert!(alias.matches_name("eth0"));
        assert!(alias.matches_name("eth0:1"));
        assert!(!alias.matches_name("eth1"));
    }

    #[test]
    fn pairs_drop_loopback_by_flag_and_by_range() {
        let snap = fixture();
        let pairs: Vec<(String, Ipv4Addr)> =
            snap.pairs().map(|(n, a)| (n.to_string(), a)).collect();
        assert!(pairs.iter().all(|(_, a)| !a.is_loopback()));
        assert!(!pairs.iter().any(|(n, _)| n == "lo"));
        assert!(!pairs.iter().any(|(n, _)| n == "odd0"));
        // The flag half: a global address on `lo` is excluded as well.
        assert!(!pairs.iter().any(|(_, a)| *a == Ipv4Addr::new(10, 0, 0, 5)));
        assert_eq!(snap.non_loopback_entries().count(), pairs.len());
        // OS order preserved, alias attributed to the device name.
        assert_eq!(
            pairs,
            vec![
                ("eth0".to_string(), Ipv4Addr::new(192, 168, 1, 10)),
                ("eth0".to_string(), Ipv4Addr::new(192, 168, 2, 10)),
                ("eth0".to_string(), Ipv4Addr::new(192, 168, 3, 10)),
                ("dummy1".to_string(), Ipv4Addr::new(10, 9, 2, 1)),
                ("tun0".to_string(), Ipv4Addr::new(10, 9, 3, 1)),
                ("docker0".to_string(), Ipv4Addr::new(172, 17, 0, 1)),
            ]
        );
    }

    #[test]
    fn down_interface_with_address_is_kept() {
        // No UP/RUNNING filtering.
        let snap = fixture();
        assert!(snap
            .pairs()
            .any(|(n, a)| n == "dummy1" && a == Ipv4Addr::new(10, 9, 2, 1)));
    }

    #[test]
    fn point_to_point_is_flagged_on_local_not_peer() {
        let snap = fixture();
        assert!(snap.is_tunnel_ip(Ipv4Addr::new(10, 9, 3, 1)));
        assert!(!snap.is_tunnel_ip(Ipv4Addr::new(10, 9, 3, 2)));
        assert!(!snap.is_tunnel_ip(Ipv4Addr::new(192, 168, 1, 10)));
        let tun = snap
            .find_by_addr(Ipv4Addr::new(10, 9, 3, 1))
            .expect("tun0 present");
        assert_eq!(tun.peer, Some(Ipv4Addr::new(10, 9, 3, 2)));
        // The local side is what pairs() exposes, never the peer.
        assert!(snap.pairs().any(|(_, a)| a == Ipv4Addr::new(10, 9, 3, 1)));
        assert!(!snap.pairs().any(|(_, a)| a == Ipv4Addr::new(10, 9, 3, 2)));
    }

    #[test]
    fn resolve_name_by_device_label_and_explicit_loopback() {
        let snap = fixture();
        // Device name: first address of the device in OS order.
        assert_eq!(
            snap.resolve_name("eth0"),
            Some(Ipv4Addr::new(192, 168, 1, 10))
        );
        // Exact label still works for someone who wrote it.
        assert_eq!(
            snap.resolve_name("eth0:1"),
            Some(Ipv4Addr::new(192, 168, 3, 10))
        );
        // An explicit loopback name is honoured;
        // first address of the device in OS order, so 127.0.0.1 before 10.0.0.5.
        assert_eq!(snap.resolve_name("lo"), Some(Ipv4Addr::new(127, 0, 0, 1)));
        assert_eq!(snap.resolve_name("nonexistent_iface_xyz"), None);
    }

    #[test]
    fn empty_snapshot_answers_negatively() {
        let snap = InterfaceSnapshot::default();
        assert_eq!(snap.addresses().len(), 0);
        assert_eq!(snap.pairs().count(), 0);
        assert!(!snap.is_tunnel_ip(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(snap.resolve_name("eth0"), None);
        assert!(snap.find_by_addr(Ipv4Addr::new(10, 0, 0, 1)).is_none());
    }

    #[cfg(unix)]
    #[test]
    fn capture_on_this_host_has_sane_entries() {
        // No host assumption: every entry has a non-empty label, its name is
        // a prefix of its label, a peer is only ever reported on a
        // point-to-point entry and shares the family of the address, a
        // prefix length fits the family, and the IPv4 projection is exactly
        // the IPv4 subset of the addresses. A sandbox that denies the
        // enumeration (the production code degrades to an empty snapshot
        // there) skips.
        let snap = match InterfaceSnapshot::capture() {
            Ok(s) => s,
            Err(e) => {
                eprintln!("skipped: getifaddrs failed: {}", e);
                return;
            }
        };
        for e in snap.addresses() {
            assert!(!e.label.is_empty());
            assert!(e.label.starts_with(&e.name));
            assert!(!e.name.contains(':'));
            if let Some(peer) = e.peer {
                assert!(e.point_to_point);
                assert!(same_family(peer, e.addr));
            }
            if let Some(len) = e.prefix_len {
                assert!(len <= if e.addr.is_ipv4() { 32 } else { 128 });
            }
        }
        let projected: Vec<IpAddr> = snap.entries().iter().map(|e| IpAddr::V4(e.addr)).collect();
        let v4_subset: Vec<IpAddr> = snap
            .addresses()
            .iter()
            .map(|e| e.addr)
            .filter(IpAddr::is_ipv4)
            .collect();
        assert_eq!(projected, v4_subset);
        // Whatever pairs() returns is never loopback.
        assert!(snap.pairs().all(|(_, a)| !a.is_loopback()));
    }

    /// Enumeration under fixtures the test builds itself in a fresh network
    /// namespace: labelled alias, DOWN device with an address, point-to-point
    /// tun with a peer. Needs `HDDS_NETNS_TESTS=1`, `unshare -rn` (unprivileged
    /// user namespaces enabled), `ip` from iproute2 and the `dummy` module;
    /// skips cleanly when any of these is missing. The test re-executes this
    /// binary inside the namespace (a threaded process cannot unshare a user
    /// namespace itself) with `HDDS_NETNS_CHILD=1`, and the child prints the
    /// snapshot for the parent to check.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "set HDDS_NETNS_TESTS=1 and run with --ignored (needs unshare -rn)"]
    fn netns_fixture_enumeration() {
        use std::process::Command;

        const TEST_PATH: &str = "transport::ifaddrs::tests::netns_fixture_enumeration";

        if std::env::var("HDDS_NETNS_CHILD").as_deref() == Ok("1") {
            // A fresh namespace has `lo` DOWN and address-less; bringing it
            // up gives it 127.0.0.1 so the loopback flag path is covered.
            let script = "ip link set lo up \
                && ip link add dummy0 type dummy \
                && ip addr add 10.9.0.1/24 dev dummy0 \
                && ip addr add 10.9.0.2/24 dev dummy0 label dummy0:1 \
                && ip link set dummy0 up \
                && ip link add dummy1 type dummy \
                && ip addr add 10.9.2.1/24 dev dummy1 \
                && ip tuntap add tun0 mode tun \
                && ip addr add 10.9.3.1 peer 10.9.3.2/32 dev tun0 \
                && ip link set tun0 up";
            let status = Command::new("sh")
                .args(["-c", script])
                .status()
                .expect("spawn sh");
            if !status.success() {
                println!("NETNS_FIXTURE_FAILED");
                return;
            }
            let snap = InterfaceSnapshot::capture().expect("getifaddrs in netns");
            for e in snap.addresses() {
                println!(
                    "NETNS_ENTRY {} {} {} {} {} {}",
                    e.name,
                    e.label,
                    e.addr,
                    e.prefix_len
                        .map_or_else(|| "-".to_string(), |p| p.to_string()),
                    e.point_to_point,
                    e.peer.map_or_else(|| "-".to_string(), |p| p.to_string())
                );
            }
            return;
        }

        if std::env::var("HDDS_NETNS_TESTS").as_deref() != Ok("1") {
            eprintln!("skipped: HDDS_NETNS_TESTS is not 1");
            return;
        }
        let exe = std::env::current_exe().expect("current_exe");
        let output = match Command::new("unshare")
            .args(["-rn", "--"])
            .arg(&exe)
            .args(["--exact", TEST_PATH, "--ignored", "--nocapture"])
            .env("HDDS_NETNS_CHILD", "1")
            .env("HDDS_NETNS_TESTS", "1")
            .output()
        {
            Ok(o) => o,
            Err(e) => {
                eprintln!("skipped: cannot spawn unshare: {}", e);
                return;
            }
        };
        let stdout = String::from_utf8_lossy(&output.stdout);
        if !output.status.success() && !stdout.contains("NETNS_ENTRY") {
            eprintln!(
                "skipped: unshare -rn unavailable or child failed: {}\n{}",
                String::from_utf8_lossy(&output.stderr),
                stdout
            );
            return;
        }
        if stdout.contains("NETNS_FIXTURE_FAILED") {
            eprintln!("skipped: fixtures could not be created in the namespace");
            return;
        }
        let entries: Vec<Vec<&str>> = stdout
            .lines()
            .filter_map(|l| l.strip_prefix("NETNS_ENTRY "))
            .map(|l| l.split(' ').collect())
            .collect();
        assert!(!entries.is_empty(), "no entries from child:\n{}", stdout);
        let has = |name: &str, label: &str, addr: &str, prefix: &str, ptp: &str, peer: &str| {
            entries
                .iter()
                .any(|f| f == &[name, label, addr, prefix, ptp, peer])
        };
        // Loopback: 127.0.0.1/8 (and ::1/128 when IPv6 is enabled).
        assert!(
            has("lo", "lo", "127.0.0.1", "8", "false", "-"),
            "{}",
            stdout
        );
        assert!(
            has("dummy0", "dummy0", "10.9.0.1", "24", "false", "-"),
            "{}",
            stdout
        );
        // Alias: raw label kept, name normalised to the device.
        assert!(
            has("dummy0", "dummy0:1", "10.9.0.2", "24", "false", "-"),
            "{}",
            stdout
        );
        // DOWN device with an address is listed.
        assert!(
            has("dummy1", "dummy1", "10.9.2.1", "24", "false", "-"),
            "{}",
            stdout
        );
        // Point-to-point: local address, /32 mask, peer reported, flag set.
        assert!(
            has("tun0", "tun0", "10.9.3.1", "32", "true", "10.9.3.2"),
            "{}",
            stdout
        );
        // Every IPv6 line, if any, carries a prefix that fits the family.
        for f in entries.iter().filter(|f| f[2].contains(':') && f[3] != "-") {
            let prefix: u8 = f[3].parse().expect("v6 prefix");
            assert!(prefix <= 128, "{}", stdout);
        }
    }
}
