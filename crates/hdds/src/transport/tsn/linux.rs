// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Linux TSN backend implementation.

use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::os::unix::io::AsRawFd;
use std::path::PathBuf;
use std::process::Command;

use super::backend::{TsnBackend, TsnErrorStats};
use super::config::{TsnClockId, TsnConfig, TxTimePolicy};
use super::probe::{SupportLevel, TsnCapabilities};

// Linux constants not in stable libc
mod linux_consts {
    pub const SO_TXTIME: libc::c_int = 61;
    pub const SCM_TXTIME: libc::c_int = 61;
    pub const CLOCK_TAI: libc::clockid_t = 11;

    pub const SOF_TXTIME_DEADLINE_MODE: u32 = 1 << 0;
    pub const SOF_TXTIME_REPORT_ERRORS: u32 = 1 << 1;
}

/// Linux TSN backend with full SO_PRIORITY and SO_TXTIME support.
#[derive(Clone, Debug, Default)]
pub struct LinuxTsnBackend {
    /// Cached txtime support level.
    #[allow(dead_code)]
    txtime_support: Option<SupportLevel>,
}

impl LinuxTsnBackend {
    /// Create a new Linux TSN backend.
    pub fn new() -> Self {
        Self {
            txtime_support: None,
        }
    }

    /// Set socket priority (SO_PRIORITY).
    ///
    /// Priority 0-6 works without CAP_NET_ADMIN.
    /// Priority 7 requires CAP_NET_ADMIN.
    pub fn set_socket_priority(sock: &UdpSocket, priority: u8) -> io::Result<()> {
        let prio = priority as libc::c_int;
        // SAFETY:
        // - sock.as_raw_fd() returns a valid file descriptor owned by the UdpSocket
        // - &prio is a valid pointer to a properly initialized c_int on the stack
        // - size_of::<c_int>() correctly specifies the buffer size
        // - SO_PRIORITY is a valid socket option for SOL_SOCKET level
        let ret = unsafe {
            libc::setsockopt(
                sock.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PRIORITY,
                &prio as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Get socket priority (SO_PRIORITY).
    pub fn get_socket_priority(sock: &UdpSocket) -> io::Result<u8> {
        let mut prio: libc::c_int = 0;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY:
        // - sock.as_raw_fd() returns a valid file descriptor owned by the UdpSocket
        // - &mut prio is a valid pointer to a properly sized buffer for c_int
        // - &mut len is a valid pointer; len is initialized to the correct buffer size
        // - SO_PRIORITY is a valid socket option for SOL_SOCKET level
        let ret = unsafe {
            libc::getsockopt(
                sock.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PRIORITY,
                &mut prio as *mut _ as *mut libc::c_void,
                &mut len,
            )
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(prio as u8)
    }

    /// Enable SO_TXTIME on socket.
    pub fn enable_txtime(sock: &UdpSocket, clock: &TsnClockId, strict: bool) -> io::Result<()> {
        #[repr(C)]
        struct SockTxtime {
            clockid: libc::clockid_t,
            flags: u32,
        }

        let clockid = match clock {
            TsnClockId::Monotonic => libc::CLOCK_MONOTONIC,
            TsnClockId::Tai => linux_consts::CLOCK_TAI,
            TsnClockId::Realtime => libc::CLOCK_REALTIME,
            TsnClockId::Phc(path) => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    format!("PHC path {:?} requires fd_to_clockid conversion", path),
                ));
            }
        };

        let mut flags = linux_consts::SOF_TXTIME_REPORT_ERRORS;
        if strict {
            flags |= linux_consts::SOF_TXTIME_DEADLINE_MODE;
        }

        let txtime = SockTxtime { clockid, flags };

        // SAFETY:
        // - sock.as_raw_fd() returns a valid file descriptor owned by the UdpSocket
        // - &txtime is a valid pointer to a properly initialized SockTxtime struct
        // - SockTxtime is repr(C) and matches the kernel's sock_txtime structure layout
        // - size_of::<SockTxtime>() correctly specifies the buffer size
        // - SO_TXTIME (61) is the correct socket option for txtime on Linux >= 4.19
        let ret = unsafe {
            libc::setsockopt(
                sock.as_raw_fd(),
                libc::SOL_SOCKET,
                linux_consts::SO_TXTIME,
                &txtime as *const _ as *const libc::c_void,
                std::mem::size_of::<SockTxtime>() as libc::socklen_t,
            )
        };

        if ret < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ENOPROTOOPT) {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "SO_TXTIME not supported (kernel < 4.19?)",
                ));
            }
            return Err(err);
        }
        Ok(())
    }

    /// Get kernel version.
    pub fn kernel_version() -> io::Result<(u32, u32)> {
        // SAFETY:
        // - utsname is a POD type that can be safely zero-initialized
        // - All fields are arrays of c_char, which have no invalid bit patterns
        let mut uname: libc::utsname = unsafe { std::mem::zeroed() };
        // SAFETY:
        // - &mut uname is a valid pointer to a properly sized utsname struct
        // - uname() will write valid data to the struct on success
        let ret = unsafe { libc::uname(&mut uname) };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        // SAFETY:
        // - uname() succeeded, so uname.release contains a valid null-terminated C string
        // - The pointer remains valid for the lifetime of this function (uname is on stack)
        // - The string is guaranteed to be null-terminated by the kernel
        let release = unsafe {
            std::ffi::CStr::from_ptr(uname.release.as_ptr())
                .to_string_lossy()
                .to_string()
        };

        // Parse "5.15.0-generic" -> (5, 15)
        let parts: Vec<&str> = release.split('.').collect();
        let major = parts.first().and_then(|s| s.parse().ok()).unwrap_or(0);
        let minor = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
        Ok((major, minor))
    }

    /// Detect qdiscs on interface using tc command.
    fn detect_qdiscs(iface: &str) -> io::Result<(bool, bool, bool, bool)> {
        let output = Command::new("tc")
            .args(["qdisc", "show", "dev", iface])
            .output();

        match output {
            Ok(out) => {
                let stdout = String::from_utf8_lossy(&out.stdout);
                let etf = stdout.contains("etf");
                let taprio = stdout.contains("taprio");
                let mqprio = stdout.contains("mqprio");
                let cbs = stdout.contains("cbs");
                Ok((etf, taprio, mqprio, cbs))
            }
            Err(_) => Ok((false, false, false, false)),
        }
    }

    /// Detect HW timestamping using ethtool.
    fn detect_hw_timestamping(iface: &str) -> SupportLevel {
        let output = Command::new("ethtool").args(["-T", iface]).output();

        match output {
            Ok(out) => {
                let stdout = String::from_utf8_lossy(&out.stdout);
                if stdout.contains("hardware-transmit")
                    || stdout.contains("SOF_TIMESTAMPING_TX_HARDWARE")
                {
                    SupportLevel::SupportedWithOffload
                } else if stdout.contains("software-transmit")
                    || stdout.contains("SOF_TIMESTAMPING_TX_SOFTWARE")
                {
                    SupportLevel::Supported
                } else {
                    SupportLevel::Unsupported
                }
            }
            Err(_) => SupportLevel::Unsupported,
        }
    }

    /// Find PHC device for interface.
    fn find_phc_device(iface: &str) -> Option<PathBuf> {
        // Try /sys/class/net/<iface>/device/ptp/ptp*
        let ptp_path = format!("/sys/class/net/{}/device/ptp", iface);
        if let Ok(entries) = std::fs::read_dir(&ptp_path) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                if let Some(name_str) = name.to_str() {
                    if name_str.starts_with("ptp") {
                        return Some(PathBuf::from(format!("/dev/{}", name_str)));
                    }
                }
            }
        }
        None
    }

    /// Probe TSN capabilities for an interface.
    pub fn probe_capabilities(&self, iface: &str) -> io::Result<TsnCapabilities> {
        let mut caps = TsnCapabilities::default();

        // Kernel version
        if let Ok((major, minor)) = Self::kernel_version() {
            caps.kernel_version = Some((major, minor));

            // SO_TXTIME requires kernel >= 4.19
            if major > 4 || (major == 4 && minor >= 19) {
                caps.so_txtime = SupportLevel::Supported;
            } else {
                caps.add_note(format!(
                    "Kernel {}.{} < 4.19, SO_TXTIME not available",
                    major, minor
                ));
            }
        }

        // Detect qdiscs
        if let Ok((etf, taprio, mqprio, cbs)) = Self::detect_qdiscs(iface) {
            caps.etf_configured = etf;
            caps.taprio_configured = taprio;
            caps.mqprio_configured = mqprio;
            caps.cbs_configured = cbs;

            if etf {
                caps.add_note("ETF qdisc detected - scheduled TX available");
            }
            if taprio {
                caps.add_note("TAPRIO qdisc detected - time-aware scheduling");
            }
            if mqprio {
                caps.add_note("mqprio qdisc detected - traffic class mapping");
            }
        }

        // HW timestamping
        caps.hw_timestamping = Self::detect_hw_timestamping(iface);
        if caps.hw_timestamping.has_offload() {
            caps.so_txtime = SupportLevel::SupportedWithOffload;
        }

        // PHC device
        caps.phc_device = Self::find_phc_device(iface);
        if let Some(ref phc) = caps.phc_device {
            caps.add_note(format!("PHC device: {:?}", phc));
        }

        Ok(caps)
    }

    /// Get current time from clock.
    fn get_clock_time(clock: &TsnClockId) -> io::Result<u64> {
        let clockid = match clock {
            TsnClockId::Monotonic => libc::CLOCK_MONOTONIC,
            TsnClockId::Tai => linux_consts::CLOCK_TAI,
            TsnClockId::Realtime => libc::CLOCK_REALTIME,
            TsnClockId::Phc(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "PHC clock requires fd conversion",
                ));
            }
        };

        // SAFETY:
        // - timespec is a POD type that can be safely zero-initialized
        // - tv_sec and tv_nsec have no invalid bit patterns
        let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
        // SAFETY:
        // - clockid is a valid clock ID (CLOCK_MONOTONIC, CLOCK_TAI, or CLOCK_REALTIME)
        // - &mut ts is a valid pointer to a properly sized timespec struct
        // - clock_gettime() will write valid time data on success
        let ret = unsafe { libc::clock_gettime(clockid, &mut ts) };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64)
    }
}

impl TsnBackend for LinuxTsnBackend {
    fn apply_socket_opts(&self, sock: &UdpSocket, cfg: &TsnConfig) -> io::Result<()> {
        if !cfg.enabled {
            return Ok(());
        }

        // Apply SO_PRIORITY if configured
        if let Some(pcp) = cfg.pcp {
            Self::set_socket_priority(sock, pcp)?;
        }

        // Apply SO_TXTIME if configured
        if cfg.tx_time != TxTimePolicy::Disabled {
            let result = Self::enable_txtime(sock, &cfg.clock_id, cfg.strict_deadline);
            match (&cfg.tx_time, result) {
                (TxTimePolicy::Mandatory, Err(e)) => return Err(e),
                (TxTimePolicy::Opportunistic, Err(_)) => {
                    // Silently degrade - counter should be incremented
                }
                (_, Ok(())) => {}
                (TxTimePolicy::Disabled, _) => {}
            }
        }

        Ok(())
    }

    fn send_with_txtime(
        &self,
        sock: &UdpSocket,
        buf: &[u8],
        addr: SocketAddr,
        txtime: Option<u64>,
        cfg: &TsnConfig,
    ) -> io::Result<usize> {
        match txtime {
            Some(txtime_ns) if cfg.tx_time != TxTimePolicy::Disabled => {
                send_with_cmsg_txtime(sock, buf, addr, txtime_ns)
            }
            _ => sock.send_to(buf, addr),
        }
    }

    fn probe(&self, iface: &str) -> io::Result<TsnCapabilities> {
        self.probe_capabilities(iface)
    }

    fn drain_error_queue(&self, sock: &UdpSocket) -> TsnErrorStats {
        drain_socket_error_queue(sock)
    }

    fn supports_txtime(&self) -> bool {
        if let Ok((major, minor)) = Self::kernel_version() {
            major > 4 || (major == 4 && minor >= 19)
        } else {
            false
        }
    }

    fn clock_gettime(&self, cfg: &TsnConfig) -> io::Result<u64> {
        Self::get_clock_time(&cfg.clock_id)
    }
}

/// Send with SCM_TXTIME ancillary data.
fn send_with_cmsg_txtime(
    sock: &UdpSocket,
    buf: &[u8],
    addr: SocketAddr,
    txtime_ns: u64,
) -> io::Result<usize> {
    use std::mem::MaybeUninit;

    // SAFETY:
    // - sockaddr_storage is a POD type designed to hold any socket address
    // - Zero-initialization is valid; specific fields are set below based on address family
    // Prepare destination address using sockaddr_storage for proper size
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let socklen = match addr {
        SocketAddr::V4(v4) => {
            let sa = &mut storage as *mut _ as *mut libc::sockaddr_in;
            // SAFETY:
            // - storage is properly aligned and large enough for sockaddr_in
            // - sockaddr_storage is designed to be cast to any sockaddr type
            // - sa pointer is valid for writes; storage is owned and mutable
            // - All fields are set to valid values from the Rust SocketAddrV4
            unsafe {
                (*sa).sin_family = libc::AF_INET as libc::sa_family_t;
                (*sa).sin_port = v4.port().to_be();
                (*sa).sin_addr.s_addr = u32::from_ne_bytes(v4.ip().octets());
            }
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t
        }
        SocketAddr::V6(v6) => {
            let sa = &mut storage as *mut _ as *mut libc::sockaddr_in6;
            // SAFETY:
            // - storage is properly aligned and large enough for sockaddr_in6
            // - sockaddr_storage is designed to be cast to any sockaddr type
            // - sa pointer is valid for writes; storage is owned and mutable
            // - All fields are set to valid values from the Rust SocketAddrV6
            unsafe {
                (*sa).sin6_family = libc::AF_INET6 as libc::sa_family_t;
                (*sa).sin6_port = v6.port().to_be();
                (*sa).sin6_flowinfo = v6.flowinfo();
                (*sa).sin6_addr.s6_addr = v6.ip().octets();
                (*sa).sin6_scope_id = v6.scope_id();
            }
            std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t
        }
    };

    // Prepare iovec
    let iov = libc::iovec {
        iov_base: buf.as_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };

    // SAFETY:
    // - CMSG_SPACE is a macro that computes required buffer size for cmsg with given payload
    // - size_of::<u64>() is a valid payload size for txtime ancillary data
    // Prepare cmsg buffer
    let cmsg_space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<u64>() as u32) };
    let mut cmsg_buf = vec![0u8; cmsg_space as usize];

    // SAFETY:
    // - msghdr is a POD type that can be safely zero-initialized
    // - All pointer fields are set to valid values below before use
    // - Zero-initialization ensures no uninitialized padding bytes
    // Prepare msghdr
    let mut msg: libc::msghdr = unsafe { MaybeUninit::zeroed().assume_init() };
    msg.msg_name = &storage as *const _ as *mut libc::c_void;
    msg.msg_namelen = socklen;
    msg.msg_iov = &iov as *const _ as *mut libc::iovec;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = cmsg_space as _;

    // SAFETY:
    // - msg.msg_control points to cmsg_buf which is properly sized via CMSG_SPACE
    // - msg.msg_controllen is set to the buffer size
    // - CMSG_FIRSTHDR returns a valid pointer within cmsg_buf (non-null for non-empty buffer)
    // - cmsg_level, cmsg_type, and cmsg_len are set to valid values for SCM_TXTIME
    // - CMSG_DATA returns a properly aligned pointer within the cmsg for the u64 payload
    // - The cmsg buffer remains valid and unaliased for the duration of sendmsg
    // Fill cmsg with txtime
    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = linux_consts::SCM_TXTIME;
        (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<u64>() as u32) as _;

        let data_ptr = libc::CMSG_DATA(cmsg) as *mut u64;
        *data_ptr = txtime_ns;
    }

    // SAFETY:
    // - sock.as_raw_fd() returns a valid file descriptor owned by the UdpSocket
    // - &msg points to a properly initialized msghdr with all fields set correctly:
    //   - msg_name: valid sockaddr_storage pointer with correct address family data
    //   - msg_namelen: correct size for the address family
    //   - msg_iov: valid iovec pointing to buf slice data
    //   - msg_iovlen: 1 (matching the single iovec)
    //   - msg_control: valid cmsg buffer with SCM_TXTIME ancillary data
    //   - msg_controllen: correct cmsg buffer size
    // - All buffers (storage, buf, cmsg_buf) remain valid for the duration of sendmsg
    // Send
    let ret = unsafe { libc::sendmsg(sock.as_raw_fd(), &msg, 0) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(ret as usize)
}

/// Drain socket error queue for ETF drops.
fn drain_socket_error_queue(sock: &UdpSocket) -> TsnErrorStats {
    let mut stats = TsnErrorStats::default();
    let mut buf = [0u8; 256];
    let mut cmsg_buf = [0u8; 256];

    loop {
        // SAFETY:
        // - msghdr is a POD type that can be safely zero-initialized
        // - All fields are set to valid values below before recvmsg is called
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr() as *mut _,
            iov_len: buf.len(),
        };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg_buf.as_mut_ptr() as *mut _;
        msg.msg_controllen = cmsg_buf.len() as _;

        // SAFETY:
        // - sock.as_raw_fd() returns a valid file descriptor owned by the UdpSocket
        // - &mut msg is a valid pointer to a properly initialized msghdr:
        //   - msg_iov: valid iovec pointing to buf array
        //   - msg_iovlen: 1 (matching the single iovec)
        //   - msg_control: valid cmsg_buf array for receiving ancillary data
        //   - msg_controllen: correct cmsg buffer size
        // - MSG_ERRQUEUE reads from error queue without affecting normal data
        // - MSG_DONTWAIT ensures non-blocking operation
        // - All buffers remain valid for the duration of recvmsg
        let ret = unsafe {
            libc::recvmsg(
                sock.as_raw_fd(),
                &mut msg,
                libc::MSG_ERRQUEUE | libc::MSG_DONTWAIT,
            )
        };

        if ret < 0 {
            break; // Queue empty or error
        }

        // SAFETY:
        // - recvmsg succeeded (ret >= 0), so msg contains valid cmsg data
        // - msg.msg_control points to cmsg_buf which received ancillary data
        // - msg.msg_controllen was set by recvmsg to the actual data length
        // - CMSG_FIRSTHDR returns NULL or a valid pointer within cmsg_buf
        // - CMSG_NXTHDR returns NULL when no more messages, or valid pointer
        // - The cmsg pointer is only dereferenced after null check
        // - cmsg_buf remains valid and unmodified during iteration
        // Parse cmsg for SCM_TXTIME errors
        unsafe {
            let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
            while !cmsg.is_null() {
                if (*cmsg).cmsg_level == libc::SOL_SOCKET
                    && (*cmsg).cmsg_type == linux_consts::SCM_TXTIME
                {
                    // Error code indicates deadline missed
                    stats.dropped_late += 1;
                }
                cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
            }
        }
    }

    stats
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_linux_backend_new() {
        let backend = LinuxTsnBackend::new();
        assert!(backend.txtime_support.is_none());
    }

    #[test]
    fn test_kernel_version() {
        let result = LinuxTsnBackend::kernel_version();
        assert!(result.is_ok());
        let (major, minor) = result.expect("kernel version should be available");
        assert!(major >= 4, "Expected kernel major >= 4, got {}", major);
        println!("Kernel version: {}.{}", major, minor);
    }

    #[test]
    fn test_set_get_socket_priority() {
        let sock = UdpSocket::bind("127.0.0.1:0").expect("bind should succeed");

        // Set priority 5
        LinuxTsnBackend::set_socket_priority(&sock, 5).expect("set priority should succeed");

        // Get and verify
        let prio =
            LinuxTsnBackend::get_socket_priority(&sock).expect("get priority should succeed");
        assert_eq!(prio, 5);
    }

    #[test]
    fn test_set_socket_priority_range() {
        let sock = UdpSocket::bind("127.0.0.1:0").expect("bind should succeed");

        // Test priorities 0-6 (no CAP_NET_ADMIN required)
        for prio in 0..=6 {
            LinuxTsnBackend::set_socket_priority(&sock, prio)
                .unwrap_or_else(|_| panic!("set priority {} should succeed", prio));
            let got =
                LinuxTsnBackend::get_socket_priority(&sock).expect("get priority should succeed");
            assert_eq!(got, prio);
        }
    }

    #[test]
    fn test_probe_capabilities() {
        let backend = LinuxTsnBackend::new();
        let caps = backend
            .probe_capabilities("lo")
            .expect("probe should succeed");

        // loopback should have basic support
        assert!(caps.kernel_version.is_some());

        // SO_TXTIME depends on kernel version
        if let Some((major, minor)) = caps.kernel_version {
            if major > 4 || (major == 4 && minor >= 19) {
                assert!(caps.so_txtime.is_available());
            }
        }
    }

    #[test]
    fn test_supports_txtime() {
        let backend = LinuxTsnBackend::new();
        let supports = backend.supports_txtime();

        // Should match kernel version check
        if let Ok((major, minor)) = LinuxTsnBackend::kernel_version() {
            let expected = major > 4 || (major == 4 && minor >= 19);
            assert_eq!(supports, expected);
        }
    }

    #[test]
    fn test_clock_gettime_monotonic() {
        let backend = LinuxTsnBackend::new();
        let cfg = TsnConfig {
            clock_id: TsnClockId::Monotonic,
            ..Default::default()
        };
        let time1 = backend
            .clock_gettime(&cfg)
            .expect("clock_gettime should succeed");
        let time2 = backend
            .clock_gettime(&cfg)
            .expect("clock_gettime should succeed");
        assert!(time2 >= time1);
    }

    #[test]
    fn test_clock_gettime_tai() {
        let backend = LinuxTsnBackend::new();
        let cfg = TsnConfig {
            clock_id: TsnClockId::Tai,
            ..Default::default()
        };
        let result = backend.clock_gettime(&cfg);
        // TAI may fail on systems without proper time sync
        if let Ok(time) = result {
            assert!(time > 0);
        }
    }

    #[test]
    fn test_apply_socket_opts_disabled() {
        let backend = LinuxTsnBackend::new();
        let sock = UdpSocket::bind("127.0.0.1:0").expect("bind should succeed");
        let cfg = TsnConfig::default(); // enabled = false

        backend
            .apply_socket_opts(&sock, &cfg)
            .expect("apply_socket_opts should succeed");
    }

    #[test]
    fn test_apply_socket_opts_priority() {
        let backend = LinuxTsnBackend::new();
        let sock = UdpSocket::bind("127.0.0.1:0").expect("bind should succeed");
        let cfg = TsnConfig::new().with_priority(5);

        backend
            .apply_socket_opts(&sock, &cfg)
            .expect("apply_socket_opts should succeed");

        let prio =
            LinuxTsnBackend::get_socket_priority(&sock).expect("get priority should succeed");
        assert_eq!(prio, 5);
    }

    #[test]
    fn test_drain_error_queue_empty() {
        let backend = LinuxTsnBackend::new();
        let sock = UdpSocket::bind("127.0.0.1:0").expect("bind should succeed");

        let stats = backend.drain_error_queue(&sock);
        assert_eq!(stats.total_dropped(), 0);
    }

    #[test]
    fn test_send_with_txtime_fallback() {
        let backend = LinuxTsnBackend::new();
        let sock = UdpSocket::bind("127.0.0.1:0").expect("bind should succeed");
        let cfg = TsnConfig::default(); // txtime disabled

        // Should use regular send
        let result = backend.send_with_txtime(
            &sock,
            b"test",
            "127.0.0.1:9999".parse().expect("valid addr"),
            None,
            &cfg,
        );
        // May fail due to no listener, but should not panic
        let _ = result;
    }
}
