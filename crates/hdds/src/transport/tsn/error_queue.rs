// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Error queue handling for ETF drops and txtime errors.

use std::net::UdpSocket;

use super::backend::TsnErrorStats;

// Linux constants
#[cfg(target_os = "linux")]
mod linux_consts {
    pub const SCM_TXTIME: libc::c_int = 61;
}

/// Error queue drainer for TSN sockets.
///
/// Drains MSG_ERRQUEUE to collect information about dropped packets
/// from the ETF qdisc (late packets, deadline misses).
#[derive(Debug, Default)]
pub struct ErrorQueueDrainer {
    /// Total stats since creation.
    total_stats: TsnErrorStats,
}

impl ErrorQueueDrainer {
    /// Create a new error queue drainer.
    pub fn new() -> Self {
        Self::default()
    }

    /// Drain the error queue and return stats for this drain.
    pub fn drain(&mut self, sock: &UdpSocket) -> TsnErrorStats {
        let stats = drain_error_queue_impl(sock);
        self.total_stats.merge(&stats);
        stats
    }

    /// Get total stats since creation.
    pub fn total_stats(&self) -> &TsnErrorStats {
        &self.total_stats
    }

    /// Reset total stats.
    pub fn reset_stats(&mut self) {
        self.total_stats = TsnErrorStats::default();
    }
}

/// Drain the socket error queue.
#[cfg(target_os = "linux")]
fn drain_error_queue_impl(sock: &UdpSocket) -> TsnErrorStats {
    use std::os::unix::io::AsRawFd;

    let mut stats = TsnErrorStats::default();
    let mut buf = [0u8; 256];
    let mut cmsg_buf = [0u8; 512];

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
        //   - msg_controllen: correct cmsg buffer size (512 bytes)
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
            // Queue empty or error - stop draining
            break;
        }

        // Parse control messages for error info
        parse_error_cmsg(&msg, &mut stats);
    }

    stats
}

#[cfg(not(target_os = "linux"))]
fn drain_error_queue_impl(_sock: &UdpSocket) -> TsnErrorStats {
    TsnErrorStats::default()
}

/// Parse control messages from error queue.
#[cfg(target_os = "linux")]
fn parse_error_cmsg(msg: &libc::msghdr, stats: &mut TsnErrorStats) {
    // SAFETY:
    // - msg is a valid pointer to a msghdr that was populated by a successful recvmsg call
    // - msg.msg_control points to a valid buffer containing ancillary data
    // - msg.msg_controllen contains the actual length of received ancillary data
    // - CMSG_FIRSTHDR returns NULL or a valid pointer within the control buffer
    // - CMSG_NXTHDR returns NULL when no more messages, or a valid pointer
    // - The cmsg pointer is only dereferenced after null check in while condition
    // - The control buffer remains valid and unmodified during iteration
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(msg);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::SOL_SOCKET {
                if (*cmsg).cmsg_type == linux_consts::SCM_TXTIME {
                    // This is a txtime error - likely deadline missed
                    stats.dropped_late += 1;
                } else if (*cmsg).cmsg_type == libc::SCM_RIGHTS {
                    // Other error
                    stats.dropped_other += 1;
                }
            }

            // Check for IP_RECVERR / IPV6_RECVERR for extended error info
            if (*cmsg).cmsg_level == libc::IPPROTO_IP || (*cmsg).cmsg_level == libc::IPPROTO_IPV6 {
                // Could parse sock_extended_err here for more details
                // For now, just count as other
                stats.dropped_other += 1;
            }

            cmsg = libc::CMSG_NXTHDR(msg, cmsg);
        }
    }
}

/// Extended error information from error queue.
#[derive(Clone, Debug, Default)]
pub struct ExtendedError {
    /// Error number.
    pub errno: i32,
    /// Error origin.
    pub origin: ErrorOrigin,
    /// Error type.
    pub error_type: u8,
    /// Error code.
    pub code: u8,
    /// Offending packet info.
    pub info: u32,
    /// Additional data.
    pub data: u32,
}

/// Origin of the error.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ErrorOrigin {
    /// Unknown origin.
    #[default]
    Unknown,
    /// Local error.
    Local,
    /// ICMP error.
    Icmp,
    /// ICMPv6 error.
    Icmp6,
    /// Txtime/ETF error.
    Txtime,
}

impl ExtendedError {
    /// Check if this is a txtime-related error.
    pub fn is_txtime_error(&self) -> bool {
        self.origin == ErrorOrigin::Txtime
    }

    /// Check if this is a deadline miss error.
    pub fn is_deadline_miss(&self) -> bool {
        self.is_txtime_error() && self.errno == libc::ECANCELED
    }
}

/// Error queue configuration.
#[derive(Clone, Debug)]
pub struct ErrorQueueConfig {
    /// Enable error reporting on socket.
    pub enabled: bool,
    /// Drain interval in milliseconds (0 = drain on each send).
    pub drain_interval_ms: u32,
}

impl Default for ErrorQueueConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            drain_interval_ms: 100,
        }
    }
}

/// Enable error queue reporting on a socket.
#[cfg(target_os = "linux")]
pub fn enable_error_queue(sock: &UdpSocket) -> std::io::Result<()> {
    use std::os::unix::io::AsRawFd;

    let enable: libc::c_int = 1;

    // SAFETY:
    // - sock.as_raw_fd() returns a valid file descriptor owned by the UdpSocket
    // - &enable is a valid pointer to a properly initialized c_int on the stack
    // - size_of::<c_int>() correctly specifies the buffer size
    // - IP_RECVERR is a valid socket option for IPPROTO_IP level
    // Enable IP_RECVERR for IPv4
    let ret = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            libc::IPPROTO_IP,
            libc::IP_RECVERR,
            &enable as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };

    if ret < 0 {
        // SAFETY:
        // - sock.as_raw_fd() returns a valid file descriptor owned by the UdpSocket
        // - &enable is a valid pointer to a properly initialized c_int on the stack
        // - size_of::<c_int>() correctly specifies the buffer size
        // - IPV6_RECVERR is a valid socket option for IPPROTO_IPV6 level
        // May fail for IPv6 sockets, try IPv6 option
        let ret = unsafe {
            libc::setsockopt(
                sock.as_raw_fd(),
                libc::IPPROTO_IPV6,
                libc::IPV6_RECVERR,
                &enable as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }
    }

    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn enable_error_queue(_sock: &UdpSocket) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_queue_drainer_new() {
        let drainer = ErrorQueueDrainer::new();
        assert_eq!(drainer.total_stats().total_dropped(), 0);
    }

    #[test]
    fn test_error_queue_drainer_drain_empty() {
        let mut drainer = ErrorQueueDrainer::new();
        let sock = UdpSocket::bind("127.0.0.1:0").expect("bind should succeed");

        let stats = drainer.drain(&sock);
        assert_eq!(stats.total_dropped(), 0);
    }

    #[test]
    fn test_error_queue_drainer_reset() {
        let mut drainer = ErrorQueueDrainer::new();
        drainer.total_stats.dropped_late = 5;

        drainer.reset_stats();
        assert_eq!(drainer.total_stats().dropped_late, 0);
    }

    #[test]
    fn test_extended_error_default() {
        let err = ExtendedError::default();
        assert_eq!(err.errno, 0);
        assert_eq!(err.origin, ErrorOrigin::Unknown);
        assert!(!err.is_txtime_error());
        assert!(!err.is_deadline_miss());
    }

    #[test]
    fn test_extended_error_txtime() {
        let err = ExtendedError {
            errno: libc::ECANCELED,
            origin: ErrorOrigin::Txtime,
            ..Default::default()
        };
        assert!(err.is_txtime_error());
        assert!(err.is_deadline_miss());
    }

    #[test]
    fn test_error_queue_config_default() {
        let cfg = ErrorQueueConfig::default();
        assert!(cfg.enabled);
        assert_eq!(cfg.drain_interval_ms, 100);
    }

    #[test]
    fn test_enable_error_queue() {
        let sock = UdpSocket::bind("127.0.0.1:0").expect("bind should succeed");
        // Should not panic, may succeed or fail depending on socket type
        let _ = enable_error_queue(&sock);
    }

    #[test]
    fn test_error_origin_variants() {
        assert_eq!(ErrorOrigin::default(), ErrorOrigin::Unknown);
        assert_ne!(ErrorOrigin::Txtime, ErrorOrigin::Local);
    }

    #[test]
    fn test_tsn_error_stats_merge() {
        let mut stats1 = TsnErrorStats {
            dropped_late: 5,
            dropped_other: 2,
        };
        let stats2 = TsnErrorStats {
            dropped_late: 3,
            dropped_other: 1,
        };

        stats1.merge(&stats2);
        assert_eq!(stats1.dropped_late, 8);
        assert_eq!(stats1.dropped_other, 3);
    }
}
