// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! ECN (Explicit Congestion Notification) support for HDDS.
//!
//! ECN allows routers to signal congestion without dropping packets by setting
//! bits in the IP header. This module provides:
//!
//! - Socket configuration for ECN (setting/receiving TOS bits)
//! - ECN codepoint detection from received packets
//! - Congestion signal generation from CE (Congestion Experienced) marks
//!
//! # ECN Codepoints (RFC 3168)
//!
//! ```text
//! +-----+-----+-----------+
//! | ECT | CE  | Meaning   |
//! +-----+-----+-----------+
//! |  0  |  0  | Not-ECT   |
//! |  0  |  1  | ECT(1)    |
//! |  1  |  0  | ECT(0)    |
//! |  1  |  1  | CE        |
//! +-----+-----+-----------+
//! ```
//!
//! - **Not-ECT (00)**: Non-ECN-capable transport
//! - **ECT(0) (10)**: ECN-capable, set by sender
//! - **ECT(1) (01)**: ECN-capable, alternative
//! - **CE (11)**: Congestion Experienced, set by router
//!
//! # Usage
//!
//! ```rust,ignore
//! use hdds::congestion::ecn::{EcnSocket, EcnCodepoint};
//!
//! // Configure socket for ECN
//! let ecn_socket = EcnSocket::new(socket)?;
//! ecn_socket.set_ecn_capable(true)?;
//!
//! // On receive, check for congestion
//! let (data, tos) = ecn_socket.recv_with_tos(buf)?;
//! if EcnCodepoint::from_tos(tos) == EcnCodepoint::Ce {
//!     controller.on_ecn_ce();
//! }
//! ```

use std::io;
use std::net::UdpSocket;
#[cfg(unix)]
use std::os::unix::io::AsRawFd;

use super::config::EcnMode;

/// ECN codepoint values from IP header TOS field.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum EcnCodepoint {
    /// Not ECN-Capable Transport (bits 00)
    #[default]
    NotEct = 0b00,
    /// ECN-Capable Transport (1) (bits 01)
    Ect1 = 0b01,
    /// ECN-Capable Transport (0) (bits 10)
    Ect0 = 0b10,
    /// Congestion Experienced (bits 11)
    Ce = 0b11,
}

impl EcnCodepoint {
    /// Extract ECN codepoint from TOS byte (lower 2 bits).
    #[inline]
    pub fn from_tos(tos: u8) -> Self {
        // Safety: tos & 0b11 can only produce 0, 1, 2, or 3
        match tos & 0b11 {
            0b00 => EcnCodepoint::NotEct,
            0b01 => EcnCodepoint::Ect1,
            0b10 => EcnCodepoint::Ect0,
            // 0b11 is the only remaining case
            _ => EcnCodepoint::Ce,
        }
    }

    /// Convert to TOS bits.
    #[inline]
    pub fn to_tos(self) -> u8 {
        self as u8
    }

    /// Check if this codepoint indicates congestion.
    #[inline]
    pub fn is_congestion_experienced(self) -> bool {
        self == EcnCodepoint::Ce
    }

    /// Check if this codepoint indicates ECN capability.
    #[inline]
    pub fn is_ecn_capable(self) -> bool {
        matches!(self, EcnCodepoint::Ect0 | EcnCodepoint::Ect1)
    }
}

/// DSCP (Differentiated Services Code Point) presets.
///
/// These can be combined with ECN codepoints in the TOS field.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(u8)]
pub enum Dscp {
    /// Default / Best Effort
    #[default]
    Default = 0,
    /// Expedited Forwarding (voice/video)
    Ef = 46 << 2,
    /// Assured Forwarding 41 (high priority)
    Af41 = 34 << 2,
    /// Assured Forwarding 31 (medium priority)
    Af31 = 26 << 2,
    /// Assured Forwarding 21 (low priority)
    Af21 = 18 << 2,
    /// Class Selector 6 (network control)
    Cs6 = 48 << 2,
}

impl Dscp {
    /// Create TOS byte with this DSCP and an ECN codepoint.
    #[inline]
    pub fn with_ecn(self, ecn: EcnCodepoint) -> u8 {
        (self as u8) | ecn.to_tos()
    }
}

/// ECN configuration result.
#[derive(Clone, Debug)]
pub struct EcnCapabilities {
    /// Whether ECN send is enabled (can set ECT bits).
    pub send_enabled: bool,
    /// Whether ECN receive is enabled (can read TOS from incoming packets).
    pub recv_enabled: bool,
    /// Actual mode after negotiation.
    pub effective_mode: EcnMode,
}

impl Default for EcnCapabilities {
    fn default() -> Self {
        Self {
            send_enabled: false,
            recv_enabled: false,
            effective_mode: EcnMode::Off,
        }
    }
}

/// ECN-aware socket wrapper.
///
/// Provides methods to configure and use ECN on UDP sockets.
pub struct EcnSocket {
    /// The underlying socket file descriptor (Unix) or handle (Windows).
    #[cfg(unix)]
    fd: i32,
    /// Detected capabilities.
    capabilities: EcnCapabilities,
    /// Default DSCP for outgoing packets.
    dscp: Dscp,
}

impl EcnSocket {
    /// Set an integer socket option via setsockopt.
    #[cfg(unix)]
    fn set_ip_option(&self, option: libc::c_int, value: i32) -> io::Result<()> {
        // SAFETY: self.fd is a valid socket descriptor from UdpSocket::as_raw_fd(),
        // IPPROTO_IP and option are valid constants, value is stack-allocated i32,
        // and setsockopt only modifies kernel socket state (no memory corruption).
        let result = unsafe {
            libc::setsockopt(
                self.fd,
                libc::IPPROTO_IP,
                option,
                &value as *const i32 as *const libc::c_void,
                std::mem::size_of::<i32>() as libc::socklen_t,
            )
        };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Configure a UDP socket for ECN.
    ///
    /// # Arguments
    ///
    /// * `socket` - The UDP socket to configure
    /// * `mode` - Desired ECN mode
    ///
    /// # Returns
    ///
    /// Returns the configured `EcnSocket` with actual capabilities.
    /// If `mode` is `Mandatory` and ECN cannot be enabled, returns an error.
    #[cfg(unix)]
    pub fn configure(socket: &UdpSocket, mode: EcnMode) -> io::Result<Self> {
        let fd = socket.as_raw_fd();

        let mut ecn_socket = Self {
            fd,
            capabilities: EcnCapabilities::default(),
            dscp: Dscp::Default,
        };

        if mode == EcnMode::Off {
            return Ok(ecn_socket);
        }

        // Try to enable ECN send (IP_TOS)
        let send_result = ecn_socket.enable_ecn_send();

        // Try to enable ECN receive (IP_RECVTOS)
        let recv_result = ecn_socket.enable_ecn_recv();

        ecn_socket.capabilities = EcnCapabilities {
            send_enabled: send_result.is_ok(),
            recv_enabled: recv_result.is_ok(),
            effective_mode: if send_result.is_ok() && recv_result.is_ok() {
                mode
            } else if mode == EcnMode::Opportunistic {
                EcnMode::Off
            } else {
                mode // Mandatory - will return error below
            },
        };

        // If mandatory and either failed, return error
        if mode == EcnMode::Mandatory && (send_result.is_err() || recv_result.is_err()) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "ECN mandatory but not supported: send={:?}, recv={:?}",
                    send_result, recv_result
                ),
            ));
        }

        Ok(ecn_socket)
    }

    /// Configure for non-Unix platforms (no-op fallback).
    #[cfg(not(unix))]
    pub fn configure(_socket: &UdpSocket, mode: EcnMode) -> io::Result<Self> {
        if mode == EcnMode::Mandatory {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "ECN not supported on this platform",
            ));
        }
        Ok(Self {
            capabilities: EcnCapabilities::default(),
            dscp: Dscp::Default,
        })
    }

    /// Enable ECN marking on outgoing packets.
    #[cfg(unix)]
    fn enable_ecn_send(&self) -> io::Result<()> {
        // Set IP_TOS to ECT(0) by default
        let tos = self.dscp.with_ecn(EcnCodepoint::Ect0) as i32;
        self.set_ip_option(libc::IP_TOS, tos)
    }

    /// Enable receiving TOS from incoming packets.
    #[cfg(unix)]
    fn enable_ecn_recv(&self) -> io::Result<()> {
        self.set_ip_option(libc::IP_RECVTOS, 1)
    }

    /// Set the DSCP for outgoing packets.
    #[cfg(unix)]
    pub fn set_dscp(&mut self, dscp: Dscp) -> io::Result<()> {
        self.dscp = dscp;

        if self.capabilities.send_enabled {
            // Re-apply TOS with new DSCP
            let tos = dscp.with_ecn(EcnCodepoint::Ect0) as i32;
            self.set_ip_option(libc::IP_TOS, tos)?;
        }
        Ok(())
    }

    /// Set DSCP no-op fallback for non-Unix.
    #[cfg(not(unix))]
    pub fn set_dscp(&mut self, dscp: Dscp) -> io::Result<()> {
        self.dscp = dscp;
        Ok(())
    }

    /// Get current capabilities.
    pub fn capabilities(&self) -> &EcnCapabilities {
        &self.capabilities
    }

    /// Check if ECN is active.
    pub fn is_ecn_active(&self) -> bool {
        self.capabilities.send_enabled && self.capabilities.recv_enabled
    }

    /// Get effective mode.
    pub fn effective_mode(&self) -> EcnMode {
        self.capabilities.effective_mode
    }
}

/// ECN statistics tracker.
#[derive(Clone, Debug, Default)]
pub struct EcnStats {
    /// Total packets received.
    pub packets_received: u64,
    /// Packets with ECT(0) marking.
    pub ect0_received: u64,
    /// Packets with ECT(1) marking.
    pub ect1_received: u64,
    /// Packets with CE (congestion) marking.
    pub ce_received: u64,
    /// Packets with Not-ECT marking.
    pub not_ect_received: u64,
    /// CE marks that triggered congestion response.
    pub ce_responded: u64,
}

impl EcnStats {
    /// Create new stats tracker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a received packet's ECN codepoint.
    pub fn record(&mut self, codepoint: EcnCodepoint) {
        self.packets_received += 1;
        match codepoint {
            EcnCodepoint::NotEct => self.not_ect_received += 1,
            EcnCodepoint::Ect0 => self.ect0_received += 1,
            EcnCodepoint::Ect1 => self.ect1_received += 1,
            EcnCodepoint::Ce => self.ce_received += 1,
        }
    }

    /// Record that a CE mark was acted upon.
    pub fn record_ce_response(&mut self) {
        self.ce_responded += 1;
    }

    /// Calculate CE ratio (congestion indicator).
    pub fn ce_ratio(&self) -> f64 {
        let ecn_total = self.ect0_received + self.ect1_received + self.ce_received;
        if ecn_total == 0 {
            0.0
        } else {
            self.ce_received as f64 / ecn_total as f64
        }
    }

    /// Check if peer appears ECN-capable (sends ECT marks).
    pub fn peer_is_ecn_capable(&self) -> bool {
        self.ect0_received > 0 || self.ect1_received > 0
    }
}

/// ECN feedback processor.
///
/// Processes incoming ECN marks and generates congestion signals.
#[derive(Clone, Debug)]
pub struct EcnProcessor {
    /// Statistics.
    stats: EcnStats,
    /// CE marks in current window.
    ce_in_window: u32,
    /// Total packets in current window.
    packets_in_window: u32,
    /// Window size for CE ratio calculation.
    window_size: u32,
    /// CE ratio threshold for congestion signal.
    ce_threshold: f64,
}

impl Default for EcnProcessor {
    fn default() -> Self {
        Self::new(100, 0.01) // 100 packet window, 1% CE threshold
    }
}

impl EcnProcessor {
    /// Create new ECN processor.
    ///
    /// # Arguments
    ///
    /// * `window_size` - Number of packets per window
    /// * `ce_threshold` - CE ratio threshold to signal congestion (0.0-1.0)
    pub fn new(window_size: u32, ce_threshold: f64) -> Self {
        Self {
            stats: EcnStats::new(),
            ce_in_window: 0,
            packets_in_window: 0,
            window_size,
            ce_threshold,
        }
    }

    /// Process a received packet's TOS byte.
    ///
    /// Returns `true` if congestion should be signaled.
    pub fn process_tos(&mut self, tos: u8) -> bool {
        let codepoint = EcnCodepoint::from_tos(tos);
        self.stats.record(codepoint);

        // Only count ECN-capable packets in window
        if codepoint.is_ecn_capable() || codepoint.is_congestion_experienced() {
            self.packets_in_window += 1;
            if codepoint.is_congestion_experienced() {
                self.ce_in_window += 1;
            }
        }

        // Check if window complete
        if self.packets_in_window >= self.window_size {
            let should_signal = self.check_window();
            self.reset_window();
            should_signal
        } else {
            false
        }
    }

    /// Check window for congestion.
    fn check_window(&mut self) -> bool {
        if self.packets_in_window == 0 {
            return false;
        }

        let ce_ratio = self.ce_in_window as f64 / self.packets_in_window as f64;
        if ce_ratio >= self.ce_threshold {
            self.stats.record_ce_response();
            true
        } else {
            false
        }
    }

    /// Reset window counters.
    fn reset_window(&mut self) {
        self.ce_in_window = 0;
        self.packets_in_window = 0;
    }

    /// Process a single CE mark immediately (for low-latency response).
    ///
    /// Returns `true` - CE always signals congestion.
    pub fn process_ce(&mut self) -> bool {
        self.stats.record(EcnCodepoint::Ce);
        self.stats.record_ce_response();
        true
    }

    /// Get statistics.
    pub fn stats(&self) -> &EcnStats {
        &self.stats
    }

    /// Check if peer appears ECN-capable.
    pub fn peer_is_ecn_capable(&self) -> bool {
        self.stats.peer_is_ecn_capable()
    }

    /// Get current CE ratio.
    pub fn current_ce_ratio(&self) -> f64 {
        self.stats.ce_ratio()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ecn_codepoint_from_tos() {
        assert_eq!(EcnCodepoint::from_tos(0b00), EcnCodepoint::NotEct);
        assert_eq!(EcnCodepoint::from_tos(0b01), EcnCodepoint::Ect1);
        assert_eq!(EcnCodepoint::from_tos(0b10), EcnCodepoint::Ect0);
        assert_eq!(EcnCodepoint::from_tos(0b11), EcnCodepoint::Ce);
    }

    #[test]
    fn test_ecn_codepoint_from_tos_with_dscp() {
        // DSCP EF (46) = 0b101110, shifted = 0b10111000
        // ECT0 = 0b10
        // Combined = 0b10111010 = 186
        let tos = 186u8;
        assert_eq!(EcnCodepoint::from_tos(tos), EcnCodepoint::Ect0);
    }

    #[test]
    fn test_ecn_codepoint_to_tos() {
        assert_eq!(EcnCodepoint::NotEct.to_tos(), 0b00);
        assert_eq!(EcnCodepoint::Ect1.to_tos(), 0b01);
        assert_eq!(EcnCodepoint::Ect0.to_tos(), 0b10);
        assert_eq!(EcnCodepoint::Ce.to_tos(), 0b11);
    }

    #[test]
    fn test_ecn_is_congestion_experienced() {
        assert!(!EcnCodepoint::NotEct.is_congestion_experienced());
        assert!(!EcnCodepoint::Ect0.is_congestion_experienced());
        assert!(!EcnCodepoint::Ect1.is_congestion_experienced());
        assert!(EcnCodepoint::Ce.is_congestion_experienced());
    }

    #[test]
    fn test_ecn_is_ecn_capable() {
        assert!(!EcnCodepoint::NotEct.is_ecn_capable());
        assert!(EcnCodepoint::Ect0.is_ecn_capable());
        assert!(EcnCodepoint::Ect1.is_ecn_capable());
        assert!(!EcnCodepoint::Ce.is_ecn_capable());
    }

    #[test]
    fn test_dscp_with_ecn() {
        assert_eq!(Dscp::Default.with_ecn(EcnCodepoint::NotEct), 0b00);
        assert_eq!(Dscp::Default.with_ecn(EcnCodepoint::Ect0), 0b10);
        assert_eq!(Dscp::Ef.with_ecn(EcnCodepoint::Ect0), (46 << 2) | 0b10);
    }

    #[test]
    fn test_ecn_stats_record() {
        let mut stats = EcnStats::new();

        stats.record(EcnCodepoint::Ect0);
        stats.record(EcnCodepoint::Ect0);
        stats.record(EcnCodepoint::Ce);
        stats.record(EcnCodepoint::NotEct);

        assert_eq!(stats.packets_received, 4);
        assert_eq!(stats.ect0_received, 2);
        assert_eq!(stats.ce_received, 1);
        assert_eq!(stats.not_ect_received, 1);
    }

    #[test]
    fn test_ecn_stats_ce_ratio() {
        let mut stats = EcnStats::new();

        // 9 ECT0 + 1 CE = 10% CE ratio
        for _ in 0..9 {
            stats.record(EcnCodepoint::Ect0);
        }
        stats.record(EcnCodepoint::Ce);

        let ratio = stats.ce_ratio();
        assert!((ratio - 0.1).abs() < 0.001);
    }

    #[test]
    fn test_ecn_stats_ce_ratio_no_ecn() {
        let mut stats = EcnStats::new();

        stats.record(EcnCodepoint::NotEct);
        stats.record(EcnCodepoint::NotEct);

        // No ECN-capable packets, ratio should be 0
        assert_eq!(stats.ce_ratio(), 0.0);
    }

    #[test]
    fn test_ecn_stats_peer_ecn_capable() {
        let mut stats = EcnStats::new();

        assert!(!stats.peer_is_ecn_capable());

        stats.record(EcnCodepoint::Ect0);
        assert!(stats.peer_is_ecn_capable());
    }

    #[test]
    fn test_ecn_processor_window() {
        let mut processor = EcnProcessor::new(10, 0.2); // 10 packets, 20% threshold

        // 8 ECT0 + 2 CE = 20% CE
        for _ in 0..8 {
            let signal = processor.process_tos(EcnCodepoint::Ect0.to_tos());
            assert!(!signal); // Window not complete
        }

        // 9th packet (still below threshold with 1 CE)
        processor.process_tos(EcnCodepoint::Ce.to_tos());

        // 10th packet completes window, should signal (2/10 = 20%)
        let signal = processor.process_tos(EcnCodepoint::Ce.to_tos());
        assert!(signal);
    }

    #[test]
    fn test_ecn_processor_below_threshold() {
        let mut processor = EcnProcessor::new(10, 0.2);

        // 9 ECT0 + 1 CE = 10% CE (below 20% threshold)
        for _ in 0..9 {
            processor.process_tos(EcnCodepoint::Ect0.to_tos());
        }
        let signal = processor.process_tos(EcnCodepoint::Ce.to_tos());

        // Should not signal (10% < 20%)
        assert!(!signal);
    }

    #[test]
    fn test_ecn_processor_process_ce_immediate() {
        let mut processor = EcnProcessor::new(100, 0.01);

        // Direct CE processing always signals
        assert!(processor.process_ce());
        assert_eq!(processor.stats().ce_received, 1);
        assert_eq!(processor.stats().ce_responded, 1);
    }

    #[test]
    fn test_ecn_processor_ignores_not_ect() {
        let mut processor = EcnProcessor::new(10, 0.5);

        // Send 10 Not-ECT packets - should not affect window
        for _ in 0..10 {
            let signal = processor.process_tos(EcnCodepoint::NotEct.to_tos());
            assert!(!signal);
        }

        // Window should still be empty for ECN calculation
        assert_eq!(processor.stats().not_ect_received, 10);
    }

    #[test]
    fn test_ecn_capabilities_default() {
        let caps = EcnCapabilities::default();
        assert!(!caps.send_enabled);
        assert!(!caps.recv_enabled);
        assert_eq!(caps.effective_mode, EcnMode::Off);
    }

    #[test]
    fn test_dscp_values() {
        // Verify DSCP values match standards
        assert_eq!(Dscp::Default as u8, 0);
        assert_eq!(Dscp::Ef as u8, 46 << 2);
        assert_eq!(Dscp::Af41 as u8, 34 << 2);
        assert_eq!(Dscp::Cs6 as u8, 48 << 2);
    }

    #[test]
    fn test_ecn_processor_multiple_windows() {
        let mut processor = EcnProcessor::new(5, 0.4);

        // First window: 3 ECT0 + 2 CE = 40% (exactly threshold)
        for _ in 0..3 {
            processor.process_tos(EcnCodepoint::Ect0.to_tos());
        }
        processor.process_tos(EcnCodepoint::Ce.to_tos());
        let signal1 = processor.process_tos(EcnCodepoint::Ce.to_tos());
        assert!(signal1); // 40% >= 40%

        // Second window: 5 ECT0 = 0%
        for i in 0..5 {
            let signal = processor.process_tos(EcnCodepoint::Ect0.to_tos());
            if i < 4 {
                assert!(!signal);
            } else {
                assert!(!signal); // 0% < 40%
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn test_ecn_socket_off_mode() {
        use std::net::UdpSocket;

        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let ecn_socket = EcnSocket::configure(&socket, EcnMode::Off).unwrap();

        assert!(!ecn_socket.is_ecn_active());
        assert_eq!(ecn_socket.effective_mode(), EcnMode::Off);
    }

    #[cfg(unix)]
    #[test]
    fn test_ecn_socket_opportunistic() {
        use std::net::UdpSocket;

        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let ecn_socket = EcnSocket::configure(&socket, EcnMode::Opportunistic).unwrap();

        // On most modern Linux systems, ECN should work
        // But we don't fail the test if it doesn't
        let caps = ecn_socket.capabilities();
        println!(
            "ECN capabilities: send={}, recv={}",
            caps.send_enabled, caps.recv_enabled
        );
    }
}
