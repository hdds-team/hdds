// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Transport abstraction for HDDS Micro
//!
//! Defines a generic transport trait that can be implemented for:
//! - WiFi UDP (ESP32, RP2040W)
//! - LoRa (SX1276/78)
//! - Serial (UART, USB CDC)
//! - CAN bus
//!
//! ## Design Principles
//!
//! - **No heap allocations** - uses fixed buffers
//! - **Blocking I/O** - simpler for embedded (async optional via features)
//! - **Zero-copy** - borrow slices instead of copying
//! - **Error handling** - Result-based, no panics

use crate::error::{Error, Result};
use crate::rtps::Locator;

pub mod cc1101;
pub mod hc12;
pub mod lora;
pub mod mesh;
pub mod nrf24;
pub mod udp;

pub use cc1101::{Cc1101Band, Cc1101Config, Cc1101DataRate, Cc1101Power, Cc1101Transport};
pub use mesh::{MeshConfig, MeshHeader, MeshStats, MeshTransport};
pub use nrf24::{Nrf24Config, Nrf24DataRate, Nrf24Power, Nrf24Transport};

/// Transport trait for sending/receiving RTPS packets
///
/// Implementors must handle:
/// - Network initialization
/// - Packet send/receive
/// - Address translation (Locator <-> platform-specific address)
pub trait Transport {
    /// Initialize transport
    ///
    /// Called once during participant setup.
    fn init(&mut self) -> Result<()>;

    /// Send packet to destination
    ///
    /// # Arguments
    ///
    /// * `data` - RTPS packet (header + submessages)
    /// * `dest` - Destination locator
    ///
    /// # Returns
    ///
    /// Number of bytes sent
    fn send(&mut self, data: &[u8], dest: &Locator) -> Result<usize>;

    /// Receive packet (blocking)
    ///
    /// # Arguments
    ///
    /// * `buf` - Buffer to receive into (must be >= MAX_PACKET_SIZE)
    ///
    /// # Returns
    ///
    /// (bytes_received, source_locator)
    fn recv(&mut self, buf: &mut [u8]) -> Result<(usize, Locator)>;

    /// Receive packet (non-blocking)
    ///
    /// Returns `Err(Error::ResourceExhausted)` if no packet available.
    fn try_recv(&mut self, buf: &mut [u8]) -> Result<(usize, Locator)>;

    /// Get local locator (own address)
    fn local_locator(&self) -> Locator;

    /// Get MTU (maximum transmission unit)
    fn mtu(&self) -> usize;

    /// Get last received packet RSSI (for radio transports)
    ///
    /// Returns None if RSSI is not available (e.g., UDP transport).
    fn last_rssi(&self) -> Option<i16> {
        None
    }

    /// Shutdown transport
    fn shutdown(&mut self) -> Result<()>;
}

/// Null transport (for testing)
///
/// Discards all packets, never receives anything.
pub struct NullTransport {
    local_locator: Locator,
}

impl NullTransport {
    /// Create a new null transport
    pub const fn new(local_locator: Locator) -> Self {
        Self { local_locator }
    }
}

impl Default for NullTransport {
    fn default() -> Self {
        Self {
            local_locator: Locator::udpv4([127, 0, 0, 1], 7400),
        }
    }
}

impl Transport for NullTransport {
    fn init(&mut self) -> Result<()> {
        Ok(())
    }

    fn send(&mut self, data: &[u8], _dest: &Locator) -> Result<usize> {
        // Discard packet
        Ok(data.len())
    }

    fn recv(&mut self, _buf: &mut [u8]) -> Result<(usize, Locator)> {
        // Never receive anything
        Err(Error::TransportError)
    }

    fn try_recv(&mut self, _buf: &mut [u8]) -> Result<(usize, Locator)> {
        Err(Error::ResourceExhausted)
    }

    fn local_locator(&self) -> Locator {
        self.local_locator
    }

    fn mtu(&self) -> usize {
        1024
    }

    fn shutdown(&mut self) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_null_transport() {
        let mut transport = NullTransport::default();

        transport.init().unwrap();

        let data = b"hello";
        let dest = Locator::udpv4([192, 168, 1, 100], 7400);
        let sent = transport.send(data, &dest).unwrap();
        assert_eq!(sent, data.len());

        let mut buf = [0u8; 64];
        let result = transport.try_recv(&mut buf);
        assert_eq!(result, Err(Error::ResourceExhausted));
    }
}
