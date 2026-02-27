// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! UDP transport for WiFi/Ethernet
//!
//! Provides UDP socket abstraction for no_std and std environments.

use crate::error::{Error, Result};
use crate::rtps::Locator;
use crate::transport::Transport;

/// UDP socket abstraction
///
/// Platform-agnostic trait for UDP operations.
/// Implementations:
/// - `StdUdpSocket` for std (host testing)
/// - Platform-specific for ESP32, RP2040, etc.
pub trait UdpSocket {
    /// Bind socket to local address
    ///
    /// # Arguments
    ///
    /// * `port` - Local port to bind (0 = OS assigns)
    fn bind(&mut self, port: u16) -> Result<()>;

    /// Join multicast group
    ///
    /// # Arguments
    ///
    /// * `multicast_addr` - Multicast IP (e.g., 239.255.0.1)
    /// * `interface_addr` - Local interface IP
    fn join_multicast(&mut self, multicast_addr: [u8; 4], interface_addr: [u8; 4]) -> Result<()>;

    /// Send data to destination
    ///
    /// # Arguments
    ///
    /// * `data` - Packet bytes
    /// * `dest_ip` - Destination IPv4 address
    /// * `dest_port` - Destination port
    ///
    /// # Returns
    ///
    /// Number of bytes sent
    fn send_to(&mut self, data: &[u8], dest_ip: [u8; 4], dest_port: u16) -> Result<usize>;

    /// Receive data (blocking)
    ///
    /// # Arguments
    ///
    /// * `buf` - Receive buffer
    ///
    /// # Returns
    ///
    /// (bytes_received, source_ip, source_port)
    fn recv_from(&mut self, buf: &mut [u8]) -> Result<(usize, [u8; 4], u16)>;

    /// Receive data (non-blocking)
    ///
    /// Returns `Err(Error::ResourceExhausted)` if no data available.
    fn try_recv_from(&mut self, buf: &mut [u8]) -> Result<(usize, [u8; 4], u16)>;

    /// Get local port
    fn local_port(&self) -> u16;

    /// Get local IP address
    fn local_ip(&self) -> [u8; 4];
}

/// Standard library UDP socket (for host testing)
#[cfg(feature = "std")]
pub struct StdUdpSocket {
    socket: std::net::UdpSocket,
    local_ip: [u8; 4],
}

#[cfg(feature = "std")]
impl StdUdpSocket {
    /// Create a new standard UDP socket
    pub fn new() -> Self {
        // Create unbound socket (will bind later)
        let socket = std::net::UdpSocket::bind("0.0.0.0:0").expect("Failed to create UDP socket");

        // Set non-blocking for try_recv
        socket
            .set_nonblocking(false)
            .expect("Failed to set blocking mode");

        Self {
            socket,
            local_ip: [0, 0, 0, 0],
        }
    }

    /// Detect local IP address
    fn detect_local_ip() -> [u8; 4] {
        // Try to connect to a public IP to determine our local IP
        // (doesn't actually send data)
        if let Ok(socket) = std::net::UdpSocket::bind("0.0.0.0:0") {
            if socket.connect("8.8.8.8:80").is_ok() {
                if let Ok(addr) = socket.local_addr() {
                    if let std::net::IpAddr::V4(ipv4) = addr.ip() {
                        return ipv4.octets();
                    }
                }
            }
        }

        // Fallback to localhost
        [127, 0, 0, 1]
    }
}

#[cfg(feature = "std")]
impl Default for StdUdpSocket {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "std")]
impl UdpSocket for StdUdpSocket {
    fn bind(&mut self, port: u16) -> Result<()> {
        let addr = format!("0.0.0.0:{}", port);
        self.socket = std::net::UdpSocket::bind(&addr).map_err(|_| Error::TransportError)?;

        // Detect local IP
        self.local_ip = Self::detect_local_ip();

        Ok(())
    }

    fn join_multicast(&mut self, multicast_addr: [u8; 4], interface_addr: [u8; 4]) -> Result<()> {
        let multicast_ip = std::net::Ipv4Addr::from(multicast_addr);
        let interface_ip = std::net::Ipv4Addr::from(interface_addr);

        self.socket
            .join_multicast_v4(&multicast_ip, &interface_ip)
            .map_err(|_| Error::TransportError)?;

        Ok(())
    }

    fn send_to(&mut self, data: &[u8], dest_ip: [u8; 4], dest_port: u16) -> Result<usize> {
        let addr = std::net::SocketAddr::from((dest_ip, dest_port));
        self.socket
            .send_to(data, addr)
            .map_err(|_| Error::TransportError)
    }

    fn recv_from(&mut self, buf: &mut [u8]) -> Result<(usize, [u8; 4], u16)> {
        let (size, addr) = self
            .socket
            .recv_from(buf)
            .map_err(|_| Error::TransportError)?;

        if let std::net::SocketAddr::V4(v4addr) = addr {
            Ok((size, v4addr.ip().octets(), v4addr.port()))
        } else {
            Err(Error::TransportError)
        }
    }

    fn try_recv_from(&mut self, buf: &mut [u8]) -> Result<(usize, [u8; 4], u16)> {
        // Set non-blocking temporarily
        self.socket
            .set_nonblocking(true)
            .map_err(|_| Error::TransportError)?;

        let result = match self.socket.recv_from(buf) {
            Ok((size, addr)) => {
                if let std::net::SocketAddr::V4(v4addr) = addr {
                    Ok((size, v4addr.ip().octets(), v4addr.port()))
                } else {
                    Err(Error::TransportError)
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                Err(Error::ResourceExhausted)
            }
            Err(_) => Err(Error::TransportError),
        };

        // Restore blocking mode
        self.socket
            .set_nonblocking(false)
            .map_err(|_| Error::TransportError)?;

        result
    }

    fn local_port(&self) -> u16 {
        self.socket
            .local_addr()
            .map(|addr| addr.port())
            .unwrap_or(0)
    }

    fn local_ip(&self) -> [u8; 4] {
        self.local_ip
    }
}

/// WiFi UDP Transport
///
/// Implements Transport trait using UDP sockets.
pub struct WifiUdpTransport<S: UdpSocket> {
    socket: S,
    multicast_enabled: bool,
}

impl<S: UdpSocket> WifiUdpTransport<S> {
    /// Create a new WiFi UDP transport
    ///
    /// # Arguments
    ///
    /// * `socket` - UDP socket implementation
    /// * `port` - Local port to bind (typically 7400 for DDS)
    pub fn new(mut socket: S, port: u16) -> Result<Self> {
        socket.bind(port)?;

        Ok(Self {
            socket,
            multicast_enabled: false,
        })
    }

    /// Enable multicast (for SPDP discovery)
    ///
    /// # Arguments
    ///
    /// * `multicast_addr` - Multicast group (e.g., [239, 255, 0, 1])
    pub fn enable_multicast(&mut self, multicast_addr: [u8; 4]) -> Result<()> {
        let local_ip = self.socket.local_ip();
        self.socket.join_multicast(multicast_addr, local_ip)?;
        self.multicast_enabled = true;
        Ok(())
    }

    /// Check if multicast is enabled
    pub const fn is_multicast_enabled(&self) -> bool {
        self.multicast_enabled
    }
}

impl<S: UdpSocket> Transport for WifiUdpTransport<S> {
    fn init(&mut self) -> Result<()> {
        // Already initialized in new()
        Ok(())
    }

    fn send(&mut self, data: &[u8], dest: &Locator) -> Result<usize> {
        // Extract IPv4 address from locator
        if dest.kind != Locator::KIND_UDPV4 {
            return Err(Error::InvalidParameter);
        }

        // IPv4-mapped IPv6 address: last 4 bytes are the IPv4 address
        let dest_ip = [
            dest.address[12],
            dest.address[13],
            dest.address[14],
            dest.address[15],
        ];
        let dest_port = dest.port as u16;

        self.socket.send_to(data, dest_ip, dest_port)
    }

    fn recv(&mut self, buf: &mut [u8]) -> Result<(usize, Locator)> {
        let (size, src_ip, src_port) = self.socket.recv_from(buf)?;

        let locator = Locator::udpv4(src_ip, src_port);

        Ok((size, locator))
    }

    fn try_recv(&mut self, buf: &mut [u8]) -> Result<(usize, Locator)> {
        let (size, src_ip, src_port) = self.socket.try_recv_from(buf)?;

        let locator = Locator::udpv4(src_ip, src_port);

        Ok((size, locator))
    }

    fn local_locator(&self) -> Locator {
        let ip = self.socket.local_ip();
        let port = self.socket.local_port();

        Locator::udpv4(ip, port)
    }

    fn mtu(&self) -> usize {
        // Standard Ethernet MTU - IP header - UDP header
        1500 - 20 - 8
    }

    fn shutdown(&mut self) -> Result<()> {
        // Nothing to cleanup for UDP
        Ok(())
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    #[test]
    fn test_std_udp_socket_creation() {
        let socket = StdUdpSocket::new();
        assert_eq!(socket.local_ip, [0, 0, 0, 0]); // Not bound yet
    }

    #[test]
    fn test_std_udp_socket_bind() {
        let mut socket = StdUdpSocket::new();
        socket.bind(0).unwrap(); // OS assigns port

        let port = socket.local_port();
        assert!(port > 0);
    }

    #[test]
    fn test_wifi_transport_creation() {
        let socket = StdUdpSocket::new();
        let transport = WifiUdpTransport::new(socket, 0).unwrap();

        assert!(!transport.is_multicast_enabled());
        assert!(transport.local_locator().port > 0);
    }

    #[test]
    fn test_wifi_transport_loopback() {
        let socket1 = StdUdpSocket::new();
        let mut transport1 = WifiUdpTransport::new(socket1, 0).unwrap();

        let socket2 = StdUdpSocket::new();
        let mut transport2 = WifiUdpTransport::new(socket2, 0).unwrap();

        // Get transport1's locator to send to
        let dest = transport1.local_locator();

        // Send from transport2 to transport1
        let data = b"Hello, HDDS Micro!";
        let sent = transport2.send(data, &dest).unwrap();
        assert_eq!(sent, data.len());

        // Receive on transport1
        let mut buf = [0u8; 128];
        let (received, source) = transport1.recv(&mut buf).unwrap();

        assert_eq!(received, data.len());
        assert_eq!(&buf[0..received], data);
        assert_eq!(source.port, transport2.local_locator().port);
    }

    #[test]
    fn test_wifi_transport_try_recv_no_data() {
        let socket = StdUdpSocket::new();
        let mut transport = WifiUdpTransport::new(socket, 0).unwrap();

        let mut buf = [0u8; 128];
        let result = transport.try_recv(&mut buf);

        assert_eq!(result, Err(Error::ResourceExhausted));
    }

    #[test]
    fn test_wifi_transport_multicast() {
        let socket = StdUdpSocket::new();
        let mut transport = WifiUdpTransport::new(socket, 0).unwrap();

        // Enable multicast on standard DDS multicast group
        let result = transport.enable_multicast([239, 255, 0, 1]);

        // May fail on some systems without multicast support
        if result.is_ok() {
            assert!(transport.is_multicast_enabled());
        }
    }
}
