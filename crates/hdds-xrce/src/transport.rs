// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

// Transport abstraction for UDP, Serial and TCP.

use std::net::SocketAddr;

use crate::protocol::XrceError;

// ---------------------------------------------------------------------------
// Transport address
// ---------------------------------------------------------------------------

/// Address identifying a remote XRCE client over any transport.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TransportAddr {
    /// UDP socket address.
    Udp(SocketAddr),
    /// Serial port - only one peer, address is the device path.
    Serial(String),
    /// TCP connection identified by peer address.
    Tcp(SocketAddr),
}

// ---------------------------------------------------------------------------
// Transport trait
// ---------------------------------------------------------------------------

/// Abstraction over the physical transport used between the XRCE agent
/// and its clients.
pub trait XrceTransport: Send {
    /// Receive bytes into `buf`. Returns (bytes_read, sender_address).
    fn recv(&mut self, buf: &mut [u8]) -> Result<(usize, TransportAddr), XrceError>;

    /// Send `data` to the given address.
    fn send(&mut self, addr: &TransportAddr, data: &[u8]) -> Result<(), XrceError>;
}

// ---------------------------------------------------------------------------
// UDP transport
// ---------------------------------------------------------------------------

/// UDP transport using `socket2`.
pub struct UdpTransport {
    socket: socket2::Socket,
}

impl UdpTransport {
    /// Bind a UDP socket to `0.0.0.0:<port>`.
    pub fn bind(port: u16) -> Result<Self, XrceError> {
        let addr: SocketAddr = ([0, 0, 0, 0], port).into();
        let sa: socket2::SockAddr = addr.into();
        let socket = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )?;
        socket.set_reuse_address(true)?;
        socket.bind(&sa)?;
        // Non-blocking so the agent loop can poll
        socket.set_nonblocking(true)?;
        Ok(Self { socket })
    }
}

impl XrceTransport for UdpTransport {
    fn recv(&mut self, buf: &mut [u8]) -> Result<(usize, TransportAddr), XrceError> {
        let buf_ref = unsafe {
            // socket2 wants MaybeUninit slice; we have a zeroed buffer.
            &mut *(buf as *mut [u8] as *mut [std::mem::MaybeUninit<u8>])
        };
        let (n, addr) = self.socket.recv_from(buf_ref)?;
        let peer: SocketAddr = addr
            .as_socket()
            .ok_or_else(|| XrceError::Io("invalid peer address".into()))?;
        Ok((n, TransportAddr::Udp(peer)))
    }

    fn send(&mut self, addr: &TransportAddr, data: &[u8]) -> Result<(), XrceError> {
        match addr {
            TransportAddr::Udp(sa) => {
                let sa2: socket2::SockAddr = (*sa).into();
                self.socket.send_to(data, &sa2)?;
                Ok(())
            }
            _ => Err(XrceError::Io("UDP transport requires UDP address".into())),
        }
    }
}

// ---------------------------------------------------------------------------
// Serial transport (file-based)
// ---------------------------------------------------------------------------

/// Serial transport using basic file I/O.
///
/// On Linux this opens the serial device as a regular file. Baud rate
/// configuration is expected to be done externally (e.g. via `stty`).
pub struct SerialTransport {
    device_path: String,
    reader: std::fs::File,
    writer: std::fs::File,
}

impl SerialTransport {
    /// Open a serial device for XRCE communication.
    pub fn open(device_path: &str) -> Result<Self, XrceError> {
        use std::fs::OpenOptions;
        let reader = OpenOptions::new()
            .read(true)
            .open(device_path)?;
        let writer = OpenOptions::new()
            .write(true)
            .open(device_path)?;
        Ok(Self {
            device_path: device_path.to_string(),
            reader,
            writer,
        })
    }
}

impl XrceTransport for SerialTransport {
    fn recv(&mut self, buf: &mut [u8]) -> Result<(usize, TransportAddr), XrceError> {
        use std::io::Read;
        let n = self.reader.read(buf)?;
        Ok((n, TransportAddr::Serial(self.device_path.clone())))
    }

    fn send(&mut self, _addr: &TransportAddr, data: &[u8]) -> Result<(), XrceError> {
        use std::io::Write;
        self.writer.write_all(data)?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// TCP transport
// ---------------------------------------------------------------------------

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::net::TcpStream;

/// TCP transport that accepts connections and multiplexes them.
pub struct TcpTransport {
    listener: TcpListener,
    connections: HashMap<SocketAddr, TcpStream>,
    /// Addresses of connections with pending data (round-robin).
    pending: Vec<SocketAddr>,
}

impl TcpTransport {
    /// Bind a TCP listener on `0.0.0.0:<port>`.
    pub fn bind(port: u16) -> Result<Self, XrceError> {
        let listener = TcpListener::bind(("0.0.0.0", port))?;
        listener.set_nonblocking(true)?;
        Ok(Self {
            listener,
            connections: HashMap::new(),
            pending: Vec::new(),
        })
    }

    /// Try to accept new connections (non-blocking).
    fn accept_new(&mut self) {
        while let Ok((stream, addr)) = self.listener.accept() {
            let _ = stream.set_nonblocking(true);
            self.connections.insert(addr, stream);
            self.pending.push(addr);
        }
    }
}

impl XrceTransport for TcpTransport {
    fn recv(&mut self, buf: &mut [u8]) -> Result<(usize, TransportAddr), XrceError> {
        self.accept_new();

        // Round-robin across connected peers.
        let addrs: Vec<SocketAddr> = self.connections.keys().copied().collect();
        for addr in &addrs {
            if let Some(stream) = self.connections.get_mut(addr) {
                match stream.read(buf) {
                    Ok(0) => {
                        // Connection closed
                        self.connections.remove(addr);
                        continue;
                    }
                    Ok(n) => return Ok((n, TransportAddr::Tcp(*addr))),
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                    Err(e) => {
                        self.connections.remove(addr);
                        return Err(XrceError::Io(e.to_string()));
                    }
                }
            }
        }
        Err(XrceError::Io("no data available".into()))
    }

    fn send(&mut self, addr: &TransportAddr, data: &[u8]) -> Result<(), XrceError> {
        match addr {
            TransportAddr::Tcp(sa) => {
                if let Some(stream) = self.connections.get_mut(sa) {
                    stream.write_all(data)?;
                    Ok(())
                } else {
                    Err(XrceError::Io("TCP peer not connected".into()))
                }
            }
            _ => Err(XrceError::Io("TCP transport requires TCP address".into())),
        }
    }
}
