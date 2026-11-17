// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

// Transport abstraction for UDP, Serial and TCP.
//
// Every listener defaults to loopback. An XRCE agent is an unauthenticated
// write path into a DDS domain, so binding every interface is something the
// operator asks for by name, never something a default does quietly.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};

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

/// Reject a wildcard bind that the caller did not ask for explicitly.
fn check_not_wildcard(addr: IpAddr) -> Result<(), XrceError> {
    if addr.is_unspecified() {
        return Err(XrceError::ConfigError(
            "refusing to bind the wildcard address implicitly; pass --bind-any (bind_any() from Rust) to listen on every interface".into(),
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// UDP transport
// ---------------------------------------------------------------------------

/// UDP transport on `std::net::UdpSocket`.
///
/// No `socket2`, no `MaybeUninit` cast: the standard library covers a
/// non-blocking datagram socket, which is all the agent loop needs.
pub struct UdpTransport {
    socket: UdpSocket,
}

impl UdpTransport {
    /// Bind a UDP socket to `127.0.0.1:<port>`.
    pub fn bind(port: u16) -> Result<Self, XrceError> {
        Self::bind_on(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
    }

    /// Bind a UDP socket to an explicit address. Wildcard addresses are
    /// refused here; use [`UdpTransport::bind_any`].
    pub fn bind_on(addr: IpAddr, port: u16) -> Result<Self, XrceError> {
        check_not_wildcard(addr)?;
        Self::bind_unchecked(SocketAddr::new(addr, port))
    }

    /// Bind a UDP socket to every interface. Explicit by construction.
    pub fn bind_any(port: u16) -> Result<Self, XrceError> {
        Self::bind_unchecked(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port))
    }

    fn bind_unchecked(addr: SocketAddr) -> Result<Self, XrceError> {
        let socket = UdpSocket::bind(addr)?;
        // Non-blocking so the agent loop can poll.
        socket.set_nonblocking(true)?;
        Ok(Self { socket })
    }

    /// The address the socket actually bound to (port 0 resolves here).
    pub fn local_addr(&self) -> Result<SocketAddr, XrceError> {
        Ok(self.socket.local_addr()?)
    }
}

impl XrceTransport for UdpTransport {
    fn recv(&mut self, buf: &mut [u8]) -> Result<(usize, TransportAddr), XrceError> {
        let (n, peer) = self.socket.recv_from(buf)?;
        Ok((n, TransportAddr::Udp(peer)))
    }

    fn send(&mut self, addr: &TransportAddr, data: &[u8]) -> Result<(), XrceError> {
        match addr {
            TransportAddr::Udp(sa) => {
                self.socket.send_to(data, sa)?;
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
/// Baud rate, parity and flow control are NOT configured here: setting them
/// needs `termios` through `libc`, i.e. an FFI dependency with `unsafe`, and
/// this crate stays free of both. Configure the device externally
/// (`stty -F /dev/ttyUSB0 115200 raw -echo`) before opening it; the
/// `serial_baud` field of the config is documentation for the operator, not
/// something this transport applies.
pub struct SerialTransport {
    device_path: String,
    reader: std::fs::File,
    writer: std::fs::File,
}

impl SerialTransport {
    /// Open a serial device for XRCE communication.
    pub fn open(device_path: &str) -> Result<Self, XrceError> {
        use std::fs::OpenOptions;
        let reader = OpenOptions::new().read(true).open(device_path)?;
        let writer = OpenOptions::new().write(true).open(device_path)?;
        Ok(Self {
            device_path: device_path.to_string(),
            reader,
            writer,
        })
    }
}

impl XrceTransport for SerialTransport {
    fn recv(&mut self, buf: &mut [u8]) -> Result<(usize, TransportAddr), XrceError> {
        let n = self.reader.read(buf)?;
        Ok((n, TransportAddr::Serial(self.device_path.clone())))
    }

    fn send(&mut self, _addr: &TransportAddr, data: &[u8]) -> Result<(), XrceError> {
        self.writer.write_all(data)?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// TCP transport
// ---------------------------------------------------------------------------

/// Length prefix carried before every XRCE message on a stream transport
/// (DDS-XRCE 1.0 TCP framing: `unsigned short` length, little endian).
pub const TCP_LENGTH_PREFIX_SIZE: usize = 2;

/// Wrap one XRCE message in its TCP length prefix.
pub fn tcp_frame(message: &[u8]) -> Result<Vec<u8>, XrceError> {
    if message.len() > u16::MAX as usize {
        return Err(XrceError::Io("message exceeds the TCP frame length".into()));
    }
    let mut out = Vec::with_capacity(TCP_LENGTH_PREFIX_SIZE + message.len());
    out.extend_from_slice(&(message.len() as u16).to_le_bytes());
    out.extend_from_slice(message);
    Ok(out)
}

/// Per-connection inbound state: a byte stream is not a datagram stream, so
/// bytes are accumulated until a whole length-prefixed message is present.
struct TcpPeer {
    stream: TcpStream,
    inbox: Vec<u8>,
}

impl TcpPeer {
    /// Pop one complete message from the accumulated bytes, if any.
    fn take_message(&mut self) -> Option<Vec<u8>> {
        if self.inbox.len() < TCP_LENGTH_PREFIX_SIZE {
            return None;
        }
        let len = u16::from_le_bytes([self.inbox[0], self.inbox[1]]) as usize;
        if self.inbox.len() < TCP_LENGTH_PREFIX_SIZE + len {
            return None;
        }
        let msg = self.inbox[TCP_LENGTH_PREFIX_SIZE..TCP_LENGTH_PREFIX_SIZE + len].to_vec();
        self.inbox.drain(..TCP_LENGTH_PREFIX_SIZE + len);
        Some(msg)
    }
}

/// TCP transport that accepts connections and multiplexes them.
///
/// Messages are length-prefixed on the wire, so a `read()` that splits or
/// merges messages no longer corrupts the stream.
pub struct TcpTransport {
    listener: TcpListener,
    connections: HashMap<SocketAddr, TcpPeer>,
    /// Largest message accepted from a peer; a bigger length prefix drops the
    /// connection instead of allocating what the peer asked for.
    max_message_size: usize,
}

impl TcpTransport {
    /// Bind a TCP listener on `127.0.0.1:<port>`.
    pub fn bind(port: u16) -> Result<Self, XrceError> {
        Self::bind_on(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
    }

    /// Bind a TCP listener on an explicit address. Wildcard addresses are
    /// refused here; use [`TcpTransport::bind_any`].
    pub fn bind_on(addr: IpAddr, port: u16) -> Result<Self, XrceError> {
        check_not_wildcard(addr)?;
        Self::bind_unchecked(SocketAddr::new(addr, port))
    }

    /// Bind a TCP listener on every interface. Explicit by construction.
    pub fn bind_any(port: u16) -> Result<Self, XrceError> {
        Self::bind_unchecked(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port))
    }

    fn bind_unchecked(addr: SocketAddr) -> Result<Self, XrceError> {
        let listener = TcpListener::bind(addr)?;
        listener.set_nonblocking(true)?;
        Ok(Self {
            listener,
            connections: HashMap::new(),
            max_message_size: u16::MAX as usize,
        })
    }

    /// Cap the size of an inbound message. Frames longer than this drop the
    /// offending connection.
    pub fn with_max_message_size(mut self, max: usize) -> Self {
        self.max_message_size = max;
        self
    }

    /// The address the listener actually bound to (port 0 resolves here).
    pub fn local_addr(&self) -> Result<SocketAddr, XrceError> {
        Ok(self.listener.local_addr()?)
    }

    /// Number of live connections.
    pub fn connection_count(&self) -> usize {
        self.connections.len()
    }

    /// Try to accept new connections (non-blocking).
    fn accept_new(&mut self) {
        while let Ok((stream, addr)) = self.listener.accept() {
            let _ = stream.set_nonblocking(true);
            self.connections.insert(
                addr,
                TcpPeer {
                    stream,
                    inbox: Vec::new(),
                },
            );
        }
    }
}

impl XrceTransport for TcpTransport {
    fn recv(&mut self, buf: &mut [u8]) -> Result<(usize, TransportAddr), XrceError> {
        self.accept_new();

        let addrs: Vec<SocketAddr> = self.connections.keys().copied().collect();
        let mut chunk = [0u8; 1024];
        for addr in &addrs {
            // Drain whatever the socket has, then look for a complete frame.
            while let Some(peer) = self.connections.get_mut(addr) {
                let read = peer.stream.read(&mut chunk);
                match read {
                    Ok(0) => {
                        self.connections.remove(addr);
                        break;
                    }
                    Ok(n) => {
                        if let Some(peer) = self.connections.get_mut(addr) {
                            if peer.inbox.len() + n > self.max_message_size * 2 {
                                log::warn!("TCP peer {} exceeded the inbox budget", addr);
                                self.connections.remove(addr);
                                break;
                            }
                            peer.inbox.extend_from_slice(&chunk[..n]);
                        }
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(_) => {
                        self.connections.remove(addr);
                        break;
                    }
                }
            }

            let (message, oversized) = match self.connections.get_mut(addr) {
                Some(peer) => {
                    let too_long = peer.inbox.len() >= TCP_LENGTH_PREFIX_SIZE
                        && u16::from_le_bytes([peer.inbox[0], peer.inbox[1]]) as usize
                            > self.max_message_size;
                    (peer.take_message(), too_long)
                }
                None => (None, false),
            };
            if oversized {
                log::warn!("TCP peer {} announced an oversized frame", addr);
                self.connections.remove(addr);
                continue;
            }
            if let Some(msg) = message {
                // The frame has already been taken out of the inbox, so a
                // buffer that cannot hold it means the tail is gone. Copying
                // the prefix and reporting it as a whole message would hand
                // the agent a truncated submessage sequence to execute -
                // exactly the stream corruption the length prefix exists to
                // prevent. Report it instead.
                if msg.len() > buf.len() {
                    return Err(XrceError::PayloadTooLarge(msg.len()));
                }
                buf[..msg.len()].copy_from_slice(&msg);
                return Ok((msg.len(), TransportAddr::Tcp(*addr)));
            }
        }
        Err(XrceError::Io("no data available".into()))
    }

    fn send(&mut self, addr: &TransportAddr, data: &[u8]) -> Result<(), XrceError> {
        match addr {
            TransportAddr::Tcp(sa) => {
                let framed = tcp_frame(data)?;
                if let Some(peer) = self.connections.get_mut(sa) {
                    peer.stream.write_all(&framed)?;
                    Ok(())
                } else {
                    Err(XrceError::Io("TCP peer not connected".into()))
                }
            }
            _ => Err(XrceError::Io("TCP transport requires TCP address".into())),
        }
    }
}
