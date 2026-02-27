// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! ByteStream trait for TCP and TLS abstraction.
//!
//! This module provides a trait abstraction over byte streams to enable:
//! - Plain TCP (`TcpStream`)
//! - Future TLS support (`TlsStream<TcpStream>`)
//! - Testing with mock streams
//!
//! The trait is designed to work with non-blocking I/O via mio.
//!
//! # Example
//!
//! ```ignore
//! use hdds::transport::tcp::ByteStream;
//!
//! fn send_message<S: ByteStream>(stream: &mut S, msg: &[u8]) -> io::Result<()> {
//!     stream.write_all(msg)?;
//!     stream.flush()
//! }
//! ```

use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::time::Duration;

#[cfg(unix)]
use std::os::unix::io::{AsRawFd, RawFd};

#[cfg(windows)]
use std::os::windows::io::{AsRawSocket, RawSocket};

/// Abstraction over byte-oriented streams.
///
/// This trait unifies plain TCP and TLS streams, allowing the transport
/// layer to be agnostic about encryption.
///
/// # Implementation Notes
///
/// - Implementations should be non-blocking by default
/// - `poll_readable` and `poll_writable` are hints for the I/O loop
/// - TLS implementations must handle handshake internally
pub trait ByteStream: Read + Write + Send {
    /// Shutdown the stream.
    fn shutdown(&mut self, how: Shutdown) -> io::Result<()>;

    /// Get the local address of this stream.
    fn local_addr(&self) -> io::Result<SocketAddr>;

    /// Get the peer address of this stream.
    fn peer_addr(&self) -> io::Result<SocketAddr>;

    /// Set non-blocking mode.
    fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()>;

    /// Set TCP_NODELAY (disable Nagle's algorithm).
    fn set_nodelay(&self, nodelay: bool) -> io::Result<()>;

    /// Get TCP_NODELAY setting.
    fn nodelay(&self) -> io::Result<bool>;

    /// Set read timeout.
    fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()>;

    /// Set write timeout.
    fn set_write_timeout(&self, dur: Option<Duration>) -> io::Result<()>;

    /// Take error from the socket.
    fn take_error(&self) -> io::Result<Option<io::Error>>;

    /// Check if this is a TLS stream (for logging/debugging).
    fn is_tls(&self) -> bool {
        false
    }

    /// Get the raw file descriptor (Unix) or socket (Windows).
    ///
    /// Used for registering with mio::Poll.
    #[cfg(unix)]
    fn as_raw_fd(&self) -> RawFd;

    #[cfg(windows)]
    fn as_raw_socket(&self) -> RawSocket;
}

// ============================================================================
// TcpStream implementation
// ============================================================================

impl ByteStream for TcpStream {
    fn shutdown(&mut self, how: Shutdown) -> io::Result<()> {
        TcpStream::shutdown(self, how)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        TcpStream::local_addr(self)
    }

    fn peer_addr(&self) -> io::Result<SocketAddr> {
        TcpStream::peer_addr(self)
    }

    fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        TcpStream::set_nonblocking(self, nonblocking)
    }

    fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        TcpStream::set_nodelay(self, nodelay)
    }

    fn nodelay(&self) -> io::Result<bool> {
        TcpStream::nodelay(self)
    }

    fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        TcpStream::set_read_timeout(self, dur)
    }

    fn set_write_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        TcpStream::set_write_timeout(self, dur)
    }

    fn take_error(&self) -> io::Result<Option<io::Error>> {
        TcpStream::take_error(self)
    }

    #[cfg(unix)]
    fn as_raw_fd(&self) -> RawFd {
        AsRawFd::as_raw_fd(self)
    }

    #[cfg(windows)]
    fn as_raw_socket(&self) -> RawSocket {
        AsRawSocket::as_raw_socket(self)
    }
}

// ============================================================================
// Boxed ByteStream
// ============================================================================

/// Type alias for a boxed ByteStream.
pub type BoxedByteStream = Box<dyn ByteStream>;

impl ByteStream for BoxedByteStream {
    fn shutdown(&mut self, how: Shutdown) -> io::Result<()> {
        (**self).shutdown(how)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        (**self).local_addr()
    }

    fn peer_addr(&self) -> io::Result<SocketAddr> {
        (**self).peer_addr()
    }

    fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        (**self).set_nonblocking(nonblocking)
    }

    fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        (**self).set_nodelay(nodelay)
    }

    fn nodelay(&self) -> io::Result<bool> {
        (**self).nodelay()
    }

    fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        (**self).set_read_timeout(dur)
    }

    fn set_write_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        (**self).set_write_timeout(dur)
    }

    fn take_error(&self) -> io::Result<Option<io::Error>> {
        (**self).take_error()
    }

    fn is_tls(&self) -> bool {
        (**self).is_tls()
    }

    #[cfg(unix)]
    fn as_raw_fd(&self) -> RawFd {
        (**self).as_raw_fd()
    }

    #[cfg(windows)]
    fn as_raw_socket(&self) -> RawSocket {
        (**self).as_raw_socket()
    }
}

// ============================================================================
// Test mock stream
// ============================================================================

#[cfg(test)]
pub mod mock {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    /// Mock byte stream for testing.
    ///
    /// Provides configurable read/write behavior including:
    /// - Buffered data for reading
    /// - Write capture for verification
    /// - Error injection
    #[derive(Debug)]
    pub struct MockStream {
        /// Data available for reading
        read_data: Arc<Mutex<VecDeque<u8>>>,

        /// Data written (for verification)
        write_data: Arc<Mutex<Vec<u8>>>,

        /// Whether to return WouldBlock on empty read
        nonblocking: bool,

        /// Whether the stream is "connected"
        connected: bool,

        /// Simulated local address
        local_addr: SocketAddr,

        /// Simulated peer address
        peer_addr: SocketAddr,

        /// Error to inject on next read
        read_error: Option<io::ErrorKind>,

        /// Error to inject on next write
        write_error: Option<io::ErrorKind>,

        /// TCP_NODELAY setting
        nodelay: bool,
    }

    impl MockStream {
        /// Create a new mock stream.
        pub fn new() -> Self {
            Self {
                read_data: Arc::new(Mutex::new(VecDeque::new())),
                write_data: Arc::new(Mutex::new(Vec::new())),
                nonblocking: true,
                connected: true,
                local_addr: "127.0.0.1:12345".parse().unwrap(),
                peer_addr: "127.0.0.1:54321".parse().unwrap(),
                read_error: None,
                write_error: None,
                nodelay: true,
            }
        }

        /// Create a connected pair of mock streams.
        pub fn pair() -> (Self, Self) {
            let a_to_b = Arc::new(Mutex::new(VecDeque::new()));
            let b_to_a = Arc::new(Mutex::new(VecDeque::new()));

            let stream_a = Self {
                read_data: b_to_a.clone(),
                write_data: Arc::new(Mutex::new(Vec::new())),
                nonblocking: true,
                connected: true,
                local_addr: "127.0.0.1:10001".parse().unwrap(),
                peer_addr: "127.0.0.1:10002".parse().unwrap(),
                read_error: None,
                write_error: None,
                nodelay: true,
            };

            let stream_b = Self {
                read_data: a_to_b,
                write_data: Arc::new(Mutex::new(Vec::new())),
                nonblocking: true,
                connected: true,
                local_addr: "127.0.0.1:10002".parse().unwrap(),
                peer_addr: "127.0.0.1:10001".parse().unwrap(),
                read_error: None,
                write_error: None,
                nodelay: true,
            };

            (stream_a, stream_b)
        }

        /// Add data to the read buffer.
        pub fn feed_read_data(&self, data: &[u8]) {
            let mut buf = self.read_data.lock().unwrap();
            buf.extend(data);
        }

        /// Get all data written to this stream.
        pub fn get_written_data(&self) -> Vec<u8> {
            self.write_data.lock().unwrap().clone()
        }

        /// Clear the write buffer.
        pub fn clear_written_data(&self) {
            self.write_data.lock().unwrap().clear();
        }

        /// Inject a read error.
        pub fn inject_read_error(&mut self, kind: io::ErrorKind) {
            self.read_error = Some(kind);
        }

        /// Inject a write error.
        pub fn inject_write_error(&mut self, kind: io::ErrorKind) {
            self.write_error = Some(kind);
        }

        /// Clear injected errors.
        pub fn clear_errors(&mut self) {
            self.read_error = None;
            self.write_error = None;
        }

        /// Disconnect the stream.
        pub fn disconnect(&mut self) {
            self.connected = false;
        }
    }

    impl Default for MockStream {
        fn default() -> Self {
            Self::new()
        }
    }

    impl Read for MockStream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if let Some(kind) = self.read_error.take() {
                return Err(io::Error::new(kind, "injected error"));
            }

            if !self.connected {
                return Ok(0); // EOF
            }

            let mut data = self.read_data.lock().unwrap();
            if data.is_empty() {
                if self.nonblocking {
                    return Err(io::Error::new(io::ErrorKind::WouldBlock, "would block"));
                } else {
                    return Ok(0);
                }
            }

            let to_read = buf.len().min(data.len());
            for (i, byte) in data.drain(..to_read).enumerate() {
                buf[i] = byte;
            }
            Ok(to_read)
        }
    }

    impl Write for MockStream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if let Some(kind) = self.write_error.take() {
                return Err(io::Error::new(kind, "injected error"));
            }

            if !self.connected {
                return Err(io::Error::new(io::ErrorKind::BrokenPipe, "not connected"));
            }

            let mut data = self.write_data.lock().unwrap();
            data.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl ByteStream for MockStream {
        fn shutdown(&mut self, _how: Shutdown) -> io::Result<()> {
            self.connected = false;
            Ok(())
        }

        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok(self.local_addr)
        }

        fn peer_addr(&self) -> io::Result<SocketAddr> {
            Ok(self.peer_addr)
        }

        fn set_nonblocking(&self, _nonblocking: bool) -> io::Result<()> {
            // Can't modify self in mock - would need RefCell
            Ok(())
        }

        fn set_nodelay(&self, _nodelay: bool) -> io::Result<()> {
            Ok(())
        }

        fn nodelay(&self) -> io::Result<bool> {
            Ok(self.nodelay)
        }

        fn set_read_timeout(&self, _dur: Option<Duration>) -> io::Result<()> {
            Ok(())
        }

        fn set_write_timeout(&self, _dur: Option<Duration>) -> io::Result<()> {
            Ok(())
        }

        fn take_error(&self) -> io::Result<Option<io::Error>> {
            Ok(None)
        }

        #[cfg(unix)]
        fn as_raw_fd(&self) -> RawFd {
            -1 // Invalid FD for mock
        }

        #[cfg(windows)]
        fn as_raw_socket(&self) -> RawSocket {
            0 // Invalid for mock
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    #[test]
    fn test_tcp_stream_trait_object() {
        // Verify TcpStream can be used as trait object
        // This stub function proves the trait is object-safe (can be used as dyn ByteStream)
        fn _accept_stream(_s: &dyn ByteStream) {
            // Intentionally empty - only used for compile-time trait object safety check.
        }

        // Can't actually test without a real connection,
        // but we can verify the trait is object-safe
    }

    #[test]
    fn test_mock_stream_basic() {
        let mut stream = mock::MockStream::new();

        // Write some data
        stream.write_all(b"hello").unwrap();
        assert_eq!(stream.get_written_data(), b"hello");

        // Read should WouldBlock (nonblocking, no data)
        let mut buf = [0u8; 10];
        let result = stream.read(&mut buf);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::WouldBlock);

        // Feed data and read
        stream.feed_read_data(b"world");
        let n = stream.read(&mut buf).unwrap();
        assert_eq!(n, 5);
        assert_eq!(&buf[..n], b"world");
    }

    #[test]
    fn test_mock_stream_error_injection() {
        let mut stream = mock::MockStream::new();

        stream.inject_read_error(io::ErrorKind::ConnectionReset);
        let mut buf = [0u8; 10];
        let result = stream.read(&mut buf);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::ConnectionReset);

        // Error is cleared after one use
        stream.feed_read_data(b"ok");
        assert!(stream.read(&mut buf).is_ok());

        stream.inject_write_error(io::ErrorKind::BrokenPipe);
        let result = stream.write(b"test");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::BrokenPipe);
    }

    #[test]
    fn test_mock_stream_disconnect() {
        let mut stream = mock::MockStream::new();

        stream.disconnect();

        // Read returns 0 (EOF)
        let mut buf = [0u8; 10];
        assert_eq!(stream.read(&mut buf).unwrap(), 0);

        // Write returns error
        assert!(stream.write(b"test").is_err());
    }

    #[test]
    fn test_mock_stream_addresses() {
        let stream = mock::MockStream::new();

        assert!(stream.local_addr().is_ok());
        assert!(stream.peer_addr().is_ok());
        assert_ne!(stream.local_addr().unwrap(), stream.peer_addr().unwrap());
    }

    #[test]
    fn test_mock_stream_pair() {
        let (mut a, mut b) = mock::MockStream::pair();

        // Data written to a's write_data (would normally go to b)
        a.write_all(b"from a").unwrap();
        assert_eq!(a.get_written_data(), b"from a");

        // Feed data directly for test (simulating transfer)
        b.feed_read_data(b"from a");

        let mut buf = [0u8; 10];
        let n = b.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"from a");
    }

    #[test]
    fn test_byte_stream_is_tls() {
        let stream = mock::MockStream::new();
        assert!(!stream.is_tls());
    }
}
