// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! I/O thread for TCP transport.
//!
//! Provides a dedicated thread for handling TCP I/O using mio's poll-based
//! event loop. This ensures non-blocking operation and efficient multiplexing
//! of multiple connections.
//!
//! # Architecture
//!
//! ```text
//! +-------------------------------------------------------------+
//! |                        IoThread                              |
//! |  +-------------------------------------------------------+  |
//! |  |                    mio::Poll                           |  |
//! |  |  - TCP Listener (accept new connections)              |  |
//! |  |  - TCP Streams (read/write data)                      |  |
//! |  |  - Waker (receive commands from main thread)          |  |
//! |  +-------------------------------------------------------+  |
//! |                              |                               |
//! |                              v                               |
//! |  +-------------+    +-------------+    +-----------------+  |
//! |  |   Accept    |    |    Read     |    |     Write       |  |
//! |  |  new conn   |    |   frames    |    |    frames       |  |
//! |  +-------------+    +-------------+    +-----------------+  |
//! |                              |                               |
//! |                              v                               |
//! |  +-------------------------------------------------------+  |
//! |  |              Event Channel -> Main Thread              |  |
//! |  +-------------------------------------------------------+  |
//! +-------------------------------------------------------------+
//! ```

use std::collections::HashMap;
#[cfg(feature = "tcp-tls")]
use std::io::Read;
use std::io::{self, Write};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender, TryRecvError};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use mio::net::{TcpListener, TcpStream};
use mio::{Events, Interest, Poll, Token, Waker};

use super::connection::ConnectionState;
use super::frame_codec::FrameCodec;
use super::metrics::TcpTransportMetrics;
use super::TcpConfig;

// v233: TLS support via rustls
#[cfg(feature = "tcp-tls")]
use rustls::pki_types::ServerName;

// ============================================================================
// Constants
// ============================================================================

/// Token for the TCP listener
const LISTENER_TOKEN: Token = Token(0);

/// Token for the waker (command channel)
const WAKER_TOKEN: Token = Token(1);

/// Starting token for connections
const CONNECTION_TOKEN_START: usize = 2;

/// Default poll timeout
const DEFAULT_POLL_TIMEOUT: Duration = Duration::from_millis(100);

/// Maximum events to process per poll
const MAX_EVENTS: usize = 128;

// ============================================================================
// Events and Commands
// ============================================================================

/// Events emitted by the I/O thread.
#[derive(Debug)]
pub enum TcpEvent {
    /// New connection accepted
    ConnectionAccepted {
        /// Connection ID
        conn_id: u64,
        /// Remote address
        remote_addr: SocketAddr,
    },

    /// Outbound connection established
    ConnectionEstablished {
        /// Connection ID
        conn_id: u64,
        /// Remote address
        remote_addr: SocketAddr,
    },

    /// Connection closed or failed
    ConnectionClosed {
        /// Connection ID
        conn_id: u64,
        /// Remote address
        remote_addr: SocketAddr,
        /// Reason (if any)
        reason: Option<String>,
    },

    /// Message received
    MessageReceived {
        /// Connection ID
        conn_id: u64,
        /// Remote address
        remote_addr: SocketAddr,
        /// Message payload
        payload: Vec<u8>,
    },

    /// Connection ready for writing (backpressure cleared)
    WriteReady {
        /// Connection ID
        conn_id: u64,
    },

    /// I/O thread started
    Started {
        /// Local listener address (if listening)
        local_addr: Option<SocketAddr>,
    },

    /// I/O thread stopped
    Stopped,

    /// Error occurred
    Error {
        /// Connection ID (if connection-specific)
        conn_id: Option<u64>,
        /// Error description
        error: String,
    },
}

/// Commands sent to the I/O thread.
#[derive(Debug)]
pub enum IoCommand {
    /// Connect to a remote address
    Connect {
        /// Target address
        addr: SocketAddr,
        /// Connection ID to assign
        conn_id: u64,
    },

    /// Send a message on a connection
    Send {
        /// Connection ID
        conn_id: u64,
        /// Message payload
        payload: Vec<u8>,
    },

    /// Close a connection
    Close {
        /// Connection ID
        conn_id: u64,
    },

    /// Shutdown the I/O thread
    Shutdown,
}

// ============================================================================
// I/O Thread Handle
// ============================================================================

/// Handle for interacting with the I/O thread.
///
/// Provides methods to send commands and receive events.
pub struct IoThreadHandle {
    /// Command sender
    cmd_tx: Sender<IoCommand>,

    /// Event receiver
    event_rx: Receiver<TcpEvent>,

    /// Waker to wake the poll
    waker: Arc<Waker>,

    /// Thread handle
    thread_handle: Option<JoinHandle<()>>,

    /// Running flag
    running: Arc<AtomicBool>,

    /// Next connection ID
    next_conn_id: u64,
}

impl IoThreadHandle {
    /// Connect to a remote address.
    pub fn connect(&mut self, addr: SocketAddr) -> io::Result<u64> {
        let conn_id = self.next_conn_id;
        self.next_conn_id += 1;

        self.cmd_tx
            .send(IoCommand::Connect { addr, conn_id })
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "I/O thread stopped"))?;

        self.waker.wake()?;
        Ok(conn_id)
    }

    /// Send a message on a connection.
    pub fn send(&self, conn_id: u64, payload: Vec<u8>) -> io::Result<()> {
        self.cmd_tx
            .send(IoCommand::Send { conn_id, payload })
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "I/O thread stopped"))?;

        self.waker.wake()?;
        Ok(())
    }

    /// Close a connection.
    pub fn close(&self, conn_id: u64) -> io::Result<()> {
        self.cmd_tx
            .send(IoCommand::Close { conn_id })
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "I/O thread stopped"))?;

        self.waker.wake()?;
        Ok(())
    }

    /// Try to receive an event (non-blocking).
    pub fn try_recv(&self) -> Option<TcpEvent> {
        match self.event_rx.try_recv() {
            Ok(event) => Some(event),
            Err(TryRecvError::Empty) => None,
            Err(TryRecvError::Disconnected) => Some(TcpEvent::Stopped),
        }
    }

    /// Receive an event (blocking).
    pub fn recv(&self) -> Option<TcpEvent> {
        self.event_rx.recv().ok()
    }

    /// Receive an event with timeout.
    pub fn recv_timeout(&self, timeout: Duration) -> Option<TcpEvent> {
        self.event_rx.recv_timeout(timeout).ok()
    }

    /// Check if the I/O thread is running.
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    /// Shutdown the I/O thread.
    pub fn shutdown(&mut self) -> io::Result<()> {
        if !self.is_running() {
            return Ok(());
        }

        let _ = self.cmd_tx.send(IoCommand::Shutdown);
        let _ = self.waker.wake();

        if let Some(handle) = self.thread_handle.take() {
            handle
                .join()
                .map_err(|_| io::Error::other("I/O thread panicked"))?;
        }

        Ok(())
    }
}

impl Drop for IoThreadHandle {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

// ============================================================================
// I/O Thread
// ============================================================================

/// I/O thread state and runner.
pub struct IoThread {
    /// Configuration
    config: TcpConfig,

    /// mio Poll
    poll: Poll,

    /// TCP listener
    listener: Option<TcpListener>,

    /// Active connections by token
    connections: HashMap<Token, IoConnection>,

    /// Connection ID to token mapping
    conn_id_to_token: HashMap<u64, Token>,

    /// Next token ID
    next_token: usize,

    /// Command receiver
    cmd_rx: Receiver<IoCommand>,

    /// Event sender
    event_tx: Sender<TcpEvent>,

    /// Metrics
    metrics: Arc<TcpTransportMetrics>,

    /// Running flag
    running: Arc<AtomicBool>,

    // v233: TLS configuration (when tcp-tls feature enabled)
    #[cfg(feature = "tcp-tls")]
    tls_server_config: Option<Arc<rustls::ServerConfig>>,
    #[cfg(feature = "tcp-tls")]
    tls_client_config: Option<Arc<rustls::ClientConfig>>,
}

/// Per-connection state for the I/O thread.
struct IoConnection {
    /// mio TcpStream
    stream: TcpStream,

    /// Connection ID
    conn_id: u64,

    /// Remote address
    remote_addr: SocketAddr,

    /// Connection state
    state: ConnectionState,

    /// Frame codec
    codec: FrameCodec,

    /// Send queue (framed data)
    send_queue: Vec<u8>,

    /// Send offset (for partial writes)
    send_offset: usize,

    /// Whether we initiated this connection (used by tcp-tls feature)
    #[cfg_attr(not(feature = "tcp-tls"), allow(dead_code))]
    is_initiator: bool,

    // v233: TLS state (optional, only when tcp-tls feature enabled)
    #[cfg(feature = "tcp-tls")]
    tls_state: Option<TlsConnectionState>,
}

/// v233: TLS connection state wrapper for rustls integration
#[cfg(feature = "tcp-tls")]
enum TlsConnectionState {
    /// Client-side TLS connection
    Client(rustls::ClientConnection),
    /// Server-side TLS connection
    Server(rustls::ServerConnection),
}

#[cfg(feature = "tcp-tls")]
impl TlsConnectionState {
    /// Check if TLS handshake is still in progress
    fn is_handshaking(&self) -> bool {
        match self {
            Self::Client(conn) => conn.is_handshaking(),
            Self::Server(conn) => conn.is_handshaking(),
        }
    }

    /// Process incoming TLS data from the socket
    fn read_tls(&mut self, rd: &mut impl Read) -> io::Result<usize> {
        match self {
            Self::Client(conn) => conn.read_tls(rd),
            Self::Server(conn) => conn.read_tls(rd),
        }
    }

    /// Write outgoing TLS data to the socket
    fn write_tls(&mut self, wr: &mut impl Write) -> io::Result<usize> {
        match self {
            Self::Client(conn) => conn.write_tls(wr),
            Self::Server(conn) => conn.write_tls(wr),
        }
    }

    /// Process any new TLS packets
    fn process_new_packets(&mut self) -> Result<rustls::IoState, rustls::Error> {
        match self {
            Self::Client(conn) => conn.process_new_packets(),
            Self::Server(conn) => conn.process_new_packets(),
        }
    }

    /// Check if there's data to write
    fn wants_write(&self) -> bool {
        match self {
            Self::Client(conn) => conn.wants_write(),
            Self::Server(conn) => conn.wants_write(),
        }
    }

    /// Read plaintext from TLS
    fn reader(&mut self) -> impl Read + '_ {
        match self {
            Self::Client(conn) => TlsReader::Client(conn.reader()),
            Self::Server(conn) => TlsReader::Server(conn.reader()),
        }
    }

    /// Write plaintext to TLS
    fn writer(&mut self) -> impl Write + '_ {
        match self {
            Self::Client(conn) => TlsWriter::Client(conn.writer()),
            Self::Server(conn) => TlsWriter::Server(conn.writer()),
        }
    }
}

/// v233: Helper wrapper for TLS reader
#[cfg(feature = "tcp-tls")]
enum TlsReader<'a> {
    Client(rustls::Reader<'a>),
    Server(rustls::Reader<'a>),
}

#[cfg(feature = "tcp-tls")]
impl<'a> Read for TlsReader<'a> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Client(r) => r.read(buf),
            Self::Server(r) => r.read(buf),
        }
    }
}

/// v233: Helper wrapper for TLS writer
#[cfg(feature = "tcp-tls")]
enum TlsWriter<'a> {
    Client(rustls::Writer<'a>),
    Server(rustls::Writer<'a>),
}

#[cfg(feature = "tcp-tls")]
impl<'a> Write for TlsWriter<'a> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::Client(w) => w.write(buf),
            Self::Server(w) => w.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Client(w) => w.flush(),
            Self::Server(w) => w.flush(),
        }
    }
}

impl IoThread {
    /// Create a new I/O thread.
    pub fn new(
        config: TcpConfig,
        metrics: Arc<TcpTransportMetrics>,
    ) -> io::Result<(Self, IoThreadHandle)> {
        let poll = Poll::new()?;

        // Create listener if we should listen
        let listener = if config.role.can_listen() {
            let addr = SocketAddr::new(
                config.listen_address.unwrap_or([0, 0, 0, 0].into()),
                config.listen_port,
            );
            let mut listener = TcpListener::bind(addr)?;
            poll.registry()
                .register(&mut listener, LISTENER_TOKEN, Interest::READABLE)?;
            Some(listener)
        } else {
            None
        };

        // v233: Extract TLS configurations
        #[cfg(feature = "tcp-tls")]
        let (tls_server_config, tls_client_config) = if config.tls_enabled {
            if let Some(ref tls_config) = config.tls_config {
                (
                    tls_config.server_config.clone(),
                    tls_config.client_config.clone(),
                )
            } else {
                (None, None)
            }
        } else {
            (None, None)
        };

        // Create channels
        let (cmd_tx, cmd_rx) = channel();
        let (event_tx, event_rx) = channel();

        // Create waker
        let waker = Arc::new(Waker::new(poll.registry(), WAKER_TOKEN)?);

        let running = Arc::new(AtomicBool::new(true));

        let io_thread = Self {
            config,
            poll,
            listener,
            connections: HashMap::new(),
            conn_id_to_token: HashMap::new(),
            next_token: CONNECTION_TOKEN_START,
            cmd_rx,
            event_tx,
            metrics,
            running: running.clone(),
            #[cfg(feature = "tcp-tls")]
            tls_server_config,
            #[cfg(feature = "tcp-tls")]
            tls_client_config,
        };

        let handle = IoThreadHandle {
            cmd_tx,
            event_rx,
            waker,
            thread_handle: None,
            running,
            next_conn_id: 1,
        };

        Ok((io_thread, handle))
    }

    /// Spawn the I/O thread.
    pub fn spawn(
        config: TcpConfig,
        metrics: Arc<TcpTransportMetrics>,
    ) -> io::Result<IoThreadHandle> {
        let (io_thread, mut handle) = Self::new(config, metrics)?;

        let thread_handle = thread::Builder::new()
            .name("hdds-tcp-io".to_string())
            .spawn(move || {
                io_thread.run();
            })?;

        handle.thread_handle = Some(thread_handle);

        Ok(handle)
    }

    /// Run the I/O event loop.
    pub fn run(mut self) {
        // Send started event
        let local_addr = self.listener.as_ref().and_then(|l| l.local_addr().ok());
        let _ = self.event_tx.send(TcpEvent::Started { local_addr });

        let mut events = Events::with_capacity(MAX_EVENTS);

        while self.running.load(Ordering::Relaxed) {
            // Poll for events
            if let Err(e) = self.poll.poll(&mut events, Some(DEFAULT_POLL_TIMEOUT)) {
                if e.kind() != io::ErrorKind::Interrupted {
                    let _ = self.event_tx.send(TcpEvent::Error {
                        conn_id: None,
                        error: format!("poll error: {}", e),
                    });
                }
                continue;
            }

            // Process events
            for event in events.iter() {
                match event.token() {
                    LISTENER_TOKEN => {
                        self.handle_accept();
                    }
                    WAKER_TOKEN => {
                        self.handle_commands();
                    }
                    token => {
                        if event.is_readable() {
                            self.handle_readable(token);
                        }
                        if event.is_writable() {
                            self.handle_writable(token);
                        }
                    }
                }
            }
        }

        // Cleanup
        for (_, conn) in self.connections.drain() {
            let _ = self.event_tx.send(TcpEvent::ConnectionClosed {
                conn_id: conn.conn_id,
                remote_addr: conn.remote_addr,
                reason: Some("I/O thread shutdown".to_string()),
            });
        }

        let _ = self.event_tx.send(TcpEvent::Stopped);
    }

    /// Handle incoming connections.
    fn handle_accept(&mut self) {
        let listener = match &self.listener {
            Some(l) => l,
            None => return,
        };

        loop {
            match listener.accept() {
                Ok((mut stream, remote_addr)) => {
                    let token = Token(self.next_token);
                    self.next_token += 1;

                    // Generate connection ID
                    let conn_id = token.0 as u64;

                    // Register with poll
                    if let Err(e) = self.poll.registry().register(
                        &mut stream,
                        token,
                        Interest::READABLE | Interest::WRITABLE,
                    ) {
                        let _ = self.event_tx.send(TcpEvent::Error {
                            conn_id: Some(conn_id),
                            error: format!("failed to register connection: {}", e),
                        });
                        continue;
                    }

                    // Configure stream
                    let _ = stream.set_nodelay(self.config.nodelay);

                    // v233: Create TLS server connection if TLS enabled
                    #[cfg(feature = "tcp-tls")]
                    let tls_state = if let Some(ref server_config) = self.tls_server_config {
                        match rustls::ServerConnection::new(Arc::clone(server_config)) {
                            Ok(conn) => Some(TlsConnectionState::Server(conn)),
                            Err(e) => {
                                let _ = self.event_tx.send(TcpEvent::Error {
                                    conn_id: Some(conn_id),
                                    error: format!("TLS setup failed: {}", e),
                                });
                                continue;
                            }
                        }
                    } else {
                        None
                    };

                    // Determine initial state based on TLS
                    #[cfg(feature = "tcp-tls")]
                    let has_tls = tls_state.is_some();
                    #[cfg(feature = "tcp-tls")]
                    let initial_state = if has_tls {
                        ConnectionState::Connecting // TLS handshake pending
                    } else {
                        ConnectionState::Connected
                    };
                    #[cfg(not(feature = "tcp-tls"))]
                    let initial_state = ConnectionState::Connected;

                    // Create connection state
                    let conn = IoConnection {
                        stream,
                        conn_id,
                        remote_addr,
                        state: initial_state,
                        codec: FrameCodec::new(self.config.max_message_size),
                        send_queue: Vec::new(),
                        send_offset: 0,
                        is_initiator: false,
                        #[cfg(feature = "tcp-tls")]
                        tls_state,
                    };

                    // Check if TLS handshake pending before moving conn
                    #[cfg(feature = "tcp-tls")]
                    let emit_connected = !has_tls;
                    #[cfg(not(feature = "tcp-tls"))]
                    let emit_connected = true;

                    self.connections.insert(token, conn);
                    self.conn_id_to_token.insert(conn_id, token);

                    self.metrics.record_connection_established();

                    // Only emit Connected event if not doing TLS handshake
                    if emit_connected {
                        let _ = self.event_tx.send(TcpEvent::ConnectionAccepted {
                            conn_id,
                            remote_addr,
                        });
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    break;
                }
                Err(e) => {
                    let _ = self.event_tx.send(TcpEvent::Error {
                        conn_id: None,
                        error: format!("accept error: {}", e),
                    });
                    break;
                }
            }
        }
    }

    /// Handle commands from the main thread.
    fn handle_commands(&mut self) {
        loop {
            match self.cmd_rx.try_recv() {
                Ok(IoCommand::Connect { addr, conn_id }) => {
                    self.handle_connect(addr, conn_id);
                }
                Ok(IoCommand::Send { conn_id, payload }) => {
                    self.handle_send(conn_id, payload);
                }
                Ok(IoCommand::Close { conn_id }) => {
                    self.handle_close(conn_id);
                }
                Ok(IoCommand::Shutdown) => {
                    self.running.store(false, Ordering::Relaxed);
                    break;
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    self.running.store(false, Ordering::Relaxed);
                    break;
                }
            }
        }
    }

    /// Handle connect command.
    fn handle_connect(&mut self, addr: SocketAddr, conn_id: u64) {
        match TcpStream::connect(addr) {
            Ok(mut stream) => {
                let token = Token(self.next_token);
                self.next_token += 1;

                if let Err(e) = self.poll.registry().register(
                    &mut stream,
                    token,
                    Interest::READABLE | Interest::WRITABLE,
                ) {
                    let _ = self.event_tx.send(TcpEvent::Error {
                        conn_id: Some(conn_id),
                        error: format!("failed to register connection: {}", e),
                    });
                    self.metrics.record_connection_failed();
                    return;
                }

                let _ = stream.set_nodelay(self.config.nodelay);

                // v233: Create TLS client connection if TLS enabled
                #[cfg(feature = "tcp-tls")]
                let tls_state = if let Some(ref client_config) = self.tls_client_config {
                    // Use IP address as server name for TLS SNI
                    // In production, this should be configurable per-connection
                    let server_name = match ServerName::try_from(addr.ip().to_string()) {
                        Ok(sn) => sn,
                        Err(e) => {
                            let _ = self.event_tx.send(TcpEvent::Error {
                                conn_id: Some(conn_id),
                                error: format!(
                                    "TLS SNI failed for {}: {} -- refusing insecure fallback",
                                    addr, e
                                ),
                            });
                            self.metrics.record_connection_failed();
                            return;
                        }
                    };
                    match rustls::ClientConnection::new(Arc::clone(client_config), server_name) {
                        Ok(conn) => Some(TlsConnectionState::Client(conn)),
                        Err(e) => {
                            let _ = self.event_tx.send(TcpEvent::Error {
                                conn_id: Some(conn_id),
                                error: format!("TLS client setup failed: {}", e),
                            });
                            self.metrics.record_connection_failed();
                            return;
                        }
                    }
                } else {
                    None
                };

                let conn = IoConnection {
                    stream,
                    conn_id,
                    remote_addr: addr,
                    state: ConnectionState::Connecting,
                    codec: FrameCodec::new(self.config.max_message_size),
                    send_queue: Vec::new(),
                    send_offset: 0,
                    is_initiator: true,
                    #[cfg(feature = "tcp-tls")]
                    tls_state,
                };

                self.connections.insert(token, conn);
                self.conn_id_to_token.insert(conn_id, token);
            }
            Err(e) => {
                let _ = self.event_tx.send(TcpEvent::Error {
                    conn_id: Some(conn_id),
                    error: format!("connect failed: {}", e),
                });
                self.metrics.record_connection_failed();
            }
        }
    }

    /// Handle send command.
    fn handle_send(&mut self, conn_id: u64, payload: Vec<u8>) {
        let token = match self.conn_id_to_token.get(&conn_id) {
            Some(t) => *t,
            None => {
                let _ = self.event_tx.send(TcpEvent::Error {
                    conn_id: Some(conn_id),
                    error: "connection not found".to_string(),
                });
                return;
            }
        };

        let conn = match self.connections.get_mut(&token) {
            Some(c) => c,
            None => return,
        };

        if conn.state != ConnectionState::Connected {
            let _ = self.event_tx.send(TcpEvent::Error {
                conn_id: Some(conn_id),
                error: format!("connection not ready: {:?}", conn.state),
            });
            return;
        }

        // Frame and queue the message
        FrameCodec::encode_into(&payload, &mut conn.send_queue);

        // Try to send immediately
        self.try_flush(token);
    }

    /// Handle close command.
    fn handle_close(&mut self, conn_id: u64) {
        if let Some(token) = self.conn_id_to_token.remove(&conn_id) {
            if let Some(mut conn) = self.connections.remove(&token) {
                let _ = self.poll.registry().deregister(&mut conn.stream);
                self.metrics.record_connection_closed();

                let _ = self.event_tx.send(TcpEvent::ConnectionClosed {
                    conn_id,
                    remote_addr: conn.remote_addr,
                    reason: Some("closed by request".to_string()),
                });
            }
        }
    }

    /// Handle readable event.
    fn handle_readable(&mut self, token: Token) {
        // v233: Handle TLS I/O if TLS is active
        #[cfg(feature = "tcp-tls")]
        {
            let conn = match self.connections.get_mut(&token) {
                Some(c) => c,
                None => return,
            };

            if let Some(ref mut tls_state) = conn.tls_state {
                // Read encrypted data from socket into TLS
                match tls_state.read_tls(&mut conn.stream) {
                    Ok(0) => {
                        // Connection closed
                        self.close_connection(token, Some("TLS connection closed".to_string()));
                        return;
                    }
                    Ok(_) => {
                        // Process TLS packets
                        if let Err(e) = tls_state.process_new_packets() {
                            self.close_connection(token, Some(format!("TLS error: {}", e)));
                            return;
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    Err(e) => {
                        self.close_connection(token, Some(format!("TLS read error: {}", e)));
                        return;
                    }
                }

                // Check if handshake just completed
                if conn.state == ConnectionState::Connecting && !tls_state.is_handshaking() {
                    conn.state = ConnectionState::Connected;
                    let conn_id = conn.conn_id;
                    let remote_addr = conn.remote_addr;
                    let is_initiator = conn.is_initiator;

                    if is_initiator {
                        let _ = self.event_tx.send(TcpEvent::ConnectionEstablished {
                            conn_id,
                            remote_addr,
                        });
                    } else {
                        let _ = self.event_tx.send(TcpEvent::ConnectionAccepted {
                            conn_id,
                            remote_addr,
                        });
                    }
                }

                // If still handshaking, try to write TLS data
                if tls_state.is_handshaking() && tls_state.wants_write() {
                    while tls_state.wants_write() {
                        match tls_state.write_tls(&mut conn.stream) {
                            Ok(0) => break,
                            Ok(_) => {}
                            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                            Err(_) => break,
                        }
                    }
                    return;
                }

                // Read decrypted plaintext and decode frames
                if conn.state == ConnectionState::Connected {
                    let mut plaintext_buf = [0u8; 16384];
                    loop {
                        let mut reader = tls_state.reader();
                        match reader.read(&mut plaintext_buf) {
                            Ok(0) => break,
                            Ok(n) => {
                                // Feed plaintext to codec
                                conn.codec.feed(&plaintext_buf[..n]);
                            }
                            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                            Err(_) => break,
                        }
                    }

                    // Decode frames from codec buffer
                    while let Some(payload) = conn.codec.decode_buffered() {
                        self.metrics.record_message_received(payload.len() + 4);
                        let _ = self.event_tx.send(TcpEvent::MessageReceived {
                            conn_id: conn.conn_id,
                            remote_addr: conn.remote_addr,
                            payload,
                        });
                    }
                }
                return;
            }
        }

        // Non-TLS path: read directly from stream
        let conn = match self.connections.get_mut(&token) {
            Some(c) => c,
            None => return,
        };

        // Read all available messages
        loop {
            match conn.codec.decode(&mut conn.stream) {
                Ok(Some(payload)) => {
                    self.metrics.record_message_received(payload.len() + 4);

                    let _ = self.event_tx.send(TcpEvent::MessageReceived {
                        conn_id: conn.conn_id,
                        remote_addr: conn.remote_addr,
                        payload,
                    });
                }
                Ok(None) => {
                    // WouldBlock - no more data
                    break;
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    break;
                }
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                    // Connection closed
                    self.close_connection(token, Some("connection closed by peer".to_string()));
                    return;
                }
                Err(e) => {
                    self.metrics.record_recv_error();
                    self.close_connection(token, Some(format!("read error: {}", e)));
                    return;
                }
            }
        }
    }

    /// Handle writable event.
    fn handle_writable(&mut self, token: Token) {
        // v233: Handle TLS handshake and writes
        #[cfg(feature = "tcp-tls")]
        {
            let conn = match self.connections.get_mut(&token) {
                Some(c) => c,
                None => return,
            };

            if let Some(ref mut tls_state) = conn.tls_state {
                // Check for TCP connection error first (for outbound connections)
                if conn.is_initiator && conn.state == ConnectionState::Connecting {
                    match conn.stream.take_error() {
                        Ok(Some(e)) => {
                            self.metrics.record_connection_failed();
                            let _ = conn;
                            self.close_connection(token, Some(format!("connect failed: {}", e)));
                            return;
                        }
                        Ok(None) => {
                            // TCP connected, but TLS handshake still pending
                        }
                        Err(e) => {
                            self.metrics.record_connection_failed();
                            let _ = conn;
                            self.close_connection(token, Some(format!("connect error: {}", e)));
                            return;
                        }
                    }
                }

                // Write pending TLS data
                while tls_state.wants_write() {
                    match tls_state.write_tls(&mut conn.stream) {
                        Ok(0) => break,
                        Ok(_) => {}
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                        Err(e) => {
                            let _ = conn;
                            self.close_connection(token, Some(format!("TLS write error: {}", e)));
                            return;
                        }
                    }
                }

                // Check if handshake just completed
                if conn.state == ConnectionState::Connecting && !tls_state.is_handshaking() {
                    conn.state = ConnectionState::Connected;
                    let conn_id = conn.conn_id;
                    let remote_addr = conn.remote_addr;
                    let is_initiator = conn.is_initiator;

                    self.metrics.record_connection_established();

                    if is_initiator {
                        let _ = self.event_tx.send(TcpEvent::ConnectionEstablished {
                            conn_id,
                            remote_addr,
                        });
                    } else {
                        let _ = self.event_tx.send(TcpEvent::ConnectionAccepted {
                            conn_id,
                            remote_addr,
                        });
                    }
                }

                // If connected and have data to send, flush through TLS
                if conn.state == ConnectionState::Connected && !conn.send_queue.is_empty() {
                    let _ = conn;
                    self.try_flush(token);
                }
                return;
            }
        }

        // Non-TLS path
        let conn = match self.connections.get_mut(&token) {
            Some(c) => c,
            None => return,
        };

        // Check if connecting
        if conn.state == ConnectionState::Connecting {
            // Check for connection error
            match conn.stream.take_error() {
                Ok(Some(e)) => {
                    self.metrics.record_connection_failed();
                    self.close_connection(token, Some(format!("connect failed: {}", e)));
                    return;
                }
                Ok(None) => {
                    // Connection established
                    conn.state = ConnectionState::Connected;
                    self.metrics.record_connection_established();

                    let _ = self.event_tx.send(TcpEvent::ConnectionEstablished {
                        conn_id: conn.conn_id,
                        remote_addr: conn.remote_addr,
                    });
                }
                Err(e) => {
                    self.metrics.record_connection_failed();
                    self.close_connection(token, Some(format!("connect error: {}", e)));
                    return;
                }
            }
        }

        // Try to flush send queue
        self.try_flush(token);
    }

    /// Try to flush the send queue for a connection.
    fn try_flush(&mut self, token: Token) {
        // v233: Handle TLS write path
        #[cfg(feature = "tcp-tls")]
        {
            // Check if this is a TLS connection and get necessary state
            let (has_tls, queue_empty) = {
                let conn = match self.connections.get(&token) {
                    Some(c) => c,
                    None => return,
                };
                (conn.tls_state.is_some(), conn.send_queue.is_empty())
            };

            if has_tls {
                if queue_empty {
                    return;
                }

                // Write plaintext to TLS - need to scope the mutable borrow
                let write_error: Option<String> = {
                    #[allow(clippy::unwrap_used)]
                    // connection must exist: looked up earlier in this function
                    let conn = self.connections.get_mut(&token).unwrap();
                    #[allow(clippy::unwrap_used)] // tls_state is Some when has_tls is true
                    let tls_state = conn.tls_state.as_mut().unwrap();

                    let mut error = None;
                    while conn.send_offset < conn.send_queue.len() {
                        // Scope the writer borrow
                        let result = {
                            let mut writer = tls_state.writer();
                            writer.write(&conn.send_queue[conn.send_offset..])
                        };
                        match result {
                            Ok(0) => break,
                            Ok(n) => {
                                conn.send_offset += n;
                            }
                            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                            Err(e) => {
                                error = Some(format!("TLS write error: {}", e));
                                break;
                            }
                        }
                    }
                    error
                };

                if let Some(err) = write_error {
                    self.metrics.record_send_error();
                    self.close_connection(token, Some(err));
                    return;
                }

                // Flush TLS data to socket
                let flush_error: Option<String> = {
                    #[allow(clippy::unwrap_used)]
                    // connection must exist: looked up earlier in this function
                    let conn = self.connections.get_mut(&token).unwrap();
                    #[allow(clippy::unwrap_used)] // tls_state is Some when has_tls is true
                    let tls_state = conn.tls_state.as_mut().unwrap();

                    let mut error = None;
                    while tls_state.wants_write() {
                        match tls_state.write_tls(&mut conn.stream) {
                            Ok(0) => break,
                            Ok(_) => {}
                            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                                break;
                            }
                            Err(e) => {
                                error = Some(format!("TLS flush error: {}", e));
                                break;
                            }
                        }
                    }
                    error
                };

                if let Some(err) = flush_error {
                    self.metrics.record_send_error();
                    self.close_connection(token, Some(err));
                    return;
                }

                // Check if all data was sent and emit WriteReady
                #[allow(clippy::unwrap_used)]
                // connection must exist: looked up earlier in this function
                let conn = self.connections.get_mut(&token).unwrap();
                if conn.send_offset >= conn.send_queue.len() {
                    conn.send_queue.clear();
                    conn.send_offset = 0;
                    let conn_id = conn.conn_id;
                    let _ = self.event_tx.send(TcpEvent::WriteReady { conn_id });
                }
                return;
            }
        }

        // Non-TLS path
        let conn = match self.connections.get_mut(&token) {
            Some(c) => c,
            None => return,
        };

        if conn.send_queue.is_empty() {
            return;
        }

        while conn.send_offset < conn.send_queue.len() {
            match conn.stream.write(&conn.send_queue[conn.send_offset..]) {
                Ok(0) => {
                    self.close_connection(token, Some("write returned 0".to_string()));
                    return;
                }
                Ok(n) => {
                    conn.send_offset += n;
                    self.metrics.record_bytes_sent(n);
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    self.metrics.record_send_blocked();
                    return;
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {
                    continue;
                }
                Err(e) => {
                    self.metrics.record_send_error();
                    self.close_connection(token, Some(format!("write error: {}", e)));
                    return;
                }
            }
        }

        // All data sent
        conn.send_queue.clear();
        conn.send_offset = 0;

        let _ = self.event_tx.send(TcpEvent::WriteReady {
            conn_id: conn.conn_id,
        });
    }

    /// Close a connection and clean up.
    fn close_connection(&mut self, token: Token, reason: Option<String>) {
        if let Some(mut conn) = self.connections.remove(&token) {
            let _ = self.poll.registry().deregister(&mut conn.stream);
            self.conn_id_to_token.remove(&conn.conn_id);
            self.metrics.record_connection_closed();

            let _ = self.event_tx.send(TcpEvent::ConnectionClosed {
                conn_id: conn.conn_id,
                remote_addr: conn.remote_addr,
                reason,
            });
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_event_debug() {
        let event = TcpEvent::Started { local_addr: None };
        let _ = format!("{:?}", event);

        let event = TcpEvent::MessageReceived {
            conn_id: 1,
            remote_addr: "127.0.0.1:8080".parse().unwrap(),
            payload: vec![1, 2, 3],
        };
        let _ = format!("{:?}", event);
    }

    #[test]
    fn test_io_command_debug() {
        let cmd = IoCommand::Connect {
            addr: "127.0.0.1:8080".parse().unwrap(),
            conn_id: 1,
        };
        let _ = format!("{:?}", cmd);

        let cmd = IoCommand::Send {
            conn_id: 1,
            payload: vec![1, 2, 3],
        };
        let _ = format!("{:?}", cmd);

        let cmd = IoCommand::Close { conn_id: 1 };
        let _ = format!("{:?}", cmd);

        let cmd = IoCommand::Shutdown;
        let _ = format!("{:?}", cmd);
    }

    #[test]
    fn test_io_thread_creation() {
        let config = TcpConfig {
            enabled: true,
            listen_port: 0, // Ephemeral port
            ..Default::default()
        };
        let metrics = Arc::new(TcpTransportMetrics::new());

        let result = IoThread::new(config, metrics);
        assert!(result.is_ok());

        let (io_thread, _handle) = result.unwrap();
        assert!(io_thread.listener.is_some());
    }

    #[test]
    fn test_io_thread_client_only() {
        use super::super::TcpRole;

        let config = TcpConfig {
            enabled: true,
            role: TcpRole::ClientOnly,
            initial_peers: vec!["127.0.0.1:8080".parse().unwrap()],
            ..Default::default()
        };
        let metrics = Arc::new(TcpTransportMetrics::new());

        let result = IoThread::new(config, metrics);
        assert!(result.is_ok());

        let (io_thread, _handle) = result.unwrap();
        assert!(io_thread.listener.is_none());
    }

    #[test]
    fn test_constants() {
        assert_eq!(LISTENER_TOKEN, Token(0));
        assert_eq!(WAKER_TOKEN, Token(1));
        assert_eq!(CONNECTION_TOKEN_START, 2);
        assert_eq!(DEFAULT_POLL_TIMEOUT, Duration::from_millis(100));
        assert_eq!(MAX_EVENTS, 128);
    }

    // Integration test would require actual network connections
    // which we avoid in unit tests
}
