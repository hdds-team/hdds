// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Discovery Server client implementation.
//!
//! An event-driven TCP client for a discovery server. The socket is
//! non-blocking and the session sleeps in one place -
//! [`DiscoveryServerClient::wait_for_io`] - so that a thread other than the
//! session's can hand it work and have it picked up at once, through a
//! [`SessionWaker`].
//!
//! # Why not a blocking socket
//!
//! A single thread doing blocking reads AND blocking writes on the same
//! bidirectional stream blocks against itself: once both directions fill -
//! the server writing to us while we write to it, neither reading - the
//! write stalls until its own budget runs out and ends the session. That is
//! a session that falls over exactly under load. The relay's send path makes
//! this ordinary rather than theoretical, because it puts whole RTPS
//! datagrams through a stream that until now carried a few hundred bytes at
//! a time.

use super::config::DiscoveryServerConfig;
use super::protocol::{ClientMessage, EntityId, GuidPrefix, ServerMessage};
use mio::net::TcpStream;
use mio::{Events, Interest, Poll, Token};
use std::collections::VecDeque;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Discovery server client for DDS participants.
///
/// Manages connection to a discovery server, handles reconnection,
/// and provides async methods for participant/endpoint announcements.
pub struct DiscoveryServerClient {
    config: DiscoveryServerConfig,
    state: ClientState,
    guid_prefix: GuidPrefix,
    last_heartbeat: Option<Instant>,
    read_buffer: Vec<u8>,
    /// Frames accepted from callers but not yet taken by the socket.
    outbox: Outbox,
    /// The readiness registry this client's session thread sleeps on.
    ///
    /// Owned by the client rather than by the session loop so that the
    /// [`SessionWaker`] handed to other threads outlives any one connection:
    /// it belongs to the registry, and the registry survives a reconnect.
    poll: Poll,
    /// The handle other threads use to interrupt [`Self::wait_for_io`].
    waker: Arc<mio::Waker>,
    /// Scratch space for one `poll` call.
    events: Events,
    /// Frames dropped because their type is not implemented by this build.
    ///
    /// Cumulative over the life of the client, reconnections included: the
    /// question it answers ("is this build older than the server it talks
    /// to, or is someone feeding it frames it has no business receiving?")
    /// is not per-connection.
    unknown_messages: u64,
    /// Relayed frames addressed to a participant that is not us.
    ///
    /// A well-behaved server never produces one. A non-zero value means the
    /// server's routing table disagrees with ours about who we are, which is
    /// worth seeing rather than worth obeying.
    misrouted_relay_frames: u64,
}

/// Internal client state.
enum ClientState {
    /// Not connected.
    Disconnected,
    /// Connected to server.
    Connected { stream: TcpStream },
}

/// Events received from the discovery server.
#[derive(Debug, Clone)]
pub enum ClientEvent {
    /// Successfully connected to server.
    Connected,

    /// Disconnected from server.
    Disconnected { reason: String },

    /// Server acknowledged our participant registration.
    ParticipantAcknowledged,

    /// New remote participant discovered.
    ParticipantDiscovered {
        guid_prefix: GuidPrefix,
        domain_id: u32,
        name: Option<String>,
        unicast_locators: Vec<SocketAddr>,
        builtin_endpoints: u32,
    },

    /// Remote participant left.
    ParticipantLeft { guid_prefix: GuidPrefix },

    /// New remote endpoint discovered.
    EndpointDiscovered {
        guid_prefix: GuidPrefix,
        entity_id: EntityId,
        topic_name: String,
        type_name: String,
        is_writer: bool,
        reliable: bool,
        durability: u8,
        unicast_locators: Vec<SocketAddr>,
    },

    /// Error from server.
    Error { code: u32, message: String },

    /// A whole RTPS datagram relayed by the server on behalf of another
    /// participant of the same domain.
    ///
    /// The sender is not on the envelope: it is at bytes 8..20 of the
    /// datagram itself, which is the copy the receiver will actually parse.
    RelayDataReceived { payload: Vec<u8> },
}

/// Client error types.
#[derive(Debug)]
pub enum ClientError {
    /// Connection failed.
    ConnectionFailed(String),

    /// Connection closed unexpectedly.
    ConnectionClosed,

    /// I/O error.
    Io(io::Error),

    /// Protocol error.
    Protocol(String),

    /// Server returned an error.
    ServerError { code: u32, message: String },

    /// Configuration error.
    Config(String),

    /// Not connected.
    NotConnected,

    /// The session has more queued than it can hold, so a frame was refused.
    ///
    /// Distinct from an I/O error on purpose: nothing failed. The socket is
    /// simply behind, which on this protocol means the server has stopped
    /// reading, and the frame was never handed over.
    Backpressure(String),
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ConnectionFailed(s) => write!(f, "Connection failed: {}", s),
            Self::ConnectionClosed => write!(f, "Connection closed"),
            Self::Io(e) => write!(f, "I/O error: {}", e),
            Self::Protocol(s) => write!(f, "Protocol error: {}", s),
            Self::ServerError { code, message } => {
                write!(f, "Server error {}: {}", code, message)
            }
            Self::Config(s) => write!(f, "Configuration error: {}", s),
            Self::NotConnected => write!(f, "Not connected to server"),
            Self::Backpressure(s) => write!(f, "Session backpressure: {}", s),
        }
    }
}

impl std::error::Error for ClientError {}

impl From<io::Error> for ClientError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// The session's socket in the client's own readiness registry.
const SESSION_TOKEN: Token = Token(0);

/// The token a [`SessionWaker`] fires on.
const WAKER_TOKEN: Token = Token(1);

/// How many readiness events one [`DiscoveryServerClient::wait_for_io`] may
/// report. Two sources are registered - the socket and the waker - so this is
/// already more than can ever arrive at once.
const EVENT_CAPACITY: usize = 8;

/// Bytes the outbox may hold before it refuses further frames.
///
/// An outbox with no ceiling turns a server that stopped reading into
/// unbounded memory in every one of its clients - the same failure this
/// branch already fixed on the server's own fan-out, seen from the other
/// end. One mebibyte holds sixteen relayed datagrams at the 64 KiB ceiling
/// an RTPS datagram cannot exceed, which is room for the socket to drain a
/// burst and far below what an unresponsive server could otherwise make us
/// hold. It must stay well above the largest single frame, or that frame
/// could never be queued at all.
const MAX_OUTBOX_BYTES: usize = 1024 * 1024;

/// The shortest a stalled outbox is given before the session is ended.
///
/// The limit itself is [`DiscoveryServerConfig::heartbeat_interval`]: a
/// session that cannot get one byte out within its own liveliness period is
/// not a session, whatever the network is doing. This floor exists for a
/// configuration that sets a very short heartbeat, where the interval alone
/// would end sessions over an ordinary congested round trip.
const MIN_OUTBOX_STALL_LIMIT: Duration = Duration::from_millis(500);

/// How long [`DiscoveryServerClient::leave`] waits for its own frame to go out.
///
/// Sits inside the runtime's join timeout on purpose: the thread has to be
/// able to send its departure AND exit before the participant stops waiting
/// for it.
const LEAVE_FLUSH_BUDGET: Duration = Duration::from_millis(200);

/// A nudge that wakes the session thread out of [`DiscoveryServerClient::wait_for_io`].
///
/// The relay's send path runs on a DDS writer thread: it hands a datagram to
/// a queue the session thread drains, and the session thread is asleep on a
/// socket that has nothing to say. Without this it would sleep out its whole
/// timeout first, adding that delay to every relayed datagram. Cloneable and
/// cheap. `mio` is deliberately absent from the signature so that whoever
/// holds one never has to name it.
#[derive(Clone)]
pub struct SessionWaker {
    inner: Arc<mio::Waker>,
}

impl SessionWaker {
    /// Wake the session thread.
    ///
    /// Several wakes before the thread runs coalesce into one wake-up, which
    /// is what draining a queue wants anyway.
    pub fn wake(&self) -> io::Result<()> {
        self.inner.wake()
    }
}

impl std::fmt::Debug for SessionWaker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SessionWaker")
    }
}

/// Frames handed to the session but not yet accepted by the socket.
///
/// On a non-blocking socket a partial write is ordinary rather than a
/// failure. What makes it safe is that the remainder stays here, in order,
/// and the next writable socket resumes at the exact byte it stopped on - so
/// a frame is never truncated on the wire, which is the one property a
/// length-prefixed protocol rests on.
#[derive(Default)]
struct Outbox {
    /// Whole frames, oldest first. Only the front one may be partly sent.
    frames: VecDeque<Vec<u8>>,
    /// Bytes of `frames.front()` the socket has already accepted.
    sent: usize,
    /// Bytes still to go, across every queued frame.
    queued: usize,
    /// When the socket last refused a byte with work waiting.
    ///
    /// `None` while the socket is keeping up. Any progress clears it, so a
    /// slow link that keeps trickling is never mistaken for a peer that
    /// stopped reading - the same distinction the blocking write path drew
    /// by counting timeouts, restated in time because a non-blocking socket
    /// offers no attempts to count.
    stalled_since: Option<Instant>,
}

impl Outbox {
    /// Bytes this outbox would still accept.
    fn room(&self) -> usize {
        MAX_OUTBOX_BYTES.saturating_sub(self.queued)
    }

    fn is_empty(&self) -> bool {
        self.frames.is_empty()
    }

    /// Forget everything queued.
    ///
    /// Frames queued for a stream that no longer exists are not frames the
    /// next session may send: the server would be reading the tail of a
    /// conversation it never had.
    fn clear(&mut self) {
        self.frames.clear();
        self.sent = 0;
        self.queued = 0;
        self.stalled_since = None;
    }
}

/// Why the outbox stopped, when it was not the socket merely filling up.
#[derive(Debug)]
struct OutboxFailure {
    /// Bytes of the front frame that already reached the stream.
    ///
    /// Zero means the stream still starts on a frame boundary and could
    /// carry another frame; anything else means it cannot.
    partial: usize,
    /// What stopped it.
    error: io::Error,
}

/// Whether a stopped outbox left the stream unable to carry another frame.
///
/// `None` means it did not: not one byte of the front frame went out, so the
/// stream still starts on a frame boundary and the failure is the caller's
/// to weigh. `Some` names the loss, and the session it belongs to has to end,
/// because the damage is not the frame that stopped but every frame after
/// it.
///
/// Split out from [`DiscoveryServerClient::flush`] so both answers are tested
/// directly: provoking the "nothing written" case through a real socket means
/// catching the instant between a full send buffer and the stall limit, which
/// is not a thing a test can hold still.
fn framing_loss(failure: &OutboxFailure, frame_len: usize) -> Option<String> {
    if failure.partial == 0 {
        return None;
    }

    Some(format!(
        "the stream stopped {} of {} bytes into a frame and did not resume; it can no longer \
         be framed, closing the session: {}",
        failure.partial, frame_len, failure.error
    ))
}

/// Push as much of the outbox into the writer as it will take.
///
/// Returns once the writer refuses more, the outbox is empty, or something
/// happened that the session has to answer for. `now` is a parameter so the
/// stall limit can be tested without waiting for it, and the writer is
/// generic so the stall and framing cases are provoked on demand rather than
/// by filling a real socket's send buffer.
fn drain_outbox<W: io::Write>(
    writer: &mut W,
    outbox: &mut Outbox,
    now: Instant,
    stall_limit: Duration,
) -> Result<(), OutboxFailure> {
    loop {
        let Some(front) = outbox.frames.front() else {
            outbox.stalled_since = None;
            // A no-op on a `TcpStream`, which buffers nothing of its own, but
            // a writer that does buffer has to be told to let go.
            return writer
                .flush()
                .map_err(|error| OutboxFailure { partial: 0, error });
        };
        let frame_len = front.len();
        let outcome = writer.write(&front[outbox.sent..]);

        match outcome {
            Ok(0) => {
                return Err(OutboxFailure {
                    partial: outbox.sent,
                    error: io::Error::new(
                        io::ErrorKind::WriteZero,
                        "the stream accepted no further bytes",
                    ),
                })
            }
            Ok(count) => {
                outbox.sent += count;
                outbox.queued -= count;
                // Progress, so the peer is reading: forget the stall.
                outbox.stalled_since = None;
                if outbox.sent == frame_len {
                    outbox.frames.pop_front();
                    outbox.sent = 0;
                }
            }
            // A signal interrupted the call; nothing was written.
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                let since = *outbox.stalled_since.get_or_insert(now);
                if now.saturating_duration_since(since) >= stall_limit {
                    return Err(OutboxFailure {
                        partial: outbox.sent,
                        error,
                    });
                }
                return Ok(());
            }
            Err(error) => {
                return Err(OutboxFailure {
                    partial: outbox.sent,
                    error,
                })
            }
        }
    }
}

impl DiscoveryServerClient {
    /// Create a new client with the given configuration and GUID prefix.
    pub fn new(
        config: DiscoveryServerConfig,
        guid_prefix: GuidPrefix,
    ) -> Result<Self, ClientError> {
        config
            .validate()
            .map_err(|e| ClientError::Config(e.to_string()))?;

        let poll = Poll::new().map_err(ClientError::Io)?;
        let waker =
            Arc::new(mio::Waker::new(poll.registry(), WAKER_TOKEN).map_err(ClientError::Io)?);

        Ok(Self {
            config,
            state: ClientState::Disconnected,
            guid_prefix,
            last_heartbeat: None,
            read_buffer: Vec::new(),
            outbox: Outbox::default(),
            poll,
            waker,
            events: Events::with_capacity(EVENT_CAPACITY),
            unknown_messages: 0,
            misrouted_relay_frames: 0,
        })
    }

    /// Connect to the discovery server.
    ///
    /// The connect itself stays blocking and bounded by `connect_timeout`:
    /// that is a configured promise, and nothing else can happen on this
    /// client until the session exists, so reproducing the timeout inside the
    /// poll loop would buy nothing. Everything after it is non-blocking.
    pub fn connect(&mut self) -> Result<(), ClientError> {
        let stream = std::net::TcpStream::connect_timeout(
            &self.config.server_address,
            self.config.connect_timeout,
        )
        .map_err(|e| ClientError::ConnectionFailed(e.to_string()))?;

        stream.set_nodelay(true).ok();
        stream.set_nonblocking(true).map_err(ClientError::Io)?;

        let mut stream = TcpStream::from_std(stream);
        self.poll
            .registry()
            .register(
                &mut stream,
                SESSION_TOKEN,
                Interest::READABLE | Interest::WRITABLE,
            )
            .map_err(ClientError::Io)?;

        self.state = ClientState::Connected { stream };
        self.last_heartbeat = Some(Instant::now());
        self.read_buffer.clear();
        self.outbox.clear();

        Ok(())
    }

    /// Sleep until the socket is ready, a [`SessionWaker`] fires, or `timeout`.
    ///
    /// The one place a session thread blocks. It reports nothing about WHAT
    /// became ready, on purpose: with a single socket and a single waker
    /// registered, "something did" is all a caller can act on. It then drains
    /// reads until [`Self::read_message`] reports the socket empty and calls
    /// [`Self::flush`] until the socket refuses - which is also exactly what
    /// mio's edge-triggered readiness requires of it.
    pub fn wait_for_io(&mut self, timeout: Duration) -> io::Result<()> {
        match self.poll.poll(&mut self.events, Some(timeout)) {
            Ok(()) => Ok(()),
            // A signal arrived. Not a failure, and the caller's next pass
            // over the socket is the work it would have done anyway.
            Err(error) if error.kind() == io::ErrorKind::Interrupted => Ok(()),
            Err(error) => Err(error),
        }
    }

    /// A handle that wakes this client's session thread.
    ///
    /// Stable for the life of the client, reconnections included: it belongs
    /// to the readiness registry, not to a socket. Whoever needs one can
    /// therefore be handed it once, at startup, and keep it.
    pub fn waker(&self) -> SessionWaker {
        SessionWaker {
            inner: Arc::clone(&self.waker),
        }
    }

    /// Restore the socket's readiness registration after an early exit.
    ///
    /// mio is edge-triggered on every platform and only restores a source's
    /// interests when an operation returns `WouldBlock`: on Windows
    /// `SockState::feed_event` clears each delivered readiness bit and
    /// `IoSourceState::do_io` reregisters solely on that error. A caller that
    /// stops draining early - on a fairness cap, say - has to say so here, or
    /// the socket stays registered for nothing and never wakes again. The
    /// same trap, and the same remedy, as `transport/tcp/io_thread.rs`.
    pub fn rearm(&mut self) -> io::Result<()> {
        match &mut self.state {
            ClientState::Connected { stream } => self.poll.registry().reregister(
                stream,
                SESSION_TOKEN,
                Interest::READABLE | Interest::WRITABLE,
            ),
            ClientState::Disconnected => Ok(()),
        }
    }

    /// Bytes this session would still accept for sending.
    ///
    /// Whoever feeds the relay reads this before taking work off its queue:
    /// leaving a datagram on the queue is a refusal the producer can see and
    /// count, while accepting one the outbox cannot hold would be a silent
    /// drop halfway down.
    pub fn outbox_room(&self) -> usize {
        self.outbox.room()
    }

    /// Check if connected to the server.
    pub fn is_connected(&self) -> bool {
        matches!(self.state, ClientState::Connected { .. })
    }

    /// Return the local TCP address selected by the OS for the server route.
    pub fn local_addr(&self) -> Option<SocketAddr> {
        match &self.state {
            ClientState::Connected { stream } => stream.local_addr().ok(),
            ClientState::Disconnected => None,
        }
    }

    /// Get the GUID prefix.
    pub fn guid_prefix(&self) -> &GuidPrefix {
        &self.guid_prefix
    }

    /// Announce this participant to the server.
    pub fn announce_participant(
        &mut self,
        domain_id: u32,
        name: Option<String>,
        unicast_locators: Vec<SocketAddr>,
        builtin_endpoints: u32,
    ) -> Result<(), ClientError> {
        let msg = ClientMessage::ParticipantAnnounce {
            guid_prefix: self.guid_prefix,
            domain_id,
            name,
            unicast_locators,
            builtin_endpoints,
        };

        self.send_message(&msg)
    }

    /// Announce an endpoint (writer or reader) to the server.
    #[allow(clippy::too_many_arguments)] // Discovery protocol fields
    pub fn announce_endpoint(
        &mut self,
        entity_id: EntityId,
        topic_name: String,
        type_name: String,
        is_writer: bool,
        reliable: bool,
        durability: u8,
        unicast_locators: Vec<SocketAddr>,
    ) -> Result<(), ClientError> {
        let msg = ClientMessage::EndpointAnnounce {
            guid_prefix: self.guid_prefix,
            entity_id,
            topic_name,
            type_name,
            is_writer,
            reliable,
            durability,
            unicast_locators,
        };

        self.send_message(&msg)
    }

    /// Send a heartbeat to keep the lease alive.
    pub fn send_heartbeat(&mut self) -> Result<(), ClientError> {
        let msg = ClientMessage::Heartbeat {
            guid_prefix: self.guid_prefix,
        };

        self.send_message(&msg)?;
        self.last_heartbeat = Some(Instant::now());
        Ok(())
    }

    /// Announce that this participant is leaving.
    pub fn leave(&mut self) -> Result<(), ClientError> {
        let msg = ClientMessage::ParticipantLeave {
            guid_prefix: self.guid_prefix,
        };

        // Queue it, then WAIT for it. This is the message that tells the
        // server this participant is gone; one left sitting in the outbox
        // leaves every other client believing it reachable until its lease
        // runs out, which is the one case where blocking briefly is right.
        let result = self
            .send_message(&msg)
            .and_then(|()| self.flush_blocking(LEAVE_FLUSH_BUDGET));
        self.disconnect();
        result
    }

    /// Disconnect from the server.
    pub fn disconnect(&mut self) {
        if let ClientState::Connected { stream } = &mut self.state {
            // Take the dead source out of the registry before it drops, so
            // the next `connect` registers the same token on a clean slate.
            let _ = self.poll.registry().deregister(stream);
        }
        self.state = ClientState::Disconnected;
        self.last_heartbeat = None;
        self.read_buffer.clear();
        self.outbox.clear();
    }

    /// Read one message from the server.
    ///
    /// Partial frames are retained across calls. `Ok(None)` means the socket
    /// has been DRAINED: either no complete frame has arrived yet or the peer
    /// closed the connection; use [`Self::is_connected`] to tell those apart.
    ///
    /// "Drained" is a promise, not a description, and it is what lets a
    /// caller follow one rule - read until `Ok(None)`. mio is edge-triggered
    /// on every platform, so a caller that stops while bytes are still
    /// waiting is not woken for them again, and on Windows the source is not
    /// even re-armed (`IoSourceState::do_io` reregisters only on
    /// `WouldBlock`). Returning as soon as a read left the buffer short of a
    /// whole frame would hand the caller exactly that trap, so this reads on
    /// until the socket itself refuses.
    pub fn read_message(&mut self) -> Result<Option<ClientEvent>, ClientError> {
        use std::io::Read;

        loop {
            if let Some(event) = self.decode_buffered_message()? {
                return Ok(Some(event));
            }

            let mut chunk = [0u8; 8192];
            let read_result = match &mut self.state {
                ClientState::Connected { stream } => stream.read(&mut chunk),
                ClientState::Disconnected => return Err(ClientError::NotConnected),
            };

            match read_result {
                Ok(0) => {
                    self.disconnect();
                    return Ok(None);
                }
                Ok(bytes_read) => {
                    self.read_buffer.extend_from_slice(&chunk[..bytes_read]);
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    return Ok(None);
                }
                // A signal interrupted the call and nothing was read. Ending
                // the session over that would drop a working connection on a
                // profiler's timer tick.
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => {
                    self.disconnect();
                    return Err(ClientError::Io(error));
                }
            }
        }
    }

    /// Decode buffered frames until one of them yields an event.
    ///
    /// The loop exists for frames of a type this build does not implement:
    /// they are consumed and skipped, so the next buffered frame must be
    /// tried immediately. Returning `Ok(None)` there would send the caller
    /// back to the socket and leave a complete, decodable frame sitting in
    /// the buffer until unrelated bytes arrived.
    fn decode_buffered_message(&mut self) -> Result<Option<ClientEvent>, ClientError> {
        const LENGTH_PREFIX_SIZE: usize = 4;

        loop {
            if self.read_buffer.len() < LENGTH_PREFIX_SIZE {
                return Ok(None);
            }

            // Indexed rather than `try_into().expect(..)`: the guard above
            // already proved there are four bytes, so the fallible conversion
            // was a panic path that could never be taken and that no reader
            // could verify without going back to the guard. This form cannot
            // fail at all.
            let len = u32::from_be_bytes([
                self.read_buffer[0],
                self.read_buffer[1],
                self.read_buffer[2],
                self.read_buffer[3],
            ]) as usize;

            if len == 0 || len > self.config.max_message_size {
                self.disconnect();
                return Err(ClientError::Protocol(format!(
                    "Invalid message length: {}",
                    len
                )));
            }

            let frame_len = LENGTH_PREFIX_SIZE + len;
            if self.read_buffer.len() < frame_len {
                return Ok(None);
            }

            let payload = self.read_buffer[LENGTH_PREFIX_SIZE..frame_len].to_vec();
            self.read_buffer.drain(..frame_len);

            match ServerMessage::decode(&payload) {
                // A relayed frame the server addressed to somebody else.
                // Dropping it is the only safe answer - injecting another
                // participant's traffic into our engine would be worse than
                // losing it - but it is counted and said, because it means
                // the server's routing table and ours disagree about who we
                // are.
                Ok(ServerMessage::Data { destination, .. }) if destination != self.guid_prefix => {
                    self.note_misrouted_relay(&destination);
                }
                Ok(msg) => return Ok(Some(self.message_to_event(msg))),
                Err(error) if error.kind() == io::ErrorKind::Unsupported => {
                    // A type this build does not implement. The framing was
                    // sound and the frame is already out of the buffer, so
                    // the stream stays synchronised: carry on with what
                    // follows it.
                    self.note_unsupported_message(&error);
                }
                Err(error) => return Err(ClientError::Protocol(error.to_string())),
            }
        }
    }

    /// Count and report a frame whose type this build does not implement.
    ///
    /// Ignoring it is deliberate. A relay-capable server forwards frames
    /// chosen by a THIRD party, so treating an unimplemented type as a fatal
    /// protocol error hands every client of the domain the ability to churn
    /// every other one. It is not a silent swallow either: the first one
    /// warns, and every later one keeps the running total visible.
    fn note_unsupported_message(&mut self, error: &io::Error) {
        self.unknown_messages = self.unknown_messages.saturating_add(1);
        if self.unknown_messages == 1 {
            log::warn!(
                "[discovery-server] ignoring a server frame this build does not implement: {}",
                error
            );
        } else {
            log::debug!(
                "[discovery-server] ignored {} server frames this build does not implement (last: {})",
                self.unknown_messages,
                error
            );
        }
    }

    /// Number of frames ignored because their type is not implemented here.
    ///
    /// A non-zero value means this build is older than the server it is
    /// talking to, or that something is sending it frames it has no business
    /// receiving. Cumulative across reconnections.
    pub fn unknown_messages(&self) -> u64 {
        self.unknown_messages
    }

    /// Count and report a relayed frame addressed to another participant.
    fn note_misrouted_relay(&mut self, destination: &GuidPrefix) {
        self.misrouted_relay_frames = self.misrouted_relay_frames.saturating_add(1);
        log::warn!(
            "[discovery-server] dropped a relayed frame addressed to {:02x?}, not to us \
             ({} so far); the server is routing to a participant we are not",
            destination,
            self.misrouted_relay_frames
        );
    }

    /// Number of relayed frames dropped because they were addressed to
    /// another participant. A well-behaved server never produces one.
    pub fn misrouted_relay_frames(&self) -> u64 {
        self.misrouted_relay_frames
    }

    /// Ask the server to relay an RTPS datagram to another participant.
    ///
    /// Only a server started with the relay enabled forwards it, and only
    /// within this participant's own DDS domain. A server that refuses says
    /// nothing back: the relay is best-effort by construction, and the RTPS
    /// reliability protocol above it is what notices a loss.
    pub fn send_relay_data(
        &mut self,
        destination: GuidPrefix,
        payload: Vec<u8>,
    ) -> Result<(), ClientError> {
        self.send_message(&ClientMessage::Data {
            destination,
            payload,
        })
    }

    /// Send a message to the server.
    ///
    /// Queues the frame and pushes what the socket will take right now. It
    /// does not wait: a caller on the relay path is a DDS writer delivering a
    /// sample, and the whole point of the outbox is that it never has to.
    fn send_message(&mut self, msg: &ClientMessage) -> Result<(), ClientError> {
        let encoded = msg
            .encode()
            .map_err(|e| ClientError::Protocol(e.to_string()))?;

        self.enqueue(encoded)?;
        self.flush()
    }

    /// Queue one encoded frame, or refuse it.
    ///
    /// Refuses rather than grows. A refusal is survivable in both directions
    /// it can happen: RTPS reliability treats a refused relay datagram
    /// exactly as it treats a lost packet, and a refused control frame ends a
    /// session whose server has stopped reading and was not going to work.
    fn enqueue(&mut self, frame: Vec<u8>) -> Result<(), ClientError> {
        if !self.is_connected() {
            return Err(ClientError::NotConnected);
        }
        if frame.is_empty() {
            // A zero-length frame would come back out of `drain_outbox` as a
            // write of nothing, which a stream reports as `Ok(0)` - the same
            // answer it gives when it is finished. Nothing this client
            // encodes is ever empty; refusing here keeps it that way rather
            // than leaving a caller's bug to surface as a broken stream.
            return Err(ClientError::Protocol(
                "an empty frame cannot be sent".to_string(),
            ));
        }
        if frame.len() > self.outbox.room() {
            return Err(ClientError::Backpressure(format!(
                "the session is {} bytes behind and cannot take another {}",
                self.outbox.queued,
                frame.len()
            )));
        }

        self.outbox.queued += frame.len();
        self.outbox.frames.push_back(frame);
        Ok(())
    }

    /// Push the outbox into the socket, and decide what stopping it means.
    ///
    /// Called on every turn of a session loop, not only after queueing: a
    /// frame the socket refused earlier resumes here, and the stall that ends
    /// a session is measured here.
    ///
    /// Once one byte of a frame is out, that frame must complete or the
    /// stream is meaningless - whoever writes next appends a new frame after
    /// a truncated one and the server reads the tail of our JSON as a 4-byte
    /// length prefix. That is how the read side of this same protocol failed
    /// earlier on this branch (`Message too large: 578058608` was the ASCII
    /// of `"t_`). So a stream whose framing cannot be vouched for is closed
    /// here rather than handed back to a caller who cannot judge it.
    ///
    /// The stall limit is the configured heartbeat interval, floored at
    /// [`MIN_OUTBOX_STALL_LIMIT`]: a session that cannot get one byte out
    /// within its own liveliness period is not a session. A fixed few hundred
    /// milliseconds would have been wrong here - on a WAN link with a full
    /// congestion window the socket stays unwritable for longer than that
    /// while working perfectly, and a WAN link is the whole reason the relay
    /// exists.
    pub fn flush(&mut self) -> Result<(), ClientError> {
        let stall_limit = self.config.heartbeat_interval.max(MIN_OUTBOX_STALL_LIMIT);
        let now = Instant::now();
        let frame_len = self.outbox.frames.front().map_or(0, Vec::len);

        let outcome = match &mut self.state {
            ClientState::Connected { stream } => {
                drain_outbox(stream, &mut self.outbox, now, stall_limit)
            }
            ClientState::Disconnected => return Err(ClientError::NotConnected),
        };

        let Err(failure) = outcome else {
            return Ok(());
        };

        match framing_loss(&failure, frame_len) {
            // The stream still starts on a frame boundary and stays usable.
            // Report and let the caller weigh it.
            None => Err(ClientError::Io(failure.error)),
            Some(reason) => {
                self.disconnect();
                Err(ClientError::Protocol(reason))
            }
        }
    }

    /// Push the outbox out, waiting on the socket, for at most `budget`.
    ///
    /// A session loop never needs this - it has a poll to go back to - but
    /// shutdown does, because there is no next turn to finish the work in.
    pub fn flush_blocking(&mut self, budget: Duration) -> Result<(), ClientError> {
        let deadline = Instant::now() + budget;

        loop {
            self.flush()?;
            if self.outbox.is_empty() {
                return Ok(());
            }

            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(ClientError::Backpressure(format!(
                    "{} bytes were still queued after {:?}",
                    self.outbox.queued, budget
                )));
            }
            self.wait_for_io(remaining).map_err(ClientError::Io)?;
        }
    }

    /// Convert a server message to a client event.
    fn message_to_event(&self, msg: ServerMessage) -> ClientEvent {
        match msg {
            ServerMessage::ParticipantAck { .. } => ClientEvent::ParticipantAcknowledged,

            ServerMessage::ParticipantAnnounce {
                guid_prefix,
                domain_id,
                name,
                unicast_locators,
                builtin_endpoints,
            } => ClientEvent::ParticipantDiscovered {
                guid_prefix,
                domain_id,
                name,
                unicast_locators,
                builtin_endpoints,
            },

            ServerMessage::ParticipantLeave { guid_prefix } => {
                ClientEvent::ParticipantLeft { guid_prefix }
            }

            ServerMessage::EndpointAnnounce {
                guid_prefix,
                entity_id,
                topic_name,
                type_name,
                is_writer,
                reliable,
                durability,
                unicast_locators,
            } => ClientEvent::EndpointDiscovered {
                guid_prefix,
                entity_id,
                topic_name,
                type_name,
                is_writer,
                reliable,
                durability,
                unicast_locators,
            },

            ServerMessage::Error { code, message } => ClientEvent::Error { code, message },

            // The destination was checked against our own GUID prefix before
            // we got here (`decode_buffered_message`), so this frame is ours.
            ServerMessage::Data { payload, .. } => ClientEvent::RelayDataReceived { payload },
        }
    }

    /// Check if a heartbeat is due.
    pub fn heartbeat_due(&self) -> bool {
        if let Some(last) = self.last_heartbeat {
            last.elapsed() >= self.config.heartbeat_interval
        } else {
            false
        }
    }

    /// Get the server address.
    pub fn server_address(&self) -> SocketAddr {
        self.config.server_address
    }

    /// Get the configuration.
    pub fn config(&self) -> &DiscoveryServerConfig {
        &self.config
    }
}

/// Builder for creating a discovery server client.
#[allow(dead_code)]
pub struct DiscoveryServerClientBuilder {
    config: DiscoveryServerConfig,
    guid_prefix: Option<GuidPrefix>,
}

#[allow(dead_code)]
impl DiscoveryServerClientBuilder {
    /// Create a new builder with the server address.
    pub fn new(server_address: SocketAddr) -> Self {
        Self {
            config: DiscoveryServerConfig::new(server_address),
            guid_prefix: None,
        }
    }

    /// Set the GUID prefix.
    pub fn guid_prefix(mut self, guid_prefix: GuidPrefix) -> Self {
        self.guid_prefix = Some(guid_prefix);
        self
    }

    /// Set the connection timeout.
    pub fn connect_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.config.connect_timeout = timeout;
        self
    }

    /// Set the heartbeat interval.
    pub fn heartbeat_interval(mut self, interval: std::time::Duration) -> Self {
        self.config.heartbeat_interval = interval;
        self
    }

    /// Disable auto-reconnect.
    pub fn without_auto_reconnect(mut self) -> Self {
        self.config.auto_reconnect = false;
        self
    }

    /// Keep multicast discovery enabled (hybrid mode).
    pub fn with_multicast_enabled(mut self) -> Self {
        self.config.disable_multicast = false;
        self
    }

    /// Build the client.
    pub fn build(self) -> Result<DiscoveryServerClient, ClientError> {
        let guid_prefix = self
            .guid_prefix
            .ok_or_else(|| ClientError::Config("GUID prefix is required".into()))?;

        DiscoveryServerClient::new(self.config, guid_prefix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::{Ipv4Addr, TcpListener};
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_client_creation() {
        let guid_prefix = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let config = DiscoveryServerConfig::default();

        let client = DiscoveryServerClient::new(config, guid_prefix).unwrap();
        assert!(!client.is_connected());
        assert_eq!(client.guid_prefix(), &guid_prefix);
    }

    #[test]
    fn test_client_builder() {
        let addr: SocketAddr = "192.168.1.100:7400".parse().unwrap();
        let guid_prefix = [0xaa; 12];

        let client = DiscoveryServerClientBuilder::new(addr)
            .guid_prefix(guid_prefix)
            .connect_timeout(Duration::from_secs(10))
            .heartbeat_interval(Duration::from_secs(5))
            .without_auto_reconnect()
            .with_multicast_enabled()
            .build()
            .unwrap();

        assert_eq!(client.server_address(), addr);
        assert_eq!(client.config().connect_timeout, Duration::from_secs(10));
        assert_eq!(client.config().heartbeat_interval, Duration::from_secs(5));
        assert!(!client.config().auto_reconnect);
        assert!(!client.config().disable_multicast);
    }

    #[test]
    fn test_client_builder_requires_guid() {
        let addr: SocketAddr = "192.168.1.100:7400".parse().unwrap();

        let result = DiscoveryServerClientBuilder::new(addr).build();
        assert!(result.is_err());
    }

    #[test]
    fn test_not_connected_error() {
        let guid_prefix = [1; 12];
        let config = DiscoveryServerConfig::default();
        let mut client = DiscoveryServerClient::new(config, guid_prefix).unwrap();

        // Should fail when not connected
        let result = client.announce_participant(0, None, vec![], 0);
        assert!(matches!(result, Err(ClientError::NotConnected)));
    }

    #[test]
    fn test_heartbeat_due() {
        let guid_prefix = [1; 12];
        let config = DiscoveryServerConfig {
            heartbeat_interval: Duration::from_millis(10),
            ..Default::default()
        };

        let mut client = DiscoveryServerClient::new(config, guid_prefix).unwrap();

        // Initially no heartbeat is due (not connected)
        assert!(!client.heartbeat_due());

        // Simulate connected state
        client.last_heartbeat = Some(Instant::now() - Duration::from_millis(20));
        assert!(client.heartbeat_due());
    }

    #[test]
    fn test_client_error_display() {
        let err = ClientError::ConnectionFailed("timeout".into());
        assert!(err.to_string().contains("Connection failed"));

        let err = ClientError::NotConnected;
        assert!(err.to_string().contains("Not connected"));

        let err = ClientError::ServerError {
            code: 1,
            message: "Max participants".into(),
        };
        assert!(err.to_string().contains("Server error 1"));
    }

    /// Frame a JSON body the way the protocol does: 4-byte BE length, body.
    fn framed(json: &str) -> Vec<u8> {
        let mut out = u32::try_from(json.len())
            .expect("test frame fits a u32 length")
            .to_be_bytes()
            .to_vec();
        out.extend_from_slice(json.as_bytes());
        out
    }

    /// RELAY-0: a frame of a type this build does not implement must be
    /// skipped, not turned into an error that ends the session.
    ///
    /// The case that made this urgent was the relayed `data` frame, whose
    /// DESTINATION is chosen by another client: decoding it failed,
    /// `run_connected_session` mapped the failure to
    /// `SessionOutcome::Disconnected`, and any client of the domain could
    /// churn any other one with a single frame. `data` is implemented now,
    /// so the case is carried here by a type from a later revision - which
    /// is the general shape of the problem and the one that outlives this
    /// particular frame.
    #[test]
    fn an_unimplemented_frame_type_is_skipped_not_fatal() {
        let config = DiscoveryServerConfig::default();
        let mut client = DiscoveryServerClient::new(config, [1; 12]).unwrap();

        // The unimplemented frame first, then one we do implement: the
        // second is what proves the stream stayed synchronised rather than
        // merely that the first did not blow up.
        client.read_buffer.extend_from_slice(&framed(
            r#"{"type":"something_newer","destination":"0102030405060708090a0b0c","whatever":42}"#,
        ));
        client.read_buffer.extend_from_slice(&framed(
            r#"{"type":"participant_ack","guid_prefix":"0102030405060708090a0b0c"}"#,
        ));

        let event = client
            .decode_buffered_message()
            .expect("an unimplemented frame type must not be an error");

        assert!(
            matches!(event, Some(ClientEvent::ParticipantAcknowledged)),
            "the frame following the skipped one must still be delivered, got {:?}",
            event
        );
        assert_eq!(
            client.unknown_messages(),
            1,
            "the skipped frame must be counted, not silently swallowed"
        );
    }

    /// The counterpart: tolerating an unknown TYPE must not make the parser
    /// tolerant of a corrupt frame. A type we implement, with a body that
    /// does not satisfy it, is a real protocol error and still ends the
    /// session.
    #[test]
    fn a_known_type_with_a_malformed_body_is_still_an_error() {
        let config = DiscoveryServerConfig::default();
        let mut client = DiscoveryServerClient::new(config, [1; 12]).unwrap();

        // `participant_ack` requires `guid_prefix`.
        client
            .read_buffer
            .extend_from_slice(&framed(r#"{"type":"participant_ack"}"#));

        let outcome = client.decode_buffered_message();

        assert!(
            matches!(outcome, Err(ClientError::Protocol(_))),
            "a malformed body of a known type must stay a protocol error, got {:?}",
            outcome.map(|event| format!("{:?}", event))
        );
        assert_eq!(
            client.unknown_messages(),
            0,
            "a malformed frame is not an unimplemented type"
        );
    }

    /// A relayed frame addressed to us is delivered with its bytes intact.
    #[test]
    fn a_relayed_frame_addressed_to_us_is_delivered() {
        let config = DiscoveryServerConfig::default();
        let mut client = DiscoveryServerClient::new(config, [1; 12]).unwrap();

        // "AQID" is base64 for [1, 2, 3].
        client.read_buffer.extend_from_slice(&framed(
            r#"{"type":"data","destination":"010101010101010101010101","payload":"AQID"}"#,
        ));

        match client
            .decode_buffered_message()
            .expect("a relayed frame is not an error")
        {
            Some(ClientEvent::RelayDataReceived { payload }) => {
                assert_eq!(payload, vec![1, 2, 3], "the payload must survive the wire");
            }
            other => panic!("expected a relayed datagram, got {:?}", other),
        }
        assert_eq!(client.misrouted_relay_frames(), 0);
    }

    /// One addressed to another participant is dropped and counted. Handing
    /// somebody else's traffic to our own engine would be worse than losing
    /// it, and a server that does this has a routing table that disagrees
    /// with ours about who we are - worth seeing, not worth obeying.
    #[test]
    fn a_relayed_frame_addressed_to_another_participant_is_dropped() {
        let config = DiscoveryServerConfig::default();
        let mut client = DiscoveryServerClient::new(config, [1; 12]).unwrap();

        client.read_buffer.extend_from_slice(&framed(
            r#"{"type":"data","destination":"020202020202020202020202","payload":"AQID"}"#,
        ));
        // A frame we do want, behind it: the stream must stay synchronised.
        client.read_buffer.extend_from_slice(&framed(
            r#"{"type":"participant_ack","guid_prefix":"010101010101010101010101"}"#,
        ));

        let event = client
            .decode_buffered_message()
            .expect("a misrouted frame is not an error");

        assert!(
            matches!(event, Some(ClientEvent::ParticipantAcknowledged)),
            "the frame behind the dropped one must still be delivered, got {:?}",
            event
        );
        assert_eq!(
            client.misrouted_relay_frames(),
            1,
            "the misrouted frame must be counted, not silently swallowed"
        );
    }

    /// A payload that is not valid base64 is a corrupt frame, which is a
    /// real protocol error - not an unimplemented type to be skipped.
    #[test]
    fn a_relayed_frame_with_a_malformed_payload_is_an_error() {
        let config = DiscoveryServerConfig::default();
        let mut client = DiscoveryServerClient::new(config, [1; 12]).unwrap();

        client.read_buffer.extend_from_slice(&framed(
            r#"{"type":"data","destination":"010101010101010101010101","payload":"!!!!"}"#,
        ));

        let outcome = client.decode_buffered_message();

        assert!(
            matches!(outcome, Err(ClientError::Protocol(_))),
            "a malformed payload must stay a protocol error, got {:?}",
            outcome.map(|event| format!("{:?}", event))
        );
        assert_eq!(
            client.unknown_messages(),
            0,
            "a corrupt payload is not an unimplemented type"
        );
    }

    #[test]
    fn test_message_to_event_participant_ack() {
        let guid_prefix = [1; 12];
        let config = DiscoveryServerConfig::default();
        let client = DiscoveryServerClient::new(config, guid_prefix).unwrap();

        let msg = ServerMessage::ParticipantAck {
            guid_prefix: [2; 12],
        };
        let event = client.message_to_event(msg);

        assert!(matches!(event, ClientEvent::ParticipantAcknowledged));
    }

    #[test]
    fn test_message_to_event_participant_discovered() {
        let guid_prefix = [1; 12];
        let config = DiscoveryServerConfig::default();
        let client = DiscoveryServerClient::new(config, guid_prefix).unwrap();

        let msg = ServerMessage::ParticipantAnnounce {
            guid_prefix: [2; 12],
            domain_id: 0,
            name: Some("TestParticipant".into()),
            unicast_locators: vec![],
            builtin_endpoints: 0x3f,
        };
        let event = client.message_to_event(msg);

        match event {
            ClientEvent::ParticipantDiscovered {
                guid_prefix,
                domain_id,
                name,
                builtin_endpoints,
                ..
            } => {
                assert_eq!(guid_prefix, [2; 12]);
                assert_eq!(domain_id, 0);
                assert_eq!(name, Some("TestParticipant".into()));
                assert_eq!(builtin_endpoints, 0x3f);
            }
            other => assert!(
                matches!(other, ClientEvent::ParticipantDiscovered { .. }),
                "Expected ParticipantDiscovered, got {:?}",
                other
            ),
        }
    }

    #[test]
    fn test_message_to_event_error() {
        let guid_prefix = [1; 12];
        let config = DiscoveryServerConfig::default();
        let client = DiscoveryServerClient::new(config, guid_prefix).unwrap();

        let msg = ServerMessage::Error {
            code: 100,
            message: "Test error".into(),
        };
        let event = client.message_to_event(msg);

        match event {
            ClientEvent::Error { code, message } => {
                assert_eq!(code, 100);
                assert_eq!(message, "Test error");
            }
            other => assert!(
                matches!(other, ClientEvent::Error { .. }),
                "Expected Error, got {:?}",
                other
            ),
        }
    }

    #[test]
    fn an_empty_socket_reports_no_event_without_disconnecting() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (_stream, _) = listener.accept().unwrap();
            thread::sleep(Duration::from_millis(200));
        });

        let config =
            DiscoveryServerConfig::new(address).with_connect_timeout(Duration::from_millis(25));
        let mut client = DiscoveryServerClient::new(config, [1; 12]).unwrap();
        client.connect().unwrap();

        assert!(client.read_message().unwrap().is_none());
        assert!(client.is_connected());
        server.join().unwrap();
    }

    #[test]
    fn a_frame_arriving_in_pieces_is_reassembled() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let payload = br#"{"type":"participant_ack","guid_prefix":"020202020202020202020202"}"#;
        let mut frame = Vec::with_capacity(4 + payload.len());
        frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        frame.extend_from_slice(payload);

        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream.write_all(&frame[..2]).unwrap();
            thread::sleep(Duration::from_millis(40));
            stream.write_all(&frame[2..7]).unwrap();
            thread::sleep(Duration::from_millis(40));
            stream.write_all(&frame[7..]).unwrap();
        });

        let config =
            DiscoveryServerConfig::new(address).with_connect_timeout(Duration::from_millis(15));
        let mut client = DiscoveryServerClient::new(config, [1; 12]).unwrap();
        client.connect().unwrap();

        let deadline = Instant::now() + Duration::from_secs(1);
        let event = loop {
            if let Some(event) = client.read_message().unwrap() {
                break event;
            }
            assert!(client.is_connected());
            assert!(Instant::now() < deadline, "fragmented frame timed out");
            // The socket is non-blocking: without this the loop would be a
            // hot spin, and the point of the test is the reassembly, not the
            // core it burns getting there.
            client.wait_for_io(Duration::from_millis(50)).unwrap();
        };

        assert!(matches!(event, ClientEvent::ParticipantAcknowledged));
        server.join().unwrap();
    }

    #[test]
    fn peer_close_is_distinct_from_idle_timeout() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            drop(stream);
        });

        let config =
            DiscoveryServerConfig::new(address).with_connect_timeout(Duration::from_millis(100));
        let mut client = DiscoveryServerClient::new(config, [1; 12]).unwrap();
        client.connect().unwrap();

        // A single `read_message()` call cannot tell "no data
        // yet" from "the peer closed" - the `server` thread above must first
        // be scheduled and run `accept()` + `drop()`, which is not guaranteed
        // inside any fixed window on a loaded or slow machine. So the test
        // asserts on the EVENT (`is_connected()` flipping false through the
        // `Ok(0)` EOF branch of `read_message`) over a generous ceiling,
        // never on which single read observed it. That was true when the
        // socket had a read timeout and it is still true now that it has
        // none: what changed is only what the thread does while it waits.
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            client.wait_for_io(Duration::from_millis(50)).unwrap();
            let event = client.read_message().unwrap();
            assert!(
                event.is_none(),
                "no message is ever sent on this connection, so read_message must never \
                 decode one"
            );
            if !client.is_connected() {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "peer close was never observed as a distinct EOF within 5s"
            );
        }

        assert!(!client.is_connected());
        server.join().unwrap();
    }

    #[test]
    fn connected_client_exposes_selected_local_address() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (_stream, _) = listener.accept().unwrap();
            thread::sleep(Duration::from_millis(50));
        });

        let config =
            DiscoveryServerConfig::new(address).with_connect_timeout(Duration::from_millis(100));
        let mut client = DiscoveryServerClient::new(config, [1; 12]).unwrap();
        client.connect().unwrap();

        assert_eq!(
            client.local_addr().map(|addr| addr.ip()),
            Some(address.ip())
        );
        server.join().unwrap();
    }

    // ===== The outbox: a partial write must never be left behind =====

    /// One `write` call's behaviour. The last step of a script repeats.
    #[derive(Clone, Copy)]
    enum Step {
        /// Accept up to this many bytes of what is offered.
        Accept(usize),
        /// The socket has no room right now.
        Blocked,
        /// A signal interrupted the call before anything was written.
        Interrupted,
        /// The stream takes nothing more, and does not call it an error.
        Refuse,
    }

    /// A writer whose every call is scripted.
    ///
    /// Filling a real socket's send buffer to provoke a partial write takes
    /// megabytes and depends on the host's autotuning; scripting the writer
    /// makes each case exact and instant. The socket is exercised separately
    /// by `a_stalled_session_is_closed_rather_than_desynchronised`.
    struct ScriptedWriter {
        script: Vec<Step>,
        calls: usize,
        accepted: Vec<u8>,
        flushes: usize,
    }

    impl ScriptedWriter {
        fn new(script: Vec<Step>) -> Self {
            Self {
                script,
                calls: 0,
                accepted: Vec::new(),
                flushes: 0,
            }
        }
    }

    impl io::Write for ScriptedWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            let step = self.script[self.calls.min(self.script.len() - 1)];
            self.calls += 1;
            match step {
                Step::Accept(max) => {
                    let count = max.min(buf.len());
                    self.accepted.extend_from_slice(&buf[..count]);
                    Ok(count)
                }
                Step::Blocked => Err(io::Error::from(io::ErrorKind::WouldBlock)),
                Step::Interrupted => Err(io::Error::from(io::ErrorKind::Interrupted)),
                Step::Refuse => Ok(0),
            }
        }

        fn flush(&mut self) -> io::Result<()> {
            self.flushes += 1;
            Ok(())
        }
    }

    /// An outbox holding these frames, as `enqueue` would have left it.
    fn outbox_of(frames: &[&[u8]]) -> Outbox {
        let mut outbox = Outbox::default();
        for frame in frames {
            outbox.queued += frame.len();
            outbox.frames.push_back(frame.to_vec());
        }
        outbox
    }

    /// The stall limit every scripted test uses, so `now` is the only clock.
    const TEST_STALL: Duration = Duration::from_secs(10);

    #[test]
    fn a_frame_the_socket_takes_whole_leaves_nothing_behind() {
        let frame = b"{\"type\":\"heartbeat\"}";
        let mut outbox = outbox_of(&[frame]);
        let mut writer = ScriptedWriter::new(vec![Step::Accept(usize::MAX)]);

        assert!(drain_outbox(&mut writer, &mut outbox, Instant::now(), TEST_STALL).is_ok());
        assert_eq!(writer.accepted, frame);
        assert!(outbox.is_empty());
        assert_eq!(outbox.queued, 0);
        assert_eq!(writer.flushes, 1, "an emptied outbox is flushed");
    }

    #[test]
    fn a_refused_write_resumes_at_the_byte_it_stopped_on() {
        // THE property the whole outbox exists for. Two frames, handed to a
        // socket that takes three bytes at a time and blocks in between: what
        // comes out has to be the two frames end to end, in order, with
        // nothing repeated and nothing dropped - otherwise the server reads
        // our payload as a length prefix.
        let first = b"AAAAAAAAAA";
        let second = b"BBBBBBB";
        let mut outbox = outbox_of(&[first, second]);
        let mut writer = ScriptedWriter::new(vec![Step::Accept(3), Step::Blocked]);
        let now = Instant::now();

        let mut rounds = 0;
        while !outbox.is_empty() {
            rounds += 1;
            assert!(rounds < 20, "the outbox must converge");
            // Each call is one readiness event: three bytes, then blocked.
            writer.calls = 0;
            drain_outbox(&mut writer, &mut outbox, now, TEST_STALL)
                .expect("blocking is not an error");
        }

        let mut expected = first.to_vec();
        expected.extend_from_slice(second);
        assert_eq!(
            writer.accepted, expected,
            "the stream is the frames, in order"
        );
        assert_eq!(outbox.queued, 0);
        assert_eq!(outbox.sent, 0);
    }

    #[test]
    fn a_slow_link_keeps_its_session_however_long_it_takes() {
        // One byte accepted, then blocked, over and over, across a span far
        // longer than the stall limit. Every block is preceded by progress,
        // so the peer IS reading - just slowly. Giving up here would drop a
        // Discovery Server session on a congested WAN link, which is
        // precisely the deployment the relay exists for.
        let frame = b"12345";
        let mut outbox = outbox_of(&[frame]);
        let mut writer = ScriptedWriter::new(vec![Step::Accept(1), Step::Blocked]);
        let start = Instant::now();

        for round in 0..frame.len() {
            writer.calls = 0;
            // Each round is a whole stall limit later than the one before.
            let now = start + TEST_STALL * (round as u32 + 1) * 2;
            drain_outbox(&mut writer, &mut outbox, now, TEST_STALL)
                .expect("progress between blocks must clear the stall");
        }

        assert_eq!(writer.accepted, frame);
        assert!(outbox.is_empty());
    }

    #[test]
    fn a_peer_that_stops_reading_is_given_the_whole_stall_limit_and_no_more() {
        let frame = vec![0x41u8; 100];
        let mut outbox = outbox_of(&[&frame]);
        let mut writer = ScriptedWriter::new(vec![Step::Accept(10), Step::Blocked]);
        let start = Instant::now();

        // First pass: ten bytes out, then the socket blocks. The clock starts.
        drain_outbox(&mut writer, &mut outbox, start, TEST_STALL)
            .expect("a first block is not a failure");
        assert_eq!(outbox.sent, 10);

        // Just short of the limit, with no progress at all: still alive.
        drain_outbox(
            &mut writer,
            &mut outbox,
            start + TEST_STALL - Duration::from_millis(1),
            TEST_STALL,
        )
        .expect("the limit had not elapsed");

        // At the limit: given up on, and the count says where the stream is.
        let failure = drain_outbox(&mut writer, &mut outbox, start + TEST_STALL, TEST_STALL)
            .expect_err("a peer that took nothing for a whole limit is stuck");
        assert_eq!(
            failure.partial, 10,
            "the caller must learn the stream is 10 bytes into a frame"
        );
    }

    #[test]
    fn a_frame_that_never_started_leaves_the_stream_on_a_boundary() {
        let mut outbox = outbox_of(&[b"anything"]);
        let mut writer = ScriptedWriter::new(vec![Step::Blocked]);
        let start = Instant::now();

        drain_outbox(&mut writer, &mut outbox, start, TEST_STALL).expect("blocked is not failed");
        let failure = drain_outbox(&mut writer, &mut outbox, start + TEST_STALL, TEST_STALL)
            .expect_err("nothing is ever accepted");
        assert_eq!(
            failure.partial, 0,
            "zero is what tells a caller the stream is still usable"
        );
    }

    #[test]
    fn an_interrupted_write_is_retried_rather_than_counted_as_a_stall() {
        let frame = b"payload";
        let mut outbox = outbox_of(&[frame]);
        let mut writer = ScriptedWriter::new(vec![
            Step::Interrupted,
            Step::Interrupted,
            Step::Interrupted,
            Step::Interrupted,
            Step::Accept(usize::MAX),
        ]);

        assert!(
            drain_outbox(&mut writer, &mut outbox, Instant::now(), TEST_STALL).is_ok(),
            "a signal is not a stalled peer, however many arrive"
        );
        assert_eq!(writer.accepted, frame);
        assert!(outbox.is_empty());
    }

    #[test]
    fn a_stream_that_accepts_nothing_more_is_a_failure_not_a_spin() {
        let frame = vec![0x42u8; 20];
        let mut outbox = outbox_of(&[&frame]);
        let mut writer = ScriptedWriter::new(vec![Step::Accept(5), Step::Refuse]);

        let failure = drain_outbox(&mut writer, &mut outbox, Instant::now(), TEST_STALL)
            .expect_err("Ok(0) cannot make progress");
        assert_eq!(failure.error.kind(), io::ErrorKind::WriteZero);
        assert_eq!(failure.partial, 5);
    }

    #[test]
    fn nothing_written_is_not_a_framing_loss() {
        let failure = OutboxFailure {
            partial: 0,
            error: io::Error::from(io::ErrorKind::WouldBlock),
        };

        assert_eq!(
            framing_loss(&failure, 512),
            None,
            "a frame that never started leaves the stream usable"
        );
    }

    #[test]
    fn a_single_byte_written_is_already_a_framing_loss() {
        // There is no safe amount of a frame to leave behind. One byte is
        // enough for the server to read our next frame's length prefix from
        // the wrong offset.
        let failure = OutboxFailure {
            partial: 1,
            error: io::Error::from(io::ErrorKind::WouldBlock),
        };

        let reason = framing_loss(&failure, 512).expect("one byte is a loss");
        assert!(
            reason.contains("1 of 512"),
            "the reason must say how far: {reason}"
        );
        assert!(reason.contains("can no longer be framed"));
    }

    // ===== The outbox has a ceiling, and the session obeys it =====

    fn connected_to_a_silent_peer(
        heartbeat: Duration,
    ) -> (DiscoveryServerClient, TcpListener, std::net::TcpStream) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
        let address = listener.local_addr().expect("local addr");
        let config = DiscoveryServerConfig::new(address)
            .with_connect_timeout(Duration::from_millis(500))
            .with_heartbeat_interval(heartbeat);
        let mut client = DiscoveryServerClient::new(config, [0x5A; 12]).expect("build");
        client.connect().expect("connect");
        // Accept AFTER connecting: the backlog holds it until then.
        let (held, _) = listener.accept().expect("accept");
        (client, listener, held)
    }

    #[test]
    fn the_outbox_refuses_rather_than_growing() {
        let (mut client, _listener, _held) = connected_to_a_silent_peer(Duration::from_secs(10));

        // A peer that never reads: everything past the socket's own buffers
        // piles up here, and the pile has an end.
        let frame = vec![0x33u8; 64 * 1024];
        let mut accepted = 0usize;
        let refusal = loop {
            match client.enqueue(frame.clone()) {
                Ok(()) => {
                    accepted += 1;
                    assert!(
                        accepted < 4096,
                        "the outbox must refuse long before this many frames"
                    );
                    let _ = client.flush();
                }
                Err(error) => break error,
            }
        };

        assert!(
            matches!(refusal, ClientError::Backpressure(_)),
            "a full outbox is backpressure, not an I/O failure: {refusal}"
        );
        assert!(
            client.outbox_room() < frame.len(),
            "a refusal means there was genuinely no room"
        );
        assert!(
            client.is_connected(),
            "refusing a frame is not a reason to end the session"
        );
    }

    #[test]
    fn an_empty_frame_is_refused_at_the_door() {
        let (mut client, _listener, _held) = connected_to_a_silent_peer(Duration::from_secs(10));

        let error = client
            .enqueue(Vec::new())
            .expect_err("nothing this client encodes is empty");
        assert!(matches!(error, ClientError::Protocol(_)), "got {error}");
    }

    #[test]
    fn a_disconnect_leaves_nothing_queued_for_the_next_session() {
        let (mut client, _listener, _held) = connected_to_a_silent_peer(Duration::from_secs(10));

        client
            .enqueue(vec![0x44u8; 1024])
            .expect("room for one frame");
        client.disconnect();

        assert_eq!(
            client.outbox_room(),
            MAX_OUTBOX_BYTES,
            "a frame queued for a stream that no longer exists must not be carried over: the \
             server would read the tail of a conversation it never had"
        );
    }

    #[test]
    fn a_stalled_session_is_closed_rather_than_desynchronised() {
        // End to end, through a real socket: a peer that accepts the
        // connection and never reads a byte. Fill its buffers and ours, and
        // the session must END - with the framing loss named, not with a
        // stream nobody can frame left open.
        //
        // The assertion is on the OUTCOME over a generous window, never on
        // which `flush` observed it. Data already in flight keeps trickling
        // into the peer's receive buffer for a while after our own send
        // buffer fills, and every byte that lands is progress that rightly
        // clears the stall - so the first flush after the limit can still
        // succeed, and would make a single-shot assertion flaky.
        let (mut client, _listener, _held) = connected_to_a_silent_peer(Duration::from_millis(1));

        let frame = vec![0x7Eu8; 64 * 1024];
        let mut queued = 0usize;
        let deadline = Instant::now() + Duration::from_secs(20);

        let error = loop {
            assert!(
                Instant::now() < deadline,
                "an unread peer never stalled this session within 20s"
            );

            // Keep the outbox as full as it will go, then push.
            while client.outbox_room() >= frame.len() {
                client.enqueue(frame.clone()).expect("there was room");
                queued += frame.len();
                assert!(
                    queued < 512 * 1024 * 1024,
                    "this host's socket buffers absorbed 512 MiB unread; the test cannot \
                     provoke a stall here"
                );
            }

            match client.flush() {
                Ok(()) => thread::sleep(Duration::from_millis(25)),
                Err(error) => break error,
            }
        };

        assert!(
            matches!(error, ClientError::Protocol(ref text) if text.contains("can no longer be framed")),
            "a half-written frame must be reported as a framing loss, got: {error}"
        );
        assert!(
            !client.is_connected(),
            "a stream carrying half a frame must not be left open for the next writer"
        );
    }

    // ===== Waiting, and being woken =====

    #[test]
    fn waiting_ends_on_its_own_timeout_when_nothing_happens() {
        let (mut client, _listener, _held) = connected_to_a_silent_peer(Duration::from_secs(10));

        // A freshly registered socket is writable, and mio says so once. That
        // is one extra turn of the session loop after each connect, not a
        // spin: being edge-triggered, it does not say so again until the
        // socket has actually filled and drained.
        client.wait_for_io(Duration::from_millis(80)).expect("poll");

        let start = Instant::now();
        client.wait_for_io(Duration::from_millis(80)).expect("poll");
        assert!(
            start.elapsed() >= Duration::from_millis(60),
            "a quiet socket must not return early and spin the session thread"
        );
    }

    #[test]
    fn a_waker_returns_the_session_thread_at_once() {
        // The reason the waker exists: a DDS writer hands the session
        // something to send while it is asleep on a socket with nothing to
        // say. Without this it would sleep out its whole timeout first.
        let (mut client, _listener, _held) = connected_to_a_silent_peer(Duration::from_secs(10));
        let waker = client.waker();

        let nudge = thread::spawn(move || {
            thread::sleep(Duration::from_millis(30));
            waker.wake().expect("wake");
        });

        let start = Instant::now();
        client.wait_for_io(Duration::from_secs(5)).expect("poll");
        let waited = start.elapsed();
        nudge.join().expect("nudge thread");

        assert!(
            waited < Duration::from_secs(2),
            "the waker must cut the wait short, waited {waited:?}"
        );
    }

    #[test]
    fn a_waker_outlives_the_connection_it_was_taken_from() {
        // Whoever holds one is handed it once, at startup, and keeps it
        // across every reconnection - so it must belong to the client, not
        // to a socket.
        let (mut client, _listener, _held) = connected_to_a_silent_peer(Duration::from_secs(10));
        let waker = client.waker();
        client.disconnect();

        waker.wake().expect("a waker survives its session");
        let start = Instant::now();
        client.wait_for_io(Duration::from_secs(5)).expect("poll");
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "the wake must still reach a disconnected client's poll"
        );
    }
}
