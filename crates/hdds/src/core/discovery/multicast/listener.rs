// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Multicast UDP listener thread for RTPS discovery packets.
//!
//!
//! Spawns a dedicated IO thread to receive, classify, and dispatch RTPS packets.
//! Uses lock-free buffer pool and ring buffer for zero-allocation hot-path.
//!
//! # Architecture (mio/epoll)
//!
//! ```text
//! mio::poll() -> recv_from(temp_buf) -> classify_rtps() -> RxPool::acquire() -> copy -> RxRing::push()
//!                                          v
//!                              DiscoveryCallback (SPDP/SEDP)
//! ```
//!
//! # Optimizations
//! - **epoll**: Uses mio for event-driven I/O (no blocking timeout overhead)
//! - **edge-triggered drain**: Process all available packets per poll event

use super::classifier::walk::{destined_to, split_by_receiver_state, Destined, Sources};
use super::control_parser::{
    parse_all_acknack_submessages, parse_all_nack_frag_submessages,
    scan_all_embedded_control_submessages,
};
use super::control_types::ControlMessage;
use super::{classify_rtps, for_each_data_submessage, Origin, PacketKind, RxMeta, RxPool};
use crate::engine::wake::WakeNotifier;
use crate::engine::writer_control::user_writer;
use crossbeam::channel::Sender;
use crossbeam::queue::ArrayQueue;
use mio::{Events, Interest, Poll, Token, Waker};
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;

/// Readiness of the listening socket in the poll.
const SOCKET_TOKEN: Token = Token(0);
/// Wakes the poll for shutdown; carries no packet.
const WAKE_TOKEN: Token = Token(1);

// Fragment metadata moved to meta.rs to avoid circular dependencies
pub use super::meta::FragmentMetadata;

/// Discovery callback type for SPDP/SEDP packet processing
///
/// Arguments:
/// - PacketKind: Type of packet (Data, DataFrag, etc.)
/// - &[u8]: Full RTPS packet (including headers, for DialectDetector)
/// - usize: CDR payload offset within the packet (computed by classifier)
/// - `Option<FragmentMetadata>`: Fragment metadata if PacketKind::DataFrag
/// - `Origin`: where the packet came from, and where a reply may go (RTPS
///   2.5 8.3.4, 8.3.8.10: `None` behind an INFO_SRC)
pub type DiscoveryCallback =
    Arc<dyn Fn(PacketKind, &[u8], usize, Option<FragmentMetadata>, Origin) + Send + Sync>;

/// Listener metrics for diagnostics
#[derive(Debug)]
pub struct ListenerMetrics {
    /// Total packets received (all types)
    pub packets_received: AtomicU64,
    /// Packets dropped (pool exhausted or ring full)
    pub packets_dropped: AtomicU64,
    /// Invalid packets (malformed RTPS header)
    pub packets_invalid: AtomicU64,
    /// Total bytes received
    pub bytes_received: AtomicU64,
    /// Discovery callback errors (panics caught)
    pub callback_errors: AtomicU64,
}

impl ListenerMetrics {
    pub(crate) fn new() -> Arc<Self> {
        crate::trace_fn!("ListenerMetrics::new");
        Arc::new(Self {
            packets_received: AtomicU64::new(0),
            packets_dropped: AtomicU64::new(0),
            packets_invalid: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            callback_errors: AtomicU64::new(0),
        })
    }

    /// Get snapshot of metrics
    pub fn snapshot(&self) -> (u64, u64, u64, u64, u64) {
        crate::trace_fn!("ListenerMetrics::snapshot");
        (
            self.packets_received.load(Ordering::Relaxed),
            self.packets_dropped.load(Ordering::Relaxed),
            self.packets_invalid.load(Ordering::Relaxed),
            self.bytes_received.load(Ordering::Relaxed),
            self.callback_errors.load(Ordering::Relaxed),
        )
    }
}

/// A receive error that reports an earlier send to a peer that was not
/// listening (an ICMP port-unreachable surfaced on this socket), not a
/// fault of the socket itself. Windows reports it on UDP sockets as
/// `WSAECONNRESET`; other systems may report `ECONNREFUSED`. The next
/// receive is unaffected.
fn is_peer_unreachable_report(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionRefused
    )
}

/// Which packet kinds are handed to the discovery callback.
///
/// Every other kind either goes to the rx ring for the demux router or is
/// dropped. Extracted from the recv loop so the dispatch set is a testable
/// value rather than a condition buried inside a thread closure -- a stale
/// list would leave a kind with a complete handler (the DDS-Security
/// handshake, say) unreachable.
#[inline]
fn wants_discovery_callback(kind: PacketKind) -> bool {
    match kind {
        PacketKind::Data
        | PacketKind::DataFrag
        | PacketKind::SPDP
        | PacketKind::SEDP
        | PacketKind::TypeLookup
        | PacketKind::Heartbeat => true,

        // A builtin endpoint we do not implement. It comes here to be named
        // and counted, not handled: the dispatch drops it. It is deliberately
        // NOT pushed to the rx ring below either - it is a builtin's traffic,
        // so the router has no topic for it and could only orphan it.
        PacketKind::UnknownBuiltin => true,

        // DDS-Security v1.1 sec. 7.4.1.3: the PKI-DH handshake tunnel (Stateless,
        // entity 0x000201C3/C4) and the encrypted SEDP tunnel (SecureSEDP, the
        // 0xff-prefixed builtin entities) are handled by this same callback.
        // Both handlers are complete in `discovery_setup`; this gate is the
        // only thing that makes them reachable. Were it to refuse them, no
        // handshake could ever complete and every secure SEDP announcement
        // would be silently discarded.
        //
        // They must be admitted TOGETHER: once handshakes start completing, the
        // SEDP send path begins protecting its secure writers, so
        // admitting Stateless alone would take SEDP down outright.
        //
        // SecureVolatile names a CLEAR DATA of the ParticipantVolatileMessage
        // Secure endpoints: delivered so `discovery_setup` refuses and counts
        // it (the topic is submessage-protected; its protected DATA arrives
        // as a SEC_PREFIX, below, and is opened under the peer's KxKeys).
        //
        // Gated on the feature so a default build keeps exactly the dispatch set
        // the interop suite is calibrated against.
        //
        // SecureSPDP carries one thing HDDS reads: the sealed departure of an
        // authenticated participant (`DiscoveryFsm::open_sealed_departure`).
        #[cfg(feature = "security")]
        PacketKind::Stateless
        | PacketKind::SecureSEDP
        | PacketKind::SecureVolatile
        | PacketKind::SecureSPDP => true,

        // Every refusal is named, and there is deliberately no `_` arm. A
        // wildcard here would let a kind with a complete handler (the
        // DDS-Security handshake, say) fall into `_ => false` without anyone
        // deciding it should. With the refusals listed, a new
        // `PacketKind` does not compile until somebody decides whether
        // discovery wants it - here, and in `DiscoveryDispatch::dispatch`,
        // which is exhaustive for the same reason.
        #[cfg(not(feature = "security"))]
        PacketKind::Stateless
        | PacketKind::SecureSEDP
        | PacketKind::SecureVolatile
        | PacketKind::SecureSPDP => false,

        // Control plane: consumed by the control branches of the recv loop
        // or routed through the rx ring to the demux router.
        PacketKind::AckNack
        | PacketKind::Gap
        | PacketKind::NackFrag
        | PacketKind::HeartbeatFrag => false,

        // Not a datagram: never classified, only queued by the departure
        // route (`engine::departures`).
        PacketKind::Departure => false,

        // Context submessages. The classifier never elects one to name a
        // datagram (they describe the submessages that follow them), so these
        // arms exist for the compiler rather than for any datagram.
        PacketKind::InfoTs | PacketKind::InfoSrc | PacketKind::InfoDst | PacketKind::InfoReply => {
            false
        }

        // A remote participant's liveliness assertion (RTPS v2.5
        // Sec.8.4.13): the dispatch reads its kind; a MANUAL one renews the
        // participant's MANUAL_BY_PARTICIPANT writers.
        PacketKind::ParticipantMessage => true,

        // Nothing to deliver: padding, a malformed header (counted earlier as
        // `packets_invalid`), or a datagram in which no submessage described
        // itself.
        PacketKind::Pad | PacketKind::Invalid | PacketKind::Unknown => false,
    }
}

/// Multicast listener for RTPS discovery packets
///
/// Spawns dedicated IO thread to receive UDP multicast packets,
/// classify them (SPDP/SEDP), and push to lock-free ring for FSM processing.
///
/// # Architecture
/// ```text
/// UDP recv_from() (blocking)
///     v
/// classify_packet() -> PacketKind
///     v
/// RxPool::acquire()
///     v
/// Copy to buffer
///     v
/// RxRing::push((meta, buffer_id))
/// ```
///
/// # Performance
/// - Zero allocation in hot-path (pre-allocated buffers)
/// - Lock-free ring (crossbeam SPSC)
/// - CPU idle when no packets (blocking recv)
pub struct MulticastListener {
    /// Thread join handle
    handle: Option<JoinHandle<()>>,
    /// Running flag for graceful shutdown
    running: Arc<AtomicBool>,
    /// Wakes the listener thread out of its poll so it sees `running` clear
    /// without waiting for a socket event.
    waker: Arc<Waker>,
    /// Listener metrics
    pub metrics: Arc<ListenerMetrics>,
    /// Optional discovery callback for SPDP/SEDP processing
    #[allow(dead_code)] // Used only for ownership, passed to thread
    discovery_callback: Option<DiscoveryCallback>,
    /// Optional control channel sender for the Two-Ring architecture
    #[allow(dead_code)] // Used only for ownership, passed to thread
    control_tx: Option<Sender<ControlMessage>>,
    /// Optional wake notifier for low-latency router wake
    #[allow(dead_code)] // Used only for ownership, passed to thread
    notifier: Option<Arc<WakeNotifier>>,
    /// The participant this listener receives for, as given to its thread.
    #[cfg(test)]
    local_prefix: Option<[u8; 12]>,
}

impl MulticastListener {
    /// Spawn multicast listener thread
    ///
    /// # Arguments
    /// - `socket`: Shared UDP socket (from UdpTransport)
    /// - `pool`: Shared buffer pool
    /// - `ring`: SPSC ring to FSM
    /// - `discovery_callback`: Optional callback for SPDP/SEDP packet processing
    ///
    /// # Returns
    /// MulticastListener instance for shutdown control
    ///
    /// # Errors
    /// Returns IO error if thread spawn fails
    ///
    /// # Examples
    /// ```no_run
    /// use hdds::core::discovery::multicast::{MulticastListener, RxPool, RxMeta};
    /// use hdds::transport::{UdpTransport, PortMapping};
    /// use crossbeam::queue::ArrayQueue;
    /// use std::sync::Arc;
    ///
    /// let mapping = PortMapping::calculate(0, 0)
    ///     .expect("Port mapping calculation should succeed");
    /// let transport = UdpTransport::new(0, 0, mapping)
    ///     .expect("UDP transport creation should succeed");
    /// let pool = Arc::new(RxPool::new(16, 1500).expect("RxPool creation should succeed"));
    /// let ring = Arc::new(ArrayQueue::new(256));
    ///
    /// let listener = MulticastListener::spawn(
    ///     transport.socket(),
    ///     pool,
    ///     ring,
    ///     None, // No discovery callback
    /// ).expect("Listener spawn should succeed");
    /// ```
    pub fn spawn(
        socket: Arc<UdpSocket>,
        pool: Arc<RxPool>,
        ring: Arc<ArrayQueue<(RxMeta, u8)>>,
        discovery_callback: Option<DiscoveryCallback>,
    ) -> io::Result<Self> {
        Self::spawn_with_control(socket, pool, ring, discovery_callback, None)
    }

    /// Spawn multicast listener with the Two-Ring control channel
    ///
    /// # Arguments
    /// - `socket`: Shared UDP socket (from UdpTransport)
    /// - `pool`: Shared buffer pool for DATA packets
    /// - `ring`: SPSC ring to DemuxRouter (DATA path)
    /// - `discovery_callback`: Optional callback for SPDP/SEDP packet processing
    /// - `control_tx`: Optional sender for control messages (HEARTBEAT/ACKNACK)
    ///
    /// When `control_tx` is Some, HEARTBEAT packets are sent to the control
    /// channel instead of being processed synchronously. This prevents the
    /// hot DATA path from being blocked by HEARTBEAT processing.
    pub fn spawn_with_control(
        socket: Arc<UdpSocket>,
        pool: Arc<RxPool>,
        ring: Arc<ArrayQueue<(RxMeta, u8)>>,
        discovery_callback: Option<DiscoveryCallback>,
        control_tx: Option<Sender<ControlMessage>>,
    ) -> io::Result<Self> {
        Self::spawn_with_notifier(socket, pool, ring, discovery_callback, control_tx, None)
    }

    /// Spawn multicast listener with wake notifier for low-latency routing.
    ///
    /// # Arguments
    /// - `socket`: Shared UDP socket (from UdpTransport)
    /// - `pool`: Shared buffer pool for DATA packets
    /// - `ring`: SPSC ring to DemuxRouter (DATA path)
    /// - `discovery_callback`: Optional callback for SPDP/SEDP packet processing
    /// - `control_tx`: Optional sender for control messages (HEARTBEAT/ACKNACK)
    /// - `notifier`: Optional wake notifier to signal router immediately on data
    ///
    /// When `notifier` is provided, the listener will call `notify()` after
    /// pushing data to the ring, allowing the router to wake immediately
    /// instead of polling, reducing latency from ~100us to ~1-10us.
    ///
    /// A listener spawned here knows no participant, so it cannot tell a
    /// submessage destined to another one (INFO_DST, RTPS 2.5 8.3.8.8) and
    /// hands every submessage on. A participant spawns its listeners with
    /// its own GUID prefix.
    pub fn spawn_with_notifier(
        socket: Arc<UdpSocket>,
        pool: Arc<RxPool>,
        ring: Arc<ArrayQueue<(RxMeta, u8)>>,
        discovery_callback: Option<DiscoveryCallback>,
        control_tx: Option<Sender<ControlMessage>>,
        notifier: Option<Arc<WakeNotifier>>,
    ) -> io::Result<Self> {
        Self::spawn_for_participant(
            socket,
            pool,
            ring,
            discovery_callback,
            control_tx,
            notifier,
            None,
            None,
        )
    }

    /// Spawn the listener of the participant whose GUID prefix is
    /// `local_prefix`: a submessage an INFO_DST destines to another
    /// participant is not applied here (see `PacketDispatch::dispatch`).
    /// Each datagram renews the liveliness of its sender (`liveliness`).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn spawn_for_participant(
        socket: Arc<UdpSocket>,
        pool: Arc<RxPool>,
        ring: Arc<ArrayQueue<(RxMeta, u8)>>,
        discovery_callback: Option<DiscoveryCallback>,
        control_tx: Option<Sender<ControlMessage>>,
        notifier: Option<Arc<WakeNotifier>>,
        local_prefix: Option<[u8; 12]>,
        liveliness: Option<Arc<crate::dds::liveliness::Shared>>,
    ) -> io::Result<Self> {
        crate::trace_fn!("MulticastListener::spawn_with_notifier");
        // Non-blocking socket for mio epoll
        socket.set_nonblocking(true)?;

        // The poll is created here, not on the thread, so the waker can be
        // registered on it before the thread starts.
        let mio_poll = Poll::new()?;
        let waker = Arc::new(Waker::new(mio_poll.registry(), WAKE_TOKEN)?);

        let running = Arc::new(AtomicBool::new(true));
        let running_clone = Arc::clone(&running);

        let metrics = ListenerMetrics::new();
        let metrics_clone = Arc::clone(&metrics);

        let callback_clone = discovery_callback.clone();
        let control_tx_clone = control_tx.clone();
        let notifier_clone = notifier.clone();

        // Spawn IO thread
        let handle = std::thread::Builder::new()
            .name("hdds-mcast-rx".to_string())
            .spawn(crate::core::rt::shutdown::owned(move || {
                Self::run_loop(
                    mio_poll,
                    socket,
                    pool,
                    ring,
                    running_clone,
                    metrics_clone,
                    callback_clone,
                    control_tx_clone,
                    notifier_clone,
                    local_prefix,
                    liveliness,
                );
            }))?;

        Ok(Self {
            handle: Some(handle),
            running,
            waker,
            metrics,
            discovery_callback,
            control_tx,
            notifier,
            #[cfg(test)]
            local_prefix,
        })
    }

    /// The GUID prefix of the participant this listener receives for.
    #[cfg(test)]
    pub(crate) fn local_prefix(&self) -> Option<[u8; 12]> {
        self.local_prefix
    }

    /// Main IO loop (runs in dedicated thread)
    ///
    /// Uses mio/epoll for event-driven I/O with minimal latency.
    #[allow(clippy::too_many_arguments)]
    fn run_loop(
        mut mio_poll: Poll,
        socket: Arc<UdpSocket>,
        pool: Arc<RxPool>,
        ring: Arc<ArrayQueue<(RxMeta, u8)>>,
        running: Arc<AtomicBool>,
        metrics: Arc<ListenerMetrics>,
        discovery_callback: Option<DiscoveryCallback>,
        control_tx: Option<Sender<ControlMessage>>,
        notifier: Option<Arc<WakeNotifier>>,
        local_prefix: Option<[u8; 12]>,
        liveliness: Option<Arc<crate::dds::liveliness::Shared>>,
    ) {
        let local_addr = socket
            .local_addr()
            .map(|addr| addr.to_string())
            .unwrap_or_else(|_| "<unknown>".to_string());
        log::debug!(
            "[MCAST-THREAD] started with mio/epoll addr={} thread={:?}",
            local_addr,
            std::thread::current().id()
        );

        let mut events = Events::with_capacity(16);

        // Convert std socket to mio socket for registration
        // We clone the socket because Arc<UdpSocket> doesn't implement Source
        let socket_clone = match socket.try_clone() {
            Ok(s) => s,
            Err(e) => {
                log::error!("[MCAST-THREAD] Failed to clone socket: {}", e);
                return;
            }
        };
        let mut mio_socket = mio::net::UdpSocket::from_std(socket_clone);

        // Register socket with poll for read events
        if let Err(e) =
            mio_poll
                .registry()
                .register(&mut mio_socket, SOCKET_TOKEN, Interest::READABLE)
        {
            log::error!("[MCAST-THREAD] Failed to register socket with poll: {}", e);
            return;
        }

        // Temporary buffer for recv_from (reused across iterations)
        let mut temp_buf = vec![0u8; crate::config::MAX_PACKET_SIZE];

        // Drain stale packets from OS socket buffer before processing.
        //
        // When a previous DDS process on the same domain is killed (SIGINT),
        // its SPDP/SEDP packets may linger in the OS socket buffer. Draining
        // the buffer here (instant, non-blocking) ensures stale packets from
        // dead processes never enter the discovery FSM.
        //
        // IMPORTANT: No sleep/delay here -- even 10ms delays discovery enough
        // to cause incompatibility tests to fail (subscriber receives multicast
        // data before SEDP detects the incompatibility).
        {
            let mut drained = 0u32;
            loop {
                match mio_socket.recv_from(&mut temp_buf) {
                    Ok((len, _)) => {
                        drained += 1;
                        log::debug!("[MCAST-THREAD] Drained stale packet ({} bytes)", len);
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) if is_peer_unreachable_report(&e) => continue,
                    Err(_) => break,
                }
            }
            if drained > 0 {
                log::info!(
                    "[MCAST-THREAD] Drained {} stale packet(s) from OS buffer on {}",
                    drained,
                    local_addr
                );
            }
        }

        let dispatch = PacketDispatch::new(
            pool,
            ring,
            metrics,
            discovery_callback,
            control_tx,
            notifier,
            local_prefix,
            liveliness,
        );

        while running.load(Ordering::Relaxed) {
            // Blocks until the socket is readable or shutdown wakes the poll.
            // No timeout: an idle listener does not wake up.
            if let Err(e) = mio_poll.poll(&mut events, None) {
                if e.kind() != io::ErrorKind::Interrupted {
                    log::debug!("[MCAST-THREAD] poll error: {:?}", e);
                }
                continue;
            }

            // Process all ready events
            for event in events.iter() {
                if event.token() != SOCKET_TOKEN {
                    continue;
                }

                // Drain all available packets (edge-triggered style)
                loop {
                    let (len, src_addr) = match mio_socket.recv_from(&mut temp_buf) {
                        Ok(result) => result,
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                        // An ICMP port-unreachable for an earlier send (a peer
                        // that just stopped) consumes one receive and says
                        // nothing about this socket: keep draining. Leaving
                        // the loop before WouldBlock would leave the socket
                        // unarmed for good on Windows, where the poller only
                        // reports a new edge after a full drain.
                        Err(e) if is_peer_unreachable_report(&e) => {
                            log::debug!("[hdds-mcast-rx] peer unreachable report: {:?}", e);
                            continue;
                        }
                        Err(e) => {
                            log::debug!("[hdds-mcast-rx] recv_from error: {:?}", e);
                            break;
                        }
                    };
                    log::debug!(
                        "[MCAST] recv len={} src={} thread={:?}",
                        len,
                        src_addr,
                        std::thread::current().id()
                    );

                    dispatch.dispatch(&temp_buf[..len], src_addr);
                } // end inner drain loop
            } // end for event
        } // end while running
    }

    /// Shutdown listener gracefully
    ///
    /// Signals thread to exit and waits for join.
    pub fn shutdown(mut self) {
        crate::trace_fn!("MulticastListener::shutdown");
        self.running.store(false, Ordering::Relaxed);
        self.wake();
        if let Some(handle) = self.handle.take() {
            crate::core::rt::shutdown::join_bounded(handle, "multicast listener");
        }
    }
}

/// Everything one received datagram is routed into.
///
/// It exists so the routing is callable without a socket. The UDP listener
/// thread builds one and hands it what `recv_from` returned; nothing in here
/// touches the socket, the bind address or the shutdown flag, which is what
/// makes a datagram that arrived some other way - relayed by a Discovery
/// Server, say, carrying the sender's locator as `src_addr` - a first-class
/// caller rather than a special case.
pub(crate) struct PacketDispatch {
    pool: Arc<RxPool>,
    ring: Arc<ArrayQueue<(RxMeta, u8)>>,
    metrics: Arc<ListenerMetrics>,
    discovery_callback: Option<DiscoveryCallback>,
    control_tx: Option<Sender<ControlMessage>>,
    notifier: Option<Arc<WakeNotifier>>,
    /// GUID prefix of the participant this dispatch receives for; `None`
    /// for a listener that knows no participant.
    local_prefix: Option<[u8; 12]>,
    /// The participant's liveliness: each message renews its sender's
    /// AUTOMATIC writers (`Shared::heard_from`).
    liveliness: Option<Arc<crate::dds::liveliness::Shared>>,
}

impl PacketDispatch {
    /// Tests only: a dispatch that ringed into `ring` and sent its control
    /// messages to `control_tx`, with no discovery callback.
    #[cfg(test)]
    pub(crate) fn for_test(
        pool: Arc<RxPool>,
        ring: Arc<ArrayQueue<(RxMeta, u8)>>,
        control_tx: Sender<ControlMessage>,
    ) -> Self {
        Self {
            pool,
            ring,
            metrics: ListenerMetrics::new(),
            discovery_callback: None,
            control_tx: Some(control_tx),
            notifier: None,
            local_prefix: None,
            liveliness: None,
        }
    }

    /// Build a routing target over receive plumbing that already exists.
    ///
    /// The arguments are the participant's, not a socket's: the same pool,
    /// the same ring, the same discovery callback, the same control channel
    /// and the same notifier every UDP listener of that participant was
    /// given. What a caller brings of its own is `metrics`, because a set of
    /// counters answers the question "what did THIS source deliver", and an
    /// ingress that is not a socket has no business inflating a socket's
    /// numbers.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        pool: Arc<RxPool>,
        ring: Arc<ArrayQueue<(RxMeta, u8)>>,
        metrics: Arc<ListenerMetrics>,
        discovery_callback: Option<DiscoveryCallback>,
        control_tx: Option<Sender<ControlMessage>>,
        notifier: Option<Arc<WakeNotifier>>,
        local_prefix: Option<[u8; 12]>,
        liveliness: Option<Arc<crate::dds::liveliness::Shared>>,
    ) -> Self {
        Self {
            pool,
            ring,
            metrics,
            discovery_callback,
            control_tx,
            notifier,
            local_prefix,
            liveliness,
        }
    }

    /// The counters this dispatch feeds.
    pub(crate) fn metrics(&self) -> &Arc<ListenerMetrics> {
        &self.metrics
    }

    /// The GUID prefix of the participant this dispatch receives for.
    #[cfg(test)]
    pub(crate) fn local_prefix(&self) -> Option<[u8; 12]> {
        self.local_prefix
    }

    /// Forward every NACK_FRAG of `datagram` that actually asks for
    /// fragments to the control channel.
    ///
    /// ONE reader for a question five branches of the dispatch ask. Separate
    /// copies of this loop drift: one that answers a NACK_FRAG whose
    /// fragmentNumberState names nothing with `return` would lose the rest of
    /// the datagram, where the others skip it. A single reader keeps every
    /// branch identical.
    ///
    /// Skipping an empty request is not a filter the consumer relies on
    /// being absent: `control.rs` already refuses to deliver one
    /// (`if !nf.missing_fragments.is_empty()`), so forwarding it only spends
    /// a slot of a 1024-deep channel whose overflow is a silent drop.
    fn dispatch_nack_frags(tx: &Sender<ControlMessage>, origin: Origin, datagram: &[u8]) {
        let mut peer_guid_prefix = [0u8; 12];
        if datagram.len() >= 20 {
            peer_guid_prefix.copy_from_slice(&datagram[8..20]);
        }
        for nf_info in parse_all_nack_frag_submessages(datagram) {
            // A pure fragment-level acknowledgment (RTPS v2.5 Sec.8.3.8.12):
            // nothing to retransmit, and nothing for the consumer to do.
            if nf_info.missing_fragments.is_empty() {
                continue;
            }
            log::debug!(
                "[MCAST-RX] Sending NACK_FRAG to control channel: writer={:02x?} sn={} frags={:?} from {}",
                nf_info.writer_entity_id,
                nf_info.writer_sn,
                nf_info.missing_fragments,
                origin.from()
            );
            if let Some(msg) =
                ControlMessage::nack_frag(origin, peer_guid_prefix, nf_info, datagram)
            {
                if tx.try_send(msg).is_err() {
                    log::debug!(
                        "[MCAST-RX] Control channel full, dropping NACK_FRAG from {}",
                        origin.from()
                    );
                }
            }
        }
    }

    /// Classify one datagram and route it: to the discovery callback, to the
    /// control channel, or into the ring for the router.
    ///
    /// Extracted from `run_loop`: each `continue` that meant "on to the next
    /// datagram" is a `return`, and the buffer it reads is the parameter.
    ///
    /// Only the submessages destined to this participant are routed: one
    /// behind an INFO_DST naming another participant acts on none of our
    /// endpoints (RTPS 2.5 8.3.8.8), whatever its entityId says. And each
    /// submessage is read with its own source: a datagram carrying INFO_SRC
    /// is dispatched as one message per source (8.3.8.10).
    pub(crate) fn dispatch(&self, received: &[u8], src_addr: SocketAddr) {
        let metrics = &self.metrics;

        // Update metrics
        metrics.packets_received.fetch_add(1, Ordering::Relaxed);
        metrics
            .bytes_received
            .fetch_add(received.len() as u64, Ordering::Relaxed);

        let part;
        let datagram = match self.local_prefix.map(|ours| destined_to(received, &ours)) {
            None | Some(Destined::Whole) => received,
            Some(Destined::Part(destined)) => {
                part = destined;
                &part[..]
            }
            Some(Destined::Nothing) => {
                log::trace!(
                    "[MCAST] datagram from {} destined to another participant",
                    src_addr
                );
                return;
            }
        };
        // One message per source (INFO_SRC, RTPS 2.5 8.3.8.10) and reply
        // locator (INFO_REPLY, 8.3.8.9), each read as if it had arrived
        // alone. The leading part (if any) is direct: its source IS
        // `src_addr`. Every part behind an INFO_SRC is relayed: `src_addr`
        // only forwarded it, and 8.3.8.10 leaves it no reply locator. Every
        // part behind an INFO_REPLY replies to the locator it names.
        match split_by_receiver_state(datagram) {
            Sources::One(message) => self.dispatch_datagram(message, Origin::direct(src_addr)),
            Sources::Split(parts) => {
                for part in &parts {
                    self.dispatch_datagram(&part.message, part.origin(src_addr));
                }
            }
        }
    }

    /// Dispatch one RTPS message whose submessages all have the source its
    /// header names and are all destined to this participant.
    fn dispatch_datagram(&self, datagram: &[u8], origin: Origin) {
        let pool = &self.pool;
        let ring = &self.ring;
        let metrics = &self.metrics;
        let discovery_callback = &self.discovery_callback;
        let control_tx = &self.control_tx;
        // A user writer's HEARTBEAT or GAP travels with its datagram on the
        // ring, where the Router applies it in arrival order behind the DATA it
        // follows (`engine::writer_control`). Set by the branches below.
        let mut user_controls_on_ring = false;
        // Whether the datagram carries any HEARTBEAT or GAP, when a control
        // thread scanned it (`RxMeta::controls_may_ride`).
        let mut datagram_has_controls = true;
        // A datagram elected as neither DATA nor a control (SPDP, SEDP...) that
        // carries a user writer's control rides the ring as a controls-only copy
        // (kind Heartbeat): the Router applies that control in order (F3).
        let mut control_only_ring = false;
        // The controls that wait for the ring: sent once the datagram is in it
        // (riding it), or as the control thread's when it is not.
        let mut deferred_controls: Vec<ControlMessage> = Vec::new();
        let notifier = &self.notifier;
        let len = datagram.len();

        // Classify packet (returns kind, optional DATA payload offset, fragment metadata, and RTPS context)
        // The context captures INFO_DST/INFO_TS for stateful RTPS parsing
        let (kind, payload_offset, fragment_metadata, rtps_context) =
            classify_rtps(&datagram[..len]);

        let kind_label = match kind {
            PacketKind::Data => "DATA",
            PacketKind::Departure => "DEPARTURE",
            PacketKind::UnknownBuiltin => "UNKNOWN_BUILTIN",
            PacketKind::Heartbeat => "HEARTBEAT",
            PacketKind::AckNack => "ACKNACK",
            PacketKind::DataFrag => "DATA_FRAG",
            PacketKind::Gap => "GAP",
            PacketKind::NackFrag => "NACK_FRAG",
            PacketKind::HeartbeatFrag => "HEARTBEAT_FRAG",
            PacketKind::InfoTs => "INFO_TS",
            PacketKind::InfoSrc => "INFO_SRC",
            PacketKind::InfoDst => "INFO_DST",
            PacketKind::InfoReply => "INFO_REPLY",
            PacketKind::Pad => "PAD",
            PacketKind::SPDP => "SPDP",
            PacketKind::SEDP => "SEDP",
            PacketKind::TypeLookup => "TYPE_LOOKUP",
            PacketKind::ParticipantMessage => "PARTICIPANT_MESSAGE",
            PacketKind::SecureSPDP => "SECURE_SPDP",
            PacketKind::SecureSEDP => "SECURE_SEDP",
            PacketKind::SecureVolatile => "SECURE_VOLATILE",
            PacketKind::Stateless => "STATELESS",
            PacketKind::Invalid => "INVALID",
            PacketKind::Unknown => "UNKNOWN",
        };
        log::debug!(
            "[MCAST] recv kind={} len={} src={} thread={:?}",
            kind_label,
            len,
            origin.from(),
            std::thread::current().id()
        );

        // Submessage enumeration diagnostic
        // When HDDS_INTEROP_DIAGNOSTICS=1, dump ALL submessage IDs in each packet.
        // This shows whether a peer sends compound [DATA+HEARTBEAT]
        // packets or separate ones.
        // The knob is answered once per process (see `config::env_flags`):
        // this line is on the path of EVERY received datagram, and an
        // `env::var` here would take a process-wide lock per packet, on each
        // of the four listener threads.
        if crate::config::env_flags::interop_diagnostics() && len >= 20 {
            let mut scan_offset = 20usize;
            let mut submsg_ids: Vec<(usize, u8, u16)> = Vec::new();
            while scan_offset + 4 <= len {
                let sid = datagram[scan_offset];
                let sflags = datagram[scan_offset + 1];
                let sotn = if sflags & 0x01 != 0 {
                    u16::from_le_bytes([datagram[scan_offset + 2], datagram[scan_offset + 3]])
                } else {
                    u16::from_be_bytes([datagram[scan_offset + 2], datagram[scan_offset + 3]])
                };
                submsg_ids.push((scan_offset, sid, sotn));
                if sotn == 0 {
                    break;
                }
                scan_offset += 4 + sotn as usize;
            }
            let labels: Vec<String> = submsg_ids
                .iter()
                .map(|(off, id, otn)| {
                    let name = match id {
                        0x01 => "PAD",
                        0x06 => "ACKNACK",
                        0x07 => "HB",
                        0x08 => "GAP",
                        0x09 => "INFO_TS",
                        0x0c => "INFO_SRC",
                        0x0e => "INFO_DST",
                        0x0f => "INFO_REPLY",
                        0x12 => "NACK_FRAG",
                        0x13 => "HB_FRAG",
                        0x15 => "DATA",
                        0x16 => "DATA_FRAG",
                        0x80 => "VENDOR_80",
                        _ => "UNK",
                    };
                    format!("{}@{}({})", name, off, otn)
                })
                .collect();
            log::info!(
                "[DIAG] src={} classified={} len={} submessages=[{}]",
                origin.from(),
                kind_label,
                len,
                labels.join(", ")
            );
        }

        // Drop invalid packets
        if matches!(kind, PacketKind::Invalid) {
            metrics.packets_invalid.fetch_add(1, Ordering::Relaxed);
            return;
        }

        // Any RTPS message of a participant renews the liveliness of its
        // AUTOMATIC writers (DDS v1.4 Sec.2.2.3.11): once per message, not
        // per submessage.
        if let (Some(liveliness), Some(source)) = (
            self.liveliness.as_ref(),
            datagram
                .get(8..20)
                .and_then(|p| <&[u8; 12]>::try_from(p).ok()),
        ) {
            liveliness.heard_from(source);
        }

        // DDS-Security 1.1 submessage protection (SEC_PREFIX, SEC_BODY,
        // SEC_POSTFIX, Sec.7.3.6): nothing in it can be read before it is
        // decoded, so the classifier names no kind for it. Delivered here,
        // whatever else the datagram carries, and before the branches below
        // that return once they have handed a HEARTBEAT on. HDDS protects its
        // secure SEDP announcements this way, one per datagram
        // (`secure_sedp::protect_sedp_packet`): the discovery dispatch
        // decodes it with the sender's keys and reads it only when what it
        // protects is a DATA of a secure SEDP writer.
        #[cfg(feature = "security")]
        if let Some(at) =
            crate::security::crypto::secure_submessage::first_secure_prefix(&datagram[..len])
        {
            if let Some(callback) = discovery_callback.as_ref() {
                let callback_result =
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        callback(PacketKind::SecureSEDP, &datagram[..len], at, None, origin);
                    }));
                if callback_result.is_err() {
                    metrics.callback_errors.fetch_add(1, Ordering::Relaxed);
                }
            }

            // A datagram
            // carrying a secure envelope whose own visible DATA makes the
            // classifier elect a kind OTHER than AckNack (SecureSEDP, a
            // SIGNED SecureSEDP DATA's writer id being a secure one) can
            // still carry an independent CLEAR ACKNACK for an ordinary
            // (non-secure) local writer, outside that envelope -- `kind`
            // never becomes AckNack for it, so the `kind == PacketKind::
            // AckNack` branch below never runs, and this ACKNACK would be
            // silently lost. `parse_all_acknack_submessages` already
            // excludes whatever THIS envelope owns (`EnvelopeTracker`),
            // so it only ever finds a
            // genuinely separate clear ACKNACK here. Guarded on `kind !=
            // PacketKind::AckNack` so a datagram that DOES classify as
            // AckNack (an unprotected ACKNACK visible because nothing
            // else in it named a bigger kind, e.g. an ENCRYPTED envelope
            // whose DATA stays opaque) is delivered EXACTLY ONCE, by that
            // branch, not duplicated here.
            if kind != PacketKind::AckNack {
                if let Some(ref tx) = control_tx {
                    let independent_acknacks = parse_all_acknack_submessages(&datagram[..len]);
                    if !independent_acknacks.is_empty() {
                        let mut peer_guid_prefix = [0u8; 12];
                        if len >= 20 {
                            peer_guid_prefix.copy_from_slice(&datagram[8..20]);
                        }
                        for an_info in independent_acknacks {
                            if let Some(msg) = ControlMessage::acknack(
                                origin,
                                peer_guid_prefix,
                                an_info,
                                &datagram[..len],
                            ) {
                                if tx.try_send(msg).is_err() {
                                    log::debug!(
                                        "[MCAST-RX] control channel full, dropping an \
                                         independent ACKNACK riding alongside a secure \
                                         envelope from {}",
                                        origin.from()
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }

        // Two-Ring Architecture - dispatch HEARTBEAT/ACKNACK to control channel
        // When control_tx is available, these control packets bypass the pool and go
        // to a dedicated ControlHandler thread. This prevents pool exhaustion under
        // high HEARTBEAT/ACKNACK load (RELIABLE QoS).
        //
        // AckNack packets bypass the pool too: left in it they would saturate it
        // and starve the sample path
        if kind == PacketKind::Heartbeat {
            if let Some(ref tx) = control_tx {
                // Parse ALL heartbeat submessages from the packet.
                // A peer may bundle HBs for multiple writers (03C2, 04C2, 0200C2)
                // in one RTPS packet; taking only the first would silently drop
                // SEDP pub/sub HBs.
                //
                // ONE walk answers both this and the embedded-GAP extraction
                // below. A parser that returns the FIRST GAP only would make a
                // datagram carrying several GAPs yield a different set
                // depending on which submessage happened to come first in it.
                // Both collections are capped by the same constants inside the
                // scanner.
                //
                // The scan answers for NACK_FRAGs too: a writer that
                // announces what it holds while its reader asks for the
                // holes in a fragmented sample sends [HEARTBEAT, NACK_FRAG]
                // in one datagram, and neither half of the answer may be
                // thrown away.
                let (all_gaps, all_hbs, has_nack_frag) =
                    scan_all_embedded_control_submessages(&datagram[..len]);
                if has_nack_frag {
                    Self::dispatch_nack_frags(tx, origin, &datagram[..len]);
                }
                // A user writer's control also rides the ring with its datagram.
                user_controls_on_ring = all_hbs
                    .iter()
                    .any(|hb| user_writer(&hb.info.writer_entity_id))
                    || all_gaps
                        .iter()
                        .any(|gap| user_writer(&gap.info.writer_entity_id));

                if all_hbs.is_empty() {
                    if !user_controls_on_ring {
                        log::debug!(
                            "[MCAST-RX] Failed to parse HEARTBEAT from {}, len={}",
                            origin.from(),
                            len
                        );
                    }
                } else {
                    // Extract peer GUID prefix from RTPS header
                    let mut peer_guid_prefix = [0u8; 12];
                    if len >= 20 {
                        peer_guid_prefix.copy_from_slice(&datagram[8..20]);
                    }

                    log::debug!(
                        "[MCAST-RX] Parsed {} HEARTBEAT(s) from {} writers={:?}",
                        all_hbs.len(),
                        origin.from(),
                        all_hbs
                            .iter()
                            .map(|h| h.info.writer_entity_id)
                            .collect::<Vec<_>>()
                    );

                    for hb_info in all_hbs {
                        if let Some(msg) = ControlMessage::addressed_heartbeat(
                            origin,
                            peer_guid_prefix,
                            hb_info,
                            &datagram[..len],
                        ) {
                            // Non-blocking send - drop if channel full (HBs are idempotent)
                            if user_controls_on_ring {
                                deferred_controls.push(msg);
                            } else if tx.try_send(msg).is_err() {
                                log::debug!(
                                    "[MCAST-RX] Control channel full, dropping HEARTBEAT from {}",
                                    origin.from()
                                );
                            }
                        }
                    }
                }

                // Compound packet: a GAP commonly rides WITH the HEARTBEAT.
                // A message such as [INFO_DST, HEARTBEAT, GAP] is one RTPS message, so
                // `kind` resolves to Heartbeat and the standalone GAP branch below
                // never fires. Extract any embedded GAP here and forward it as its
                // own control message. RTPS 2.5 sec 8.3.8.4. The scan above
                // reads the whole packet, so order inside it does not matter,
                // and EVERY GAP it carries is forwarded -- a writer purging
                // several ranges in one datagram must not have all but the
                // first silently dropped, which would leave the reorder gate of
                // those writers waiting for sequences that will never come.
                if !all_gaps.is_empty() {
                    let mut gap_guid_prefix = [0u8; 12];
                    if len >= 20 {
                        gap_guid_prefix.copy_from_slice(&datagram[8..20]);
                    }
                    for gap_info in all_gaps {
                        if let Some(msg) = ControlMessage::addressed_gap(
                            origin,
                            gap_guid_prefix,
                            gap_info,
                            &datagram[..len],
                        ) {
                            if user_controls_on_ring {
                                deferred_controls.push(msg);
                            } else if tx.try_send(msg).is_err() {
                                metrics.packets_dropped.fetch_add(1, Ordering::Relaxed);
                                log::debug!(
                                    "[MCAST-RX] control channel full, dropping GAP from {}",
                                    origin.from()
                                );
                            }
                        }
                    }
                }

                // Nothing for the ring: no synchronous callback, no pool.
                if !user_controls_on_ring {
                    return;
                }
            }
            // No control_tx: fall through to legacy synchronous callback
        }

        // Parse and send ACKNACKs to control channel for SEDP response.
        //
        // A peer may send ACKNACKs asking for our publications (0x03c2).
        // We respond with a HEARTBEAT indicating "empty writer" (lastSeq=0),
        // which completes the SEDP handshake (DDSI-RTPS 2.5 Sec.8.3.8.6).
        //
        // Non-SEDP AckNack packets, which need no processing, bypass the pool too.
        if kind == PacketKind::AckNack {
            if let Some(ref tx) = control_tx {
                // Parse EVERY ACKNACK of the datagram and send them all to
                // the control channel. One ACKNACK names one (reader, writer)
                // pair, so a peer with several readers matched to several of
                // our writers sends a handful in one datagram; reading only
                // the first left every other writer named in it without a
                // repair request, and its reader NACKing the same sequences
                // forever -- with no counter and no log.
                let all_acknacks = parse_all_acknack_submessages(&datagram[..len]);
                if all_acknacks.is_empty() {
                    log::debug!(
                        "[MCAST-RX] no ACKNACK parsed from {} bytes from {}",
                        len,
                        origin.from()
                    );
                } else {
                    // Extract peer GUID prefix from RTPS header
                    let mut peer_guid_prefix = [0u8; 12];
                    if len >= 20 {
                        peer_guid_prefix.copy_from_slice(&datagram[8..20]);
                    }

                    for an_info in all_acknacks {
                        // Non-blocking send - drop if channel full (ACKNACKs can be retried)
                        log::debug!(
                            "[MCAST-RX] Sending ACKNACK to control channel: writer={:02x?} from {} ranges={}",
                            an_info.writer_entity_id,
                            origin.from(),
                            an_info.missing_ranges.len()
                        );
                        if let Some(msg) = ControlMessage::acknack(
                            origin,
                            peer_guid_prefix,
                            an_info,
                            &datagram[..len],
                        ) {
                            if tx.try_send(msg).is_err() {
                                log::debug!(
                                    "[MCAST-RX] Control channel full, dropping ACKNACK from {}",
                                    origin.from()
                                );
                            }
                        } else {
                            log::debug!(
                                "[MCAST-RX] ControlMessage::acknack returned None for ACKNACK from {}",
                                origin.from()
                            );
                        }
                    }
                }

                // Compound packet: NACK_FRAGs commonly ride WITH the
                // ACKNACK. A reader may bundle [INFO_DST, ACKNACK,
                // NACK_FRAG x N] in one RTPS message, so `kind`
                // resolves to AckNack and the standalone NackFrag
                // branch below never fires -- without this the fragment
                // retransmission requests would be silently dropped and
                // the writer-side selective retransmit would never run
                // (holes NACKed forever, the large sample never
                // completes). Mirror of the HEARTBEAT+GAP
                // compound handling above.
                Self::dispatch_nack_frags(tx, origin, &datagram[..len]);
                // Skip synchronous callback and pool for this ACKNACK
                return;
            }
            // No control_tx: fall through to pool-based processing
        }

        // Handle NACK_FRAG packets (fragment retransmission requests)
        if kind == PacketKind::NackFrag {
            if let Some(ref tx) = control_tx {
                // One packet may carry several NACK_FRAGs, split per-sample.
                Self::dispatch_nack_frags(tx, origin, &datagram[..len]);
                // Skip synchronous callback and pool for this NACK_FRAG
                return;
            }
            // No control_tx: fall through to pool-based processing
        }

        // Forward GAP submessages to the control channel so the
        // reorder gate can advance past writer-declared-irrelevant
        // sequences (RTPS v2.5 sec 8.3.8.4).  GAP is a pure control
        // message; it never carries user data, so it does NOT go into
        // the pool / ring -- always consumed here.
        if kind == PacketKind::Gap {
            if let Some(ref tx) = control_tx {
                // One walk for the GAPs, the embedded HEARTBEATs and the
                // NACK_FRAGs alike; see the Heartbeat-classified branch above
                // for why a first-GAP-only parser is not used.
                let (all_gaps, embedded_hbs, has_nack_frag) =
                    scan_all_embedded_control_submessages(&datagram[..len]);
                if has_nack_frag {
                    Self::dispatch_nack_frags(tx, origin, &datagram[..len]);
                }
                // A user writer's control also rides the ring with its datagram.
                user_controls_on_ring = all_gaps
                    .iter()
                    .any(|gap| user_writer(&gap.info.writer_entity_id))
                    || embedded_hbs
                        .iter()
                        .any(|hb| user_writer(&hb.info.writer_entity_id));

                if !all_gaps.is_empty() {
                    let mut peer_guid_prefix = [0u8; 12];
                    if len >= 20 {
                        peer_guid_prefix.copy_from_slice(&datagram[8..20]);
                    }
                    for gap_info in all_gaps {
                        if let Some(msg) = ControlMessage::addressed_gap(
                            origin,
                            peer_guid_prefix,
                            gap_info,
                            &datagram[..len],
                        ) {
                            if user_controls_on_ring {
                                deferred_controls.push(msg);
                            } else if tx.try_send(msg).is_err() {
                                log::debug!(
                                    "[MCAST-RX] Control channel full, dropping GAP from {}",
                                    origin.from()
                                );
                            }
                        }
                    }
                }

                // Compound packet: a HEARTBEAT commonly rides WITH the GAP.
                // Some vendors bundle [INFO_DST, GAP, HEARTBEAT] in one RTPS
                // message during durable (TRANSIENT_LOCAL+) history replay, so
                // `kind` resolves to Gap (first non-INFO submessage wins) and
                // the HEARTBEAT branch above never fires. Without the HEARTBEAT
                // the reader never answers with an ACKNACK, and a NACK-driven
                // durable writer never releases its history. Mirror of the
                // embedded-GAP extraction in the Heartbeat branch above.
                // RTPS v2.5 sec 8.3.3: submessages are independently valid.
                // Forwarded AFTER the GAP so the proxy folds the gap floor in
                // before the heartbeat computes the ACKNACK base.
                if !embedded_hbs.is_empty() {
                    let mut peer_guid_prefix = [0u8; 12];
                    if len >= 20 {
                        peer_guid_prefix.copy_from_slice(&datagram[8..20]);
                    }
                    for hb_info in embedded_hbs {
                        if let Some(msg) = ControlMessage::addressed_heartbeat(
                            origin,
                            peer_guid_prefix,
                            hb_info,
                            &datagram[..len],
                        ) {
                            if user_controls_on_ring {
                                deferred_controls.push(msg);
                            } else if tx.try_send(msg).is_err() {
                                log::debug!(
                                    "[MCAST-RX] Control channel full, dropping embedded HEARTBEAT from {}",
                                    origin.from()
                                );
                            }
                        }
                    }
                }
            }
            // A GAP carries no user payload: unless a user writer's control
            // rides the ring, skip the pool and the ring.
            if !user_controls_on_ring {
                return;
            }
        }

        // Compound DATA message control-submessage extraction
        //
        // RTPS allows multiple submessages in one packet, e.g.
        // [INFO_TS, DATA, HEARTBEAT] or [GAP, INFO_TS, DATA] in a single
        // RTPS message. The classifier
        // breaks early after finding DATA (octets_to_next > 100), so
        // `kind` is PacketKind::Data and neither the HEARTBEAT nor the
        // GAP dispatch blocks above are ever reached.
        //
        // When the packet is classified as DATA (not
        // Heartbeat/AckNack/NackFrag), also scan for embedded
        // HEARTBEATs, GAPs, and NACK_FRAGs in one pass, then dispatch
        // them to the control channel. Without the GAP side, a reader
        // that only ever sees a writer's purge-GAP in compound form never
        // advances its reorder gate; a TRANSIENT_LOCAL late-joiner then
        // waits for the next HEARTBEAT to unstick. GAP is
        // forwarded unconditionally, same as the standalone-GAP branch
        // above -- control.rs filters SEDP writer GAPs itself
        // (is_sedp_endpoint), so no filtering is duplicated here.
        if !matches!(
            kind,
            PacketKind::Heartbeat | PacketKind::AckNack | PacketKind::NackFrag | PacketKind::Gap
        ) {
            if let Some(ref tx) = control_tx {
                let (embedded_gaps, embedded_hbs, has_embedded_nack_frag) =
                    scan_all_embedded_control_submessages(&datagram[..len]);
                // A DATA or DATA_FRAG rides the ring: the Router applies the user
                // writers' controls behind it (`control::applies_gate_on_control`).
                let data_rides_ring = matches!(kind, PacketKind::Data | PacketKind::DataFrag);
                datagram_has_controls = !(embedded_gaps.is_empty() && embedded_hbs.is_empty());
                control_only_ring = !data_rides_ring
                    && (embedded_gaps
                        .iter()
                        .any(|gap| user_writer(&gap.info.writer_entity_id))
                        || embedded_hbs
                            .iter()
                            .any(|hb| user_writer(&hb.info.writer_entity_id)));

                if !embedded_gaps.is_empty() || !embedded_hbs.is_empty() || has_embedded_nack_frag {
                    let mut peer_guid_prefix = [0u8; 12];
                    if len >= 20 {
                        peer_guid_prefix.copy_from_slice(&datagram[8..20]);
                    }

                    for gap_info in embedded_gaps {
                        log::debug!(
                            "[MCAST-RX] Compound msg: extracted embedded GAP from {:?} packet, writer={:02x?} gap_start={} gap_list_base={}",
                            kind,
                            gap_info.info.writer_entity_id,
                            gap_info.info.gap_start,
                            gap_info.info.gap_list_base
                        );

                        if let Some(msg) = ControlMessage::addressed_gap(
                            origin,
                            peer_guid_prefix,
                            gap_info,
                            &datagram[..len],
                        ) {
                            if data_rides_ring || control_only_ring {
                                deferred_controls.push(msg);
                            } else if tx.try_send(msg).is_err() {
                                metrics.packets_dropped.fetch_add(1, Ordering::Relaxed);
                                log::debug!(
                                    "[MCAST-RX] Control channel full, dropping embedded GAP from {}",
                                    origin.from()
                                );
                            }
                        }
                    }

                    if has_embedded_nack_frag {
                        Self::dispatch_nack_frags(tx, origin, &datagram[..len]);
                    }

                    if !embedded_hbs.is_empty() {
                        log::debug!(
                            "[MCAST-RX] Compound msg: extracted {} embedded HEARTBEAT(s) from {:?} packet, writers={:?}",
                            embedded_hbs.len(),
                            kind,
                            embedded_hbs.iter().map(|h| h.info.writer_entity_id).collect::<Vec<_>>()
                        );

                        for hb_info in embedded_hbs {
                            if let Some(msg) = ControlMessage::addressed_heartbeat(
                                origin,
                                peer_guid_prefix,
                                hb_info,
                                &datagram[..len],
                            ) {
                                if data_rides_ring || control_only_ring {
                                    deferred_controls.push(msg);
                                } else if tx.try_send(msg).is_err() {
                                    metrics.packets_dropped.fetch_add(1, Ordering::Relaxed);
                                    log::debug!(
                                        "[MCAST-RX] Control channel full, dropping embedded HEARTBEAT from {}",
                                        origin.from()
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }

        // Invoke discovery callback for discovery packets (DATA/DATA_FRAG/SPDP/SEDP/TYPE_LOOKUP/Heartbeat)
        // SPDP announcements may arrive as DATA_FRAG; SEDP comes from builtin writers.
        // Also invoked for HEARTBEAT to enable SEDP NACK responses
        // Callback processes discovery synchronously before ring push
        // Panic boundary to prevent callback failures from killing listener thread
        // HEARTBEATs with control_tx are handled above, skip here
        if !user_controls_on_ring && wants_discovery_callback(kind) {
            if let Some(ref callback) = discovery_callback {
                if crate::config::env_flags::interop_diagnostics() {
                    let head_len = len.min(16);
                    log::debug!(
                        "[MCAST-RX] kind={} len={} src={} head={:02x?}",
                        kind_label,
                        len,
                        origin.from(),
                        &datagram[..head_len]
                    );
                }
                // Deliver ONE discovery submessage, behind the panic
                // boundary that keeps a bad handler from killing the
                // listener thread (v0.4.0+).
                let full_packet = &datagram[..len];
                let deliver = |kind: PacketKind, offset: usize, frag: Option<FragmentMetadata>| {
                    if len < offset {
                        log::debug!(
                            "[hdds-mcast-rx] {:?} payload at offset {} is past the {}-byte datagram",
                            kind,
                            offset,
                            len
                        );
                        return;
                    }

                    // The callback receives the FULL RTPS packet (the
                    // DialectDetector needs the header) plus the offset its
                    // CDR starts at.
                    log::debug!(
                        "[callback] delivering {:?}, len={}, cdr_offset={}",
                        kind,
                        len,
                        offset
                    );

                    let callback_result =
                        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            callback(kind, full_packet, offset, frag, origin);
                        }));

                    if let Err(e) = callback_result {
                        metrics.callback_errors.fetch_add(1, Ordering::Relaxed);
                        log::debug!(
                            "[hdds-mcast-rx:{}] Discovery callback panicked: {:?}",
                            std::process::id(),
                            e
                        );
                        // Continue processing, don't crash listener thread
                    }
                };

                // DATA_FRAG and HEARTBEAT go out as the classifier saw them:
                // one per datagram, carrying the fragment metadata it
                // extracted. Their payload offset can be absent, and then
                // the legacy fallback applies -- 20 (RTPS header) + 24 (DATA
                // submessage header); a value 4 bytes short would read the tail
                // of writerSeqNum as encapsulation.
                //
                // Stateless/SecureSEDP/SecureVolatile sit on DATA submessages
                // and are delivered by the walk below with an offset computed
                // from their own header, so nothing reaches this line with a
                // guessed offset for them.
                //
                // The test is `fragment_metadata.is_some()`, not `kind ==
                // DataFrag`, because a DATA_FRAG is named by the writer that
                // sent it: `classify_data_frag` answers SPDP or SEDP for the
                // three builtin discovery writers, so a FRAGMENTED
                // announcement never carries the DataFrag kind. Testing the
                // kind alone would deliver it to nobody - the walk below only
                // visits DATA (0x15) - and lose every fragmented SPDP and
                // SEDP announcement on this path. The classifier publishes
                // fragment metadata exactly when it saw a DATA_FRAG, so that
                // is the question to ask.
                const LEGACY_RTPS_DATA_PAYLOAD_OFFSET: usize = 44;
                if fragment_metadata.is_some()
                    || matches!(kind, PacketKind::DataFrag | PacketKind::Heartbeat)
                {
                    deliver(
                        kind,
                        payload_offset.unwrap_or(LEGACY_RTPS_DATA_PAYLOAD_OFFSET),
                        fragment_metadata,
                    );
                }

                // Then every DATA submessage the datagram carries, in wire
                // order, each with its own payload offset.
                //
                // The classification above names the datagram with ONE kind
                // and ONE offset, which is what the ring push below needs.
                // Discovery needs all of them: RTPS v2.5 Sec.8.3.3 lets a
                // message bundle as many DATA as fit, e.g. an SPDP with two
                // SEDP announcements in one datagram. Delivering only the
                // elected one would drop the others without a trace.
                let mut data_seen = 0usize;
                for_each_data_submessage(full_packet, |data| {
                    if wants_discovery_callback(data.kind) {
                        data_seen += 1;
                        deliver(data.kind, data.payload_offset, None);
                    }
                });
                if data_seen > 1 {
                    log::debug!(
                        "[MCAST-RX] compound datagram from {} delivered {} DATA submessages",
                        origin.from(),
                        data_seen
                    );
                }
            }
        }

        // Only process relevant packet types for ring buffer. The ring comes
        // first: the controls that wait for it are sent after, riding the
        // datagram only if it went in. A refused datagram leaves its controls to
        // the control thread, which applies them (`control::applies_gate_on_control`).
        let ringed = 'ring: {
            let ring_kind = if control_only_ring {
                PacketKind::Heartbeat
            } else {
                kind
            };
            if !control_only_ring {
                // SPDP/SEDP are handled by the discovery callback above, not the ring.
                if !(matches!(
                    kind,
                    PacketKind::Data
                        | PacketKind::DataFrag
                        | PacketKind::Heartbeat
                        | PacketKind::HeartbeatFrag
                        | PacketKind::AckNack
                        | PacketKind::SPDP
                        | PacketKind::SEDP
                ) || (kind == PacketKind::Gap && user_controls_on_ring))
                {
                    break 'ring false;
                }
                if matches!(kind, PacketKind::SPDP | PacketKind::SEDP) {
                    break 'ring false;
                }
            }

            // Acquire buffer from pool
            let buffer_id = match pool.acquire_for_listener() {
                Some(id) => id,
                None => {
                    // Pool exhausted
                    metrics.packets_dropped.fetch_add(1, Ordering::Relaxed);
                    log::debug!(
                        "[hdds-mcast-rx] Pool exhausted, dropping {:?} packet ({} bytes)",
                        kind,
                        len
                    );
                    break 'ring false;
                }
            };

            // Copy packet to pool buffer
            // SAFETY: buffer_id is valid (just acquired), no concurrent access
            unsafe {
                let pool_ptr = Arc::as_ptr(pool);
                let buf = (*pool_ptr.cast_mut()).get_buffer_mut(buffer_id);
                buf[..len].copy_from_slice(&datagram[..len]);
            }

            // Build metadata (including payload offset / fragment info when available)
            let mut meta = if let Some(offset) = payload_offset {
                if let Some(frag_meta) = fragment_metadata {
                    RxMeta::new_with_fragment(origin, len, ring_kind, offset, frag_meta)
                } else {
                    RxMeta::new_with_offset(origin, len, ring_kind, offset)
                }
            } else {
                RxMeta::new(origin, len, ring_kind)
            };
            // Apply accumulated RTPS context from INFO_DST/INFO_TS submessages
            meta.rtps_context = rtps_context;
            // The controls of this datagram go to the control thread, when there
            // is one, and it answers them (`engine::writer_control`).
            meta.control_answers = control_tx.is_some();
            meta.controls_may_ride = datagram_has_controls;

            // Log RTPS context propagation when non-empty (avoid unwrap in hot path)
            if let Some(dest_prefix) = rtps_context.destination_guid_prefix {
                log::debug!(
                    "[RTPS-CONTEXT] Applied INFO_DST: dest_prefix={:02x?}",
                    dest_prefix
                );
            }
            if let Some((sec, frac)) = rtps_context.source_timestamp {
                log::debug!(
                    "[RTPS-CONTEXT] Applied INFO_TS: timestamp=({}, {})",
                    sec,
                    frac
                );
            }

            // Push to ring (non-blocking)
            if ring.push((meta, buffer_id)).is_err() {
                // Ring full, release buffer to avoid leak
                if let Err(e) = pool.release(buffer_id) {
                    log::debug!(
                        "[hdds-mcast-rx] CRITICAL: Failed to release buffer {}: {}",
                        buffer_id,
                        e
                    );
                }
                metrics.packets_dropped.fetch_add(1, Ordering::Relaxed);
                log::debug!("[hdds-mcast-rx] Ring full, dropping {:?} packet", kind);
                break 'ring false;
            }
            // Always notify to ensure router wakes from idle
            // The spin loop in router catches most hot traffic before condvar
            if let Some(ref n) = notifier {
                n.notify();
            }
            true
        };

        // The controls that waited for the ring: riding it if it went in. When it
        // did not, the control thread applies them (counted above as dropped).
        if let Some(ref tx) = control_tx {
            if !ringed && !deferred_controls.is_empty() {
                log::debug!(
                    "[MCAST-RX] {:?} from {} not ringed: its controls go to the control thread",
                    kind,
                    origin.from()
                );
            }
            for msg in deferred_controls {
                if tx.try_send(msg.riding_ring(ringed)).is_err() {
                    metrics.packets_dropped.fetch_add(1, Ordering::Relaxed);
                    log::debug!(
                        "[MCAST-RX] control channel full, dropping a control message from {}",
                        origin.from()
                    );
                }
            }
        }
    }
}

impl MulticastListener {
    /// Wake the listener thread so it re-reads `running`.
    fn wake(&self) {
        if let Err(e) = self.waker.wake() {
            log::warn!(
                "[MCAST-THREAD] could not wake the listener for shutdown: {}",
                e
            );
        }
    }
}

impl Drop for MulticastListener {
    fn drop(&mut self) {
        // Signal the listener thread to stop
        self.running.store(false, Ordering::Relaxed);
        self.wake();
        // Join the thread to ensure clean shutdown
        if let Some(handle) = self.handle.take() {
            crate::core::rt::shutdown::join_bounded(handle, "multicast listener");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::UdpTransport;
    use std::thread;
    use std::time::{Duration, Instant};

    /// Only the two ICMP-report kinds keep the drain loop going; an empty
    /// socket and any other error still end it.
    #[test]
    fn only_a_peer_unreachable_report_keeps_the_drain_going() {
        for kind in [
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::ConnectionRefused,
        ] {
            assert!(is_peer_unreachable_report(&io::Error::from(kind)));
        }
        for kind in [
            io::ErrorKind::WouldBlock,
            io::ErrorKind::Interrupted,
            io::ErrorKind::InvalidInput,
            io::ErrorKind::Other,
        ] {
            assert!(!is_peer_unreachable_report(&io::Error::from(kind)));
        }
    }

    /// A minimal well-formed RTPS message carrying one user DATA submessage.
    ///
    /// Built from DDS-RTPS v2.5, not from whatever the classifier happens to
    /// accept: a 20-byte Header (s8.3.3) - magic, ProtocolVersion, vendorId,
    /// guidPrefix - then at offset 20 a Data submessage (s8.3.8.2) whose
    /// writerId is a user-defined entity, so the packet is user data rather
    /// than one of the builtin discovery kinds.
    ///
    /// The message must be at least 24 bytes and carry a ProtocolVersion the
    /// major-version gate admits (DDS-RTPS v2.5 s8.6), with its submessage id
    /// at offset 20 rather than inside the guidPrefix: anything shorter or
    /// older cannot reach the ring.
    fn user_data_datagram() -> Vec<u8> {
        // A user-defined writer with key, so the classifier reports user data
        // rather than one of the builtin discovery kinds.
        data_datagram_from([0x00, 0x00, 0x01, 0x02])
    }

    /// The same message, attributed to `writer_id`.
    ///
    /// The writer entity id is what tells SPDP from SEDP from user data
    /// (DDS-RTPS v2.5 s9.3.1.2, Table 9.10), so it is the only thing a test
    /// needs to vary to reach a different branch of the dispatch.
    fn data_datagram_from(writer_id: [u8; 4]) -> Vec<u8> {
        use crate::core::rtps_constants::{RTPS_VERSION_MAJOR, RTPS_VERSION_MINOR};
        use crate::protocol::constants::HDDS_VENDOR_ID;

        let mut packet = Vec::with_capacity(48);
        // Header, DDS-RTPS v2.5 s8.3.3
        packet.extend_from_slice(b"RTPS");
        packet.push(RTPS_VERSION_MAJOR);
        packet.push(RTPS_VERSION_MINOR);
        packet.extend_from_slice(&HDDS_VENDOR_ID);
        packet.extend_from_slice(&[0x0A; 12]);
        // SubmessageHeader, s8.3.3.3: id, flags (E set = little-endian),
        // octetsToNextHeader = the Data submessage below. Declaring 24 for
        // a 20-octet body would be harmless while nothing follows
        // it (the walk simply runs off the end), but fatal the moment a test
        // appends a second submessage, because the DATA then swallows the
        // first four octets of its header. So the length is computed and
        // asserted rather than written by hand.
        packet.push(0x15);
        packet.push(0x01);
        let declared = packet.len();
        packet.extend_from_slice(&0u16.to_le_bytes()); // placeholder
        let body_start = packet.len();
        // Data submessage, s8.3.8.2
        packet.extend_from_slice(&0u16.to_le_bytes()); // extraFlags
        packet.extend_from_slice(&16u16.to_le_bytes()); // octetsToInlineQos
        packet.extend_from_slice(&[0x00, 0x00, 0x01, 0x07]); // readerId, user-defined with key
        packet.extend_from_slice(&writer_id);
        packet.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 1]); // writerSN = 1
        let body = packet.len() - body_start;
        assert_eq!(
            body, 20,
            "a DATA with neither inlineQos nor serializedPayload is 20 octets (s8.3.8.2)"
        );
        packet[declared..declared + 2].copy_from_slice(
            &u16::try_from(body)
                .expect("the fixture's DATA body fits octetsToNextHeader")
                .to_le_bytes(),
        );
        packet
    }

    /// Re-send `payload` until `done` says the listener acted on it.
    ///
    /// The thread drains its socket buffer once at startup (to discard
    /// what a killed process left behind), so a datagram sent before that
    /// drain is legitimately swallowed - and there is no readiness signal to
    /// wait on. A fixed sleep is a guess about one machine's scheduling, which
    /// makes a test flaky. This asserts on the OUTCOME within a deadline
    /// instead of on the timing.
    fn send_until(
        sender: &UdpSocket,
        destination: &str,
        payload: &[u8],
        done: impl Fn() -> bool,
    ) -> bool {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            sender
                .send_to(payload, destination)
                .expect("the sending socket accepts the datagram");
            let retry_at = Instant::now() + Duration::from_millis(50);
            while Instant::now() < retry_at {
                if done() {
                    return true;
                }
                thread::sleep(Duration::from_millis(2));
            }
        }
        false
    }

    /// A listener transport on a port pair nobody else on the box holds.
    ///
    /// `with_port` binds TWO sockets: the multicast one on `port`, and a
    /// unicast metatraffic one on `port + 10`. So port 0 is not an option -
    /// the kernel could pick a port whose +10 is someone else's, or
    /// privileged. And the multicast socket sets SO_REUSEADDR, so
    /// it would cheerfully share a port another process is already listening
    /// on and let the kernel decide which of the two gets our datagrams. The
    /// exclusive bind below is what makes the port actually ours; the atomic
    /// cursor keeps two tests in the same binary from racing for it.
    /// `with_port` is deprecated in favour of `new` plus a `PortMapping`, and
    /// that is the right call for a participant: the mapping is how RTPS
    /// derives its ports from the domain. A test does not want a domain's
    /// ports, it wants one nobody else holds - which is the whole point of the
    /// search below. The allow is scoped to this function and to that reason.
    #[allow(deprecated)]
    fn transport_on_a_free_port() -> UdpTransport {
        use std::sync::atomic::{AtomicU16, Ordering};
        static NEXT_PORT: AtomicU16 = AtomicU16::new(24000);

        for _ in 0..64 {
            let port = NEXT_PORT.fetch_add(20, Ordering::Relaxed);
            if UdpSocket::bind(("0.0.0.0", port)).is_err() {
                continue;
            }
            if UdpSocket::bind(("0.0.0.0", port + 10)).is_err() {
                continue;
            }
            if let Ok(transport) = UdpTransport::with_port(port) {
                return transport;
            }
        }
        panic!("no free port pair for the listener under test");
    }

    /// The loopback address and the port the listener is bound to.
    fn destination_of(transport: &UdpTransport) -> String {
        let bound = transport
            .socket()
            .local_addr()
            .expect("the listening socket is bound");
        format!("127.0.0.1:{}", bound.port())
    }

    /// A datagram that arrives on the socket reaches the ring, classified.
    ///
    /// The only test in the tree that exercises the listener end to end -
    /// socket, thread, classifier, pool, ring - which is why it is worth
    /// keeping honest rather than ignoring.
    #[test]
    #[allow(deprecated)]
    fn a_datagram_on_the_socket_reaches_the_ring() {
        let pool = Arc::new(RxPool::new(16, 1500).expect("Pool creation should succeed"));
        let ring = Arc::new(ArrayQueue::new(256));

        let transport = transport_on_a_free_port();
        let destination = destination_of(&transport);

        let listener = MulticastListener::spawn(
            transport.socket(),
            Arc::clone(&pool),
            Arc::clone(&ring),
            None, // No discovery callback for this test
        )
        .expect("Listener spawn should succeed");

        let sender = UdpSocket::bind("0.0.0.0:0").expect("Socket bind should succeed");
        let datagram = user_data_datagram();
        assert!(
            send_until(&sender, &destination, &datagram, || !ring.is_empty()),
            "a well-formed user DATA datagram must reach the ring"
        );

        let (meta, buffer_id) = ring.pop().expect("the ring is not empty");
        assert_eq!(meta.kind, PacketKind::Data);
        let expected_len = u16::try_from(datagram.len()).expect("len should fit in u16");
        assert_eq!(meta.len, expected_len, "the whole datagram is kept");
        pool.release(buffer_id).expect("release should succeed");

        let (rx, dropped, invalid, bytes, callback_errors) = listener.metrics.snapshot();
        assert!(rx >= 1);
        assert_eq!(dropped, 0, "a 256-slot ring drops nothing here");
        assert_eq!(callback_errors, 0);
        assert_eq!(invalid, 0, "the datagram is well-formed per DDS-RTPS v2.5");
        assert!(bytes >= datagram.len() as u64);

        // The retry loop may have delivered more than one copy.
        while let Some((_, id)) = ring.pop() {
            pool.release(id).expect("release should succeed");
        }
        listener.shutdown();
    }

    /// Shutdown is a wake, not a timeout: a listener idle on its socket
    /// stops at once instead of after a wait runs out.
    #[test]
    #[allow(deprecated)]
    fn an_idle_listener_stops_at_once_on_shutdown() {
        let pool = Arc::new(RxPool::new(4, 1500).expect("Pool creation should succeed"));
        let ring = Arc::new(ArrayQueue::new(4));
        let transport = transport_on_a_free_port();
        let listener = MulticastListener::spawn(transport.socket(), pool, ring, None)
            .expect("Listener spawn should succeed");

        thread::sleep(Duration::from_millis(50));
        let started = std::time::Instant::now();
        listener.shutdown();
        let stopped_in = started.elapsed();
        assert!(
            stopped_in < Duration::from_millis(500),
            "an idle listener took {stopped_in:?} to stop; shutdown must wake it"
        );
    }

    /// A full ring drops the datagram and gives its buffer back.
    ///
    /// ANSSI pattern 4. What matters is not the drop - a bounded ring must
    /// drop - it is that the buffer taken from the pool on the way in comes
    /// back. A leak here starves the receive path silently, one packet at a
    /// time, and only under the load that made the ring full in the first
    /// place.
    #[test]
    #[allow(deprecated)]
    fn a_full_ring_drops_the_datagram_and_releases_its_buffer() -> Result<(), String> {
        const CAPACITY: usize = 4;

        let pool = Arc::new(RxPool::new(16, 1500).expect("Pool creation should succeed"));
        let ring = Arc::new(ArrayQueue::new(CAPACITY));

        let transport = transport_on_a_free_port();
        let destination = destination_of(&transport);

        let listener = MulticastListener::spawn(
            transport.socket(),
            Arc::clone(&pool),
            Arc::clone(&ring),
            None, // No callback for this test
        )
        .map_err(|e| format!("Failed to spawn listener: {}", e))?;

        let sender =
            UdpSocket::bind("0.0.0.0:0").map_err(|e| format!("Failed to bind sender: {}", e))?;
        let datagram = user_data_datagram();

        // The thread is up once one datagram has been through it.
        if !send_until(&sender, &destination, &datagram, || !ring.is_empty()) {
            return Err("the listener never took a datagram".to_string());
        }
        // Let whatever the retry loop put in flight land, then start clean.
        thread::sleep(Duration::from_millis(100));
        while let Some((_, id)) = ring.pop() {
            pool.release(id).map_err(|e| format!("release: {}", e))?;
        }

        for _ in 0..CAPACITY {
            let target = ring.len() + 1;
            if !send_until(&sender, &destination, &datagram, || ring.len() >= target) {
                return Err(format!("the ring stopped filling at {}", ring.len()));
            }
        }
        thread::sleep(Duration::from_millis(100));
        if ring.len() != CAPACITY {
            return Err(format!(
                "Ring should be full ({}), got {}",
                CAPACITY,
                ring.len()
            ));
        }

        // Counted here, AFTER the fill: the tail of the fill drops packets of
        // its own, and counting before would credit them to the next step.
        let (_, dropped_before, _, _, _) = listener.metrics.snapshot();
        let spare = pool
            .acquire_for_listener()
            .ok_or("Pool should have free buffers before the extra datagram")?;
        pool.release(spare).map_err(|e| format!("release: {}", e))?;

        if !send_until(&sender, &destination, &datagram, || {
            listener.metrics.snapshot().1 > dropped_before
        }) {
            return Err("the extra datagram was neither queued nor counted as dropped".to_string());
        }
        if ring.len() != CAPACITY {
            return Err(format!(
                "Ring should still hold {} (the extra datagram is dropped), got {}",
                CAPACITY,
                ring.len()
            ));
        }

        let recovered = pool
            .acquire_for_listener()
            .ok_or("the dropped datagram's buffer never came back to the pool")?;
        pool.release(recovered)
            .map_err(|e| format!("release: {}", e))?;

        while let Some((_, id)) = ring.pop() {
            pool.release(id).map_err(|e| format!("release: {}", e))?;
        }
        listener.shutdown();
        Ok(())
    }

    /// A HEARTBEAT message from a user-defined writer.
    ///
    /// DDS-RTPS v2.5 s8.3.8.6: readerId, writerId, firstSN, lastSN, count -
    /// 28 bytes after the submessage header. SequenceNumber_t is a high i32
    /// then a low u32 (s8.3.5.4), which is why 1 is not eight zero bytes.
    fn heartbeat_datagram() -> Vec<u8> {
        use crate::core::rtps_constants::{RTPS_VERSION_MAJOR, RTPS_VERSION_MINOR};
        use crate::protocol::constants::HDDS_VENDOR_ID;

        let mut packet = Vec::with_capacity(52);
        packet.extend_from_slice(b"RTPS");
        packet.push(RTPS_VERSION_MAJOR);
        packet.push(RTPS_VERSION_MINOR);
        packet.extend_from_slice(&HDDS_VENDOR_ID);
        packet.extend_from_slice(&[0x0A; 12]);
        packet.push(0x07); // HEARTBEAT
        packet.push(0x01); // E flag: little-endian
        packet.extend_from_slice(&28u16.to_le_bytes());
        packet.extend_from_slice(&[0x00, 0x00, 0x01, 0x07]); // readerId
        packet.extend_from_slice(&[0x00, 0x00, 0x01, 0x02]); // writerId
        packet.extend_from_slice(&0i32.to_le_bytes()); // firstSN high
        packet.extend_from_slice(&1u32.to_le_bytes()); // firstSN low
        packet.extend_from_slice(&0i32.to_le_bytes()); // lastSN high
        packet.extend_from_slice(&1u32.to_le_bytes()); // lastSN low
        packet.extend_from_slice(&1i32.to_le_bytes()); // count
        packet
    }

    /// Where the relay will inject from: a synthetic locator, never a real
    /// interface address. Using one here proves the dispatch takes the source
    /// address it is handed and does not re-derive it from a socket.
    fn synthetic_source() -> SocketAddr {
        "240.0.0.5:7400".parse().expect("a literal address parses")
    }

    /// A HEARTBEAT submessage (s8.3.8.6) addressed to `reader`.
    fn heartbeat_to(reader: [u8; 4]) -> Vec<u8> {
        let mut sub = vec![0x07, 0x01];
        sub.extend_from_slice(&28u16.to_le_bytes());
        sub.extend_from_slice(&reader);
        sub.extend_from_slice(&[0x00, 0x00, 0x01, 0x02]); // writerId
        sub.extend_from_slice(&0i32.to_le_bytes());
        sub.extend_from_slice(&1u32.to_le_bytes()); // firstSN 1
        sub.extend_from_slice(&0i32.to_le_bytes());
        sub.extend_from_slice(&3u32.to_le_bytes()); // lastSN 3
        sub.extend_from_slice(&1i32.to_le_bytes()); // count
        sub
    }

    /// A GAP submessage (s8.3.8.4) addressed to `reader`: gapStart 1,
    /// gapList.base 2, empty bitmap.
    fn gap_to(reader: [u8; 4]) -> Vec<u8> {
        let mut sub = vec![0x08, 0x01];
        sub.extend_from_slice(&28u16.to_le_bytes());
        sub.extend_from_slice(&reader);
        sub.extend_from_slice(&[0x00, 0x00, 0x01, 0x02]); // writerId
        sub.extend_from_slice(&0i32.to_le_bytes());
        sub.extend_from_slice(&1u32.to_le_bytes()); // gapStart 1
        sub.extend_from_slice(&0i32.to_le_bytes());
        sub.extend_from_slice(&2u32.to_le_bytes()); // gapList.base 2
        sub.extend_from_slice(&0u32.to_le_bytes()); // numBits 0
        sub
    }

    /// An ACKNACK submessage (s8.3.8.1) naming `writer`, empty bitmap
    /// (a pure ack of sequence 1).
    #[cfg(feature = "security")]
    fn acknack_to(writer: [u8; 4]) -> Vec<u8> {
        let mut sub = vec![0x06, 0x01];
        sub.extend_from_slice(&24u16.to_le_bytes());
        sub.extend_from_slice(&[0x00, 0x00, 0x01, 0x07]); // readerId, arbitrary user reader
        sub.extend_from_slice(&writer);
        sub.extend_from_slice(&0i32.to_le_bytes());
        sub.extend_from_slice(&1u32.to_le_bytes()); // bitmapBase = 1
        sub.extend_from_slice(&0u32.to_le_bytes()); // numBits = 0
        sub.extend_from_slice(&1i32.to_le_bytes()); // count
        sub
    }

    /// The RTPS header of `user_data_datagram` followed by `submessages`.
    fn datagram_of(submessages: &[Vec<u8>]) -> Vec<u8> {
        let mut packet = user_data_datagram()[..20].to_vec();
        for sub in submessages {
            packet.extend_from_slice(sub);
        }
        packet
    }

    /// Every HEARTBEAT and GAP reaches the control thread with the reader
    /// its readerId addresses (s8.3.8.4, s8.3.8.6), whichever kind the
    /// datagram is classified as: the three forwarding branches of the
    /// dispatch each carry it.
    #[test]
    fn heartbeats_and_gaps_reach_control_with_the_reader_they_address() {
        const R1: [u8; 4] = [0x00, 0x00, 0x05, 0x07];
        const R2: [u8; 4] = [0x00, 0x00, 0x06, 0x07];
        let mut with_data = user_data_datagram();
        with_data.extend_from_slice(&heartbeat_to(R1));
        with_data.extend_from_slice(&gap_to(R2));
        let datagrams = [
            (
                "heartbeat first",
                datagram_of(&[heartbeat_to(R1), gap_to(R2)]),
            ),
            ("gap first", datagram_of(&[gap_to(R2), heartbeat_to(R1)])),
            ("behind a DATA", with_data),
        ];
        for (shape, datagram) in datagrams {
            let w = wiring(8);
            w.dispatch.dispatch(&datagram, synthetic_source());
            let mut seen = Vec::new();
            while let Ok(msg) = w.control.try_recv() {
                seen.push((msg.kind, msg.reader_entity_id()));
            }
            while let Some((_, buffer_id)) = w.ring.pop() {
                w.pool.release(buffer_id).expect("release should succeed");
            }
            assert!(
                seen.contains(&(
                    super::super::control_types::ControlMessageKind::Heartbeat,
                    R1
                )),
                "{shape}: {seen:?}"
            );
            assert!(
                seen.contains(&(super::super::control_types::ControlMessageKind::Gap, R2)),
                "{shape}: {seen:?}"
            );
        }
    }

    /// In a datagram carrying a
    /// SIGNED SecureSEDP DATA (visible plaintext under AES256_GMAC, its
    /// writer id one of the secure SEDP writers, so the classifier elects
    /// `SecureSEDP` for the WHOLE datagram) and, outside that envelope, a
    /// CLEAR ACKNACK for an ordinary (non-secure) local writer, the ACKNACK
    /// must still reach the control channel: `kind` never becomes `AckNack` for this
    /// datagram, so the dedicated `kind == PacketKind::AckNack` branch
    /// never runs, and the general embedded-control scan (GAP/HEARTBEAT/
    /// NACK_FRAG) does not look for ACKNACK either.
    ///
    /// The scan inside the secure-prefix block is what delivers it, and its
    /// `kind != PacketKind::AckNack` guard is what keeps a datagram that DOES
    /// classify as AckNack from being delivered twice; this test pins both.
    #[cfg(feature = "security")]
    #[test]
    fn an_independent_clear_acknack_after_a_signed_secure_sedp_data_is_delivered_once() {
        use crate::core::rtps_constants::RTPS_ENTITYID_SEDP_PUBLICATIONS_SECURE_WRITER;
        use crate::security::crypto::secure_submessage::{
            encode_datawriter_submessage, Transformation, WriterKeyMaterial,
        };

        let plain = data_datagram_from(RTPS_ENTITYID_SEDP_PUBLICATIONS_SECURE_WRITER);
        let sub = plain[20..].to_vec();
        let material = WriterKeyMaterial::new([0x11; 32], [0x22; 32], [0, 0, 1, 1])
            .with_transformation(Transformation::Aes256Gmac);
        let protected = encode_datawriter_submessage(&material, &sub).expect("protect");

        let ordinary_writer = [0x00, 0x00, 0x01, 0x02];
        let mut datagram = plain[..20].to_vec();
        datagram.extend_from_slice(&protected);
        datagram.extend_from_slice(&acknack_to(ordinary_writer));

        let (kind, _, _, _) = classify_rtps(&datagram);
        assert_eq!(
            kind,
            PacketKind::SecureSEDP,
            "fixture: the classifier must elect SecureSEDP from the visible signed DATA, \
             never AckNack, for this to exercise the reported routing gap"
        );

        let w = wiring(8);
        w.dispatch.dispatch(&datagram, synthetic_source());

        let mut seen = Vec::new();
        while let Ok(msg) = w.control.try_recv() {
            seen.push(msg.kind);
        }
        let acknacks = seen
            .iter()
            .filter(|k| **k == super::super::control_types::ControlMessageKind::AckNack)
            .count();
        assert_eq!(
            acknacks, 1,
            "the independent clear ACKNACK must reach the control channel exactly once: {seen:?}"
        );
    }

    /// A single valid signed SecureSEDP DATA first succeeds through the
    /// secure-prefix callback. The listener must not then enumerate that same
    /// visible DATA and call discovery again with its CDR offset (SIGN cannot
    /// satisfy NONE, so opening would fail and `secure_sedp_undecodable`
    /// would advance). That second call is what this test targets directly,
    /// at the level it would happen -- `dispatch_datagram`'s own
    /// `for_each_data_submessage` enumeration -- by counting how many
    /// times discovery is actually invoked for this ONE envelope's DATA,
    /// which is what decides whether the downstream double-dispatch (and
    /// so the false `secure_sedp_undecodable` increment) can happen at all: a callback invoked once has nothing
    /// left to double-process.
    ///
    /// `for_each_data_submessage`'s `EnvelopeTracker`-style exclusion
    /// (classifier/mod.rs) is what keeps the count at 1: without it the
    /// count would be 2.
    #[cfg(feature = "security")]
    #[test]
    fn a_signed_secure_sedp_data_reaches_discovery_exactly_once() {
        use crate::core::rtps_constants::RTPS_ENTITYID_SEDP_PUBLICATIONS_SECURE_WRITER;
        use crate::security::crypto::secure_submessage::{
            encode_datawriter_submessage, Transformation, WriterKeyMaterial,
        };

        let plain = data_datagram_from(RTPS_ENTITYID_SEDP_PUBLICATIONS_SECURE_WRITER);
        let sub = plain[20..].to_vec();
        let material = WriterKeyMaterial::new([0x33; 32], [0x44; 32], [0, 0, 2, 2])
            .with_transformation(Transformation::Aes256Gmac);
        let protected = encode_datawriter_submessage(&material, &sub).expect("protect");

        let mut datagram = plain[..20].to_vec();
        datagram.extend_from_slice(&protected);

        let (kind, _, _, _) = classify_rtps(&datagram);
        assert_eq!(
            kind,
            PacketKind::SecureSEDP,
            "fixture: the classifier must elect SecureSEDP from the visible signed DATA"
        );

        let w = wiring(8);
        w.dispatch.dispatch(&datagram, synthetic_source());

        let secure_sedp_calls = w
            .seen
            .lock()
            .expect("the recorder mutex is never poisoned")
            .iter()
            .filter(|(kind, _, _)| *kind == PacketKind::SecureSEDP)
            .count();
        assert_eq!(
            secure_sedp_calls, 1,
            "a valid signed SecureSEDP DATA must reach discovery exactly once -- a second \
             delivery of the same visible DATA tries the clear path downstream and \
             increments secure_sedp_undecodable on perfectly valid traffic"
        );
    }

    /// A dispatch over fresh state, plus the ends a test inspects.
    struct Wiring {
        dispatch: PacketDispatch,
        pool: Arc<RxPool>,
        ring: Arc<ArrayQueue<(RxMeta, u8)>>,
        metrics: Arc<ListenerMetrics>,
        seen: Arc<std::sync::Mutex<Vec<(PacketKind, Origin, usize)>>>,
        control: crossbeam::channel::Receiver<ControlMessage>,
    }

    fn wiring(ring_capacity: usize) -> Wiring {
        let pool = Arc::new(RxPool::new(16, 1500).expect("Pool creation should succeed"));
        let ring = Arc::new(ArrayQueue::new(ring_capacity));
        let metrics = ListenerMetrics::new();
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorder = Arc::clone(&seen);
        let callback: DiscoveryCallback = Arc::new(move |kind, _buf, offset, _fragment, source| {
            recorder
                .lock()
                .expect("the recorder mutex is never poisoned")
                .push((kind, source, offset));
        });
        let (control_tx, control) = crossbeam::channel::unbounded();

        Wiring {
            dispatch: PacketDispatch {
                pool: Arc::clone(&pool),
                ring: Arc::clone(&ring),
                metrics: Arc::clone(&metrics),
                discovery_callback: Some(callback),
                control_tx: Some(control_tx),
                notifier: None,
                local_prefix: None,
                liveliness: None,
            },
            pool,
            ring,
            metrics,
            seen,
            control,
        }
    }

    /// A HEARTBEAT submessage (s8.3.8.6) of `writer`, addressed to `reader`.
    fn heartbeat_of(reader: [u8; 4], writer: [u8; 4]) -> Vec<u8> {
        let mut sub = heartbeat_to(reader);
        sub[8..12].copy_from_slice(&writer);
        sub
    }

    /// A GAP submessage (s8.3.8.4) of `writer`, addressed to `reader`.
    fn gap_of(reader: [u8; 4], writer: [u8; 4]) -> Vec<u8> {
        let mut sub = gap_to(reader);
        sub[8..12].copy_from_slice(&writer);
        sub
    }

    /// What one dispatch put where: the writer and `rides_ring` of every
    /// HEARTBEAT or GAP the control channel received, and the kind of every
    /// datagram the ring received.
    fn dispatched(datagram: &[u8]) -> (Vec<([u8; 4], bool)>, Vec<PacketKind>) {
        let w = wiring(8);
        w.dispatch.dispatch(datagram, synthetic_source());
        let mut controls = Vec::new();
        while let Ok(msg) = w.control.try_recv() {
            if let Some(hb) = msg.heartbeat.as_ref() {
                controls.push((hb.writer_entity_id, msg.rides_ring));
            }
            if let Some(gap) = msg.gap.as_ref() {
                controls.push((gap.writer_entity_id, msg.rides_ring));
            }
        }
        controls.sort();
        let mut ring_kinds = Vec::new();
        while let Some((meta, buffer_id)) = w.ring.pop() {
            ring_kinds.push(meta.kind);
            w.pool.release(buffer_id).expect("release should succeed");
        }
        (controls, ring_kinds)
    }

    /// A user writer's GAP behind a builtin DATA (a datagram elected as SEDP,
    /// whose DATA is the discovery callback's) rides the ring as a controls-only
    /// copy, so the Router applies it in order: the control thread is told it
    /// rides, and applies none of its gate effects (F3).
    #[test]
    fn a_user_gap_behind_a_builtin_data_rides_the_ring_too() {
        const R: [u8; 4] = [0x00, 0x00, 0x05, 0x07];
        const USER: [u8; 4] = [0x00, 0x00, 0x01, 0x02];
        let mut datagram = data_datagram_from([0x00, 0x00, 0x03, 0xC2]);
        datagram.extend_from_slice(&gap_of(R, USER));
        let (control, ring) = dispatched(&datagram);
        assert_eq!(control, vec![(USER, true)], "the user GAP rides the ring");
        assert_eq!(ring, vec![PacketKind::Heartbeat], "one controls-only copy");
    }

    /// A user writer's HEARTBEAT or GAP reaches the control thread, which
    /// answers it, AND rides the ring with its datagram, where the Router
    /// applies its reorder-gate effects in arrival order (the control thread
    /// applies none of them, `control::applies_gate_on_control`). A builtin
    /// writer's control reaches the control thread only. Covers a standalone
    /// HEARTBEAT, a standalone GAP, controls embedded in a DATA (which reach
    /// the control thread before the DATA is ringed), and a datagram mixing
    /// both.
    #[test]
    fn user_controls_ride_the_ring_and_reach_control_for_the_answer() {
        const R: [u8; 4] = [0x00, 0x00, 0x05, 0x07];
        const USER: [u8; 4] = [0x00, 0x00, 0x01, 0x02];
        const BUILTIN: [u8; 4] = [0x00, 0x00, 0x03, 0xC2];

        // (a) a standalone user HEARTBEAT
        let (control, ring) = dispatched(&datagram_of(&[heartbeat_of(R, USER)]));
        assert_eq!(control, vec![(USER, true)], "(a) control");
        assert_eq!(ring, vec![PacketKind::Heartbeat], "(a) ring");

        // (b) a standalone user GAP
        let (control, ring) = dispatched(&datagram_of(&[gap_of(R, USER)]));
        assert_eq!(control, vec![(USER, true)], "(b) control");
        assert_eq!(ring, vec![PacketKind::Gap], "(b) ring");

        // (c) a user HEARTBEAT and GAP embedded in a DATA
        let mut with_data = user_data_datagram();
        with_data.extend_from_slice(&heartbeat_of(R, USER));
        with_data.extend_from_slice(&gap_of(R, USER));
        let (control, ring) = dispatched(&with_data);
        assert_eq!(control, vec![(USER, true), (USER, true)], "(c) control");
        assert_eq!(ring, vec![PacketKind::Data], "(c) the DATA is ringed");

        // (d) a builtin HEARTBEAT and a user GAP in one datagram
        let (control, ring) =
            dispatched(&datagram_of(&[heartbeat_of(R, BUILTIN), gap_of(R, USER)]));
        assert_eq!(control, vec![(USER, true), (BUILTIN, true)], "(d) control");
        assert_eq!(ring, vec![PacketKind::Heartbeat], "(d) ring");

        // A builtin-only HEARTBEAT keeps its path: the control channel, no ring.
        let (control, ring) = dispatched(&datagram_of(&[heartbeat_of(R, BUILTIN)]));
        assert_eq!(
            control,
            vec![(BUILTIN, false)],
            "builtin HEARTBEAT on control"
        );
        assert_eq!(
            ring,
            Vec::<PacketKind>::new(),
            "builtin HEARTBEAT not ringed"
        );
    }

    /// Any message of a participant renews the liveliness of its AUTOMATIC
    /// writers, whatever it carries: here a lone HEARTBEAT, which the
    /// dispatch hands the control channel and nothing else.
    #[test]
    fn any_message_renews_its_sender() {
        let mut w = wiring(8);
        let shared = crate::dds::liveliness::Shared::new(Arc::new(
            crate::dds::liveliness::MonotonicClock::new(),
        ));
        w.dispatch.liveliness = Some(Arc::clone(&shared));
        let sender = [0x42; 12];
        let (automatic, manual) = shared.remote(sender);
        let (other, _) = shared.remote([0x43; 12]);
        let before = (automatic.last(), manual.last(), other.last());
        std::thread::sleep(Duration::from_millis(2));
        let mut hb = Vec::new();
        hb.extend_from_slice(b"RTPS");
        hb.extend_from_slice(&[0x02, 0x05, 0x01, 0x0F]);
        hb.extend_from_slice(&sender);
        hb.extend_from_slice(&[0x07, 0x01, 28, 0]);
        hb.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0x01, 0x02]);
        hb.extend_from_slice(&[0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0]);
        w.dispatch
            .dispatch(&hb, "127.0.0.1:9".parse().expect("addr"));
        assert!(automatic.last() > before.0, "renewed by its message");
        assert_eq!(
            manual.last(),
            before.1,
            "a message is not a manual assertion"
        );
        assert_eq!(other.last(), before.2, "another participant is not renewed");
    }

    #[test]
    fn user_data_lands_in_the_ring_whole() {
        let w = wiring(8);
        let datagram = user_data_datagram();

        w.dispatch.dispatch(&datagram, synthetic_source());

        let (meta, buffer_id) = w.ring.pop().expect("user data goes to the ring");
        assert_eq!(meta.kind, PacketKind::Data);
        assert_eq!(
            usize::from(meta.len),
            datagram.len(),
            "the whole datagram is kept, not the payload alone"
        );
        assert_eq!(
            w.metrics.packets_received.load(Ordering::Relaxed),
            1,
            "a datagram that arrived by any door is a received datagram"
        );
        w.pool.release(buffer_id).expect("release should succeed");
    }

    #[test]
    fn a_discovery_datagram_reaches_the_callback_with_the_address_it_was_given() {
        let w = wiring(8);
        let spdp = data_datagram_from(crate::core::rtps_constants::RTPS_ENTITYID_SPDP_WRITER);

        w.dispatch.dispatch(&spdp, synthetic_source());

        let seen = w.seen.lock().expect("the recorder mutex is never poisoned");
        assert_eq!(seen.len(), 1, "SPDP reaches the discovery callback");
        assert_eq!(seen[0].0, PacketKind::SPDP);
        // The load-bearing assertion for the relay: the dispatch forwards the
        // source it was handed. A relayed datagram carries the sender's
        // synthetic locator, and the reply path answers that source.
        assert_eq!(
            seen[0].1.from(),
            synthetic_source(),
            "the source address is carried through untouched"
        );
        assert_eq!(
            seen[0].1.reply(),
            Some(synthetic_source()),
            "not behind an INFO_SRC: a reply may use it"
        );
    }

    /// The same announcement, split: a DATA_FRAG (s8.3.8.3) attributed to
    /// `writer_id`, carrying `payload_len` octets of fragment and complete
    /// enough that the classifier publishes fragment metadata for it.
    fn data_frag_datagram_from(writer_id: [u8; 4], payload_len: usize) -> Vec<u8> {
        use crate::core::rtps_constants::{RTPS_VERSION_MAJOR, RTPS_VERSION_MINOR};
        use crate::protocol::constants::HDDS_VENDOR_ID;

        let mut packet = Vec::new();
        packet.extend_from_slice(b"RTPS");
        packet.push(RTPS_VERSION_MAJOR);
        packet.push(RTPS_VERSION_MINOR);
        packet.extend_from_slice(&HDDS_VENDOR_ID);
        packet.extend_from_slice(&[0x0A; 12]);

        packet.push(0x16); // DATA_FRAG
        packet.push(0x01); // E flag set: little-endian
        let declared = packet.len();
        packet.extend_from_slice(&0u16.to_le_bytes()); // placeholder
        let body_start = packet.len();
        packet.extend_from_slice(&0u16.to_le_bytes()); // extraFlags
        packet.extend_from_slice(&28u16.to_le_bytes()); // octetsToInlineQos
        packet.extend_from_slice(&[0x00, 0x01, 0x00, 0xC7]); // readerId: SPDP reader
        packet.extend_from_slice(&writer_id);
        packet.extend_from_slice(&[0x00; 4]); // writerSN high
        packet.extend_from_slice(&1u32.to_le_bytes()); // writerSN low
        packet.extend_from_slice(&1u32.to_le_bytes()); // fragmentStartingNum
        packet.extend_from_slice(&1u16.to_le_bytes()); // fragmentsInSubmessage
        packet.extend_from_slice(
            &u16::try_from(payload_len)
                .expect("the fixture's fragment fits fragmentSize")
                .to_le_bytes(),
        );
        packet.extend_from_slice(
            &u32::try_from(payload_len)
                .expect("the fixture's fragment fits sampleSize")
                .to_le_bytes(),
        );
        packet.extend_from_slice(&vec![0xBB; payload_len]);

        let body = packet.len() - body_start;
        assert_eq!(
            body,
            32 + payload_len,
            "a DATA_FRAG body is 32 octets of fixed fields plus its fragment (s8.3.8.3)"
        );
        packet[declared..declared + 2].copy_from_slice(
            &u16::try_from(body)
                .expect("the fixture's DATA_FRAG body fits octetsToNextHeader")
                .to_le_bytes(),
        );
        assert!(
            packet.len().is_multiple_of(4),
            "a fixture datagram ends on a 4-octet boundary like the wire (RTPS 2.5 9.4.1)"
        );
        packet
    }

    /// A fragmented SPDP announcement must reach discovery.
    ///
    /// Vendors split SPDP across DATA_FRAG submessages when the participant's
    /// QoS does not fit one datagram - this file's own comment says "SPDP
    /// announcements may arrive as DATA_FRAG", and the classifier's recovery
    /// scan exists for exactly that packet.
    ///
    /// `classify_data_frag` names such a fragment by its writer, so the
    /// datagram is classified SPDP, not DataFrag. The dispatch then delivers
    /// by kind: `DataFrag` and `Heartbeat` go out whole, and everything else
    /// is looked for by walking the datagram for DATA (0x15) submessages. A
    /// DATA_FRAG is neither, so the announcement is classified and then
    /// handed to nobody.
    #[test]
    fn a_fragmented_announcement_reaches_discovery_whatever_kind_it_is_given() {
        use crate::core::rtps_constants::{
            RTPS_ENTITYID_SEDP_PUBLICATIONS_WRITER, RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_WRITER,
            RTPS_ENTITYID_SPDP_WRITER,
        };
        const USER_WRITER: [u8; 4] = [0x00, 0x00, 0x01, 0x02];

        // 20 octets of RTPS header, 4 of submessage header, 32 of DATA_FRAG
        // fixed fields (s8.3.8.3): the fragment itself starts at 56.
        const FRAGMENT_AT: usize = 56;

        for (writer, expected) in [
            (RTPS_ENTITYID_SPDP_WRITER, PacketKind::SPDP),
            (RTPS_ENTITYID_SEDP_PUBLICATIONS_WRITER, PacketKind::SEDP),
            (RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_WRITER, PacketKind::SEDP),
            (USER_WRITER, PacketKind::DataFrag),
        ] {
            let w = wiring(8);
            let frag = data_frag_datagram_from(writer, 40);
            assert_eq!(
                frag[FRAGMENT_AT], 0xBB,
                "the fixture's fragment starts where the test says it does"
            );

            w.dispatch.dispatch(&frag, synthetic_source());

            let seen = w.seen.lock().expect("the recorder mutex is never poisoned");
            assert_eq!(
                seen.len(),
                1,
                "the DATA_FRAG from writer {writer:02x?} reaches discovery exactly once"
            );
            assert_eq!(seen[0].0, expected, "delivered under the classified kind");
            assert_eq!(
                seen[0].2, FRAGMENT_AT,
                "delivered with the offset its fragment starts at"
            );
        }
    }

    /// One RTPS message, several announcements: an SPDP followed by an SEDP
    /// publication, each a DATA submessage of the same datagram. RTPS v2.5
    /// Sec.8.3.3 allows it, so the listener must deliver every DATA of the
    /// datagram, not only the one the classifier names.
    ///
    /// The SPDP is deliberately the long one. Its octetsToNextHeader of 104
    /// is over the threshold that ends the classifier's scan, so the datagram
    /// is named SPDP and the SPDP is delivered; the SEDP behind it would be
    /// dropped without a counter, a log or a trace unless every DATA is
    /// delivered.
    fn spdp_then_sedp_datagram() -> (Vec<u8>, usize, usize) {
        use crate::core::rtps_constants::{
            RTPS_ENTITYID_SEDP_PUBLICATIONS_WRITER, RTPS_ENTITYID_SPDP_WRITER, RTPS_VERSION_MAJOR,
            RTPS_VERSION_MINOR,
        };
        use crate::protocol::constants::HDDS_VENDOR_ID;

        fn data(writer_id: [u8; 4], payload: &[u8]) -> Vec<u8> {
            let mut submessage = vec![0x15, 0x01];
            submessage.extend_from_slice(&((20 + payload.len()) as u16).to_le_bytes());
            submessage.extend_from_slice(&0u16.to_le_bytes()); // extraFlags
            submessage.extend_from_slice(&16u16.to_le_bytes()); // octetsToInlineQos
            submessage.extend_from_slice(&[0x00, 0x00, 0x01, 0x07]); // readerId
            submessage.extend_from_slice(&writer_id);
            submessage.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 1]); // writerSN = 1
            submessage.extend_from_slice(payload);
            submessage
        }

        let mut packet = Vec::new();
        packet.extend_from_slice(b"RTPS");
        packet.push(RTPS_VERSION_MAJOR);
        packet.push(RTPS_VERSION_MINOR);
        packet.extend_from_slice(&HDDS_VENDOR_ID);
        packet.extend_from_slice(&[0x0A; 12]);

        let spdp = data(RTPS_ENTITYID_SPDP_WRITER, &[0x11; 84]);
        let sedp = data(RTPS_ENTITYID_SEDP_PUBLICATIONS_WRITER, &[0x22; 40]);
        // Payload offset of each: submessage start + octetsToInlineQos + 8.
        let spdp_payload = 20 + 24;
        let sedp_payload = 20 + spdp.len() + 24;
        packet.extend_from_slice(&spdp);
        packet.extend_from_slice(&sedp);

        (packet, spdp_payload, sedp_payload)
    }

    #[test]
    fn every_discovery_submessage_of_a_compound_datagram_reaches_the_callback() {
        let w = wiring(8);
        let (packet, spdp_payload, sedp_payload) = spdp_then_sedp_datagram();

        w.dispatch.dispatch(&packet, synthetic_source());

        let seen = w.seen.lock().expect("the recorder mutex is never poisoned");
        assert_eq!(
            seen.iter().map(|(kind, _, _)| *kind).collect::<Vec<_>>(),
            vec![PacketKind::SPDP, PacketKind::SEDP],
            "both announcements are delivered, in wire order"
        );
        assert_eq!(
            seen.iter().map(|(_, _, at)| *at).collect::<Vec<_>>(),
            vec![spdp_payload, sedp_payload],
            "each call carries the offset of ITS submessage, not of the first"
        );
        assert!(
            seen.iter()
                .all(|(_, source, _)| source.from() == synthetic_source()),
            "the source address is carried through untouched"
        );
        assert_eq!(
            &packet[sedp_payload..sedp_payload + 40],
            &[0x22; 40],
            "the second offset lands on the second submessage's own payload"
        );
    }

    /// A DDS-Security 1.1 protected submessage reaches discovery once, as
    /// the secure SEDP topic at its SEC_PREFIX, whatever the classifier
    /// names the datagram for what rides with it: here an INFO_TS before it
    /// and a HEARTBEAT after it, which still reaches the control channel.
    #[cfg(feature = "security")]
    #[test]
    fn a_protected_submessage_reaches_discovery_at_its_sec_prefix() {
        let w = wiring(8);
        let mut packet = bare_rtps_header();
        packet.extend_from_slice(&[0x09, 0x01, 0x08, 0x00, 1, 0, 0, 0, 2, 0, 0, 0]);
        let prefix_at = packet.len();
        let material = crate::security::crypto::secure_submessage::WriterKeyMaterial::new(
            [1; 32],
            [2; 32],
            [0, 0, 0, 3],
        );
        let data = [
            0x15, 0x01, 0x14, 0x00, 0, 0, 0x10, 0, 0xff, 0, 3, 0xc7, 0xff, 0, 3, 0xc2, 0, 0, 0, 0,
            1, 0, 0, 0,
        ];
        packet.extend_from_slice(
            &crate::security::crypto::secure_submessage::encode_datawriter_submessage(
                &material, &data,
            )
            .expect("protect"),
        );
        push_heartbeat(&mut packet, [0x00, 0x00, 0x03, 0xC2]);

        w.dispatch.dispatch(&packet, synthetic_source());

        let seen = w.seen.lock().expect("the recorder mutex is never poisoned");
        assert_eq!(
            seen.iter()
                .filter(|(kind, _, _)| *kind == PacketKind::SecureSEDP)
                .map(|(_, _, at)| *at)
                .collect::<Vec<_>>(),
            vec![prefix_at],
            "delivered once, at its SEC_PREFIX: {:?}",
            *seen
        );
        let (_, heartbeats) = nack_frags_and_heartbeats_of(&w.control);
        assert_eq!(heartbeats, 1, "the HEARTBEAT too");
    }

    /// Appends a GAP submessage (id 0x08, little-endian, empty bitmap) for
    /// `writer_id`, declaring sequences [`start`, `start`] irrelevant.
    /// Body: readerEntityId 4, writerEntityId 4, gapStart 8, gapList.base 8,
    /// gapList.numBits 4 (RTPS v2.5 Sec.8.3.8.4).
    fn push_gap(packet: &mut Vec<u8>, writer_id: [u8; 4], start: u32) {
        packet.push(0x08);
        packet.push(0x01); // E flag: little-endian
        packet.extend_from_slice(&28u16.to_le_bytes());
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // readerEntityId
        packet.extend_from_slice(&writer_id);
        packet.extend_from_slice(&0i32.to_le_bytes()); // gapStart.high
        packet.extend_from_slice(&start.to_le_bytes()); // gapStart.low
        packet.extend_from_slice(&0i32.to_le_bytes()); // gapList.base.high
        packet.extend_from_slice(&(start + 1).to_le_bytes()); // gapList.base.low
        packet.extend_from_slice(&0u32.to_le_bytes()); // gapList.numBits = 0
    }

    /// The three writers whose purges must all survive the dispatch.
    const GAP_WRITERS: [[u8; 4]; 3] = [
        [0x00, 0x00, 0x01, 0x02],
        [0x00, 0x00, 0x03, 0x02],
        [0x00, 0x00, 0x05, 0x02],
    ];

    /// Every GAP kinds are collected from, in wire order.
    fn gaps_of(control: &crossbeam::channel::Receiver<ControlMessage>) -> Vec<[u8; 4]> {
        let mut out = Vec::new();
        while let Ok(msg) = control.try_recv() {
            if let Some(gap) = msg.gap {
                out.push(gap.writer_entity_id);
            }
        }
        out
    }

    /// Appends an ACKNACK submessage (id 0x06, little-endian, empty bitmap)
    /// from `writer_id`'s reader. Body: readerEntityId 4, writerEntityId 4,
    /// readerSNState.bitmapBase 8, numBits 4, count 4 (Sec.8.3.8.1).
    fn push_acknack(packet: &mut Vec<u8>, writer_id: [u8; 4], base: u32) {
        packet.push(0x06);
        packet.push(0x01); // E flag: little-endian
        packet.extend_from_slice(&24u16.to_le_bytes());
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // readerEntityId
        packet.extend_from_slice(&writer_id);
        packet.extend_from_slice(&0i32.to_le_bytes()); // bitmapBase.high
        packet.extend_from_slice(&base.to_le_bytes()); // bitmapBase.low
        packet.extend_from_slice(&0u32.to_le_bytes()); // numBits = 0
        packet.extend_from_slice(&1u32.to_le_bytes()); // count
    }

    /// Appends a NACK_FRAG submessage (id 0x12, little-endian) asking
    /// `writer_id` about sample `writer_sn`. `num_bits == 0` builds the pure
    /// fragment-level acknowledgment a reader sends when nothing is missing
    /// -- legal on the wire (RTPS v2.5 Sec.8.3.8.12) and decoded into an
    /// EMPTY missing-fragment list. Body: readerEntityId 4, writerEntityId 4,
    /// writerSN 8, fragmentNumberState (base 4 + numBits 4 + words), count 4.
    fn push_nack_frag(packet: &mut Vec<u8>, writer_id: [u8; 4], writer_sn: u32, num_bits: u32) {
        let words = num_bits.div_ceil(32) as usize;
        let body = 24 + words * 4 + 4;
        packet.push(0x12);
        packet.push(0x01); // E flag: little-endian
        packet.extend_from_slice(
            &u16::try_from(body)
                .expect("the fixture's NACK_FRAG body fits the octetsToNextHeader field")
                .to_le_bytes(),
        );
        packet.extend_from_slice(&[0x00, 0x00, 0x01, 0x07]); // readerEntityId
        packet.extend_from_slice(&writer_id);
        packet.extend_from_slice(&0i32.to_le_bytes()); // writerSN.high
        packet.extend_from_slice(&writer_sn.to_le_bytes()); // writerSN.low
        packet.extend_from_slice(&1u32.to_le_bytes()); // fragmentNumberState.base
        packet.extend_from_slice(&num_bits.to_le_bytes());
        for _ in 0..words {
            // MSB-first, Sec.8.3.5.5: fragments base+0 and base+2 are missing.
            packet.extend_from_slice(&0xA000_0000u32.to_le_bytes());
        }
        packet.extend_from_slice(&1u32.to_le_bytes()); // count
    }

    /// Appends a HEARTBEAT submessage (id 0x07, little-endian) announcing
    /// sequences 1..=1 for `writer_id` (Sec.8.3.8.6, 28-octet body).
    fn push_heartbeat(packet: &mut Vec<u8>, writer_id: [u8; 4]) {
        packet.push(0x07);
        packet.push(0x01); // E flag: little-endian
        packet.extend_from_slice(&28u16.to_le_bytes());
        packet.extend_from_slice(&[0x00, 0x00, 0x01, 0x07]); // readerEntityId
        packet.extend_from_slice(&writer_id);
        packet.extend_from_slice(&0i32.to_le_bytes()); // firstSN.high
        packet.extend_from_slice(&1u32.to_le_bytes()); // firstSN.low
        packet.extend_from_slice(&0i32.to_le_bytes()); // lastSN.high
        packet.extend_from_slice(&1u32.to_le_bytes()); // lastSN.low
        packet.extend_from_slice(&1i32.to_le_bytes()); // count
    }

    /// The samples every NACK_FRAG on the channel asks about, and how many
    /// HEARTBEATs arrived, in one drain.
    fn nack_frags_and_heartbeats_of(
        control: &crossbeam::channel::Receiver<ControlMessage>,
    ) -> (Vec<u64>, usize) {
        let mut sns = Vec::new();
        let mut heartbeats = 0;
        while let Ok(msg) = control.try_recv() {
            if let Some(nf) = msg.nack_frag {
                sns.push(nf.writer_sn);
            }
            if msg.heartbeat.is_some() {
                heartbeats += 1;
            }
        }
        (sns, heartbeats)
    }

    /// A reader that has every fragment of one sample and holes in the next
    /// sends [NACK_FRAG(nothing missing), NACK_FRAG(holes)], and a writer
    /// bundles a HEARTBEAT behind them. The datagram classifies as Data (the
    /// DATA submessage wins and the scan does not stop under 100 octets), so
    /// the compound-extraction block is the only place that sees any of it.
    ///
    /// That block must answer an empty missing-fragment list with
    /// `continue`, as the SAME loop in the ACKNACK-classified branch does. A
    /// `return` would leave the whole dispatch: every later NACK_FRAG would be
    /// dropped AND so would the embedded-HEARTBEAT dispatch that follows it,
    /// which is more than the fragments it is meant to skip.
    #[test]
    fn an_empty_nack_frag_bitmap_does_not_end_the_compound_dispatch() {
        const WRITER: [u8; 4] = [0x00, 0x00, 0x01, 0x02];
        let w = wiring(8);
        let mut datagram = data_datagram_from(WRITER);
        push_nack_frag(&mut datagram, WRITER, 7, 0); // nothing missing
        push_nack_frag(&mut datagram, WRITER, 9, 3); // fragments 1 and 3
        push_heartbeat(&mut datagram, WRITER);

        w.dispatch.dispatch(&datagram, synthetic_source());

        let (sns, heartbeats) = nack_frags_and_heartbeats_of(&w.control);
        assert_eq!(
            sns,
            vec![9],
            "the sample with holes is requested; the one with nothing missing is skipped, not fatal"
        );
        assert_eq!(
            heartbeats, 1,
            "a NACK_FRAG asking for nothing must not swallow the HEARTBEAT behind it"
        );
    }

    /// An RTPS header with nothing after it, for a fixture that appends its
    /// own submessages.
    fn bare_rtps_header() -> Vec<u8> {
        use crate::core::rtps_constants::{RTPS_VERSION_MAJOR, RTPS_VERSION_MINOR};
        use crate::protocol::constants::HDDS_VENDOR_ID;

        let mut packet = Vec::with_capacity(20);
        packet.extend_from_slice(b"RTPS");
        packet.push(RTPS_VERSION_MAJOR);
        packet.push(RTPS_VERSION_MINOR);
        packet.extend_from_slice(&HDDS_VENDOR_ID);
        packet.extend_from_slice(&[0x0A; 12]);
        packet
    }

    /// A writer announcing what it holds while its reader asks for the holes
    /// in a fragmented sample: [HEARTBEAT, NACK_FRAG] in one datagram, which
    /// classifies as Heartbeat because the HEARTBEAT comes first.
    ///
    /// That branch must not throw the NACK_FRAG half of the answer away: the
    /// writer-side selective retransmit would never run and the reader would
    /// ask for the same fragments forever - with no counter and no log.
    #[test]
    fn a_nack_frag_riding_with_a_heartbeat_reaches_the_control_channel() {
        const WRITER: [u8; 4] = [0x00, 0x00, 0x01, 0x02];
        let w = wiring(8);
        let mut datagram = heartbeat_datagram();
        push_nack_frag(&mut datagram, WRITER, 9, 3);

        w.dispatch.dispatch(&datagram, synthetic_source());

        let (sns, heartbeats) = nack_frags_and_heartbeats_of(&w.control);
        assert_eq!(
            sns,
            vec![9],
            "the fragment request rides with the HEARTBEAT"
        );
        assert_eq!(heartbeats, 1, "and the HEARTBEAT still arrives");
    }

    /// The same, one classification over: [GAP, NACK_FRAG] resolves to Gap,
    /// and that branch threw the NACK_FRAG away for the same reason.
    #[test]
    fn a_nack_frag_riding_with_a_gap_reaches_the_control_channel() {
        const WRITER: [u8; 4] = [0x00, 0x00, 0x01, 0x02];
        let w = wiring(8);
        let mut datagram = bare_rtps_header();
        push_gap(&mut datagram, WRITER, 10);
        push_nack_frag(&mut datagram, WRITER, 9, 3);

        w.dispatch.dispatch(&datagram, synthetic_source());

        let mut sns = Vec::new();
        let mut gaps = 0;
        while let Ok(msg) = w.control.try_recv() {
            if let Some(nf) = msg.nack_frag {
                sns.push(nf.writer_sn);
            }
            if msg.gap.is_some() {
                gaps += 1;
            }
        }
        assert_eq!(sns, vec![9], "the fragment request rides with the GAP");
        assert_eq!(gaps, 1, "and the GAP still arrives");
    }

    /// The standalone NACK_FRAG datagram: the oldest of the fragment-request
    /// paths.
    ///
    /// It skips a request that names no fragment rather than forwarding it.
    /// That costs the consumer nothing (`control.rs` already refuses to
    /// deliver an empty one) and saves a slot of a 1024-deep channel whose
    /// overflow is a silent drop.
    #[test]
    fn a_standalone_nack_frag_datagram_reaches_the_control_channel() {
        const WRITER: [u8; 4] = [0x00, 0x00, 0x01, 0x02];
        let w = wiring(8);
        let mut datagram = bare_rtps_header();
        push_nack_frag(&mut datagram, WRITER, 7, 0); // nothing missing
        push_nack_frag(&mut datagram, WRITER, 9, 3); // fragments 1 and 3

        w.dispatch.dispatch(&datagram, synthetic_source());

        let (sns, _) = nack_frags_and_heartbeats_of(&w.control);
        assert_eq!(
            sns,
            vec![9],
            "the sample with holes is requested, the pure acknowledgment is not forwarded"
        );
    }

    /// A peer with several readers matched to several of our writers sends
    /// one ACKNACK per (reader, writer) pair in ONE datagram. Every one of
    /// them must reach the control channel.
    ///
    /// Reading the first ACKNACK only is not enough. Each writer's nack
    /// handler filters on the ACKNACK's writerEntityId, so every writer but
    /// the one named first would see a request that was not for it, drop it,
    /// and never retransmit -- its reader NACKing the same sequences
    /// forever, with no counter and no log.
    #[test]
    fn every_acknack_of_a_datagram_reaches_the_control_channel() {
        let w = wiring(8);
        let mut datagram = Vec::new();
        {
            use crate::core::rtps_constants::{RTPS_VERSION_MAJOR, RTPS_VERSION_MINOR};
            use crate::protocol::constants::HDDS_VENDOR_ID;
            datagram.extend_from_slice(b"RTPS");
            datagram.push(RTPS_VERSION_MAJOR);
            datagram.push(RTPS_VERSION_MINOR);
            datagram.extend_from_slice(&HDDS_VENDOR_ID);
            datagram.extend_from_slice(&[0x0A; 12]);
        }
        let writers = [
            [0x00u8, 0x00, 0x01, 0x03],
            [0x00, 0x00, 0x03, 0x03],
            [0x00, 0x00, 0x05, 0x03],
        ];
        for (i, writer) in writers.iter().enumerate() {
            push_acknack(&mut datagram, *writer, i as u32 + 1);
        }

        w.dispatch.dispatch(&datagram, synthetic_source());

        let mut seen = Vec::new();
        while let Ok(msg) = w.control.try_recv() {
            if let Some(an) = msg.acknack {
                seen.push(an.writer_entity_id);
            }
        }
        assert_eq!(seen, writers.to_vec(), "every ACKNACK, in wire order");
    }

    /// A datagram carrying a HEARTBEAT and THREE GAPs classifies as
    /// Heartbeat, and every one of the three purges must reach the control
    /// channel.
    ///
    /// A first-GAP-only parser would leave writers 3 and 5 waiting for
    /// sequences their writer has already declared irrelevant -- with no
    /// counter and no log. The same bytes classified as Data yield all three,
    /// so the answer must not depend on which submessage happens to come
    /// first in the datagram.
    #[test]
    fn every_gap_riding_with_a_heartbeat_reaches_the_control_channel() {
        let w = wiring(8);
        let mut datagram = heartbeat_datagram();
        for (i, writer) in GAP_WRITERS.iter().enumerate() {
            push_gap(&mut datagram, *writer, 10 * (i as u32 + 1));
        }

        w.dispatch.dispatch(&datagram, synthetic_source());

        assert_eq!(gaps_of(&w.control), GAP_WRITERS.to_vec());
    }

    /// Same datagram the other way round: THREE GAPs then a HEARTBEAT, which
    /// classifies as Gap. All three purges must reach the control channel.
    ///
    /// The order is pinned too. The control handler reads GAP and HEARTBEAT
    /// as two separate messages in channel order (`control.rs`, the
    /// `msg.heartbeat` / `else if msg.gap` chain), so what this branch sends
    /// first is what the proxy folds in first. This branch sends the GAPs
    /// first on purpose; the pin exists so that a rewrite of it
    /// cannot invert the order in silence. Whether the proxy would actually
    /// misbehave the other way round is asserted by the comment in this
    /// branch and is NOT measured here.
    #[test]
    fn every_gap_of_a_gap_classified_datagram_arrives_before_the_heartbeat() {
        let w = wiring(8);
        let mut datagram = Vec::new();
        {
            use crate::core::rtps_constants::{RTPS_VERSION_MAJOR, RTPS_VERSION_MINOR};
            use crate::protocol::constants::HDDS_VENDOR_ID;
            datagram.extend_from_slice(b"RTPS");
            datagram.push(RTPS_VERSION_MAJOR);
            datagram.push(RTPS_VERSION_MINOR);
            datagram.extend_from_slice(&HDDS_VENDOR_ID);
            datagram.extend_from_slice(&[0x0A; 12]);
        }
        for (i, writer) in GAP_WRITERS.iter().enumerate() {
            push_gap(&mut datagram, *writer, 10 * (i as u32 + 1));
        }
        // The HEARTBEAT body of `heartbeat_datagram`, appended after the GAPs.
        datagram.extend_from_slice(&heartbeat_datagram()[20..]);

        w.dispatch.dispatch(&datagram, synthetic_source());

        let mut order = Vec::new();
        while let Ok(msg) = w.control.try_recv() {
            match (msg.gap, msg.heartbeat) {
                (Some(gap), _) => order.push(Some(gap.writer_entity_id)),
                (None, Some(_)) => order.push(None),
                _ => {}
            }
        }
        assert_eq!(
            order,
            vec![
                Some(GAP_WRITERS[0]),
                Some(GAP_WRITERS[1]),
                Some(GAP_WRITERS[2]),
                None
            ],
            "the three GAPs, in wire order, then the HEARTBEAT"
        );
    }

    #[test]
    fn a_builtin_heartbeat_goes_to_the_control_channel_and_not_to_the_ring() {
        let w = wiring(8);

        // A builtin writer's HEARTBEAT: a user writer's rides the ring too
        // (`user_controls_ride_the_ring_and_reach_control_for_the_answer`).
        w.dispatch
            .dispatch(&datagram_of(&[heartbeat_to_builtin()]), synthetic_source());

        let message = w
            .control
            .try_recv()
            .expect("a HEARTBEAT belongs to the control channel");
        assert_eq!(message.origin.from(), synthetic_source());
        assert_eq!(message.origin.reply(), Some(synthetic_source()));
        assert!(
            w.ring.is_empty(),
            "control traffic must not consume a data buffer"
        );
    }

    /// A HEARTBEAT (s8.3.8.6) of a builtin writer (SEDP publications).
    fn heartbeat_to_builtin() -> Vec<u8> {
        heartbeat_of([0x00, 0x00, 0x05, 0x07], [0x00, 0x00, 0x03, 0xC2])
    }

    const LOCAL_PREFIX: [u8; 12] = [0x0B; 12];
    const OTHER_PREFIX: [u8; 12] = [0x0C; 12];

    /// `datagram` with an INFO_DST naming `prefix` ahead of its submessages.
    fn destined(prefix: [u8; 12], datagram: &[u8]) -> Vec<u8> {
        let mut packet = datagram[..20].to_vec();
        packet.extend_from_slice(&[0x0e, 0x01, 0x0c, 0x00]);
        packet.extend_from_slice(&prefix);
        packet.extend_from_slice(&datagram[20..]);
        packet
    }

    /// RTPS 2.5 8.3.8.10: a submessage behind an INFO_SRC comes from the
    /// participant the INFO_SRC names, not from the one whose header carried
    /// it (a relay, a routing service). Each submessage reaches the control
    /// thread under its own source, the one before the INFO_SRC included.
    #[test]
    fn a_submessage_behind_an_info_src_comes_from_the_source_it_names() {
        const ORIGIN: [u8; 12] = [0x0D; 12];
        let mut info_src = vec![0x0c, 0x01, 0x14, 0x00, 0, 0, 0, 0, 0x02, 0x05, 0x01, 0x0F];
        info_src.extend_from_slice(&ORIGIN);
        let packet = datagram_of(&[
            heartbeat_to([0x00, 0x00, 0x01, 0x07]),
            info_src,
            heartbeat_to([0x00, 0x00, 0x01, 0x07]),
        ]);
        let mut forwarder = [0u8; 12];
        forwarder.copy_from_slice(&packet[8..20]);
        assert_ne!(forwarder, ORIGIN);

        let w = wiring(8);
        w.dispatch.dispatch(&packet, synthetic_source());
        let sources: Vec<_> = std::iter::from_fn(|| w.control.try_recv().ok())
            .map(|msg| msg.peer_guid_prefix)
            .collect();
        assert_eq!(sources, vec![forwarder, ORIGIN]);
    }

    /// RTPS 2.5 8.3.4 / 8.3.8.10: the leading part of a datagram (before its
    /// first INFO_SRC) is direct -- `synthetic_source()` is a real reply
    /// locator for it. Everything behind the INFO_SRC is relayed: the same
    /// `synthetic_source()` only forwarded it, and has no reply locator.
    #[test]
    fn a_submessage_behind_an_info_src_reaches_its_consumer_relayed() {
        const PEER: [u8; 12] = [0x0D; 12];
        let mut info_src = vec![0x0c, 0x01, 0x14, 0x00, 0, 0, 0, 0, 0x02, 0x05, 0x01, 0x0F];
        info_src.extend_from_slice(&PEER);
        let packet = datagram_of(&[
            heartbeat_to([0x00, 0x00, 0x01, 0x07]),
            info_src,
            heartbeat_to([0x00, 0x00, 0x01, 0x07]),
        ]);

        let w = wiring(8);
        w.dispatch.dispatch(&packet, synthetic_source());
        let replies: Vec<_> = std::iter::from_fn(|| w.control.try_recv().ok())
            .map(|msg| msg.origin.reply())
            .collect();
        assert_eq!(
            replies,
            vec![Some(synthetic_source()), None],
            "the leading part is direct, the part behind the INFO_SRC is relayed"
        );
    }

    /// An INFO_REPLY_IP4 (RTPS 2.5 9.4.5.15), built from the spec layout:
    /// header, then LocatorUDPv4 `{unsigned long address, unsigned long
    /// port}` (9.4.3.1) in the submessage's byte order, little-endian here.
    fn info_reply_ip4(address: [u8; 4], port: u32) -> Vec<u8> {
        let mut sub = vec![0x0d, 0x01];
        sub.extend_from_slice(&8u16.to_le_bytes());
        sub.extend_from_slice(&u32::from_be_bytes(address).to_le_bytes());
        sub.extend_from_slice(&port.to_le_bytes());
        sub
    }

    /// An INFO_REPLY (RTPS 2.5 9.4.5.10) with a unicast LocatorList of one
    /// UDPv4 Locator_t `{long kind, unsigned long port, octet address[16]}`
    /// (9.4.2.10), big-endian here (E = 0), and no multicast list (M = 0).
    fn info_reply(address: [u8; 4], port: u32) -> Vec<u8> {
        let mut sub = vec![0x0f, 0x00];
        sub.extend_from_slice(&28u16.to_be_bytes());
        sub.extend_from_slice(&1u32.to_be_bytes()); // numLocators
        sub.extend_from_slice(&1i32.to_be_bytes()); // LOCATOR_KIND_UDPv4
        sub.extend_from_slice(&port.to_be_bytes());
        sub.extend_from_slice(&[0; 12]);
        sub.extend_from_slice(&address);
        sub
    }

    /// RTPS 2.5 8.3.8.9 / 8.3.4: an INFO_REPLY sets the Receiver's reply
    /// locator for the submessages that FOLLOW it in the message, and an
    /// INFO_SRC resets it (8.3.8.10) until the next INFO_REPLY. Each
    /// HEARTBEAT reaches the control thread with the reply locator in force
    /// where it sits; the stateful fallback (`reply`) is untouched by it.
    #[test]
    fn a_submessage_behind_an_info_reply_carries_the_locator_it_names() {
        const PEER: [u8; 12] = [0x0D; 12];
        let mut info_src = vec![0x0c, 0x01, 0x14, 0x00, 0, 0, 0, 0, 0x02, 0x05, 0x01, 0x0F];
        info_src.extend_from_slice(&PEER);
        let packet = datagram_of(&[
            heartbeat_to([0x00, 0x00, 0x01, 0x07]),
            info_reply_ip4([127, 0, 0, 9], 7411),
            heartbeat_to([0x00, 0x00, 0x01, 0x07]),
            info_src,
            heartbeat_to([0x00, 0x00, 0x01, 0x07]),
            info_reply([10, 1, 2, 3], 7412),
            heartbeat_to([0x00, 0x00, 0x01, 0x07]),
        ]);

        let w = wiring(8);
        w.dispatch.dispatch(&packet, synthetic_source());
        let origins: Vec<_> = std::iter::from_fn(|| w.control.try_recv().ok())
            .map(|msg| msg.origin)
            .collect();
        assert_eq!(
            origins
                .iter()
                .map(|origin| origin.receiver_reply_locator())
                .collect::<Vec<_>>(),
            vec![
                Some(synthetic_source()),
                Some("127.0.0.9:7411".parse().expect("literal")),
                None,
                Some("10.1.2.3:7412".parse().expect("literal")),
            ],
            "sender, then the INFO_REPLY_IP4 locator, then none behind the \
             INFO_SRC, then the INFO_REPLY locator"
        );
        assert_eq!(
            origins
                .iter()
                .map(|origin| origin.reply())
                .collect::<Vec<_>>(),
            vec![
                Some(synthetic_source()),
                Some(synthetic_source()),
                None,
                None
            ],
            "the stateful fallback: the sender where it is the source"
        );
    }

    /// A SEDP HEARTBEAT from `peer`, for the control thread to answer:
    /// writerId SEDP publications writer, readerId UNKNOWN, [1, 1], final.
    fn sedp_heartbeat(peer: [u8; 12], info_reply: Option<Vec<u8>>) -> Vec<u8> {
        let mut packet = user_data_datagram()[..8].to_vec();
        packet.extend_from_slice(&peer);
        if let Some(info_reply) = info_reply {
            packet.extend_from_slice(&info_reply);
        }
        packet.extend_from_slice(&[0x07, 0x03]); // HEARTBEAT, E + F
        packet.extend_from_slice(&28u16.to_le_bytes());
        packet.extend_from_slice(&[0, 0, 0, 0]); // readerId UNKNOWN
        packet.extend_from_slice(&[0x00, 0x00, 0x03, 0xC2]); // SEDP pub writer
        packet.extend_from_slice(&0i32.to_le_bytes());
        packet.extend_from_slice(&1u32.to_le_bytes()); // firstSN 1
        packet.extend_from_slice(&0i32.to_le_bytes());
        packet.extend_from_slice(&1u32.to_le_bytes()); // lastSN 1
        packet.extend_from_slice(&1i32.to_le_bytes()); // count
        packet
    }

    /// End to end over real sockets, through the production dispatch and
    /// the production control thread: a SEDP HEARTBEAT behind an
    /// INFO_REPLY_IP4 (RTPS 2.5 8.3.8.9, 9.4.5.15) naming another address
    /// is answered exactly as the same HEARTBEAT without one: by the SEDP
    /// reader, a stateful endpoint, through its WriterProxy (8.4.12.2,
    /// 8.4.10.4) -- here a peer not yet discovered, so at the source -- and
    /// NEVER at the INFO_REPLY locator, which only a Reliable
    /// StatelessWriter reads (8.4.8.2.6). An unauthenticated INFO_REPLY
    /// cannot aim this participant's answers at a third party.
    #[test]
    fn a_heartbeat_behind_an_info_reply_is_not_answered_at_the_locator_it_names() {
        use super::super::control::ControlHandler;
        use super::super::sedp_history::SedpHistory;
        use super::super::DiscoveryFsm;
        use crate::core::discovery::multicast::control_parser::parse_all_acknack_submessages;
        use crate::core::discovery::GUID;
        use crate::core::reader::ReaderProxyRegistry;
        use crate::engine::TopicRegistry;
        use std::sync::RwLock;

        let bind = || {
            let socket = UdpSocket::bind("127.0.0.1:0").expect("bind");
            socket
                .set_read_timeout(Some(Duration::from_millis(1500)))
                .expect("read timeout");
            let address = socket.local_addr().expect("local addr");
            (socket, address)
        };
        let acknack_at = |socket: &UdpSocket| -> bool {
            let mut buf = [0u8; 512];
            socket
                .recv(&mut buf)
                .is_ok_and(|len| !parse_all_acknack_submessages(&buf[..len]).is_empty())
        };

        let lease = crate::test_support::domains::unique_domain();
        let mapping =
            crate::transport::PortMapping::calculate(lease.id(), 2).expect("port mapping");
        let transport =
            Arc::new(UdpTransport::new(lease.id(), 2, mapping).expect("test transport"));
        let handler = ControlHandler::spawn_with_topic_registry(
            transport,
            [0x40; 12],
            7400,
            ReaderProxyRegistry::new(),
            ReaderProxyRegistry::new(),
            Arc::new(TopicRegistry::new()),
            Arc::new(DiscoveryFsm::new(
                GUID::new([0x40; 12], [0, 0, 1, 0xC1]),
                30_000,
            )),
            Arc::new(RwLock::new(SedpHistory::new())),
        );
        let mut w = wiring(8);
        w.dispatch.control_tx = Some(handler.sender());

        // With an INFO_REPLY: answered at the source, not at its locator.
        let (source, source_addr) = bind();
        let (named, named_addr) = bind();
        let std::net::SocketAddr::V4(named_v4) = named_addr else {
            panic!("bound on IPv4");
        };
        w.dispatch.dispatch(
            &sedp_heartbeat(
                [0x41; 12],
                Some(info_reply_ip4(
                    named_v4.ip().octets(),
                    u32::from(named_v4.port()),
                )),
            ),
            source_addr,
        );
        assert!(acknack_at(&source), "the ACKNACK reaches the source");
        assert!(
            !acknack_at(&named),
            "and nothing reaches the INFO_REPLY locator"
        );

        // Without one (another peer): answered at the source.
        let (plain_source, plain_source_addr) = bind();
        w.dispatch
            .dispatch(&sedp_heartbeat([0x42; 12], None), plain_source_addr);
        assert!(
            acknack_at(&plain_source),
            "no INFO_REPLY: the ACKNACK reaches the datagram's source"
        );

        handler.shutdown();
    }

    /// RTPS 2.5 8.3.8.8: a submessage behind an INFO_DST naming another
    /// participant acts on none of this participant's endpoints, on the
    /// control channel as in the ring.
    #[test]
    fn a_participants_dispatch_applies_only_what_is_destined_to_it() {
        let mut w = wiring(8);
        w.dispatch.local_prefix = Some(LOCAL_PREFIX);

        w.dispatch.dispatch(
            &destined(OTHER_PREFIX, &heartbeat_datagram()),
            synthetic_source(),
        );
        w.dispatch.dispatch(
            &destined(OTHER_PREFIX, &user_data_datagram()),
            synthetic_source(),
        );
        assert!(w.control.try_recv().is_err(), "not our HEARTBEAT");
        assert!(w.ring.is_empty(), "not our DATA");
        assert_eq!(
            w.metrics.packets_received.load(Ordering::Relaxed),
            2,
            "received all the same"
        );

        w.dispatch.dispatch(
            &destined(LOCAL_PREFIX, &heartbeat_datagram()),
            synthetic_source(),
        );
        assert!(w.control.try_recv().is_ok(), "our HEARTBEAT");
        // GUIDPREFIX_UNKNOWN: the participant receiving the message.
        w.dispatch.dispatch(
            &destined([0; 12], &user_data_datagram()),
            synthetic_source(),
        );
        let (_, buffer_id) = w.ring.pop().expect("our DATA");
        w.pool.release(buffer_id).expect("release should succeed");
    }

    /// A datagram in which only part is destined here: the padded-out part
    /// must not decide what the rest is. An ACKNACK behind another
    /// participant's HEARTBEAT, and a small DATA behind another
    /// participant's DATA, still reach this participant.
    #[test]
    fn what_is_destined_here_survives_what_was_padded_out() {
        let info_dst = |prefix: [u8; 12]| {
            let mut sub = vec![0x0e, 0x01, 0x0c, 0x00];
            sub.extend_from_slice(&prefix);
            sub
        };
        let acknack = crate::protocol::builder::build_acknack_submessage(
            [0x00, 0x00, 0x01, 0x07],
            [0x00, 0x00, 0x01, 0x02],
            1,
            &[1],
            1,
        );
        let mut w = wiring(8);
        w.dispatch.local_prefix = Some(LOCAL_PREFIX);

        w.dispatch.dispatch(
            &datagram_of(&[
                info_dst(OTHER_PREFIX),
                heartbeat_to([0x00, 0x00, 0x01, 0x07]),
                info_dst(LOCAL_PREFIX),
                acknack,
            ]),
            synthetic_source(),
        );
        let kinds: Vec<_> = std::iter::from_fn(|| w.control.try_recv().ok())
            .map(|msg| msg.kind)
            .collect();
        assert_eq!(
            kinds,
            vec![super::super::control_types::ControlMessageKind::AckNack],
            "our ACKNACK, not their HEARTBEAT"
        );

        let data = user_data_datagram()[20..].to_vec();
        w.dispatch.dispatch(
            &datagram_of(&[
                info_dst(OTHER_PREFIX),
                data.clone(),
                info_dst(LOCAL_PREFIX),
                data,
            ]),
            synthetic_source(),
        );
        let (meta, buffer_id) = w.ring.pop().expect("our DATA reaches the ring");
        assert_eq!(meta.kind, PacketKind::Data);
        w.pool.release(buffer_id).expect("release should succeed");
    }

    /// A listener spawned without a participant cannot tell whose a
    /// submessage is, and hands every one on.
    #[test]
    fn a_dispatch_that_knows_no_participant_hands_every_submessage_on() {
        let w = wiring(8);
        w.dispatch.dispatch(
            &destined(OTHER_PREFIX, &heartbeat_datagram()),
            synthetic_source(),
        );
        assert!(w.control.try_recv().is_ok());
    }

    #[test]
    fn a_datagram_that_is_not_rtps_is_counted_and_routed_nowhere() {
        let w = wiring(8);

        w.dispatch
            .dispatch(b"this is not an RTPS message at all", synthetic_source());

        assert!(w.ring.is_empty(), "nothing reaches the router");
        assert!(
            w.seen
                .lock()
                .expect("the recorder mutex is never poisoned")
                .is_empty(),
            "nothing reaches discovery"
        );
        assert!(w.control.try_recv().is_err(), "nothing reaches control");
        assert_eq!(w.metrics.packets_invalid.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn a_full_ring_drops_the_datagram_and_returns_its_buffer() {
        const CAPACITY: usize = 2;
        let w = wiring(CAPACITY);
        let datagram = user_data_datagram();

        for _ in 0..CAPACITY {
            w.dispatch.dispatch(&datagram, synthetic_source());
        }
        assert_eq!(w.ring.len(), CAPACITY, "the ring is full");
        assert_eq!(w.metrics.packets_dropped.load(Ordering::Relaxed), 0);

        w.dispatch.dispatch(&datagram, synthetic_source());

        assert_eq!(w.ring.len(), CAPACITY, "the extra datagram is dropped");
        assert_eq!(
            w.metrics.packets_dropped.load(Ordering::Relaxed),
            1,
            "and the loss is counted, not silent"
        );
        // The leak this guards against only shows up under the load that
        // filled the ring: the buffer is taken from the pool on the way in,
        // and a drop that forgets to give it back starves the receive path
        // one packet at a time.
        let recovered = w
            .pool
            .acquire_for_listener()
            .expect("the dropped datagram's buffer came back to the pool");
        w.pool.release(recovered).expect("release should succeed");
    }
}

#[cfg(test)]
mod dispatch_gate_tests {
    use super::*;

    /// The plaintext dispatch set. Frozen deliberately: the OMG interop suite
    /// is calibrated against exactly these kinds, so a change here is a
    /// change to the wire behaviour of every non-secure deployment.
    ///
    /// `UnknownBuiltin` does not widen the set: the datagrams it names would
    /// otherwise arrive as `Data`, which is already here. What differs is what
    /// happens at the end of the walk - they are counted and dropped by name
    /// instead of being handed to a parser that guesses their type. A kind
    /// that does not reach the callback cannot be counted at all.
    #[test]
    fn plaintext_discovery_kinds_are_dispatched() {
        for kind in [
            PacketKind::Data,
            PacketKind::DataFrag,
            PacketKind::SPDP,
            PacketKind::SEDP,
            PacketKind::TypeLookup,
            PacketKind::Heartbeat,
            PacketKind::UnknownBuiltin,
        ] {
            assert!(
                wants_discovery_callback(kind),
                "{:?} must reach the discovery callback",
                kind
            );
        }
    }

    /// Control-plane kinds are routed through the rx ring, never the callback.
    #[test]
    fn control_kinds_are_not_dispatched() {
        for kind in [
            PacketKind::AckNack,
            PacketKind::HeartbeatFrag,
            PacketKind::Gap,
            PacketKind::InfoTs,
            PacketKind::InfoDst,
            PacketKind::Unknown,
            PacketKind::Invalid,
        ] {
            assert!(
                !wants_discovery_callback(kind),
                "{:?} must not reach the discovery callback",
                kind
            );
        }
    }

    /// With the feature ON, the two secure-builtin tunnels that have handlers
    /// must be dispatched, or the whole DDS-Security control plane stays
    /// inert.
    #[cfg(feature = "security")]
    #[test]
    fn secure_builtin_tunnels_with_handlers_are_dispatched() {
        assert!(
            wants_discovery_callback(PacketKind::Stateless),
            "the PKI-DH handshake cannot complete unless Stateless is dispatched"
        );
        assert!(
            wants_discovery_callback(PacketKind::SecureSEDP),
            "SecureSEDP must be admitted alongside Stateless or completing a \
             handshake takes SEDP down"
        );
        assert!(
            wants_discovery_callback(PacketKind::SecureVolatile),
            "a clear DATA of the volatile secure endpoints must be dispatched: \
             the discovery dispatch refuses and counts it by name"
        );
    }

    /// The whole decision, written down: every `PacketKind`, one row each,
    /// as literals.
    ///
    /// The gate has no `_` arm, so a NEW kind cannot compile without a
    /// decision. This pins WHICH decision each existing kind got, including
    /// the refusals (`NackFrag`, `InfoSrc`, `InfoReply`, `Pad`,
    /// `ParticipantMessage`): admitting any of them must turn a row red. The
    /// rows are literals on purpose - a table
    /// computed from the function would agree with it whatever it said.
    #[test]
    fn every_kind_has_a_pinned_dispatch_decision() {
        let secure_tunnels = cfg!(feature = "security");
        let table: [(PacketKind, bool); 23] = [
            (PacketKind::Data, true),
            (PacketKind::DataFrag, true),
            (PacketKind::SPDP, true),
            (PacketKind::SEDP, true),
            (PacketKind::TypeLookup, true),
            (PacketKind::Heartbeat, true),
            (PacketKind::UnknownBuiltin, true),
            (PacketKind::Stateless, secure_tunnels),
            (PacketKind::SecureSEDP, secure_tunnels),
            (PacketKind::SecureVolatile, secure_tunnels),
            (PacketKind::AckNack, false),
            (PacketKind::Gap, false),
            (PacketKind::NackFrag, false),
            (PacketKind::HeartbeatFrag, false),
            (PacketKind::InfoTs, false),
            (PacketKind::InfoSrc, false),
            (PacketKind::InfoDst, false),
            (PacketKind::InfoReply, false),
            (PacketKind::ParticipantMessage, true),
            (PacketKind::SecureSPDP, secure_tunnels),
            (PacketKind::Pad, false),
            (PacketKind::Invalid, false),
            (PacketKind::Unknown, false),
        ];
        for (kind, expected) in table {
            assert_eq!(
                wants_discovery_callback(kind),
                expected,
                "{:?}: the discovery gate's decision changed",
                kind
            );
        }
    }

    /// Without the feature the dispatch set must be the plaintext one, unchanged:
    /// no secure kind reaches the callback in a default build.
    #[cfg(not(feature = "security"))]
    #[test]
    fn default_build_dispatches_no_secure_kind() {
        assert!(!wants_discovery_callback(PacketKind::Stateless));
        assert!(!wants_discovery_callback(PacketKind::SecureSEDP));
        assert!(!wants_discovery_callback(PacketKind::SecureVolatile));
        assert!(!wants_discovery_callback(PacketKind::SecureSPDP));
    }
}
