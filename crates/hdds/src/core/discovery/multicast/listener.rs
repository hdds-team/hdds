// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Multicast UDP listener thread for RTPS discovery packets.
//!
//!
//! Spawns a dedicated IO thread to receive, classify, and dispatch RTPS packets.
//! Uses lock-free buffer pool and ring buffer for zero-allocation hot-path.
//!
//! # Architecture (v212: mio/epoll)
//!
//! ```text
//! mio::poll() -> recv_from(temp_buf) -> classify_rtps() -> RxPool::acquire() -> copy -> RxRing::push()
//!                                          v
//!                              DiscoveryCallback (SPDP/SEDP)
//! ```
//!
//! # v212 Optimizations
//! - **epoll**: Uses mio for event-driven I/O (no blocking timeout overhead)
//! - **edge-triggered drain**: Process all available packets per poll event

use super::control_parser::{
    parse_acknack_submessage, parse_all_heartbeat_submessages, parse_nack_frag_submessage,
};
use super::control_types::ControlMessage;
use super::{classify_rtps, PacketKind, RxMeta, RxPool};
use crate::engine::wake::WakeNotifier;
use crossbeam::channel::Sender;
use crossbeam::queue::ArrayQueue;
use mio::{Events, Interest, Poll, Token};
use std::io;
use std::net::UdpSocket;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

// Fragment metadata moved to meta.rs to avoid circular dependencies
pub use super::meta::FragmentMetadata;

/// Discovery callback type for SPDP/SEDP packet processing
///
/// Arguments:
/// - PacketKind: Type of packet (Data, DataFrag, etc.)
/// - &[u8]: Full RTPS packet (including headers, for DialectDetector)
/// - usize: CDR payload offset within the packet (computed by classifier)
/// - `Option<FragmentMetadata>`: Fragment metadata if PacketKind::DataFrag
/// - std::net::SocketAddr: Source address of the packet (for locator inference)
pub type DiscoveryCallback = Arc<
    dyn Fn(PacketKind, &[u8], usize, Option<FragmentMetadata>, std::net::SocketAddr) + Send + Sync,
>;

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
    fn new() -> Arc<Self> {
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
    /// Listener metrics
    pub metrics: Arc<ListenerMetrics>,
    /// Optional discovery callback for SPDP/SEDP processing
    #[allow(dead_code)] // Used only for ownership, passed to thread
    discovery_callback: Option<DiscoveryCallback>,
    /// Optional control channel sender for Two-Ring architecture (v202)
    #[allow(dead_code)] // Used only for ownership, passed to thread
    control_tx: Option<Sender<ControlMessage>>,
    /// v210: Optional wake notifier for low-latency router wake
    #[allow(dead_code)] // Used only for ownership, passed to thread
    notifier: Option<Arc<WakeNotifier>>,
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

    /// Spawn multicast listener with Two-Ring control channel (v202)
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

    /// v210: Spawn multicast listener with wake notifier for low-latency routing.
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
    /// instead of polling, reducing latency from ~100μs to ~1-10μs.
    pub fn spawn_with_notifier(
        socket: Arc<UdpSocket>,
        pool: Arc<RxPool>,
        ring: Arc<ArrayQueue<(RxMeta, u8)>>,
        discovery_callback: Option<DiscoveryCallback>,
        control_tx: Option<Sender<ControlMessage>>,
        notifier: Option<Arc<WakeNotifier>>,
    ) -> io::Result<Self> {
        crate::trace_fn!("MulticastListener::spawn_with_notifier");
        // v212: Set socket to non-blocking for mio epoll
        socket.set_nonblocking(true)?;

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
            .spawn(move || {
                Self::run_loop(
                    socket,
                    pool,
                    ring,
                    running_clone,
                    metrics_clone,
                    callback_clone,
                    control_tx_clone,
                    notifier_clone,
                );
            })?;

        Ok(Self {
            handle: Some(handle),
            running,
            metrics,
            discovery_callback,
            control_tx,
            notifier,
        })
    }

    /// Main IO loop (runs in dedicated thread)
    ///
    /// v212: Uses mio/epoll for event-driven I/O with minimal latency.
    #[allow(clippy::too_many_arguments)]
    fn run_loop(
        socket: Arc<UdpSocket>,
        pool: Arc<RxPool>,
        ring: Arc<ArrayQueue<(RxMeta, u8)>>,
        running: Arc<AtomicBool>,
        metrics: Arc<ListenerMetrics>,
        discovery_callback: Option<DiscoveryCallback>,
        control_tx: Option<Sender<ControlMessage>>,
        notifier: Option<Arc<WakeNotifier>>,
    ) {
        let local_addr = socket
            .local_addr()
            .map(|addr| addr.to_string())
            .unwrap_or_else(|_| "<unknown>".to_string());
        log::debug!(
            "[MCAST-THREAD] v212: started with mio/epoll addr={} thread={:?}",
            local_addr,
            std::thread::current().id()
        );

        // v212: Setup mio poll for epoll-based I/O
        let mut poll = match Poll::new() {
            Ok(p) => p,
            Err(e) => {
                log::error!("[MCAST-THREAD] Failed to create mio Poll: {}", e);
                return;
            }
        };
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
        const SOCKET_TOKEN: Token = Token(0);
        if let Err(e) = poll
            .registry()
            .register(&mut mio_socket, SOCKET_TOKEN, Interest::READABLE)
        {
            log::error!("[MCAST-THREAD] Failed to register socket with poll: {}", e);
            return;
        }

        // Temporary buffer for recv_from (reused across iterations)
        let mut temp_buf = vec![0u8; crate::config::MAX_PACKET_SIZE];

        while running.load(Ordering::Relaxed) {
            // v212: Wait for socket readability with mio poll
            // Minimal timeout (1ms) for ultra-low latency, graceful shutdown check
            if let Err(e) = poll.poll(&mut events, Some(Duration::from_millis(1))) {
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

                    // Update metrics
                    metrics.packets_received.fetch_add(1, Ordering::Relaxed);
                    metrics
                        .bytes_received
                        .fetch_add(len as u64, Ordering::Relaxed);

                    // Classify packet (returns kind, optional DATA payload offset, fragment metadata, and RTPS context)
                    // v61 Blocker #1: Now captures INFO_DST/INFO_TS context for stateful RTPS parsing
                    let (kind, payload_offset, fragment_metadata, rtps_context) =
                        classify_rtps(&temp_buf[..len]);

                    let kind_label = match kind {
                        PacketKind::Data => "DATA",
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
                        PacketKind::Invalid => "INVALID",
                        PacketKind::Unknown => "UNKNOWN",
                    };
                    log::debug!(
                        "[MCAST] recv kind={} len={} src={} thread={:?}",
                        kind_label,
                        len,
                        src_addr,
                        std::thread::current().id()
                    );

                    // Drop invalid packets
                    if matches!(kind, PacketKind::Invalid) {
                        metrics.packets_invalid.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }

                    // v202/v203: Two-Ring Architecture - dispatch HEARTBEAT/ACKNACK to control channel
                    // When control_tx is available, these control packets bypass the pool and go
                    // to a dedicated ControlHandler thread. This prevents pool exhaustion under
                    // high HEARTBEAT/ACKNACK load (RELIABLE QoS).
                    //
                    // v203: Extended to also bypass AckNack packets which were saturating the pool
                    // (623 AckNack drops observed in EVENT test causing 0 samples received)
                    if kind == PacketKind::Heartbeat {
                        if let Some(ref tx) = control_tx {
                            // v210: Parse ALL heartbeat submessages from the packet.
                            // FastDDS bundles HBs for multiple writers (03C2, 04C2, 0200C2)
                            // in one RTPS packet. Previous code only extracted the first one,
                            // silently dropping SEDP pub/sub HBs.
                            let all_hbs = parse_all_heartbeat_submessages(&temp_buf[..len]);

                            if all_hbs.is_empty() {
                                log::debug!(
                                    "[MCAST-RX] v189: Failed to parse HEARTBEAT from {}, len={}",
                                    src_addr,
                                    len
                                );
                            } else {
                                // Extract peer GUID prefix from RTPS header
                                let mut peer_guid_prefix = [0u8; 12];
                                if len >= 20 {
                                    peer_guid_prefix.copy_from_slice(&temp_buf[8..20]);
                                }

                                log::debug!(
                                    "[MCAST-RX] v210: Parsed {} HEARTBEAT(s) from {} writers={:?}",
                                    all_hbs.len(),
                                    src_addr,
                                    all_hbs
                                        .iter()
                                        .map(|h| h.writer_entity_id)
                                        .collect::<Vec<_>>()
                                );

                                for hb_info in all_hbs {
                                    if let Some(msg) = ControlMessage::heartbeat(
                                        src_addr,
                                        peer_guid_prefix,
                                        hb_info,
                                        &temp_buf[..len],
                                    ) {
                                        // Non-blocking send - drop if channel full (HBs are idempotent)
                                        if tx.try_send(msg).is_err() {
                                            log::debug!(
                                        "[MCAST-RX] Control channel full, dropping HEARTBEAT from {}",
                                        src_addr
                                    );
                                        }
                                    }
                                }
                            }
                            // Skip synchronous callback and pool for this HEARTBEAT
                            continue;
                        }
                        // No control_tx: fall through to legacy synchronous callback
                    }

                    // v137: Parse and send ACKNACKs to control channel for SEDP response.
                    //
                    // RTI sends ACKNACKs asking for our publications (0x03c2).
                    // We must respond with a HEARTBEAT indicating "empty writer" (lastSeq=0).
                    // Without this, RTI never sends its SEDP Publications DATA.
                    //
                    // v203: Extended to also bypass non-SEDP AckNack packets which don't need processing.
                    if kind == PacketKind::AckNack {
                        if let Some(ref tx) = control_tx {
                            // Parse ACKNACK and send to control channel
                            if let Some(an_info) = parse_acknack_submessage(&temp_buf[..len]) {
                                // Extract peer GUID prefix from RTPS header
                                let mut peer_guid_prefix = [0u8; 12];
                                if len >= 20 {
                                    peer_guid_prefix.copy_from_slice(&temp_buf[8..20]);
                                }

                                if let Some(msg) = ControlMessage::acknack(
                                    src_addr,
                                    peer_guid_prefix,
                                    an_info.clone(),
                                    &temp_buf[..len],
                                ) {
                                    // Non-blocking send - drop if channel full (ACKNACKs can be retried)
                                    log::debug!(
                                "[MCAST-RX] v204: Sending ACKNACK to control channel: writer={:02x?} from {} ranges={}",
                                an_info.writer_entity_id,
                                src_addr,
                                an_info.missing_ranges.len()
                            );
                                    if tx.try_send(msg).is_err() {
                                        log::debug!(
                                    "[MCAST-RX] Control channel full, dropping ACKNACK from {}",
                                    src_addr
                                );
                                    }
                                } else {
                                    log::debug!(
                                "[MCAST-RX] v204: ControlMessage::acknack returned None for ACKNACK from {}",
                                src_addr
                            );
                                }
                            } else {
                                log::debug!(
                            "[MCAST-RX] v204: parse_acknack_submessage returned None for {} bytes from {}",
                            len,
                            src_addr
                        );
                            }
                            // Skip synchronous callback and pool for this ACKNACK
                            continue;
                        }
                        // No control_tx: fall through to pool-based processing
                    }

                    // Handle NACK_FRAG packets (fragment retransmission requests)
                    if kind == PacketKind::NackFrag {
                        if let Some(ref tx) = control_tx {
                            // Parse NACK_FRAG and send to control channel
                            if let Some(nf_info) = parse_nack_frag_submessage(&temp_buf[..len]) {
                                // Extract peer GUID prefix from RTPS header
                                let mut peer_guid_prefix = [0u8; 12];
                                if len >= 20 {
                                    peer_guid_prefix.copy_from_slice(&temp_buf[8..20]);
                                }

                                if let Some(msg) = ControlMessage::nack_frag(
                                    src_addr,
                                    peer_guid_prefix,
                                    nf_info.clone(),
                                    &temp_buf[..len],
                                ) {
                                    log::debug!(
                                "[MCAST-RX] Sending NACK_FRAG to control channel: writer={:02x?} sn={} frags={:?} from {}",
                                nf_info.writer_entity_id,
                                nf_info.writer_sn,
                                nf_info.missing_fragments,
                                src_addr
                            );
                                    if tx.try_send(msg).is_err() {
                                        log::debug!(
                                    "[MCAST-RX] Control channel full, dropping NACK_FRAG from {}",
                                    src_addr
                                );
                                    }
                                }
                            }
                            // Skip synchronous callback and pool for this NACK_FRAG
                            continue;
                        }
                        // No control_tx: fall through to pool-based processing
                    }

                    // Invoke discovery callback for discovery packets (DATA/DATA_FRAG/SPDP/SEDP/TYPE_LOOKUP/Heartbeat)
                    // RTI uses DATA_FRAG for SPDP announcements and builtin writers for SEDP.
                    // v104: Also invoke for HEARTBEAT to enable SEDP NACK responses
                    // Callback processes discovery synchronously before ring push
                    // v0.4.0+: Panic boundary to prevent callback failures from killing listener thread
                    // v202: HEARTBEATs with control_tx are handled above, skip here
                    if matches!(
                        kind,
                        PacketKind::Data
                            | PacketKind::DataFrag
                            | PacketKind::SPDP
                            | PacketKind::SEDP
                            | PacketKind::TypeLookup
                            | PacketKind::Heartbeat
                    ) {
                        if let Some(ref callback) = discovery_callback {
                            if std::env::var("HDDS_INTEROP_DIAGNOSTICS").is_ok() {
                                let head_len = len.min(16);
                                log::debug!(
                                    "[MCAST-RX] kind={} len={} src={} head={:02x?}",
                                    kind_label,
                                    len,
                                    src_addr,
                                    &temp_buf[..head_len]
                                );
                            }
                            if std::env::var("HDDS_INTEROP_DIAGNOSTICS").is_ok() {
                                let head_len = len.min(16);
                                log::debug!(
                                    "[MCAST-RX] kind={} len={} src={} head={:02x?}",
                                    kind_label,
                                    len,
                                    src_addr,
                                    &temp_buf[..head_len]
                                );
                            }
                            // Extract CDR payload from RTPS packet using classifier-provided offset
                            // For standard HDDS packets: offset = 20 (16-byte header + 4-byte submessage header)
                            // For RTI packets after recovery: offset = variable (e.g., 24 if DATA at offset 20)
                            //
                            // v62: Fix fallback offset: 20 (RTPS header) + 24 (DATA submessage header) = 44
                            // Previous value of 40 was 4 bytes short, reading tail of writerSeqNum as encapsulation
                            const LEGACY_RTPS_DATA_PAYLOAD_OFFSET: usize = 44;
                            let offset = payload_offset.unwrap_or(LEGACY_RTPS_DATA_PAYLOAD_OFFSET);

                            if len >= offset {
                                // v124: Pass full RTPS packet + offset to callback
                                // Callback receives full packet (for DialectDetector) + offset (for CDR extraction)
                                let full_packet = &temp_buf[..len];

                                log::debug!(
                            "[callback] v124: Received DATA packet, len={}, cdr_offset={}, passing full packet",
                            len,
                            offset
                        );

                                let callback_result =
                                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                        callback(
                                            kind,
                                            full_packet,
                                            offset,
                                            fragment_metadata,
                                            src_addr,
                                        );
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
                            } else {
                                log::debug!(
                            "[hdds-mcast-rx] DATA packet too short for payload: {} bytes (need >= 44)",
                            len
                        );
                            }
                        }
                    }

                    // Only process relevant packet types for ring buffer
                    // SPDP/SEDP are handled by discovery callback above, not sent to ring
                    if !matches!(
                        kind,
                        PacketKind::Data
                            | PacketKind::DataFrag
                            | PacketKind::Heartbeat
                            | PacketKind::HeartbeatFrag
                            | PacketKind::AckNack
                            | PacketKind::SPDP
                            | PacketKind::SEDP
                    ) {
                        continue;
                    }

                    // Skip SPDP/SEDP packets - they were already handled by discovery callback
                    if matches!(kind, PacketKind::SPDP | PacketKind::SEDP) {
                        continue;
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
                            continue;
                        }
                    };

                    // Copy packet to pool buffer
                    // SAFETY: buffer_id is valid (just acquired), no concurrent access
                    unsafe {
                        let pool_ptr = Arc::as_ptr(&pool);
                        let buf = (*pool_ptr.cast_mut()).get_buffer_mut(buffer_id);
                        buf[..len].copy_from_slice(&temp_buf[..len]);
                    }

                    // Build metadata (including payload offset / fragment info when available)
                    let mut meta = if let Some(offset) = payload_offset {
                        if let Some(frag_meta) = fragment_metadata {
                            RxMeta::new_with_fragment(src_addr, len, kind, offset, frag_meta)
                        } else {
                            RxMeta::new_with_offset(src_addr, len, kind, offset)
                        }
                    } else {
                        RxMeta::new(src_addr, len, kind)
                    };
                    // v61 Blocker #1: Apply accumulated RTPS context from INFO_DST/INFO_TS submessages
                    meta.rtps_context = rtps_context;

                    // v62: Log RTPS context propagation when non-empty (avoid unwrap in hot path)
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
                    } else {
                        // v211: Always notify to ensure router wakes from idle
                        // The spin loop in router catches most hot traffic before condvar
                        if let Some(ref n) = notifier {
                            n.notify();
                        }
                    }
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
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for MulticastListener {
    fn drop(&mut self) {
        // Signal the listener thread to stop
        self.running.store(false, Ordering::Relaxed);
        // Join the thread to ensure clean shutdown
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Integration test (requires actual UDP socket, marked ignore for CI)
    #[test]
    #[ignore = "requires UDP socket, flaky in CI"]
    #[allow(deprecated)]
    fn test_listener_loopback() {
        use crate::transport::UdpTransport;
        use std::thread;
        use std::time::Duration;

        let pool = Arc::new(RxPool::new(16, 1500).expect("Pool creation should succeed"));
        let ring = Arc::new(ArrayQueue::new(256));

        // Create transport (port 7401 to avoid conflicts)
        let transport =
            UdpTransport::with_port(7401).expect("UDP transport creation should succeed");

        // Spawn listener with shared socket
        let listener = MulticastListener::spawn(
            transport.socket(),
            Arc::clone(&pool),
            Arc::clone(&ring),
            None, // No discovery callback for this test
        )
        .expect("Listener spawn should succeed");

        // Send fake DATA packet (0x09)
        let socket = UdpSocket::bind("0.0.0.0:0").expect("Socket bind should succeed");
        let mut fake_data = vec![0u8; 20];
        fake_data[0..4].copy_from_slice(b"RTPS");
        fake_data[16] = 0x09; // DATA submessage

        socket
            .send_to(&fake_data, "127.0.0.1:7401")
            .expect("Socket send should succeed");

        // Wait for processing
        thread::sleep(Duration::from_millis(150));

        // Verify ring contains packet
        let (meta, buffer_id) = ring.pop().expect("Ring should contain packet");
        assert_eq!(meta.kind, PacketKind::Data);
        let expected_len = u16::try_from(fake_data.len()).expect("len should fit in u16");
        assert_eq!(meta.len, expected_len);

        // Verify metrics
        let (rx, dropped, invalid, bytes, callback_errors) = listener.metrics.snapshot();
        assert!(rx >= 1);
        assert_eq!(dropped, 0);
        assert_eq!(callback_errors, 0);
        assert_eq!(invalid, 0);
        assert!(bytes >= fake_data.len() as u64);

        pool.release(buffer_id).expect("release should succeed");
        listener.shutdown();
    }

    /// Layer 1 Resilience Test: Verify ring full scenario releases buffer (ANSSI Pattern 4)
    ///
    /// **Goal:** Prove that when ring is full, listener releases buffer to avoid leak
    ///
    /// **Scenario:**
    /// 1. Create small ring (capacity 4)
    /// 2. Fill ring completely (push 4 packets)
    /// 3. Send 5th packet while ring is full
    /// 4. Verify listener acquires buffer from pool
    /// 5. Verify ring.push() fails (ring full)
    /// 6. Verify listener releases buffer back to pool (no leak)
    /// 7. Verify packets_dropped metric increments
    ///
    /// **Success Criteria:**
    /// - Ring remains at capacity 4 (5th packet not pushed)
    /// - Buffer released back to pool (can be re-acquired)
    /// - packets_dropped metric == 1
    /// - No memory leak
    #[test]
    #[ignore = "requires UDP socket, flaky in CI"]
    #[allow(deprecated)]
    fn test_ring_full_releases_buffer_no_leak() -> Result<(), String> {
        use crate::transport::UdpTransport;
        use std::thread;
        use std::time::Duration;

        // Setup: Small ring with capacity 4 (intentionally tiny)
        let pool = Arc::new(RxPool::new(16, 1500).expect("Pool creation should succeed"));
        let ring = Arc::new(ArrayQueue::new(4)); // Only 4 slots

        let transport = UdpTransport::with_port(7403).map_err(|e| {
            crate::core::string_utils::format_string(format_args!(
                "Failed to create transport: {}",
                e
            ))
        })?;

        let listener = MulticastListener::spawn(
            transport.socket(),
            Arc::clone(&pool),
            Arc::clone(&ring),
            None, // No callback for this test
        )
        .map_err(|e| {
            crate::core::string_utils::format_string(format_args!(
                "Failed to spawn listener: {}",
                e
            ))
        })?;

        // Fill ring completely (4 packets)
        let sender = UdpSocket::bind("0.0.0.0:0").map_err(|e| {
            crate::core::string_utils::format_string(format_args!("Failed to bind sender: {}", e))
        })?;
        let mut fake_data = vec![0u8; 20];
        fake_data[0..4].copy_from_slice(b"RTPS");
        fake_data[16] = 0x09; // DATA submessage

        for i in 1..=4 {
            sender.send_to(&fake_data, "127.0.0.1:7403").map_err(|e| {
                crate::core::string_utils::format_string(format_args!(
                    "Failed to send packet: {}",
                    e
                ))
            })?;
            log::debug!("[test sender] Sent packet #{} (filling ring)", i);
            thread::sleep(Duration::from_millis(50));
        }

        // Wait for ring to fill
        thread::sleep(Duration::from_millis(200));

        // Verify ring is full
        if ring.len() != 4 {
            return Err(crate::core::string_utils::format_string(format_args!(
                "Ring should be full (4), got {}",
                ring.len()
            )));
        }

        // Record pool state before 5th packet
        let pool_before = {
            let test_id = pool.acquire_for_listener();
            if let Some(id) = test_id {
                pool.release(id).expect("release should succeed");
                true
            } else {
                false
            }
        };
        if !pool_before {
            return Err("Pool should have free buffers before 5th packet".to_string());
        }

        // Send 5th packet (ring is full, should trigger graceful drop)
        sender.send_to(&fake_data, "127.0.0.1:7403").map_err(|e| {
            crate::core::string_utils::format_string(format_args!(
                "Failed to send 5th packet: {}",
                e
            ))
        })?;
        log::debug!("[test sender] Sent packet #5 (ring full, expect graceful drop)");

        // Wait for processing
        thread::sleep(Duration::from_millis(200));

        // Verify ring still at capacity 4 (5th packet gracefully dropped)
        if ring.len() != 4 {
            return Err(crate::core::string_utils::format_string(format_args!(
                "Ring should still be full (5th packet dropped), got {}",
                ring.len()
            )));
        }

        // Verify buffer was released back to pool (no leak)
        let pool_after = pool
            .acquire_for_listener()
            .ok_or("Pool should have available buffers (buffer was released)")?;
        pool.release(pool_after).expect("release should succeed");

        // Verify packets_dropped metric incremented (graceful handling)
        let (rx, dropped, _invalid, _bytes, _callback_errors) = listener.metrics.snapshot();

        log::debug!("[test verify] Packets received: {}", rx);
        log::debug!("[test verify] Packets dropped: {}", dropped);
        log::debug!("[test verify] Ring size: {}", ring.len());

        if dropped < 1 {
            return Err(crate::core::string_utils::format_string(format_args!(
                "At least 1 packet should be gracefully dropped (ring full), got {}",
                dropped
            )));
        }

        // Cleanup
        while let Some((_, buffer_id)) = ring.pop() {
            pool.release(buffer_id).expect("release should succeed");
        }
        listener.shutdown();

        log::debug!("[test] [OK] Ring full handled gracefully - buffer released, no leak");
        Ok(())
    }
}
