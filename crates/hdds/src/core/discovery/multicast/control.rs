// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Two-Ring Architecture: Control Channel for RTPS protocol messages.
//!
//!
//! This module implements the "cold path" for RTPS control messages (HEARTBEAT,
//! ACKNACK, GAP) that are separated from the "hot path" user data flow.
//!
//! # Architecture
//!
//! ```text
//! +-------------------------------------------------------------+
//! |                     MulticastListener                        |
//! |  recv_from() -> classify_packet() -> dispatch                 |
//! +-----------------+----------------------+--------------------+
//!                   |                      |
//!          +--------v--------+    +--------v--------+
//!          |   DATA Ring     |    |  Control Channel |
//!          | (hot path)      |    | (cold path)      |
//!          | Pool-backed     |    | Stack buffer     |
//!          +--------+--------+    +--------+---------+
//!                   |                      |
//!          +--------v--------+    +--------v---------+
//!          |  DemuxRouter    |    | ControlHandler   |
//!          | -> topic queues  |    | HB batching      |
//!          +-----------------+    | ACKNACK response |
//!                                 +------------------+
//! ```
//!
//! # Benefits
//!
//! - DATA packets never blocked by HEARTBEAT processing
//! - Control messages use stack buffers (no pool allocation)
//! - Bounded channel with backpressure (old HBs dropped)
//! - Batched ACKNACK responses reduce network traffic
//!
//! # RTPS v2.5 Compliance
//!
//! Per RTPS v2.5 Sec.8.3.7.5, HEARTBEAT flags:
//! - Bit 1 (0x02): FinalFlag - writer expects ACKNACK response
//! - Bit 2 (0x04): LivelinessFlag - liveliness assertion only
//!
//! We respond to HEARTBEATs with FinalFlag=1, batch others.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crossbeam::channel::{self, Receiver, Sender, TrySendError};

use crate::core::discovery::multicast::DiscoveryFsm;
use crate::core::reader::{AcknackDecision, ReaderProxyRegistry};
use crate::core::writer::MatchedReadersRegistry;
use crate::engine::TopicRegistry;
use crate::protocol::builder::{build_acknack_packet, build_acknack_packet_with_final};
use crate::protocol::dialect::Dialect;
use crate::protocol::discovery::SedpData;
use crate::transport::UdpTransport;

use super::rtps_packet::{build_sedp_rtps_packet, SedpEndpointKind};

/// SEDP announcements cache — stores local endpoints for retransmission on NACK.
/// Mirrors entity_registry::SedpAnnouncementsCache but avoids pub(super) visibility issue.
type SedpCache = Arc<RwLock<Vec<(SedpData, SedpEndpointKind)>>>;

// Import from refactored modules
use super::control_builder::build_unknown80_locator;
use super::control_metrics::ControlMetrics;
use super::control_types::{ControlMessage, HeartbeatInfo, WriterState};

/// Control channel capacity (bounded to prevent memory explosion)
const CONTROL_CHANNEL_CAPACITY: usize = 1024;

/// Batch flush interval (milliseconds)
const BATCH_FLUSH_INTERVAL_MS: u64 = 50;

/// Maximum HEARTBEATs to batch before flushing
const BATCH_MAX_SIZE: usize = 10;

/// Control handler thread - processes HEARTBEAT/ACKNACK/GAP messages
pub struct ControlHandler {
    /// Thread join handle
    handle: Option<JoinHandle<()>>,
    /// Running flag for graceful shutdown
    running: Arc<AtomicBool>,
    /// Channel sender (for listener to push messages)
    sender: Sender<ControlMessage>,
    /// Metrics
    pub metrics: Arc<ControlMetrics>,
    /// v150: Shared SEDP Reader proxy registry for DATA notification
    pub sedp_registry: ReaderProxyRegistry,
    /// v178: Shared SEDP Writer registry for multi-reader ACKNACK tracking
    /// Enables 1-pub->N-sub scenarios (e.g., 1 command center -> 36 vehicles)
    pub sedp_writer_registry: MatchedReadersRegistry,
    /// v201: Topic registry for user data ACKNACK dispatch to WriterNackHandler
    /// Enables RELIABLE retransmission on publisher side
    #[allow(dead_code)]
    topic_registry: Option<Arc<TopicRegistry>>,
}

impl ControlHandler {
    /// Spawn control handler thread
    ///
    /// # Arguments
    /// - `transport`: UDP transport for sending ACKNACK responses
    /// - `our_guid_prefix`: Our participant GUID prefix (12 bytes)
    /// - `peer_metatraffic_port`: Default peer metatraffic port (e.g., 7410)
    ///
    /// # Returns
    /// ControlHandler with shared sedp_registry for DATA notification
    pub fn spawn(
        transport: Arc<UdpTransport>,
        our_guid_prefix: [u8; 12],
        peer_metatraffic_port: u16,
        discovery_fsm: Arc<DiscoveryFsm>,
    ) -> Self {
        let (sender, receiver) = channel::bounded(CONTROL_CHANNEL_CAPACITY);
        let running = Arc::new(AtomicBool::new(true));
        let metrics = Arc::new(ControlMetrics::new());

        // v150: Create shared registry for SEDP Reader state tracking.
        let sedp_registry = ReaderProxyRegistry::new();
        let registry_clone = sedp_registry.clone();

        // v178: Create shared registry for SEDP Writer state tracking.
        let sedp_writer_registry = MatchedReadersRegistry::new();

        let running_clone = Arc::clone(&running);
        let metrics_clone = Arc::clone(&metrics);

        #[allow(clippy::expect_used)] // thread spawn failure is unrecoverable
        let handle = std::thread::Builder::new()
            .name("hdds-control".to_string())
            .spawn(move || {
                Self::run_loop(
                    receiver,
                    transport,
                    our_guid_prefix,
                    peer_metatraffic_port,
                    running_clone,
                    metrics_clone,
                    registry_clone,
                    None,
                    discovery_fsm,
                    Arc::new(RwLock::new(Vec::new())), // No SEDP cache in basic mode
                );
            })
            .expect("Failed to spawn control handler thread");

        Self {
            handle: Some(handle),
            running,
            sender,
            metrics,
            sedp_registry,
            sedp_writer_registry,
            topic_registry: None,
        }
    }

    /// v150: Spawn control handler thread with external SEDP registry.
    pub fn spawn_with_registry(
        transport: Arc<UdpTransport>,
        our_guid_prefix: [u8; 12],
        peer_metatraffic_port: u16,
        sedp_registry: ReaderProxyRegistry,
        discovery_fsm: Arc<DiscoveryFsm>,
    ) -> Self {
        let (sender, receiver) = channel::bounded(CONTROL_CHANNEL_CAPACITY);
        let running = Arc::new(AtomicBool::new(true));
        let metrics = Arc::new(ControlMetrics::new());

        let registry_clone = sedp_registry.clone();
        let sedp_writer_registry = MatchedReadersRegistry::new();

        let running_clone = Arc::clone(&running);
        let metrics_clone = Arc::clone(&metrics);

        #[allow(clippy::expect_used)] // thread spawn failure is unrecoverable
        let handle = std::thread::Builder::new()
            .name("hdds-control".to_string())
            .spawn(move || {
                Self::run_loop(
                    receiver,
                    transport,
                    our_guid_prefix,
                    peer_metatraffic_port,
                    running_clone,
                    metrics_clone,
                    registry_clone,
                    None,
                    discovery_fsm,
                    Arc::new(RwLock::new(Vec::new())), // No SEDP cache in basic mode
                );
            })
            .expect("Failed to spawn control handler thread");

        Self {
            handle: Some(handle),
            running,
            sender,
            metrics,
            sedp_registry,
            sedp_writer_registry,
            topic_registry: None,
        }
    }

    /// v201: Spawn control handler thread with SEDP registry AND topic registry.
    pub fn spawn_with_topic_registry(
        transport: Arc<UdpTransport>,
        our_guid_prefix: [u8; 12],
        peer_metatraffic_port: u16,
        sedp_registry: ReaderProxyRegistry,
        topic_registry: Arc<TopicRegistry>,
        discovery_fsm: Arc<DiscoveryFsm>,
        sedp_cache: SedpCache,
    ) -> Self {
        let (sender, receiver) = channel::bounded(CONTROL_CHANNEL_CAPACITY);
        let running = Arc::new(AtomicBool::new(true));
        let metrics = Arc::new(ControlMetrics::new());

        let registry_clone = sedp_registry.clone();
        let topic_registry_clone = Arc::clone(&topic_registry);
        let sedp_writer_registry = MatchedReadersRegistry::new();

        let running_clone = Arc::clone(&running);
        let metrics_clone = Arc::clone(&metrics);

        #[allow(clippy::expect_used)] // thread spawn failure is unrecoverable
        let handle = std::thread::Builder::new()
            .name("hdds-control".to_string())
            .spawn(move || {
                Self::run_loop(
                    receiver,
                    transport,
                    our_guid_prefix,
                    peer_metatraffic_port,
                    running_clone,
                    metrics_clone,
                    registry_clone,
                    Some(topic_registry_clone),
                    discovery_fsm,
                    sedp_cache,
                );
            })
            .expect("Failed to spawn control handler thread");

        Self {
            handle: Some(handle),
            running,
            sender,
            metrics,
            sedp_registry,
            sedp_writer_registry,
            topic_registry: Some(topic_registry),
        }
    }

    /// Get sender for pushing control messages from listener
    pub fn sender(&self) -> Sender<ControlMessage> {
        self.sender.clone()
    }

    /// Try to send a control message (non-blocking)
    ///
    /// Returns false if channel is full (message dropped)
    pub fn try_send(&self, msg: ControlMessage) -> bool {
        match self.sender.try_send(msg) {
            Ok(()) => {
                self.metrics
                    .messages_received
                    .fetch_add(1, Ordering::Relaxed);
                true
            }
            Err(TrySendError::Full(_)) => {
                self.metrics
                    .messages_dropped
                    .fetch_add(1, Ordering::Relaxed);
                false
            }
            Err(TrySendError::Disconnected(_)) => {
                log::debug!("[CONTROL] Channel disconnected");
                false
            }
        }
    }

    /// v207: Resolve peer's actual metatraffic unicast address from SPDP data.
    ///
    /// FastDDS 2.x sends HEARTBEATs from ephemeral source ports, not from
    /// the metatraffic unicast port. We must look up the peer's real port
    /// from the SPDP discovery data stored in the DiscoveryFsm.
    fn resolve_peer_metatraffic_port(
        peer_guid_prefix: &[u8; 12],
        src_addr: SocketAddr,
        fsm: &DiscoveryFsm,
    ) -> u16 {
        let db = fsm.db();
        if let Ok(guard) = db.read() {
            for (guid, info) in guard.iter() {
                if &guid.as_bytes()[..12] == peer_guid_prefix {
                    for ep in &info.endpoints {
                        if ep.ip() == src_addr.ip() {
                            log::debug!(
                                "[CONTROL] v207: Resolved peer metatraffic port {} from SPDP (prefix={:02x?})",
                                ep.port(), &peer_guid_prefix[..4]
                            );
                            return ep.port();
                        }
                    }
                    if let Some(ep) = info.endpoints.first() {
                        log::debug!(
                            "[CONTROL] v207: Using first peer metatraffic port {} (prefix={:02x?})",
                            ep.port(),
                            &peer_guid_prefix[..4]
                        );
                        return ep.port();
                    }
                }
            }
        }
        log::debug!(
            "[CONTROL] v207: Peer not found in FSM, using src port {} (prefix={:02x?})",
            src_addr.port(),
            &peer_guid_prefix[..4]
        );
        src_addr.port()
    }

    /// Main control loop
    #[allow(clippy::too_many_arguments)] // RTPS control loop - parameters are protocol-mandated
    fn run_loop(
        receiver: Receiver<ControlMessage>,
        transport: Arc<UdpTransport>,
        our_guid_prefix: [u8; 12],
        _default_peer_port: u16,
        running: Arc<AtomicBool>,
        metrics: Arc<ControlMetrics>,
        sedp_registry: ReaderProxyRegistry,
        topic_registry: Option<Arc<TopicRegistry>>,
        discovery_fsm: Arc<DiscoveryFsm>,
        sedp_cache: SedpCache,
    ) {
        log::debug!("[CONTROL] Control handler thread started");

        let mut acknack_count: u32 = 1;
        let mut batch: std::collections::HashMap<[u8; 16], WriterState> =
            std::collections::HashMap::new();
        let mut last_flush = Instant::now();
        let user_data_registry = ReaderProxyRegistry::new();
        let flush_interval = Duration::from_millis(BATCH_FLUSH_INTERVAL_MS);

        // v207: Track endpoint count per SEDP writer for stable HEARTBEAT range.
        // HEARTBEAT always uses first=1, last=count (fixed positional seq nums).
        let mut effective_pub_first: u64 = 1; // Publications: Writer endpoint count
        let mut effective_sub_first: u64 = 1; // Subscriptions: Reader endpoint count

        while running.load(Ordering::Relaxed) {
            match receiver.recv_timeout(Duration::from_millis(10)) {
                Ok(msg) => {
                    // Skip our own messages (multicast loopback)
                    if msg.peer_guid_prefix == our_guid_prefix {
                        continue;
                    }

                    if let Some(ref hb) = msg.heartbeat {
                        let mut writer_guid = [0u8; 16];
                        writer_guid[..12].copy_from_slice(&msg.peer_guid_prefix);
                        writer_guid[12..16].copy_from_slice(&hb.writer_entity_id);

                        // v207: Resolve peer's actual metatraffic port from SPDP data.
                        // FastDDS 2.x sends HEARTBEATs from ephemeral source ports,
                        // so msg.src_addr.port() would be wrong for ACKNACK destination.
                        let peer_port = Self::resolve_peer_metatraffic_port(
                            &msg.peer_guid_prefix,
                            msg.src_addr,
                            &discovery_fsm,
                        );

                        if is_sedp_endpoint(&hb.writer_entity_id) {
                            let decision = sedp_registry.on_heartbeat(
                                writer_guid,
                                hb.first_seq,
                                hb.last_seq,
                                hb.count,
                                hb.final_flag,
                            );

                            match decision {
                                AcknackDecision::Ignore | AcknackDecision::RateLimited => {}
                                AcknackDecision::Synchronized { bitmap_base } => {
                                    Self::send_sedp_acknack(
                                        &transport,
                                        our_guid_prefix,
                                        &msg.peer_guid_prefix,
                                        &hb.writer_entity_id,
                                        peer_port,
                                        msg.src_addr.ip(),
                                        &metrics,
                                        bitmap_base,
                                        true,
                                        &mut acknack_count,
                                    );
                                    sedp_registry.mark_acknack_sent(&writer_guid);
                                }
                                AcknackDecision::NeedData { bitmap_base } => {
                                    Self::send_sedp_acknack(
                                        &transport,
                                        our_guid_prefix,
                                        &msg.peer_guid_prefix,
                                        &hb.writer_entity_id,
                                        peer_port,
                                        msg.src_addr.ip(),
                                        &metrics,
                                        bitmap_base,
                                        false,
                                        &mut acknack_count,
                                    );
                                    sedp_registry.mark_acknack_sent(&writer_guid);
                                }
                            }
                            continue;
                        }

                        if hb.final_flag {
                            metrics.heartbeats_final.fetch_add(1, Ordering::Relaxed);
                            Self::send_acknack(
                                &transport,
                                our_guid_prefix,
                                &msg,
                                hb,
                                peer_port,
                                &mut acknack_count,
                                &metrics,
                            );
                        } else {
                            metrics.heartbeats_batched.fetch_add(1, Ordering::Relaxed);
                            let state = batch.entry(writer_guid).or_insert(WriterState {
                                first_seq: hb.first_seq,
                                highest_seq: hb.last_seq,
                                last_count: hb.count,
                                peer_ip: msg.src_addr.ip(),
                                peer_port,
                                peer_guid_prefix: msg.peer_guid_prefix,
                            });

                            if hb.first_seq > state.first_seq {
                                state.first_seq = hb.first_seq;
                            }
                            if hb.last_seq > state.highest_seq {
                                state.highest_seq = hb.last_seq;
                            }
                            state.last_count = hb.count;
                            state.peer_ip = msg.src_addr.ip();
                        }
                    } else if let Some(ref an) = msg.acknack {
                        if is_sedp_endpoint(&an.writer_entity_id) {
                            // v207: Resolve peer metatraffic port for HB response
                            let an_peer_port = Self::resolve_peer_metatraffic_port(
                                &msg.peer_guid_prefix,
                                msg.src_addr,
                                &discovery_fsm,
                            );

                            // v210: Only retransmit + HEARTBEAT when peer NACKs (missing data).
                            // Pure ACK (ranges=0) means peer received everything — no response needed.
                            // Previous bug: HEARTBEAT was sent for EVERY ACKNACK, creating
                            // a HB/ACKNACK loop that prevented FastDDS from starting its own SEDP.
                            if !an.missing_ranges.is_empty() {
                                if let Some(count) = Self::retransmit_sedp_data(
                                    &transport,
                                    our_guid_prefix,
                                    &msg.peer_guid_prefix,
                                    &an.writer_entity_id,
                                    an_peer_port,
                                    msg.src_addr.ip(),
                                    &sedp_cache,
                                    &metrics,
                                ) {
                                    // Track endpoint count for HEARTBEAT range
                                    if an.writer_entity_id == [0x00, 0x00, 0x03, 0xC2] {
                                        effective_pub_first = count;
                                    } else {
                                        effective_sub_first = count;
                                    }
                                }

                                // HEARTBEAT with fixed range first=1, last=N (only after NACK retransmit)
                                let hb_last = if an.writer_entity_id == [0x00, 0x00, 0x03, 0xC2] {
                                    effective_pub_first as i64
                                } else {
                                    effective_sub_first as i64
                                };
                                Self::send_sedp_heartbeat_response(
                                    &transport,
                                    our_guid_prefix,
                                    &msg.peer_guid_prefix,
                                    &an.writer_entity_id,
                                    an_peer_port,
                                    msg.src_addr.ip(),
                                    &metrics,
                                    1,       // first_seq always 1 (fixed)
                                    hb_last, // last_seq = endpoint count
                                    &mut acknack_count,
                                );
                            } else {
                                log::debug!(
                                    "[CONTROL] v210: SEDP ACKNACK pure-ACK from {:?} writer={:02x?} — no HB response",
                                    msg.src_addr.ip(), an.writer_entity_id
                                );
                            }
                        } else if let Some(ref registry) = topic_registry {
                            if !an.missing_ranges.is_empty() {
                                let nack_msg = crate::reliability::NackMsg::from_ranges(
                                    an.missing_ranges.clone(),
                                );
                                let nack_bytes = nack_msg.encode_cdr2_le();
                                let _ = registry.deliver_nack(&nack_bytes);
                            }
                        }
                    } else if let Some(ref nf) = msg.nack_frag {
                        // Handle NACK_FRAG: Request for fragment retransmission
                        // Dispatch to topic registry for writer-side handling
                        if let Some(ref registry) = topic_registry {
                            if !nf.missing_fragments.is_empty() {
                                log::debug!(
                                    "[CONTROL] NACK_FRAG: writer={:02x?} sn={} missing_frags={:?}",
                                    nf.writer_entity_id,
                                    nf.writer_sn,
                                    nf.missing_fragments
                                );
                                let _ = registry.deliver_nack_frag(
                                    &nf.writer_entity_id,
                                    nf.writer_sn,
                                    &nf.missing_fragments,
                                );
                            }
                        }
                    }
                }
                Err(channel::RecvTimeoutError::Timeout) => {}
                Err(channel::RecvTimeoutError::Disconnected) => {
                    log::debug!("[CONTROL] Channel disconnected, exiting");
                    break;
                }
            }

            // Flush batch if interval elapsed or batch is large
            if last_flush.elapsed() >= flush_interval || batch.len() >= BATCH_MAX_SIZE {
                if !batch.is_empty() {
                    for (writer_guid, state) in batch.drain() {
                        #[allow(clippy::unwrap_used)]
                        // slice is exactly 4 bytes from a 16-byte GUID
                        let writer_entity_id: [u8; 4] = writer_guid[12..16].try_into().unwrap();

                        if is_sedp_endpoint(&writer_entity_id) {
                            continue;
                        }

                        let reader_entity_id = derive_reader_entity_id(&writer_entity_id);

                        let decision = user_data_registry.on_heartbeat(
                            writer_guid,
                            state.first_seq,
                            state.highest_seq,
                            state.last_count,
                            false,
                        );

                        let (seq_base, missing_seqs, final_flag) = match decision {
                            AcknackDecision::Ignore | AcknackDecision::RateLimited => continue,
                            AcknackDecision::Synchronized { bitmap_base } => {
                                (bitmap_base.max(1) as u64, vec![], true)
                            }
                            AcknackDecision::NeedData { bitmap_base } => (
                                bitmap_base.max(1) as u64,
                                vec![bitmap_base.max(1) as u64],
                                false,
                            ),
                        };

                        user_data_registry.mark_acknack_sent(&writer_guid);

                        let acknack = build_acknack_packet_with_final(
                            our_guid_prefix,
                            state.peer_guid_prefix,
                            reader_entity_id,
                            writer_entity_id,
                            seq_base,
                            &missing_seqs,
                            acknack_count,
                            final_flag,
                        );
                        acknack_count = acknack_count.wrapping_add(1);

                        let dest_addr = SocketAddr::new(state.peer_ip, state.peer_port);

                        if transport.send_to_endpoint(&acknack, &dest_addr).is_ok() {
                            metrics.acknacks_sent.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    // Shrink HashMap capacity to avoid memory accumulation
                    batch.shrink_to_fit();
                }
                last_flush = Instant::now();
            }
        }

        log::debug!("[CONTROL] Control handler thread exiting");
    }

    /// Send ACKNACK response to a HEARTBEAT
    fn send_acknack(
        transport: &UdpTransport,
        our_guid_prefix: [u8; 12],
        msg: &ControlMessage,
        hb: &HeartbeatInfo,
        peer_port: u16,
        acknack_count: &mut u32,
        metrics: &ControlMetrics,
    ) {
        let reader_entity_id = derive_reader_entity_id(&hb.writer_entity_id);

        if is_sedp_endpoint(&hb.writer_entity_id) {
            return;
        }

        let seq_base = hb.first_seq.max(1) as u64;
        let missing_seqs: Vec<u64> = vec![];

        let acknack = build_acknack_packet(
            our_guid_prefix,
            msg.peer_guid_prefix,
            reader_entity_id,
            hb.writer_entity_id,
            seq_base,
            &missing_seqs,
            *acknack_count,
        );
        *acknack_count = acknack_count.wrapping_add(1);

        let dest_addr = SocketAddr::new(msg.src_addr.ip(), peer_port);

        if transport.send_to_endpoint(&acknack, &dest_addr).is_ok() {
            metrics.acknacks_sent.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Send ACKNACK for SEDP endpoint
    #[allow(clippy::too_many_arguments)]
    fn send_sedp_acknack(
        transport: &UdpTransport,
        our_guid_prefix: [u8; 12],
        peer_guid_prefix: &[u8; 12],
        their_writer_id: &[u8; 4],
        peer_port: u16,
        peer_ip: std::net::IpAddr,
        metrics: &ControlMetrics,
        bitmap_base: i64,
        final_flag: bool,
        acknack_count: &mut u32,
    ) {
        let our_reader_id = derive_reader_entity_id(their_writer_id);
        let dest_addr = SocketAddr::new(peer_ip, peer_port);

        let seq_base = bitmap_base.max(1) as u64;
        let missing_seqs: Vec<u64> = if final_flag { vec![] } else { vec![seq_base] };

        let acknack = build_acknack_packet_with_final(
            our_guid_prefix,
            *peer_guid_prefix,
            our_reader_id,
            *their_writer_id,
            seq_base,
            &missing_seqs,
            *acknack_count,
            final_flag,
        );
        *acknack_count = acknack_count.wrapping_add(1);

        match transport.send_to_endpoint(&acknack, &dest_addr) {
            Ok(_) => {
                metrics.acknacks_sent.fetch_add(1, Ordering::Relaxed);
                log::debug!(
                    "[CONTROL] v210: Sent SEDP ACKNACK to {}:{} writer={:02x?} base={} final={} missing={}",
                    peer_ip, peer_port, their_writer_id, seq_base, final_flag, missing_seqs.len()
                );
            }
            Err(e) => {
                log::debug!(
                    "[CONTROL] v210: Failed SEDP ACKNACK to {}:{} writer={:02x?}: {}",
                    peer_ip,
                    peer_port,
                    their_writer_id,
                    e
                );
            }
        }
    }

    /// Send HEARTBEAT response for SEDP endpoints.
    ///
    /// v207: When first_seq > 0, use the provided range (from retransmission).
    /// This tells FastDDS that seq nums below first_seq are no longer available,
    /// preventing infinite NACK loops for old seq nums.
    #[allow(clippy::too_many_arguments)]
    fn send_sedp_heartbeat_response(
        transport: &UdpTransport,
        our_guid_prefix: [u8; 12],
        peer_guid_prefix: &[u8; 12],
        their_writer_id: &[u8; 4],
        peer_port: u16,
        peer_ip: std::net::IpAddr,
        metrics: &ControlMetrics,
        retransmit_first: i64,
        retransmit_last: i64,
        _acknack_count: &mut u32,
    ) {
        use crate::protocol::dialect::{get_encoder, Dialect};
        use crate::protocol::rtps::encode_heartbeat_final;

        let our_writer_id = *their_writer_id;
        let their_reader_id = derive_reader_entity_id(their_writer_id);
        let dest_addr = SocketAddr::new(peer_ip, peer_port);

        let encoder = get_encoder(Dialect::Hybrid);
        let mut packet = Vec::with_capacity(128);

        // RTPS Header
        packet.extend_from_slice(b"RTPS");
        packet.extend_from_slice(&[2, 4]);
        packet.extend_from_slice(&[0x01, 0xaa]);
        packet.extend_from_slice(&our_guid_prefix);

        // INFO_DST submessage
        let info_dst = encoder.build_info_dst(peer_guid_prefix);
        packet.extend_from_slice(&info_dst);

        // v207: Use retransmitted range if provided, otherwise fall back to counters.
        // CRITICAL: first_seq MUST match the actual DATA we sent, otherwise
        // FastDDS keeps NACKing old (non-existent) seq nums in an infinite loop.
        let (first_seq, last_seq) = if retransmit_first > 0 {
            (retransmit_first as u64, retransmit_last as u64)
        } else {
            use super::rtps_packet::{get_publications_last_seq, get_subscriptions_last_seq};
            let last = if our_writer_id == [0x00, 0x00, 0x04, 0xC2] {
                get_subscriptions_last_seq()
            } else if our_writer_id == [0x00, 0x00, 0x03, 0xC2] {
                get_publications_last_seq()
            } else {
                0
            };
            (1, last)
        };

        log::debug!(
            "[CONTROL] v207: Sending SEDP HEARTBEAT first={} last={} to {}:{}",
            first_seq,
            last_seq,
            peer_ip,
            peer_port
        );

        if let Ok(heartbeat) =
            encode_heartbeat_final(&their_reader_id, &our_writer_id, first_seq, last_seq, 1)
        {
            packet.extend_from_slice(&heartbeat);

            let unknown80 = build_unknown80_locator(peer_ip, peer_port);
            packet.extend_from_slice(&unknown80);

            if transport.send_to_endpoint(&packet, &dest_addr).is_ok() {
                metrics.acknacks_sent.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// v207: Retransmit SEDP DATA to peer that NACKed our SEDP writer.
    ///
    /// Uses FIXED positional sequence numbers (1-based cache index) instead of
    /// the global atomic counter. This is critical for multi-peer interop:
    /// with 5 FastDDS participants each NACKing, allocating new seq nums per-peer
    /// causes an infinite escalation (peer A's retransmit invalidates peer B's
    /// HEARTBEAT range, causing peer B to re-NACK, ad infinitum).
    ///
    /// Returns `Some(count)` = number of endpoints retransmitted, or `None`.
    #[allow(clippy::too_many_arguments)]
    fn retransmit_sedp_data(
        transport: &UdpTransport,
        our_guid_prefix: [u8; 12],
        peer_guid_prefix: &[u8; 12],
        writer_entity_id: &[u8; 4],
        peer_port: u16,
        peer_ip: std::net::IpAddr,
        sedp_cache: &SedpCache,
        metrics: &ControlMetrics,
    ) -> Option<u64> {
        // Determine which endpoint kind to retransmit based on writer entity ID
        let target_kind = if *writer_entity_id == [0x00, 0x00, 0x03, 0xC2] {
            SedpEndpointKind::Writer // Publications writer -> retransmit Writer endpoints
        } else if *writer_entity_id == [0x00, 0x00, 0x04, 0xC2] {
            SedpEndpointKind::Reader // Subscriptions writer -> retransmit Reader endpoints
        } else {
            return None;
        };

        let cache_guard = match sedp_cache.read() {
            Ok(g) => g,
            Err(e) => {
                log::debug!("[CONTROL] v207: Failed to read SEDP cache: {}", e);
                return None;
            }
        };

        if cache_guard.is_empty() {
            log::debug!("[CONTROL] v207: SEDP cache empty, nothing to retransmit");
            return None;
        }

        let dest_addr = SocketAddr::new(peer_ip, peer_port);
        let mut sent = 0u64;

        // Use FIXED positional seq nums: endpoint[0] = seq 1, endpoint[1] = seq 2, etc.
        // This is stable across all peers and all retransmission rounds.
        let mut pos = 0u64;
        for (sd, kind) in cache_guard.iter() {
            if *kind != target_kind {
                continue;
            }
            pos += 1;
            let seq_num = pos; // Fixed: always 1, 2, 3, ...

            match build_sedp_rtps_packet(
                sd,
                *kind,
                &our_guid_prefix,
                Some(peer_guid_prefix),
                seq_num,
                Dialect::Hybrid,
            ) {
                Ok(pkt) => {
                    if transport.send_to_endpoint(&pkt, &dest_addr).is_ok() {
                        sent += 1;
                        metrics.acknacks_sent.fetch_add(1, Ordering::Relaxed);
                    }
                }
                Err(e) => {
                    log::debug!(
                        "[CONTROL] v207: Failed to build SEDP retransmit packet: {:?}",
                        e
                    );
                }
            }
        }

        if sent > 0 {
            log::debug!(
                "[CONTROL] v207: Retransmitted {} SEDP {:?} DATA(s) seq=1..{} to {} (fixed seq)",
                sent,
                target_kind,
                sent,
                dest_addr
            );
            Some(sent)
        } else {
            None
        }
    }

    /// Shutdown control handler gracefully
    pub fn shutdown(mut self) {
        self.running.store(false, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for ControlHandler {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Check if writer entity ID is an SEDP endpoint (built-in discovery).
fn is_sedp_endpoint(writer_id: &[u8; 4]) -> bool {
    let kind = writer_id[3];
    (kind == 0xC2 || kind == 0xC3) && writer_id[0] == 0x00 && writer_id[1] == 0x00
}

/// Derive reader entity ID from writer entity ID
fn derive_reader_entity_id(writer_id: &[u8; 4]) -> [u8; 4] {
    let mut reader_id = *writer_id;
    reader_id[3] = match writer_id[3] {
        0x02 => 0x04,
        0x03 => 0x07,
        0xC2 => 0xC7,
        0xC3 => 0xC7,
        _ => 0x04,
    };
    reader_id
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_reader_entity_id() {
        assert_eq!(
            derive_reader_entity_id(&[0x00, 0x00, 0x01, 0x02]),
            [0x00, 0x00, 0x01, 0x04]
        );
        assert_eq!(
            derive_reader_entity_id(&[0x00, 0x00, 0x01, 0x03]),
            [0x00, 0x00, 0x01, 0x07]
        );
        assert_eq!(
            derive_reader_entity_id(&[0x00, 0x00, 0x03, 0xC2]),
            [0x00, 0x00, 0x03, 0xC7]
        );
    }

    #[test]
    fn test_is_sedp_endpoint() {
        assert!(is_sedp_endpoint(&[0x00, 0x00, 0x03, 0xC2]));
        assert!(is_sedp_endpoint(&[0x00, 0x00, 0x04, 0xC2]));
        assert!(!is_sedp_endpoint(&[0x00, 0x00, 0x01, 0x02]));
    }
}
