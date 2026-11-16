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
use crate::protocol::builder::build_acknack_packet_with_final;
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
    #[allow(clippy::similar_names)] // effective_pub_first / effective_sub_first are intentionally parallel
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
        // Reception watermarks live in the TopicRegistry so the router's delivery
        // path feeds them; a thread-local registry would never see a sample and
        // every ACKNACK would keep saying "expecting sample 1".
        let user_data_registry = topic_registry
            .as_ref()
            .map(|reg| reg.user_reader_proxies().clone())
            .unwrap_or_default();
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

                        // Seed the per-writer reorder gate so any sample that
                        // arrived in arrival order during discovery can now be
                        // released in writer-seq order (RTPS v2.5 §8.3.7.5
                        // `firstSN`). No-op for VOLATILE readers (gate
                        // disabled) and for SEDP writers (no user-data subs).
                        // Reject malformed HEARTBEATs: per RTPS v2.5 §9.3.2
                        // `firstSN` is `SequenceNumber_t` and MUST be > 0;
                        // silently seeding from a negative or zero value
                        // would let a buggy/adversarial peer fabricate a
                        // delivery baseline and release buffered samples
                        // out of order.
                        if !is_sedp_endpoint(&hb.writer_entity_id) && hb.first_seq > 0 {
                            if let Some(ref reg) = topic_registry {
                                if let Ok(first) = u64::try_from(hb.first_seq) {
                                    let _ = reg.notify_writer_heartbeat(writer_guid, first);
                                }
                            }
                        }

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

                        // User data ACKNACKs are routed to the writer's advertised
                        // user-traffic locator (see `send_user_acknack`); `peer_port`
                        // stays as the metatraffic fallback for undiscovered peers.

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
                                &discovery_fsm,
                                &user_data_registry,
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
                                    &discovery_fsm,
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

                        // ACKNACK readerEntityId must identify our actual local
                        // reader so the remote writer can route the response and
                        // (more importantly) deliver TRANSIENT_LOCAL history to
                        // the right endpoint. Acknowledge on behalf of *every*
                        // local reader on the writer's topic: a reliable writer
                        // holds a ReaderProxy per matched reader and
                        // wait_for_acknowledgments() needs all of them to ack.
                        // Fall back to the legacy derive-from-writer path only if
                        // the lookup fails (early-discovery race, loopback
                        // multicast without discovered endpoints).
                        let mut reader_entity_ids = discovery_fsm
                            .local_reader_entity_ids_for_writer(
                                &crate::core::discovery::GUID::new(
                                    state.peer_guid_prefix,
                                    writer_entity_id,
                                ),
                            );
                        if reader_entity_ids.is_empty() {
                            reader_entity_ids.push(derive_reader_entity_id(&writer_entity_id));
                        }

                        let decision = user_data_registry.on_heartbeat(
                            writer_guid,
                            state.first_seq,
                            state.highest_seq,
                            state.last_count,
                            false,
                        );

                        if matches!(
                            decision,
                            AcknackDecision::Ignore | AcknackDecision::RateLimited
                        ) {
                            continue;
                        }

                        // readerSNState from what this reader actually received:
                        // base = first unreceived sample, bitmap = the real gaps
                        // (RTPS v2.5 Sec.8.3.7.1). Empty bitmap => Final=1, which
                        // is what completes the writer's wait_for_acknowledgments.
                        let (seq_base, missing_seqs) = reader_sn_state(
                            &user_data_registry,
                            writer_guid,
                            state.first_seq,
                            state.highest_seq,
                        );
                        let final_flag = missing_seqs.is_empty();

                        user_data_registry.mark_acknack_sent(&writer_guid);

                        // One ACKNACK per local reader entity, identical SN state.
                        for reader_entity_id in reader_entity_ids {
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

                            // RTPS 2.5 §9.6.1.1: user-data endpoints are not registered
                            // on the metatraffic port; ACKNACKs must target the
                            // writer's advertised unicast locator (§8.4.7).
                            if send_user_acknack(
                                &transport,
                                &discovery_fsm,
                                &state.peer_guid_prefix,
                                &writer_entity_id,
                                &acknack,
                                SocketAddr::new(state.peer_ip, state.peer_port),
                            ) {
                                metrics.acknacks_sent.fetch_add(1, Ordering::Relaxed);
                            }
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
    #[allow(clippy::too_many_arguments)]
    fn send_acknack(
        transport: &UdpTransport,
        our_guid_prefix: [u8; 12],
        msg: &ControlMessage,
        hb: &HeartbeatInfo,
        peer_port: u16,
        acknack_count: &mut u32,
        metrics: &ControlMetrics,
        discovery_fsm: &DiscoveryFsm,
        user_data_registry: &ReaderProxyRegistry,
    ) {
        if is_sedp_endpoint(&hb.writer_entity_id) {
            return;
        }

        let mut writer_key = [0u8; 16];
        writer_key[..12].copy_from_slice(&msg.peer_guid_prefix);
        writer_key[12..].copy_from_slice(&hb.writer_entity_id);

        // Same duplicate/rate-limit gate as the batched path: without it every
        // retransmitted FINAL heartbeat triggered a fresh ACKNACK burst.
        // The decision's bitmap_base is unused — the readerSNState below is built
        // from reception state (or is a plain positive ack for built-ins).
        if matches!(
            user_data_registry.on_heartbeat(
                writer_key,
                hb.first_seq,
                hb.last_seq,
                hb.count,
                hb.final_flag,
            ),
            AcknackDecision::Ignore | AcknackDecision::RateLimited
        ) {
            return;
        }

        // Name our real local readers; a writer-derived id is not a valid reader
        // GUID and the remote writer cannot route history to it. With 2+ local
        // readers on one topic we must acknowledge for each of them — a reliable
        // writer's wait_for_acknowledgments() waits on every matched ReaderProxy.
        let writer_guid =
            crate::core::discovery::GUID::new(msg.peer_guid_prefix, hb.writer_entity_id);
        let mut reader_entity_ids = discovery_fsm.local_reader_entity_ids_for_writer(&writer_guid);
        if reader_entity_ids.is_empty() {
            reader_entity_ids.push(derive_reader_entity_id(&hb.writer_entity_id));
        }

        // Acknowledge what we actually received: base = first unreceived sample,
        // bitmap = the real gaps (RTPS v2.5 Sec.8.3.7.1). The previous
        // `base = firstSN` was a fixed "expecting sample 1" for every writer
        // whose history starts at 1, so a reliable writer's
        // wait_for_acknowledgments() never completed. Final=1 when nothing is
        // missing, which is exactly what a FINAL heartbeat is asking for.
        let (seq_base, missing_seqs) =
            reader_sn_state(user_data_registry, writer_key, hb.first_seq, hb.last_seq);
        let final_flag = missing_seqs.is_empty();

        user_data_registry.mark_acknack_sent(&writer_key);

        // One ACKNACK per local reader entity, identical SN state: the reception
        // state is per writer GUID and every local reader on the topic consumed
        // the same samples.
        for reader_entity_id in reader_entity_ids {
            let acknack = build_acknack_packet_with_final(
                our_guid_prefix,
                msg.peer_guid_prefix,
                reader_entity_id,
                hb.writer_entity_id,
                seq_base,
                &missing_seqs,
                *acknack_count,
                final_flag,
            );
            *acknack_count = acknack_count.wrapping_add(1);

            if send_user_acknack(
                transport,
                discovery_fsm,
                &msg.peer_guid_prefix,
                &hb.writer_entity_id,
                &acknack,
                SocketAddr::new(msg.src_addr.ip(), peer_port),
            ) {
                metrics.acknacks_sent.fetch_add(1, Ordering::Relaxed);
            }
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
        discovery_fsm: &DiscoveryFsm,
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

            // Use locked dialect if available (RTI needs its own SEDP format),
            // fallback to Hybrid for unknown or mixed vendors.
            let dialect = discovery_fsm
                .get_locked_dialect()
                .unwrap_or(Dialect::Hybrid);

            match build_sedp_rtps_packet(
                sd,
                *kind,
                &our_guid_prefix,
                Some(peer_guid_prefix),
                seq_num,
                dialect,
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

/// `readerSNState` (base, missing) for an ACKNACK to `writer_key`.
///
/// Reception is only recorded for user-data samples (the router needs a resolved
/// topic), so tracked state may only drive user writers — gated on the same
/// entity-kind discriminator as ACKNACK routing. Built-in writers get a plain
/// positive ack (`base = firstSN`, empty bitmap); a bitmap there would be an
/// unsatisfiable standing repair request and loop forever.
fn reader_sn_state(
    user_data_registry: &ReaderProxyRegistry,
    writer_key: [u8; 16],
    first_seq: i64,
    last_seq: i64,
) -> (u64, Vec<u64>) {
    #[allow(clippy::unwrap_used)] // slice is exactly 4 bytes from a 16-byte GUID
    let entity_id: [u8; 4] = writer_key[12..16].try_into().unwrap();
    if crate::core::rtps_constants::is_user_data_writer_kind(&entity_id) {
        user_data_registry.acknack_state(writer_key, first_seq, last_seq)
    } else {
        (first_seq.max(1) as u64, Vec::new())
    }
}

/// Send an ACKNACK, choosing the channel by the writer's entity kind.
///
/// RTPS 2.5 §9.6.1.1: user-data endpoints are not registered on the metatraffic
/// port; ACKNACKs must target the writer's advertised unicast locator (§8.4.7).
/// Only user-defined writer kinds (0x02/0x03, §9.3.1.2) take the user route —
/// `is_sedp_endpoint` is too narrow a guard because built-ins such as the
/// participant-message writer (0x0200C2) are neither SEDP nor user data and must
/// stay on metatraffic.
///
/// Falls back to `metatraffic_dest` when no user-traffic locator is known.
/// Returns true when the packet was sent.
fn send_user_acknack(
    transport: &UdpTransport,
    discovery_fsm: &DiscoveryFsm,
    peer_guid_prefix: &[u8; 12],
    writer_entity_id: &[u8; 4],
    acknack: &[u8],
    metatraffic_dest: SocketAddr,
) -> bool {
    if crate::core::rtps_constants::is_user_data_writer_kind(writer_entity_id) {
        match discovery_fsm.writer_user_traffic_locator(
            peer_guid_prefix,
            writer_entity_id,
            Some(metatraffic_dest.ip()),
        ) {
            Some(dest) => match transport.send_user_data_unicast(acknack, &dest) {
                Ok(_) => {
                    log::debug!(
                        "[CONTROL] Sent user ACKNACK to {} (writer={:02x?}) user-traffic locator",
                        dest,
                        writer_entity_id
                    );
                    return true;
                }
                Err(_e) => log::debug!("[CONTROL] User ACKNACK to {} failed: {}", dest, _e),
            },
            None => log::debug!(
                "[CONTROL] No user-traffic locator for writer {:02x?}, falling back to metatraffic {}",
                writer_entity_id, metatraffic_dest
            ),
        }
    }
    transport
        .send_to_endpoint(acknack, &metatraffic_dest)
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::discovery::GUID;
    use crate::transport::PortMapping;
    use std::net::UdpSocket;
    use std::time::Duration;

    /// A user-traffic ACKNACK must reach the writer's advertised unicast locator
    /// (RTPS 2.5 §8.4.7), not the metatraffic port, which serves only built-in
    /// endpoints (§9.6.1.1).
    #[test]
    fn user_acknack_reaches_writer_user_traffic_locator() {
        let _ports = crate::transport::udp::lock_transport_ports();

        let writer_sock = UdpSocket::bind("127.0.0.1:0").expect("bind stand-in writer socket");
        writer_sock
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set read timeout");
        let writer_addr = writer_sock.local_addr().expect("writer local addr");

        let metatraffic_sock =
            UdpSocket::bind("127.0.0.1:0").expect("bind stand-in metatraffic socket");
        metatraffic_sock
            .set_read_timeout(Some(Duration::from_millis(200)))
            .expect("set read timeout");
        let metatraffic_addr = metatraffic_sock
            .local_addr()
            .expect("metatraffic local addr");

        let peer_prefix = [0x0au8; 12];
        let writer_entity_id = [0x00, 0x00, 0x05, 0x02];

        // The remote writer announced this user-traffic locator via SEDP.
        let fsm = DiscoveryFsm::new(GUID::zero(), 100_000);
        fsm.endpoint_registry()
            .register_writer_locator(GUID::new(peer_prefix, writer_entity_id), writer_addr);

        let mapping = PortMapping::calculate(0, 11).expect("port mapping");
        let transport = UdpTransport::new(0, 11, mapping).expect("udp transport");

        let acknack = build_acknack_packet_with_final(
            [0x77; 12],
            peer_prefix,
            [0x00, 0x00, 0x0a, 0x07],
            writer_entity_id,
            1,
            &[1],
            1,
            false,
        );

        assert!(send_user_acknack(
            &transport,
            &fsm,
            &peer_prefix,
            &writer_entity_id,
            &acknack,
            metatraffic_addr,
        ));

        let mut buf = [0u8; 1024];
        let (len, _from) = writer_sock
            .recv_from(&mut buf)
            .expect("ACKNACK must be delivered to the writer's advertised user locator");
        assert_eq!(&buf[..len], &acknack[..]);

        assert!(
            metatraffic_sock.recv_from(&mut buf).is_err(),
            "user-traffic ACKNACK must not be sent to the metatraffic port"
        );

        // A built-in writer must stay on metatraffic even though the peer's
        // participant locator resolves: the peer has no built-in writer on its
        // user-traffic port. `is_sedp_endpoint` would not catch 0x0200C2.
        writer_sock
            .set_read_timeout(Some(Duration::from_millis(200)))
            .expect("set read timeout");
        fsm.endpoint_registry().register(
            GUID::new(
                peer_prefix,
                crate::core::rtps_constants::RTPS_ENTITYID_PARTICIPANT,
            ),
            writer_addr,
        );
        let builtin_writer_id = [0x00, 0x02, 0x00, 0xC2];
        let builtin_acknack = build_acknack_packet_with_final(
            [0x77; 12],
            peer_prefix,
            [0x00, 0x02, 0x00, 0xC7],
            builtin_writer_id,
            1,
            &[],
            2,
            true,
        );

        assert!(send_user_acknack(
            &transport,
            &fsm,
            &peer_prefix,
            &builtin_writer_id,
            &builtin_acknack,
            metatraffic_addr,
        ));

        let (len, _from) = metatraffic_sock
            .recv_from(&mut buf)
            .expect("built-in ACKNACK must be delivered to the metatraffic port");
        assert_eq!(&buf[..len], &builtin_acknack[..]);
        assert!(
            writer_sock.recv_from(&mut buf).is_err(),
            "built-in ACKNACK must not be rerouted to the user-traffic port"
        );
    }

    /// Extract (readerEntityId, bitmapBase, numBits) from an ACKNACK packet built
    /// by `build_acknack_packet_with_final`: RTPS header (20) + INFO_DST (16) +
    /// ACKNACK submessage header (4), body little-endian.
    fn acknack_fields(packet: &[u8]) -> ([u8; 4], u64, u32) {
        assert_eq!(&packet[0..4], b"RTPS");
        assert_eq!(packet[20], 0x0e, "INFO_DST expected before the ACKNACK");
        assert_eq!(packet[36], 0x06, "ACKNACK submessage expected");
        let body = 40;
        let reader_entity_id: [u8; 4] = packet[body..body + 4]
            .try_into()
            .expect("4-byte reader entityId");
        let high = i32::from_le_bytes(
            packet[body + 8..body + 12]
                .try_into()
                .expect("bitmapBase high"),
        );
        let low = u32::from_le_bytes(
            packet[body + 12..body + 16]
                .try_into()
                .expect("bitmapBase low"),
        );
        let num_bits =
            u32::from_le_bytes(packet[body + 16..body + 20].try_into().expect("numBits"));
        (
            reader_entity_id,
            ((high as i64) << 32 | low as i64) as u64,
            num_bits,
        )
    }

    /// A HEARTBEAT on a topic with two local readers must produce one ACKNACK per
    /// reader entity, carrying the same readerSNState.
    ///
    /// RTPS 2.5 §8.4.7: a reliable writer tracks one ReaderProxy per matched
    /// reader, and each must acknowledge independently.
    #[test]
    fn user_acknack_fans_out_to_every_local_reader_on_shared_topic() {
        let _ports = crate::transport::udp::lock_transport_ports();

        let writer_sock = UdpSocket::bind("127.0.0.1:0").expect("bind stand-in writer socket");
        writer_sock
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set read timeout");
        let writer_addr = writer_sock.local_addr().expect("writer local addr");

        let local_prefix = [0x77u8; 12];
        let peer_prefix = [0x0au8; 12];
        let writer_entity_id = [0x00, 0x00, 0x05, 0x02];
        let writer_guid = GUID::new(peer_prefix, writer_entity_id);
        let peer_participant = GUID::new(peer_prefix, [0x00, 0x00, 0x01, 0xC1]);
        let local_guid = GUID::new(local_prefix, [0x00, 0x00, 0x01, 0xC1]);

        let fsm = DiscoveryFsm::new(local_guid, 100_000);
        fsm.handle_spdp(crate::protocol::discovery::SpdpData {
            participant_guid: peer_participant,
            lease_duration_ms: 100_000,
            domain_id: 0,
            metatraffic_unicast_locators: vec![writer_addr],
            default_unicast_locators: vec![writer_addr],
            default_multicast_locators: vec![],
            metatraffic_multicast_locators: vec![],
            identity_token: None,
        });

        let topic = "External_Communications__Communication_Device__enableRadioSilence";
        let sedp = |endpoint_guid: GUID, participant_guid: GUID, qos_hash: u64| SedpData {
            topic_name: topic.to_string(),
            type_name: "Command".to_string(),
            participant_guid,
            endpoint_guid,
            qos_hash,
            qos: None,
            type_object: None,
            unicast_locators: vec![],
            user_data: None,
            has_explicit_reliability: false,
            has_explicit_ownership: false,
            has_ownership_strength: false,
            type_information: None,
        };
        fsm.handle_sedp(sedp(writer_guid, peer_participant, 1));

        // Two local readers on the one topic (modem + sdr devices).
        let modem_reader = [0x00, 0x00, 0x0a, 0x07];
        let sdr_reader = [0x00, 0x00, 0x0b, 0x07];
        fsm.handle_sedp(sedp(GUID::new(local_prefix, modem_reader), local_guid, 2));
        fsm.handle_sedp(sedp(GUID::new(local_prefix, sdr_reader), local_guid, 3));

        fsm.endpoint_registry()
            .register_writer_locator(writer_guid, writer_addr);

        let mapping = PortMapping::calculate(0, 12).expect("port mapping");
        let transport = UdpTransport::new(0, 12, mapping).expect("udp transport");

        let hb = HeartbeatInfo {
            writer_entity_id,
            first_seq: 1,
            last_seq: 1,
            count: 1,
            final_flag: true,
            liveliness_flag: false,
        };
        let mut msg = ControlMessage::new(
            super::super::control_types::ControlMessageKind::Heartbeat,
            writer_addr,
            &[0u8; 52],
        )
        .expect("control message");
        msg.peer_guid_prefix = peer_prefix;
        msg.heartbeat = Some(hb.clone());

        let metrics = ControlMetrics::new();
        let user_data_registry = ReaderProxyRegistry::new();
        let mut acknack_count = 1u32;

        ControlHandler::send_acknack(
            &transport,
            local_prefix,
            &msg,
            &hb,
            writer_addr.port(),
            &mut acknack_count,
            &metrics,
            &fsm,
            &user_data_registry,
        );

        let mut seen: Vec<([u8; 4], u64, u32)> = Vec::new();
        let mut buf = [0u8; 1024];
        for _ in 0..2 {
            let (len, _from) = writer_sock
                .recv_from(&mut buf)
                .expect("one ACKNACK per local reader must reach the writer");
            seen.push(acknack_fields(&buf[..len]));
        }
        seen.sort_unstable();

        assert_eq!(
            seen.iter().map(|f| f.0).collect::<Vec<_>>(),
            vec![modem_reader, sdr_reader],
            "each local reader entityId must be acknowledged exactly once"
        );
        let (_, base, num_bits) = seen[0];
        assert!(
            seen.iter().all(|f| f.1 == base && f.2 == num_bits),
            "readerSNState is shared per writer GUID, so every fan-out ACKNACK carries it verbatim"
        );
        assert_eq!(
            (base, num_bits),
            (1, 1),
            "seq 1 announced, not received yet"
        );
        assert_eq!(
            metrics.acknacks_sent.load(Ordering::Relaxed),
            2,
            "both sends must be counted"
        );
        assert_eq!(acknack_count, 3, "each ACKNACK gets its own count");

        writer_sock
            .set_read_timeout(Some(Duration::from_millis(200)))
            .expect("set read timeout");
        assert!(
            writer_sock.recv_from(&mut buf).is_err(),
            "exactly N ACKNACKs for N local readers, no duplicates"
        );

        // Once the sample is consumed, both readers must report the advanced base
        // (base = 2, empty bitmap, Final=1) — that is what releases the writer's
        // wait_for_acknowledgments() for every matched ReaderProxy.
        let mut writer_key = [0u8; 16];
        writer_key[..12].copy_from_slice(&peer_prefix);
        writer_key[12..].copy_from_slice(&writer_entity_id);
        user_data_registry.on_data(writer_key, 1);
        writer_sock
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set read timeout");
        // A *new* heartbeat past the ACKNACK rate-limit window: replaying `hb`
        // verbatim is a duplicate and is now deliberately suppressed.
        let hb_next = HeartbeatInfo {
            count: 2,
            ..hb.clone()
        };
        std::thread::sleep(Duration::from_millis(20));
        ControlHandler::send_acknack(
            &transport,
            local_prefix,
            &msg,
            &hb_next,
            writer_addr.port(),
            &mut acknack_count,
            &metrics,
            &fsm,
            &user_data_registry,
        );
        let mut acked: Vec<([u8; 4], u64, u32)> = Vec::new();
        for _ in 0..2 {
            let (len, _from) = writer_sock
                .recv_from(&mut buf)
                .expect("both readers ack the consumed sample");
            acked.push(acknack_fields(&buf[..len]));
        }
        acked.sort_unstable();
        assert_eq!(
            acked.iter().map(|f| f.0).collect::<Vec<_>>(),
            vec![modem_reader, sdr_reader]
        );
        assert!(
            acked.iter().all(|f| f.1 == 2 && f.2 == 0),
            "every fan-out ACKNACK must advance to base=2 with an empty bitmap, got {acked:?}"
        );
    }

    /// A HEARTBEAT from a non-SEDP built-in writer (participant-message 0x0200C2)
    /// must get exactly ONE positive ACKNACK on metatraffic: empty bitmap, no
    /// user fan-out.
    ///
    /// Regression: reception is only recorded for topic-resolved user samples, so
    /// applying the reader-state bitmap to built-in writers produced a standing
    /// `[firstSN..=lastSN]` repair request that could never be satisfied — a
    /// self-sustaining HEARTBEAT/ACKNACK loop per reliable built-in writer.
    #[test]
    fn builtin_heartbeat_gets_single_positive_acknack_on_metatraffic() {
        let _ports = crate::transport::udp::lock_transport_ports();

        let metatraffic_sock =
            UdpSocket::bind("127.0.0.1:0").expect("bind stand-in metatraffic socket");
        metatraffic_sock
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set read timeout");
        let metatraffic_addr = metatraffic_sock
            .local_addr()
            .expect("metatraffic local addr");

        let local_prefix = [0x77u8; 12];
        let peer_prefix = [0x0bu8; 12];
        // Participant-message writer: built-in, kind 0xC2, but NOT SEDP.
        let writer_entity_id = [0x00, 0x02, 0x00, 0xC2];

        let fsm = DiscoveryFsm::new(GUID::new(local_prefix, [0x00, 0x00, 0x01, 0xC1]), 100_000);
        let mapping = PortMapping::calculate(0, 13).expect("port mapping");
        let transport = UdpTransport::new(0, 13, mapping).expect("udp transport");

        let hb = HeartbeatInfo {
            writer_entity_id,
            first_seq: 1,
            last_seq: 3,
            count: 1,
            final_flag: true,
            liveliness_flag: false,
        };
        let mut msg = ControlMessage::new(
            super::super::control_types::ControlMessageKind::Heartbeat,
            metatraffic_addr,
            &[0u8; 52],
        )
        .expect("control message");
        msg.peer_guid_prefix = peer_prefix;
        msg.heartbeat = Some(hb.clone());

        let metrics = ControlMetrics::new();
        let user_data_registry = ReaderProxyRegistry::new();
        let mut acknack_count = 1u32;

        ControlHandler::send_acknack(
            &transport,
            local_prefix,
            &msg,
            &hb,
            metatraffic_addr.port(),
            &mut acknack_count,
            &metrics,
            &fsm,
            &user_data_registry,
        );

        let mut buf = [0u8; 1024];
        let (len, _from) = metatraffic_sock
            .recv_from(&mut buf)
            .expect("built-in HEARTBEAT must be acknowledged on the metatraffic port");
        let (reader_entity_id, base, num_bits) = acknack_fields(&buf[..len]);
        assert_eq!(
            reader_entity_id,
            [0x00, 0x02, 0x00, 0xC7],
            "built-in ACKNACK names the matching built-in reader"
        );
        assert_eq!(
            (base, num_bits),
            (1, 0),
            "built-in writers have no tracked reception state: positive ack, never a NACK bitmap"
        );

        metatraffic_sock
            .set_read_timeout(Some(Duration::from_millis(200)))
            .expect("set read timeout");
        assert!(
            metatraffic_sock.recv_from(&mut buf).is_err(),
            "exactly one ACKNACK for a built-in writer, no per-reader fan-out"
        );
        assert_eq!(
            metrics.acknacks_sent.load(Ordering::Relaxed),
            1,
            "one built-in ACKNACK sent"
        );
    }

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
