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
//! Per RTPS v2.5 Sec.8.3.8.6, HEARTBEAT flags:
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

use crate::core::discovery::multicast::{DiscoveryFsm, Origin};
use crate::core::discovery::GUID;
use crate::core::reader::{AcknackDecision, Addressees, HeartbeatSeen, ReaderProxyRegistry};
use crate::core::rtps_constants::RTPS_ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_WRITER;
use crate::core::writer::MatchedReadersRegistry;
use crate::engine::{Topic, TopicRegistry};
use crate::protocol::builder::build_acknack_packet_with_final;
use crate::protocol::constants::{is_zzdds_vendor, EPROSIMA_VENDOR_ID_U16};
use crate::protocol::dialect::Dialect;
use crate::protocol::rtps::participant_message::{
    reader_reply_to_heartbeat, PARTICIPANT_MESSAGE_READER, PARTICIPANT_MESSAGE_WRITER,
};
use crate::transport::UdpTransport;

use super::directed_writer::TypeLookupWriters;
use super::rtps_packet::SedpEndpointKind;
use super::sedp_history::SedpHistory;

/// The history of the participant's SEDP writers, for retransmission on NACK.
/// Mirrors entity_registry::SedpAnnouncementsCache but avoids pub(super) visibility issue.
type SedpCache = Arc<RwLock<SedpHistory>>;

// Import from refactored modules
use super::control_builder::build_unknown80_locator;
use super::control_metrics::ControlMetrics;
use super::control_types::{ControlMessage, GapInfo, HeartbeatInfo, WriterState, ENTITYID_UNKNOWN};

/// Control channel capacity (bounded to prevent memory explosion)
const CONTROL_CHANNEL_CAPACITY: usize = 1024;

/// Batch flush interval (milliseconds)
const BATCH_FLUSH_INTERVAL_MS: u64 = 50;

/// Maximum HEARTBEATs to batch before flushing
const BATCH_MAX_SIZE: usize = 10;

/// One writer's answers from a flushed HEARTBEAT batch, in answering order.
type WriterBatches = Vec<(Addressees, WriterState)>;

/// Vendor id 0x0101 (`PID_VENDORID`) -- the peers the preemptive SEDP
/// solicitation is gated on (see `tick_connext_sedp_storm`).
const CONNEXT_VENDOR_ID: u16 = 0x0101;

/// Number of preemptive solicitation ACKNACKs sent to a freshly discovered
/// vendor id 0x0101 peer's SEDP publications writer, spread over the first
/// ~2 s of discovery (see `tick_connext_sedp_storm`).
const CONNEXT_SEDP_STORM_COUNT: u32 = 12;

/// Cadence between preemptive solicitation ACKNACKs to a vendor id 0x0101
/// peer (ms). 12 x 150ms ~= 1.7s solicitation window, comfortably inside the
/// discovery phase.
const CONNEXT_SEDP_STORM_INTERVAL_MS: u64 = 150;

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
    /// Shared SEDP Reader proxy registry for DATA notification
    pub sedp_registry: ReaderProxyRegistry,
    /// Shared SEDP Writer registry for multi-reader ACKNACK tracking
    /// Enables 1-pub->N-sub scenarios (e.g., 1 command center -> 36 vehicles)
    pub sedp_writer_registry: MatchedReadersRegistry,
    /// Topic registry for user data ACKNACK dispatch to WriterNackHandler
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

        // Create shared registry for SEDP Reader state tracking.
        let sedp_registry = ReaderProxyRegistry::new();
        let registry_clone = sedp_registry.clone();

        // Create shared registry for SEDP Writer state tracking.
        let sedp_writer_registry = MatchedReadersRegistry::new();

        let running_clone = Arc::clone(&running);
        let metrics_clone = Arc::clone(&metrics);

        #[allow(clippy::expect_used)] // thread spawn failure is unrecoverable
        let handle = std::thread::Builder::new()
            .name("hdds-control".to_string())
            .spawn(crate::core::rt::shutdown::owned(move || {
                Self::run_loop(
                    receiver,
                    transport,
                    our_guid_prefix,
                    peer_metatraffic_port,
                    running_clone,
                    metrics_clone,
                    registry_clone,
                    ReaderProxyRegistry::new(),
                    None,
                    discovery_fsm,
                    Arc::new(RwLock::new(SedpHistory::new())), // No SEDP cache in basic mode
                    None,
                );
            }))
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

    /// Spawn control handler thread with external SEDP registry.
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
            .spawn(crate::core::rt::shutdown::owned(move || {
                Self::run_loop(
                    receiver,
                    transport,
                    our_guid_prefix,
                    peer_metatraffic_port,
                    running_clone,
                    metrics_clone,
                    registry_clone,
                    ReaderProxyRegistry::new(),
                    None,
                    discovery_fsm,
                    Arc::new(RwLock::new(SedpHistory::new())), // No SEDP cache in basic mode
                    None,
                );
            }))
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

    /// Spawn control handler thread with SEDP registry AND topic registry.
    // justification: protocol handler thread-spawn needs transport, guid, port,
    // both registries, topic registry, discovery FSM, and SEDP cache; splitting
    // into a struct would change the public constructor surface.
    #[allow(clippy::too_many_arguments)]
    pub fn spawn_with_topic_registry(
        transport: Arc<UdpTransport>,
        our_guid_prefix: [u8; 12],
        peer_metatraffic_port: u16,
        sedp_registry: ReaderProxyRegistry,
        user_data_registry: ReaderProxyRegistry,
        topic_registry: Arc<TopicRegistry>,
        discovery_fsm: Arc<DiscoveryFsm>,
        sedp_cache: SedpCache,
    ) -> Self {
        Self::spawn_with_type_lookup_writers(
            transport,
            our_guid_prefix,
            peer_metatraffic_port,
            sedp_registry,
            user_data_registry,
            topic_registry,
            discovery_fsm,
            sedp_cache,
            None,
        )
    }

    /// `spawn_with_topic_registry`, plus the participant's two TypeLookup
    /// writers: an ACKNACK addressed to either is answered from them
    /// (`DirectedWriter::answer_acknack`) instead of being handed to the
    /// topic registry, which knows no builtin writer.
    #[allow(clippy::too_many_arguments)]
    pub fn spawn_with_type_lookup_writers(
        transport: Arc<UdpTransport>,
        our_guid_prefix: [u8; 12],
        peer_metatraffic_port: u16,
        sedp_registry: ReaderProxyRegistry,
        user_data_registry: ReaderProxyRegistry,
        topic_registry: Arc<TopicRegistry>,
        discovery_fsm: Arc<DiscoveryFsm>,
        sedp_cache: SedpCache,
        type_lookup_writers: Option<Arc<TypeLookupWriters>>,
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
            .spawn(crate::core::rt::shutdown::owned(move || {
                Self::run_loop(
                    receiver,
                    transport,
                    our_guid_prefix,
                    peer_metatraffic_port,
                    running_clone,
                    metrics_clone,
                    registry_clone,
                    user_data_registry,
                    Some(topic_registry_clone),
                    discovery_fsm,
                    sedp_cache,
                    type_lookup_writers,
                );
            }))
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

    /// Resolve the destination for a reply to `peer_guid_prefix`: IP and
    /// metatraffic port together.
    ///
    /// Direct: the datagram's own IP, with the metatraffic port the peer
    /// recorded in SPDP (a peer may send HEARTBEATs from an ephemeral
    /// source port it does not listen on; replies belong on the metatraffic
    /// locator it announced), or the datagram's port for a peer not yet
    /// discovered.
    /// Relayed (RTPS 2.5 8.3.4 / 8.3.8.10: no reply locator behind an
    /// INFO_SRC): there is no address of the peer's own to pair a port with,
    /// so both come from the FSM's record of the peer, and a peer the FSM
    /// does not know resolves to `None`: no reply, and never one aimed at
    /// the forwarder that only relayed this message.
    fn resolve_peer_metatraffic_addr(
        peer_guid_prefix: &[u8; 12],
        origin: Origin,
        fsm: &DiscoveryFsm,
    ) -> Option<SocketAddr> {
        let recorded = fsm.metatraffic_locator_for(peer_guid_prefix, origin);
        log::debug!(
            "[CONTROL] peer {:02x?} recorded metatraffic locator {:?} (origin {:?})",
            &peer_guid_prefix[..4],
            recorded,
            origin
        );
        match origin.reply() {
            Some(reply) => Some(SocketAddr::new(
                reply.ip(),
                recorded.map_or(reply.port(), |ep| ep.port()),
            )),
            None => recorded,
        }
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
        user_data_registry: ReaderProxyRegistry,
        topic_registry: Option<Arc<TopicRegistry>>,
        discovery_fsm: Arc<DiscoveryFsm>,
        sedp_cache: SedpCache,
        type_lookup_writers: Option<Arc<TypeLookupWriters>>,
    ) {
        log::debug!("[CONTROL] Control handler thread started");

        let mut acknack_count: u32 = 1;
        // Keyed by the writer AND the reader its HEARTBEATs address: one
        // addressed to a single reader is that reader's alone.
        let mut batch: std::collections::HashMap<([u8; 16], [u8; 4]), WriterState> =
            std::collections::HashMap::new();
        let mut last_flush = Instant::now();
        // Shared with the subscriber DATA path so the per-writer
        // ReliableReaderProxy.highest_received_seq advances as user data is
        // admitted. Without this the ACKNACK bitmapBase stays frozen at the
        // writer firstSN and a RELIABLE+KEEP_ALL writer never sees its
        // samples acknowledged, so it never releases its history. RTPS v2.5 Sec.8.4.12.2.
        let flush_interval = Duration::from_millis(BATCH_FLUSH_INTERVAL_MS);

        // Track endpoint count per SEDP writer for stable HEARTBEAT range.
        // HEARTBEAT range: first available (`SedpHistory::first_available`) .. last.
        let mut effective_pub_first: u64 = 1; // Publications: Writer endpoint count
        let mut effective_sub_first: u64 = 1; // Subscriptions: Reader endpoint count

        // Per-peer (vendor id 0x0101) preemptive SEDP-solicitation state.
        // Keyed by GUID prefix. See `tick_connext_sedp_storm` for the
        // rationale. Vendor-id-gated cold path.
        let mut connext_storms: std::collections::HashMap<[u8; 12], ConnextStorm> =
            std::collections::HashMap::new();
        let mut last_storm_tick = Instant::now();
        // HDDS peers whose SEDP writers this participant asked for their
        // history, by the discovery each request was made for (the peer's
        // `created_at`). See `tick_sedp_solicitation`.
        let mut solicited = SedpSolicitations::default();

        // SEDP-announced writer locators (user ACKNACK destinations for
        // vendors that only read user control traffic on their user port).
        // Cloned once; shares the underlying maps with the discovery FSM.
        let endpoint_registry = discovery_fsm.endpoint_registry();

        // The discovery side effects of this thread's traffic run on a
        // worker: the matches a late liveness mark releases, and the
        // probation ticks (whose drain surfaces deferred matches). Both run
        // user listeners; on this thread a slow or blocking listener would
        // stall every HEARTBEAT and ACKNACK behind it (the channel is
        // bounded, `try_send` drops), and a listener that creates an
        // endpoint would do so from inside the protocol loop.
        let discovery_work =
            DiscoveryWorker::spawn(Arc::clone(&discovery_fsm), Arc::clone(&running));

        while running.load(Ordering::Relaxed) {
            match receiver.recv_timeout(Duration::from_millis(10)) {
                Ok(msg) => {
                    // Skip our own messages (multicast loopback)
                    if msg.peer_guid_prefix == our_guid_prefix {
                        continue;
                    }

                    'handled: {
                        if let Some(ref hb) = msg.heartbeat {
                            let writer_guid =
                                writer_guid_of(&msg.peer_guid_prefix, &hb.writer_entity_id);
                            // A HEARTBEAT from a peer's SEDP writer: the
                            // reliable exchange with it has started, no more
                            // soliciting it (`tick_sedp_solicitation`).
                            solicited.heard(&msg.peer_guid_prefix, &hb.writer_entity_id);

                            // Seed the per-writer reorder gate. The rule lives in
                            // `seed_reorder_gate`, which the TCP/QUIC door calls too.
                            if let Some(ref reg) = topic_registry {
                                if applies_gate_on_control(&msg, &hb.writer_entity_id) {
                                    seed_reorder_gate(
                                        reg,
                                        &msg.peer_guid_prefix,
                                        hb,
                                        msg.reader_entity_id(),
                                        msg.heartbeat_group_info(),
                                    );
                                }
                                // RTPS v2.5 Sec.8.3.7.5: the Liveliness
                                // flag renews a MANUAL_BY_TOPIC writer's
                                // lease. Shared with the TCP/QUIC door
                                // (`renew_heartbeat_liveliness`'s own doc).
                                // A user writer's HEARTBEAT riding the ring is
                                // renewed by the Router, once, when it applies it.
                                if applies_gate_on_control(&msg, &hb.writer_entity_id) {
                                    renew_heartbeat_liveliness(reg, &msg.peer_guid_prefix, hb);
                                }
                            }

                            // Resolve peer's actual metatraffic port from SPDP data.
                            // A peer may send HEARTBEATs from an ephemeral source port, so
                            // msg.origin.from().port() would be wrong for ACKNACK destination.
                            //
                            // RTPS 2.5 8.3.4 / 8.3.8.10: direct uses the datagram's IP with
                            // the port recorded in SPDP; relayed (behind an INFO_SRC) has no
                            // reply address of its own, so both IP and port come from the
                            // FSM's own record of the peer.
                            //
                            // A peer the FSM does not know -- or knows but with no
                            // metatraffic locator of its own (a relayed announcement with
                            // empty `endpoints`) -- gets `None` here, and that must gate
                            // only the OUTGOING reply, never the state this HEARTBEAT
                            // updates: `sedp_registry.on_heartbeat` (writer proxy creation,
                            // low_mark from firstSN) and the user-data path below both run
                            // unconditionally. Skipping them on top of the missing address
                            // would be PERMANENT for such a peer: it never announces a
                            // locator of its own by definition, so every future HEARTBEAT
                            // would hit the same `continue` and the writer proxy this
                            // participant needs to ever answer it would never be created.
                            let peer_addr = Self::resolve_peer_metatraffic_addr(
                                &msg.peer_guid_prefix,
                                msg.origin,
                                &discovery_fsm,
                            );
                            if peer_addr.is_none() {
                                log::debug!(
                                    "[CONTROL] relayed origin and peer {:02x?} has no metatraffic \
                                 locator of its own: no reply address, but its HEARTBEAT \
                                 state still updates",
                                    &msg.peer_guid_prefix[..4]
                                );
                            }

                            // A peer's TypeLookup writer: our request or
                            // reply reader answers from what it received
                            // (RTPS 2.5 8.4.15.5), at the locator the peer
                            // announced.
                            if let (Some(endpoints), Some(reader_id)) = (
                                type_lookup_writers.as_deref(),
                                TypeLookupWriters::reader_for(&hb.writer_entity_id),
                            ) {
                                let due = endpoints.received.on_heartbeat(
                                    msg.peer_guid_prefix,
                                    hb.writer_entity_id,
                                    u64::try_from(hb.first_seq).unwrap_or(0),
                                    u64::try_from(hb.last_seq).unwrap_or(0),
                                    hb.count,
                                );
                                if let (Some(due), Some(addr)) = (
                                    due,
                                    discovery_fsm.first_metatraffic_locator(&msg.peer_guid_prefix),
                                ) {
                                    let acknack = build_acknack_packet_with_final(
                                        our_guid_prefix,
                                        msg.peer_guid_prefix,
                                        reader_id,
                                        hb.writer_entity_id,
                                        due.base,
                                        &due.missing,
                                        acknack_count,
                                        due.missing.is_empty(),
                                    );
                                    acknack_count = acknack_count.wrapping_add(1);
                                    if transport.send_to_endpoint(&acknack, &addr).is_ok() {
                                        metrics.acknacks_sent.fetch_add(1, Ordering::Relaxed);
                                    }
                                }
                                break 'handled;
                            }

                            if hb.writer_entity_id
                                == RTPS_ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_WRITER
                            {
                                // RTPS v2.5 Sec.8.4.13.3: the peer's
                                // BuiltinParticipantMessageWriter is RELIABLE.
                                // Its entity id (kind 0xC2) is neither SEDP's
                                // nor TypeLookup's, so without this branch it
                                // fell to the generic final-HEARTBEAT path
                                // below, which answers through a
                                // ReaderProxyRegistry that never holds a
                                // proxy for this builtin endpoint: the peer's
                                // writer never learned we held its
                                // assertion, and never repaired one we lost.
                                let have = discovery_fsm
                                    .participant_message_received(&msg.peer_guid_prefix);
                                let last_sn = u64::try_from(hb.last_seq).unwrap_or(0);
                                let (bitmap_base, missing) =
                                    reader_reply_to_heartbeat(have, last_sn);
                                if let Some(addr) = peer_addr {
                                    let missing_seqs: Vec<u64> = missing.into_iter().collect();
                                    let final_flag = missing_seqs.is_empty();
                                    let acknack = build_acknack_packet_with_final(
                                        our_guid_prefix,
                                        msg.peer_guid_prefix,
                                        PARTICIPANT_MESSAGE_READER,
                                        PARTICIPANT_MESSAGE_WRITER,
                                        bitmap_base,
                                        &missing_seqs,
                                        acknack_count,
                                        final_flag,
                                    );
                                    acknack_count = acknack_count.wrapping_add(1);
                                    if transport.send_to_endpoint(&acknack, &addr).is_ok() {
                                        metrics.acknacks_sent.fetch_add(1, Ordering::Relaxed);
                                    }
                                }
                                break 'handled;
                            }

                            if is_sedp_endpoint(&hb.writer_entity_id) {
                                // The writer proxy is created/updated here regardless of
                                // whether a reply can go anywhere: it is what makes this
                                // participant able to answer the writer at all, on this
                                // or a later HEARTBEAT.
                                let proxy_guid =
                                    sedp_proxy_guid(&msg.peer_guid_prefix, &hb.writer_entity_id);
                                let decision = sedp_registry.on_heartbeat(
                                    proxy_guid,
                                    hb.first_seq,
                                    hb.last_seq,
                                    hb.count,
                                    hb.final_flag,
                                );

                                #[cfg(feature = "security")]
                                if matches!(decision, AcknackDecision::Synchronized { .. }) {
                                    discovery_fsm.finish_secure_sedp_repair(
                                        &msg.peer_guid_prefix,
                                        &hb.writer_entity_id,
                                    );
                                }
                                match (decision, peer_addr) {
                                    (AcknackDecision::Ignore | AcknackDecision::RateLimited, _) => {
                                    }
                                    (
                                        AcknackDecision::Synchronized { .. }
                                        | AcknackDecision::NeedData { .. },
                                        None,
                                    ) => {
                                        log::debug!(
                                            "[CONTROL] no reply address for writer {:02x?}: SEDP \
                                         ACKNACK dropped, state already updated",
                                            hb.writer_entity_id
                                        );
                                    }
                                    (
                                        AcknackDecision::Synchronized { bitmap_base },
                                        Some(peer_addr),
                                    ) => {
                                        Self::send_sedp_acknack(
                                            &transport,
                                            our_guid_prefix,
                                            &msg.peer_guid_prefix,
                                            &hb.writer_entity_id,
                                            peer_addr.port(),
                                            peer_addr.ip(),
                                            &metrics,
                                            bitmap_base,
                                            &[],
                                            &mut acknack_count,
                                            #[cfg(feature = "security")]
                                            &discovery_fsm,
                                        );
                                        sedp_registry.mark_acknack_sent(&proxy_guid);
                                    }
                                    (
                                        AcknackDecision::NeedData { bitmap_base },
                                        Some(peer_addr),
                                    ) => {
                                        // RTPS v2.5 Sec.8.4.12.2: the ACKNACK lists
                                        // every change still missing up to the
                                        // HEARTBEAT's lastSN, not the first one alone.
                                        let mut missing =
                                            sedp_registry.missing_holes(&proxy_guid, hb.last_seq);
                                        missing.retain(|&s| s >= bitmap_base);
                                        if missing.is_empty() {
                                            missing.push(bitmap_base);
                                        }
                                        Self::send_sedp_acknack(
                                            &transport,
                                            our_guid_prefix,
                                            &msg.peer_guid_prefix,
                                            &hb.writer_entity_id,
                                            peer_addr.port(),
                                            peer_addr.ip(),
                                            &metrics,
                                            bitmap_base,
                                            &missing,
                                            &mut acknack_count,
                                            #[cfg(feature = "security")]
                                            &discovery_fsm,
                                        );
                                        sedp_registry.mark_acknack_sent(&proxy_guid);
                                    }
                                }
                                break 'handled;
                            }

                            // User data ACKNACKs use the METATRAFFIC port, same as
                            // SEDP ACKNACKs. RTPS control messages (HB, ACKNACK, GAP) are
                            // always exchanged on the metatraffic channel, the locator the
                            // peer announced for them; sending to the user data port would
                            // let them be silently dropped.

                            if hb.final_flag {
                                // Defense-in-depth: SEDP endpoints are handled by the
                                // dedicated branch above (with its own `continue`).
                                // Re-asserting the guard here protects this block from
                                // future refactors that might split or reorder the
                                // upstream branch.
                                if is_sedp_endpoint(&hb.writer_entity_id) {
                                    break 'handled;
                                }

                                metrics.heartbeats_final.fetch_add(1, Ordering::Relaxed);
                                // Route Final HEARTBEATs through each matched reader's
                                // proxy for a correct ACKNACK with Final flag. A writer may
                                // set Final on every HEARTBEAT; without the Final flag on our
                                // ACKNACK response the HEARTBEAT/ACKNACK cycle never ends and
                                // the writer keeps the history it waits to see acknowledged.
                                Self::answer_user_heartbeat(
                                    &transport,
                                    &user_data_registry,
                                    &discovery_fsm,
                                    &topic_registry,
                                    &endpoint_registry,
                                    &metrics,
                                    our_guid_prefix,
                                    &UserHeartbeat {
                                        writer_guid,
                                        addressees: Addressees::of(msg.reader_entity_id()),
                                        first_seq: hb.first_seq,
                                        last_seq: hb.last_seq,
                                        count: hb.count,
                                        final_flag: true,
                                        peer_guid_prefix: msg.peer_guid_prefix,
                                        peer_addr,
                                    },
                                );
                            } else {
                                metrics.heartbeats_batched.fetch_add(1, Ordering::Relaxed);
                                let state = batch
                                    .entry((writer_guid, msg.reader_entity_id()))
                                    .or_insert(WriterState {
                                        first_seq: hb.first_seq,
                                        highest_seq: hb.last_seq,
                                        last_count: hb.count,
                                        peer_addr,
                                        peer_guid_prefix: msg.peer_guid_prefix,
                                    });

                                if hb.first_seq > state.first_seq {
                                    state.first_seq = hb.first_seq;
                                }
                                if hb.last_seq > state.highest_seq {
                                    state.highest_seq = hb.last_seq;
                                }
                                state.last_count = hb.count;
                                // Never replace a known-good address with "unknown": a
                                // relayed HEARTBEAT batched behind an earlier direct one
                                // (or one already resolved via the FSM) must not blank
                                // out the destination the flush below will send to.
                                if peer_addr.is_some() {
                                    state.peer_addr = peer_addr;
                                }
                            }
                        } else if let Some(ref an) = msg.acknack {
                            if is_sedp_endpoint(&an.writer_entity_id) {
                                #[cfg(feature = "security")]
                                if an.writer_entity_id[0] == 0xff
                                    && !discovery_fsm.is_peer_authenticated(&msg.peer_guid_prefix)
                                {
                                    break 'handled;
                                }
                                // DDS Security v1.1 Sec.8.8.9.3: a secure SEDP
                                // reader protects its own ACKNACK with the key
                                // its DatareaderCryptoTokens announced
                                // (Sec.8.8.8.3's submessage protection is
                                // symmetric: our writer protects what it
                                // sends that reader, that reader protects
                                // what it sends our writer). `msg` reached
                                // here either straight off a plaintext parse
                                // (`parse_all_acknack_submessages`, which
                                // cannot see INSIDE a SEC_PREFIX envelope) or
                                // as the synthetic message
                                // `DiscoveryDispatch::handle_secure_sedp`
                                // built after successfully decoding one
                                // (`ControlMessage::protected`): an
                                // authenticated peer's CLEAR ACKNACK on this
                                // topic is a violation to refuse, never a
                                // degraded mode to serve.
                                #[cfg(feature = "security")]
                                if secure_sedp_acknack_must_be_refused(
                                    &an.writer_entity_id,
                                    msg.was_protected(),
                                    discovery_fsm.discovery_protection_kind(),
                                ) {
                                    discovery_fsm
                                        .metrics
                                        .secure_sedp_undecodable
                                        .fetch_add(1, Ordering::Relaxed);
                                    log::debug!(
                                        "[CONTROL] clear ACKNACK for secure SEDP writer {:02x?} \
                                         from {:02x?}: submessage protection required, refused",
                                        an.writer_entity_id,
                                        &msg.peer_guid_prefix[..4]
                                    );
                                    break 'handled;
                                }
                                // RTPS 2.5 8.3.4 / 8.3.8.10: same rule as the HEARTBEAT
                                // branch above -- direct unchanged, relayed resolves
                                // from the FSM alone, unknown peer gets no reply.
                                let Some(peer_addr) = Self::resolve_peer_metatraffic_addr(
                                    &msg.peer_guid_prefix,
                                    msg.origin,
                                    &discovery_fsm,
                                ) else {
                                    log::debug!(
                                        "[CONTROL] relayed origin and peer {:02x?} unknown to the \
                                     FSM: no reply address, dropping SEDP ACKNACK response",
                                        &msg.peer_guid_prefix[..4]
                                    );
                                    break 'handled;
                                };
                                // A reader our SEDP writer is not matched with,
                                // its participant unknown to discovery, is not
                                // answered, HEARTBEAT included (RTPS v2.5
                                // Sec.8.4.7, Sec.8.5.3): its SPDP will send it
                                // the history.
                                if discovery_fsm
                                    .type_object_pid_for(&msg.peer_guid_prefix)
                                    .is_none()
                                {
                                    log::debug!(
                                        "[CONTROL] SEDP ACKNACK from {:02x?}, unknown to \
                                         discovery: not answered",
                                        &msg.peer_guid_prefix[..4]
                                    );
                                    break 'handled;
                                }
                                let an_peer_port = peer_addr.port();

                                // Retransmit + HEARTBEAT only when the peer is BEHIND. A peer
                                // that received everything ACKs bitmapBase = last_sn + 1 (> last_sn)
                                // with an empty bitmap -> no response (a HB for every pure ACK makes
                                // an endless HB/ACKNACK loop). BUT a late-joining reader may ACK
                                // bitmapBase = 1 with an EMPTY bitmap (received nothing, cumulative
                                // ack = base - 1 = 0); missing_ranges is empty, so a test on the
                                // bitmap alone would skip it and that reader would stay frozen at
                                // base 1, never matching our writer. Treat bitmapBase <= our last
                                // published SEDP seq as "peer behind" and respond even when the
                                // bitmap is empty.
                                // Use the in-scope endpoint counts (same source the HEARTBEAT
                                // range below uses), NOT the global SEDP_*_SEQ_NUM atomics, which
                                // are not populated on this re-announce path (they read back 0).
                                let our_last_sedp_seq = if sedp_endpoint_kind(&an.writer_entity_id)
                                    == Some(SedpEndpointKind::Writer)
                                {
                                    effective_pub_first
                                } else {
                                    effective_sub_first
                                };
                                let peer_behind =
                                    our_last_sedp_seq > 0 && an.bitmap_base <= our_last_sedp_seq;
                                if !an.missing_ranges.is_empty() || peer_behind {
                                    // The HEARTBEAT starts at the first change not
                                    // superseded (RTPS v2.5 Sec.8.3.8.6); 1 when
                                    // nothing was sent.
                                    let mut hb_first: u64 = 1;
                                    if let Some((first, count, sent_data)) =
                                        Self::retransmit_sedp_data(
                                            &transport,
                                            our_guid_prefix,
                                            &msg.peer_guid_prefix,
                                            &an.writer_entity_id,
                                            an_peer_port,
                                            peer_addr.ip(),
                                            &sedp_cache,
                                            &metrics,
                                            &discovery_fsm,
                                        )
                                    {
                                        hb_first = first;
                                        // Track endpoint count for HEARTBEAT range
                                        if sedp_endpoint_kind(&an.writer_entity_id)
                                            == Some(SedpEndpointKind::Writer)
                                        {
                                            effective_pub_first = count;
                                        } else {
                                            effective_sub_first = count;
                                        }
                                        // A repair response just ran, driven by THIS
                                        // ACKNACK: count it when the ACKNACK itself
                                        // was submessage-protected, so a test can
                                        // tell "a repair ran" apart from "the
                                        // protected-ACKNACK/repair path ran".
                                        // `protected_sedp_retransmissions`
                                        // moves on a GAP-only answer too; only
                                        // `protected_sedp_data_retransmissions`
                                        // answers "and real DATA crossed the wire".
                                        #[cfg(feature = "security")]
                                        if msg.was_protected() {
                                            discovery_fsm
                                                .metrics
                                                .protected_sedp_retransmissions
                                                .fetch_add(1, Ordering::Relaxed);
                                            if sent_data {
                                                discovery_fsm
                                                    .metrics
                                                    .protected_sedp_data_retransmissions
                                                    .fetch_add(1, Ordering::Relaxed);
                                            }
                                        }
                                        #[cfg(not(feature = "security"))]
                                        let _ = sent_data;
                                    }

                                    // HEARTBEAT first..=N (only after NACK retransmit)
                                    let hb_last = if sedp_endpoint_kind(&an.writer_entity_id)
                                        == Some(SedpEndpointKind::Writer)
                                    {
                                        effective_pub_first as i64
                                    } else {
                                        effective_sub_first as i64
                                    };
                                    let mut peer_participant = [0u8; 16];
                                    peer_participant[..12].copy_from_slice(&msg.peer_guid_prefix);
                                    peer_participant[12..]
                                        .copy_from_slice(&[0x00, 0x00, 0x01, 0xc1]);
                                    let peer_vendor = discovery_fsm.vendor_id_for_participant(
                                        &GUID::from_bytes(peer_participant),
                                    );
                                    Self::send_sedp_heartbeat_response(
                                        &transport,
                                        our_guid_prefix,
                                        &msg.peer_guid_prefix,
                                        peer_vendor,
                                        &an.writer_entity_id,
                                        an_peer_port,
                                        peer_addr.ip(),
                                        &metrics,
                                        i64::try_from(hb_first).unwrap_or(1),
                                        hb_last, // last_seq = the writer's last number
                                        &mut acknack_count,
                                    );
                                } else {
                                    log::debug!(
                                    "[CONTROL] SEDP ACKNACK pure-ACK from {:?} writer={:02x?} -- no HB response",
                                    peer_addr.ip(), an.writer_entity_id
                                );
                                }
                            } else if let Some(writer) = type_lookup_writers
                                .as_deref()
                                .and_then(|w| w.for_writer(&an.writer_entity_id))
                            {
                                // A TypeLookup writer keeps its own short
                                // history: it answers for itself (GAP for the
                                // numbers this peer was never sent, repair for
                                // the held ones it NACKs, a HEARTBEAT). Only a
                                // participant discovery knows, at the locator it
                                // announced: never the datagram's source.
                                let Some(peer_addr) =
                                    discovery_fsm.first_metatraffic_locator(&msg.peer_guid_prefix)
                                else {
                                    break 'handled;
                                };
                                let answer = writer.answer_acknack(
                                    &our_guid_prefix,
                                    &msg.peer_guid_prefix,
                                    an.count.unwrap_or(0),
                                    an.bitmap_base,
                                    &an.missing_ranges,
                                    Instant::now(),
                                );
                                for datagram in &answer {
                                    if let Err(e) = transport.send_to_endpoint(datagram, &peer_addr)
                                    {
                                        log::debug!(
                                            "[CONTROL] TypeLookup ACKNACK answer to {}: {}",
                                            peer_addr,
                                            e
                                        );
                                    }
                                }
                            } else if an.writer_entity_id
                                == RTPS_ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_WRITER
                            {
                                // RTPS v2.5 Sec.8.4.13.3: our
                                // BuiltinParticipantMessageWriter is RELIABLE.
                                // It keeps no HistoryCache in `topic_registry`
                                // (it is not a DDS topic writer), so without
                                // this route an ACKNACK naming it would fall
                                // through to the generic branch below, which
                                // finds nothing to answer with: a peer that lost
                                // our last assertion would never get it repaired.
                                let Some(peer_addr) = Self::resolve_peer_metatraffic_addr(
                                    &msg.peer_guid_prefix,
                                    msg.origin,
                                    &discovery_fsm,
                                ) else {
                                    break 'handled;
                                };
                                let timestamp = std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .map(super::rtps_packet::rtps_time_from_unix)
                                    .unwrap_or((0, 0));
                                for packet in
                                    crate::dds::liveliness::answer_participant_message_acknack(
                                        &our_guid_prefix,
                                        &msg.peer_guid_prefix,
                                        an.bitmap_base,
                                        &an.missing_ranges,
                                        timestamp,
                                    )
                                {
                                    if transport.send_to_endpoint(&packet, &peer_addr).is_ok() {
                                        metrics.acknacks_sent.fetch_add(1, Ordering::Relaxed);
                                    }
                                }
                            } else if let Some(ref registry) = topic_registry {
                                // Hand the parsed ACKNACK over whole - the writer
                                // it names, its base, its holes - including a pure
                                // acknowledgement: the named writer both repairs
                                // the holes and records what the reader holds.
                                // The full reader GUID lets it route repairs
                                // unicast to that reader.
                                let mut reader_guid = [0u8; 16];
                                reader_guid[..12].copy_from_slice(&msg.peer_guid_prefix);
                                reader_guid[12..16].copy_from_slice(&an.reader_entity_id);
                                let _ = registry.deliver_acknack(reader_guid, an);
                            }
                        } else if let Some(ref nf) = msg.nack_frag {
                            // Handle NACK_FRAG: Request for fragment retransmission
                            // Dispatch to topic registry for writer-side handling
                            //
                            // Unlike the ACKNACK branch
                            // above (`is_sedp_endpoint` + `secure_sedp_
                            // acknack_must_be_refused`), this one is NOT
                            // gated on `nf.writer_entity_id` naming a
                            // secure SEDP builtin writer at all, for a
                            // concrete reason: `topic_registry` (a
                            // `TopicRegistry` of USER application writers)
                            // never holds a `NackFragHandler` for a
                            // builtin SEDP writer -- only `dds::writer::
                            // Writer` instances register one, and SEDP's
                            // own writers are internal to discovery, never
                            // user-created. `deliver_nack_frag` below
                            // therefore matches ZERO handlers for ANY
                            // SEDP-targeted NACK_FRAG, clear or protected:
                            // there is no SEDP-specific answering path for
                            // this message to reach, so there is nothing a
                            // refusal gate would be protecting (the
                            // ACKNACK gate exists because `retransmit_sedp_
                            // data` DOES actively answer a SEDP ACKNACK).
                            // A future SEDP-fragment repair path (large
                            // TypeObjects can fragment) would need this
                            // gate re-examined alongside it.
                            if let Some(ref registry) = topic_registry {
                                if !nf.missing_fragments.is_empty() {
                                    // Build full reader GUID for unicast retransmit targeting.
                                    let mut reader_guid = [0u8; 16];
                                    reader_guid[..12].copy_from_slice(&msg.peer_guid_prefix);
                                    reader_guid[12..16].copy_from_slice(&nf.reader_entity_id);
                                    log::debug!(
                                    "[CONTROL] NACK_FRAG: writer={:02x?} sn={} missing_frags={:?} reader={:02x?}",
                                    nf.writer_entity_id,
                                    nf.writer_sn,
                                    nf.missing_fragments,
                                    &reader_guid[..8]
                                );
                                    let _ = registry.deliver_nack_frag(
                                        &nf.writer_entity_id,
                                        nf.writer_sn,
                                        &nf.missing_fragments,
                                        Some(reader_guid),
                                    );
                                }
                            }
                        } else if let Some(ref gap) = msg.gap {
                            if let Some(endpoints) = type_lookup_writers.as_deref() {
                                if TypeLookupWriters::reader_for(&gap.writer_entity_id).is_some() {
                                    // A peer TypeLookup writer's irrelevant
                                    // numbers: our reader stops waiting on them.
                                    endpoints.received.on_gap(
                                        msg.peer_guid_prefix,
                                        gap.writer_entity_id,
                                        gap.gap_start,
                                        gap.gap_list_base,
                                    );
                                    for sn in &gap.gap_list_seqs {
                                        endpoints.received.on_gap(
                                            msg.peer_guid_prefix,
                                            gap.writer_entity_id,
                                            *sn,
                                            sn + 1,
                                        );
                                    }
                                    break 'handled;
                                }
                            }
                            // Handle GAP: advance per-writer reorder gate so buffered
                            // live samples waiting on writer-declared-irrelevant
                            // sequences are released in order.
                            // Only user-data writers have a reorder gate; SEDP builtin
                            // writers do not have user-data subscribers.
                            if is_sedp_endpoint(&gap.writer_entity_id) {
                                // An SEDP writer retires the announcement of an
                                // endpoint it deleted with a GAP (RTPS v2.5
                                // Sec.8.5.4.4, Sec.8.3.8.4): the SEDP reader counts
                                // the range as received, or its ACKNACK asks for
                                // that number for as long as the writer lives.
                                // Every number the GAP names, the range and the
                                // bitmap alike (Sec.8.3.8.4, Table 8.43).
                                sedp_registry.on_gap_listed(
                                    sedp_proxy_guid(&msg.peer_guid_prefix, &gap.writer_entity_id),
                                    i64::try_from(gap.gap_start).unwrap_or(i64::MAX),
                                    i64::try_from(gap.gap_list_base).unwrap_or(i64::MAX),
                                    &gap.gap_list_seqs,
                                );
                            } else {
                                log::debug!(
                                "[CONTROL] GAP: writer={:02x?} gap_start={} gap_list_base={} list_len={}",
                                gap.writer_entity_id,
                                gap.gap_start,
                                gap.gap_list_base,
                                gap.gap_list_seqs.len()
                            );

                                // One door for the reader side of a GAP: each reader
                                // it addresses advances its reorder gate AND its
                                // WriterProxy, so the next ACKNACK stops requesting
                                // what the writer declared irrelevant (a writer that
                                // purged SN 1..34 sends GAP(gapStart=1,
                                // gapList.base=35) then DATA from 36:
                                // without this the ACKNACK base stays at 1). Shared
                                // with the TCP/QUIC door: `release_reorder_gate`.
                                if let Some(ref registry) = topic_registry {
                                    if applies_gate_on_control(&msg, &gap.writer_entity_id) {
                                        release_group_reorder_gate(
                                            registry,
                                            &msg.peer_guid_prefix,
                                            gap,
                                            msg.reader_entity_id(),
                                            msg.gap_filtered_count(),
                                            msg.gap_names_gsns(),
                                            msg.gap_group_info(),
                                        );
                                    }
                                }
                            }
                        }
                    }

                    // Any control message from a known peer proves its
                    // process is alive: refresh liveness so the zombie purge
                    // (calibrated on the HDDS 3 s SPDP period) cannot evict a
                    // live slow announcer (SPDP period of tens of seconds) mid-test.
                    // Cold path (~hundreds of msgs/s worst case). Counted
                    // once the message is handled; the replay of matches the
                    // mark releases goes to the worker.
                    if let Some(participant) =
                        discovery_fsm.note_control_traffic(&msg.peer_guid_prefix)
                    {
                        discovery_work.replay(participant);
                    }
                }
                Err(channel::RecvTimeoutError::Timeout) => {}
                Err(channel::RecvTimeoutError::Disconnected) => {
                    log::debug!("[CONTROL] Channel disconnected, exiting");
                    break;
                }
            }

            discovery_work.tick_if_inline();
            #[cfg(feature = "security")]
            discovery_fsm.retry_secure_sedp_repairs(Instant::now());

            // Flush batch if interval elapsed or batch is large
            if last_flush.elapsed() >= flush_interval || batch.len() >= BATCH_MAX_SIZE {
                if !batch.is_empty() {
                    for (writer_guid, batches) in Self::fold_heartbeat_batch(batch.drain()) {
                        // Same idiom this file uses to BUILD the GUID above:
                        // copy_from_slice on two equal-length slices cannot
                        // fail, so no unwrap is needed to say so.
                        let mut writer_entity_id = [0u8; 4];
                        writer_entity_id.copy_from_slice(&writer_guid[12..16]);

                        if is_sedp_endpoint(&writer_entity_id) {
                            continue;
                        }

                        for (addressees, state) in batches {
                            Self::answer_user_heartbeat(
                                &transport,
                                &user_data_registry,
                                &discovery_fsm,
                                &topic_registry,
                                &endpoint_registry,
                                &metrics,
                                our_guid_prefix,
                                &UserHeartbeat {
                                    writer_guid,
                                    addressees,
                                    first_seq: state.first_seq,
                                    last_seq: state.highest_seq,
                                    count: state.last_count,
                                    final_flag: false,
                                    peer_guid_prefix: state.peer_guid_prefix,
                                    peer_addr: state.peer_addr,
                                },
                            );
                        }
                    }
                    // Shrink HashMap capacity to avoid memory accumulation
                    batch.shrink_to_fit();
                }
                last_flush = Instant::now();
            }

            // Preemptive SEDP solicitation. Cold path, gated to peers with
            // vendorId 0x0101; harmless empty-bitmap ACKNACKs.
            if last_storm_tick.elapsed() >= Duration::from_millis(CONNEXT_SEDP_STORM_INTERVAL_MS) {
                last_storm_tick = Instant::now();
                Self::tick_connext_sedp_storm(
                    &transport,
                    our_guid_prefix,
                    &discovery_fsm,
                    &metrics,
                    &mut connext_storms,
                    &mut acknack_count,
                );
                Self::tick_sedp_solicitation(
                    &transport,
                    our_guid_prefix,
                    &discovery_fsm,
                    &metrics,
                    &mut solicited,
                    &mut acknack_count,
                );
            }
        }

        discovery_work.stop();
        log::debug!("[CONTROL] Control handler thread exiting");
    }

    /// Fire repeated preemptive empty-bitmap ACKNACKs at the SEDP publications
    /// writer (0x000003c2) of freshly discovered peers with vendorId 0x0101.
    ///
    /// # Why
    /// For vendorId 0x0101 we solicit the peer's SEDP publications early and
    /// repeatedly, so that all of its writers are announced within the
    /// discovery phase rather than one at a time. A multi-topic coherent set
    /// needs every writer matched before its samples are read, which the
    /// interoperability tests exercise. HDDS sends up to
    /// CONNEXT_SEDP_STORM_COUNT preemptive empty-bitmap ACKNACKs
    /// (bitmapBase=1, numBits=0) to the SEDP publications writer 0x000003c2,
    /// one every CONNEXT_SEDP_STORM_INTERVAL_MS.
    ///
    /// # Safety / blast radius
    /// Gated on the vendor id 0x0101 captured at SPDP (cold path), so no other
    /// vendor and no self path is touched. An empty-bitmap ACKNACK is a pure
    /// "send me everything from seq 1" solicitation (RTPS v2.5 Sec.8.3.8.1); a
    /// peer with nothing withheld simply ignores it. Each peer receives at most
    /// CONNEXT_SEDP_STORM_COUNT of them, then is silent.
    fn tick_connext_sedp_storm(
        transport: &UdpTransport,
        our_guid_prefix: [u8; 12],
        discovery_fsm: &DiscoveryFsm,
        metrics: &ControlMetrics,
        storms: &mut std::collections::HashMap<[u8; 12], ConnextStorm>,
        acknack_count: &mut u32,
    ) {
        // Register any newly discovered participants with vendor id 0x0101.
        {
            let db = discovery_fsm.db();
            let Ok(guard) = db.read() else {
                return;
            };
            for info in guard.values() {
                if info.vendor_id != Some(CONNEXT_VENDOR_ID) {
                    continue;
                }
                let prefix: [u8; 12] = match info.guid.as_bytes()[..12].try_into() {
                    Ok(p) => p,
                    Err(_) => continue,
                };
                if prefix == our_guid_prefix || storms.contains_key(&prefix) {
                    continue;
                }
                let Some(ep) = info.endpoints.first() else {
                    continue;
                };
                // Backdate last_sent so the first ACKNACK fires on this tick.
                let first_due = Instant::now()
                    .checked_sub(Duration::from_millis(CONNEXT_SEDP_STORM_INTERVAL_MS))
                    .unwrap_or_else(Instant::now);
                storms.insert(
                    prefix,
                    ConnextStorm {
                        peer_ip: ep.ip(),
                        peer_port: ep.port(),
                        sent: 0,
                        last_sent: first_due,
                    },
                );
                log::debug!(
                    "[CONTROL] connext SEDP storm armed for peer={:02x?} dest={}:{}",
                    &prefix[..4],
                    ep.ip(),
                    ep.port()
                );
            }
        }

        // Fire any due solicitations.
        for (prefix, storm) in storms.iter_mut() {
            if storm.sent >= CONNEXT_SEDP_STORM_COUNT {
                continue;
            }
            if storm.last_sent.elapsed() < Duration::from_millis(CONNEXT_SEDP_STORM_INTERVAL_MS) {
                continue;
            }

            // Preemptive empty-bitmap ACKNACK (base=1, numBits=0) to the SEDP
            // publications writer; non-final so the writer is asked to respond.
            let acknack = build_acknack_packet_with_final(
                our_guid_prefix,
                *prefix,
                crate::core::rtps_constants::RTPS_ENTITYID_SEDP_PUBLICATIONS_READER,
                crate::core::rtps_constants::RTPS_ENTITYID_SEDP_PUBLICATIONS_WRITER,
                1,
                &[],
                *acknack_count,
                false,
            );
            *acknack_count = acknack_count.wrapping_add(1);

            let dest_addr = SocketAddr::new(storm.peer_ip, storm.peer_port);
            if transport.send_to_endpoint(&acknack, &dest_addr).is_ok() {
                metrics.acknacks_sent.fetch_add(1, Ordering::Relaxed);
                storm.sent += 1;
                storm.last_sent = Instant::now();
            }
        }
    }

    /// Ask each HDDS participant discovered since the last tick, by a
    /// pre-emptive ACKNACK from our SEDP publications and subscriptions
    /// readers (bitmapBase 1, no bit set, Final clear), for its SEDP
    /// history. RTPS v2.5 Sec.8.4.2.2 lets a reader send an ACKNACK "when it
    /// first discovers a Writer"; our SEDP writer answers one whose base is
    /// at or below its last change with its history and a HEARTBEAT.
    ///
    /// Without it, a participant that took a live peer for departed (a
    /// lease expiry over an outage, a probation purge) and then discovered
    /// it again never learned the peer's endpoints: the peer still holds
    /// this participant as matched and acknowledged, so it neither pushes
    /// its announcements again nor sends a HEARTBEAT a fresh proxy could
    /// NACK, and our readers never matched its writers again.
    ///
    /// Per discovery of a peer (its `created_at`, which a new discovery
    /// renews), repeated with backoff until a HEARTBEAT of that SEDP writer
    /// arrives or `SEDP_SOLICIT_ATTEMPTS` were sent (`SedpSolicitations`): a
    /// datagram can be lost, and a peer that does not know us yet drops it.
    /// HDDS peers only: another vendor's discovery is its own (and vendor
    /// id 0x0101 has its storm above).
    fn tick_sedp_solicitation(
        transport: &UdpTransport,
        our_guid_prefix: [u8; 12],
        discovery_fsm: &DiscoveryFsm,
        metrics: &ControlMetrics,
        solicited: &mut SedpSolicitations,
        acknack_count: &mut u32,
    ) {
        let peers: std::collections::HashMap<[u8; 12], Instant> = {
            let db = discovery_fsm.db();
            let Ok(guard) = db.read() else {
                return;
            };
            guard
                .values()
                .filter(|info| {
                    info.vendor_id == Some(crate::core::rtps_constants::HDDS_VENDOR_ID_U16)
                })
                .filter_map(|info| {
                    let prefix: [u8; 12] = info.guid.as_bytes()[..12].try_into().ok()?;
                    (prefix != our_guid_prefix).then_some((prefix, info.created_at))
                })
                .collect()
        };
        for (prefix, writers) in solicited.due(&peers, Instant::now()) {
            let Some(dest) = discovery_fsm.first_metatraffic_locator(&prefix) else {
                continue;
            };
            for writer in writers {
                let reader = if writer
                    == crate::core::rtps_constants::RTPS_ENTITYID_SEDP_PUBLICATIONS_WRITER
                {
                    crate::core::rtps_constants::RTPS_ENTITYID_SEDP_PUBLICATIONS_READER
                } else {
                    crate::core::rtps_constants::RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_READER
                };
                let acknack = build_acknack_packet_with_final(
                    our_guid_prefix,
                    prefix,
                    reader,
                    writer,
                    1,
                    &[],
                    *acknack_count,
                    false,
                );
                *acknack_count = acknack_count.wrapping_add(1);
                if transport.send_to_endpoint(&acknack, &dest).is_ok() {
                    metrics.acknacks_sent.fetch_add(1, Ordering::Relaxed);
                }
            }
            log::debug!(
                "[CONTROL] SEDP history solicited from peer={:02x?} at {}",
                &prefix[..4],
                dest
            );
        }
    }

    /// A flushed batch of HEARTBEATs, grouped by writer: each reader
    /// answers once, from the latest announcement that addresses it. The
    /// one addressed to one reader is folded with the one addressed to
    /// every reader (a reader answered from its folded state already holds
    /// the latest count, so the HEARTBEAT to every reader would be a
    /// duplicate to it, RTPS 2.5 8.3.8.6); the one to every reader is
    /// answered last, by the readers not named.
    fn fold_heartbeat_batch(
        batch: impl IntoIterator<Item = (([u8; 16], [u8; 4]), WriterState)>,
    ) -> Vec<([u8; 16], WriterBatches)> {
        type Batched = (Option<WriterState>, Vec<([u8; 4], WriterState)>);
        let mut by_writer: std::collections::HashMap<[u8; 16], Batched> =
            std::collections::HashMap::new();
        for ((writer_guid, reader_entity_id), state) in batch {
            let (to_all, to_one) = by_writer.entry(writer_guid).or_default();
            if reader_entity_id == ENTITYID_UNKNOWN {
                *to_all = Some(state);
            } else {
                to_one.push((reader_entity_id, state));
            }
        }
        by_writer
            .into_iter()
            .map(|(writer_guid, (to_all, to_one))| {
                let mut batches: Vec<(Addressees, WriterState)> = to_one
                    .into_iter()
                    .map(|(reader, state)| {
                        let state = match to_all {
                            Some(ref all) => state.folded_with(all),
                            None => state,
                        };
                        (Addressees::One(reader), state)
                    })
                    .collect();
                if let Some(all) = to_all {
                    batches.push((Addressees::All, all));
                }
                (writer_guid, batches)
            })
            .collect()
    }

    /// Answer a user writer's HEARTBEAT: one ACKNACK per local reliable
    /// reader matched with that writer, each built from that reader's own
    /// proxy and sent under that reader's own readerId (RTPS 2.5 8.4.12).
    /// A writer no local reliable reader is matched with gets no answer.
    #[allow(clippy::too_many_arguments)]
    fn answer_user_heartbeat(
        transport: &UdpTransport,
        registry: &ReaderProxyRegistry,
        discovery_fsm: &DiscoveryFsm,
        topic_registry: &Option<Arc<TopicRegistry>>,
        endpoint_registry: &crate::core::discovery::EndpointRegistry,
        metrics: &ControlMetrics,
        our_guid_prefix: [u8; 12],
        hb: &UserHeartbeat,
    ) {
        // DDS Security v1.1 Sec.8.8.7.1, 9.4.3: a writer the security
        // plugins do not admit gets no ACKNACK and moves no WriterProxy
        // state. Its topic is the one its SEDP announced
        // (`get_topic_by_guid`); one unknown is not admitted.
        #[cfg(feature = "security")]
        if discovery_fsm.admission_gate_active() {
            let admitted = topic_registry
                .as_ref()
                .and_then(|topics| topics.get_topic_by_guid(&hb.writer_guid))
                .is_some_and(|topic| {
                    discovery_fsm.admits_remote_endpoint(
                        &topic,
                        &GUID::from_bytes(hb.writer_guid),
                        true,
                    )
                });
            if !admitted {
                log::debug!(
                    "[CONTROL] HEARTBEAT of writer {:02x?} not answered: the security plugins \
                     do not admit it",
                    hb.writer_guid
                );
                return;
            }
        }
        let answers = registry.answer_heartbeat(
            &hb.writer_guid,
            hb.addressees,
            &HeartbeatSeen {
                first_seq: hb.first_seq,
                last_seq: hb.last_seq,
                count: hb.count,
                final_flag: hb.final_flag,
            },
        );
        if answers.is_empty() {
            return;
        }
        // The credit state above (`registry.answer_heartbeat`) is what makes
        // this writer answerable at all, and it already ran: a relayed
        // HEARTBEAT from a peer with no metatraffic locator of its own must
        // not leave that state stuck at its initial value forever. Only the
        // ACKNACK itself needs a destination.
        let dest_addr = match hb.peer_addr {
            Some(peer_addr) => {
                // Per-vendor user ACKNACK port dialect (zzdds/FastDDS
                // metatraffic+1 gate, OpenDDS SEDP writer locator). See
                // resolve_user_acknack_port for the wire rationale.
                // Vendor-gated -> zero blast on the other vendors.
                let ack_port = resolve_user_acknack_port(
                    discovery_fsm,
                    topic_registry,
                    endpoint_registry,
                    &hb.writer_guid,
                    peer_addr.port(),
                );
                SocketAddr::new(peer_addr.ip(), ack_port)
            }
            // Relayed (behind an INFO_SRC, 8.3.8.10) from a participant that
            // announced no metatraffic locator: answer through the
            // WriterProxy's other discovered locators (8.4.10.4, 8.4.12.2).
            // Already user-data locators, so no port dialect applies.
            None => match writer_proxy_unicast_locator(endpoint_registry, &hb.writer_guid) {
                Some(locator) => locator,
                None => {
                    log::debug!(
                        "[CONTROL] no reply address for writer {:02x?}: user ACKNACK dropped, \
                         state already updated",
                        hb.writer_guid
                    );
                    return;
                }
            },
        };
        let [.., w0, w1, w2, w3] = hb.writer_guid;
        let writer_entity_id = [w0, w1, w2, w3];

        for answer in answers {
            let [.., r0, r1, r2, r3] = answer.reader;
            let acknack = build_acknack_packet_with_final(
                our_guid_prefix,
                hb.peer_guid_prefix,
                [r0, r1, r2, r3],
                writer_entity_id,
                answer.bitmap_base,
                &answer.missing,
                answer.count,
                answer.final_flag,
            );
            if transport.send_to_endpoint(&acknack, &dest_addr).is_ok() {
                metrics.acknacks_sent.fetch_add(1, Ordering::Relaxed);
                registry.mark_acknack_sent_for(&hb.writer_guid, &answer.reader);
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
        missing: &[i64],
        acknack_count: &mut u32,
        #[cfg(feature = "security")] discovery_fsm: &DiscoveryFsm,
    ) {
        let our_reader_id = derive_reader_entity_id(their_writer_id);
        let dest_addr = SocketAddr::new(peer_ip, peer_port);

        let seq_base = bitmap_base.max(1) as u64;
        // Final is set only when nothing is missing (RTPS v2.5 Sec.8.3.8.1).
        let missing_seqs: Vec<u64> = missing
            .iter()
            .filter_map(|&s| u64::try_from(s).ok())
            .filter(|&s| s >= seq_base)
            .collect();
        let final_flag = missing_seqs.is_empty();

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

        // DDS Security v1.1 Sec.8.8.9.3: our secure SEDP reader protects
        // its own ACKNACK with the key it minted and announced
        // (`register_builtin_reader_keys`), under the writer's matching
        // entity id (`builtin_peer_entity_id`, 1:1 by construction for a
        // builtin tunnel). A plain (non-secure) SEDP endpoint, or one
        // whose key has not been minted yet, is sent unprotected.
        #[cfg(feature = "security")]
        let acknack = if their_writer_id[0] == 0xff {
            match discovery_fsm.local_builtin_reader_material_for(peer_guid_prefix, their_writer_id)
            {
                Some(material) => {
                    match crate::security::crypto::secure_sedp::protect_reader_control_packet(
                        &acknack, &material,
                    ) {
                        Some(protected) => protected,
                        None => {
                            log::warn!(
                                "[CONTROL] could not protect SEDP ACKNACK to {:02x?} writer={:02x?}: \
                                 not sent",
                                peer_guid_prefix,
                                their_writer_id
                            );
                            return;
                        }
                    }
                }
                None => acknack,
            }
        } else {
            acknack
        };

        match transport.send_to_endpoint(&acknack, &dest_addr) {
            Ok(_) => {
                metrics.acknacks_sent.fetch_add(1, Ordering::Relaxed);
                log::debug!(
                    "[CONTROL] Sent SEDP ACKNACK to {}:{} writer={:02x?} base={} final={} missing={}",
                    peer_ip, peer_port, their_writer_id, seq_base, final_flag, missing_seqs.len()
                );
            }
            Err(e) => {
                log::debug!(
                    "[CONTROL] Failed SEDP ACKNACK to {}:{} writer={:02x?}: {}",
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
    /// When first_seq > 0, use the provided range (from retransmission).
    /// This tells the peer reader that seq nums below first_seq are no longer available,
    /// preventing infinite NACK loops for old seq nums.
    #[allow(clippy::too_many_arguments)]
    fn send_sedp_heartbeat_response(
        transport: &UdpTransport,
        our_guid_prefix: [u8; 12],
        peer_guid_prefix: &[u8; 12],
        peer_vendor: Option<u16>,
        their_writer_id: &[u8; 4],
        peer_port: u16,
        peer_ip: std::net::IpAddr,
        metrics: &ControlMetrics,
        retransmit_first: i64,
        retransmit_last: i64,
        _acknack_count: &mut u32,
    ) {
        let dest_addr = SocketAddr::new(peer_ip, peer_port);

        // Use retransmitted range if provided, otherwise fall back to counters.
        // CRITICAL: first_seq MUST match the actual DATA we sent, otherwise
        // the peer reader keeps NACKing old (non-existent) seq nums in an infinite loop.
        let (first_seq, last_seq) = if retransmit_first > 0 {
            (retransmit_first as u64, retransmit_last as u64)
        } else {
            use super::rtps_packet::{get_publications_last_seq, get_subscriptions_last_seq};
            let last = if sedp_endpoint_kind(their_writer_id) == Some(SedpEndpointKind::Reader) {
                get_subscriptions_last_seq()
            } else if sedp_endpoint_kind(their_writer_id) == Some(SedpEndpointKind::Writer) {
                get_publications_last_seq()
            } else {
                0
            };
            (1, last)
        };

        log::debug!(
            "[CONTROL] Sending SEDP HEARTBEAT first={} last={} to {}:{}",
            first_seq,
            last_seq,
            peer_ip,
            peer_port
        );

        if let Some(packet) = sedp_heartbeat_response_packet(
            our_guid_prefix,
            peer_guid_prefix,
            peer_vendor,
            their_writer_id,
            first_seq,
            last_seq,
            peer_ip,
            peer_port,
        ) {
            if transport.send_to_endpoint(&packet, &dest_addr).is_ok() {
                metrics.acknacks_sent.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Retransmit SEDP DATA to peer that NACKed our SEDP writer.
    ///
    /// Uses FIXED positional sequence numbers (`SedpHistory`) instead of
    /// the global atomic counter. This is critical for multi-peer interop:
    /// with 5 remote participants each NACKing, allocating new seq nums per-peer
    /// causes an infinite escalation (peer A's retransmit invalidates peer B's
    /// HEARTBEAT range, causing peer B to re-NACK, ad infinitum).
    ///
    /// Each number is sent as what it currently is: the announcement of an endpoint
    /// that exists, a GAP for the announcement of one since deleted, the
    /// dispose of a deleted one (RTPS v2.5 Sec.8.5.4.4). A deleted endpoint is
    /// never announced again.
    ///
    /// Returns `Some((first, last, sent_data))`, the writer's first
    /// available and highest sequence numbers (`SedpHistory::
    /// first_available`) plus whether at least one of what was sent was a
    /// real DATA submessage rather than only a GAP, when anything was
    /// sent; `None` otherwise. The third field exists because `sent` (what
    /// decided this `Some`/`None` split) counts a GAP-only answer exactly
    /// like a real retransmission -- a caller that needs to tell them
    /// apart reads this field, not
    /// `Some`/`None`.
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
    ) -> Option<(u64, u64, bool)> {
        let target_kind = sedp_endpoint_kind(writer_entity_id)?;
        #[cfg(feature = "security")]
        if writer_entity_id[0] == 0xff && !discovery_fsm.is_peer_authenticated(peer_guid_prefix) {
            return None;
        }

        // Held across the sends below: the participant closes the history
        // under its write lock before its farewell, so a retransmission is
        // either on the wire before the farewell or not sent at all (a closed
        // history has nothing to send).
        let history = match sedp_cache.read() {
            Ok(g) => g,
            Err(e) => {
                log::debug!("[CONTROL] Failed to read SEDP cache: {}", e);
                return None;
            }
        };
        let (first, sends) = (
            history.first_available(target_kind),
            history.sends(Some(target_kind)),
        );

        if sends.is_empty() {
            log::debug!("[CONTROL] SEDP cache empty, nothing to retransmit");
            return None;
        }

        let dest_addr = SocketAddr::new(peer_ip, peer_port);
        let mut sent = 0u64;
        // `sent` alone cannot tell a real
        // DATA retransmission from a GAP-only answer (both move it), so a
        // caller that wants to know "did our history actually cross the
        // wire again" needs this narrower tally.
        let mut sent_data = 0u64;
        let mut last = 0u64;

        // Use locked dialect if available (the RTI dialect has its own SEDP format),
        // fallback to Hybrid for unknown or mixed vendors.
        let dialect = discovery_fsm
            .get_locked_dialect()
            .unwrap_or(Dialect::Hybrid);

        // Only a participant discovery knows is served: a remote reader is
        // matched to our SEDP writer through its SPDP (RTPS v2.5 Sec.8.5.3),
        // and a writer answers the ACKNACKs of its matched readers only
        // (Sec.8.4.7, Sec.8.4.9). The SPDP that makes the peer known sends it
        // the history, built with the class decided here.
        let Some(type_object) = discovery_fsm.type_object_pid_for(peer_guid_prefix) else {
            log::debug!(
                "[CONTROL] SEDP ACKNACK from {:02x?}, a participant discovery does not know: \
                 not served",
                &peer_guid_prefix[..4]
            );
            return None;
        };
        for send in &sends {
            last = last.max(send.last_seq());
            // Governance alone decides where the change goes: without a
            // document the endpoint's attribute says nothing of discovery
            // (`governed_discovery_protected`).
            #[cfg(feature = "security")]
            let discovery_protected =
                crate::security::crypto::secure_sedp::governed_discovery_protected(
                    discovery_fsm.discovery_governed(),
                    send.discovery_protected(),
                );
            #[cfg(feature = "security")]
            if writer_entity_id[0] == 0xff && discovery_protected == Some(false) {
                // The endpoint belongs to ordinary SEDP, so this secure
                // writer declares its shared-history number irrelevant.
                if let Ok(gap) = send.build_gap(&our_guid_prefix) {
                    let gap = secure_sedp_gap(gap, writer_entity_id);
                    if transport.send_to_endpoint(&gap, &dest_addr).is_ok() {
                        sent += 1;
                    }
                }
                continue;
            }
            // To an authenticated participant the repair goes where the
            // original went: on the secure SEDP topic
            // (`DiscoveryFsm::sedp_for_peer`).
            match send
                .build_for(
                    &our_guid_prefix,
                    Some(peer_guid_prefix),
                    dialect,
                    type_object,
                )
                .map(|pkt| {
                    discovery_fsm.sedp_for_peer(peer_guid_prefix, pkt, send.discovery_protected())
                }) {
                // Not for this participant: the number as a GAP of the
                // regular writer, so its reader does not ask for it again.
                Ok(None) => {
                    if let Ok(gap) = send.build_gap(&our_guid_prefix) {
                        #[cfg(feature = "security")]
                        let gap = if writer_entity_id[0] == 0xff {
                            secure_sedp_gap(gap, writer_entity_id)
                        } else {
                            gap
                        };
                        let sent_gap = transport.send_to_endpoint(&gap, &dest_addr);
                        #[cfg(feature = "security")]
                        if sent_gap.is_ok() && writer_entity_id[0] == 0xff {
                            sent += 1;
                        }
                        #[cfg(not(feature = "security"))]
                        let _ = sent_gap;
                    }
                }
                Ok(Some(pkt)) => {
                    #[cfg(feature = "security")]
                    let pkt = if writer_entity_id[0] == 0xff && send.is_gap() {
                        secure_sedp_gap(pkt, writer_entity_id)
                    } else {
                        pkt
                    };
                    if transport.send_to_endpoint(&pkt, &dest_addr).is_ok() {
                        sent += 1;
                        if !send.is_gap() {
                            sent_data += 1;
                        }
                        metrics.acknacks_sent.fetch_add(1, Ordering::Relaxed);
                    }
                }
                Err(e) => {
                    log::debug!("[CONTROL] Failed to build SEDP retransmit packet: {:?}", e);
                }
            }
        }

        if sent > 0 {
            log::debug!(
                "[CONTROL] Retransmitted {} SEDP {:?} message(s), {} as real DATA, \
                 seq=1..{} to {} (fixed seq)",
                sent,
                target_kind,
                sent_data,
                last,
                dest_addr
            );
            Some((first, last, sent_data > 0))
        } else {
            None
        }
    }

    /// Shutdown control handler gracefully
    pub fn shutdown(mut self) {
        self.running.store(false, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            crate::core::rt::shutdown::join_bounded(handle, "control handler");
        }
    }
}

impl Drop for ControlHandler {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            crate::core::rt::shutdown::join_bounded(handle, "control handler");
        }
    }
}

/// The discovery work the control thread hands off: replaying the matches a
/// late liveness mark released (`DiscoveryFsm::replay_after_late_eligibility`)
/// and the probation ticks (`DiscoveryFsm::maybe_complete_probation`), on a
/// thread of its own. The probation boundary fires on our own clock, not only
/// on the next SPDP/SEDP: a peer that goes quiet after its startup burst
/// (its next SPDP possibly tens of seconds away) would otherwise leave its deferred match
/// unresolved for as long as it stays quiet. Both surface matches to user
/// listeners, which must never stall the control loop.
struct DiscoveryWorker {
    /// `None` when the worker could not be spawned: the work then runs on
    /// the control thread.
    sender: Option<Sender<GUID>>,
    handle: Option<JoinHandle<()>>,
    fsm: Arc<DiscoveryFsm>,
}

impl DiscoveryWorker {
    /// The worker's wake period: the probation ticks' resolution.
    const TICK: Duration = Duration::from_millis(10);

    fn spawn(fsm: Arc<DiscoveryFsm>, running: Arc<AtomicBool>) -> Self {
        let (sender, receiver) = channel::unbounded::<GUID>();
        let worker_fsm = Arc::clone(&fsm);
        let spawned = std::thread::Builder::new()
            .name("hdds-discovery-work".to_string())
            .spawn(crate::core::rt::shutdown::owned(move || {
                Self::run(&worker_fsm, &receiver, &running)
            }));
        match spawned {
            Ok(handle) => Self {
                sender: Some(sender),
                handle: Some(handle),
                fsm,
            },
            Err(e) => {
                log::error!(
                    "[CONTROL] discovery worker not spawned ({}): its work runs on the control thread",
                    e
                );
                Self {
                    sender: None,
                    handle: None,
                    fsm,
                }
            }
        }
    }

    /// The worker's loop. A replay and a probation tick run user listeners
    /// (`on_publication_matched`, ...); a listener that panics must not end
    /// the worker: the replays queued behind it would be lost, and the
    /// probation ticks (the boundary, the verdicts, the silence purge) would
    /// run on nobody's clock, `tick_if_inline` falling back only when no
    /// worker was ever spawned. So each turn runs under `catch_unwind`; a
    /// panic is logged, and what the panicking turn had not yet notified is
    /// lost with it (the listener's own failure), not the worker.
    ///
    /// It ends once its participant has said its farewell
    /// (`DiscoveryFsm::depart`): the participant's fields, the control
    /// handler among them, drop after that, and until then the worker would
    /// still drain and purge for a participant that is leaving.
    fn run(fsm: &DiscoveryFsm, receiver: &Receiver<GUID>, running: &AtomicBool) {
        while running.load(Ordering::Relaxed) && !fsm.has_departed() {
            let job = match receiver.recv_timeout(Self::TICK) {
                Ok(participant) => Some(participant),
                Err(channel::RecvTimeoutError::Timeout) => None,
                Err(channel::RecvTimeoutError::Disconnected) => break,
            };
            let turn = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                if let Some(participant) = job {
                    fsm.replay_after_late_eligibility(participant);
                }
                fsm.maybe_complete_probation();
            }));
            if turn.is_err() {
                log::error!(
                    "[CONTROL] a discovery listener panicked on the discovery worker; \
                     the worker carries on"
                );
            }
        }
    }

    /// Replay what `participant`'s late eligibility released. Never dropped:
    /// one participant becomes eligible once, so the queue is bounded by the
    /// participant count.
    fn replay(&self, participant: GUID) {
        let unsent = match self.sender {
            Some(ref sender) => sender.send(participant).err().map(|e| e.0),
            None => Some(participant),
        };
        if let Some(participant) = unsent {
            self.fsm.replay_after_late_eligibility(participant);
        }
    }

    /// The probation tick, on the control thread only when no worker runs.
    fn tick_if_inline(&self) {
        if self.sender.is_none() {
            self.fsm.maybe_complete_probation();
        }
    }

    fn stop(mut self) {
        drop(self.sender.take());
        if let Some(handle) = self.handle.take() {
            crate::core::rt::shutdown::join_bounded(handle, "discovery worker");
        }
    }
}

/// A user writer's HEARTBEAT as the control thread answers it.
struct UserHeartbeat {
    writer_guid: [u8; 16],
    /// The local readers it is answered for (from its readerId).
    addressees: Addressees,
    first_seq: i64,
    last_seq: i64,
    count: u32,
    final_flag: bool,
    peer_guid_prefix: [u8; 12],
    /// `None` when this HEARTBEAT could not be resolved to a reply address
    /// (relayed, and the peer announced no metatraffic locator of its own).
    /// The state `answer_user_heartbeat` updates runs regardless; when this
    /// is `None` the ACKNACK goes to the writer's other discovered locators
    /// (`writer_proxy_unicast_locator`), and is skipped only without any.
    peer_addr: Option<SocketAddr>,
}

/// The unicast locator a remote user writer's WriterProxy holds besides
/// its participant's metatraffic one (RTPS 2.5 8.4.10.4): the locator the
/// writer announced in SEDP, else its participant's default unicast locator
/// from SPDP. `None` when discovery recorded neither.
fn writer_proxy_unicast_locator(
    endpoint_registry: &crate::core::discovery::EndpointRegistry,
    writer_guid: &[u8; 16],
) -> Option<SocketAddr> {
    let writer = GUID::from_bytes(*writer_guid);
    endpoint_registry.get_writer_locator(&writer).or_else(|| {
        let mut participant = *writer_guid;
        participant[12..].copy_from_slice(&crate::core::rtps_constants::RTPS_ENTITYID_PARTICIPANT);
        endpoint_registry.get(&GUID::from_bytes(participant))
    })
}

/// Resolve the destination port for a user-data ACKNACK aimed at `writer_guid`.
///
/// Per-vendor user ACKNACK port dialect, resolved on the control (cold) path:
///
/// - OpenDDS (vendorId 0x0103): the ACKNACK goes to the unicast locator the
///   remote writer announced in SEDP (PID_UNICAST_LOCATOR), the locator its
///   user DATA and HEARTBEATs come from, because user-entity submessages sent
///   to the participant's metatraffic port are not acted on by that writer.
///   Uses the SEDP-announced writer locator port when known and keeps the
///   metatraffic port when no locator was announced.
///   Not scoped by durability: the ACKNACK requests only the holes this
///   reader is missing, so redirecting a VOLATILE writer's ACKNACK does not
///   cause the duplicate delivery described for the user-data port (below).
/// - zzdds (0x0123) / FastDDS (0x010F): user-data unicast port =
///   metatraffic + 1 (RTPS default port mapping d3-d1=1), scoped to
///   non-volatile writers. See `acknack_targets_user_data_port`.
/// - every other vendor: metatraffic port.
fn resolve_user_acknack_port(
    discovery_fsm: &DiscoveryFsm,
    topic_registry: &Option<Arc<TopicRegistry>>,
    endpoint_registry: &crate::core::discovery::EndpointRegistry,
    writer_guid: &[u8; 16],
    peer_port: u16,
) -> u16 {
    let vendor_id = discovery_fsm.vendor_id_for_participant(&GUID::from_bytes(*writer_guid));
    if vendor_id == Some(0x0103) {
        return endpoint_registry
            .get_writer_locator(&GUID::from_bytes(*writer_guid))
            .map(|locator| locator.port())
            .unwrap_or(peer_port);
    }
    if acknack_targets_user_data_port(vendor_id)
        && remote_writer_is_non_volatile(discovery_fsm, topic_registry, writer_guid)
    {
        return peer_port.saturating_add(1);
    }
    peer_port
}

/// Vendors that only act on user-data ACKNACKs delivered to the writer's
/// user-data unicast locator (metatraffic + 1, per the RTPS default port
/// mapping d3-d1=1). Every other vendor keeps the metatraffic port.
///
/// - zzdds (0x0123 up to 0.2.0, registered 0x011B from 0.3.1 on, see
///   `is_zzdds_vendor`) and FastDDS (0x010F): a user ACKNACK sent to the
///   metatraffic port is not acted on by these writers, so the history of a
///   non-volatile writer would never be replayed to a late-joining reader;
///   HDDS sends it to the user-data unicast port instead.
///
/// Gated with `remote_writer_is_non_volatile` at both call sites: redirecting
/// a VOLATILE writer's ACKNACK makes the peer retransmit live samples the
/// reader already holds, which the application would see as duplicates.
fn acknack_targets_user_data_port(vendor_id: Option<u16>) -> bool {
    matches!(vendor_id, Some(v) if is_zzdds_vendor(v) || v == EPROSIMA_VENDOR_ID_U16)
}

/// True when the remote writer identified by `writer_guid` advertises a
/// non-volatile durability (TRANSIENT_LOCAL / TRANSIENT / PERSISTENT) in
/// discovery.
///
/// Scopes the zzdds (`is_zzdds_vendor`) user-data ACKNACK port redirect:
/// only a non-volatile writer waits for our ACKNACK before it replays its
/// history and sends live data, so only it needs that ACKNACK on its
/// user-data locator. A
/// VOLATILE writer pushes live data without that handshake; redirecting
/// its ACKNACK to the user port makes the writer act on the reader's NACKs
/// and retransmit samples the reader already holds, so the application
/// sees duplicates. Returns false on any discovery miss (safe default: keep
/// the metatraffic port).
fn remote_writer_is_non_volatile(
    discovery_fsm: &DiscoveryFsm,
    topic_registry: &Option<Arc<TopicRegistry>>,
    writer_guid: &[u8; 16],
) -> bool {
    let Some(topic) = topic_registry
        .as_ref()
        .and_then(|reg| reg.get_topic_by_guid(writer_guid))
    else {
        return false;
    };
    discovery_fsm
        .find_writers_for_topic(&topic)
        .into_iter()
        .find(|w| w.endpoint_guid.as_bytes() == *writer_guid)
        .map(|w| !matches!(w.qos.durability, crate::dds::qos::Durability::Volatile))
        .unwrap_or(false)
}

/// Pre-emptive ACKNACKs sent to one discovery of a peer's SEDP writer at
/// most (`ControlHandler::tick_sedp_solicitation`).
const SEDP_SOLICIT_ATTEMPTS: u32 = 5;

/// Wait before the second solicitation; doubled after each one (200, 400,
/// 800, 1600 ms: the last goes about 3 s after the discovery).
const SEDP_SOLICIT_FIRST_BACKOFF: Duration = Duration::from_millis(200);

/// The two SEDP writers a peer is asked for its history.
const SOLICITED_SEDP_WRITERS: [[u8; 4]; 2] = [
    crate::core::rtps_constants::RTPS_ENTITYID_SEDP_PUBLICATIONS_WRITER,
    crate::core::rtps_constants::RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_WRITER,
];

/// Which SEDP writers of which discovered peers are still to be asked for
/// their history, and when (`ControlHandler::tick_sedp_solicitation`).
#[derive(Default)]
struct SedpSolicitations {
    peers: std::collections::HashMap<[u8; 12], Solicitation>,
}

struct Solicitation {
    /// The discovery this is for: the peer's `created_at`.
    discovered: Instant,
    /// Per `SOLICITED_SEDP_WRITERS`: no HEARTBEAT of it heard yet.
    pending: [bool; 2],
    attempts: u32,
    next_due: Instant,
}

impl SedpSolicitations {
    /// The writers to ask now, per peer, given the discovered peers and
    /// their `created_at`. A peer gone is forgotten, a new discovery of one
    /// starts over; a writer heard from, or asked `SEDP_SOLICIT_ATTEMPTS`
    /// times, is not asked again. Linear in the peers.
    fn due(
        &mut self,
        peers: &std::collections::HashMap<[u8; 12], Instant>,
        now: Instant,
    ) -> Vec<([u8; 12], Vec<[u8; 4]>)> {
        self.peers
            .retain(|prefix, s| peers.get(prefix) == Some(&s.discovered));
        let mut due = Vec::new();
        for (prefix, discovered) in peers {
            let s = self.peers.entry(*prefix).or_insert(Solicitation {
                discovered: *discovered,
                pending: [true; 2],
                attempts: 0,
                next_due: now,
            });
            if s.attempts >= SEDP_SOLICIT_ATTEMPTS || now < s.next_due {
                continue;
            }
            let writers: Vec<[u8; 4]> = SOLICITED_SEDP_WRITERS
                .iter()
                .zip(s.pending)
                .filter_map(|(writer, pending)| pending.then_some(*writer))
                .collect();
            if writers.is_empty() {
                continue;
            }
            s.attempts += 1;
            s.next_due = now + SEDP_SOLICIT_FIRST_BACKOFF * (1 << (s.attempts - 1));
            due.push((*prefix, writers));
        }
        due
    }

    /// A HEARTBEAT of `writer` from `peer`: if it is one of its SEDP
    /// writers, it is no longer to be asked.
    fn heard(&mut self, peer: &[u8; 12], writer: &[u8; 4]) {
        if let Some(s) = self.peers.get_mut(peer) {
            for (i, solicited) in SOLICITED_SEDP_WRITERS.iter().enumerate() {
                if solicited == writer {
                    s.pending[i] = false;
                }
            }
        }
    }
}

/// The datagram answering a SEDP ACKNACK: RTPS header, INFO_DST, a final
/// HEARTBEAT from our SEDP writer `their_writer_id` (the same entity id as
/// the peer's writer) to the matching reader, for `first_seq..=last_seq`.
///
/// For a vendor 0x0101 peer, and only for one, the HEARTBEAT is followed by
/// the vendor-specific submessage 0x80 that echoes the peer's locator
/// (`build_unknown80_locator`, layout from a Fast DDS capture). A Connext
/// 6.1 peer delivers samples with it and none without. It is not sent to
/// other peers: it is vendor-specific content under HDDS's vendor id, which
/// a receiver ignores (RTPS 2.5 Sec.8.3.4.1 rule 3), so its only effect
/// elsewhere would be the extra octets.
#[allow(clippy::too_many_arguments)]
fn sedp_heartbeat_response_packet(
    our_guid_prefix: [u8; 12],
    peer_guid_prefix: &[u8; 12],
    peer_vendor: Option<u16>,
    their_writer_id: &[u8; 4],
    first_seq: u64,
    last_seq: u64,
    peer_ip: std::net::IpAddr,
    peer_port: u16,
) -> Option<Vec<u8>> {
    use crate::protocol::dialect::{get_encoder, Dialect};
    use crate::protocol::rtps::encode_heartbeat_final;

    let our_writer_id = *their_writer_id;
    let their_reader_id = derive_reader_entity_id(their_writer_id);
    let encoder = get_encoder(Dialect::Hybrid);
    let mut packet = Vec::with_capacity(128);

    // RTPS Header
    packet.extend_from_slice(b"RTPS");
    packet.extend_from_slice(&[2, 4]);
    packet.extend_from_slice(&[0x01, 0x1a]);
    packet.extend_from_slice(&our_guid_prefix);

    // INFO_DST submessage
    packet.extend_from_slice(&encoder.build_info_dst(peer_guid_prefix));

    let count = 1;
    #[cfg(feature = "security")]
    let count = if their_writer_id[0] == 0xff {
        super::rtps_packet::next_sedp_heartbeat_count()
    } else {
        count
    };
    let heartbeat =
        encode_heartbeat_final(&their_reader_id, &our_writer_id, first_seq, last_seq, count)
            .ok()?;
    packet.extend_from_slice(&heartbeat);

    if peer_vendor == Some(crate::protocol::constants::RTI_VENDOR_ID_U16) {
        packet.extend_from_slice(&build_unknown80_locator(peer_ip, peer_port));
    }
    Some(packet)
}

/// Per-peer (vendor id 0x0101) state for the preemptive SEDP-solicitation storm.
/// See `ControlHandler::tick_connext_sedp_storm`.
struct ConnextStorm {
    /// Peer metatraffic unicast IP (ACKNACK destination).
    peer_ip: std::net::IpAddr,
    /// Peer metatraffic unicast port (ACKNACK destination).
    peer_port: u16,
    /// Preemptive ACKNACKs sent so far (capped at CONNEXT_SEDP_STORM_COUNT).
    sent: u32,
    /// When the last preemptive ACKNACK was sent (cadence gate).
    last_sent: Instant,
}

/// The writer a control submessage speaks for: the message header's guid
/// prefix and the submessage's writerEntityId. Both doors build it from the
/// header (`datagram[8..20]`), never from an INFO_SRC.
fn writer_guid_of(peer_prefix: &[u8; 12], writer_entity_id: &[u8; 4]) -> [u8; 16] {
    let mut guid = [0u8; 16];
    guid[..12].copy_from_slice(peer_prefix);
    guid[12..16].copy_from_slice(writer_entity_id);
    guid
}

/// Whether this thread applies the reorder-gate effects of a HEARTBEAT or
/// GAP of `writer_entity_id`. A user writer's controls riding the receive
/// ring are the Router's to apply, in arrival order behind the DATA they
/// follow (`engine::writer_control`); applying them here, ahead of that DATA,
/// would drop it. Every other control is applied here.
pub(crate) fn applies_gate_on_control(msg: &ControlMessage, writer_entity_id: &[u8; 4]) -> bool {
    !(msg.rides_ring && crate::engine::writer_control::user_writer(writer_entity_id))
}

/// Seed the reader-side reorder gate of a HEARTBEAT's writer.
///
/// ONE rule for the reorder-gate half of a HEARTBEAT, whichever door it came
/// through: the UDP control loop above and the TCP/QUIC unicast router
/// (`engine::unicast_router`). Both doors need the rule: a non-volatile reader
/// whose samples come through a door that does not seed it delivers nothing -
/// its gate holds every sample until a HEARTBEAT or a GAP says where the
/// writer's history starts. Keeping the rule here, rather than a copy of it
/// there, is what stops the two doors disagreeing the day one of them
/// changes.
///
/// What is NOT shared, stated so nobody reads "one rule" as "same handling":
/// resolving the peer's metatraffic port and building the ACKNACK from the
/// reader proxy stay UDP-only. The TCP/QUIC door answers through its own
/// heartbeat handlers (`TopicRegistry::deliver_heartbeat`), a separate
/// machine. The Liveliness flag (`renew_heartbeat_liveliness` below) IS
/// shared: RTPS has no transport exception for it either.
///
/// Seeding lets any sample that arrived out of order during discovery be
/// released in writer-seq order (RTPS v2.5 Sec.8.3.8.6 `firstSN`). A no-op
/// for VOLATILE best-effort readers (gate disabled) and for builtin writers
/// (no user-data subscriber). A malformed HEARTBEAT is refused: `firstSN` is
/// a `SequenceNumber_t` and MUST be > 0 (Sec.9.3.2), and seeding from zero or
/// a negative value would let a buggy or adversarial peer fabricate a
/// delivery baseline and release buffered samples out of order.
///
/// Returns whether a gate was notified.
pub(crate) fn seed_reorder_gate(
    registry: &TopicRegistry,
    peer_prefix: &[u8; 12],
    hb: &HeartbeatInfo,
    reader_entity_id: [u8; 4],
    group_info: Option<super::control_types::GroupInfo>,
) -> bool {
    if is_sedp_endpoint(&hb.writer_entity_id) || hb.first_seq <= 0 {
        return false;
    }
    let Ok(first) = u64::try_from(hb.first_seq) else {
        return false;
    };
    let writer_guid = writer_guid_of(peer_prefix, &hb.writer_entity_id);
    let Some(topic) = registry
        .get_topic_by_guid(&writer_guid)
        .and_then(|name| registry.get_topic(&name))
    else {
        return false;
    };
    if topic.requires_ordered_group() {
        return seed_ordered_group_gate(
            registry,
            &topic,
            writer_guid,
            first,
            u64::try_from(hb.last_seq).ok(),
            reader_entity_id,
            group_info,
        );
    }
    if group_info.is_none() {
        let _ = topic.deliver_writer_heartbeat_to(
            writer_guid,
            first,
            u64::try_from(hb.last_seq).ok(),
            reader_entity_id,
        );
        return true;
    }
    // Coherent GROUP readers without ordered access still consume GroupInfo.
    notify_reorder_heartbeat(
        registry,
        &topic,
        writer_guid,
        first,
        u64::try_from(hb.last_seq).ok(),
        reader_entity_id,
        group_info,
    )
}

#[cold]
#[inline(never)]
fn seed_ordered_group_gate(
    registry: &TopicRegistry,
    topic: &Topic,
    writer_guid: [u8; 16],
    first: u64,
    last: Option<u64>,
    reader_entity_id: [u8; 4],
    group_info: Option<super::control_types::GroupInfo>,
) -> bool {
    // GroupInfo, WriterSN and roster callbacks belong to one HEARTBEAT.
    // A departure between them must invalidate the original event for all.
    let _arrival = crate::dds::GroupArrivalScope::enter(
        writer_guid,
        None,
        registry.capture_group_arrival(&writer_guid),
    );
    notify_reorder_heartbeat(
        registry,
        topic,
        writer_guid,
        first,
        last,
        reader_entity_id,
        group_info,
    )
}

#[cold]
#[inline(never)]
fn notify_reorder_heartbeat(
    registry: &TopicRegistry,
    topic: &Topic,
    writer_guid: [u8; 16],
    first: u64,
    last: Option<u64>,
    reader_entity_id: [u8; 4],
    group_info: Option<super::control_types::GroupInfo>,
) -> bool {
    // The GroupInfo of a writer of the spec GROUP class, for its readers'
    // commit rule (RTPS v2.5 Sec.8.7.5, D15), BEFORE the HEARTBEAT that may
    // release a set: from any other writer it means nothing here.
    if let Some(super::control_types::GroupInfo::Heartbeat {
        current_gsn,
        first_gsn,
        last_gsn,
        ..
    }) = group_info
    {
        if registry.writer_speaks_spec_group(&writer_guid) {
            let _ = topic.deliver_writer_group_heartbeat_to(
                writer_guid,
                [current_gsn, first_gsn, last_gsn],
                reader_entity_id,
            );
        }
    }
    let _ = topic.deliver_writer_heartbeat_to(writer_guid, first, last, reader_entity_id);
    if let Some(super::control_types::GroupInfo::Heartbeat {
        current_gsn,
        first_gsn,
        last_gsn,
        writer_set,
    }) = group_info
    {
        if registry.writer_speaks_spec_group(&writer_guid) {
            let _ = topic.deliver_writer_group_heartbeat_proof_to(
                writer_guid,
                [current_gsn, first_gsn, last_gsn],
                writer_set,
                reader_entity_id,
            );
        }
    }
    true
}

/// A HEARTBEAT's Liveliness flag (RTPS v2.5 Sec.8.3.7.5) renews a
/// MANUAL_BY_TOPIC writer's lease: `TopicRegistry::notify_writer_heartbeat_liveliness`.
///
/// ONE rule, like `seed_reorder_gate` above, for both doors (the UDP
/// control loop and the TCP/QUIC unicast router): RTPS has no transport
/// exception for the flag, and a writer whose only matched reader sits
/// behind TCP/QUIC must not be wrongly expired just because that door
/// drops the bit after parsing it.
pub(crate) fn renew_heartbeat_liveliness(
    registry: &TopicRegistry,
    peer_prefix: &[u8; 12],
    hb: &HeartbeatInfo,
) {
    if hb.liveliness_flag {
        registry
            .notify_writer_heartbeat_liveliness(writer_guid_of(peer_prefix, &hb.writer_entity_id));
    }
}

/// The liveliness-renewal half of receiving a `ParticipantMessageData`
/// that names itself (RTPS v2.5 Sec.8.4.13.5 R9): kind MANUAL renews the
/// sender's MANUAL_BY_PARTICIPANT writers (`Shared::manual_from`). Kind
/// AUTOMATIC needs nothing here -- every receive door already renews
/// AUTOMATIC on any traffic from the sender (`Shared::heard_from`), which
/// covers it.
///
/// ONE rule for both doors, like the two functions above: the UDP
/// discovery dispatch (`handle_participant_message`) and the TCP/QUIC
/// unicast router each decode and self-check the message themselves (the
/// decode shape differs: one already has a `DiscoveryFsm` to feed, the
/// other does not), then call this with the result, so the renewal
/// itself is never duplicated.
pub(crate) fn renew_liveliness_from_participant_message(
    message: &crate::protocol::rtps::participant_message::ParticipantMessage,
    liveliness: &crate::dds::liveliness::Shared,
) {
    use crate::protocol::rtps::participant_message::KIND_MANUAL;
    if message.kind == KIND_MANUAL {
        liveliness.manual_from(&message.participant_guid_prefix);
    }
}

/// Advance the reader-side reorder gate of a GAP's writer past the
/// sequences the writer declared irrelevant (RTPS v2.5 Sec.8.3.8.4).
///
/// Same single-rule contract as `seed_reorder_gate`, and the same two doors.
/// Builtin writers have no user-data subscriber, so they have no gate.
///
/// Each addressed reader's subscriber advances both its reorder gate and
/// its WriterProxy (the ACKNACK base), whichever door the GAP came through.
///
/// Returns whether a gate was notified.
pub(crate) fn announce_ordered_group_gap(
    registry: &TopicRegistry,
    prefix: &[u8; 12],
    gap: &GapInfo,
    reader: [u8; 4],
    info: Option<super::control_types::GroupInfo>,
) {
    if let Some(super::control_types::GroupInfo::Gap { start_gsn, end_gsn }) = info {
        let guid = writer_guid_of(prefix, &gap.writer_entity_id);
        if registry.writer_speaks_spec_group(&guid) {
            registry.notify_writer_group_gap_to(
                guid,
                start_gsn,
                group_gap_safe_end(gap, start_gsn, end_gsn),
                reader,
            );
        }
    }
}

/// Keep one GAP's GSN evidence available while native receipt is decided.
#[allow(clippy::too_many_arguments)]
pub(crate) fn release_group_reorder_gate(
    registry: &TopicRegistry,
    prefix: &[u8; 12],
    gap: &GapInfo,
    reader: [u8; 4],
    filtered: Option<u64>,
    names_gsns: bool,
    info: Option<super::control_types::GroupInfo>,
) -> bool {
    let writer = writer_guid_of(prefix, &gap.writer_entity_id);
    let _order = match info {
        Some(super::control_types::GroupInfo::Gap { start_gsn, end_gsn })
            if registry.writer_speaks_spec_group(&writer) =>
        {
            Some(crate::core::reader::GapOrderScope::enter(
                writer,
                start_gsn,
                group_gap_safe_end(gap, start_gsn, end_gsn),
            ))
        }
        _ => None,
    };
    let notified = release_reorder_gate(registry, prefix, gap, reader, filtered, names_gsns);
    announce_ordered_group_gap(registry, prefix, gap, reader, info);
    notified
}

/// The SN interval itself proves at least this many increasing GSNs
/// unavailable. The GroupInfo endpoint may name the next available sample;
/// retain that endpoint unless the contiguous SN span proves it is missing.
pub(crate) fn group_gap_safe_end(gap: &GapInfo, start_gsn: u64, end_gsn: u64) -> u64 {
    let mut end_sn = gap.gap_list_base;
    while gap.gap_list_seqs.contains(&end_sn) {
        let Some(next) = end_sn.checked_add(1) else {
            break;
        };
        end_sn = next;
    }
    start_gsn
        .saturating_add(end_sn.saturating_sub(gap.gap_start))
        .max(end_gsn)
}

pub(crate) fn release_reorder_gate(
    registry: &TopicRegistry,
    peer_prefix: &[u8; 12],
    gap: &GapInfo,
    reader_entity_id: [u8; 4],
    filtered_count: Option<u64>,
    names_gsns: bool,
) -> bool {
    if is_sedp_endpoint(&gap.writer_entity_id) {
        return false;
    }
    let writer_guid = writer_guid_of(peer_prefix, &gap.writer_entity_id);
    // A writer of the spec GROUP class names the GSNs of a GAP (the
    // GroupInfoFlag) only for changes it took and never made (D16): they
    // are in no history, so in no coherent set (RTPS v2.5 Sec.8.7.6), as
    // a filtered change is not; and none of them is a sample lost.
    let filtered_count = if names_gsns && registry.writer_speaks_spec_group(&writer_guid) {
        Some(u64::try_from(gap.gap_list_seqs.len()).unwrap_or(u64::MAX))
    } else {
        filtered_count
    };
    registry.notify_writer_gap_to(
        writer_guid,
        gap.gap_start,
        gap.gap_list_base,
        gap.gap_list_seqs.clone(),
        reader_entity_id,
        filtered_count,
    )
}

/// A GAP answers in the namespace of the writer the reader requested.
#[cfg(feature = "security")]
fn secure_sedp_gap(mut packet: Vec<u8>, writer: &[u8; 4]) -> Vec<u8> {
    let mut gaps = Vec::new();
    super::classifier::walk::for_each_submessage(&packet, |sub| {
        if sub.id == 0x08 && sub.body_end >= sub.offset + 12 {
            gaps.push(sub.offset);
        }
        super::classifier::walk::Step::Continue
    });
    for at in gaps {
        packet[at + 8..at + 12].copy_from_slice(writer);
        if packet[at + 4..at + 8] != [0; 4] {
            let mut reader = *writer;
            reader[3] = 0xc7;
            packet[at + 4..at + 8].copy_from_slice(&reader);
        }
    }
    packet
}

/// Secure SEDP uses the same history implementation and reliable reader
/// bookkeeping as ordinary SEDP, with its own writer id on the wire.
fn sedp_endpoint_kind(writer: &[u8; 4]) -> Option<SedpEndpointKind> {
    match *writer {
        [0, 0, 3, 0xc2] => Some(SedpEndpointKind::Writer),
        [0, 0, 4, 0xc2] => Some(SedpEndpointKind::Reader),
        #[cfg(feature = "security")]
        crate::core::rtps_constants::RTPS_ENTITYID_SEDP_PUBLICATIONS_SECURE_WRITER => {
            Some(SedpEndpointKind::Writer)
        }
        #[cfg(feature = "security")]
        crate::core::rtps_constants::RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_SECURE_WRITER => {
            Some(SedpEndpointKind::Reader)
        }
        _ => None,
    }
}

fn sedp_proxy_guid(prefix: &[u8; 12], writer: &[u8; 4]) -> [u8; 16] {
    #[cfg(feature = "security")]
    if writer[0] == 0xff && sedp_endpoint_kind(writer).is_some() {
        let mut id = *writer;
        id[0] = 0;
        return writer_guid_of(prefix, &id);
    }
    writer_guid_of(prefix, writer)
}

/// DDS Security v1.1 Sec.8.8.9.3: whether an ACKNACK naming the secure SEDP
/// writer `writer_entity_id` must be refused because it arrived CLEAR while
/// the topic's discovery protection requires every reader submessage of
/// that writer to be protected (Sec.8.8.8.3's submessage protection is
/// symmetric: our writer protects what it sends that reader, that reader
/// protects what it sends our writer -- never a degraded mode either
/// direction can fall back to).
///
/// `was_protected`: whether THIS message was already verified to have
/// arrived under DDS-Security submessage protection
/// (`ControlMessage::was_protected`, set only after a successful
/// `decode_datareader_submessage`); never computed from the bytes carried
/// here, because by the time a message reaches this check its protection,
/// if any, has already been removed.
///
/// `required`: this participant's discovery protection kind, `None`
/// without a governance document (nothing to require).
///
/// A plain (non-secure) SEDP endpoint is never refused here: `writer_
/// entity_id[0] != 0xff` short-circuits every path below `true`.
#[cfg(feature = "security")]
#[must_use]
fn secure_sedp_acknack_must_be_refused(
    writer_entity_id: &[u8; 4],
    was_protected: bool,
    required: Option<crate::security::access::ProtectionKind>,
) -> bool {
    writer_entity_id[0] == 0xff
        && !was_protected
        && required.is_some_and(crate::security::access::ProtectionKind::is_protected)
}

/// Check if writer entity ID is an SEDP endpoint (built-in discovery).
fn is_sedp_endpoint(writer_id: &[u8; 4]) -> bool {
    let kind = writer_id[3];
    if kind != 0xc2 && kind != 0xc3 {
        return false;
    }
    #[cfg(feature = "security")]
    if writer_id[0] == 0xff {
        return sedp_endpoint_kind(writer_id).is_some();
    }
    writer_id[0] == 0 && writer_id[1] == 0
}

/// Derive reader entity ID from writer entity ID.
///
/// Entity kind pairing per RTPS v2.5 Table 9.1:
/// - 0x02 user writer WITH_KEY    -> 0x07 user reader WITH_KEY
/// - 0x03 user writer NO_KEY      -> 0x04 user reader NO_KEY
/// - 0xC2 builtin writer WITH_KEY -> 0xC7 builtin reader WITH_KEY
/// - 0xC3 builtin writer NO_KEY   -> 0xC4 builtin reader NO_KEY
fn derive_reader_entity_id(writer_id: &[u8; 4]) -> [u8; 4] {
    let mut reader_id = *writer_id;
    reader_id[3] = match writer_id[3] {
        0x02 => 0x07, // user writer WITH_KEY -> user reader WITH_KEY
        0x03 => 0x04, // user writer NO_KEY -> user reader NO_KEY
        0xC2 => 0xC7, // builtin writer WITH_KEY -> builtin reader WITH_KEY
        0xC3 => 0xC4, // builtin writer NO_KEY -> builtin reader NO_KEY
        _ => 0x04,    // unknown kind: default to user reader NO_KEY
    };
    reader_id
}

#[cfg(test)]
mod tests {
    /// The user ACKNACK port dialect follows the zzdds STACK, under both
    /// vendor IDs it has announced (placeholder 0x0123 up to 0.2.0, the
    /// registered 0x011B from 0.3.1 on); everyone else keeps the
    /// metatraffic port except FastDDS.
    #[test]
    fn acknack_port_dialect_follows_both_zzdds_vendor_ids() {
        use super::acknack_targets_user_data_port as redirect;
        assert!(redirect(Some(
            crate::protocol::constants::ZZDDS_VENDOR_ID_U16
        )));
        assert!(redirect(Some(
            crate::protocol::constants::ZZDDS_LEGACY_VENDOR_ID_U16
        )));
        assert!(redirect(Some(
            crate::protocol::constants::EPROSIMA_VENDOR_ID_U16
        )));
        assert!(!redirect(Some(
            crate::protocol::constants::HDDS_VENDOR_ID_U16
        )));
        assert!(!redirect(Some(
            crate::protocol::constants::RTI_VENDOR_ID_U16
        )));
        assert!(!redirect(None));
    }

    use super::*;

    /// The submessage ids of an RTPS datagram, decoded from its bytes.
    fn submessage_ids(packet: &[u8]) -> Vec<u8> {
        assert_eq!(&packet[..4], b"RTPS");
        let mut ids = Vec::new();
        let mut offset = 20;
        while offset + 4 <= packet.len() {
            ids.push(packet[offset]);
            let len = usize::from(u16::from_le_bytes([packet[offset + 2], packet[offset + 3]]));
            offset += 4 + len;
        }
        assert_eq!(offset, packet.len(), "submessages fill the datagram");
        ids
    }

    /// The vendor-specific 0x80 trailer of the SEDP HEARTBEAT response goes
    /// to a vendor 0x0101 peer only: to any other peer, HDDS's datagram is
    /// INFO_DST + HEARTBEAT and nothing under another vendor's layout.
    #[test]
    fn the_sedp_heartbeat_trailer_goes_to_a_vendor_0x0101_peer_only() {
        let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 7));
        let build = |vendor| {
            sedp_heartbeat_response_packet(
                [0x01, 0x1a, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8],
                &[9; 12],
                vendor,
                &[0x00, 0x00, 0x03, 0xC2],
                1,
                3,
                ip,
                7410,
            )
            .expect("build")
        };
        for vendor in [
            None,
            Some(crate::protocol::constants::HDDS_VENDOR_ID_U16),
            Some(crate::protocol::constants::EPROSIMA_VENDOR_ID_U16),
            Some(crate::protocol::constants::ZZDDS_VENDOR_ID_U16),
            Some(0x0110),
        ] {
            assert_eq!(
                submessage_ids(&build(vendor)),
                vec![0x0e, 0x07],
                "{vendor:?}"
            );
        }
        let rti = build(Some(crate::protocol::constants::RTI_VENDOR_ID_U16));
        assert_eq!(submessage_ids(&rti), vec![0x0e, 0x07, 0x80]);
        // The trailer echoes the peer's locator: port, then the IPv4 address
        // in the last four of the sixteen address octets.
        let trailer = &rti[rti.len() - 60..];
        assert_eq!(u32::from_le_bytes(trailer[8..12].try_into().unwrap()), 7410);
        assert_eq!(&trailer[28..32], &[192, 0, 2, 7]);
    }

    /// A direct HEARTBEAT arriving from an ephemeral source port is
    /// answered at the datagram's IP, but at the peer's RECORDED metatraffic
    /// port -- not the ephemeral one the datagram happened to carry.
    ///
    /// The two ports must differ, and the recorded locator's IP must match
    /// the reply IP (so `metatraffic_locator_for`'s same-IP preference finds
    /// it): otherwise "use the recorded port" and "use the datagram's own
    /// port" answer the same value and the test pins nothing.
    #[test]
    fn resolve_peer_metatraffic_addr_uses_the_recorded_port_not_the_ephemeral_one() {
        let fsm = DiscoveryFsm::new(GUID::new([0x11; 12], [0, 0, 1, 0xC1]), 30_000);
        let peer_prefix = [0x33u8; 12];
        let recorded_locator: SocketAddr = "192.0.2.30:7410".parse().expect("addr");
        fsm.handle_spdp(crate::protocol::discovery::SpdpData {
            participant_guid: GUID::new(peer_prefix, [0x00, 0x00, 0x01, 0xC1]),
            lease_duration_ms: 30_000,
            domain_id: 0,
            metatraffic_unicast_locators: vec![recorded_locator],
            default_unicast_locators: vec![],
            default_multicast_locators: vec![],
            metatraffic_multicast_locators: vec![],
            identity_token: None,
            permissions_token: None,
            participant_security_info: None,
            vendor_id: None,
            hdds_capabilities: None,
            builtin_endpoint_set: None,
        });

        // Same IP as the recorded locator, but an ephemeral port the peer
        // never announced as its metatraffic port.
        let ephemeral_source: SocketAddr = "192.0.2.30:55123".parse().expect("addr");
        let origin = Origin::direct(ephemeral_source);

        assert_eq!(
            ControlHandler::resolve_peer_metatraffic_addr(&peer_prefix, origin, &fsm),
            Some(recorded_locator),
            "the recorded metatraffic port must win over the ephemeral source port"
        );

        // RTPS 2.5 8.3.8.9 / 8.4.8.2.6: an INFO_REPLY naming another address
        // changes nothing here -- the SEDP endpoints are stateful and answer
        // through the peer's discovered locator.
        let named: std::net::SocketAddrV4 = "198.51.100.4:7999".parse().expect("addr");
        assert_eq!(
            ControlHandler::resolve_peer_metatraffic_addr(
                &peer_prefix,
                origin.replying_to(Some(named)),
                &fsm
            ),
            Some(recorded_locator),
            "never the INFO_REPLY locator"
        );
    }

    /// A user ACKNACK reaches the writer it names whole (writerId, base,
    /// holes), a pure acknowledgement included. Forwarding only ACKNACKs that
    /// have holes, re-encoded without writerId or base, would leave every
    /// writer unaware of what a reader acknowledged and every writer of the
    /// participant servicing every NACK.
    #[test]
    fn a_user_acknack_reaches_the_writers_whole_even_without_a_hole() {
        use crate::core::discovery::multicast::control_types::AckNackInfo;
        use crate::engine::NackHandler;
        use std::sync::Mutex;

        type Seen = Arc<Mutex<Vec<([u8; 16], AckNackInfo)>>>;
        struct Recorder(Seen);
        impl NackHandler for Recorder {
            fn on_nack(&self, _: &[u8], _: Option<[u8; 16]>) {}
            fn on_acknack(&self, reader_guid: [u8; 16], acknack: &AckNackInfo) {
                self.0
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push((reader_guid, acknack.clone()));
            }
        }

        let lease = crate::test_support::domains::unique_domain();
        let mapping =
            crate::transport::PortMapping::calculate(lease.id(), 2).expect("port mapping");
        let transport =
            Arc::new(UdpTransport::new(lease.id(), 2, mapping).expect("test transport"));
        let seen: Seen = Arc::new(Mutex::new(Vec::new()));
        let topics = Arc::new(TopicRegistry::new());
        topics.register_nack_handler(Arc::new(Recorder(Arc::clone(&seen))));
        let handler = ControlHandler::spawn_with_topic_registry(
            transport,
            [0x40; 12],
            7400,
            ReaderProxyRegistry::new(),
            ReaderProxyRegistry::new(),
            topics,
            Arc::new(DiscoveryFsm::new(GUID::zero(), 30_000)),
            Arc::new(RwLock::new(SedpHistory::new())),
        );

        let pure_ack = AckNackInfo {
            reader_entity_id: [0x00, 0x00, 0x01, 0x04],
            writer_entity_id: [0x00, 0x00, 0x01, 0x03],
            missing_ranges: Vec::new(),
            bitmap_base: 5,
            count: None,
        };
        let msg = ControlMessage::acknack(
            Origin::direct("127.0.0.1:7410".parse().expect("addr")),
            [0x41; 12],
            pure_ack,
            &[],
        )
        .expect("control message");
        assert!(handler.try_send(msg));

        let deadline = Instant::now() + Duration::from_secs(5);
        while seen.lock().unwrap_or_else(|e| e.into_inner()).is_empty() && Instant::now() < deadline
        {
            std::thread::sleep(Duration::from_millis(5));
        }
        let seen = seen.lock().unwrap_or_else(|e| e.into_inner()).clone();
        handler.shutdown();

        assert_eq!(seen.len(), 1, "the pure acknowledgement must be delivered");
        let (reader_guid, acknack) = &seen[0];
        let mut expected_reader = [0x41u8; 16];
        expected_reader[12..].copy_from_slice(&[0x00, 0x00, 0x01, 0x04]);
        assert_eq!(*reader_guid, expected_reader);
        assert_eq!(acknack.writer_entity_id, [0x00, 0x00, 0x01, 0x03]);
        assert_eq!(acknack.bitmap_base, 5);
    }

    /// RTPS 2.5 8.4.12: each reliable reader keeps its own WriterProxy and
    /// answers a writer's HEARTBEAT with its own ACKNACK, under its own
    /// readerId. Two local readers are matched with one writer and only one
    /// of them received its three samples: two ACKNACKs, each naming its
    /// reader and carrying that reader's own state. A writer no local
    /// reader is matched with gets no answer at all.
    #[test]
    fn each_matched_reader_answers_a_heartbeat_under_its_own_name() {
        use crate::core::discovery::multicast::control_parser::parse_all_acknack_submessages;
        use crate::core::discovery::multicast::control_types::HeartbeatInfo;
        use std::net::UdpSocket;

        let guid = |prefix: u8, entity_id: [u8; 4]| {
            let mut guid = [prefix; 16];
            guid[12..].copy_from_slice(&entity_id);
            guid
        };
        let writer = guid(0x41, [0x00, 0x00, 0x01, 0x02]);
        let unmatched_writer = guid(0x41, [0x00, 0x00, 0x02, 0x02]);
        let holder = guid(0x40, [0x00, 0x00, 0x01, 0x07]);
        let newcomer = guid(0x40, [0x00, 0x00, 0x02, 0x07]);

        let registry = ReaderProxyRegistry::new();
        registry.match_writer(writer, holder);
        registry.match_writer(writer, newcomer);
        for seq in 1..=3 {
            registry.on_data_for(&writer, &holder, seq);
        }

        // The ACKNACKs go back to the HEARTBEAT's source: the peer is
        // unknown to the FSM, so its source port is used as is.
        let peer = UdpSocket::bind("127.0.0.1:0").expect("bind peer");
        peer.set_read_timeout(Some(Duration::from_millis(300)))
            .expect("read timeout");
        let peer_addr = peer.local_addr().expect("peer addr");

        let lease = crate::test_support::domains::unique_domain();
        let mapping =
            crate::transport::PortMapping::calculate(lease.id(), 2).expect("port mapping");
        let transport =
            Arc::new(UdpTransport::new(lease.id(), 2, mapping).expect("test transport"));
        let observer = registry.clone();
        let handler = ControlHandler::spawn_with_topic_registry(
            transport,
            [0x40; 12],
            7400,
            ReaderProxyRegistry::new(),
            registry,
            Arc::new(TopicRegistry::new()),
            Arc::new(DiscoveryFsm::new(GUID::zero(), 30_000)),
            Arc::new(RwLock::new(SedpHistory::new())),
        );

        let heartbeat = |writer_entity_id: [u8; 4]| {
            ControlMessage::heartbeat(
                Origin::direct(peer_addr),
                [0x41; 12],
                HeartbeatInfo {
                    writer_entity_id,
                    first_seq: 1,
                    last_seq: 3,
                    count: 1,
                    final_flag: true,
                    liveliness_flag: false,
                },
                &[],
            )
            .expect("control message")
        };
        assert!(handler.try_send(heartbeat([0x00, 0x00, 0x02, 0x02])));
        assert!(handler.try_send(heartbeat([0x00, 0x00, 0x01, 0x02])));

        let mut acknacks = Vec::new();
        let mut counts = Vec::new();
        let mut buf = [0u8; 512];
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline {
            if let Ok(len) = peer.recv(&mut buf) {
                acknacks.extend(parse_all_acknack_submessages(&buf[..len]));
                // The ACKNACK is the datagram's last submessage and closes
                // on its little-endian count (RTPS 2.5 9.4.5.3).
                let mut count = [0u8; 4];
                count.copy_from_slice(&buf[len - 4..len]);
                counts.push(u32::from_le_bytes(count));
            } else if acknacks.len() >= 2 {
                break;
            }
        }
        handler.shutdown();

        // Each pair's first ACKNACK carries count 1 (RTPS 2.5 8.3.8.1), and
        // each answer that left opened that reader's rate-limit window.
        assert_eq!(counts, vec![1, 1]);
        for reader in [holder, newcomer] {
            let proxy = observer.pair(&writer, &reader).expect("matched");
            assert!(proxy.acknack_sent(), "{reader:02x?}");
        }

        assert!(
            acknacks
                .iter()
                .all(|a| a.writer_entity_id == [0x00, 0x00, 0x01, 0x02]),
            "only the matched writer is answered, unmatched {:02x?}: {acknacks:?}",
            &unmatched_writer[12..]
        );
        let mut answers: Vec<_> = acknacks
            .iter()
            .map(|a| (a.reader_entity_id, a.bitmap_base, a.missing_ranges.clone()))
            .collect();
        answers.sort_by_key(|(reader, _, _)| *reader);
        assert_eq!(
            answers,
            vec![
                // The reader holding 1..=3 acknowledges them all.
                ([0x00, 0x00, 0x01, 0x07], 4, vec![]),
                // The reader holding nothing asks for all three.
                (
                    [0x00, 0x00, 0x02, 0x07],
                    1,
                    vec![std::ops::Range { start: 1, end: 4 }]
                ),
            ]
        );
    }

    /// RTPS 2.5 8.3.4 / 8.3.8.10: a SEDP HEARTBEAT behind an INFO_SRC has no
    /// reply address of its own. A peer already known from SPDP is still
    /// answered, at the FSM's own record of it (its metatraffic locator) --
    /// never at the forwarder, which nothing is listening on here.
    #[test]
    fn a_relayed_sedp_heartbeat_answers_at_the_fsms_address() {
        use crate::core::discovery::multicast::control_parser::parse_all_acknack_submessages;
        use crate::protocol::discovery::SpdpData;
        use std::net::UdpSocket;

        const SEDP_PUB_WRITER: [u8; 4] = [0x00, 0x00, 0x03, 0xC2];
        const PEER_PREFIX: [u8; 12] = [0x41; 12];
        // A real address nobody relayed this datagram through: if the
        // handler ever aimed a reply here instead of the FSM's address,
        // this test would still pass by accident unless something is bound
        // here to prove it silent. Left unbound on purpose: an ACKNACK sent
        // here would simply vanish (ICMP unreachable at worst), which is
        // the point -- the real assertion is that the ACKNACK arrives on
        // `peer_metatraffic` below.
        let forwarder: SocketAddr = "203.0.113.77:9999".parse().expect("valid address");

        let peer_metatraffic = UdpSocket::bind("127.0.0.1:0").expect("bind peer");
        peer_metatraffic
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("read timeout");
        let peer_metatraffic_addr = peer_metatraffic.local_addr().expect("peer addr");

        let fsm = Arc::new(DiscoveryFsm::new(
            GUID::new([0x40; 12], [0, 0, 1, 0xC1]),
            30_000,
        ));
        fsm.handle_spdp(SpdpData {
            participant_guid: GUID::new(PEER_PREFIX, [0, 0, 1, 0xC1]),
            lease_duration_ms: 30_000,
            domain_id: 0,
            metatraffic_unicast_locators: vec![peer_metatraffic_addr],
            default_unicast_locators: vec![],
            default_multicast_locators: vec![],
            metatraffic_multicast_locators: vec![],
            identity_token: None,
            permissions_token: None,
            participant_security_info: None,
            vendor_id: None,
            hdds_capabilities: None,
            builtin_endpoint_set: None,
        });

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
            fsm,
            Arc::new(RwLock::new(SedpHistory::new())),
        );

        let hb = ControlMessage::heartbeat(
            Origin::relayed(forwarder),
            PEER_PREFIX,
            HeartbeatInfo {
                writer_entity_id: SEDP_PUB_WRITER,
                first_seq: 1,
                last_seq: 1,
                count: 1,
                final_flag: true,
                liveliness_flag: false,
            },
            &[],
        )
        .expect("control message");
        assert!(handler.try_send(hb));

        let mut buf = [0u8; 512];
        let len = peer_metatraffic
            .recv(&mut buf)
            .expect("the ACKNACK reaches the FSM's own metatraffic address");
        let acknacks = parse_all_acknack_submessages(&buf[..len]);
        assert_eq!(acknacks.len(), 1);
        assert_eq!(acknacks[0].writer_entity_id, SEDP_PUB_WRITER);

        handler.shutdown();
    }

    /// The other half: a relayed SEDP HEARTBEAT from a peer the FSM has
    /// never seen gets no ACKNACK at all -- specifically, NOT one sent to
    /// the forwarder's own address (the datagram's source, which is not the
    /// peer's). The forwarder is a REAL bound socket here for that reason: a
    /// fallback to `origin.from()` would be caught arriving on it, not merely
    /// timed out against an address nobody owns.
    #[test]
    fn a_relayed_sedp_heartbeat_from_an_unknown_peer_gets_no_acknack() {
        const SEDP_PUB_WRITER: [u8; 4] = [0x00, 0x00, 0x03, 0xC2];
        const PEER_PREFIX: [u8; 12] = [0x42; 12];

        let forwarder_socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind forwarder");
        forwarder_socket
            .set_read_timeout(Some(Duration::from_millis(400)))
            .expect("read timeout");
        let forwarder = forwarder_socket.local_addr().expect("forwarder addr");

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
            Arc::new(DiscoveryFsm::new(GUID::zero(), 30_000)),
            Arc::new(RwLock::new(SedpHistory::new())),
        );

        let hb = ControlMessage::heartbeat(
            Origin::relayed(forwarder),
            PEER_PREFIX,
            HeartbeatInfo {
                writer_entity_id: SEDP_PUB_WRITER,
                first_seq: 1,
                last_seq: 1,
                count: 1,
                final_flag: true,
                liveliness_flag: false,
            },
            &[],
        )
        .expect("control message");
        assert!(handler.try_send(hb));

        let mut buf = [0u8; 64];
        assert!(
            forwarder_socket.recv(&mut buf).is_err(),
            "an unknown peer, relayed, must never be answered at the forwarder's address"
        );

        handler.shutdown();
    }

    /// RTPS 2.5 8.3.8.4 and 8.3.8.6: a HEARTBEAT or GAP whose readerId
    /// names one reader is that reader's alone. Readers A and B are matched
    /// with one writer and hold nothing. A final HEARTBEAT addressed to A,
    /// then a batched one addressed to B, are each answered once, by their
    /// reader, and seed that reader's reorder gate only. A GAP addressed to
    /// B reaches B's subscriber only (which also moves B's WriterProxy:
    /// `a_gap_reaching_a_reader_moves_its_acknowledgement`). A batch holding
    /// a HEARTBEAT to A AND a later one to every reader is answered once per
    /// reader, A from the later of the two.
    /// A flushed batch: each reader answers once, from the latest
    /// announcement that addresses it; the one to every reader comes last,
    /// for the readers not named.
    #[test]
    fn a_batch_answers_each_reader_once_from_its_latest_announcement() {
        const A: [u8; 4] = [0x00, 0x00, 0x01, 0x07];
        const B: [u8; 4] = [0x00, 0x00, 0x02, 0x07];
        let state = |highest_seq, last_count| WriterState {
            first_seq: 1,
            highest_seq,
            last_count,
            peer_addr: Some(SocketAddr::from(([127, 0, 0, 1], 7400))),
            peer_guid_prefix: [0x41; 12],
        };
        let (w1, w2) = ([1u8; 16], [2u8; 16]);
        let mut folded = ControlHandler::fold_heartbeat_batch(vec![
            ((w1, A), state(3, 3)),
            ((w1, ENTITYID_UNKNOWN), state(5, 4)),
            ((w2, B), state(7, 1)),
        ]);
        folded.sort_by_key(|(writer, _)| *writer);
        type Answers = Vec<(Addressees, i64, u32)>;
        let summary: Vec<([u8; 16], Answers)> = folded
            .into_iter()
            .map(|(writer, batches)| {
                let batches = batches
                    .into_iter()
                    .map(|(to, s)| (to, s.highest_seq, s.last_count))
                    .collect();
                (writer, batches)
            })
            .collect();
        assert_eq!(
            summary,
            vec![
                (
                    w1,
                    vec![(Addressees::One(A), 5, 4), (Addressees::All, 5, 4)]
                ),
                (w2, vec![(Addressees::One(B), 7, 1)]),
            ]
        );
    }

    /// The GroupInfo of a HEARTBEAT of a writer of the spec GROUP class
    /// reaches the topic's readers (`on_writer_group_heartbeat`), read from
    /// the bytes of the control message; from any other writer it does
    /// not.
    #[test]
    fn a_spec_writers_heartbeat_group_info_reaches_its_readers() {
        type Log = Arc<std::sync::Mutex<Vec<[u64; 3]>>>;
        struct Probe(Log);
        impl crate::engine::Subscriber for Probe {
            fn on_data(&self, _: &str, _: u64, _: &[u8]) {}
            fn topic_name(&self) -> &str {
                "HbGroup"
            }
            fn on_writer_group_heartbeat(&self, _: [u8; 16], current: u64, first: u64, last: u64) {
                self.0.lock().expect("log").push([current, first, last]);
            }
        }
        let ctx = crate::protocol::builder::RtpsEndpointContext {
            guid_prefix: [0x44; 12],
            reader_entity_id: [0, 0, 0, 0],
            writer_entity_id: [0, 0, 0x01, 0x02],
            encapsulation_kind: 0x0007,
            publisher_entity_id: [0, 0, 0x01, 0x08],
        };
        let packet =
            crate::protocol::builder::build_heartbeat_packet_group(&ctx, 1, 3, 7, [9, 2, 6]);
        let origin = super::super::meta::Origin::direct("127.0.0.1:9".parse().expect("addr"));
        let hb = super::super::control_parser::scan_all_embedded_control_submessages(&packet)
            .1
            .pop()
            .expect("a HEARTBEAT");
        let msg =
            ControlMessage::addressed_heartbeat(origin, [0x44; 12], hb, &packet).expect("message");
        let info = msg.heartbeat_group_info();
        assert!(info.is_some(), "read back from the message's bytes");
        let mut writer = [0u8; 16];
        writer[..12].copy_from_slice(&[0x44; 12]);
        writer[12..].copy_from_slice(&ctx.writer_entity_id);
        for spec in [true, false] {
            let log: Log = Arc::default();
            let topics = TopicRegistry::new();
            topics
                .register_subscriber(Arc::new(Probe(Arc::clone(&log))))
                .expect("register");
            topics.register_writer_guid(writer, "HbGroup".to_string());
            if spec {
                topics.record_writer_group_dialect(
                    writer,
                    crate::protocol::group::GroupDialect::Spec,
                    Some([0, 0, 0x01, 0x08]),
                );
            }
            seed_reorder_gate(
                &topics,
                &[0x44; 12],
                msg.heartbeat.as_ref().expect("hb"),
                [0; 4],
                info,
            );
            let got = log.lock().expect("log").clone();
            if spec {
                assert_eq!(got, vec![[9, 2, 6]]);
            } else {
                assert!(got.is_empty());
            }
        }
    }

    #[test]
    fn an_ordinary_heartbeat_skips_group_metadata_and_preserves_arrival_context() {
        use crate::dds::GroupArrivalScope;
        use std::sync::mpsc;

        struct Probe {
            sentinel: [u8; 16],
            observed: mpsc::Sender<bool>,
        }
        impl crate::engine::Subscriber for Probe {
            fn on_data(&self, _: &str, _: u64, _: &[u8]) {}
            fn topic_name(&self) -> &str {
                "ordinary-heartbeat-interest"
            }
            fn on_writer_heartbeat(&self, _: [u8; 16], _: u64) {
                self.observed
                    .send(GroupArrivalScope::captured(self.sentinel).is_some())
                    .expect("observer remains live");
            }
        }

        let registry = Arc::new(TopicRegistry::new());
        let prefix = [0x46; 12];
        let entity = [0, 0, 1, 2];
        let writer = writer_guid_of(&prefix, &entity);
        let sentinel = [0x47; 16];
        let (tx, rx) = mpsc::channel();
        registry
            .register_subscriber(Arc::new(Probe {
                sentinel,
                observed: tx,
            }))
            .unwrap();
        registry.register_writer_guid(writer, "ordinary-heartbeat-interest".to_string());
        registry.record_writer_group_dialect(
            writer,
            crate::protocol::group::GroupDialect::Spec,
            Some([0, 0, 1, 8]),
        );
        let stamp = registry
            .capture_group_arrival(&writer)
            .expect("known writer");
        let hb = HeartbeatInfo {
            writer_entity_id: entity,
            first_seq: 1,
            last_seq: 3,
            count: 1,
            final_flag: true,
            liveliness_flag: false,
        };

        let (worker, observed) = registry.with_spec_group_writers_locked_for_test(|| {
            let registry = registry.clone();
            let worker = std::thread::spawn(move || {
                let _outer = GroupArrivalScope::enter(sentinel, None, Some(stamp));
                seed_reorder_gate(&registry, &prefix, &hb, [0; 4], None)
            });
            let observed = rx.recv_timeout(std::time::Duration::from_secs(2));
            (worker, observed)
        });
        assert!(worker.join().expect("heartbeat worker"));
        assert_eq!(
            observed,
            Ok(true),
            "ordinary HEARTBEAT must bypass the GROUP map and leave arrival TLS untouched"
        );
    }

    #[test]
    fn an_ordered_groups_plain_heartbeat_captures_its_arrival() {
        struct Probe(Arc<std::sync::Mutex<Vec<bool>>>);
        impl crate::engine::Subscriber for Probe {
            fn on_data(&self, _: &str, _: u64, _: &[u8]) {}
            fn topic_name(&self) -> &str {
                "ordered-plain-heartbeat"
            }
            fn requires_ordered_group(&self) -> bool {
                true
            }
            fn on_writer_heartbeat(&self, writer: [u8; 16], _: u64) {
                self.0
                    .lock()
                    .unwrap()
                    .push(crate::dds::GroupArrivalScope::captured(writer).is_some());
            }
        }
        let registry = TopicRegistry::new();
        let observed = Arc::new(std::sync::Mutex::new(Vec::new()));
        registry
            .register_subscriber(Arc::new(Probe(observed.clone())))
            .unwrap();
        let prefix = [0x48; 12];
        let entity = [0, 0, 1, 2];
        let writer = writer_guid_of(&prefix, &entity);
        registry.register_writer_guid(writer, "ordered-plain-heartbeat".to_string());
        registry.record_writer_group_dialect(
            writer,
            crate::protocol::group::GroupDialect::Spec,
            Some([0, 0, 1, 8]),
        );
        let hb = HeartbeatInfo {
            writer_entity_id: entity,
            first_seq: 1,
            last_seq: 3,
            count: 1,
            final_flag: true,
            liveliness_flag: false,
        };
        assert!(seed_reorder_gate(&registry, &prefix, &hb, [0; 4], None));
        assert_eq!(
            *observed.lock().unwrap(),
            vec![true],
            "plain HEARTBEAT still supplies one arrival event to ordered GROUP readers"
        );
    }

    #[test]
    fn a_reader_joining_during_group_info_waits_for_the_next_whole_heartbeat() {
        use crate::dds::GroupArrivalScope;
        use std::sync::atomic::{AtomicBool, Ordering};

        type Log = Arc<std::sync::Mutex<Vec<(u8, bool)>>>;
        struct Joined(Log);
        impl crate::engine::Subscriber for Joined {
            fn on_data(&self, _: &str, _: u64, _: &[u8]) {}
            fn topic_name(&self) -> &str {
                "heartbeat-membership-snapshot"
            }
            fn requires_ordered_group(&self) -> bool {
                true
            }
            fn on_writer_group_heartbeat(&self, writer: [u8; 16], _: u64, _: u64, _: u64) {
                self.0
                    .lock()
                    .unwrap()
                    .push((1, GroupArrivalScope::captured(writer).is_some()));
            }
            fn on_writer_heartbeat(&self, writer: [u8; 16], _: u64) {
                self.0
                    .lock()
                    .unwrap()
                    .push((2, GroupArrivalScope::captured(writer).is_some()));
            }
            fn on_writer_group_heartbeat_roster(
                &self,
                writer: [u8; 16],
                _: [u64; 3],
                _: Option<([u8; 4], [u8; 4])>,
            ) {
                self.0
                    .lock()
                    .unwrap()
                    .push((3, GroupArrivalScope::captured(writer).is_some()));
            }
        }
        struct Registrar {
            registry: std::sync::Weak<TopicRegistry>,
            joined: Arc<Joined>,
            registered: AtomicBool,
            arrivals: Arc<std::sync::Mutex<Vec<bool>>>,
        }
        impl crate::engine::Subscriber for Registrar {
            fn on_data(&self, _: &str, _: u64, _: &[u8]) {}
            fn topic_name(&self) -> &str {
                "heartbeat-membership-snapshot"
            }
            fn on_writer_group_heartbeat(&self, writer: [u8; 16], _: u64, _: u64, _: u64) {
                self.arrivals
                    .lock()
                    .unwrap()
                    .push(GroupArrivalScope::captured(writer).is_some());
                if !self.registered.swap(true, Ordering::AcqRel) {
                    self.registry
                        .upgrade()
                        .unwrap()
                        .register_subscriber(self.joined.clone())
                        .unwrap();
                }
            }
        }

        let registry = Arc::new(TopicRegistry::new());
        let observed: Log = Arc::default();
        let arrivals = Arc::new(std::sync::Mutex::new(Vec::new()));
        registry
            .register_subscriber(Arc::new(Registrar {
                registry: Arc::downgrade(&registry),
                joined: Arc::new(Joined(observed.clone())),
                registered: AtomicBool::new(false),
                arrivals: arrivals.clone(),
            }))
            .unwrap();
        let prefix = [0x49; 12];
        let entity = [0, 0, 1, 2];
        let writer = writer_guid_of(&prefix, &entity);
        registry.register_writer_guid(writer, "heartbeat-membership-snapshot".to_string());
        registry.record_writer_group_dialect(
            writer,
            crate::protocol::group::GroupDialect::Spec,
            Some([0, 0, 1, 8]),
        );
        let hb = HeartbeatInfo {
            writer_entity_id: entity,
            first_seq: 1,
            last_seq: 3,
            count: 1,
            final_flag: true,
            liveliness_flag: false,
        };
        let info = Some(super::super::control_types::GroupInfo::Heartbeat {
            current_gsn: 3,
            first_gsn: 1,
            last_gsn: 3,
            writer_set: None,
        });
        assert!(seed_reorder_gate(&registry, &prefix, &hb, [0; 4], info));
        assert!(
            observed.lock().unwrap().is_empty(),
            "a reader must not receive the tail of a HEARTBEAT already in progress"
        );
        assert!(seed_reorder_gate(&registry, &prefix, &hb, [0; 4], info));
        assert_eq!(
            *observed.lock().unwrap(),
            vec![(1, true), (2, true), (3, true)]
        );
        assert_eq!(*arrivals.lock().unwrap(), vec![false, true]);
    }

    #[test]
    fn one_heartbeat_event_cannot_revive_a_departure_between_its_hooks() {
        use crate::dds::GroupArrivalScope;
        use crate::engine::subscriber::{DisposeKind, WriterDeparture};

        struct Probe {
            registry: std::sync::Weak<TopicRegistry>,
            results: std::sync::Mutex<Vec<bool>>,
        }
        impl crate::engine::Subscriber for Probe {
            fn on_data(&self, _: &str, _: u64, _: &[u8]) {}
            fn topic_name(&self) -> &str {
                "heartbeat-arrival"
            }
            fn requires_ordered_group(&self) -> bool {
                true
            }
            fn on_writer_group_heartbeat(&self, writer: [u8; 16], _: u64, _: u64, _: u64) {
                let registry = self.registry.upgrade().unwrap();
                let stamp = GroupArrivalScope::captured(writer).expect("GroupInfo event");
                assert!(registry.note_group_writer_alive_stamped(&writer, &stamp));
                registry.notify_writer_departure(
                    writer,
                    DisposeKind::Unregistered,
                    WriterDeparture::Unheard,
                );
            }
            fn on_writer_heartbeat(&self, writer: [u8; 16], _: u64) {
                let registry = self.registry.upgrade().unwrap();
                let stamp = GroupArrivalScope::captured(writer).expect("WriterSN event");
                self.results
                    .lock()
                    .unwrap()
                    .push(registry.note_group_writer_alive_stamped(&writer, &stamp));
            }
            fn on_writer_group_heartbeat_roster(
                &self,
                writer: [u8; 16],
                _: [u64; 3],
                _: Option<([u8; 4], [u8; 4])>,
            ) {
                let registry = self.registry.upgrade().unwrap();
                let stamp = GroupArrivalScope::captured(writer).expect("roster event");
                self.results
                    .lock()
                    .unwrap()
                    .push(registry.note_group_writer_alive_stamped(&writer, &stamp));
            }
        }
        let ctx = crate::protocol::builder::RtpsEndpointContext {
            guid_prefix: [0x45; 12],
            reader_entity_id: [0; 4],
            writer_entity_id: [0, 0, 1, 2],
            encapsulation_kind: 0x0007,
            publisher_entity_id: [0, 0, 1, 8],
        };
        let packet =
            crate::protocol::builder::build_heartbeat_packet_group(&ctx, 1, 3, 7, [9, 2, 6]);
        let origin = super::super::meta::Origin::direct("127.0.0.1:9".parse().unwrap());
        let hb = super::super::control_parser::scan_all_embedded_control_submessages(&packet)
            .1
            .pop()
            .unwrap();
        let msg =
            ControlMessage::addressed_heartbeat(origin, ctx.guid_prefix, hb, &packet).unwrap();
        let registry = Arc::new(TopicRegistry::new());
        let probe = Arc::new(Probe {
            registry: Arc::downgrade(&registry),
            results: std::sync::Mutex::new(Vec::new()),
        });
        registry.register_subscriber(probe.clone()).unwrap();
        let writer = writer_guid_of(&ctx.guid_prefix, &ctx.writer_entity_id);
        registry.register_writer_guid(writer, "heartbeat-arrival".to_string());
        registry.record_writer_group_dialect(
            writer,
            crate::protocol::group::GroupDialect::Spec,
            Some(ctx.publisher_entity_id),
        );
        assert!(seed_reorder_gate(
            &registry,
            &ctx.guid_prefix,
            msg.heartbeat.as_ref().unwrap(),
            [0; 4],
            msg.heartbeat_group_info(),
        ));
        assert_eq!(
            *probe.results.lock().unwrap(),
            vec![false, false],
            "later hooks of an old HEARTBEAT must preserve the newer departure"
        );
    }

    /// A GAP naming the GSNs of what it declares (the GroupInfoFlag) from
    /// a writer of the spec GROUP class declares changes it took and never
    /// made (D16): handed to the readers as filtered, every change of it,
    /// so in no coherent set and no sample lost. From any other writer, or
    /// without the flag, the GAP is handed over as it came.
    #[test]
    fn a_gap_naming_gsns_from_a_spec_writer_declares_changes_never_made() {
        type Log = Arc<std::sync::Mutex<Vec<Option<u64>>>>;
        struct Probe(Log);
        impl crate::engine::Subscriber for Probe {
            fn on_data(&self, _: &str, _: u64, _: &[u8]) {}
            fn topic_name(&self) -> &str {
                "HoleGap"
            }
            fn on_writer_gap(&self, _: [u8; 16], _: u64, _: u64, _: Vec<u64>) {
                self.0.lock().expect("log").push(None);
            }
            fn on_writer_gap_filtered(
                &self,
                _: [u8; 16],
                _: u64,
                _: u64,
                _: Vec<u64>,
                filtered_count: u64,
            ) {
                self.0.lock().expect("log").push(Some(filtered_count));
            }
        }
        let gap = GapInfo {
            writer_entity_id: [0, 0, 0x01, 0x02],
            gap_start: 3,
            gap_list_base: 4,
            gap_list_seqs: vec![3],
        };
        let prefix = [0x43; 12];
        let mut writer = [0u8; 16];
        writer[..12].copy_from_slice(&prefix);
        writer[12..].copy_from_slice(&gap.writer_entity_id);
        for (spec, names_gsns, expected) in [
            (true, true, Some(1)),
            (true, false, None),
            (false, true, None),
        ] {
            let log: Log = Arc::default();
            let topics = TopicRegistry::new();
            topics
                .register_subscriber(Arc::new(Probe(Arc::clone(&log))))
                .expect("register");
            topics.register_writer_guid(writer, "HoleGap".to_string());
            if spec {
                topics.record_writer_group_dialect(
                    writer,
                    crate::protocol::group::GroupDialect::Spec,
                    Some([0, 0, 0x01, 0x08]),
                );
            }
            release_reorder_gate(&topics, &prefix, &gap, [0; 4], None, names_gsns);
            assert_eq!(
                log.lock().expect("log").clone(),
                vec![expected],
                "spec={spec} names_gsns={names_gsns}"
            );
        }
    }

    /// DDS Security v1.1 Sec.8.8.7.1: the control thread answers no
    /// HEARTBEAT of a writer the security plugins do not admit (an
    /// unauthenticated participant's writer of a protected topic) and moves
    /// no WriterProxy for it; the same participant's writer of an
    /// unprotected topic, the control, is answered.
    #[test]
    #[cfg(feature = "security")]
    fn a_heartbeat_of_a_writer_not_admitted_is_not_answered() {
        use crate::core::discovery::multicast::control_parser::parse_all_acknack_submessages;
        use crate::core::discovery::multicast::control_types::HeartbeatInfo;
        use crate::security::access::{
            BasicProtectionKind, DiscoveryGovernance, DomainRule, ProtectionKind, TopicRule,
        };
        use std::net::UdpSocket;

        const READER: [u8; 4] = [0x00, 0x00, 0x01, 0x07];
        const OPEN: [u8; 4] = [0x00, 0x00, 0x01, 0x02];
        const FREE: [u8; 4] = [0x00, 0x00, 0x02, 0x02];
        let guid = |prefix: u8, entity_id: [u8; 4]| {
            let mut guid = [prefix; 16];
            guid[12..].copy_from_slice(&entity_id);
            guid
        };
        let registry = ReaderProxyRegistry::new();
        registry.match_writer(guid(0x41, OPEN), guid(0x40, READER));
        registry.match_writer(guid(0x41, FREE), guid(0x40, READER));
        let topics = Arc::new(TopicRegistry::new());
        topics.register_writer_guid(guid(0x41, OPEN), "OpenData".to_string());
        topics.register_writer_guid(guid(0x41, FREE), "FreeData".to_string());
        let mut fsm = DiscoveryFsm::new(GUID::new([0x40; 12], [0, 0, 1, 0xC1]), 30_000);
        let rule = |expression: &str, access: bool| TopicRule {
            topic_expression: expression.to_string(),
            enable_discovery_protection: false,
            enable_liveliness_protection: false,
            enable_read_access_control: access,
            enable_write_access_control: access,
            metadata_protection_kind: ProtectionKind::None,
            data_protection_kind: BasicProtectionKind::None,
        };
        fsm.set_discovery_governance(Some(DiscoveryGovernance::new(DomainRule {
            domains: vec![0],
            domain_ranges: vec![],
            allow_unauthenticated: true,
            enable_join_access_control: true,
            discovery_protection_kind: ProtectionKind::None,
            liveliness_protection_kind: ProtectionKind::None,
            rtps_protection_kind: ProtectionKind::None,
            topic_rules: vec![rule("Open*", true), rule("Free*", false)],
        })));

        let peer = UdpSocket::bind("127.0.0.1:0").expect("bind peer");
        peer.set_read_timeout(Some(Duration::from_millis(300)))
            .expect("read timeout");
        let peer_addr = peer.local_addr().expect("peer addr");
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
            registry.clone(),
            Arc::clone(&topics),
            Arc::new(fsm),
            Arc::new(RwLock::new(SedpHistory::new())),
        );
        let heartbeat = |writer: [u8; 4]| {
            ControlMessage::heartbeat(
                Origin::direct(peer_addr),
                [0x41; 12],
                HeartbeatInfo {
                    writer_entity_id: writer,
                    first_seq: 1,
                    last_seq: 3,
                    count: 1,
                    final_flag: false,
                    liveliness_flag: false,
                },
                &[],
            )
            .expect("control message")
        };
        assert!(handler.try_send(heartbeat(OPEN)));
        assert!(handler.try_send(heartbeat(FREE)));
        let mut buf = [0u8; 512];
        let mut answered = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            if let Ok(len) = peer.recv(&mut buf) {
                answered.extend(
                    parse_all_acknack_submessages(&buf[..len])
                        .into_iter()
                        .map(|a| a.writer_entity_id),
                );
            }
        }
        handler.shutdown();
        assert_eq!(answered, vec![FREE], "only the admitted writer is answered");
        let pair = |writer: [u8; 4]| {
            registry
                .pair(&guid(0x41, writer), &guid(0x40, READER))
                .expect("tracked")
                .acknack_sent()
        };
        assert!(pair(FREE), "control: its WriterProxy moved");
        assert!(
            !pair(OPEN),
            "the WriterProxy of a writer not admitted moved"
        );
    }

    #[test]
    fn an_addressed_heartbeat_or_gap_is_one_readers_alone() {
        use crate::core::discovery::multicast::control_parser::parse_all_acknack_submessages;
        use crate::core::discovery::multicast::control_types::{GapInfo, HeartbeatInfo};
        use std::net::UdpSocket;

        const A: [u8; 4] = [0x00, 0x00, 0x01, 0x07];
        const B: [u8; 4] = [0x00, 0x00, 0x02, 0x07];
        const WRITER: [u8; 4] = [0x00, 0x00, 0x01, 0x02];
        let guid = |prefix: u8, entity_id: [u8; 4]| {
            let mut guid = [prefix; 16];
            guid[12..].copy_from_slice(&entity_id);
            guid
        };
        let registry = ReaderProxyRegistry::new();
        registry.match_writer(guid(0x41, WRITER), guid(0x40, A));
        registry.match_writer(guid(0x41, WRITER), guid(0x40, B));

        // The reorder gates take the same addressing as the proxies.
        type Log = Arc<std::sync::Mutex<Vec<(&'static str, &'static str)>>>;
        struct Named(&'static str, [u8; 4], Log);
        impl crate::engine::Subscriber for Named {
            fn on_data(&self, _: &str, _: u64, _: &[u8]) {}
            fn topic_name(&self) -> &str {
                "Addressed"
            }
            fn reader_entity_id(&self) -> Option<[u8; 4]> {
                Some(self.1)
            }
            fn on_writer_heartbeat(&self, _: [u8; 16], _: u64) {
                self.2.lock().expect("log").push((self.0, "hb"));
            }
            fn on_writer_gap(&self, _: [u8; 16], _: u64, _: u64, _: Vec<u64>) {
                self.2.lock().expect("log").push((self.0, "gap"));
            }
        }
        let gates: Log = Arc::new(std::sync::Mutex::new(Vec::new()));
        let topics = Arc::new(TopicRegistry::new());
        for (name, id) in [("a", A), ("b", B)] {
            topics
                .register_subscriber(Arc::new(Named(name, id, Arc::clone(&gates))))
                .expect("register");
        }
        topics.register_writer_guid(guid(0x41, WRITER), "Addressed".to_string());

        let peer = UdpSocket::bind("127.0.0.1:0").expect("bind peer");
        peer.set_read_timeout(Some(Duration::from_millis(300)))
            .expect("read timeout");
        let peer_addr = peer.local_addr().expect("peer addr");
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
            registry,
            Arc::clone(&topics),
            Arc::new(DiscoveryFsm::new(GUID::zero(), 30_000)),
            Arc::new(RwLock::new(SedpHistory::new())),
        );
        let heartbeat = |count: u32, final_flag: bool, reader: [u8; 4], last_seq: i64| {
            ControlMessage::heartbeat(
                Origin::direct(peer_addr),
                [0x41; 12],
                HeartbeatInfo {
                    writer_entity_id: WRITER,
                    first_seq: 1,
                    last_seq,
                    count,
                    final_flag,
                    liveliness_flag: false,
                },
                &[],
            )
            .expect("control message")
            .addressed_to(reader)
        };
        // Every ACKNACK that arrives within a generous deadline; `expected`
        // ends the wait early, and the extra 300 ms of quiet would catch a
        // duplicate answer.
        let answers = |expected: usize| {
            let mut buf = [0u8; 512];
            let mut seen = Vec::new();
            let deadline = Instant::now() + Duration::from_secs(3);
            while Instant::now() < deadline {
                if let Ok(len) = peer.recv(&mut buf) {
                    seen.extend(
                        parse_all_acknack_submessages(&buf[..len])
                            .into_iter()
                            .map(|a| (a.reader_entity_id, a.missing_ranges)),
                    );
                } else if seen.len() >= expected {
                    break;
                }
            }
            seen.sort_by_key(|(reader, _)| *reader);
            seen
        };

        let range = |start: u64, end: u64| vec![std::ops::Range { start, end }];
        assert!(handler.try_send(heartbeat(1, true, A, 3)));
        assert_eq!(answers(1), vec![(A, range(1, 4))], "final HEARTBEAT to A");
        assert!(handler.try_send(heartbeat(2, false, B, 3)));
        assert_eq!(answers(1), vec![(B, range(1, 4))], "batched HEARTBEAT to B");

        let gap = ControlMessage::gap(
            Origin::direct(peer_addr),
            [0x41; 12],
            GapInfo {
                writer_entity_id: WRITER,
                gap_start: 1,
                gap_list_base: 4,
                gap_list_seqs: vec![1, 2, 3],
            },
            &[],
        )
        .expect("control message")
        .addressed_to(B);
        assert!(handler.try_send(gap));

        // One batch: lastSN 3 for A alone, then lastSN 5 for every reader.
        // Past the proxies' 10 ms rate limit first.
        std::thread::sleep(Duration::from_millis(20));
        assert!(handler.try_send(heartbeat(3, false, A, 3)));
        assert!(handler.try_send(heartbeat(4, false, [0; 4], 5)));
        let seen = answers(2);
        handler.shutdown();
        // What the thread guarantees whatever the flush timing: B answers
        // once, from the announcement to every reader; A answers from the
        // latest announcement that addresses it, and nothing else. Whether
        // the two land in ONE batch (one answer from A) depends on the 50 ms
        // flush falling between them: the fold itself is pinned by
        // `a_batch_answers_each_reader_once_from_its_latest_announcement`.
        let of = |reader: [u8; 4]| -> Vec<Vec<std::ops::Range<u64>>> {
            seen.iter()
                .filter(|(r, _)| *r == reader)
                .map(|(_, missing)| missing.clone())
                .collect()
        };
        assert_eq!(of(B), vec![range(1, 6)], "{seen:?}");
        let from_a = of(A);
        assert_eq!(from_a.last(), Some(&range(1, 6)), "{seen:?}");
        assert!(
            from_a
                .iter()
                .all(|missing| *missing == range(1, 6) || *missing == range(1, 4)),
            "{seen:?}"
        );
        let mut gates = gates.lock().expect("log").clone();
        gates.sort_unstable();
        assert_eq!(
            gates,
            vec![
                ("a", "hb"),
                ("a", "hb"),
                ("a", "hb"),
                ("b", "gap"),
                ("b", "hb"),
                ("b", "hb")
            ]
        );
    }

    #[test]
    fn test_derive_reader_entity_id() {
        // RTPS v2.5 Table 9.1 entity kind pairing (writer -> reader)
        assert_eq!(
            derive_reader_entity_id(&[0x00, 0x00, 0x01, 0x02]),
            [0x00, 0x00, 0x01, 0x07]
        );
        assert_eq!(
            derive_reader_entity_id(&[0x00, 0x00, 0x01, 0x03]),
            [0x00, 0x00, 0x01, 0x04]
        );
        assert_eq!(
            derive_reader_entity_id(&[0x00, 0x00, 0x03, 0xC2]),
            [0x00, 0x00, 0x03, 0xC7]
        );
        assert_eq!(
            derive_reader_entity_id(&[0x00, 0x03, 0x00, 0xC3]),
            [0x00, 0x03, 0x00, 0xC4]
        );
    }

    #[cfg(feature = "security")]
    #[test]
    fn secure_sedp_control_repair_heartbeat_counts_advance() {
        let count = || {
            let packet = sedp_heartbeat_response_packet(
                [1; 12],
                &[2; 12],
                None,
                &[0xff, 0, 3, 0xc2],
                1,
                17,
                std::net::Ipv4Addr::LOCALHOST.into(),
                7777,
            )
            .unwrap();
            super::super::control_parser::scan_all_embedded_control_submessages(&packet).1[0]
                .info
                .count
        };
        let first = count();
        let next = count();
        assert!(
            next.wrapping_sub(first) > 0,
            "new repair heartbeats cannot repeat count=1"
        );
    }

    #[cfg(feature = "security")]
    #[test]
    fn secure_sedp_control_refuses_an_unauthenticated_peer() {
        let ours = [0x78; 12];
        let peer = [0x79; 12];
        let mut history = SedpHistory::new();
        history.announce(
            own_announcement(ours, GUID::new(ours, [0, 0, 1, 2])),
            SedpEndpointKind::Writer,
        );
        let (data, heartbeats) = answer_to_a_nack(
            ours,
            peer,
            Arc::new(RwLock::new(history)),
            [0xff, 0, 3, 0xc2],
        );
        assert!(
            data.is_empty(),
            "secure builtin writers match authenticated peers only"
        );
        assert!(heartbeats.is_empty());
    }

    #[cfg(feature = "security")]
    #[test]
    fn secure_sedp_control_uses_its_writer_id_and_the_decoded_reader_proxy() {
        let prefix = [7; 12];
        for (secure, ordinary, kind) in [
            (
                [0xff, 0, 3, 0xc2],
                [0, 0, 3, 0xc2],
                SedpEndpointKind::Writer,
            ),
            (
                [0xff, 0, 4, 0xc2],
                [0, 0, 4, 0xc2],
                SedpEndpointKind::Reader,
            ),
        ] {
            assert!(is_sedp_endpoint(&secure));
            assert_eq!(sedp_endpoint_kind(&secure), Some(kind));
            assert_eq!(
                sedp_proxy_guid(&prefix, &secure),
                writer_guid_of(&prefix, &ordinary)
            );
            let mut history = SedpHistory::new();
            history.announce(
                own_announcement(prefix, GUID::new(prefix, [0, 0, 1, 2])),
                kind,
            );
            let sends = history.sends(Some(kind));
            let gap = secure_sedp_gap(sends[0].build_gap(&prefix).unwrap(), &secure);
            let parsed =
                super::super::control_parser::scan_all_embedded_control_submessages(&gap).0;
            assert_eq!(parsed.len(), 1);
            assert_eq!(parsed[0].info.writer_entity_id, secure);
        }
    }

    /// DDS Security v1.1 Sec.8.8.9.3: a secure SEDP writer refuses a clear
    /// ACKNACK when protection is required, accepts a protected one, and
    /// never refuses a plain (non-secure) SEDP endpoint at all.
    ///
    /// Dropping the `!was_protected` term would refuse every ACKNACK on a
    /// protected topic, including the legitimately-decoded one; the
    /// "protected and required" case below pins that.
    #[cfg(feature = "security")]
    #[test]
    fn secure_sedp_acknack_refusal_rule() {
        use crate::security::access::ProtectionKind;

        const SECURE_PUB: [u8; 4] = [0xff, 0x00, 0x03, 0xc2];
        const PLAIN_PUB: [u8; 4] = [0x00, 0x00, 0x03, 0xc2];

        // Clear, required: refused.
        assert!(secure_sedp_acknack_must_be_refused(
            &SECURE_PUB,
            false,
            Some(ProtectionKind::Encrypt)
        ));
        // Protected, required: accepted.
        assert!(!secure_sedp_acknack_must_be_refused(
            &SECURE_PUB,
            true,
            Some(ProtectionKind::Encrypt)
        ));
        // Clear, no governance at all: accepted (nothing to require).
        assert!(!secure_sedp_acknack_must_be_refused(
            &SECURE_PUB,
            false,
            None
        ));
        // Clear, governance present but explicitly NONE: accepted.
        assert!(!secure_sedp_acknack_must_be_refused(
            &SECURE_PUB,
            false,
            Some(ProtectionKind::None)
        ));
        // A plain SEDP writer is never refused by this rule, protected or
        // not, governance or not.
        assert!(!secure_sedp_acknack_must_be_refused(
            &PLAIN_PUB,
            false,
            Some(ProtectionKind::Encrypt)
        ));
    }

    #[test]
    fn test_is_sedp_endpoint() {
        assert!(is_sedp_endpoint(&[0x00, 0x00, 0x03, 0xC2]));
        assert!(is_sedp_endpoint(&[0x00, 0x00, 0x04, 0xC2]));
        assert!(!is_sedp_endpoint(&[0x00, 0x00, 0x01, 0x02]));
    }

    /// RTPS 2.5 8.3.4 / 8.3.8.10: a relayed HEARTBEAT from a peer the FSM
    /// already knows -- but that announced NO metatraffic locator of its
    /// own (an SPDP announcement with empty `endpoints`, exactly what a
    /// relayed peer with nowhere for a direct reply to go looks like) --
    /// must still advance the writer proxy's state.
    ///
    /// The HEARTBEAT branch must not `continue` as soon as no reply address
    /// resolves: a relayed peer with no locator of its own can never gain
    /// one, so its proxy would never be created, PERMANENTLY, for as long as
    /// it stays relayed -- every later HEARTBEAT would hit the same early
    /// exit.
    #[test]
    fn a_relayed_heartbeat_from_a_locatorless_known_peer_still_updates_proxy_state() {
        use crate::core::discovery::multicast::control_types::HeartbeatInfo;
        use crate::protocol::discovery::SpdpData;
        use std::net::UdpSocket;

        const PEER_PREFIX: [u8; 12] = [0x51; 12];
        const WRITER: [u8; 4] = [0x00, 0x00, 0x03, 0xC2]; // SEDP Publications writer

        let fsm = Arc::new(DiscoveryFsm::new(GUID::zero(), 30_000));
        // Known to the FSM (from SPDP), but announced no metatraffic
        // locator -- the exact shape a relayed peer's own announcement
        // carries when it has nowhere direct to be reached.
        fsm.handle_spdp(SpdpData {
            participant_guid: GUID::new(PEER_PREFIX, [0x00, 0x00, 0x01, 0xC1]),
            lease_duration_ms: 30_000,
            domain_id: 0,
            metatraffic_unicast_locators: vec![],
            default_unicast_locators: vec![],
            default_multicast_locators: vec![],
            metatraffic_multicast_locators: vec![],
            identity_token: None,
            permissions_token: None,
            participant_security_info: None,
            vendor_id: None,
            hdds_capabilities: None,
            builtin_endpoint_set: None,
        });

        let forwarder = UdpSocket::bind("127.0.0.1:0").expect("bind forwarder");
        forwarder
            .set_read_timeout(Some(Duration::from_millis(300)))
            .expect("read timeout");
        let forwarder_addr = forwarder.local_addr().expect("forwarder addr");

        let lease = crate::test_support::domains::unique_domain();
        let mapping =
            crate::transport::PortMapping::calculate(lease.id(), 3).expect("port mapping");
        let transport =
            Arc::new(UdpTransport::new(lease.id(), 3, mapping).expect("test transport"));

        let sedp_registry = ReaderProxyRegistry::new();
        let observer = sedp_registry.clone();
        let handler = ControlHandler::spawn_with_topic_registry(
            transport,
            [0x40; 12],
            7400,
            sedp_registry,
            ReaderProxyRegistry::new(),
            Arc::new(TopicRegistry::new()),
            Arc::clone(&fsm),
            Arc::new(RwLock::new(SedpHistory::new())),
        );

        let msg = ControlMessage::heartbeat(
            Origin::relayed(forwarder_addr),
            PEER_PREFIX,
            HeartbeatInfo {
                writer_entity_id: WRITER,
                first_seq: 5,
                last_seq: 9,
                count: 1,
                final_flag: true,
                liveliness_flag: false,
            },
            &[],
        )
        .expect("control message");
        assert!(handler.try_send(msg));

        let writer_guid = writer_guid_of(&PEER_PREFIX, &WRITER);
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut proxy = None;
        while Instant::now() < deadline {
            proxy = observer.get_proxy(&writer_guid);
            if proxy.is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        handler.shutdown();

        let proxy = proxy.expect(
            "the writer proxy must be created from the HEARTBEAT even though no reply \
             could be sent",
        );
        assert_eq!(
            proxy.low_mark(),
            4,
            "firstSN=5 must advance low_mark to 4 (first_seq - 1), proving the \
             HEARTBEAT's state was recorded"
        );

        let mut buf = [0u8; 256];
        assert!(
            forwarder.recv_from(&mut buf).is_err(),
            "no metatraffic locator for this peer: nothing may be sent to the forwarder"
        );
    }

    /// Where a relayed HEARTBEAT of a matched user writer is answered when
    /// that writer's participant announced no metatraffic locator, for the
    /// discovered locators given: `writer_locator` registered as the
    /// writer's SEDP unicast locator, `participant_locator` as its
    /// participant's default unicast locator. Returns what each of the
    /// three sockets (writer locator, participant locator, forwarder)
    /// received: the ACKNACKs decoded, per socket.
    fn answer_relayed_user_heartbeat_from_a_locatorless_peer(
        writer_locator: bool,
        participant_locator: bool,
        final_flag: bool,
    ) -> [Vec<crate::core::discovery::multicast::control_types::AckNackInfo>; 3] {
        use crate::core::discovery::multicast::control_parser::parse_all_acknack_submessages;
        use crate::core::discovery::multicast::control_types::HeartbeatInfo;
        use crate::protocol::discovery::SpdpData;
        use std::net::UdpSocket;

        const PEER_PREFIX: [u8; 12] = [0x53; 12];
        const WRITER: [u8; 4] = [0x00, 0x00, 0x01, 0x02]; // user-data writer

        let writer_guid = writer_guid_of(&PEER_PREFIX, &WRITER);
        let reader_guid = {
            let mut g = [0x40; 16];
            g[12..].copy_from_slice(&[0x00, 0x00, 0x01, 0x07]);
            g
        };
        let registry = ReaderProxyRegistry::new();
        registry.match_writer(writer_guid, reader_guid);

        let fsm = Arc::new(DiscoveryFsm::new(GUID::zero(), 30_000));
        // Known, but with no metatraffic locator of its own: the relayed
        // HEARTBEAT has no reply address from the FSM's participant record.
        fsm.handle_spdp(SpdpData {
            participant_guid: GUID::new(PEER_PREFIX, [0x00, 0x00, 0x01, 0xC1]),
            lease_duration_ms: 30_000,
            domain_id: 0,
            metatraffic_unicast_locators: vec![],
            default_unicast_locators: vec![],
            default_multicast_locators: vec![],
            metatraffic_multicast_locators: vec![],
            identity_token: None,
            permissions_token: None,
            participant_security_info: None,
            vendor_id: None,
            hdds_capabilities: None,
            builtin_endpoint_set: None,
        });

        let socket = || {
            let s = UdpSocket::bind("127.0.0.1:0").expect("bind");
            s.set_read_timeout(Some(Duration::from_millis(300)))
                .expect("read timeout");
            s
        };
        let at_writer = socket();
        let at_participant = socket();
        let forwarder = socket();
        let endpoints = fsm.endpoint_registry();
        if writer_locator {
            endpoints.register_writer_locator(
                GUID::from_bytes(writer_guid),
                at_writer.local_addr().expect("addr"),
            );
        }
        if participant_locator {
            endpoints.register(
                GUID::new(PEER_PREFIX, [0x00, 0x00, 0x01, 0xC1]),
                at_participant.local_addr().expect("addr"),
            );
        }

        let lease = crate::test_support::domains::unique_domain();
        let mapping =
            crate::transport::PortMapping::calculate(lease.id(), 3).expect("port mapping");
        let transport =
            Arc::new(UdpTransport::new(lease.id(), 3, mapping).expect("test transport"));
        let handler = ControlHandler::spawn_with_topic_registry(
            transport,
            [0x40; 12],
            7400,
            ReaderProxyRegistry::new(),
            registry,
            Arc::new(TopicRegistry::new()),
            Arc::clone(&fsm),
            Arc::new(RwLock::new(SedpHistory::new())),
        );

        let msg = ControlMessage::heartbeat(
            Origin::relayed(forwarder.local_addr().expect("addr")),
            PEER_PREFIX,
            HeartbeatInfo {
                writer_entity_id: WRITER,
                first_seq: 1,
                last_seq: 4,
                count: 1,
                final_flag,
                liveliness_flag: false,
            },
            &[],
        )
        .expect("control message");
        assert!(handler.try_send(msg));

        let drain = |s: &UdpSocket| {
            let mut got = Vec::new();
            let mut buf = [0u8; 512];
            while let Ok(len) = s.recv(&mut buf) {
                got.extend(parse_all_acknack_submessages(&buf[..len]));
            }
            got
        };
        let sockets = [&at_writer, &at_participant, &forwarder];
        let mut out = [Vec::new(), Vec::new(), Vec::new()];
        // The batched (non-final) branch answers on a timer: when a reply is
        // owed, wait for it on a deadline instead of trusting one read
        // timeout, which a loaded machine outruns. Then one quiet drain
        // collects anything else (a second, unwanted reply).
        if writer_locator || participant_locator {
            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            while out.iter().all(Vec::is_empty) && std::time::Instant::now() < deadline {
                for (slot, s) in out.iter_mut().zip(sockets) {
                    slot.extend(drain(s));
                }
            }
        }
        for (slot, s) in out.iter_mut().zip(sockets) {
            slot.extend(drain(s));
        }
        handler.shutdown();
        out
    }

    /// RTPS 2.5 8.4.12.2 / 8.4.10.4: a StatefulReader answers a matched
    /// writer through its WriterProxy. A relayed HEARTBEAT (behind an
    /// INFO_SRC, no reply locator, 8.3.8.10) from a user writer whose
    /// participant announced no metatraffic locator is answered at the
    /// unicast locator the writer announced in SEDP, else at its
    /// participant's default unicast locator; never at the forwarder.
    /// Dropping that ACKNACK stalls a reliable writer for good. Both the
    /// final (answered at once) and the batched (non-final) branch.
    #[test]
    fn a_relayed_user_heartbeat_is_answered_at_the_writer_proxys_locators() {
        for final_flag in [true, false] {
            let [at_writer, at_participant, forwarder] =
                answer_relayed_user_heartbeat_from_a_locatorless_peer(true, true, final_flag);
            assert_eq!(
                at_writer.len(),
                1,
                "final={final_flag}: one ACKNACK at the writer's SEDP locator"
            );
            assert_eq!(at_writer[0].writer_entity_id, [0x00, 0x00, 0x01, 0x02]);
            assert_eq!(at_writer[0].reader_entity_id, [0x00, 0x00, 0x01, 0x07]);
            assert!(
                at_participant.is_empty(),
                "final={final_flag}: the writer's own locator wins"
            );
            assert!(
                forwarder.is_empty(),
                "final={final_flag}: never the forwarder"
            );

            let [at_writer, at_participant, forwarder] =
                answer_relayed_user_heartbeat_from_a_locatorless_peer(false, true, final_flag);
            assert!(at_writer.is_empty());
            assert_eq!(
                at_participant.len(),
                1,
                "final={final_flag}: one ACKNACK at the participant's default unicast locator"
            );
            assert_eq!(at_participant[0].writer_entity_id, [0x00, 0x00, 0x01, 0x02]);
            assert!(
                forwarder.is_empty(),
                "final={final_flag}: never the forwarder"
            );

            let [at_writer, at_participant, forwarder] =
                answer_relayed_user_heartbeat_from_a_locatorless_peer(false, false, final_flag);
            assert!(
                at_writer.is_empty() && at_participant.is_empty() && forwarder.is_empty(),
                "final={final_flag}: no discovered locator at all, no ACKNACK anywhere"
            );
        }
    }

    /// The batched (non-final) HEARTBEAT branch
    /// never replaces a known destination with "unknown" mid-batch. A direct
    /// HEARTBEAT for a user-data writer lands first and establishes
    /// `peer_addr` in the batch entry; a later, batched HEARTBEAT for the
    /// SAME writer, relayed from a peer the FSM has never heard of, resolves
    /// to `peer_addr = None` and must leave the entry's address alone --
    /// not blank out the destination the flush below will send to.
    ///
    /// Both land in the same batch entry (same writer, same unaddressed
    /// ENTITYID_UNKNOWN reader key) because they are sent back to back,
    /// well inside the 50 ms flush window -- the same coalescing the fold
    /// already relies on (see
    /// `a_batch_answers_each_reader_once_from_its_latest_announcement`).
    #[test]
    fn a_batched_heartbeat_with_no_reply_must_not_blank_a_known_address() {
        use crate::core::discovery::multicast::control_parser::parse_all_acknack_submessages;
        use std::net::UdpSocket;

        const PEER_PREFIX: [u8; 12] = [0x52; 12];
        const WRITER: [u8; 4] = [0x00, 0x00, 0x01, 0x02]; // non-SEDP, user-data writer

        let writer_guid = writer_guid_of(&PEER_PREFIX, &WRITER);
        let reader_guid = {
            let mut g = [0x40; 16];
            g[12..].copy_from_slice(&[0x00, 0x00, 0x01, 0x07]);
            g
        };
        let registry = ReaderProxyRegistry::new();
        registry.match_writer(writer_guid, reader_guid);

        let known_peer = UdpSocket::bind("127.0.0.1:0").expect("bind known peer");
        known_peer
            .set_read_timeout(Some(Duration::from_millis(300)))
            .expect("read timeout");
        let known_peer_addr = known_peer.local_addr().expect("known peer addr");

        let forwarder = UdpSocket::bind("127.0.0.1:0").expect("bind forwarder");
        forwarder
            .set_read_timeout(Some(Duration::from_millis(300)))
            .expect("read timeout");
        let forwarder_addr = forwarder.local_addr().expect("forwarder addr");

        let lease = crate::test_support::domains::unique_domain();
        let mapping =
            crate::transport::PortMapping::calculate(lease.id(), 3).expect("port mapping");
        let transport =
            Arc::new(UdpTransport::new(lease.id(), 3, mapping).expect("test transport"));

        let handler = ControlHandler::spawn_with_topic_registry(
            transport,
            [0x40; 12],
            7400,
            ReaderProxyRegistry::new(),
            registry,
            Arc::new(TopicRegistry::new()),
            Arc::new(DiscoveryFsm::new(GUID::zero(), 30_000)),
            Arc::new(RwLock::new(SedpHistory::new())),
        );

        let heartbeat = |origin: Origin, count: u32, last_seq: i64| {
            ControlMessage::heartbeat(
                origin,
                PEER_PREFIX,
                HeartbeatInfo {
                    writer_entity_id: WRITER,
                    first_seq: 1,
                    last_seq,
                    count,
                    final_flag: false,
                    liveliness_flag: false,
                },
                &[],
            )
            .expect("control message")
        };

        // First: direct, from a real socket -- establishes a known
        // destination in the fresh batch entry.
        assert!(handler.try_send(heartbeat(Origin::direct(known_peer_addr), 1, 3)));
        // Second: relayed, from a peer the FSM has never heard of --
        // resolves to peer_addr = None and must not blank the entry.
        assert!(handler.try_send(heartbeat(Origin::relayed(forwarder_addr), 2, 5)));

        let mut buf = [0u8; 512];
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut saw_acknack = false;
        while Instant::now() < deadline {
            if let Ok(len) = known_peer.recv(&mut buf) {
                saw_acknack = !parse_all_acknack_submessages(&buf[..len]).is_empty();
                if saw_acknack {
                    break;
                }
            }
        }
        handler.shutdown();

        assert!(
            saw_acknack,
            "a batched HEARTBEAT with no reply address of its own must not blank \
             out an earlier, known destination in the same batch: the flushed \
             ACKNACK must still reach it"
        );

        let mut fwd_buf = [0u8; 64];
        assert!(
            forwarder.recv_from(&mut fwd_buf).is_err(),
            "the relayed HEARTBEAT's own forwarder address must never receive a reply"
        );
    }

    /// An SEDP announcement of our own participant, of `endpoint`.
    fn own_announcement(ours: [u8; 12], endpoint: GUID) -> crate::protocol::discovery::SedpData {
        crate::protocol::discovery::SedpData {
            topic_name: "Y22Nack".to_string(),
            type_name: "Y22Type".to_string(),
            participant_guid: GUID::new(ours, [0, 0, 1, 0xC1]),
            endpoint_guid: endpoint,
            qos_hash: 0,
            qos: None,
            type_object: None,
            dependents: Vec::new(),
            type_object_legacy_v1: false,
            unicast_locators: vec![],
            user_data: None,
            shm_capability: None,
            has_explicit_reliability: false,
            has_explicit_ownership: false,
            has_ownership_strength: false,
            type_information: None,
            type_consistency: None,
            group_entity_id: None,
            endpoint_security_info: None,
        }
    }

    /// The parameter ids of every SEDP DATA a peer receives until its read
    /// times out, one list per DATA, and the participants its INFO_DSTs
    /// address (an answer names its reader's participant; other periodic
    /// traffic to the same socket does not).
    fn sedp_data_pids(peer: &std::net::UdpSocket) -> (Vec<Vec<u16>>, Vec<[u8; 12]>) {
        let mut out = Vec::new();
        let mut addressed = Vec::new();
        let mut buf = [0u8; 8192];
        while let Ok(len) = peer.recv(&mut buf) {
            let dgram = &buf[..len];
            crate::core::discovery::multicast::classifier::walk::for_each_submessage(
                dgram,
                |sub| {
                    if sub.id == 0x0e && sub.body_end >= sub.offset + 16 {
                        let mut prefix = [0u8; 12];
                        prefix.copy_from_slice(&dgram[sub.offset + 4..sub.offset + 16]);
                        addressed.push(prefix);
                    }
                    if sub.id == 0x15 {
                        let body = sub.offset + 4;
                        let to_inline =
                            usize::from(u16::from_le_bytes([dgram[body + 2], dgram[body + 3]]));
                        let mut p = body + 4 + to_inline + 4;
                        let mut pids = Vec::new();
                        while p + 4 <= sub.body_end {
                            let pid = u16::from_le_bytes([dgram[p], dgram[p + 1]]);
                            let len = usize::from(u16::from_le_bytes([dgram[p + 2], dgram[p + 3]]));
                            if pid == 0x0001 {
                                break;
                            }
                            pids.push(pid);
                            p += 4 + len;
                        }
                        out.push(pids);
                    }
                    crate::core::discovery::multicast::classifier::walk::Step::Continue
                },
            );
        }
        (out, addressed)
    }

    /// The SEDP repair (an ACKNACK of our publications writer, through the
    /// control loop) carries PID_TYPE_OBJECT by the class discovery keeps
    /// for the peer: not to an HDDS 1.4.x participant, to one announcing
    /// CAP_TYPE_OBJECT_SPEC_STRINGS. A participant discovery does not know is
    /// not answered at all (RTPS v2.5 Sec.8.4.7, Sec.8.5.3); once its SPDP
    /// with the capability is admitted, the repair of the same number
    /// carries the PID. PID_TYPE_INFORMATION goes to every known peer.
    #[cfg(feature = "xtypes")]
    #[test]
    fn a_sedp_repair_carries_the_type_object_by_the_peers_class() {
        use crate::core::discovery::multicast::control_types::AckNackInfo;
        use crate::protocol::discovery::SpdpData;
        use crate::protocol::group::LOCAL_CAPABILITIES;
        use std::net::UdpSocket;

        const OURS: [u8; 12] = [0x01, 0x1a, 0x73, 0x73, 0, 0, 0, 0, 0, 0, 0, 1];
        let mut announcement = own_announcement(OURS, GUID::new(OURS, [0x00, 0x00, 0x01, 0x02]));
        announcement.type_object = Some(crate::xtypes::CompleteTypeObject::Struct(
            crate::xtypes::CompleteStructType {
                struct_flags: crate::xtypes::StructTypeFlag::IS_APPENDABLE,
                header: crate::xtypes::CompleteStructHeader {
                    base_type: None,
                    detail: crate::xtypes::CompleteTypeDetail::new("Y22Type"),
                },
                member_seq: vec![crate::xtypes::CompleteStructMember {
                    common: crate::xtypes::CommonStructMember {
                        member_id: 0,
                        member_flags: crate::xtypes::MemberFlag::TRY_CONSTRUCT1,
                        member_type_id: crate::xtypes::TypeIdentifier::string(128),
                    },
                    detail: crate::xtypes::CompleteMemberDetail::new("color"),
                }],
            },
        ));
        let mut history = SedpHistory::new();
        history.announce(announcement, SedpEndpointKind::Writer);
        let history = Arc::new(RwLock::new(history));

        let peer_sock = UdpSocket::bind("127.0.0.1:0").expect("bind peer");
        peer_sock
            .set_read_timeout(Some(Duration::from_millis(400)))
            .expect("read timeout");
        let peer_addr = peer_sock.local_addr().expect("peer addr");
        let spdp = |prefix: [u8; 12], caps: Option<u32>| SpdpData {
            participant_guid: GUID::new(prefix, [0, 0, 1, 0xC1]),
            lease_duration_ms: 30_000,
            domain_id: 0,
            metatraffic_unicast_locators: vec![peer_addr],
            default_unicast_locators: vec![],
            default_multicast_locators: vec![],
            metatraffic_multicast_locators: vec![],
            identity_token: None,
            permissions_token: None,
            participant_security_info: None,
            vendor_id: Some(crate::core::rtps_constants::HDDS_VENDOR_ID_U16),
            hdds_capabilities: caps,
            builtin_endpoint_set: None,
        };
        let fsm = Arc::new(DiscoveryFsm::new(GUID::new(OURS, [0, 0, 1, 0xC1]), 30_000));
        let lease = crate::test_support::domains::unique_domain();
        let mapping =
            crate::transport::PortMapping::calculate(lease.id(), 2).expect("port mapping");
        let transport =
            Arc::new(UdpTransport::new(lease.id(), 2, mapping).expect("test transport"));
        let handler = ControlHandler::spawn_with_topic_registry(
            transport,
            OURS,
            7400,
            ReaderProxyRegistry::new(),
            ReaderProxyRegistry::new(),
            Arc::new(TopicRegistry::new()),
            Arc::clone(&fsm),
            history,
        );
        let nack = |prefix: [u8; 12]| {
            let writer = [0x00, 0x00, 0x03, 0xC2];
            let msg = ControlMessage::acknack(
                Origin::direct(peer_addr),
                prefix,
                AckNackInfo {
                    reader_entity_id: derive_reader_entity_id(&writer),
                    writer_entity_id: writer,
                    missing_ranges: vec![std::ops::Range { start: 1, end: 2 }],
                    bitmap_base: 1,
                    count: None,
                },
                &[],
            )
            .expect("control message");
            assert!(handler.try_send(msg));
            sedp_data_pids(&peer_sock)
        };

        let old = [0x01, 0x1a, 0x14, 0x08, 0, 0, 0, 0, 0, 0, 0, 2];
        fsm.handle_spdp(spdp(old, None));
        let (to_old, _) = nack(old);
        assert_eq!(to_old.len(), 1, "{to_old:04x?}");
        assert!(
            to_old[0].contains(&0x0075) && !to_old[0].contains(&0x0072),
            "{to_old:04x?}"
        );

        let new = [0x01, 0x1a, 0x15, 0x00, 0, 0, 0, 0, 0, 0, 0, 3];
        fsm.handle_spdp(spdp(new, Some(LOCAL_CAPABILITIES)));
        let (to_new, _) = nack(new);
        assert_eq!(to_new.len(), 1, "{to_new:04x?}");
        assert!(
            to_new[0].contains(&0x0072) && to_new[0].contains(&0x0075),
            "{to_new:04x?}"
        );

        let early = [0x01, 0x1a, 0x15, 0x01, 0, 0, 0, 0, 0, 0, 0, 4];
        let (data, addressed) = nack(early);
        assert!(data.is_empty(), "{data:04x?}");
        assert!(
            !addressed.contains(&early),
            "an unknown participant is not answered, HEARTBEAT included"
        );
        // The repair itself refuses it too, whoever calls it.
        let lease2 = crate::test_support::domains::unique_domain();
        let mapping2 =
            crate::transport::PortMapping::calculate(lease2.id(), 2).expect("port mapping");
        let direct = UdpTransport::new(lease2.id(), 2, mapping2).expect("test transport");
        let repair_history = {
            let mut h = SedpHistory::new();
            h.announce(
                own_announcement(OURS, GUID::new(OURS, [0x00, 0x00, 0x02, 0x02])),
                SedpEndpointKind::Writer,
            );
            Arc::new(RwLock::new(h))
        };
        assert_eq!(
            ControlHandler::retransmit_sedp_data(
                &direct,
                OURS,
                &early,
                &[0x00, 0x00, 0x03, 0xC2],
                peer_addr.port(),
                peer_addr.ip(),
                &repair_history,
                &ControlMetrics::new(),
                &fsm,
            ),
            None,
            "no repair to a participant discovery does not know"
        );
        let (data, addressed) = sedp_data_pids(&peer_sock);
        assert!(
            data.is_empty() && !addressed.contains(&early),
            "{data:04x?}"
        );
        fsm.handle_spdp(spdp(early, Some(LOCAL_CAPABILITIES)));
        let (after, _) = nack(early);
        assert_eq!(after.len(), 1, "{after:04x?}");
        assert!(after[0].contains(&0x0072), "{after:04x?}");
        handler.shutdown();
    }

    /// (id, flags, writerSN or gapStart, gapList.base or 0, writerId) of
    /// every DATA and GAP, and (firstSN, lastSN, writerId) of every
    /// HEARTBEAT, a peer that holds nothing receives when it NACKs `nacked`
    /// (1..=2) of `history`, as the control thread answers.
    #[allow(clippy::type_complexity)]
    fn answer_to_a_nack(
        ours: [u8; 12],
        peer_prefix: [u8; 12],
        history: Arc<RwLock<SedpHistory>>,
        nacked: [u8; 4],
    ) -> (Vec<(u8, u8, u64, u64, [u8; 4])>, Vec<(u64, u64, [u8; 4])>) {
        use crate::core::discovery::multicast::control_parser::parse_all_acknack_submessages;
        use crate::core::discovery::multicast::control_types::AckNackInfo;
        use crate::protocol::discovery::SpdpData;
        use std::net::UdpSocket;

        let peer = UdpSocket::bind("127.0.0.1:0").expect("bind peer");
        peer.set_read_timeout(Some(Duration::from_millis(400)))
            .expect("read timeout");
        let peer_addr = peer.local_addr().expect("peer addr");
        let fsm = Arc::new(DiscoveryFsm::new(GUID::new(ours, [0, 0, 1, 0xC1]), 30_000));
        fsm.handle_spdp(SpdpData {
            participant_guid: GUID::new(peer_prefix, [0, 0, 1, 0xC1]),
            lease_duration_ms: 30_000,
            domain_id: 0,
            metatraffic_unicast_locators: vec![peer_addr],
            default_unicast_locators: vec![],
            default_multicast_locators: vec![],
            metatraffic_multicast_locators: vec![],
            identity_token: None,
            permissions_token: None,
            participant_security_info: None,
            vendor_id: None,
            hdds_capabilities: None,
            builtin_endpoint_set: None,
        });
        let lease = crate::test_support::domains::unique_domain();
        let mapping =
            crate::transport::PortMapping::calculate(lease.id(), 2).expect("port mapping");
        let transport =
            Arc::new(UdpTransport::new(lease.id(), 2, mapping).expect("test transport"));
        let handler = ControlHandler::spawn_with_topic_registry(
            transport,
            ours,
            7400,
            ReaderProxyRegistry::new(),
            ReaderProxyRegistry::new(),
            Arc::new(TopicRegistry::new()),
            fsm,
            history,
        );

        let nack = ControlMessage::acknack(
            Origin::direct(peer_addr),
            peer_prefix,
            AckNackInfo {
                reader_entity_id: derive_reader_entity_id(&nacked),
                writer_entity_id: nacked,
                missing_ranges: vec![std::ops::Range { start: 1, end: 3 }],
                bitmap_base: 1,
                count: None,
            },
            &[],
        )
        .expect("control message");
        assert!(handler.try_send(nack));

        let is_sedp_writer =
            |id: &[u8]| id == [0x00, 0x00, 0x03, 0xC2] || id == [0x00, 0x00, 0x04, 0xC2];
        let mut seen = Vec::new();
        let mut heartbeats = Vec::new();
        let mut buf = [0u8; 2048];
        while let Ok(len) = peer.recv(&mut buf) {
            let dgram = &buf[..len];
            crate::core::discovery::multicast::classifier::walk::for_each_submessage(
                dgram,
                |sub| {
                    let body = sub.offset + 4;
                    let sn = |at: usize| {
                        let high =
                            u32::from_le_bytes(dgram[at..at + 4].try_into().expect("four octets"));
                        let low = u32::from_le_bytes(
                            dgram[at + 4..at + 8].try_into().expect("four octets"),
                        );
                        (u64::from(high) << 32) | u64::from(low)
                    };
                    let id = |at: usize| -> [u8; 4] {
                        dgram[at..at + 4].try_into().expect("four octets")
                    };
                    match sub.id {
                        0x15 if is_sedp_writer(&dgram[body + 8..body + 12]) => {
                            seen.push((sub.id, sub.flags, sn(body + 12), 0, id(body + 8)));
                        }
                        0x08 if is_sedp_writer(&dgram[body + 4..body + 8]) => {
                            seen.push((
                                sub.id,
                                sub.flags,
                                sn(body + 8),
                                sn(body + 16),
                                id(body + 4),
                            ));
                        }
                        0x07 if is_sedp_writer(&dgram[body + 4..body + 8]) => {
                            heartbeats.push((sn(body + 8), sn(body + 16), id(body + 4)));
                        }
                        _ => {}
                    }
                    crate::core::discovery::multicast::classifier::walk::Step::Continue
                },
            );
            assert!(
                parse_all_acknack_submessages(dgram).is_empty(),
                "a writer answers a NACK, it does not acknowledge"
            );
        }
        handler.shutdown();
        (seen, heartbeats)
    }

    /// The SEDP data of endpoints our own participant announced, then
    /// deleted, is never sent again. A NACK of their numbers is answered with
    /// one GAP for both, the dispose of each after them, and a HEARTBEAT
    /// whose range starts at the first dispose, the first change not
    /// superseded, and ends at the last (RTPS v2.5 Sec.8.5.4.4, Tables 8.82,
    /// 8.83, Sec.8.3.8.6).
    #[test]
    fn a_nack_after_a_deletion_gets_a_gap_and_the_dispose_never_the_announcement() {
        const OURS: [u8; 12] = [0x60; 12];
        const PEER_PREFIX: [u8; 12] = [0x61; 12];
        const SEDP_PUB_WRITER: [u8; 4] = [0x00, 0x00, 0x03, 0xC2];
        let history = Arc::new(RwLock::new(SedpHistory::new()));
        let deleted = [
            GUID::new(OURS, [0x00, 0x00, 0x01, 0x02]),
            GUID::new(OURS, [0x00, 0x00, 0x02, 0x02]),
        ];
        for endpoint in deleted {
            history
                .write()
                .expect("history")
                .announce(own_announcement(OURS, endpoint), SedpEndpointKind::Writer);
        }
        for (endpoint, seq) in deleted.iter().zip([3, 4]) {
            assert_eq!(
                history
                    .write()
                    .expect("history")
                    .retire(endpoint, SedpEndpointKind::Writer),
                Some(seq)
            );
        }

        let (seen, heartbeats) = answer_to_a_nack(OURS, PEER_PREFIX, history, SEDP_PUB_WRITER);
        assert_eq!(
            seen,
            vec![
                (0x08, 0x01, 1, 3, SEDP_PUB_WRITER),
                (0x15, 0x0b, 3, 0, SEDP_PUB_WRITER),
                (0x15, 0x0b, 4, 0, SEDP_PUB_WRITER)
            ],
            "one GAP retiring 1..2, then the disposes (E|Q|K) at 3 and 4; never an \
             announcement (D)"
        );
        assert_eq!(
            heartbeats,
            vec![(3, 4, SEDP_PUB_WRITER)],
            "the range starts at the first change not superseded and ends at the last dispose"
        );
    }

    /// A NACK of one SEDP writer is answered with that writer's history
    /// alone, when the other writer has changes too: the subscriptions
    /// writer's numbers are not the publications writer's.
    #[test]
    fn a_nack_of_one_sedp_writer_gets_that_writers_history_alone() {
        const OURS: [u8; 12] = [0x64; 12];
        const PEER_PREFIX: [u8; 12] = [0x65; 12];
        const SEDP_SUB_WRITER: [u8; 4] = [0x00, 0x00, 0x04, 0xC2];
        let history = Arc::new(RwLock::new(SedpHistory::new()));
        {
            let mut h = history.write().expect("history");
            for (entity, kind) in [
                ([0x00, 0x00, 0x01, 0x02], SedpEndpointKind::Writer),
                ([0x00, 0x00, 0x02, 0x07], SedpEndpointKind::Reader),
                ([0x00, 0x00, 0x03, 0x02], SedpEndpointKind::Writer),
            ] {
                h.announce(own_announcement(OURS, GUID::new(OURS, entity)), kind);
            }
        }

        let (seen, heartbeats) = answer_to_a_nack(OURS, PEER_PREFIX, history, SEDP_SUB_WRITER);
        assert_eq!(
            seen,
            vec![(0x15, 0x05, 1, 0, SEDP_SUB_WRITER)],
            "the one reader's announcement (E|D) at 1; neither writer's"
        );
        assert_eq!(heartbeats, vec![(1, 1, SEDP_SUB_WRITER)]);
    }

    /// Proves that a protected ACKNACK actually drives a retransmission.
    /// The live two-participant "late joiner" e2e test exercises a
    /// DIFFERENT discovery path (the proactive SEDP reannounce on
    /// handshake completion, not ACKNACK-driven repair) -- see
    /// `security::e2e_tests::a_late_secure_reader_is_caught_up_over_a_
    /// protected_secure_sedp_exchange`. THIS test proves the specific
    /// mechanism directly, independent of discovery timing, against a
    /// primed `SedpHistory`.
    ///
    /// It does not build a synthetic `AckNackInfo` by hand (that would
    /// prove the COUNTING logic only, never that a genuinely protected
    /// ACKNACK decodes). Instead it mints real key material, protects a real ACKNACK packet with
    /// `secure_sedp::protect_reader_control_packet` (the function the
    /// peer's OWN reader would call), decodes it back with `secure_sedp::
    /// open_reader_control_packet` (the function `DiscoveryDispatch::
    /// open_one_secure_envelope` calls on receipt) -- the actual AEAD
    /// verify runs -- and only THEN reproduces `dispatch_decoded_reader_
    /// control`'s own small glue (building the minimal `[RTPS header]
    /// [submessage]` buffer, parsing it, marking it `.protected()`) to
    /// hand the result to this same `ControlHandler`. The retransmission
    /// is then identified as real DATA, not merely "something arrived".
    ///
    /// The `if msg.was_protected()` guard around the `fetch_add` (which
    /// keeps unprotected retransmissions out of the count) is not exercised
    /// by `a_plain_acknack_on_a_secure_writer_is_refused_and_never_counted`
    /// below: that ACKNACK never reaches `retransmit_sedp_data` at all, it
    /// is refused earlier by the clear-ACKNACK rule, for an unrelated
    /// reason. `a_clear_acknack_on_a_plain_writer_retransmits_without_
    /// counting_as_protected` is the test that isolates this guard: a PLAIN
    /// (non-secure) writer's clear ACKNACK reaches the success arm just
    /// fine, and must NOT move this counter.
    #[cfg(feature = "security")]
    #[test]
    fn a_protected_acknack_with_real_missing_ranges_drives_a_counted_retransmission() {
        use crate::core::rtps_constants::RTPS_ENTITYID_SEDP_PUBLICATIONS_SECURE_READER;
        use crate::protocol::discovery::SpdpData;
        use crate::security::crypto::data_keys::WriterKey;
        use crate::security::crypto::secure_sedp;
        use crate::security::crypto::secure_submessage::first_secure_prefix;
        use std::net::UdpSocket;

        const OURS: [u8; 12] = crate::security::test_pki::bound_test_prefix([0x70; 6]);
        const PEER_PREFIX: [u8; 12] = crate::security::test_pki::bound_test_prefix([0x71; 6]);
        const SEDP_PUB_SECURE_WRITER: [u8; 4] = [0xff, 0x00, 0x03, 0xc2];

        let history = Arc::new(RwLock::new(SedpHistory::new()));
        {
            let mut h = history.write().expect("history");
            h.announce(
                own_announcement(OURS, GUID::new(OURS, [0, 0, 0x12, 0x02])),
                SedpEndpointKind::Writer,
            );
        }

        let peer = UdpSocket::bind("127.0.0.1:0").expect("bind peer");
        peer.set_read_timeout(Some(Duration::from_millis(400)))
            .expect("read timeout");
        let peer_addr = peer.local_addr().expect("peer addr");

        let machine =
            crate::security::test_pki::local_machine_with_completed_peer(OURS, PEER_PREFIX, None);
        let mut fsm = DiscoveryFsm::new(GUID::new(OURS, [0, 0, 1, 0xC1]), 30_000);
        fsm.set_handshake_machine(
            machine,
            crate::security::test_pki::TEST_IDENTITY_CERT_PEM.to_vec(),
            crate::security::test_pki::TEST_IDENTITY_KEY_PEM.to_vec(),
        );
        use crate::security::access::{DiscoveryGovernance, DomainRule, ProtectionKind};
        fsm.set_discovery_governance(Some(DiscoveryGovernance::new(DomainRule {
            domains: vec![0],
            domain_ranges: vec![],
            allow_unauthenticated: false,
            enable_join_access_control: true,
            discovery_protection_kind: ProtectionKind::Encrypt,
            liveliness_protection_kind: ProtectionKind::None,
            rtps_protection_kind: ProtectionKind::None,
            topic_rules: vec![],
        })));
        fsm.handle_spdp(SpdpData {
            participant_guid: GUID::new(PEER_PREFIX, [0, 0, 1, 0xC1]),
            lease_duration_ms: 30_000,
            domain_id: 0,
            metatraffic_unicast_locators: vec![peer_addr],
            default_unicast_locators: vec![],
            default_multicast_locators: vec![],
            metatraffic_multicast_locators: vec![],
            identity_token: None,
            permissions_token: None,
            participant_security_info: None,
            vendor_id: None,
            hdds_capabilities: None,
            builtin_endpoint_set: None,
        });
        assert!(
            fsm.is_peer_authenticated(&PEER_PREFIX),
            "fixture: the handshake fixture completed"
        );
        // Our own secure builtin writer key material, so `sedp_for_peer`
        // has something to protect the retransmission with rather than
        // refusing to send (`sedp_datagram_for`'s `(Some(true), None) =>
        // None` arm).
        fsm.register_builtin_writer_keys_for_tests();
        // The PEER's reader key material: what its OWN SEDP publications
        // reader would have announced in its DatareaderCryptoTokens for
        // us to decode its ACKNACK with (`DiscoveryFsm::remote_builtin_
        // reader_materials`'s lookup key is (sender prefix, reader entity
        // id) in the very same store `register_builtin_writer_keys_for_
        // tests` just populated).
        let (peer_reader_key_id, peer_reader_key) =
            WriterKey::mint().expect("mint a reader key for the peer fixture");
        let peer_reader_material = peer_reader_key.submessage_material(peer_reader_key_id);
        fsm.receive_writer_key_for_tests(
            PEER_PREFIX,
            RTPS_ENTITYID_SEDP_PUBLICATIONS_SECURE_READER,
            u64::from(peer_reader_key_id),
            peer_reader_key,
        );
        let fsm = Arc::new(fsm);

        let lease = crate::test_support::domains::unique_domain();
        let mapping =
            crate::transport::PortMapping::calculate(lease.id(), 2).expect("port mapping");
        let transport =
            Arc::new(UdpTransport::new(lease.id(), 2, mapping).expect("test transport"));
        let handler = ControlHandler::spawn_with_topic_registry(
            transport,
            OURS,
            7400,
            ReaderProxyRegistry::new(),
            ReaderProxyRegistry::new(),
            Arc::new(TopicRegistry::new()),
            fsm.clone(),
            history,
        );

        // Build a REAL ACKNACK packet (the peer's reader naming our secure
        // writer, missing sequence 1), protect it with the peer's reader
        // material -- the same function the peer's own reader would call
        // -- and decode it back with `open_reader_control_packet`, the
        // production decode this ACKNACK would actually go through
        // (`DiscoveryDispatch::open_one_secure_envelope`). This runs the
        // real AEAD verify, not a hand-set `.protected()` flag.
        let plain = crate::protocol::builder::build_acknack_packet_with_final(
            PEER_PREFIX,
            OURS,
            RTPS_ENTITYID_SEDP_PUBLICATIONS_SECURE_READER,
            SEDP_PUB_SECURE_WRITER,
            1,
            &[1],
            1,
            false,
        );
        let protected = secure_sedp::protect_reader_control_packet(&plain, &peer_reader_material)
            .expect("the peer's reader protects its own ACKNACK");
        let prefix_at =
            first_secure_prefix(&protected).expect("a SEC_PREFIX envelope was just built");
        let opened = secure_sedp::open_reader_control_packet(
            &protected,
            prefix_at,
            &peer_reader_material,
            &RTPS_ENTITYID_SEDP_PUBLICATIONS_SECURE_READER,
            ProtectionKind::Encrypt,
        )
        .expect("the production decode must open what protect_reader_control_packet built");

        // `DiscoveryDispatch::dispatch_decoded_reader_control`'s own glue,
        // reproduced here (not security-sensitive: parsing a submessage
        // this test already knows the shape of, and marking it
        // `.protected()`), to hand the DECODED result -- not a synthetic
        // one -- to this `ControlHandler` exactly as production would.
        let mut minimal = Vec::with_capacity(20 + opened.submessage.len());
        minimal.extend_from_slice(b"RTPS");
        minimal.extend_from_slice(&[
            crate::core::rtps_constants::RTPS_VERSION_MAJOR,
            crate::core::rtps_constants::RTPS_VERSION_MINOR,
        ]);
        minimal.extend_from_slice(&crate::core::rtps_constants::HDDS_VENDOR_ID);
        minimal.extend_from_slice(&PEER_PREFIX);
        minimal.extend_from_slice(&opened.submessage);
        let infos =
            crate::core::discovery::multicast::control_parser::parse_all_acknack_submessages(
                &minimal,
            );
        assert_eq!(infos.len(), 1, "the decoded submessage is one ACKNACK");
        let nack = ControlMessage::acknack(
            Origin::direct(peer_addr),
            PEER_PREFIX,
            infos.into_iter().next().expect("checked above"),
            &minimal,
        )
        .expect("control message")
        .protected();
        assert!(handler.try_send(nack));

        // The retransmission itself, captured on the wire.
        let mut captured = Vec::new();
        let mut buf = [0u8; 2048];
        while let Ok(len) = peer.recv(&mut buf) {
            captured.push(buf[..len].to_vec());
        }
        handler.shutdown();

        assert!(
            !captured.is_empty(),
            "the secure SEDP writer never retransmitted its announcement on the wire"
        );
        // Identify the retransmitted DATA. The repair response is itself
        // GCM-protected (this governance's ENCRYPT), so it is not a bare
        // 0x15 on the wire -- decode it, with our own writer material
        // (`sedp_keys_for`, the same material that encoded it, GCM being
        // symmetric), exactly as a real peer would with the copy we
        // announce it in our DatawriterCryptoTokens.
        let our_writer_keys = fsm
            .sedp_keys_for(&PEER_PREFIX)
            .expect("fixture: local writer material exists");
        let decoded_data = captured.iter().find_map(|datagram| {
            let prefix_at = first_secure_prefix(datagram)?;
            secure_sedp::open_secure_sedp_as(
                datagram,
                prefix_at,
                &our_writer_keys.publications,
                &SEDP_PUB_SECURE_WRITER,
                ProtectionKind::Encrypt,
            )
        });
        let decoded_data = decoded_data.expect(
            "no captured datagram decoded as a protected SEDP DATA of our publications writer",
        );
        assert!(
            submessage_ids(&decoded_data.datagram).contains(&0x15),
            "the decoded repair response does not carry a DATA submessage: {:?}",
            submessage_ids(&decoded_data.datagram)
        );
        assert_eq!(
            fsm.metrics
                .protected_sedp_retransmissions
                .load(std::sync::atomic::Ordering::Relaxed),
            1,
            "the protected-ACKNACK-driven repair must be counted exactly once"
        );
        assert_eq!(
            fsm.metrics
                .protected_sedp_data_retransmissions
                .load(std::sync::atomic::Ordering::Relaxed),
            1,
            "it must be counted as a real DATA retransmission, not merely a repair response"
        );
    }

    /// The GAP-only case `protected_sedp_data_retransmissions` exists for:
    /// when every entry
    /// `retransmit_sedp_data` has to answer with belongs to the REGULAR
    /// (unprotected) SEDP sequence space -- sharing numbers with the
    /// secure writer being asked, but not itself discovery-protected --
    /// the secure writer declares the whole range irrelevant and answers
    /// with nothing but a GAP (`writer_entity_id[0] == 0xff && send.
    /// discovery_protected() == Some(false)`, HDDS's own Sec.7.4.1.5-based
    /// partition of one shared sequence space into a secure and a plain
    /// half). A real repair ran (`protected_sedp_retransmissions` moves),
    /// but no DATA at all crossed the wire for it.
    #[cfg(feature = "security")]
    #[test]
    fn a_protected_acknack_answered_entirely_by_gap_counts_the_repair_not_the_data() {
        use crate::core::discovery::multicast::control_types::AckNackInfo;
        use crate::protocol::discovery::EndpointSecurityInfo;
        use crate::protocol::discovery::SpdpData;
        use std::net::UdpSocket;

        const OURS: [u8; 12] = crate::security::test_pki::bound_test_prefix([0x78; 6]);
        const PEER_PREFIX: [u8; 12] = crate::security::test_pki::bound_test_prefix([0x79; 6]);
        const SEDP_PUB_SECURE_WRITER: [u8; 4] = [0xff, 0x00, 0x03, 0xc2];
        let endpoint = GUID::new(OURS, [0, 0, 0x12, 0x02]);

        let history = Arc::new(RwLock::new(SedpHistory::new()));
        {
            let mut h = history.write().expect("history");
            // Announced with a VALID security info whose discovery-
            // protected bit is CLEAR: this entity lives on the regular
            // SEDP topic, sharing the Writer sequence space the secure
            // writer below is also asked about.
            h.announce_with(
                own_announcement(OURS, endpoint),
                SedpEndpointKind::Writer,
                Some(EndpointSecurityInfo {
                    endpoint_security_attributes: EndpointSecurityInfo::IS_VALID,
                    plugin_endpoint_security_attributes: 0,
                }),
            );
        }

        let peer = UdpSocket::bind("127.0.0.1:0").expect("bind peer");
        peer.set_read_timeout(Some(Duration::from_millis(400)))
            .expect("read timeout");
        let peer_addr = peer.local_addr().expect("peer addr");

        let machine =
            crate::security::test_pki::local_machine_with_completed_peer(OURS, PEER_PREFIX, None);
        let mut fsm = DiscoveryFsm::new(GUID::new(OURS, [0, 0, 1, 0xC1]), 30_000);
        fsm.set_handshake_machine(
            machine,
            crate::security::test_pki::TEST_IDENTITY_CERT_PEM.to_vec(),
            crate::security::test_pki::TEST_IDENTITY_KEY_PEM.to_vec(),
        );
        use crate::security::access::{DiscoveryGovernance, DomainRule, ProtectionKind};
        fsm.set_discovery_governance(Some(DiscoveryGovernance::new(DomainRule {
            domains: vec![0],
            domain_ranges: vec![],
            allow_unauthenticated: false,
            enable_join_access_control: true,
            discovery_protection_kind: ProtectionKind::Encrypt,
            liveliness_protection_kind: ProtectionKind::None,
            rtps_protection_kind: ProtectionKind::None,
            topic_rules: vec![],
        })));
        fsm.handle_spdp(SpdpData {
            participant_guid: GUID::new(PEER_PREFIX, [0, 0, 1, 0xC1]),
            lease_duration_ms: 30_000,
            domain_id: 0,
            metatraffic_unicast_locators: vec![peer_addr],
            default_unicast_locators: vec![],
            default_multicast_locators: vec![],
            metatraffic_multicast_locators: vec![],
            identity_token: None,
            permissions_token: None,
            participant_security_info: None,
            vendor_id: None,
            hdds_capabilities: None,
            builtin_endpoint_set: None,
        });
        assert!(
            fsm.is_peer_authenticated(&PEER_PREFIX),
            "fixture: the handshake fixture completed"
        );
        fsm.register_builtin_writer_keys_for_tests();
        let fsm = Arc::new(fsm);

        let lease = crate::test_support::domains::unique_domain();
        let mapping =
            crate::transport::PortMapping::calculate(lease.id(), 2).expect("port mapping");
        let transport =
            Arc::new(UdpTransport::new(lease.id(), 2, mapping).expect("test transport"));
        let handler = ControlHandler::spawn_with_topic_registry(
            transport,
            OURS,
            7400,
            ReaderProxyRegistry::new(),
            ReaderProxyRegistry::new(),
            Arc::new(TopicRegistry::new()),
            fsm.clone(),
            history,
        );

        let nack = ControlMessage::acknack(
            Origin::direct(peer_addr),
            PEER_PREFIX,
            AckNackInfo {
                reader_entity_id: derive_reader_entity_id(&SEDP_PUB_SECURE_WRITER),
                writer_entity_id: SEDP_PUB_SECURE_WRITER,
                missing_ranges: vec![std::ops::Range { start: 1, end: 2 }],
                bitmap_base: 1,
                count: None,
            },
            &[],
        )
        .expect("control message")
        .protected();
        assert!(handler.try_send(nack));

        let mut captured = Vec::new();
        let mut buf = [0u8; 2048];
        while let Ok(len) = peer.recv(&mut buf) {
            captured.push(buf[..len].to_vec());
        }
        handler.shutdown();
        let ids: Vec<Vec<u8>> = captured.iter().map(|d| submessage_ids(d)).collect();

        assert!(
            !captured.is_empty(),
            "fixture: the writer's retained history must still be answered"
        );
        // The shared number really did go out as a bare GAP (id 0x08,
        // sent in the clear even to a peer whose SEDP is protected --
        // `SedpSend::is_gap`'s own doc): this is what makes the
        // assertions below a real exclusion, not an accident of the one
        // entry never being sent at all.
        assert!(
            ids.iter().any(|m| m == &vec![0x08]),
            "the regular-topic number must have gone out as its own GAP datagram: {ids:?}"
        );
        assert!(
            !ids.iter().any(|m| m.contains(&0x15)),
            "no DATA submessage may appear: every entry answered belongs to the plain SEDP \
             topic, which this secure writer never carries: {ids:?}"
        );
        assert_eq!(
            fsm.metrics
                .protected_sedp_retransmissions
                .load(std::sync::atomic::Ordering::Relaxed),
            1,
            "one protected-ACKNACK-driven repair call, whatever it sent"
        );
        assert_eq!(
            fsm.metrics
                .protected_sedp_data_retransmissions
                .load(std::sync::atomic::Ordering::Relaxed),
            0,
            "a GAP-only answer carries no DATA: this counter must not move"
        );
    }

    /// The zero case of the test above: a CLEAR ACKNACK naming
    /// the same secure writer and the same real missing range must be
    /// refused outright (the clear-ACKNACK rule) and must drive NO
    /// retransmission and NO count on `protected_sedp_retransmissions` --
    /// proving that counter is not simply incremented on every ACKNACK.
    #[cfg(feature = "security")]
    #[test]
    fn a_plain_acknack_on_a_secure_writer_is_refused_and_never_counted() {
        use crate::core::discovery::multicast::control_types::AckNackInfo;
        use crate::protocol::discovery::SpdpData;
        use std::net::UdpSocket;

        const OURS: [u8; 12] = crate::security::test_pki::bound_test_prefix([0x72; 6]);
        const PEER_PREFIX: [u8; 12] = crate::security::test_pki::bound_test_prefix([0x73; 6]);
        const SEDP_PUB_SECURE_WRITER: [u8; 4] = [0xff, 0x00, 0x03, 0xc2];

        let history = Arc::new(RwLock::new(SedpHistory::new()));
        {
            let mut h = history.write().expect("history");
            h.announce(
                own_announcement(OURS, GUID::new(OURS, [0, 0, 0x12, 0x02])),
                SedpEndpointKind::Writer,
            );
        }

        let peer = UdpSocket::bind("127.0.0.1:0").expect("bind peer");
        peer.set_read_timeout(Some(Duration::from_millis(400)))
            .expect("read timeout");
        let peer_addr = peer.local_addr().expect("peer addr");

        let machine =
            crate::security::test_pki::local_machine_with_completed_peer(OURS, PEER_PREFIX, None);
        let mut fsm = DiscoveryFsm::new(GUID::new(OURS, [0, 0, 1, 0xC1]), 30_000);
        fsm.set_handshake_machine(
            machine,
            crate::security::test_pki::TEST_IDENTITY_CERT_PEM.to_vec(),
            crate::security::test_pki::TEST_IDENTITY_KEY_PEM.to_vec(),
        );
        use crate::security::access::{DiscoveryGovernance, DomainRule, ProtectionKind};
        fsm.set_discovery_governance(Some(DiscoveryGovernance::new(DomainRule {
            domains: vec![0],
            domain_ranges: vec![],
            allow_unauthenticated: false,
            enable_join_access_control: true,
            discovery_protection_kind: ProtectionKind::Encrypt,
            liveliness_protection_kind: ProtectionKind::None,
            rtps_protection_kind: ProtectionKind::None,
            topic_rules: vec![],
        })));
        fsm.handle_spdp(SpdpData {
            participant_guid: GUID::new(PEER_PREFIX, [0, 0, 1, 0xC1]),
            lease_duration_ms: 30_000,
            domain_id: 0,
            metatraffic_unicast_locators: vec![peer_addr],
            default_unicast_locators: vec![],
            default_multicast_locators: vec![],
            metatraffic_multicast_locators: vec![],
            identity_token: None,
            permissions_token: None,
            participant_security_info: None,
            vendor_id: None,
            hdds_capabilities: None,
            builtin_endpoint_set: None,
        });
        let fsm = Arc::new(fsm);

        let lease = crate::test_support::domains::unique_domain();
        let mapping =
            crate::transport::PortMapping::calculate(lease.id(), 2).expect("port mapping");
        let transport =
            Arc::new(UdpTransport::new(lease.id(), 2, mapping).expect("test transport"));
        let handler = ControlHandler::spawn_with_topic_registry(
            transport,
            OURS,
            7400,
            ReaderProxyRegistry::new(),
            ReaderProxyRegistry::new(),
            Arc::new(TopicRegistry::new()),
            fsm.clone(),
            history,
        );

        // was_protected() defaults to false: this IS the clear ACKNACK.
        let nack = ControlMessage::acknack(
            Origin::direct(peer_addr),
            PEER_PREFIX,
            AckNackInfo {
                reader_entity_id: derive_reader_entity_id(&SEDP_PUB_SECURE_WRITER),
                writer_entity_id: SEDP_PUB_SECURE_WRITER,
                missing_ranges: vec![std::ops::Range { start: 1, end: 2 }],
                bitmap_base: 1,
                count: None,
            },
            &[],
        )
        .expect("control message");
        assert!(handler.try_send(nack));

        let mut saw_anything = false;
        let mut buf = [0u8; 2048];
        while peer.recv(&mut buf).is_ok() {
            saw_anything = true;
        }
        handler.shutdown();

        assert!(
            !saw_anything,
            "a clear ACKNACK on a secure writer must get NO reply at all"
        );
        assert_eq!(
            fsm.metrics
                .protected_sedp_retransmissions
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
        assert_eq!(
            fsm.metrics
                .protected_sedp_data_retransmissions
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
    }

    /// Isolates the `if msg.was_protected()` guard around the
    /// `protected_sedp_retransmissions` increment (see the doc of the
    /// protected-ACKNACK test above): a CLEAR ACKNACK on a PLAIN (non-secure)
    /// writer is legitimate traffic, reaches `retransmit_sedp_data`'s
    /// success arm exactly as `a_nack_of_one_sedp_writer_gets_that_
    /// writers_history_alone` already proves, and must NOT move a counter
    /// that exists specifically to tell "a retransmission happened" apart
    /// from "a retransmission happened that a protected ACKNACK drove".
    ///
    /// The final assertion (0, not 1) pins the guard, which the positive
    /// test alone cannot.
    #[cfg(feature = "security")]
    #[test]
    fn a_clear_acknack_on_a_plain_writer_retransmits_without_counting_as_protected() {
        const OURS: [u8; 12] = crate::security::test_pki::bound_test_prefix([0x74; 6]);
        const PEER_PREFIX: [u8; 12] = crate::security::test_pki::bound_test_prefix([0x75; 6]);
        const SEDP_PUB_PLAIN_WRITER: [u8; 4] = [0x00, 0x00, 0x03, 0xC2];

        let history = Arc::new(RwLock::new(SedpHistory::new()));
        {
            let mut h = history.write().expect("history");
            h.announce(
                own_announcement(OURS, GUID::new(OURS, [0, 0, 0x12, 0x02])),
                SedpEndpointKind::Writer,
            );
        }

        let peer = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind peer");
        peer.set_read_timeout(Some(Duration::from_millis(400)))
            .expect("read timeout");
        let peer_addr = peer.local_addr().expect("peer addr");

        let fsm = Arc::new(DiscoveryFsm::new(GUID::new(OURS, [0, 0, 1, 0xC1]), 30_000));
        fsm.handle_spdp(crate::protocol::discovery::SpdpData {
            participant_guid: GUID::new(PEER_PREFIX, [0, 0, 1, 0xC1]),
            lease_duration_ms: 30_000,
            domain_id: 0,
            metatraffic_unicast_locators: vec![peer_addr],
            default_unicast_locators: vec![],
            default_multicast_locators: vec![],
            metatraffic_multicast_locators: vec![],
            identity_token: None,
            permissions_token: None,
            participant_security_info: None,
            vendor_id: None,
            hdds_capabilities: None,
            builtin_endpoint_set: None,
        });

        let lease = crate::test_support::domains::unique_domain();
        let mapping =
            crate::transport::PortMapping::calculate(lease.id(), 2).expect("port mapping");
        let transport =
            Arc::new(UdpTransport::new(lease.id(), 2, mapping).expect("test transport"));
        let handler = ControlHandler::spawn_with_topic_registry(
            transport,
            OURS,
            7400,
            ReaderProxyRegistry::new(),
            ReaderProxyRegistry::new(),
            Arc::new(TopicRegistry::new()),
            fsm.clone(),
            history,
        );

        let nack = ControlMessage::acknack(
            Origin::direct(peer_addr),
            PEER_PREFIX,
            crate::core::discovery::multicast::control_types::AckNackInfo {
                reader_entity_id: derive_reader_entity_id(&SEDP_PUB_PLAIN_WRITER),
                writer_entity_id: SEDP_PUB_PLAIN_WRITER,
                missing_ranges: vec![std::ops::Range { start: 1, end: 2 }],
                bitmap_base: 1,
                count: None,
            },
            &[],
        )
        .expect("control message");
        assert!(handler.try_send(nack));

        let mut saw_anything = false;
        let mut buf = [0u8; 2048];
        while peer.recv(&mut buf).is_ok() {
            saw_anything = true;
        }
        handler.shutdown();

        assert!(
            saw_anything,
            "fixture: a plain writer's clear ACKNACK must still be answered"
        );
        assert_eq!(
            fsm.metrics
                .protected_sedp_retransmissions
                .load(std::sync::atomic::Ordering::Relaxed),
            0,
            "a plain writer's retransmission must never be counted as protected-ACKNACK-driven"
        );
        assert_eq!(
            fsm.metrics
                .protected_sedp_data_retransmissions
                .load(std::sync::atomic::Ordering::Relaxed),
            0,
            "a plain writer's retransmission must never be counted as protected-ACKNACK-driven"
        );
    }

    /// A GAP from a remote SEDP writer is received like its DATA: the SEDP
    /// reader counts the range as delivered, so its ACKNACK stops asking for
    /// a number the writer retired (RTPS v2.5 Sec.8.3.8.4, Sec.8.5.4.4).
    #[test]
    fn a_sedp_gap_settles_the_numbers_it_retires() {
        use crate::core::discovery::multicast::control_types::GapInfo;

        const PEER_PREFIX: [u8; 12] = [0x62; 12];
        const SEDP_SUB_WRITER: [u8; 4] = [0x00, 0x00, 0x04, 0xC2];
        let writer = writer_guid_of(&PEER_PREFIX, &SEDP_SUB_WRITER);
        let sedp_registry = ReaderProxyRegistry::new();
        let _ = sedp_registry.on_heartbeat(writer, 1, 3, 1, true);
        sedp_registry.on_data(writer, 3);
        assert_eq!(sedp_registry.missing_holes(&writer, 3), vec![1, 2]);

        let lease = crate::test_support::domains::unique_domain();
        let mapping =
            crate::transport::PortMapping::calculate(lease.id(), 2).expect("port mapping");
        let transport =
            Arc::new(UdpTransport::new(lease.id(), 2, mapping).expect("test transport"));
        let handler = ControlHandler::spawn_with_topic_registry(
            transport,
            [0x63; 12],
            7400,
            sedp_registry.clone(),
            ReaderProxyRegistry::new(),
            Arc::new(TopicRegistry::new()),
            Arc::new(DiscoveryFsm::new(GUID::zero(), 30_000)),
            Arc::new(RwLock::new(SedpHistory::new())),
        );
        let gap = ControlMessage::gap(
            Origin::direct("127.0.0.1:9".parse().expect("address")),
            PEER_PREFIX,
            GapInfo {
                writer_entity_id: SEDP_SUB_WRITER,
                gap_start: 1,
                gap_list_base: 3,
                gap_list_seqs: vec![],
            },
            &[],
        )
        .expect("control message");
        assert!(handler.try_send(gap));
        let deadline = Instant::now() + Duration::from_secs(2);
        while !sedp_registry.missing_holes(&writer, 3).is_empty() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        handler.shutdown();
        assert!(
            sedp_registry.missing_holes(&writer, 3).is_empty(),
            "1 and 2 were retired by the GAP, 3 received"
        );
    }

    /// A GAP from a remote SEDP writer retires every number it names: the
    /// range gapStart..gapList.bitmapBase-1 and each number its bitmap sets
    /// (RTPS v2.5 Sec.8.3.8.4, Table 8.43). The GAP is the bytes a foreign
    /// writer puts on the wire (big-endian), read by the parser the
    /// listener uses. Crediting only the range is not enough: a number retired
    /// by the bitmap alone would be asked for again for as long as the writer
    /// lives.
    #[test]
    fn a_sedp_gap_retires_the_numbers_its_bitmap_sets() {
        use crate::core::discovery::multicast::control_parser::scan_all_embedded_control_submessages;

        const PEER_PREFIX: [u8; 12] = [0x66; 12];
        const SEDP_PUB_WRITER: [u8; 4] = [0x00, 0x00, 0x03, 0xC2];
        let writer = writer_guid_of(&PEER_PREFIX, &SEDP_PUB_WRITER);
        let sedp_registry = ReaderProxyRegistry::new();
        let _ = sedp_registry.on_heartbeat(writer, 1, 7, 1, true);
        for seq in [1, 2, 4] {
            sedp_registry.on_data(writer, seq);
        }
        assert_eq!(sedp_registry.missing_holes(&writer, 7), vec![3, 5, 6, 7]);

        // GAP, big-endian: gapStart 3, gapList.bitmapBase 5, numBits 3,
        // bits 0 and 2 set: 3..4 and {5, 7} retired, 6 not.
        let mut datagram = Vec::new();
        datagram.extend_from_slice(b"RTPS");
        datagram.extend_from_slice(&[2, 4, 0x01, 0x0f]);
        datagram.extend_from_slice(&PEER_PREFIX);
        datagram.extend_from_slice(&[0x08, 0x00, 0x00, 32]);
        datagram.extend_from_slice(&[0x00, 0x00, 0x03, 0xC7]);
        datagram.extend_from_slice(&SEDP_PUB_WRITER);
        for word in [0u32, 3, 0, 5, 3, 0xA000_0000] {
            datagram.extend_from_slice(&word.to_be_bytes());
        }
        let (gaps, _, _) = scan_all_embedded_control_submessages(&datagram);
        assert_eq!(gaps.len(), 1, "fixture: one GAP");
        let gap = gaps.into_iter().next().expect("one GAP").info;

        let lease = crate::test_support::domains::unique_domain();
        let mapping =
            crate::transport::PortMapping::calculate(lease.id(), 2).expect("port mapping");
        let transport =
            Arc::new(UdpTransport::new(lease.id(), 2, mapping).expect("test transport"));
        let handler = ControlHandler::spawn_with_topic_registry(
            transport,
            [0x67; 12],
            7400,
            sedp_registry.clone(),
            ReaderProxyRegistry::new(),
            Arc::new(TopicRegistry::new()),
            Arc::new(DiscoveryFsm::new(GUID::zero(), 30_000)),
            Arc::new(RwLock::new(SedpHistory::new())),
        );
        let message = ControlMessage::gap(
            Origin::direct("127.0.0.1:9".parse().expect("address")),
            PEER_PREFIX,
            gap,
            &datagram,
        )
        .expect("control message");
        assert!(handler.try_send(message));
        let deadline = Instant::now() + Duration::from_secs(2);
        while sedp_registry.missing_holes(&writer, 7) != vec![6] && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        handler.shutdown();
        assert_eq!(
            sedp_registry.missing_holes(&writer, 7),
            vec![6],
            "3..4 by the range, 5 and 7 by the bitmap; 6 is still asked for"
        );
    }

    /// A remote SEDP writer announces 1..=4 and we hold only 2: our ACKNACK
    /// asks for every change still missing, 1, 3 and 4, in one
    /// SequenceNumberSet (RTPS v2.5 Sec.8.4.12.2, Sec.8.3.8.1). Asking for the
    /// first hole alone left each further announcement waiting for one more
    /// HEARTBEAT period of the remote writer.
    #[test]
    fn a_sedp_acknack_requests_every_missing_change_up_to_last_sn() {
        use crate::core::discovery::multicast::control_types::HeartbeatInfo;
        use std::net::UdpSocket;

        const PEER_PREFIX: [u8; 12] = [0x6a; 12];
        const SEDP_SUB_WRITER: [u8; 4] = [0x00, 0x00, 0x04, 0xC2];
        let writer = writer_guid_of(&PEER_PREFIX, &SEDP_SUB_WRITER);
        let sedp_registry = ReaderProxyRegistry::new();
        let _ = sedp_registry.on_heartbeat(writer, 1, 4, 1, true);
        sedp_registry.on_data(writer, 2);

        let peer = UdpSocket::bind("127.0.0.1:0").expect("bind peer");
        peer.set_read_timeout(Some(Duration::from_millis(300)))
            .expect("read timeout");
        let peer_addr = peer.local_addr().expect("peer addr");
        let lease = crate::test_support::domains::unique_domain();
        let mapping =
            crate::transport::PortMapping::calculate(lease.id(), 2).expect("port mapping");
        let transport =
            Arc::new(UdpTransport::new(lease.id(), 2, mapping).expect("test transport"));
        let handler = ControlHandler::spawn_with_topic_registry(
            transport,
            [0x6b; 12],
            7400,
            sedp_registry.clone(),
            ReaderProxyRegistry::new(),
            Arc::new(TopicRegistry::new()),
            Arc::new(DiscoveryFsm::new(GUID::zero(), 30_000)),
            Arc::new(RwLock::new(SedpHistory::new())),
        );
        let hb = ControlMessage::heartbeat(
            Origin::direct(peer_addr),
            PEER_PREFIX,
            HeartbeatInfo {
                writer_entity_id: SEDP_SUB_WRITER,
                first_seq: 1,
                last_seq: 4,
                count: 2,
                final_flag: false,
                liveliness_flag: false,
            },
            &[],
        )
        .expect("control message");
        assert!(handler.try_send(hb));
        let mut buf = [0u8; 512];
        let mut got = None;
        let deadline = Instant::now() + Duration::from_secs(3);
        while got.is_none() && Instant::now() < deadline {
            if let Ok(len) = peer.recv(&mut buf) {
                got = Some(buf[..len].to_vec());
            }
        }
        handler.shutdown();
        let d = got.expect("our ACKNACK");

        // RTPS header, INFO_DST, then the ACKNACK (RTPS v2.5 Sec.9.4.5.3).
        assert_eq!(&d[24..36], &PEER_PREFIX, "INFO_DST");
        assert_eq!(d[36], 0x06, "ACKNACK");
        assert_eq!(d[37] & 0x01, 0x01, "little-endian");
        assert_eq!(d[37] & 0x02, 0, "Final clear: changes are missing");
        assert_eq!(&d[40..44], &[0x00, 0x00, 0x04, 0xC7], "readerEntityId");
        assert_eq!(&d[44..48], &SEDP_SUB_WRITER, "writerEntityId");
        let word = |at: usize| u32::from_le_bytes([d[at], d[at + 1], d[at + 2], d[at + 3]]);
        assert_eq!((word(48), word(52)), (0, 1), "bitmapBase 1");
        assert_eq!(word(56), 4, "numBits reaches lastSN");
        assert_eq!(word(60), 0xB000_0000, "1, 3 and 4 requested, 2 not");
    }

    /// The discovery worker ends once its participant has said its
    /// farewell, the control handler still running: it must not keep
    /// draining and purging, until the participant's fields drop, for a
    /// participant that is leaving.
    #[test]
    fn the_discovery_worker_ends_once_its_participant_has_departed() {
        use super::DiscoveryWorker;
        use crate::core::discovery::multicast::DiscoveryFsm;
        use crate::core::discovery::GUID;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;
        use std::time::{Duration, Instant};
        let fsm = Arc::new(DiscoveryFsm::new(GUID::zero(), 30_000));
        let running = Arc::new(AtomicBool::new(true));
        let mut worker = DiscoveryWorker::spawn(Arc::clone(&fsm), Arc::clone(&running));
        let handle = worker.handle.take().expect("the worker was spawned");
        fsm.depart();
        let deadline = Instant::now() + Duration::from_secs(1);
        while !handle.is_finished() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        let ended = handle.is_finished();
        assert!(
            running.load(Ordering::Relaxed),
            "fixture: the control handler still runs"
        );
        // Its channel closes here: the worker ends either way.
        drop(worker);
        assert!(ended, "the worker ended on its participant's departure");
        handle.join().expect("the worker did not panic");
    }

    /// A user listener that blocks inside a match released by control
    /// traffic (the late liveness mark of a peer confirmed past the
    /// probation boundary) must not stall the control loop: the replay runs
    /// on the discovery worker, and another peer's ACKNACK is handled while
    /// the listener is still blocked. A replay run inline on the control
    /// thread, ahead of the message itself, would make every HEARTBEAT and
    /// ACKNACK behind it wait (and, past the channel's capacity, be dropped).
    #[test]
    fn a_blocking_match_listener_does_not_stall_the_control_loop() {
        use crate::core::discovery::multicast::control_types::AckNackInfo;
        use crate::core::discovery::multicast::{DiscoveryListener, EndpointInfo};
        use crate::engine::NackHandler;
        use crate::protocol::discovery::{SedpData, SpdpData};
        use std::sync::mpsc;
        use std::sync::Mutex;

        struct Blocking {
            entered: Mutex<mpsc::Sender<()>>,
            release: Mutex<mpsc::Receiver<()>>,
        }
        impl DiscoveryListener for Blocking {
            fn on_endpoint_discovered(&self, _: EndpointInfo) {
                let _ = self
                    .entered
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .send(());
                let _ = self
                    .release
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .recv_timeout(Duration::from_secs(10));
            }
        }
        type Seen = Arc<Mutex<Vec<[u8; 16]>>>;
        struct Recorder(Seen);
        impl NackHandler for Recorder {
            fn on_nack(&self, _: &[u8], _: Option<[u8; 16]>) {}
            fn on_acknack(&self, reader_guid: [u8; 16], _: &AckNackInfo) {
                self.0
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push(reader_guid);
            }
        }
        const SLOW_PEER: [u8; 12] = [0x43; 12];
        const OTHER_PEER: [u8; 12] = [0x44; 12];
        let acknack_from = |prefix: [u8; 12]| {
            ControlMessage::acknack(
                Origin::direct("127.0.0.1:7410".parse().expect("addr")),
                prefix,
                AckNackInfo {
                    reader_entity_id: [0x00, 0x00, 0x01, 0x04],
                    writer_entity_id: [0x00, 0x00, 0x01, 0x03],
                    missing_ranges: Vec::new(),
                    bitmap_base: 1,
                    count: None,
                },
                &[],
            )
            .expect("control message")
        };

        let fsm = Arc::new(DiscoveryFsm::new(
            GUID::new([0x40; 12], [0, 0, 1, 0xC1]),
            30_000,
        ));
        let (entered_tx, entered) = mpsc::channel();
        let (release, release_rx) = mpsc::channel();
        fsm.register_listener(Arc::new(Blocking {
            entered: Mutex::new(entered_tx),
            release: Mutex::new(release_rx),
        }));
        let peer = GUID::new(SLOW_PEER, [0, 0, 1, 0xC1]);
        fsm.handle_spdp(SpdpData {
            participant_guid: peer,
            lease_duration_ms: 30_000,
            domain_id: 0,
            metatraffic_unicast_locators: vec![],
            default_unicast_locators: vec![],
            default_multicast_locators: vec![],
            metatraffic_multicast_locators: vec![],
            identity_token: None,
            permissions_token: None,
            participant_security_info: None,
            vendor_id: None,
            hdds_capabilities: None,
            builtin_endpoint_set: None,
        });
        std::thread::sleep(Duration::from_millis(110));
        fsm.handle_sedp(SedpData {
            topic_name: "BlockingListener".to_string(),
            type_name: "T".to_string(),
            participant_guid: peer,
            endpoint_guid: GUID::new(SLOW_PEER, [0x00, 0x00, 0x01, 0x02]),
            qos_hash: 1,
            qos: None,
            type_object: None,
            dependents: Vec::new(),
            type_object_legacy_v1: false,
            unicast_locators: vec![],
            user_data: None,
            shm_capability: None,
            has_explicit_reliability: false,
            has_explicit_ownership: false,
            has_ownership_strength: false,
            type_information: None,
            type_consistency: None,
            group_entity_id: None,
            endpoint_security_info: None,
        });
        let first_mark = Instant::now();

        let lease = crate::test_support::domains::unique_domain();
        let mapping =
            crate::transport::PortMapping::calculate(lease.id(), 2).expect("port mapping");
        let transport =
            Arc::new(UdpTransport::new(lease.id(), 2, mapping).expect("test transport"));
        let seen: Seen = Arc::new(Mutex::new(Vec::new()));
        let topics = Arc::new(TopicRegistry::new());
        topics.register_nack_handler(Arc::new(Recorder(Arc::clone(&seen))));
        let handler = ControlHandler::spawn_with_topic_registry(
            transport,
            [0x40; 12],
            7400,
            ReaderProxyRegistry::new(),
            ReaderProxyRegistry::new(),
            topics,
            Arc::clone(&fsm),
            Arc::new(RwLock::new(SedpHistory::new())),
        );
        let deadline = Instant::now() + Duration::from_secs(3);
        while !fsm.is_probation_done() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(fsm.is_probation_done(), "the boundary fired on the clock");
        let mark_due = first_mark + Duration::from_millis(110);
        if let Some(left) = mark_due.checked_duration_since(Instant::now()) {
            std::thread::sleep(left);
        }

        // Its ACKNACK is its second mark: the match is released and the
        // listener blocks in it.
        assert!(handler.try_send(acknack_from(SLOW_PEER)));
        entered
            .recv_timeout(Duration::from_secs(3))
            .expect("the late match reached the listener");

        assert!(handler.try_send(acknack_from(OTHER_PEER)));
        let deadline = Instant::now() + Duration::from_secs(2);
        let handled = || {
            seen.lock()
                .unwrap_or_else(|e| e.into_inner())
                .iter()
                .any(|reader| reader[..12] == OTHER_PEER)
        };
        while !handled() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        let other_handled = handled();
        let _ = release.send(());
        handler.shutdown();
        assert!(
            other_handled,
            "another peer's ACKNACK was handled while the listener blocked"
        );
    }

    /// A user listener that panics inside a match the discovery worker
    /// surfaces does not end the worker: the probation ticks it runs keep
    /// their clock, and a participant heard during the probation that falls
    /// silent before its matches may surface is still purged a second after
    /// it was last heard. A panic that ended the worker would end with it
    /// every later boundary, verdict and silence purge.
    #[test]
    fn a_panicking_match_listener_does_not_stop_the_probation_clock() {
        use crate::core::discovery::multicast::control_types::AckNackInfo;
        use crate::core::discovery::multicast::{DiscoveryListener, EndpointInfo};
        use crate::protocol::discovery::{SedpData, SpdpData};

        struct Panicking;
        impl DiscoveryListener for Panicking {
            fn on_endpoint_discovered(&self, _: EndpointInfo) {
                panic!("a user listener panics (expected by this test)");
            }
        }
        const LOUD_PEER: [u8; 12] = [0x45; 12];
        const SILENT_PEER: [u8; 12] = [0x46; 12];
        let spdp = |prefix: [u8; 12]| SpdpData {
            participant_guid: GUID::new(prefix, [0, 0, 1, 0xC1]),
            lease_duration_ms: 30_000,
            domain_id: 0,
            metatraffic_unicast_locators: vec![],
            default_unicast_locators: vec![],
            default_multicast_locators: vec![],
            metatraffic_multicast_locators: vec![],
            identity_token: None,
            permissions_token: None,
            participant_security_info: None,
            vendor_id: None,
            hdds_capabilities: None,
            builtin_endpoint_set: None,
        };
        let sedp = |prefix: [u8; 12]| SedpData {
            topic_name: "PanickingListener".to_string(),
            type_name: "T".to_string(),
            participant_guid: GUID::new(prefix, [0, 0, 1, 0xC1]),
            endpoint_guid: GUID::new(prefix, [0x00, 0x00, 0x01, 0x02]),
            qos_hash: 1,
            qos: None,
            type_object: None,
            dependents: Vec::new(),
            type_object_legacy_v1: false,
            unicast_locators: vec![],
            user_data: None,
            shm_capability: None,
            has_explicit_reliability: false,
            has_explicit_ownership: false,
            has_ownership_strength: false,
            type_information: None,
            type_consistency: None,
            group_entity_id: None,
            endpoint_security_info: None,
        };

        let fsm = Arc::new(DiscoveryFsm::new(
            GUID::new([0x40; 12], [0, 0, 1, 0xC1]),
            30_000,
        ));
        fsm.register_listener(Arc::new(Panicking));
        for prefix in [LOUD_PEER, SILENT_PEER] {
            fsm.handle_spdp(spdp(prefix));
        }
        std::thread::sleep(Duration::from_millis(110));
        for prefix in [LOUD_PEER, SILENT_PEER] {
            fsm.handle_sedp(sedp(prefix));
        }
        let first_marks = Instant::now();
        assert!(
            fsm.uptime() < Duration::from_millis(250),
            "fixture: both marks land before the boundary"
        );

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
            Arc::clone(&fsm),
            Arc::new(RwLock::new(SedpHistory::new())),
        );
        let deadline = Instant::now() + Duration::from_secs(3);
        while !fsm.is_probation_done() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(fsm.is_probation_done(), "the boundary fired on the clock");

        // The loud peer's ACKNACK, a mark after the boundary: its match is
        // released on the worker, and the listener panics there.
        let mark_due = first_marks + Duration::from_millis(110);
        if let Some(left) = mark_due.checked_duration_since(Instant::now()) {
            std::thread::sleep(left);
        }
        let acknack = ControlMessage::acknack(
            Origin::direct("127.0.0.1:7410".parse().expect("addr")),
            LOUD_PEER,
            AckNackInfo {
                reader_entity_id: [0x00, 0x00, 0x01, 0x04],
                writer_entity_id: [0x00, 0x00, 0x01, 0x03],
                missing_ranges: Vec::new(),
                bitmap_base: 1,
                count: None,
            },
            &[],
        )
        .expect("control message");
        assert!(handler.try_send(acknack));

        // The silent peer's silence rule, a second after its SEDP, is a tick
        // of the same worker.
        let silent = GUID::new(SILENT_PEER, [0, 0, 1, 0xC1]);
        let deadline = first_marks + Duration::from_millis(2_500);
        while fsm.has_participant(&silent) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        let purged = !fsm.has_participant(&silent);
        handler.shutdown();
        assert!(
            purged,
            "the silent peer was purged on time: the worker survived the panic"
        );
    }

    /// A SEDP repair to a participant that authenticated with us goes where
    /// the original went: on the secure SEDP topic. A repair in the clear of
    /// an endpoint it knows would be ignored there as anybody's, and the
    /// dispose of a deleted one with it.
    #[cfg(feature = "security")]
    #[test]
    fn a_sedp_repair_to_an_authenticated_participant_is_sealed() {
        use crate::core::rtps_constants::RTPS_ENTITYID_PARTICIPANT;
        use crate::security::test_pki::{
            local_machine_with_completed_peer, TEST_IDENTITY_CERT_PEM, TEST_IDENTITY_KEY_PEM,
        };
        use std::net::UdpSocket;

        const OURS: [u8; 12] = crate::security::test_pki::bound_test_prefix([0x71; 6]);
        const PEER: [u8; 12] = crate::security::test_pki::bound_test_prefix([0x21; 6]);
        let mut fsm = DiscoveryFsm::new(GUID::new(OURS, RTPS_ENTITYID_PARTICIPANT), 30_000);
        fsm.set_handshake_machine(
            local_machine_with_completed_peer(OURS, PEER, None),
            TEST_IDENTITY_CERT_PEM.to_vec(),
            TEST_IDENTITY_KEY_PEM.to_vec(),
        );
        fsm.register_builtin_writer_keys_for_tests();
        let mut history = SedpHistory::new();
        history.announce(
            own_announcement(OURS, GUID::new(OURS, [0x00, 0x00, 0x01, 0x02])),
            SedpEndpointKind::Writer,
        );
        let history = Arc::new(RwLock::new(history));
        let lease = crate::test_support::domains::unique_domain();
        let mapping =
            crate::transport::PortMapping::calculate(lease.id(), 2).expect("port mapping");
        let transport = UdpTransport::new(lease.id(), 2, mapping).expect("test transport");
        let peer = UdpSocket::bind("127.0.0.1:0").expect("bind peer");
        peer.set_read_timeout(Some(Duration::from_millis(500)))
            .expect("read timeout");
        let peer_addr = peer.local_addr().expect("peer addr");
        // Both are participants discovery knows: an unknown one is not
        // repaired at all.
        for prefix in [PEER, [0x22; 12]] {
            fsm.handle_spdp(crate::protocol::discovery::SpdpData {
                participant_guid: GUID::new(prefix, RTPS_ENTITYID_PARTICIPANT),
                lease_duration_ms: 30_000,
                domain_id: 0,
                metatraffic_unicast_locators: vec![peer_addr],
                default_unicast_locators: vec![],
                default_multicast_locators: vec![],
                metatraffic_multicast_locators: vec![],
                identity_token: None,
                permissions_token: None,
                participant_security_info: None,
                vendor_id: None,
                hdds_capabilities: None,
                builtin_endpoint_set: None,
            });
        }

        let repaired = |to: [u8; 12]| {
            ControlHandler::retransmit_sedp_data(
                &transport,
                OURS,
                &to,
                &[0x00, 0x00, 0x03, 0xC2],
                peer_addr.port(),
                peer_addr.ip(),
                &history,
                &ControlMetrics::new(),
                &fsm,
            )
            .expect("sent");
            let mut buf = [0u8; 2048];
            let n = peer.recv(&mut buf).expect("the repair");
            buf[..n].to_vec()
        };
        let sealed = repaired(PEER);
        assert!(
            crate::security::crypto::secure_sedp::find_data_cdr_bounds(&sealed).is_none()
                && crate::security::crypto::secure_submessage::first_secure_prefix(&sealed)
                    .is_some(),
            "sealed: protected on the secure SEDP topic, no DATA in clear"
        );
        let clear = repaired([0x22; 12]);
        let (eid_at, _) =
            crate::security::crypto::secure_sedp::find_data_cdr_bounds(&clear).expect("a DATA");
        assert_eq!(
            clear[eid_at], 0x00,
            "in the clear to a participant that has not authenticated"
        );
    }

    /// An ACKNACK addressed to a TypeLookup writer is answered by that
    /// writer: GAP for the number it never sent this peer, repair for the
    /// one it did, at the locator the peer announced, whatever address the
    /// ACKNACK came from. A prefix discovery does not know gets nothing, and
    /// a HEARTBEAT from the peer's reply writer gets our reply reader's
    /// ACKNACK naming what it misses.
    #[test]
    fn an_acknack_to_a_type_lookup_writer_is_answered_by_that_writer() {
        use super::super::control_types::{AckNackInfo, HeartbeatInfo};
        use crate::core::discovery::multicast::control_parser::parse_all_acknack_submessages;
        use crate::core::rtps_constants::{
            RTPS_ENTITYID_TYPELOOKUP_REPLY_READER, RTPS_ENTITYID_TYPELOOKUP_REPLY_WRITER,
        };
        use std::net::UdpSocket;

        const PEER: [u8; 12] = [0x41; 12];
        let writers = Arc::new(TypeLookupWriters::new());
        // 1 to PEER, 2 to some other participant, 3 to PEER: PEER lost 1 and 3.
        let to_peer = |tag: &'static [u8]| {
            move |sn: u64, gap: &[u8]| {
                let mut d = tag.to_vec();
                d.extend_from_slice(&sn.to_le_bytes());
                d.extend_from_slice(gap);
                Some(d)
            }
        };
        let (_, one) = writers.reply.write_to(PEER, to_peer(b"ONE")).expect("1");
        writers
            .reply
            .write_to([0x42; 12], to_peer(b"OTHER"))
            .expect("2");
        let (_, three) = writers.reply.write_to(PEER, to_peer(b"THREE")).expect("3");

        let peer = UdpSocket::bind("127.0.0.1:0").expect("bind peer");
        peer.set_read_timeout(Some(Duration::from_millis(300)))
            .expect("read timeout");
        let peer_addr = peer.local_addr().expect("peer addr");
        let spoofed = UdpSocket::bind("127.0.0.1:0").expect("bind other");
        spoofed
            .set_read_timeout(Some(Duration::from_millis(300)))
            .expect("read timeout");
        let spoofed_addr = spoofed.local_addr().expect("other addr");

        let fsm = Arc::new(DiscoveryFsm::new(GUID::zero(), 30_000));

        let lease = crate::test_support::domains::unique_domain();
        let mapping =
            crate::transport::PortMapping::calculate(lease.id(), 3).expect("port mapping");
        let transport =
            Arc::new(UdpTransport::new(lease.id(), 3, mapping).expect("test transport"));
        let handler = ControlHandler::spawn_with_type_lookup_writers(
            transport,
            [0x40; 12],
            7400,
            ReaderProxyRegistry::new(),
            ReaderProxyRegistry::new(),
            Arc::new(TopicRegistry::new()),
            Arc::clone(&fsm),
            Arc::new(RwLock::new(SedpHistory::new())),
            Some(Arc::clone(&writers)),
        );
        // Discovered after our probation: a peer heard during it and never
        // confirmed is purged when it ends.
        std::thread::sleep(Duration::from_millis(400));
        fsm.handle_spdp(crate::protocol::discovery::SpdpData {
            participant_guid: GUID::new(PEER, [0x00, 0x00, 0x01, 0xC1]),
            lease_duration_ms: 30_000,
            domain_id: 0,
            metatraffic_unicast_locators: vec![peer_addr],
            default_unicast_locators: vec![],
            default_multicast_locators: vec![],
            metatraffic_multicast_locators: vec![],
            identity_token: None,
            permissions_token: None,
            participant_security_info: None,
            vendor_id: None,
            hdds_capabilities: None,
            builtin_endpoint_set: None,
        });
        let acknack = |prefix: [u8; 12]| {
            ControlMessage::acknack(
                Origin::direct(spoofed_addr),
                prefix,
                AckNackInfo {
                    reader_entity_id: RTPS_ENTITYID_TYPELOOKUP_REPLY_READER,
                    writer_entity_id: RTPS_ENTITYID_TYPELOOKUP_REPLY_WRITER,
                    missing_ranges: vec![std::ops::Range { start: 1, end: 4 }],
                    bitmap_base: 1,
                    count: Some(1),
                },
                &[],
            )
            .expect("control message")
        };
        // Unknown to discovery, though written to: no answer anywhere.
        assert!(handler.try_send(acknack([0x42; 12])));
        assert!(handler.try_send(acknack(PEER)));

        let mut got = Vec::new();
        let mut buf = [0u8; 512];
        let deadline = Instant::now() + Duration::from_secs(3);
        while got.len() < 3 && Instant::now() < deadline {
            if let Ok(len) = peer.recv(&mut buf) {
                got.push(buf[..len].to_vec());
            }
        }
        assert!(
            spoofed.recv(&mut buf).is_err(),
            "nothing goes to the address an ACKNACK came from"
        );

        assert_eq!(got.len(), 3, "a GAP datagram and two repairs");
        let gap = &got[0];
        assert_eq!(&gap[..4], b"RTPS");
        assert_eq!(&gap[24..36], &PEER, "INFO_DST");
        assert_eq!(gap[36], 0x08, "GAP after the INFO_DST");
        assert_eq!(&gap[40..44], &RTPS_ENTITYID_TYPELOOKUP_REPLY_READER);
        assert_eq!(&gap[44..48], &RTPS_ENTITYID_TYPELOOKUP_REPLY_WRITER);
        assert_eq!(&gap[48..56], &[0, 0, 0, 0, 2, 0, 0, 0], "gapStart 2");
        assert_eq!(&gap[56..64], &[0, 0, 0, 0, 3, 0, 0, 0], "gapList.base 3");
        assert_eq!(gap[68], 0x07, "then a HEARTBEAT");
        assert_eq!(got[1], one, "1, resent as it was sent");
        assert_eq!(got[2], three, "3, resent as it was sent");

        // The peer's reply writer announces 1..=2; our reply reader got 2.
        writers
            .received
            .on_data(PEER, RTPS_ENTITYID_TYPELOOKUP_REPLY_WRITER, 2);
        let hb = ControlMessage::heartbeat(
            Origin::direct(spoofed_addr),
            PEER,
            HeartbeatInfo {
                writer_entity_id: RTPS_ENTITYID_TYPELOOKUP_REPLY_WRITER,
                first_seq: 1,
                last_seq: 2,
                count: 1,
                final_flag: false,
                liveliness_flag: false,
            },
            &[],
        )
        .expect("control message");
        assert!(handler.try_send(hb));
        let len = peer.recv(&mut buf).expect("our ACKNACK");

        // RTPS 2.5 8.3.8.9 / 8.4.8.2.6: behind an INFO_REPLY naming another
        // address, both answers still go to the locator the peer announced
        // (the TypeLookup endpoints are stateful), never to the named one.
        let named = UdpSocket::bind("127.0.0.1:0").expect("bind named");
        named
            .set_read_timeout(Some(Duration::from_millis(500)))
            .expect("read timeout");
        let std::net::SocketAddr::V4(named_addr) = named.local_addr().expect("named addr") else {
            panic!("bound on IPv4");
        };
        let replying = Origin::direct(spoofed_addr).replying_to(Some(named_addr));
        let again = ControlMessage::acknack(
            replying,
            PEER,
            AckNackInfo {
                reader_entity_id: RTPS_ENTITYID_TYPELOOKUP_REPLY_READER,
                writer_entity_id: RTPS_ENTITYID_TYPELOOKUP_REPLY_WRITER,
                missing_ranges: vec![std::ops::Range { start: 3, end: 4 }],
                bitmap_base: 3,
                count: Some(2),
            },
            &[],
        )
        .expect("control message");
        assert!(handler.try_send(again));
        let hb_again = ControlMessage::heartbeat(
            replying,
            PEER,
            HeartbeatInfo {
                writer_entity_id: RTPS_ENTITYID_TYPELOOKUP_REPLY_WRITER,
                first_seq: 1,
                last_seq: 2,
                count: 2,
                final_flag: false,
                liveliness_flag: false,
            },
            &[],
        )
        .expect("control message");
        assert!(handler.try_send(hb_again));
        let mut again_buf = [0u8; 512];
        let mut at_peer = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(3);
        while at_peer.len() < 3 && Instant::now() < deadline {
            if let Ok(n) = peer.recv(&mut again_buf) {
                at_peer.push(again_buf[..n].to_vec());
            }
        }
        assert!(
            at_peer.iter().any(|datagram| datagram == &three),
            "3, resent at the announced locator"
        );
        assert!(
            at_peer
                .iter()
                .any(|datagram| !parse_all_acknack_submessages(datagram).is_empty()),
            "our ACKNACK, at the announced locator"
        );
        assert!(
            named.recv(&mut again_buf).is_err(),
            "nothing at the INFO_REPLY locator"
        );
        handler.shutdown();
        let acknacks = parse_all_acknack_submessages(&buf[..len]);
        assert_eq!(acknacks.len(), 1);
        assert_eq!(
            acknacks[0].reader_entity_id,
            RTPS_ENTITYID_TYPELOOKUP_REPLY_READER
        );
        assert_eq!(
            acknacks[0].writer_entity_id,
            RTPS_ENTITYID_TYPELOOKUP_REPLY_WRITER
        );
        assert_eq!(acknacks[0].bitmap_base, 1);
        assert_eq!(
            acknacks[0].missing_ranges,
            vec![std::ops::Range { start: 1, end: 2 }],
            "1 is missing, 2 was received"
        );
    }

    /// RTPS v2.5 Sec.8.4.13.3: an ACKNACK naming our
    /// BuiltinParticipantMessageWriter (0x000200c2) must not fall through to
    /// the generic `topic_registry.deliver_acknack` branch, which does not
    /// know this writer (it keeps no HistoryCache there) and would answer
    /// nothing -- a peer that lost our assertion would never get it repaired.
    /// `AssertionWriter::answer_acknack`'s own tests pin the GAP-then-resend
    /// byte layout; this test pins the WIRING: the branch is reached, the
    /// peer's announced locator is used, and the resend carries the
    /// writer's real current sequence number.
    #[test]
    fn a_participant_message_writer_acknack_is_answered() {
        use crate::core::discovery::multicast::control_types::AckNackInfo;
        use crate::core::rtps_constants::{
            RTPS_ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_READER,
            RTPS_ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_WRITER,
        };
        use crate::dds::liveliness::AssertionWriter;
        use crate::protocol::builder::extract_sequence_number;
        use crate::protocol::rtps::participant_message::BUILTIN_PARTICIPANT_MESSAGE_READER;
        use std::net::UdpSocket;

        const OURS: [u8; 12] = [0x50; 12];
        const PEER: [u8; 12] = [0x51; 12];

        let peer = UdpSocket::bind("127.0.0.1:0").expect("bind peer");
        peer.set_read_timeout(Some(Duration::from_millis(500)))
            .expect("read timeout");
        let peer_addr = peer.local_addr().expect("peer addr");

        let fsm = Arc::new(DiscoveryFsm::new(GUID::new(OURS, [0, 0, 1, 0xC1]), 30_000));
        fsm.handle_spdp(crate::protocol::discovery::SpdpData {
            participant_guid: GUID::new(PEER, [0, 0, 1, 0xC1]),
            lease_duration_ms: 30_000,
            domain_id: 0,
            metatraffic_unicast_locators: vec![peer_addr],
            default_unicast_locators: vec![],
            default_multicast_locators: vec![],
            metatraffic_multicast_locators: vec![],
            identity_token: None,
            permissions_token: None,
            participant_security_info: None,
            vendor_id: None,
            hdds_capabilities: None,
            // Bit 11: the peer announces the participant-message reader,
            // so `AssertionWriter::assert_to_peers` below sends to it.
            builtin_endpoint_set: Some(BUILTIN_PARTICIPANT_MESSAGE_READER),
        });

        let lease = crate::test_support::domains::unique_domain();
        let mapping = crate::transport::PortMapping::calculate(lease.id(), 4).expect("mapping");
        let transport = Arc::new(UdpTransport::new(lease.id(), 4, mapping).expect("transport"));

        // Give our writer a real current sample (sn=1) before the peer
        // ACKNACKs: this is what `answer_acknack` must resend.
        let writer = AssertionWriter::register(OURS);
        writer.assert_to_peers(&fsm, &transport);
        let _assertion = peer.recv(&mut [0u8; 512]).expect("the assertion itself");

        let handler = ControlHandler::spawn(transport, OURS, 7410, Arc::clone(&fsm));

        let acknack = ControlMessage::acknack(
            Origin::direct(peer_addr),
            PEER,
            AckNackInfo {
                reader_entity_id: RTPS_ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_READER,
                writer_entity_id: RTPS_ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_WRITER,
                missing_ranges: vec![],
                bitmap_base: 1,
                count: Some(1),
            },
            &[],
        )
        .expect("control message");
        assert!(handler.try_send(acknack));

        let mut buf = [0u8; 512];
        let len = peer.recv(&mut buf).expect("the resend");
        assert_eq!(
            extract_sequence_number(&buf[..len]),
            Some(1),
            "the writer's current sample, resent"
        );
        // Receiving the datagram does not order the sender's subsequent
        // metric update. Join the control thread before reading its counters.
        let metrics = Arc::clone(&handler.metrics);
        handler.shutdown();
        assert_eq!(
            metrics.acknacks_sent.load(Ordering::Relaxed),
            1,
            "the resend counts as an ACKNACK answer"
        );
    }

    /// RTPS v2.5 Sec.8.4.13.3: a HEARTBEAT from a peer's
    /// BuiltinParticipantMessageWriter must not fall into the generic
    /// final-HEARTBEAT path, which answers through the user-data
    /// `ReaderProxyRegistry` -- a registry this builtin endpoint never
    /// registers a proxy in, so nothing would be sent. This pins the
    /// WIRING in the live run_loop (not the pure helper, already pinned in
    /// `protocol::rtps::participant_message`'s own tests): the ACKNACK
    /// goes out with the right reader/writer ids and asks for the newest
    /// sequence number alone.
    #[test]
    fn a_participant_message_writer_heartbeat_is_acknacked() {
        use crate::core::discovery::multicast::control_parser::parse_all_acknack_submessages;
        use crate::core::rtps_constants::{
            RTPS_ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_READER,
            RTPS_ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_WRITER,
        };
        use crate::protocol::rtps::participant_message::BUILTIN_PARTICIPANT_MESSAGE_READER;
        use std::net::UdpSocket;

        const OURS: [u8; 12] = [0x52; 12];
        const PEER: [u8; 12] = [0x53; 12];

        let peer = UdpSocket::bind("127.0.0.1:0").expect("bind peer");
        peer.set_read_timeout(Some(Duration::from_millis(500)))
            .expect("read timeout");
        let peer_addr = peer.local_addr().expect("peer addr");

        let fsm = Arc::new(DiscoveryFsm::new(GUID::new(OURS, [0, 0, 1, 0xC1]), 30_000));
        fsm.handle_spdp(crate::protocol::discovery::SpdpData {
            participant_guid: GUID::new(PEER, [0, 0, 1, 0xC1]),
            lease_duration_ms: 30_000,
            domain_id: 0,
            metatraffic_unicast_locators: vec![peer_addr],
            default_unicast_locators: vec![],
            default_multicast_locators: vec![],
            metatraffic_multicast_locators: vec![],
            identity_token: None,
            permissions_token: None,
            participant_security_info: None,
            vendor_id: None,
            hdds_capabilities: None,
            builtin_endpoint_set: Some(BUILTIN_PARTICIPANT_MESSAGE_READER),
        });

        let lease = crate::test_support::domains::unique_domain();
        let mapping = crate::transport::PortMapping::calculate(lease.id(), 5).expect("mapping");
        let transport = Arc::new(UdpTransport::new(lease.id(), 5, mapping).expect("transport"));
        let handler = ControlHandler::spawn(transport, OURS, 7410, Arc::clone(&fsm));

        let hb = ControlMessage::heartbeat(
            Origin::direct(peer_addr),
            PEER,
            HeartbeatInfo {
                writer_entity_id: RTPS_ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_WRITER,
                first_seq: 1,
                last_seq: 9,
                count: 3,
                final_flag: true,
                liveliness_flag: false,
            },
            &[],
        )
        .expect("control message");
        assert!(handler.try_send(hb));

        let mut buf = [0u8; 512];
        let len = peer.recv(&mut buf).expect("the ACKNACK");
        let acknacks = parse_all_acknack_submessages(&buf[..len]);
        assert_eq!(acknacks.len(), 1);
        assert_eq!(
            acknacks[0].reader_entity_id,
            RTPS_ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_READER
        );
        assert_eq!(
            acknacks[0].writer_entity_id,
            RTPS_ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_WRITER
        );
        assert_eq!(acknacks[0].bitmap_base, 9, "the newest alone, never 1..9");
        assert_eq!(
            acknacks[0].missing_ranges,
            vec![std::ops::Range { start: 9, end: 10 }]
        );
        handler.shutdown();
    }
}

#[cfg(test)]
mod sedp_solicitation_tests {
    use super::*;
    use std::collections::HashMap;

    const PUB: [u8; 4] = crate::core::rtps_constants::RTPS_ENTITYID_SEDP_PUBLICATIONS_WRITER;
    const SUB: [u8; 4] = crate::core::rtps_constants::RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_WRITER;

    fn peers(of: &[([u8; 12], Instant)]) -> HashMap<[u8; 12], Instant> {
        of.iter().copied().collect()
    }

    /// Unanswered, a peer is asked again after each backoff, then no more
    /// after `SEDP_SOLICIT_ATTEMPTS`: the request can be lost, or dropped by
    /// a peer that does not know us yet, and the retries are bounded.
    #[test]
    fn an_unanswered_peer_is_asked_again_with_backoff_then_left() {
        let t0 = Instant::now();
        let p = [1u8; 12];
        let known = peers(&[(p, t0)]);
        let mut s = SedpSolicitations::default();
        assert_eq!(s.due(&known, t0), vec![(p, vec![PUB, SUB])], "at discovery");
        assert!(
            s.due(&known, t0 + Duration::from_millis(100)).is_empty(),
            "not before the backoff"
        );
        let mut at = t0;
        let mut asked = 1;
        for step in 0..20u32 {
            at += SEDP_SOLICIT_FIRST_BACKOFF * (1 << step.min(10));
            asked += s.due(&known, at).len();
        }
        assert_eq!(asked, SEDP_SOLICIT_ATTEMPTS as usize, "bounded");
    }

    /// A HEARTBEAT from one SEDP writer stops asking for it; from both, the
    /// peer is not asked again.
    #[test]
    fn a_heard_writer_is_not_asked_again() {
        let t0 = Instant::now();
        let p = [2u8; 12];
        let known = peers(&[(p, t0)]);
        let mut s = SedpSolicitations::default();
        s.due(&known, t0);
        s.heard(&p, &PUB);
        let later = t0 + Duration::from_secs(1);
        assert_eq!(s.due(&known, later), vec![(p, vec![SUB])]);
        s.heard(&p, &SUB);
        assert!(s.due(&known, later + Duration::from_secs(5)).is_empty());
        s.heard(&p, &[0, 0, 0x01, 0x02]);
    }

    /// A new discovery of the same peer (a new `created_at`) is asked again
    /// from the start; a peer gone is forgotten.
    #[test]
    fn a_new_discovery_starts_over_and_a_gone_peer_is_forgotten() {
        let t0 = Instant::now();
        let p = [3u8; 12];
        let mut s = SedpSolicitations::default();
        s.due(&peers(&[(p, t0)]), t0);
        s.heard(&p, &PUB);
        s.heard(&p, &SUB);
        let t1 = t0 + Duration::from_secs(9);
        assert_eq!(s.due(&peers(&[(p, t1)]), t1), vec![(p, vec![PUB, SUB])]);
        assert!(s.due(&peers(&[]), t1).is_empty());
        assert!(s.peers.is_empty(), "forgotten");
    }
}
