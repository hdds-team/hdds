// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! RTPS packet routing engine
//!
//! Routes incoming RTPS packets (DATA, Heartbeat, AckNack) from the multicast ring
//! to registered topic subscribers. Provides background thread orchestration and
//! telemetry for packet processing.

use crate::core::discovery::multicast::{FragmentMetadata, PacketKind, RxMeta, RxPool};
use crate::core::discovery::{FragmentBuffer, GUID};
use crate::engine::demux::TopicRegistry;
use crate::engine::wake::WakeNotifier;
use crate::protocol::builder;
use crate::protocol::discovery::parse_topic_name;
use crossbeam::queue::ArrayQueue;
use std::io;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::thread::JoinHandle;
use std::time::Duration;

/// Default configuration for user DATA_FRAG fragment buffer
const USER_FRAG_MAX_PENDING: usize = 256;
const USER_FRAG_TIMEOUT_MS: u64 = 1000;

// ============================================================================
// Metrics
// ============================================================================

/// Latency-friendly counters updated by the demux router to track packet handling outcomes.
///
/// All fields use relaxed atomics which is sufficient because consumers only need
/// monotonic snapshots for observability.
#[derive(Debug)]
pub struct RouterMetrics {
    pub packets_routed: AtomicU64,
    pub packets_orphaned: AtomicU64,
    pub delivery_errors: AtomicU64,
    pub bytes_delivered: AtomicU64,
    /// Number of NACK_FRAG requests generated (fragments missing after timeout)
    pub nack_frag_requests: AtomicU64,
    /// Number of fragment sequences that timed out completely
    pub fragment_timeouts: AtomicU64,
    /// v241: Packets skipped due to deduplication (same writer_guid+seq seen before)
    pub packets_deduplicated: AtomicU64,
}

impl RouterMetrics {
    /// Create a zeroed metrics struct ready for concurrent updates.
    #[inline]
    pub fn new() -> Self {
        Self {
            packets_routed: AtomicU64::new(0),
            packets_orphaned: AtomicU64::new(0),
            delivery_errors: AtomicU64::new(0),
            bytes_delivered: AtomicU64::new(0),
            nack_frag_requests: AtomicU64::new(0),
            fragment_timeouts: AtomicU64::new(0),
            packets_deduplicated: AtomicU64::new(0),
        }
    }

    /// Return the current metrics counters without synchronisation penalties.
    #[inline]
    #[must_use]
    pub fn snapshot(&self) -> (u64, u64, u64, u64, u64, u64, u64) {
        (
            self.packets_routed.load(Ordering::Relaxed),
            self.packets_orphaned.load(Ordering::Relaxed),
            self.delivery_errors.load(Ordering::Relaxed),
            self.bytes_delivered.load(Ordering::Relaxed),
            self.nack_frag_requests.load(Ordering::Relaxed),
            self.fragment_timeouts.load(Ordering::Relaxed),
            self.packets_deduplicated.load(Ordering::Relaxed),
        )
    }
}

impl Default for RouterMetrics {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Route Status
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Outcome of routing a single RTPS data packet through the demux registry.
pub enum RouteStatus {
    Delivered,
    Orphaned,
    Dropped,
}

// ============================================================================
// Routing Logic (HOT PATH)
// ============================================================================

/// Route an RTPS data packet to the matching topic subscribers, updating metrics.
///
/// Returns [`RouteStatus::Delivered`] on success, or an error variant when the packet
/// could not be associated with a known topic.
///
/// # RTI Interop Fix (P0-6)
///
/// RTI/Cyclone/FastDDS often send DATA packets WITHOUT inline QoS (flag=0) to save bandwidth.
/// We fall back to GUID-based routing using the writer GUID announced via SEDP discovery.
///
/// # Performance
/// This is a HOT PATH function called for every incoming DATA packet.
/// All operations are optimized for minimal latency.
#[inline]
pub fn route_data_packet(
    payload: &[u8],
    packet_len: usize,
    payload_offset: Option<usize>,
    registry: &TopicRegistry,
    metrics: &RouterMetrics,
) -> RouteStatus {
    // Try inline QoS first (HDDS<->HDDS compat)
    let topic_name = match builder::extract_inline_qos(payload) {
        Some(qos) => parse_topic_name(qos),
        None => None,
    };

    // Fallback to GUID-based routing if no inline QoS (RTI/Cyclone/FastDDS)
    let topic_name = match topic_name {
        Some(name) => name,
        None => {
            // Extract writer GUID from RTPS header + DATA submessage
            let guid = match builder::extract_writer_guid(payload) {
                Some(g) => g,
                None => {
                    log::debug!("[ROUTER] DROP: Cannot extract writer GUID from DATA packet");
                    metrics.delivery_errors.fetch_add(1, Ordering::Relaxed);
                    return RouteStatus::Dropped;
                }
            };

            // Lookup topic name via GUID mapping (populated by SEDP)
            match registry.get_topic_by_guid(&guid) {
                Some(name) => {
                    log::debug!(
                        "[ROUTER] GUID-based routing: writer={:02x?} -> topic='{}'",
                        &guid[..],
                        name
                    );
                    name
                }
                None => {
                    // Optional fallback: if enabled via env var and there is a single
                    // topic with subscribers, bind this unknown writer GUID to that
                    // topic for interop scenarios where remote stacks do not send
                    // SEDP Publications.
                    if let Some(name) = registry.fallback_map_unknown_writer_to_single_topic(guid) {
                        log::debug!(
                            "[ROUTER] fallback GUID routing writer={:02x?} -> topic='{}'",
                            &guid[..],
                            name
                        );
                        name
                    } else {
                        log::debug!(
                            "[ROUTER] DROP: Topic unavailable for writer GUID {:02x?} (not announced via SEDP yet)",
                            &guid[..]
                        );
                        metrics.delivery_errors.fetch_add(1, Ordering::Relaxed);
                        return RouteStatus::Dropped;
                    }
                }
            }
        }
    };

    let topic = match registry.get_topic(&topic_name) {
        Some(topic) => topic,
        None => {
            log::debug!(
                "[ROUTER] orphaned DATA topic='{}' (registry miss)",
                topic_name
            );
            metrics.packets_orphaned.fetch_add(1, Ordering::Relaxed);
            return RouteStatus::Orphaned;
        }
    };

    let seq = match builder::extract_sequence_number(payload) {
        Some(s) => s,
        None => {
            // Some vendor stacks omit or encode writerSN in a way our extractor
            // cannot currently decode. For interop we still want to deliver
            // the sample, so fall back to a synthetic sequence number.
            log::debug!(
                "[ROUTER] missing_seq for DATA topic='{}' - using seq=0 fallback",
                topic_name
            );
            0
        }
    };

    let cdr2_payload = if let Some(offset) = payload_offset {
        // Offset already points to the serialized payload (or the CDR header).
        // Only skip the CDR encapsulation header when it is actually present.
        if offset >= payload.len() {
            log::debug!(
                "[ROUTER] drop DATA topic='{}' reason=missing_payload_offset",
                topic_name
            );
            metrics.delivery_errors.fetch_add(1, Ordering::Relaxed);
            return RouteStatus::Dropped;
        }

        let mut start = offset;
        if start + 4 <= payload.len() {
            let enc = u16::from_be_bytes([payload[start], payload[start + 1]]);
            let padding = u16::from_be_bytes([payload[start + 2], payload[start + 3]]);

            // XCDR1 encapsulations (CDR v1)
            let is_xcdr1 = matches!(enc, 0x0001 | 0x0003 | 0x8001 | 0x8003);
            // XCDR2 encapsulations (CDR v2) - non-delimited
            let is_xcdr2 = matches!(enc, 0x0006 | 0x0007);
            // D_CDR2 encapsulations (Delimited CDR v2) - has DHEADER
            let is_d_cdr2 = matches!(enc, 0x0008 | 0x0009);

            if (is_xcdr1 || is_xcdr2) && padding == 0 {
                // Skip 4-byte encapsulation header
                start += 4;
            } else if is_d_cdr2 && padding == 0 {
                // D_CDR2: Skip 4-byte encapsulation header + 4-byte DHEADER (size field)
                // DHEADER format: 4 bytes little-endian size of serialized data
                if start + 8 <= payload.len() {
                    start += 8;
                    log::trace!(
                        "[ROUTER] D_CDR2 detected (enc={:#06x}), skipped 8 bytes (encap+DHEADER)",
                        enc
                    );
                } else {
                    start += 4; // At least skip encap header
                }
            }
        }

        if start >= payload.len() {
            log::debug!(
                "[ROUTER] drop DATA topic='{}' reason=missing_payload_after_header",
                topic_name
            );
            metrics.delivery_errors.fetch_add(1, Ordering::Relaxed);
            return RouteStatus::Dropped;
        }

        if std::env::var("HDDS_INTEROP_DIAGNOSTICS").is_ok() {
            let head_len = (payload.len() - start).min(16);
            log::debug!(
                "[ROUTER] DATA payload(len={}, offset={}) head={:02x?}",
                payload.len() - start,
                start,
                &payload[start..start + head_len]
            );
        }

        &payload[start..]
    } else {
        match builder::extract_data_payload(payload) {
            Some(p) => {
                if std::env::var("HDDS_INTEROP_DIAGNOSTICS").is_ok() {
                    let head_len = p.len().min(16);
                    log::debug!(
                        "[ROUTER] DATA payload len={} head={:02x?}",
                        p.len(),
                        &p[..head_len]
                    );
                }
                p
            }
            None => {
                log::debug!(
                    "[ROUTER] drop DATA topic='{}' reason=missing_payload",
                    topic_name
                );
                metrics.delivery_errors.fetch_add(1, Ordering::Relaxed);
                return RouteStatus::Dropped;
            }
        }
    };

    let subscriber_count = topic.subscriber_count();
    log::debug!(
        "[ROUTER] deliver topic='{}' seq={} subscriber_count={}",
        topic.name(),
        seq,
        subscriber_count
    );

    let errors = topic.deliver(seq, cdr2_payload);

    metrics.packets_routed.fetch_add(1, Ordering::Relaxed);
    metrics
        .bytes_delivered
        .fetch_add(packet_len as u64, Ordering::Relaxed);
    if errors > 0 {
        metrics
            .delivery_errors
            .fetch_add(errors as u64, Ordering::Relaxed);
    }

    RouteStatus::Delivered
}

/// Route a DATA_FRAG packet: insert into fragment buffer, route complete sample when ready.
///
/// # Arguments
///
/// * `payload` - Raw RTPS packet bytes
/// * `packet_len` - Total packet length
/// * `payload_offset` - Offset to fragment payload data within packet
/// * `frag_meta` - Fragment metadata (writer GUID, seq, frag_num, total_frags)
/// * `fragment_buffer` - Thread-safe fragment reassembly buffer
/// * `registry` - Topic registry for routing complete samples
/// * `metrics` - Router metrics for telemetry
///
/// # Returns
///
/// * `RouteStatus::Delivered` - Fragment buffered (or complete sample delivered)
/// * `RouteStatus::Dropped` - Invalid fragment metadata
#[inline]
pub fn route_data_frag_packet(
    payload: &[u8],
    _packet_len: usize,
    payload_offset: Option<usize>,
    frag_meta: Option<&FragmentMetadata>,
    fragment_buffer: &Mutex<FragmentBuffer>,
    registry: &TopicRegistry,
    metrics: &RouterMetrics,
) -> RouteStatus {
    // Extract fragment metadata
    let meta = match frag_meta {
        Some(m) => m,
        None => {
            log::debug!("[ROUTER] DROP DATA_FRAG: missing fragment metadata");
            metrics.delivery_errors.fetch_add(1, Ordering::Relaxed);
            return RouteStatus::Dropped;
        }
    };

    // Extract fragment payload data
    let frag_data = if let Some(offset) = payload_offset {
        if offset >= payload.len() {
            log::debug!(
                "[ROUTER] DROP DATA_FRAG: invalid payload offset {} >= {}",
                offset,
                payload.len()
            );
            metrics.delivery_errors.fetch_add(1, Ordering::Relaxed);
            return RouteStatus::Dropped;
        }
        payload[offset..].to_vec()
    } else {
        // Fallback: extract via DATA extractor (may not work for all cases)
        match builder::extract_data_payload(payload) {
            Some(p) => p.to_vec(),
            None => {
                log::debug!("[ROUTER] DROP DATA_FRAG: cannot extract fragment payload");
                metrics.delivery_errors.fetch_add(1, Ordering::Relaxed);
                return RouteStatus::Dropped;
            }
        }
    };

    log::debug!(
        "[ROUTER] DATA_FRAG: guid={:02x?} seq={} frag={}/{} payload_len={}",
        &meta.writer_guid.as_bytes()[..],
        meta.seq_num,
        meta.frag_num,
        meta.total_frags,
        frag_data.len()
    );

    // Insert fragment into buffer
    let complete_payload = {
        let mut buffer = match fragment_buffer.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                log::warn!("[ROUTER] fragment_buffer lock poisoned; recovering");
                poisoned.into_inner()
            }
        };

        buffer.insert_fragment(
            meta.writer_guid,
            meta.seq_num,
            meta.frag_num,
            meta.total_frags,
            frag_data,
        )
    };

    // If complete, route the reassembled sample
    if let Some(reassembled) = complete_payload {
        log::debug!(
            "[ROUTER] DATA_FRAG COMPLETE: seq={} reassembled_len={}",
            meta.seq_num,
            reassembled.len()
        );

        // Route as a complete DATA packet
        // Build a synthetic packet for routing (just need topic resolution + delivery)
        return route_reassembled_data(
            &meta.writer_guid,
            meta.seq_num,
            &reassembled,
            registry,
            metrics,
        );
    }

    // Fragment buffered, waiting for more
    RouteStatus::Delivered
}

/// Route DATA_FRAG with source address tracking for NACK_FRAG.
#[inline]
#[allow(clippy::too_many_arguments)]
pub fn route_data_frag_packet_with_addr(
    payload: &[u8],
    _packet_len: usize,
    payload_offset: Option<usize>,
    frag_meta: Option<&FragmentMetadata>,
    src_addr: std::net::SocketAddr,
    fragment_buffer: &Mutex<FragmentBuffer>,
    registry: &TopicRegistry,
    metrics: &RouterMetrics,
) -> RouteStatus {
    // Extract fragment metadata
    let meta = match frag_meta {
        Some(m) => m,
        None => {
            log::debug!("[ROUTER] DROP DATA_FRAG: missing fragment metadata");
            metrics.delivery_errors.fetch_add(1, Ordering::Relaxed);
            return RouteStatus::Dropped;
        }
    };

    // Extract fragment payload data
    let frag_data = if let Some(offset) = payload_offset {
        if offset >= payload.len() {
            log::debug!(
                "[ROUTER] DROP DATA_FRAG: invalid payload offset {} >= {}",
                offset,
                payload.len()
            );
            metrics.delivery_errors.fetch_add(1, Ordering::Relaxed);
            return RouteStatus::Dropped;
        }
        payload[offset..].to_vec()
    } else {
        match builder::extract_data_payload(payload) {
            Some(p) => p.to_vec(),
            None => {
                log::debug!("[ROUTER] DROP DATA_FRAG: cannot extract fragment payload");
                metrics.delivery_errors.fetch_add(1, Ordering::Relaxed);
                return RouteStatus::Dropped;
            }
        }
    };

    log::debug!(
        "[ROUTER] DATA_FRAG: guid={:02x?} seq={} frag={}/{} payload_len={} src={}",
        &meta.writer_guid.as_bytes()[..8],
        meta.seq_num,
        meta.frag_num,
        meta.total_frags,
        frag_data.len(),
        src_addr
    );

    // Insert fragment into buffer with source address for NACK_FRAG
    let complete_payload = {
        let mut buffer = match fragment_buffer.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                log::warn!("[ROUTER] fragment_buffer lock poisoned; recovering");
                poisoned.into_inner()
            }
        };

        buffer.insert_fragment_with_addr(
            meta.writer_guid,
            meta.seq_num,
            meta.frag_num,
            meta.total_frags,
            frag_data,
            Some(src_addr),
        )
    };

    // If complete, route the reassembled sample
    if let Some(reassembled) = complete_payload {
        log::debug!(
            "[ROUTER] DATA_FRAG COMPLETE: seq={} reassembled_len={}",
            meta.seq_num,
            reassembled.len()
        );

        return route_reassembled_data(
            &meta.writer_guid,
            meta.seq_num,
            &reassembled,
            registry,
            metrics,
        );
    }

    RouteStatus::Delivered
}

/// Route a reassembled DATA_FRAG payload to topic subscribers.
///
/// This is similar to route_data_packet but uses pre-extracted GUID and sequence.
#[inline]
fn route_reassembled_data(
    writer_guid: &GUID,
    seq: u64,
    payload: &[u8],
    registry: &TopicRegistry,
    metrics: &RouterMetrics,
) -> RouteStatus {
    let guid_bytes = writer_guid.as_bytes();

    // Lookup topic name via GUID mapping (populated by SEDP)
    let topic_name = match registry.get_topic_by_guid(&guid_bytes) {
        Some(name) => {
            log::debug!(
                "[ROUTER] route_reassembled: GUID {:02x?} -> topic '{}' seq={}",
                &guid_bytes[..],
                name,
                seq
            );
            name
        }
        None => {
            // Try fallback mapping
            if let Some(name) = registry.fallback_map_unknown_writer_to_single_topic(guid_bytes) {
                log::debug!("[ROUTER] Reassembled DATA: fallback -> topic '{}'", name);
                name
            } else {
                log::debug!(
                    "[ROUTER] DROP reassembled DATA: unknown GUID {:02x?}",
                    &guid_bytes[..]
                );
                metrics.delivery_errors.fetch_add(1, Ordering::Relaxed);
                return RouteStatus::Dropped;
            }
        }
    };

    let topic = match registry.get_topic(&topic_name) {
        Some(topic) => topic,
        None => {
            log::debug!(
                "[ROUTER] orphaned reassembled DATA topic='{}' (registry miss)",
                topic_name
            );
            metrics.packets_orphaned.fetch_add(1, Ordering::Relaxed);
            return RouteStatus::Orphaned;
        }
    };

    // Strip CDR encapsulation header if present (same logic as route_data_packet)
    // CDR header format: [encoding_kind: u16 BE][options: u16] = 4 bytes
    let payload_to_deliver = if payload.len() >= 4 {
        let enc = u16::from_be_bytes([payload[0], payload[1]]);
        let padding = u16::from_be_bytes([payload[2], payload[3]]);

        // XCDR1 encapsulations (CDR v1): 0x0001 (PLAIN_CDR_LE), 0x0003 (PL_CDR_LE), etc.
        let is_xcdr1 = matches!(enc, 0x0001 | 0x0003 | 0x8001 | 0x8003);
        // XCDR2 encapsulations (CDR v2) - non-delimited
        let is_xcdr2 = matches!(enc, 0x0006 | 0x0007);
        // D_CDR2 encapsulations (Delimited CDR v2) - has DHEADER
        let is_d_cdr2 = matches!(enc, 0x0008 | 0x0009);

        if (is_xcdr1 || is_xcdr2) && padding == 0 {
            // Skip 4-byte encapsulation header
            &payload[4..]
        } else if is_d_cdr2 && padding == 0 && payload.len() >= 8 {
            // D_CDR2: Skip 4-byte encapsulation header + 4-byte DHEADER
            &payload[8..]
        } else {
            payload
        }
    } else {
        payload
    };

    let errors = topic.deliver(seq, payload_to_deliver);

    metrics.packets_routed.fetch_add(1, Ordering::Relaxed);
    metrics
        .bytes_delivered
        .fetch_add(payload.len() as u64, Ordering::Relaxed);
    if errors > 0 {
        metrics
            .delivery_errors
            .fetch_add(errors as u64, Ordering::Relaxed);
    }

    RouteStatus::Delivered
}

// ============================================================================
// Background Router Thread
// ============================================================================

/// Background thread that routes RTPS packets from the multicast ring to the topic registry.
///
/// The router owns the worker thread lifecycle and exposes telemetry gathered during routing.
pub struct Router {
    stop_flag: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
    pub metrics: Arc<RouterMetrics>,
}

impl Router {
    /// Start a router without transport (test/intra-process only).
    ///
    /// Self-loopback suppression is disabled (zero GUID prefix never matches
    /// a real participant). Use `start_with_transport` or `start_with_notifier`
    /// for production paths where a real GUID prefix is required.
    #[cfg(test)]
    pub fn start(
        ring: Arc<ArrayQueue<(RxMeta, u8)>>,
        pool: Arc<RxPool>,
        registry: Arc<TopicRegistry>,
    ) -> io::Result<Self> {
        Self::start_with_transport(ring, pool, registry, None, [0u8; 12])
    }

    /// Start router with transport for NACK_FRAG sending.
    ///
    /// When transport is provided, the router can send NACK_FRAG packets
    /// to request retransmission of missing fragments.
    pub fn start_with_transport(
        ring: Arc<ArrayQueue<(RxMeta, u8)>>,
        pool: Arc<RxPool>,
        registry: Arc<TopicRegistry>,
        transport: Option<Arc<crate::transport::UdpTransport>>,
        our_guid_prefix: [u8; 12],
    ) -> io::Result<Self> {
        Self::start_with_notifier(ring, pool, registry, transport, our_guid_prefix, None)
    }

    /// v210: Start router with wake notifier for zero-latency packet processing.
    ///
    /// When notifier is provided, the router uses efficient condvar wait
    /// instead of polling, reducing latency from ~100μs to ~1-10μs.
    ///
    /// # Arguments
    /// * `ring` - Lock-free ring buffer from multicast listener
    /// * `pool` - Buffer pool for zero-copy packet handling
    /// * `registry` - Topic registry for subscriber dispatch
    /// * `transport` - Optional transport for NACK_FRAG sending
    /// * `our_guid_prefix` - Our GUID prefix for NACK_FRAG
    /// * `notifier` - Optional wake notifier for low-latency wake
    pub fn start_with_notifier(
        ring: Arc<ArrayQueue<(RxMeta, u8)>>,
        pool: Arc<RxPool>,
        registry: Arc<TopicRegistry>,
        transport: Option<Arc<crate::transport::UdpTransport>>,
        our_guid_prefix: [u8; 12],
        notifier: Option<Arc<WakeNotifier>>,
    ) -> io::Result<Self> {
        let stop_flag = Arc::new(AtomicBool::new(false));
        let metrics = Arc::new(RouterMetrics::new());

        let stop_flag_clone = Arc::clone(&stop_flag);
        let metrics_clone = Arc::clone(&metrics);

        let handle = thread::spawn(move || {
            router_loop_with_transport(
                ring,
                pool,
                registry,
                stop_flag_clone,
                metrics_clone,
                transport,
                our_guid_prefix,
                notifier,
            );
        });

        Ok(Self {
            stop_flag,
            handle: Some(handle),
            metrics,
        })
    }

    pub fn stop(mut self) -> io::Result<()> {
        self.stop_flag.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            handle
                .join()
                .map_err(|_| io::Error::other("Router thread panicked"))?;
        }
        Ok(())
    }
}

impl Drop for Router {
    fn drop(&mut self) {
        // Signal the router thread to stop
        self.stop_flag.store(true, Ordering::Relaxed);
        // Join the thread to ensure clean shutdown
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Interval for checking stale fragment sequences (ms)
const NACK_FRAG_CHECK_INTERVAL_MS: u64 = 50;

/// Age threshold for considering a fragment sequence stale (ms)
/// After this time, we would send NACK_FRAG to request missing fragments
const NACK_FRAG_STALE_THRESHOLD_MS: u64 = 100;

/// Check for stale fragment sequences and send NACK_FRAG requests.
///
/// When transport is available, actually sends NACK_FRAG packets to request
/// retransmission of missing fragments.
fn check_stale_fragments_with_transport(
    fragment_buffer: &Mutex<FragmentBuffer>,
    metrics: &RouterMetrics,
    transport: Option<&crate::transport::UdpTransport>,
    our_guid_prefix: [u8; 12],
    nack_frag_count: &mut u32,
) {
    use crate::protocol::builder::build_nack_frag_packet;

    let mut buffer = match fragment_buffer.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };

    // Get sequences that have been waiting longer than threshold
    let stale = buffer.get_stale_sequences(NACK_FRAG_STALE_THRESHOLD_MS);

    for (guid, seq_num, missing_count, total_frags, age_ms, source_addr) in stale {
        // Get the specific missing fragment numbers
        if let Some((missing_frags, _total)) = buffer.get_missing_fragments(&guid, seq_num) {
            log::debug!(
                "[ROUTER] NACK_FRAG needed: guid={:02x?} seq={} missing={}/{} frags={:?} age={}ms src={:?}",
                &guid.as_bytes()[..8],
                seq_num,
                missing_count,
                total_frags,
                &missing_frags[..missing_frags.len().min(8)], // Log first 8 missing
                age_ms,
                source_addr
            );

            // Update metrics
            metrics.nack_frag_requests.fetch_add(1, Ordering::Relaxed);

            // Send NACK_FRAG if transport available and we have source address
            if let (Some(transport), Some(dest_addr)) = (transport, source_addr) {
                // Derive reader entity ID from writer entity ID
                let writer_entity_id = guid.entity_id;
                let reader_entity_id = derive_reader_entity_id(&writer_entity_id);

                let nack_frag = build_nack_frag_packet(
                    our_guid_prefix,
                    guid.prefix,
                    reader_entity_id,
                    writer_entity_id,
                    seq_num,
                    &missing_frags,
                    *nack_frag_count,
                );
                *nack_frag_count = nack_frag_count.wrapping_add(1);

                if let Err(e) = transport.send_to_endpoint(&nack_frag, &dest_addr) {
                    log::debug!("[ROUTER] Failed to send NACK_FRAG: {}", e);
                } else {
                    log::debug!(
                        "[ROUTER] Sent NACK_FRAG to {} for seq={} frags={:?}",
                        dest_addr,
                        seq_num,
                        &missing_frags[..missing_frags.len().min(4)]
                    );
                }
            }
        }
    }

    // Also evict expired sequences (cleanup)
    let evicted = buffer.evict_expired();
    if evicted > 0 {
        log::debug!("[ROUTER] Evicted {} expired fragment sequences", evicted);
        metrics
            .fragment_timeouts
            .fetch_add(evicted as u64, Ordering::Relaxed);
    }
}

/// Derive reader entity ID from writer entity ID (RTPS convention)
fn derive_reader_entity_id(writer_id: &[u8; 4]) -> [u8; 4] {
    let mut reader_id = *writer_id;
    // Convert writer kind to reader kind
    reader_id[3] = match writer_id[3] {
        0x02 => 0x04, // WITH_KEY writer -> WITH_KEY reader
        0x03 => 0x07, // NO_KEY writer -> NO_KEY reader
        0xC2 => 0xC7, // Built-in writer -> Built-in reader
        0xC3 => 0xC7, // Built-in writer (variant) -> Built-in reader
        _ => 0x04,    // Default to WITH_KEY reader
    };
    reader_id
}

/// Handle incoming HEARTBEAT_FRAG and respond with NACK_FRAG if fragments are missing.
///
/// This provides faster recovery than the timeout-based stale detection (100ms).
/// When the writer announces "I have fragments 1-64 for seq=5", we immediately
/// check our buffer and send NACK_FRAG for any missing fragments.
fn handle_heartbeat_frag(
    payload: &[u8],
    src_addr: std::net::SocketAddr,
    fragment_buffer: &Mutex<FragmentBuffer>,
    transport: &crate::transport::UdpTransport,
    our_guid_prefix: [u8; 12],
    nack_frag_count: &mut u32,
    metrics: &RouterMetrics,
) {
    use crate::protocol::builder::build_nack_frag_packet;

    // Parse HEARTBEAT_FRAG
    let Some((peer_guid_prefix, writer_entity_id, writer_sn, _last_frag)) =
        parse_heartbeat_frag(payload)
    else {
        log::debug!("[ROUTER] Failed to parse HEARTBEAT_FRAG");
        return;
    };

    // Skip our own HEARTBEAT_FRAGs (multicast loopback)
    if peer_guid_prefix == our_guid_prefix {
        return;
    }

    // Build writer GUID
    let writer_guid = GUID::new(peer_guid_prefix, writer_entity_id);

    // Check FragmentBuffer for missing fragments
    let missing_frags = {
        let buffer = match fragment_buffer.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        match buffer.get_missing_fragments(&writer_guid, writer_sn) {
            Some((missing, _total)) => missing,
            None => {
                // v208: No entry = we haven't received ANY fragment for this seq
                // This means the first fragment(s) were lost. Request ALL fragments.
                // The HEARTBEAT_FRAG tells us how many fragments exist (_last_frag).
                log::debug!(
                    "[ROUTER] HEARTBEAT_FRAG: seq={} unknown - requesting all {} fragments",
                    writer_sn,
                    _last_frag
                );
                // Request all fragments 1.._last_frag
                (1..=_last_frag).collect::<Vec<u32>>()
            }
        }
    };

    if missing_frags.is_empty() {
        return; // All fragments received
    }

    log::debug!(
        "[ROUTER] HEARTBEAT_FRAG: seq={} missing={:?} - sending NACK_FRAG",
        writer_sn,
        &missing_frags[..missing_frags.len().min(8)]
    );

    // Build and send NACK_FRAG
    let reader_entity_id = derive_reader_entity_id(&writer_entity_id);
    let nack_frag = build_nack_frag_packet(
        our_guid_prefix,
        peer_guid_prefix,
        reader_entity_id,
        writer_entity_id,
        writer_sn,
        &missing_frags,
        *nack_frag_count,
    );
    *nack_frag_count = nack_frag_count.wrapping_add(1);

    // Send to source address (writer listens on same port)
    if let Err(e) = transport.send_to_endpoint(&nack_frag, &src_addr) {
        log::debug!("[ROUTER] Failed to send NACK_FRAG: {}", e);
    } else {
        metrics.nack_frag_requests.fetch_add(1, Ordering::Relaxed);
        log::debug!(
            "[ROUTER] Sent NACK_FRAG to {} for seq={} frags={:?}",
            src_addr,
            writer_sn,
            &missing_frags[..missing_frags.len().min(4)]
        );
    }
}

/// Parse HEARTBEAT_FRAG submessage.
///
/// Returns (peer_guid_prefix, writer_entity_id, writer_sn, last_fragment_num)
fn parse_heartbeat_frag(payload: &[u8]) -> Option<([u8; 12], [u8; 4], u64, u32)> {
    // Need RTPS header (20) + submessage header (4) + HEARTBEAT_FRAG payload (24)
    if payload.len() < 48 || &payload[0..4] != b"RTPS" {
        return None;
    }

    let peer_guid_prefix: [u8; 12] = payload[8..20].try_into().ok()?;

    // Find HEARTBEAT_FRAG (0x13) submessage
    let mut offset = 20;
    while offset + 4 <= payload.len() {
        let submsg_id = payload[offset];
        let flags = payload[offset + 1];
        let is_le = flags & 0x01 != 0;
        let octets = if is_le {
            u16::from_le_bytes([payload[offset + 2], payload[offset + 3]]) as usize
        } else {
            u16::from_be_bytes([payload[offset + 2], payload[offset + 3]]) as usize
        };

        if submsg_id == 0x13 {
            // HEARTBEAT_FRAG found
            let hbf = offset + 4;
            if hbf + 24 > payload.len() {
                return None;
            }

            let writer_entity_id: [u8; 4] = payload[hbf + 4..hbf + 8].try_into().ok()?;

            let writer_sn = if is_le {
                let high = u32::from_le_bytes(payload[hbf + 8..hbf + 12].try_into().ok()?);
                let low = u32::from_le_bytes(payload[hbf + 12..hbf + 16].try_into().ok()?);
                ((high as u64) << 32) | (low as u64)
            } else {
                let high = u32::from_be_bytes(payload[hbf + 8..hbf + 12].try_into().ok()?);
                let low = u32::from_be_bytes(payload[hbf + 12..hbf + 16].try_into().ok()?);
                ((high as u64) << 32) | (low as u64)
            };

            let last_frag = if is_le {
                u32::from_le_bytes(payload[hbf + 16..hbf + 20].try_into().ok()?)
            } else {
                u32::from_be_bytes(payload[hbf + 16..hbf + 20].try_into().ok()?)
            };

            return Some((peer_guid_prefix, writer_entity_id, writer_sn, last_frag));
        }

        if octets == 0 {
            break;
        }
        offset += 4 + octets;
    }
    None
}

/// Router loop with transport for NACK_FRAG sending
#[allow(clippy::too_many_arguments)]
fn router_loop_with_transport(
    ring: Arc<ArrayQueue<(RxMeta, u8)>>,
    pool: Arc<RxPool>,
    registry: Arc<TopicRegistry>,
    stop_flag: Arc<AtomicBool>,
    metrics: Arc<RouterMetrics>,
    transport: Option<Arc<crate::transport::UdpTransport>>,
    our_guid_prefix: [u8; 12],
    notifier: Option<Arc<WakeNotifier>>,
) {
    use std::collections::HashMap;
    use std::time::Instant;

    // Create fragment buffer for user DATA_FRAG reassembly
    let user_fragment_buffer = Mutex::new(FragmentBuffer::new(
        USER_FRAG_MAX_PENDING,
        USER_FRAG_TIMEOUT_MS,
    ));

    // Timer for periodic NACK_FRAG checks
    let mut last_nack_frag_check = Instant::now();
    let mut nack_frag_count: u32 = 1;

    // v241: Deduplication cache to prevent double delivery
    // Key: (writer_guid, seq_num), Value: timestamp when first seen
    // Same packet arriving via multicast + unicast will be delivered only once
    let mut dedup_cache: HashMap<([u8; 16], u64), Instant> = HashMap::with_capacity(1024);
    let mut last_dedup_evict = Instant::now();
    const DEDUP_EVICT_INTERVAL_MS: u128 = 500;
    const DEDUP_ENTRY_TTL_MS: u128 = 2000;

    // v210: Log whether using notifier or polling
    if notifier.is_some() {
        log::debug!("[ROUTER] v210: Using WakeNotifier for low-latency wake");
    } else {
        log::debug!("[ROUTER] v210: Using polling (100μs interval)");
    }

    'router: while !stop_flag.load(Ordering::Relaxed) {
        // Periodic check for stale fragment sequences
        if last_nack_frag_check.elapsed().as_millis() >= NACK_FRAG_CHECK_INTERVAL_MS as u128 {
            check_stale_fragments_with_transport(
                &user_fragment_buffer,
                &metrics,
                transport.as_deref(),
                our_guid_prefix,
                &mut nack_frag_count,
            );
            last_nack_frag_check = Instant::now();
        }

        // v241: Periodic eviction of old dedup entries to bound memory
        if last_dedup_evict.elapsed().as_millis() >= DEDUP_EVICT_INTERVAL_MS {
            let now = Instant::now();
            dedup_cache.retain(|_, ts| now.duration_since(*ts).as_millis() < DEDUP_ENTRY_TTL_MS);
            last_dedup_evict = now;
        }

        // v211: Simplified ultra-low latency loop
        // Just spin checking ring directly - minimal branches
        let item = 'poll: {
            // Fast path: immediate check
            if let Some(item) = ring.pop() {
                break 'poll item;
            }

            // Spin phase: tight loop with no branches
            for _ in 0..200 {
                std::hint::spin_loop();
                if let Some(item) = ring.pop() {
                    break 'poll item;
                }
            }

            // Sleep phase: use condvar if available
            if let Some(ref n) = notifier {
                n.wait_timeout(Duration::from_millis(10));
            } else {
                thread::sleep(Duration::from_micros(100));
            }
            continue 'router;
        };

        let (meta, buffer_id) = item;
        let buffer = pool.get_buffer(buffer_id);
        let payload = &buffer[..meta.len as usize];

        match meta.kind {
            PacketKind::Data => {
                // Extract writer GUID once for both self-loopback and dedup checks
                let writer_guid = builder::extract_writer_guid(payload);

                // Self-loopback suppression: skip DATA from our own writers.
                // When both intra-process (TopicMerger) and UDP transport are active,
                // the writer delivers locally via merger AND sends via UDP. The UDP
                // packet loops back to us; delivering it again would cause duplicates.
                if let Some(guid) = writer_guid {
                    if guid[..12] == our_guid_prefix {
                        log::trace!(
                            "[ROUTER] self-loopback: dropping DATA from own writer {:02x?}",
                            &guid[..8]
                        );
                        if let Err(e) = pool.release(buffer_id) {
                            log::debug!(
                                "[hdds-router] Failed to release self-loopback buffer {}: {}",
                                buffer_id,
                                e
                            );
                        }
                        continue;
                    }
                }

                // v241: Deduplication check - skip if we've seen this (writer_guid, seq) recently
                // This prevents double delivery when same packet arrives via multicast + unicast
                let is_duplicate = match (writer_guid, builder::extract_sequence_number(payload)) {
                    (Some(guid), Some(seq)) => {
                        use std::collections::hash_map::Entry;
                        let key = (guid, seq);
                        match dedup_cache.entry(key) {
                            Entry::Occupied(_) => {
                                metrics.packets_deduplicated.fetch_add(1, Ordering::Relaxed);
                                log::trace!(
                                    "[ROUTER] DEDUP: skipping duplicate seq={} guid={:02x?}",
                                    seq,
                                    &guid[..8]
                                );
                                true
                            }
                            Entry::Vacant(e) => {
                                e.insert(Instant::now());
                                false
                            }
                        }
                    }
                    _ => false, // Can't extract guid/seq, let route_data_packet handle it
                };

                if is_duplicate {
                    if let Err(e) = pool.release(buffer_id) {
                        log::debug!(
                            "[hdds-router] Failed to release deduplicated buffer {}: {}",
                            buffer_id,
                            e
                        );
                    }
                    continue;
                }

                let status = route_data_packet(
                    payload,
                    meta.len as usize,
                    meta.data_payload_offset.map(|off| off as usize),
                    Arc::as_ref(&registry),
                    Arc::as_ref(&metrics),
                );
                if matches!(status, RouteStatus::Dropped) {
                    if let Err(e) = pool.release(buffer_id) {
                        log::debug!(
                            "[hdds-router] CRITICAL: Failed to release dropped buffer {}: {}",
                            buffer_id,
                            e
                        );
                    }
                    continue;
                }
            }
            PacketKind::DataFrag => {
                let writer_guid = builder::extract_writer_guid(payload);

                // Self-loopback suppression for fragments
                if let Some(guid) = writer_guid {
                    if guid[..12] == our_guid_prefix {
                        if let Err(e) = pool.release(buffer_id) {
                            log::debug!(
                                "[hdds-router] Failed to release self-loopback DATA_FRAG buffer {}: {}",
                                buffer_id,
                                e
                            );
                        }
                        continue;
                    }
                }

                // Dedup: skip if same (writer_guid, seq) already seen via another path
                if let (Some(guid), Some(seq)) =
                    (writer_guid, builder::extract_sequence_number(payload))
                {
                    use std::collections::hash_map::Entry;
                    let key = (guid, seq);
                    if let Entry::Occupied(_) = dedup_cache.entry(key) {
                        metrics.packets_deduplicated.fetch_add(1, Ordering::Relaxed);
                        if let Err(e) = pool.release(buffer_id) {
                            log::debug!(
                                "[hdds-router] Failed to release deduplicated DATA_FRAG buffer {}: {}",
                                buffer_id,
                                e
                            );
                        }
                        continue;
                    }
                    // Note: we don't insert into dedup_cache here because fragments
                    // share the same (guid, seq) until reassembly completes. The
                    // reassembled DATA will be inserted by the Data path above.
                }

                // Route fragmented data with source address tracking for NACK_FRAG
                let status = route_data_frag_packet_with_addr(
                    payload,
                    meta.len as usize,
                    meta.data_payload_offset.map(|off| off as usize),
                    meta.frag_meta.as_ref(),
                    meta.sock, // Source socket address for NACK_FRAG responses
                    &user_fragment_buffer,
                    Arc::as_ref(&registry),
                    Arc::as_ref(&metrics),
                );
                if matches!(status, RouteStatus::Dropped) {
                    if let Err(e) = pool.release(buffer_id) {
                        log::debug!(
                            "[hdds-router] CRITICAL: Failed to release dropped DATA_FRAG buffer {}: {}",
                            buffer_id,
                            e
                        );
                    }
                    continue;
                }
            }
            PacketKind::Heartbeat => {
                let errors = registry.deliver_heartbeat(payload);
                if errors > 0 {
                    metrics
                        .delivery_errors
                        .fetch_add(errors as u64, Ordering::Relaxed);
                }
            }
            PacketKind::AckNack => {
                let errors = registry.deliver_nack(payload);
                if errors > 0 {
                    metrics
                        .delivery_errors
                        .fetch_add(errors as u64, Ordering::Relaxed);
                }
            }
            PacketKind::HeartbeatFrag => {
                // Handle HEARTBEAT_FRAG: check for missing fragments and send NACK_FRAG
                if let Some(ref t) = transport {
                    handle_heartbeat_frag(
                        payload,
                        meta.sock,
                        &user_fragment_buffer,
                        t,
                        our_guid_prefix,
                        &mut nack_frag_count,
                        &metrics,
                    );
                }
            }
            other => {
                log::debug!(
                    "[hdds-router] [!]  Unhandled PacketKind: {:?} - packet dropped!",
                    other
                );
            }
        }

        if let Err(e) = pool.release(buffer_id) {
            log::debug!(
                "[hdds-router] CRITICAL: Failed to release buffer {}: {}",
                buffer_id,
                e
            );
        }
    }
}
