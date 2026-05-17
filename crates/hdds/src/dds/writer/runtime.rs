// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use super::heartbeat_scheduler::HeartbeatSchedulerHandle;
use crate::core::discovery::ReplayToken;
use crate::core::discovery::GUID;
use crate::core::rt;
use crate::core::rtps_constants::RTPS_ENTITYID_PARTICIPANT;
use crate::dds::listener::DataWriterListener;
use crate::dds::{BindToken, Error, QoS, Result, DDS};
use crate::protocol::builder;
use crate::reliability::{HeartbeatTx, HistoryCache, ReliableMetrics};
use crate::telemetry;
use crate::telemetry::metrics::current_time_ns;
use crate::transport::UdpTransport;
use std::cell::RefCell; // heartbeat_tx (pre-existing)
use std::convert::TryFrom;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// Global counter for HEARTBEAT_FRAG messages (RTPS v2.3 Sec.8.3.7.6)
static HEARTBEAT_FRAG_COUNT: AtomicU32 = AtomicU32::new(1);

/// A typed DDS DataWriter that publishes samples to a topic.
///
/// `DataWriter<T>` serializes data samples of type `T` and delivers them to matching
/// [`DataReader<T>`](crate::DataReader) instances via the configured transport.
///
/// # Type Parameter
///
/// * `T` - The data type, must implement [`DDS`](crate::dds::DDS) (derive with `#[derive(hdds::DDS)]`)
///
/// # Example
///
/// ```rust,no_run
/// use hdds::{Participant, QoS, Result, DDS};
///
/// #[derive(DDS)]
/// struct Temperature {
///     sensor_id: u32,
///     value: f32,
/// }
///
/// fn main() -> Result<()> {
///     let participant = Participant::builder("temp_sensor")
///         .domain_id(0)
///         .build()?;
///
///     let writer = participant.create_writer::<Temperature>(
///         "sensors/temp",
///         QoS::reliable(),
///     )?;
///
///     writer.write(&Temperature {
///         sensor_id: 42,
///         value: 23.5,
///     })?;
///
///     Ok(())
/// }
/// ```
///
/// # Delivery Guarantees
///
/// - **Best-effort**: Fire-and-forget, no retransmission
/// - **Reliable**: Sequence tracking, heartbeats, retransmission on ACKNACK
///
/// # Thread Safety
///
/// `DataWriter<T>` is `Send + Sync` when `T` is `Send + Sync`.
///
/// # See Also
///
/// - `WriterBuilder` - For advanced configuration
/// - [`DataReader`](crate::DataReader) - Subscribing counterpart
pub struct DataWriter<T: DDS> {
    pub(super) topic: String,
    /// QoS policy - stored for introspection, used during build()
    pub(super) qos: QoS,
    /// RTPS endpoint context used to align DATA packets with SEDP announcements.
    pub(super) rtps_endpoint: Option<crate::protocol::builder::RtpsEndpointContext>,
    pub(super) merger: Arc<rt::TopicMerger>,
    pub(super) transport: Option<Arc<UdpTransport>>,
    pub(super) next_seq: AtomicU64,
    pub(super) history_cache: Option<Arc<HistoryCache>>,
    pub(super) reliable_metrics: Option<Arc<ReliableMetrics>>,
    pub(super) heartbeat_tx: Option<RefCell<HeartbeatTx>>,
    /// Periodic heartbeat scheduler thread handle (RTPS 2.5 Section 8.4.7.2)
    /// Sends HEARTBEAT messages independently of write() calls for reliable recovery.
    pub(super) _heartbeat_scheduler: Option<HeartbeatSchedulerHandle>,
    pub(super) endpoint_registry: Option<crate::core::discovery::EndpointRegistry>,
    /// Discovery FSM for partition-aware data routing.
    /// When set, `send_packet_to_endpoints()` filters destinations by QoS compatibility
    /// (including partition matching) instead of broadcasting to all participants.
    pub(super) discovery_fsm: Option<Arc<crate::core::discovery::multicast::DiscoveryFsm>>,
    /// BindToken for intra-process auto-binding (unregisters on drop)
    pub(super) _bind_token: Option<BindToken>,
    /// Transient-local replay registration token (removes hook on drop).
    pub(super) _replay_token: Option<ReplayToken>,
    /// Optional listener for writer callbacks
    pub(super) listener: Option<Arc<dyn DataWriterListener<T>>>,
    /// Match notification token (fires on_publication_matched; unregisters on drop)
    pub(super) _match_token: Option<crate::dds::match_notification::MatchToken>,
    /// Deadline tracker for detecting offered deadline missed events (DDS spec 2.2.2.4.2.11).
    /// Checks are piggybacked on write() calls.
    pub(super) deadline_tracker: Mutex<crate::qos::deadline::DeadlineTracker>,
    pub(super) deadline_missed_total: AtomicU32,
    /// Security plugin suite for encryption (DDS Security v1.1)
    #[cfg(feature = "security")]
    pub(super) security: Option<Arc<crate::security::SecurityPluginSuite>>,
    /// Instance keys written by this writer (for auto-unregister on Drop).
    pub(super) written_instances: Mutex<std::collections::HashSet<[u8; 16]>>,
    pub(super) _phantom: core::marker::PhantomData<T>,
}

pub(super) struct WriterReplayState {
    topic: String,
    rtps_endpoint: Option<crate::protocol::builder::RtpsEndpointContext>,
    transport: Arc<UdpTransport>,
    history_cache: Arc<HistoryCache>,
    /// Stable CDR version derived from the writer's QoS at build time.
    /// Used for replayed samples since the cache stores raw payload bytes
    /// without per-sample version metadata.
    default_version: crate::dds::CdrVersion,
}

impl WriterReplayState {
    pub(super) fn new(
        topic: String,
        rtps_endpoint: Option<crate::protocol::builder::RtpsEndpointContext>,
        transport: Arc<UdpTransport>,
        history_cache: Arc<HistoryCache>,
        default_version: crate::dds::CdrVersion,
    ) -> Self {
        Self {
            topic,
            rtps_endpoint,
            transport,
            history_cache,
            default_version,
        }
    }

    pub(super) fn replay_to(&self, endpoint: SocketAddr) {
        let samples = self.history_cache.snapshot_payloads();
        if samples.is_empty() {
            return;
        }

        log::debug!(
            "[writer] Replaying {} cached sample(s) on topic '{}' to {}",
            samples.len(),
            self.topic,
            endpoint
        );

        for (seq, payload) in samples {
            // Check if payload needs fragmentation
            if builder::should_fragment(payload.len()) {
                if let Some(ctx) = self.rtps_endpoint {
                    let frag_packets = builder::build_data_frag_packets(
                        &ctx,
                        seq,
                        &payload,
                        builder::DEFAULT_FRAGMENT_SIZE,
                        self.default_version,
                    );
                    log::debug!(
                        "[writer] Replaying {} DATA_FRAG packets for seq {} ({} bytes)",
                        frag_packets.len(),
                        seq,
                        payload.len()
                    );
                    for packet in frag_packets {
                        if let Err(err) = self.transport.send_user_data_unicast(&packet, &endpoint)
                        {
                            log::debug!(
                                "[writer] History replay failed for seq {} fragment: {}",
                                seq,
                                err
                            );
                        }
                    }
                } else {
                    log::debug!(
                        "[writer] Skipping large payload replay (no RTPS context) for seq {}",
                        seq
                    );
                }
            } else {
                // Small payload: single DATA packet
                let packet = if let Some(ctx) = self.rtps_endpoint {
                    builder::build_data_packet_with_context(
                        &ctx,
                        &self.topic,
                        seq,
                        &payload,
                        self.default_version,
                    )
                } else {
                    builder::build_data_packet(&self.topic, seq, &payload)
                };

                if packet.is_empty() {
                    log::debug!(
                        "[writer] Skipping history replay for seq {} (packet build failed)",
                        seq
                    );
                    continue;
                }

                if let Err(err) = self.transport.send_user_data_unicast(&packet, &endpoint) {
                    log::debug!("[writer] History replay failed for seq {}: {}", seq, err);
                }
            }
        }
    }
}

#[derive(Default, Debug, Clone, Copy)]
pub struct WriterStats {
    pub messages_sent: u64,
    pub bytes_sent: u64,
    pub drops: u64,
}

impl<T: DDS> DataWriter<T> {
    #[must_use]
    pub fn qos(&self) -> &QoS {
        &self.qos
    }

    #[must_use]
    pub fn topic_name(&self) -> &str {
        &self.topic
    }

    pub fn merger(&self) -> Arc<rt::TopicMerger> {
        Arc::clone(&self.merger)
    }

    /// Resolve the effective CDR encoding version for the upcoming write()
    /// per DDS-XTypes v1.3 §7.6.3.1 (DataRepresentationQosPolicy). The
    /// matched readers are looked up once via the discovery FSM; the
    /// selection is the first writer-offered code accepted by at least one
    /// matched reader, falling back to offered[0] when no readers are
    /// known or defaulting to XCDR2 when neither side constrains the choice.
    pub(super) fn effective_cdr_version(&self) -> crate::dds::CdrVersion {
        let readers = self
            .discovery_fsm
            .as_ref()
            .map(|fsm| fsm.find_readers_for_topic(&self.topic))
            .unwrap_or_default();
        match crate::dds::cdr_negotiation::compute_effective_cdr_version(
            &self.qos.data_representation,
            &readers,
        ) {
            Ok(version) => version,
            // The match-time filter in MatchNotificationRegistry rejects
            // readers whose data_representation does not intersect the
            // writer's offered sequence, so any reader reaching this call
            // site is already compatible.
            Err(_) => unreachable!(
                "DataRepresentation match-time filter should have rejected incompatible readers"
            ),
        }
    }

    /// Encrypt payload if security is enabled and a session key is available.
    ///
    /// Returns the encrypted payload, or the original payload if encryption is not available.
    #[cfg(feature = "security")]
    fn maybe_encrypt_payload(&self, plaintext: &[u8]) -> Vec<u8> {
        if let Some(ref security) = self.security {
            if let Some(crypto) = security.cryptographic() {
                // Use session key ID 0 (local key)
                // Full per-participant keys require ECDH handshake during discovery
                if let Ok(encrypted) = crypto.encrypt_data(plaintext, 0) {
                    log::debug!(
                        "[writer] Encrypted payload: {} -> {} bytes",
                        plaintext.len(),
                        encrypted.len()
                    );
                    return encrypted;
                }
                // Session key not available - fall through to plaintext
                log::debug!(
                    "[writer] Encryption skipped: no session key available (key exchange not complete)"
                );
            }
        }
        plaintext.to_vec()
    }

    pub fn write(&self, msg: &T) -> Result<()> {
        // Check offered deadline before writing (DDS spec: fire callback on miss)
        self.check_offered_deadline();

        // Track instance key for auto-unregister on Drop (DDS 2.2.2.4.1.9).
        if T::has_key() {
            let key = msg.compute_key();
            let _ = self
                .written_instances
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(key);
        }

        let write_start_ns = current_time_ns();
        let seq = self.next_seq.fetch_add(1, Ordering::Relaxed);

        // Check if we have local readers - only allocate slab pool if needed
        let has_local_readers = self.merger.reader_count() > 0;

        // Fast path: intra-process only (no remote peers).
        // Skip RTPS framing, UDP send, history cache, and heartbeats entirely.
        let has_remote_peers = self.has_remote_peers();
        if has_local_readers && !has_remote_peers {
            return self.write_intra_process_fast(msg, seq, write_start_ns);
        }

        // Buffer must fit the ENTIRE serialized payload, not a single DATA
        // submessage. Samples larger than DEFAULT_MAX_UNFRAGMENTED_SIZE are
        // split into DATA_FRAG packets by build_data_frag_packets() later,
        // so the serialized blob can be arbitrarily large. Start at 64 KB
        // (covers typical samples with no realloc) and double on BufferTooSmall
        // up to a 16 MB cap to support LargeData-style payloads.
        const MAX_SERIALIZED_SIZE: usize = 16 * 1024 * 1024;
        // Single encode per write() per DDS-XTypes v1.3 §7.6.3.1.
        let version = self.effective_cdr_version();
        let (tmp_buf, serialized_len) = {
            let mut size = 65_536usize;
            loop {
                let mut buf = vec![0u8; size];
                match msg.encode(&mut buf, version) {
                    Ok(len) => break (buf, len),
                    Err(Error::BufferTooSmall) if size < MAX_SERIALIZED_SIZE => {
                        size = (size * 2).min(MAX_SERIALIZED_SIZE);
                    }
                    Err(e) => return Err(e),
                }
            }
        };

        log::debug!(
            "[writer] write() seq={} reader_count={} has_local_readers={}",
            seq,
            self.merger.reader_count(),
            has_local_readers
        );

        // Reserve intra-process resources only if there are local readers.
        // For remote-only delivery, skip slab allocation entirely.
        // If slab pool is full (WouldBlock), gracefully skip intra-process
        // delivery but still proceed with UDP - never fail the whole write.
        let intra_process = if has_local_readers {
            match Self::prepare_intra_process_entry(
                &tmp_buf[..serialized_len],
                serialized_len,
                seq,
                write_start_ns,
                version,
            ) {
                Ok(entry) => Some(entry),
                Err(Error::WouldBlock) => {
                    log::debug!(
                        "[writer] slab pool full seq={}, skipping intra-process",
                        seq
                    );
                    None
                }
                Err(e) => return Err(e),
            }
        } else {
            None
        };

        // Send on UDP
        if let Some(ref transport) = self.transport {
            // DDS Security: Encrypt payload if enabled
            #[cfg(feature = "security")]
            let encrypted_buf = self.maybe_encrypt_payload(&tmp_buf[..serialized_len]);
            #[cfg(feature = "security")]
            let payload_for_network: &[u8] = &encrypted_buf;
            #[cfg(not(feature = "security"))]
            let payload_for_network: &[u8] = &tmp_buf[..serialized_len];

            // Check if payload needs fragmentation (>8KB)
            let use_fragmentation =
                builder::should_fragment(payload_for_network.len()) && self.rtps_endpoint.is_some();

            log::debug!(
                "[writer] fragmentation decision: payload_len={} should_fragment={} rtps_endpoint={} use_fragmentation={}",
                payload_for_network.len(),
                builder::should_fragment(payload_for_network.len()),
                self.rtps_endpoint.is_some(),
                use_fragmentation
            );

            let sent_result = if use_fragmentation {
                // Large payload: send as DATA_FRAG packets
                #[allow(clippy::unwrap_used)]
                // Safe: use_fragmentation requires rtps_endpoint.is_some()
                let ctx = self.rtps_endpoint.unwrap();
                let frag_packets = builder::build_data_frag_packets(
                    &ctx,
                    seq,
                    payload_for_network,
                    builder::DEFAULT_FRAGMENT_SIZE,
                    version,
                );

                if frag_packets.is_empty() {
                    // Fragmentation returned empty (shouldn't happen if should_fragment is true)
                    log::debug!(
                        "[writer] DATA_FRAG build returned empty for seq {} ({} bytes)",
                        seq,
                        payload_for_network.len()
                    );
                    if let Some((_, handle)) = intra_process {
                        rt::get_slab_pool().release(handle);
                    }
                    return Err(Error::BufferTooSmall);
                }

                let num_fragments = frag_packets.len();
                log::debug!(
                    "[writer] Sending {} DATA_FRAG packets for seq={} (total {} bytes)",
                    num_fragments,
                    seq,
                    payload_for_network.len()
                );

                // Send all fragments
                let result = self.send_packets_to_endpoints(transport, &frag_packets);

                // v208: Send multiple HEARTBEAT_FRAGs to improve reliability
                // RTPS v2.3 Sec.8.3.7.6 recommends periodic heartbeats for fragment recovery.
                // We send 3 HBFs with 10ms spacing to handle transient packet loss.
                //
                // Must NOT go through send_packet_to_endpoints(): that helper
                // patches byte 28 of the packet as the reader entity id, but
                // in a HEARTBEAT_FRAG byte 28 falls inside the INFO_DST dest
                // GUID prefix -- patching it corrupts the destination and
                // Connext silently drops the submessage, never issues a
                // NACK_FRAG, and fragmented samples past seq 16 are left
                // half-reassembled. Build a per-reader HBF targeting the
                // reader's entity id + participant prefix instead.
                if result.is_ok() {
                    // Clamp to u32::MAX per RTPS HeartbeatFrag.lastFragmentNum
                    let num_fragments_u32 = num_fragments.min(u32::MAX as usize) as u32;

                    for i in 0..3 {
                        let hbf_count = HEARTBEAT_FRAG_COUNT.fetch_add(1, Ordering::Relaxed);

                        let mut hbf_delivered = false;
                        if let (Some(ref fsm), Some(ref reg)) =
                            (&self.discovery_fsm, &self.endpoint_registry)
                        {
                            let readers = fsm.find_readers_for_topic(&self.topic);
                            let local_prefix = self.rtps_endpoint.map(|c| c.guid_prefix);
                            for reader in &readers {
                                if let Some(local_pfx) = local_prefix {
                                    if reader.participant_guid.as_bytes()[..12] == local_pfx {
                                        continue;
                                    }
                                }
                                let mut dest_prefix = [0u8; 12];
                                dest_prefix
                                    .copy_from_slice(&reader.participant_guid.as_bytes()[..12]);
                                let mut pguid_bytes = [0u8; 16];
                                pguid_bytes[..12].copy_from_slice(&dest_prefix);
                                pguid_bytes[12..16].copy_from_slice(&RTPS_ENTITYID_PARTICIPANT);
                                let participant_key = GUID::from_bytes(pguid_bytes);
                                let dest = reg
                                    .get_reader_locator(&reader.endpoint_guid)
                                    .or_else(|| reg.get(&participant_key));
                                if let Some(endpoint) = dest {
                                    let hbf_packet = builder::build_heartbeat_frag_packet(
                                        ctx.guid_prefix,
                                        dest_prefix,
                                        reader.endpoint_guid.entity_id,
                                        ctx.writer_entity_id,
                                        seq,
                                        num_fragments_u32,
                                        hbf_count,
                                    );
                                    if transport
                                        .send_user_data_unicast(&hbf_packet, &endpoint)
                                        .is_ok()
                                    {
                                        hbf_delivered = true;
                                    }
                                }
                            }
                        }
                        if !hbf_delivered {
                            // Fallback: broadcast HBF (ENTITYID_UNKNOWN reader).
                            let hbf_packet = builder::build_heartbeat_frag_packet(
                                ctx.guid_prefix,
                                [0; 12],
                                [0, 0, 0, 0],
                                ctx.writer_entity_id,
                                seq,
                                num_fragments_u32,
                                hbf_count,
                            );
                            let _ = transport.send_user_data_multicast(&hbf_packet);
                        }
                        log::trace!(
                            "[writer] Sent HEARTBEAT_FRAG {}/3 for seq={} lastFrag={} count={}",
                            i + 1,
                            seq,
                            num_fragments,
                            hbf_count
                        );
                    }
                }

                result
            } else {
                // Small payload: send as single DATA packet (existing path)
                let rtps_packet = if let Some(ctx) = self.rtps_endpoint {
                    builder::build_data_packet_with_context(
                        &ctx,
                        &self.topic,
                        seq,
                        payload_for_network,
                        version,
                    )
                } else {
                    builder::build_data_packet(&self.topic, seq, payload_for_network)
                };

                if rtps_packet.is_empty() {
                    if let Some((_, handle)) = intra_process {
                        rt::get_slab_pool().release(handle);
                    }
                    log::debug!(
                        "[writer] Skipping send: failed to build DATA packet for seq {}",
                        seq
                    );
                    return Err(Error::BufferTooSmall);
                }

                self.send_packet_to_endpoints(transport, &rtps_packet)
            };

            if let Err(e) = sent_result {
                log::debug!("UDP send failed for topic '{}': {}", self.topic, e);
                if let Some(m) = telemetry::get_metrics_opt() {
                    m.increment_transport_errors(1);
                }
            } else {
                log::debug!(
                    "[writer] UDP send succeeded topic='{}' seq={}",
                    self.topic,
                    seq
                );
            }
        }

        // Commit to merger if we have local readers
        if let Some((entry, handle)) = intra_process {
            let merger_success = self.merger.push(entry);
            log::debug!(
                "[MERGER] push topic='{}' seq={} success={} reader_count={}",
                self.topic,
                seq,
                merger_success,
                self.merger.reader_count()
            );
            if !merger_success {
                rt::get_slab_pool().release(handle);
            }
        } else {
            log::debug!(
                "[writer] No local readers for topic='{}'; remote-only delivery",
                self.topic
            );
        }

        if let Some(ref cache) = self.history_cache {
            if let Err(e) = cache.insert(seq, &tmp_buf[..serialized_len]) {
                log::warn!(
                    "[writer] History cache insert failed for topic='{}' seq={} payload_len={}: {} \
                     -- sample will not be retransmittable (likely slab pool exhaustion or ResourceLimits cap)",
                    self.topic,
                    seq,
                    serialized_len,
                    e
                );
                if let Some(m) = telemetry::get_metrics_opt() {
                    m.increment_cache_insert_errors(1);
                }
            }
        }

        self.maybe_send_heartbeat(seq);

        if let Some(m) = telemetry::get_metrics_opt() {
            m.increment_sent(1);
            m.add_latency_sample(write_start_ns, current_time_ns());
        }

        // Invoke listener callback if present
        if let Some(ref listener) = self.listener {
            listener.on_sample_written(msg, seq);
        }

        // Record successful write for deadline tracking
        self.deadline_tracker
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .on_write();

        Ok(())
    }

    /// Returns true if there are remote peers discovered for this writer.
    #[inline]
    fn has_remote_peers(&self) -> bool {
        if let Some(ref registry) = self.endpoint_registry {
            let endpoints = registry.entries();
            if endpoints.is_empty() {
                return false;
            }
            // Check if any endpoint is NOT ourself
            let local_guid = self
                .rtps_endpoint
                .map(|ctx| GUID::new(ctx.guid_prefix, RTPS_ENTITYID_PARTICIPANT));
            endpoints.iter().any(|(guid, _)| Some(*guid) != local_guid)
        } else {
            false
        }
    }

    /// Intra-process write path: bypasses RTPS framing, UDP transport,
    /// history cache, and heartbeats. Encodes into a heap-temporary
    /// buffer that doubles on `BufferTooSmall` (up to 16 MB), then hands
    /// the bytes to `reserve_and_write` which routes through the
    /// primary, large, and heap fallback tiers in turn.
    fn write_intra_process_fast(&self, msg: &T, seq: u64, write_start_ns: u64) -> Result<()> {
        let slab_pool = rt::get_slab_pool();

        // Single encode per write() per DDS-XTypes v1.3 §7.6.3.1.
        let version = self.effective_cdr_version();
        const MAX_SERIALIZED_SIZE: usize = 16 * 1024 * 1024;
        let (tmp_buf, serialized_len) = {
            let mut size = 65_536usize;
            loop {
                let mut buf = vec![0u8; size];
                match msg.encode(&mut buf, version) {
                    Ok(len) => break (buf, len),
                    Err(Error::BufferTooSmall) if size < MAX_SERIALIZED_SIZE => {
                        size = (size * 2).min(MAX_SERIALIZED_SIZE);
                    }
                    Err(e) => return Err(e),
                }
            }
        };

        let (handle, _metric) = match slab_pool.reserve_and_write(&tmp_buf[..serialized_len]) {
            Some(value) => value,
            None => {
                if let Some(m) = telemetry::get_metrics_opt() {
                    m.increment_would_block(1);
                }
                return Err(Error::WouldBlock);
            }
        };

        let seq_u32 = match u32::try_from(seq) {
            Ok(v) => v,
            Err(_) => {
                slab_pool.release(handle);
                return Err(Error::Unsupported);
            }
        };
        let len_u32 = match u32::try_from(serialized_len) {
            Ok(v) => v,
            Err(_) => {
                slab_pool.release(handle);
                return Err(Error::BufferTooSmall);
            }
        };

        let entry = rt::IndexEntry {
            seq: seq_u32,
            handle,
            len: len_u32,
            flags: 0x01, // COMMITTED
            timestamp_ns: write_start_ns,
            cdr_version: version,
            event_data: 0,
        };

        let merger_success = self.merger.push(entry);
        if !merger_success {
            slab_pool.release(handle);
        }

        if let Some(m) = telemetry::get_metrics_opt() {
            m.increment_sent(1);
            m.add_latency_sample(write_start_ns, current_time_ns());
        }

        if let Some(ref listener) = self.listener {
            listener.on_sample_written(msg, seq);
        }

        // Record successful write for deadline tracking
        self.deadline_tracker
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .on_write();

        Ok(())
    }

    #[allow(clippy::missing_panics_doc)]
    fn prepare_intra_process_entry(
        payload: &[u8],
        serialized_len: usize,
        seq: u64,
        write_start_ns: u64,
        cdr_version: crate::dds::CdrVersion,
    ) -> Result<(rt::IndexEntry, rt::SlabHandle)> {
        let slab_pool = rt::get_slab_pool();
        let (handle, _metric) = match slab_pool.reserve_and_write(&payload[..serialized_len]) {
            Some(value) => value,
            None => {
                if let Some(m) = telemetry::get_metrics_opt() {
                    m.increment_would_block(1);
                }
                return Err(Error::WouldBlock);
            }
        };

        let seq_u32 = match u32::try_from(seq) {
            Ok(value) => value,
            Err(_) => {
                slab_pool.release(handle);
                if let Some(m) = telemetry::get_metrics_opt() {
                    m.increment_dropped(1);
                }
                log::debug!(
                    "[writer] Sequence {} exceeds 32-bit limit; dropping intra-process delivery",
                    seq
                );
                return Err(Error::Unsupported);
            }
        };

        let len_u32 = match u32::try_from(serialized_len) {
            Ok(value) => value,
            Err(_) => {
                slab_pool.release(handle);
                if let Some(m) = telemetry::get_metrics_opt() {
                    m.increment_dropped(1);
                }
                log::debug!(
                    "[writer] Serialized payload too large ({} bytes); dropping intra-process delivery",
                    serialized_len
                );
                return Err(Error::BufferTooSmall);
            }
        };

        let entry = rt::IndexEntry {
            seq: seq_u32,
            handle,
            len: len_u32,
            flags: 0x01,
            timestamp_ns: write_start_ns,
            cdr_version,
            event_data: 0,
        };

        Ok((entry, handle))
    }

    /// Check if offered deadline was missed and fire listener callback.
    ///
    /// Called at the start of each write() to detect if the writer has been
    /// silent for longer than the configured deadline period.
    fn check_offered_deadline(&self) {
        let mut tracker = self
            .deadline_tracker
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if tracker.is_missed() {
            let total = self.deadline_missed_total.fetch_add(1, Ordering::Relaxed) + 1;
            // Increment missed count in the tracker
            tracker.check();
            if let Some(ref listener) = self.listener {
                listener.on_offered_deadline_missed(
                    crate::dds::listener::OfferedDeadlineMissedStatus {
                        total_count: total,
                        total_count_change: 1,
                        last_instance_handle: None,
                    },
                );
            }
            log::debug!(
                "[writer] Offered deadline missed on topic='{}' (total={})",
                self.topic,
                total
            );
        }
    }

    /// Dispose an instance — marks it as NOT_ALIVE_DISPOSED.
    ///
    /// Sends a DATA submessage with key-only payload (K flag) and
    /// PID_STATUS_INFO = DISPOSED in inline QoS. Remote readers will
    /// transition this instance to NOT_ALIVE_DISPOSED_INSTANCE_STATE.
    ///
    /// DDS spec: Section 2.2.2.4.1.11 — dispose
    /// RTPS spec: Section 9.6.3.4 — StatusInfo_t
    pub fn dispose(&self, instance: &T) -> Result<()> {
        self.send_lifecycle_change(instance, crate::protocol::builder::StatusInfoKind::Disposed)
    }

    /// Unregister an instance — writer no longer claims ownership.
    ///
    /// Sends a DATA submessage with key-only payload (K flag) and
    /// PID_STATUS_INFO = UNREGISTERED in inline QoS. Remote readers will
    /// transition this instance to NOT_ALIVE_NO_WRITERS_INSTANCE_STATE
    /// (if no other writers remain).
    ///
    /// DDS spec: Section 2.2.2.4.1.9 — unregister_instance
    /// RTPS spec: Section 9.6.3.4 — StatusInfo_t
    pub fn unregister_instance(&self, instance: &T) -> Result<()> {
        self.send_lifecycle_change(
            instance,
            crate::protocol::builder::StatusInfoKind::Unregistered,
        )
    }

    /// Internal: send a dispose or unregister lifecycle change on the wire.
    fn send_lifecycle_change(
        &self,
        instance: &T,
        status_info: crate::protocol::builder::StatusInfoKind,
    ) -> Result<()> {
        let Some(ref transport) = self.transport else {
            // Intra-process only — no remote peers to notify
            log::debug!(
                "[writer] lifecycle change {:?} skipped (no transport)",
                status_info
            );
            return Ok(());
        };

        let Some(ctx) = self.rtps_endpoint else {
            log::debug!(
                "[writer] lifecycle change {:?} skipped (no RTPS endpoint context)",
                status_info
            );
            return Ok(());
        };

        let key_hash = instance.compute_key();
        let seq = self.next_seq.fetch_add(1, Ordering::Relaxed);

        // Spec-compliant K-flag DATA payload: serialized @key fields, not the
        // digest. The trait returns an owned Vec so size limits do not have to
        // be guessed here. Default the encoding to XCDR2 to match the regular
        // write path; the writer's negotiated data_representation should
        // eventually flow in here once the runtime tracks it per peer.
        let serialized_key = instance.encode_key(crate::CdrVersion::Xcdr2);

        let packet = crate::protocol::builder::build_dispose_packet_with_context(
            &ctx,
            &self.topic,
            seq,
            &key_hash,
            &serialized_key,
            status_info,
        );

        if packet.is_empty() {
            return Err(Error::BufferTooSmall);
        }

        self.send_packet_to_endpoints(transport, &packet)
            .map_err(|_| Error::TransportError)?;

        log::debug!(
            "[writer] Sent {:?} for topic='{}' seq={} key_hash={:02x?}",
            status_info,
            self.topic,
            seq,
            &key_hash[..4]
        );

        Ok(())
    }

    /// Send a lifecycle change using a pre-computed key hash (no instance data needed).
    fn send_key_lifecycle_change(
        &self,
        key_hash: &[u8; 16],
        status_info: crate::protocol::builder::StatusInfoKind,
    ) -> Result<()> {
        let Some(ref transport) = self.transport else {
            return Ok(());
        };
        let Some(ctx) = self.rtps_endpoint else {
            return Ok(());
        };
        let seq = self.next_seq.fetch_add(1, Ordering::Relaxed);
        // Drop-time path has no `&T` available; ships an empty K-payload.
        // Spec-strict peers may drop the lifecycle event. Tracked as a
        // follow-up (would need caching serialized key bytes alongside hash).
        let packet = crate::protocol::builder::build_dispose_packet_with_context(
            &ctx,
            &self.topic,
            seq,
            key_hash,
            &[],
            status_info,
        );
        if packet.is_empty() {
            return Err(Error::BufferTooSmall);
        }
        self.send_packet_to_endpoints(transport, &packet)
            .map_err(|_| Error::TransportError)
    }

    pub fn stats(&self) -> WriterStats {
        WriterStats::default()
    }

    fn maybe_send_heartbeat(&self, last_seq: u64) {
        // Update scheduler state so periodic thread knows the latest seq
        if let Some(ref scheduler) = self._heartbeat_scheduler {
            scheduler.state().update_seq(last_seq);
        }

        let Some(ref transport) = self.transport else {
            return;
        };
        let Some(ref hb_tx) = self.heartbeat_tx else {
            return;
        };

        let mut hb_tx_borrow = hb_tx.borrow_mut();

        if Instant::now() < hb_tx_borrow.next_deadline() {
            return;
        }

        // v252: Compute `firstSN` with the VOLATILE floor from scheduler state.
        // For RELIABLE writers the scheduler is always present (see builder.rs
        // spawn site) and owns the shared `first_eligible_seq`. When absent,
        // we fall back to `cache.oldest_seq()` unchanged.
        let first_seq = if let Some(ref cache) = self.history_cache {
            let cache_oldest = cache.oldest_seq().unwrap_or(1);
            if let Some(ref scheduler) = self._heartbeat_scheduler {
                scheduler.state().heartbeat_first_seq(cache_oldest)
            } else {
                cache_oldest
            }
        } else {
            1
        };

        let hb = hb_tx_borrow.build_heartbeat(first_seq, last_seq);

        // v200: Use context-aware HEARTBEAT if available (for RELIABLE user data).
        // This ensures HEARTBEATs are sent with the correct writer entity ID so
        // readers can properly match and respond with ACKNACKs for retransmission.
        let rtps_packet = if let Some(ctx) = self.rtps_endpoint {
            builder::build_heartbeat_packet_with_context(&ctx, hb.first_seq, hb.last_seq, hb.count)
        } else {
            builder::build_heartbeat_packet(hb.first_seq, hb.last_seq, hb.count)
        };
        // Send HEARTBEAT to each discovered reader's unicast locator.
        // NOTE: Do NOT use send_packet_to_endpoints() — it patches readerEntityId
        // at byte offset 28, which in a HEARTBEAT is the writerEntityId, not the
        // readerId. That would corrupt the HEARTBEAT.
        let mut hb_delivered = false;
        if let (Some(ref fsm), Some(ref reg)) = (&self.discovery_fsm, &self.endpoint_registry) {
            let readers = fsm.find_readers_for_topic(&self.topic);
            let local_prefix = self.rtps_endpoint.map(|ctx| ctx.guid_prefix);
            for reader in &readers {
                if let Some(local_pfx) = local_prefix {
                    if reader.participant_guid.as_bytes()[..12] == local_pfx {
                        continue;
                    }
                }
                let mut pguid_bytes = [0u8; 16];
                pguid_bytes[..12].copy_from_slice(&reader.participant_guid.as_bytes()[..12]);
                pguid_bytes[12..16].copy_from_slice(&RTPS_ENTITYID_PARTICIPANT);
                let participant_key = GUID::from_bytes(pguid_bytes);
                let dest = reg
                    .get_reader_locator(&reader.endpoint_guid)
                    .or_else(|| reg.get(&participant_key));
                if let Some(endpoint) = dest {
                    if transport
                        .send_user_data_unicast(&rtps_packet, &endpoint)
                        .is_ok()
                    {
                        hb_delivered = true;
                    }
                }
            }
        }
        if !hb_delivered {
            // Fallback to data multicast if no per-reader routing available
            let _ = transport.send_user_data_multicast(&rtps_packet);
        }
        if let Some(ref metrics) = self.reliable_metrics {
            metrics.increment_heartbeats_sent(1);
        }
    }

    /// Send a single RTPS packet to discovered endpoints or multicast fallback.
    ///
    /// When `discovery_fsm` is set, filters destinations by QoS compatibility
    /// (partition, reliability, durability, etc.) so data only flows to
    /// participants that have matching readers for this writer's topic.
    fn send_packet_to_endpoints(
        &self,
        transport: &UdpTransport,
        packet: &[u8],
    ) -> std::result::Result<(), std::io::Error> {
        let registry = match self.endpoint_registry {
            Some(ref r) => r,
            None => {
                log::debug!("[writer] No endpoint_registry, falling back to data multicast");
                return transport.send_user_data_multicast(packet);
            }
        };

        if registry.is_empty() {
            log::debug!("[writer] No endpoints in registry, falling back to data multicast");
            return transport.send_user_data_multicast(packet);
        }

        let local_prefix = self.rtps_endpoint.map(|ctx| ctx.guid_prefix);

        // Per-reader routing: find matched readers via discovery FSM, then send
        // to each reader's SEDP-announced unicast locator. This is the correct
        // RTPS behavior — remote readers may listen on different ports than the
        // participant's SPDP default_unicast (e.g. FastDDS ephemeral ports).
        if let Some(ref fsm) = self.discovery_fsm {
            let readers = fsm.find_readers_for_topic(&self.topic);
            let mut delivered = false;

            for reader in &readers {
                // Skip local readers (same GUID prefix = same participant)
                if let Some(local_pfx) = local_prefix {
                    if reader.participant_guid.as_bytes()[..12] == local_pfx {
                        continue;
                    }
                }
                // QoS compatibility check (partition, etc.)
                if !self.qos.partition.is_default()
                    && !crate::core::discovery::Matcher::is_compatible(&reader.qos, &self.qos)
                {
                    continue;
                }

                // Look up reader's SEDP locator, fall back to participant's SPDP locator.
                // EndpointInfo stores participant_guid with entity_id=[0,0,0,0], but
                // the registry keys use RTPS_ENTITYID_PARTICIPANT=[0,0,1,0xC1].
                let mut pguid_bytes = [0u8; 16];
                pguid_bytes[..12].copy_from_slice(&reader.participant_guid.as_bytes()[..12]);
                pguid_bytes[12..16].copy_from_slice(&RTPS_ENTITYID_PARTICIPANT);
                let participant_key = GUID::from_bytes(pguid_bytes);

                let dest = registry
                    .get_reader_locator(&reader.endpoint_guid)
                    .or_else(|| registry.get(&participant_key));

                if let Some(endpoint) = dest {
                    // v240: Patch readerEntityId for cross-vendor interop.
                    // RTPS v2.3 Sec.8.3.7.2: unicast DATA must target the
                    // specific reader entity ID, not ENTITYID_UNKNOWN.
                    let mut patched = packet.to_vec();
                    if patched.len() >= builder::READER_ENTITY_ID_OFFSET + 4 {
                        patched[builder::READER_ENTITY_ID_OFFSET
                            ..builder::READER_ENTITY_ID_OFFSET + 4]
                            .copy_from_slice(&reader.endpoint_guid.entity_id);
                    }
                    log::debug!(
                        "[writer] Sending unicast USER DATA to {} (reader={}, eid={:02x?})",
                        endpoint,
                        reader.endpoint_guid,
                        reader.endpoint_guid.entity_id
                    );
                    match transport.send_user_data_unicast(&patched, &endpoint) {
                        Ok(_) => {
                            delivered = true;
                        }
                        Err(_e) => {
                            log::debug!("[writer] Failed to send unicast to {}: {}", endpoint, _e);
                        }
                    }
                }
            }

            if delivered || !readers.is_empty() {
                return Ok(());
            }
            // No readers found in FSM — fall through to participant-level routing
        }

        // Fallback: participant-level routing (no discovery FSM, or no readers yet).
        // Sends to each participant's SPDP default_unicast_locator.
        let local_guid = local_prefix.map(|pfx| GUID::new(pfx, RTPS_ENTITYID_PARTICIPANT));
        let allowed_participants = self.compute_allowed_participants();
        let mut delivered = false;

        for (guid, endpoint) in registry.entries() {
            if Some(guid) == local_guid {
                continue;
            }
            if let Some(ref allowed) = allowed_participants {
                if !allowed.contains(&guid) {
                    continue;
                }
            }
            log::debug!(
                "[writer] Sending unicast USER DATA to endpoint={} guid={} (participant fallback)",
                endpoint,
                guid
            );
            if transport.send_user_data_unicast(packet, &endpoint).is_ok() {
                delivered = true;
            }
        }

        if delivered || allowed_participants.is_some() {
            Ok(())
        } else {
            log::debug!("[writer] No remote endpoints (self-only); falling back to data multicast");
            transport.send_user_data_multicast(packet)
        }
    }

    /// Compute set of participant GUIDs that have QoS-compatible readers.
    ///
    /// Returns `None` if no filtering is needed (no discovery FSM, or no QoS
    /// policies that require filtering). Returns `Some(set)` when the writer
    /// has partition QoS or other policies that restrict which readers match.
    fn compute_allowed_participants(&self) -> Option<Vec<GUID>> {
        let fsm = self.discovery_fsm.as_ref()?;

        // Only filter if the writer has non-default partition QoS.
        // Default partition (empty) matches everything, so no filtering needed.
        // This keeps the common case (no partitions) zero-cost.
        if self.qos.partition.is_default() {
            return None;
        }

        let readers = fsm.find_readers_for_topic(&self.topic);

        // When the writer has non-default partition and no readers are discovered yet,
        // return empty set (send to nobody). This is correct DDS behavior: a writer
        // with partition QoS only communicates with readers whose partition matches.
        // If no readers are known, there are no matches.
        if readers.is_empty() {
            return Some(Vec::new());
        }

        let mut allowed = Vec::new();
        for reader in &readers {
            if crate::core::discovery::Matcher::is_compatible(&reader.qos, &self.qos) {
                // EndpointInfo stores participant_guid with zeroed entity_id,
                // but endpoint_registry keys use RTPS_ENTITYID_PARTICIPANT.
                // Reconstruct the proper participant GUID for matching.
                let mut pguid_bytes = [0u8; 16];
                pguid_bytes[..12].copy_from_slice(&reader.participant_guid.as_bytes()[..12]);
                pguid_bytes[12..16]
                    .copy_from_slice(&crate::protocol::constants::RTPS_ENTITYID_PARTICIPANT);
                allowed.push(GUID::from_bytes(pguid_bytes));
            }
        }

        Some(allowed)
    }

    /// Send multiple RTPS packets (DATA_FRAG) to discovered endpoints or multicast fallback.
    fn send_packets_to_endpoints(
        &self,
        transport: &UdpTransport,
        packets: &[Vec<u8>],
    ) -> std::result::Result<(), std::io::Error> {
        let send_multicast = |pkts: &[Vec<u8>]| -> std::result::Result<(), std::io::Error> {
            for packet in pkts {
                transport.send_user_data_multicast(packet)?;
            }
            Ok(())
        };

        let registry = match self.endpoint_registry {
            Some(ref r) => r,
            None => {
                log::debug!(
                    "[writer] No endpoint_registry, falling back to multicast for {} fragments",
                    packets.len()
                );
                return send_multicast(packets);
            }
        };

        if registry.is_empty() {
            log::debug!(
                "[writer] No endpoints in registry, falling back to multicast for {} fragments",
                packets.len()
            );
            return send_multicast(packets);
        }

        let local_prefix = self.rtps_endpoint.map(|ctx| ctx.guid_prefix);

        // Per-reader routing (same logic as send_packet_to_endpoints)
        if let Some(ref fsm) = self.discovery_fsm {
            let readers = fsm.find_readers_for_topic(&self.topic);
            let mut delivered = false;

            for reader in &readers {
                if let Some(local_pfx) = local_prefix {
                    if reader.participant_guid.as_bytes()[..12] == local_pfx {
                        continue;
                    }
                }
                if !self.qos.partition.is_default()
                    && !crate::core::discovery::Matcher::is_compatible(&reader.qos, &self.qos)
                {
                    continue;
                }

                let mut pguid_bytes = [0u8; 16];
                pguid_bytes[..12].copy_from_slice(&reader.participant_guid.as_bytes()[..12]);
                pguid_bytes[12..16].copy_from_slice(&RTPS_ENTITYID_PARTICIPANT);
                let participant_key = GUID::from_bytes(pguid_bytes);

                let dest = registry
                    .get_reader_locator(&reader.endpoint_guid)
                    .or_else(|| registry.get(&participant_key));

                if let Some(endpoint) = dest {
                    log::debug!(
                        "[writer] Sending {} DATA_FRAG unicast to {} (reader={})",
                        packets.len(),
                        endpoint,
                        reader.endpoint_guid
                    );
                    let mut all_sent = true;
                    for packet in packets {
                        // v240: Patch readerEntityId for cross-vendor interop
                        // (same logic as single DATA path in send_packet_to_endpoints)
                        let mut patched = packet.to_vec();
                        if patched.len() >= builder::READER_ENTITY_ID_OFFSET + 4 {
                            patched[builder::READER_ENTITY_ID_OFFSET
                                ..builder::READER_ENTITY_ID_OFFSET + 4]
                                .copy_from_slice(&reader.endpoint_guid.entity_id);
                        }
                        if transport
                            .send_user_data_unicast(&patched, &endpoint)
                            .is_err()
                        {
                            all_sent = false;
                        }
                    }
                    if all_sent {
                        delivered = true;
                    }
                }
            }

            if delivered || !readers.is_empty() {
                return Ok(());
            }
        }

        // Fallback: participant-level routing
        let local_guid = local_prefix.map(|pfx| GUID::new(pfx, RTPS_ENTITYID_PARTICIPANT));
        let allowed_participants = self.compute_allowed_participants();
        let mut delivered = false;

        for (guid, endpoint) in registry.entries() {
            if Some(guid) == local_guid {
                continue;
            }
            if let Some(ref allowed) = allowed_participants {
                if !allowed.contains(&guid) {
                    continue;
                }
            }
            let mut all_sent = true;
            for packet in packets {
                if transport.send_user_data_unicast(packet, &endpoint).is_err() {
                    all_sent = false;
                }
            }
            if all_sent {
                delivered = true;
            }
        }

        if delivered || allowed_participants.is_some() {
            Ok(())
        } else {
            log::debug!(
                "[writer] No remote endpoints; falling back to multicast for {} fragments",
                packets.len()
            );
            send_multicast(packets)
        }
    }
}

/// Auto-unregister all written instances when a DataWriter is dropped.
///
/// DDS spec Section 2.2.2.4.1.9: when a DataWriter is deleted, all instances
/// it has written are automatically unregistered. Remote readers will transition
/// these instances to NOT_ALIVE_NO_WRITERS_INSTANCE_STATE.
impl<T: DDS> Drop for DataWriter<T> {
    fn drop(&mut self) {
        let instances = self
            .written_instances
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        if instances.is_empty() {
            return;
        }
        for key_hash in &instances {
            let _ = self.send_key_lifecycle_change(
                key_hash,
                crate::protocol::builder::StatusInfoKind::Unregistered,
            );
        }
        log::debug!(
            "[writer] Drop: auto-unregistered {} instances for topic '{}'",
            instances.len(),
            self.topic
        );
    }
}
