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
use std::cell::RefCell;
use std::convert::TryFrom;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
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
    /// BindToken for intra-process auto-binding (unregisters on drop)
    pub(super) _bind_token: Option<BindToken>,
    /// Transient-local replay registration token (removes hook on drop).
    pub(super) _replay_token: Option<ReplayToken>,
    /// Optional listener for writer callbacks
    pub(super) listener: Option<Arc<dyn DataWriterListener<T>>>,
    /// Security plugin suite for encryption (DDS Security v1.1)
    #[cfg(feature = "security")]
    pub(super) security: Option<Arc<crate::security::SecurityPluginSuite>>,
    pub(super) _phantom: core::marker::PhantomData<T>,
}

pub(super) struct WriterReplayState {
    topic: String,
    rtps_endpoint: Option<crate::protocol::builder::RtpsEndpointContext>,
    transport: Arc<UdpTransport>,
    history_cache: Arc<HistoryCache>,
}

impl WriterReplayState {
    pub(super) fn new(
        topic: String,
        rtps_endpoint: Option<crate::protocol::builder::RtpsEndpointContext>,
        transport: Arc<UdpTransport>,
        history_cache: Arc<HistoryCache>,
    ) -> Self {
        Self {
            topic,
            rtps_endpoint,
            transport,
            history_cache,
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
                    builder::build_data_packet_with_context(&ctx, &self.topic, seq, &payload)
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
        let write_start_ns = current_time_ns();
        // Buffer sized to fit max RTPS DATA submessage payload (~64KB)
        // RTPS submessage length field is u16, limiting single DATA payload to ~65KB
        let mut tmp_buf = vec![0u8; 65536];
        let serialized_len = msg.encode_cdr2(&mut tmp_buf)?;
        let seq = self.next_seq.fetch_add(1, Ordering::Relaxed);

        // Check if we have local readers - only allocate slab pool if needed
        let has_local_readers = self.merger.reader_count() > 0;
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
                if result.is_ok() {
                    // Clamp to u32::MAX per RTPS HeartbeatFrag.lastFragmentNum
                    let num_fragments_u32 = num_fragments.min(u32::MAX as usize) as u32;

                    for i in 0..3 {
                        let hbf_count = HEARTBEAT_FRAG_COUNT.fetch_add(1, Ordering::Relaxed);
                        let hbf_packet = builder::build_heartbeat_frag_packet(
                            ctx.guid_prefix,
                            [0; 12],      // Broadcast to all readers (will use INFO_DST)
                            [0, 0, 0, 0], // ENTITYID_UNKNOWN for multicast
                            ctx.writer_entity_id,
                            seq,
                            num_fragments_u32,
                            hbf_count,
                        );
                        // Send HEARTBEAT_FRAG to same endpoints as DATA_FRAG
                        if let Err(e) = self.send_packet_to_endpoints(transport, &hbf_packet) {
                            log::debug!("[writer] Failed to send HEARTBEAT_FRAG: {}", e);
                        } else {
                            log::trace!(
                                "[writer] Sent HEARTBEAT_FRAG {}/3 for seq={} lastFrag={} count={}",
                                i + 1,
                                seq,
                                num_fragments,
                                hbf_count
                            );
                        }
                        if i < 2 {
                            std::thread::sleep(std::time::Duration::from_millis(2));
                        }
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
                log::debug!(
                    "[writer] History cache insert failed for seq {}: {}",
                    seq,
                    e
                );
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

        Ok(())
    }

    #[allow(clippy::missing_panics_doc)]
    fn prepare_intra_process_entry(
        payload: &[u8],
        serialized_len: usize,
        seq: u64,
        write_start_ns: u64,
    ) -> Result<(rt::IndexEntry, rt::SlabHandle)> {
        let slab_pool = rt::get_slab_pool();
        let (handle, slab_buf) = match slab_pool.reserve(serialized_len) {
            Some((h, b)) => (h, b),
            None => {
                if let Some(m) = telemetry::get_metrics_opt() {
                    m.increment_would_block(1);
                }
                return Err(Error::WouldBlock);
            }
        };

        slab_buf[..serialized_len].copy_from_slice(payload);
        slab_pool.commit(handle, serialized_len);

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
        };

        Ok((entry, handle))
    }

    #[must_use]
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

        let first_seq = if let Some(ref cache) = self.history_cache {
            cache.oldest_seq().unwrap_or(1)
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
        if let Err(e) = transport.send(&rtps_packet) {
            log::debug!("Failed to send Heartbeat: {}", e);
        } else if let Some(ref metrics) = self.reliable_metrics {
            metrics.increment_heartbeats_sent(1);
        }
    }

    /// Send a single RTPS packet to discovered endpoints or multicast fallback.
    fn send_packet_to_endpoints(
        &self,
        transport: &UdpTransport,
        packet: &[u8],
    ) -> std::result::Result<(), std::io::Error> {
        if let Some(ref registry) = self.endpoint_registry {
            let endpoints = registry.entries();
            if endpoints.is_empty() {
                log::debug!("[writer] No endpoints in registry, falling back to multicast");
                return transport.send(packet);
            }

            let local_guid = self
                .rtps_endpoint
                .map(|ctx| GUID::new(ctx.guid_prefix, RTPS_ENTITYID_PARTICIPANT));
            let mut delivered = false;

            for (guid, endpoint) in endpoints {
                if Some(guid) == local_guid {
                    continue;
                }
                log::debug!(
                    "[writer] Sending unicast USER DATA to endpoint={} guid={}",
                    endpoint,
                    guid
                );
                if transport.send_user_data_unicast(packet, &endpoint).is_ok() {
                    delivered = true;
                }
            }

            if delivered {
                Ok(())
            } else {
                log::debug!("[writer] No remote endpoints (self-only); falling back to multicast");
                transport.send(packet)
            }
        } else {
            log::debug!("[writer] No endpoint_registry, falling back to multicast");
            transport.send(packet)
        }
    }

    /// Send multiple RTPS packets (DATA_FRAG) to discovered endpoints or multicast fallback.
    fn send_packets_to_endpoints(
        &self,
        transport: &UdpTransport,
        packets: &[Vec<u8>],
    ) -> std::result::Result<(), std::io::Error> {
        if let Some(ref registry) = self.endpoint_registry {
            let endpoints = registry.entries();
            if endpoints.is_empty() {
                log::debug!(
                    "[writer] No endpoints in registry, falling back to multicast for {} fragments",
                    packets.len()
                );
                for packet in packets {
                    transport.send(packet)?;
                }
                return Ok(());
            }

            let local_guid = self
                .rtps_endpoint
                .map(|ctx| GUID::new(ctx.guid_prefix, RTPS_ENTITYID_PARTICIPANT));
            let mut delivered = false;

            for (guid, endpoint) in endpoints {
                if Some(guid) == local_guid {
                    continue;
                }
                log::debug!(
                    "[writer] Sending {} DATA_FRAG unicast to endpoint={} guid={}",
                    packets.len(),
                    endpoint,
                    guid
                );
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

            if delivered {
                Ok(())
            } else {
                log::debug!(
                    "[writer] No remote endpoints; falling back to multicast for {} fragments",
                    packets.len()
                );
                for packet in packets {
                    transport.send(packet)?;
                }
                Ok(())
            }
        } else {
            log::debug!(
                "[writer] No endpoint_registry, falling back to multicast for {} fragments",
                packets.len()
            );
            for packet in packets {
                transport.send(packet)?;
            }
            Ok(())
        }
    }
}
