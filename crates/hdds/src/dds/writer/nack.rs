// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! ACKNACK processing for DataWriter.
//!
//! Handles incoming RTPS ACKNACK messages from readers and triggers
//! retransmission of missing samples from the history cache.
//!
//! ## RTPS Reliable Protocol Flow
//!
//! ```text
//! Writer                              Reader
//!   |--DATA(1,2,3,4,5)----------------->  (3 lost)
//!   |--HEARTBEAT(first=1,last=5)------->
//!   |                                   |
//!   <----------ACKNACK(missing={3})-----|
//!   |                                   |
//!   |--DATA(3) retransmit-------------->  <- This module handles this
//! ```
//!
//! ## Dual-format ACKNACK parsing
//!
//! Two callers feed `deliver_nack()` with different formats:
//!   1. `router.rs` / `unicast_router.rs` -- raw RTPS packet (starts with "RTPS" magic)
//!   2. `control.rs` -- CDR2-encoded `NackMsg` (missing-range list only)
//!
//! `on_nack()` tries RTPS parsing first, then falls back to NackMsg CDR2.

use crate::core::discovery::multicast::control_parser::parse_acknack_submessage;
use crate::engine::{NackFragHandler, NackHandler};
use crate::protocol::builder;
use crate::reliability::{GapTx, HistoryCache, NackMsg, ReliableMetrics, WriterRetransmitHandler};
use crate::transport::UdpTransport;
use std::sync::{Arc, Mutex};

pub(super) struct WriterNackHandler {
    topic: String,
    cache: Arc<HistoryCache>,
    transport: Arc<UdpTransport>,
    metrics: Arc<ReliableMetrics>,
    gap_tx: Mutex<GapTx>,
    rtps_endpoint: Option<crate::protocol::builder::RtpsEndpointContext>,
    /// Stable CDR version for retransmits; the cache stores raw bytes
    /// without per-sample version metadata, so we use the writer's
    /// first-offered version captured at build time.
    default_version: crate::dds::CdrVersion,
    /// Discovered locators, used to route retransmits to the readers'
    /// user-data locators instead of the metatraffic multicast group.
    endpoint_registry: Option<crate::core::discovery::EndpointRegistry>,
    discovery_fsm: Option<Arc<crate::core::discovery::multicast::DiscoveryFsm>>,
}

impl WriterNackHandler {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        topic: String,
        cache: Arc<HistoryCache>,
        transport: Arc<UdpTransport>,
        metrics: Arc<ReliableMetrics>,
        rtps_endpoint: Option<crate::protocol::builder::RtpsEndpointContext>,
        default_version: crate::dds::CdrVersion,
        endpoint_registry: Option<crate::core::discovery::EndpointRegistry>,
        discovery_fsm: Option<Arc<crate::core::discovery::multicast::DiscoveryFsm>>,
    ) -> Self {
        Self {
            topic,
            cache,
            transport,
            metrics,
            gap_tx: Mutex::new(GapTx::new()),
            rtps_endpoint,
            default_version,
            endpoint_registry,
            discovery_fsm,
        }
    }

    fn route_to_reader_locators(&self, packet: &[u8], patch_reader_entity_id: bool) -> bool {
        route_to_reader_locators(
            &self.transport,
            self.endpoint_registry.as_ref(),
            self.discovery_fsm.as_ref(),
            &self.topic,
            self.rtps_endpoint.map(|ctx| ctx.guid_prefix),
            packet,
            patch_reader_entity_id,
        )
    }
}

/// Route a reliability packet (retransmitted DATA/DATA_FRAG or GAP) to the
/// discovered readers' user-data locators, mirroring the fresh-write path in
/// `runtime::send_packet_to_endpoints`.
///
/// Remote readers accept user data only on the locators they announced via
/// SEDP/SPDP. Sending a retransmit to the metatraffic multicast group (the
/// `UdpTransport::send` default) reaches no remote reader, so the reader
/// re-NACKs forever and a RELIABLE in-order reader stalls permanently on the
/// missing sequence.
///
/// `patch_reader_entity_id` applies to DATA and DATA_FRAG: a unicast repair
/// names the destination reader (RTPS v2.5 Sec.8.3.7.2 readerId) rather than
/// ENTITYID_UNKNOWN. GAP has a different submessage layout and must not be
/// patched.
///
/// Returns `false` when no locator is known, leaving the caller on its original
/// multicast path.
fn route_to_reader_locators(
    transport: &UdpTransport,
    endpoint_registry: Option<&crate::core::discovery::EndpointRegistry>,
    discovery_fsm: Option<&Arc<crate::core::discovery::multicast::DiscoveryFsm>>,
    topic: &str,
    local_prefix: Option<[u8; 12]>,
    packet: &[u8],
    patch_reader_entity_id: bool,
) -> bool {
    let Some(registry) = endpoint_registry else {
        return false;
    };

    let mut delivered = false;

    // Per-reader routing: readers may listen on a port other than their
    // participant's default unicast locator.
    if let Some(fsm) = discovery_fsm {
        for reader in &fsm.find_readers_for_topic(topic) {
            if let Some(local_pfx) = local_prefix {
                if reader.participant_guid.as_bytes()[..12] == local_pfx {
                    continue;
                }
            }

            // EndpointInfo zeroes the participant GUID's entity_id, but
            // endpoint_registry keys use RTPS_ENTITYID_PARTICIPANT.
            let mut pguid_bytes = [0u8; 16];
            pguid_bytes[..12].copy_from_slice(&reader.participant_guid.as_bytes()[..12]);
            pguid_bytes[12..16]
                .copy_from_slice(&crate::core::rtps_constants::RTPS_ENTITYID_PARTICIPANT);
            let participant_key = crate::core::discovery::GUID::from_bytes(pguid_bytes);

            let Some(dest) = registry
                .get_reader_locator(&reader.endpoint_guid)
                .or_else(|| registry.get(&participant_key))
            else {
                continue;
            };

            let mut patched = packet.to_vec();
            if patch_reader_entity_id && patched.len() >= builder::READER_ENTITY_ID_OFFSET + 4 {
                patched[builder::READER_ENTITY_ID_OFFSET..builder::READER_ENTITY_ID_OFFSET + 4]
                    .copy_from_slice(&reader.endpoint_guid.entity_id);
            }

            match transport.send_user_data_unicast(&patched, &dest) {
                Ok(_) => {
                    log::debug!(
                        "[writer] Retransmit unicast to {} (reader={}) topic={}",
                        dest,
                        reader.endpoint_guid,
                        topic
                    );
                    delivered = true;
                }
                Err(_e) => {
                    log::debug!("[writer] Retransmit unicast to {} failed: {}", dest, _e);
                }
            }
        }
    }

    if delivered {
        return true;
    }

    // Fallback: the participants' SPDP-announced default unicast locators.
    let local_guid = local_prefix.map(|pfx| {
        crate::core::discovery::GUID::new(
            pfx,
            crate::core::rtps_constants::RTPS_ENTITYID_PARTICIPANT,
        )
    });
    for (guid, dest) in registry.entries() {
        if Some(guid) == local_guid {
            continue;
        }
        if transport.send_user_data_unicast(packet, &dest).is_ok() {
            log::debug!(
                "[writer] Retransmit unicast to {} (participant fallback) topic={}",
                dest,
                topic
            );
            delivered = true;
        }
    }

    delivered
}

impl NackHandler for WriterNackHandler {
    fn on_nack(&self, nack_bytes: &[u8]) {
        log::debug!(
            "[writer] on_nack called for topic={} with {} bytes",
            self.topic,
            nack_bytes.len()
        );

        // Two formats arrive here:
        // 1. Full RTPS packet (from router.rs / unicast_router.rs -- raw UDP)
        // 2. NackMsg CDR2 (from control.rs which re-encodes parsed AckNackInfo)
        let missing_ranges = if let Some(info) = parse_acknack_submessage(nack_bytes) {
            log::debug!(
                "[writer] Parsed RTPS ACKNACK for writer={:02x?} with {} missing ranges",
                info.writer_entity_id,
                info.missing_ranges.len()
            );
            info.missing_ranges
        } else if let Some(nack_msg) = NackMsg::decode_cdr2_le(nack_bytes) {
            log::debug!(
                "[writer] Parsed NackMsg CDR2 with {} missing ranges (control.rs path)",
                nack_msg.ranges.len()
            );
            nack_msg.ranges
        } else {
            log::debug!(
                "[writer] Failed to parse ACKNACK: neither RTPS nor CDR2 (len={})",
                nack_bytes.len()
            );
            return;
        };

        let nack = NackMsg::new(missing_ranges);

        // Skip if no missing ranges (pure ACK - reader is caught up)
        if nack.ranges.is_empty() {
            log::debug!("[writer] ACKNACK is pure ACK (no gaps) - reader is synchronized");
            return;
        }

        let (retransmits, gaps) = {
            let mut gap_tx = match self.gap_tx.lock() {
                Ok(guard) => guard,
                Err(poisoned) => {
                    log::debug!("[writer] WARNING: GAP transmitter lock poisoned, recovering");
                    poisoned.into_inner()
                }
            };

            let mut handler = WriterRetransmitHandler::new(&self.cache, &mut gap_tx, &self.metrics);
            handler.on_nack(&nack)
        };

        log::debug!(
            "[writer] Retransmitting {} samples, {} gaps for topic={}",
            retransmits.len(),
            gaps.len(),
            self.topic
        );

        for (seq, payload) in retransmits {
            // Check if payload needs fragmentation (same threshold as write())
            if builder::should_fragment(payload.len()) {
                // Large payload: retransmit as DATA_FRAG packets
                if let Some(ctx) = self.rtps_endpoint {
                    let frag_packets = builder::build_data_frag_packets(
                        &ctx,
                        seq,
                        &payload,
                        builder::DEFAULT_FRAGMENT_SIZE,
                        self.default_version,
                    );
                    log::debug!(
                        "[writer] Retransmitting seq {} as {} DATA_FRAG packets ({} bytes)",
                        seq,
                        frag_packets.len(),
                        payload.len()
                    );
                    for packet in frag_packets {
                        if self.route_to_reader_locators(&packet, true) {
                            continue;
                        }
                        if let Err(e) = self.transport.send(&packet) {
                            log::debug!(
                                "[writer] Retransmit DATA_FRAG failed for seq {}: {}",
                                seq,
                                e
                            );
                        }
                    }
                    self.metrics.retransmit_sent();
                } else {
                    log::debug!(
                        "[writer] Cannot retransmit large payload: no RTPS endpoint context"
                    );
                }
            } else {
                // Small payload: retransmit as single DATA packet
                let rtps_packet = if let Some(ctx) = self.rtps_endpoint {
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
                if rtps_packet.is_empty() {
                    log::debug!(
                        "[writer] Skipping retransmit: failed to build DATA packet for seq {}",
                        seq
                    );
                    continue;
                }

                if self.route_to_reader_locators(&rtps_packet, true) {
                    self.metrics.retransmit_sent();
                } else if let Err(e) = self.transport.send(&rtps_packet) {
                    log::debug!("[writer] Retransmit failed for seq {}: {}", seq, e);
                } else {
                    self.metrics.retransmit_sent();
                }
            }
        }

        for gap in gaps {
            let packet = builder::build_gap_packet(&gap.encode_cdr2_le());
            if packet.is_empty() {
                log::debug!(
                    "[writer] Skipping GAP transmit: payload too large (start={}, base={})",
                    gap.gap_start(),
                    gap.gap_list().base()
                );
                continue;
            }
            if self.route_to_reader_locators(&packet, false) {
                continue;
            }
            if let Err(e) = self.transport.send(&packet) {
                log::debug!(
                    "[writer] Failed to send GAP start={} base={}: {}",
                    gap.gap_start(),
                    gap.gap_list().base(),
                    e
                );
            }
        }
    }
}

/// Handler for NACK_FRAG messages - fragment-level retransmission.
///
/// When a reader detects missing fragments in a DATA_FRAG sequence,
/// it sends NACK_FRAG requesting specific fragments. This handler
/// re-fragments the original message and sends only the missing fragments.
pub(super) struct WriterNackFragHandler {
    topic: String,
    cache: Arc<HistoryCache>,
    transport: Arc<UdpTransport>,
    metrics: Arc<ReliableMetrics>,
    rtps_endpoint: Option<crate::protocol::builder::RtpsEndpointContext>,
    writer_entity_id: [u8; 4],
    /// Stable CDR version for fragment retransmits; see
    /// [`WriterNackHandler::default_version`].
    default_version: crate::dds::CdrVersion,
    /// See [`WriterNackHandler::endpoint_registry`].
    endpoint_registry: Option<crate::core::discovery::EndpointRegistry>,
    discovery_fsm: Option<Arc<crate::core::discovery::multicast::DiscoveryFsm>>,
}

impl WriterNackFragHandler {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        topic: String,
        cache: Arc<HistoryCache>,
        transport: Arc<UdpTransport>,
        metrics: Arc<ReliableMetrics>,
        rtps_endpoint: Option<crate::protocol::builder::RtpsEndpointContext>,
        writer_entity_id: [u8; 4],
        default_version: crate::dds::CdrVersion,
        endpoint_registry: Option<crate::core::discovery::EndpointRegistry>,
        discovery_fsm: Option<Arc<crate::core::discovery::multicast::DiscoveryFsm>>,
    ) -> Self {
        Self {
            topic,
            cache,
            transport,
            metrics,
            rtps_endpoint,
            writer_entity_id,
            default_version,
            endpoint_registry,
            discovery_fsm,
        }
    }
}

impl NackFragHandler for WriterNackFragHandler {
    fn on_nack_frag(&self, writer_entity_id: &[u8; 4], writer_sn: u64, missing_fragments: &[u32]) {
        // Only process if this NACK_FRAG is for our writer
        if writer_entity_id != &self.writer_entity_id {
            log::debug!(
                "[writer] NACK_FRAG ignored: entity_id mismatch (got {:02x?}, want {:02x?})",
                writer_entity_id,
                self.writer_entity_id
            );
            return;
        }

        log::debug!(
            "[writer] NACK_FRAG for topic={} seq={} missing_frags={:?}",
            self.topic,
            writer_sn,
            missing_fragments
        );

        // Get the original sample from cache
        let payload = match self.cache.get(writer_sn) {
            Some(p) => p,
            None => {
                log::debug!(
                    "[writer] NACK_FRAG: seq {} not in cache (expired or never existed)",
                    writer_sn
                );
                return;
            }
        };

        // Re-fragment the payload using default fragment size
        let fragment_size = builder::DEFAULT_FRAGMENT_SIZE;
        let frag_packets = if let Some(ctx) = self.rtps_endpoint {
            builder::build_data_frag_packets(
                &ctx,
                writer_sn,
                &payload,
                fragment_size,
                self.default_version,
            )
        } else {
            // Build without endpoint context (fallback). The canonical
            // PLAIN_CDR2_LE form keeps the wire encap consistent with the
            // writer's XCDR2 default; see `encap_kind_for_version`.
            let ctx = builder::RtpsEndpointContext {
                guid_prefix: [0; 12],
                reader_entity_id: [0; 4],
                writer_entity_id: self.writer_entity_id,
                encapsulation_kind: 0x0007,
            };
            builder::build_data_frag_packets(
                &ctx,
                writer_sn,
                &payload,
                fragment_size,
                self.default_version,
            )
        };

        if frag_packets.is_empty() {
            log::debug!(
                "[writer] NACK_FRAG: failed to build DATA_FRAG packets for seq {}",
                writer_sn
            );
            return;
        }

        // Send only the missing fragments
        let mut sent_count = 0;
        for (frag_num, packet) in frag_packets.iter().enumerate() {
            // Fragment numbers are 1-based in RTPS spec
            let frag_num_1based = (frag_num + 1) as u32;

            if missing_fragments.contains(&frag_num_1based) {
                if route_to_reader_locators(
                    &self.transport,
                    self.endpoint_registry.as_ref(),
                    self.discovery_fsm.as_ref(),
                    &self.topic,
                    self.rtps_endpoint.map(|ctx| ctx.guid_prefix),
                    packet,
                    true,
                ) {
                    sent_count += 1;
                    self.metrics.retransmit_sent();
                } else if let Err(e) = self.transport.send(packet) {
                    log::debug!(
                        "[writer] NACK_FRAG retransmit failed: seq={} frag={}: {}",
                        writer_sn,
                        frag_num_1based,
                        e
                    );
                } else {
                    sent_count += 1;
                    self.metrics.retransmit_sent();
                }
            }
        }

        log::debug!(
            "[writer] NACK_FRAG: retransmitted {}/{} fragments for seq={}",
            sent_count,
            missing_fragments.len(),
            writer_sn
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::discovery::{EndpointRegistry, GUID};
    use crate::core::rt::slabpool::SlabPool;
    use crate::dds::qos::History;
    use crate::dds::CdrVersion;
    use crate::transport::PortMapping;
    use std::net::UdpSocket;
    use std::time::Duration;

    /// `UdpTransport` binds the domain's fixed RTPS ports, so two transports in
    /// the same process collide. Serialize the tests that build one.
    static TRANSPORT_PORTS: Mutex<()> = Mutex::new(());

    fn lock_ports() -> std::sync::MutexGuard<'static, ()> {
        TRANSPORT_PORTS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// A NACK'd sample must be retransmitted to a locator the remote reader
    /// actually listens on.
    ///
    /// Regression: retransmits used `UdpTransport::send()`, which targets the
    /// *metatraffic* multicast group (239.255.0.x:7400). Remote readers accept
    /// user data only on their announced user-data locators, so the retransmit
    /// was silently discarded, the reader re-NACK'd forever, and a RELIABLE
    /// in-order reader stalled permanently on the missing sequence.
    #[test]
    fn retransmit_reaches_registered_reader_locator() {
        let _ports = lock_ports();

        let reader = UdpSocket::bind("127.0.0.1:0").expect("bind stand-in reader socket");
        reader
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set read timeout");
        let reader_addr = reader.local_addr().expect("reader local addr");

        // The remote participant announced this user-data locator via SPDP.
        let registry = EndpointRegistry::new();
        registry.register(
            GUID::from_bytes([
                0x01, 0x01, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x00, 0x00,
                0x01, 0xc1,
            ]),
            reader_addr,
        );

        let pool = Arc::new(SlabPool::new());
        let cache = Arc::new(HistoryCache::new_with_limits(
            pool,
            16,
            64 * 1024,
            History::KeepLast(16),
        ));
        cache.insert(1, b"retransmit-me").expect("cache insert");

        let mapping = PortMapping::calculate(0, 9).expect("port mapping");
        let transport = Arc::new(UdpTransport::new(0, 9, mapping).expect("udp transport"));

        let handler = WriterNackHandler::new(
            "RetransmitRoutingTopic".to_string(),
            cache,
            transport,
            Arc::new(ReliableMetrics::new()),
            None,
            CdrVersion::Xcdr2,
            Some(registry),
            None,
        );

        // Reader reports sequence 1 as missing (RTPS ACKNACK, control.rs CDR2 form).
        handler.on_nack(&NackMsg::new(std::iter::once(1..2).collect()).encode_cdr2_le());

        let mut buf = [0u8; 4096];
        let (len, from) = reader
            .recv_from(&mut buf)
            .expect("retransmit must be delivered to the reader's announced locator");

        assert!(
            buf[..len].windows(13).any(|w| w == b"retransmit-me"),
            "packet from {from} ({len} bytes) does not carry the retransmitted payload"
        );
    }

    /// Fragment-level retransmission (NACK_FRAG) must reach the reader's
    /// announced locator for the same reason as sequence-level retransmission.
    #[test]
    fn nack_frag_retransmit_reaches_registered_reader_locator() {
        const WRITER_ENTITY_ID: [u8; 4] = [0x00, 0x00, 0x01, 0x02];

        let _ports = lock_ports();

        let reader = UdpSocket::bind("127.0.0.1:0").expect("bind stand-in reader socket");
        reader
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set read timeout");
        let reader_addr = reader.local_addr().expect("reader local addr");

        let registry = EndpointRegistry::new();
        registry.register(
            GUID::from_bytes([
                0x01, 0x01, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0x00, 0x00,
                0x01, 0xc1,
            ]),
            reader_addr,
        );

        let pool = Arc::new(SlabPool::new());
        let cache = Arc::new(HistoryCache::new_with_limits(
            pool,
            16,
            64 * 1024,
            History::KeepLast(16),
        ));
        // Must exceed DEFAULT_MAX_UNFRAGMENTED_SIZE, or the builder produces no
        // DATA_FRAG packets at all. The marker lands in fragment 1.
        let mut payload = b"fragment-me".to_vec();
        payload.resize(16 * 1024, b'x');
        cache.insert(7, &payload).expect("cache insert");

        let mapping = PortMapping::calculate(0, 10).expect("port mapping");
        let transport = Arc::new(UdpTransport::new(0, 10, mapping).expect("udp transport"));

        let handler = WriterNackFragHandler::new(
            "FragRetransmitRoutingTopic".to_string(),
            cache,
            transport,
            Arc::new(ReliableMetrics::new()),
            None,
            WRITER_ENTITY_ID,
            CdrVersion::Xcdr2,
            Some(registry),
            None,
        );

        handler.on_nack_frag(&WRITER_ENTITY_ID, 7, &[1]);

        let mut buf = [0u8; 4096];
        let (len, from) = reader
            .recv_from(&mut buf)
            .expect("DATA_FRAG retransmit must be delivered to the reader's announced locator");

        assert!(
            buf[..len].windows(11).any(|w| w == b"fragment-me"),
            "packet from {from} ({len} bytes) does not carry the retransmitted fragment"
        );
    }
}
