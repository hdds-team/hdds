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
//!   ├──DATA(1,2,3,4,5)──────────────────▶  (3 lost)
//!   ├──HEARTBEAT(first=1,last=5)────────▶
//!   │                                   │
//!   ◀──────────ACKNACK(missing={3})─────┤
//!   │                                   │
//!   ├──DATA(3) retransmit───────────────▶  ← This module handles this
//! ```

use crate::core::discovery::multicast::control_parser::parse_acknack_submessage;
use crate::core::discovery::multicast::control_types::AckNackInfo;
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
}

impl WriterNackHandler {
    pub fn new(
        topic: String,
        cache: Arc<HistoryCache>,
        transport: Arc<UdpTransport>,
        metrics: Arc<ReliableMetrics>,
        rtps_endpoint: Option<crate::protocol::builder::RtpsEndpointContext>,
    ) -> Self {
        Self {
            topic,
            cache,
            transport,
            metrics,
            gap_tx: Mutex::new(GapTx::new()),
            rtps_endpoint,
        }
    }
}

impl NackHandler for WriterNackHandler {
    fn on_nack(&self, nack_bytes: &[u8]) {
        // v207: Use proper RTPS ACKNACK parser instead of internal format
        log::debug!(
            "[writer] v207: on_nack called for topic={} with {} bytes",
            self.topic,
            nack_bytes.len()
        );

        // Parse RTPS ACKNACK packet using the proper parser
        let ack_nack_info: AckNackInfo = match parse_acknack_submessage(nack_bytes) {
            Some(info) => {
                log::debug!(
                    "[writer] v207: Parsed ACKNACK for writer={:02x?} with {} missing ranges",
                    info.writer_entity_id,
                    info.missing_ranges.len()
                );
                info
            }
            None => {
                log::debug!(
                    "[writer] v207: Failed to parse RTPS ACKNACK packet (len={})",
                    nack_bytes.len()
                );
                return;
            }
        };

        // Convert AckNackInfo to NackMsg format for WriterRetransmitHandler
        let nack = NackMsg::new(ack_nack_info.missing_ranges);

        // Skip if no missing ranges (pure ACK - reader is caught up)
        if nack.ranges.is_empty() {
            log::debug!("[writer] v207: ACKNACK is pure ACK (no gaps) - reader is synchronized");
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
            "[writer] v207: WriterRetransmitHandler returned {} retransmits, {} gaps for topic={}",
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
                    );
                    log::debug!(
                        "[writer] Retransmitting seq {} as {} DATA_FRAG packets ({} bytes)",
                        seq,
                        frag_packets.len(),
                        payload.len()
                    );
                    for packet in frag_packets {
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
                    builder::build_data_packet_with_context(&ctx, &self.topic, seq, &payload)
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

                if let Err(e) = self.transport.send(&rtps_packet) {
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
}

impl WriterNackFragHandler {
    pub fn new(
        topic: String,
        cache: Arc<HistoryCache>,
        transport: Arc<UdpTransport>,
        metrics: Arc<ReliableMetrics>,
        rtps_endpoint: Option<crate::protocol::builder::RtpsEndpointContext>,
        writer_entity_id: [u8; 4],
    ) -> Self {
        Self {
            topic,
            cache,
            transport,
            metrics,
            rtps_endpoint,
            writer_entity_id,
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
            builder::build_data_frag_packets(&ctx, writer_sn, &payload, fragment_size)
        } else {
            // Build without endpoint context (fallback)
            let ctx = builder::RtpsEndpointContext {
                guid_prefix: [0; 12],
                reader_entity_id: [0; 4],
                writer_entity_id: self.writer_entity_id,
            };
            builder::build_data_frag_packets(&ctx, writer_sn, &payload, fragment_size)
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
                if let Err(e) = self.transport.send(packet) {
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
