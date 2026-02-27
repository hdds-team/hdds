// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Heartbeat processing for DataReader.
//!
//! Handles incoming RTPS HEARTBEAT messages from writers and triggers
//! ACKNACK responses for missing samples via the NackScheduler.
//!
//! ## RTPS Reliable Protocol Flow
//!
//! ```text
//! Writer                              Reader
//!   ├──DATA(1,2,3,4,5)──────────────────▶  (3 lost)
//!   ├──HEARTBEAT(first=1,last=5)────────▶
//!   │                                   │
//!   ◀──────────ACKNACK(missing={3})─────┤  ← This module sends this
//!   │                                   │
//!   ├──DATA(3) retransmit───────────────▶
//! ```

use crate::engine::HeartbeatHandler;
use crate::protocol::builder::build_acknack_packet;
use crate::reliability::{HeartbeatMsg, HeartbeatRx, NackScheduler};
use crate::transport::UdpTransport;
use std::cmp;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

/// Context for sending ACKNACK responses to the writer.
pub(super) struct AcknackContext {
    /// Our GUID prefix (12 bytes)
    pub our_guid_prefix: [u8; 12],
    /// Reader entity ID (4 bytes)
    pub reader_entity_id: [u8; 4],
    /// UDP transport for sending ACKNACK
    pub transport: Arc<UdpTransport>,
}

pub(super) struct ReaderHeartbeatHandler {
    heartbeat_rx: Mutex<HeartbeatRx>,
    nack_scheduler: Arc<Mutex<NackScheduler>>,
    last_seen: Mutex<u64>,
    /// ACKNACK context (None for intra-process mode)
    acknack_ctx: Option<AcknackContext>,
    /// ACKNACK counter (monotonically increasing per RTPS spec)
    acknack_count: AtomicU32,
}

impl ReaderHeartbeatHandler {
    pub fn new(nack_scheduler: Arc<Mutex<NackScheduler>>) -> Self {
        Self {
            heartbeat_rx: Mutex::new(HeartbeatRx::new()),
            nack_scheduler,
            last_seen: Mutex::new(0),
            acknack_ctx: None,
            acknack_count: AtomicU32::new(1),
        }
    }

    /// Create with ACKNACK sending capability for cross-process RELIABLE.
    pub fn with_acknack_context(
        nack_scheduler: Arc<Mutex<NackScheduler>>,
        our_guid_prefix: [u8; 12],
        reader_entity_id: [u8; 4],
        transport: Arc<UdpTransport>,
    ) -> Self {
        Self {
            heartbeat_rx: Mutex::new(HeartbeatRx::new()),
            nack_scheduler,
            last_seen: Mutex::new(0),
            acknack_ctx: Some(AcknackContext {
                our_guid_prefix,
                reader_entity_id,
                transport,
            }),
            acknack_count: AtomicU32::new(1),
        }
    }
}

impl HeartbeatHandler for ReaderHeartbeatHandler {
    fn on_heartbeat(&self, heartbeat_bytes: &[u8]) {
        // Use full packet decoder to extract GUID prefix and entity IDs
        let hb = match HeartbeatMsg::decode_from_packet(heartbeat_bytes) {
            Some(hb) => hb,
            None => {
                // Fallback to legacy decoder for compatibility
                match HeartbeatMsg::decode_cdr2_le(heartbeat_bytes) {
                    Some(hb) => hb,
                    None => {
                        log::debug!("[reader] Failed to decode Heartbeat message");
                        return;
                    }
                }
            }
        };

        let reader_last_seen = {
            let guard = match self.last_seen.lock() {
                Ok(lock) => lock,
                Err(err) => {
                    log::debug!("[Reader::handle_heartbeat] last_seen lock poisoned, recovering");
                    err.into_inner()
                }
            };
            *guard
        };

        let mut heartbeat_rx = match self.heartbeat_rx.lock() {
            Ok(lock) => lock,
            Err(err) => {
                log::debug!("[Reader::handle_heartbeat] heartbeat_rx lock poisoned, recovering");
                err.into_inner()
            }
        };

        // Detect gaps between what we have and what writer has
        let gap_ranges = heartbeat_rx.on_heartbeat(&hb, reader_last_seen);

        // Collect missing sequences for ACKNACK
        let mut missing_seqs: Vec<u64> = Vec::new();
        if let Some(ref ranges) = gap_ranges {
            for range in ranges {
                for seq in range.clone() {
                    missing_seqs.push(seq);
                }
            }
        }

        // Update NackScheduler
        if let Some(ranges) = gap_ranges {
            let mut sched = match self.nack_scheduler.lock() {
                Ok(lock) => lock,
                Err(err) => {
                    log::debug!(
                        "[Reader::handle_heartbeat] nack_scheduler lock poisoned, recovering"
                    );
                    err.into_inner()
                }
            };

            for range in ranges {
                for seq in range {
                    sched.on_receive(seq);
                }
            }
        }

        // Send ACKNACK if we have transport context and there are gaps
        if let Some(ref ctx) = self.acknack_ctx {
            // Always send ACKNACK in response to HEARTBEAT (per RTPS spec)
            // - If we have gaps: bitmap contains missing sequences
            // - If synchronized: empty bitmap (Final flag would be set)
            let count = self.acknack_count.fetch_add(1, Ordering::Relaxed);

            // We need writer's GUID prefix and entity ID from the HEARTBEAT
            // The HeartbeatMsg should contain writer_guid_prefix and writer_entity_id
            let writer_guid_prefix = hb.writer_guid_prefix;
            let writer_entity_id = hb.writer_entity_id;

            // Determine base sequence for bitmap
            let seq_base = if missing_seqs.is_empty() {
                hb.last_seq + 1 // We have everything up to last_seq
            } else {
                missing_seqs.iter().copied().min().unwrap_or(hb.first_seq)
            };

            let acknack_packet = build_acknack_packet(
                ctx.our_guid_prefix,
                writer_guid_prefix,
                ctx.reader_entity_id,
                writer_entity_id,
                seq_base,
                &missing_seqs,
                count,
            );

            if let Err(e) = ctx.transport.send(&acknack_packet) {
                log::debug!("[reader] Failed to send ACKNACK: {}", e);
            } else {
                log::trace!(
                    "[reader] Sent ACKNACK count={} base={} missing={} seqs",
                    count,
                    seq_base,
                    missing_seqs.len()
                );
            }
        }

        if let Ok(mut guard) = self.last_seen.lock() {
            *guard = cmp::max(*guard, hb.last_seq);
        }
    }
}
