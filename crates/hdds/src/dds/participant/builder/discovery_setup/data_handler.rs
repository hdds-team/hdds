// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! DATA packet handler.
//!
//!
//! Handles DATA packets (non-fragmented) including:
//! - Fallback SPDP/SEDP parsing attempts
//! - DATA packet routing via DemuxRouter (handled by MulticastListener)
//!
//! Note: Most DATA packet routing is automatic via rx_ring -> DemuxRouter.
//! This handler only provides fallback SPDP/SEDP parsing for edge cases.

use crate::core::discovery::multicast::{DiscoveryFsm, EndpointKind};
use crate::engine::TopicRegistry;
use crate::protocol::discovery::{parse_sedp, parse_spdp_partial};
use std::sync::Arc;

/// Handle DATA packet (non-fragmented).
///
/// Attempts to parse as SPDP or SEDP. If parsing fails, the packet is
/// automatically routed to DemuxRouter via rx_ring by MulticastListener.
///
/// # Arguments
/// - `payload`: Full RTPS packet (including headers)
/// - `cdr_offset`: CDR payload offset within the packet (computed by classifier)
/// - `fsm`: Discovery FSM for state updates
/// - `registry`: Topic registry for writer GUID -> topic mapping
pub(super) fn handle_data_packet(
    payload: &[u8],
    cdr_offset: usize,
    fsm: Arc<DiscoveryFsm>,
    registry: Arc<TopicRegistry>,
) {
    log::debug!(
        "[callback-builder] Received DATA packet (non-fragmented), len={}, cdr_offset={}",
        payload.len(),
        cdr_offset
    );

    // Extract CDR payload using offset from classifier
    let cdr_payload = if cdr_offset < payload.len() {
        log::debug!(
            "[data-handler] v125: Extracting CDR payload at offset {}",
            cdr_offset
        );
        &payload[cdr_offset..]
    } else {
        log::debug!(
            "[data-handler] v125: Invalid offset {}, using full payload",
            cdr_offset
        );
        payload
    };

    // Fast-path: drop DATA that clearly isn't CDR (encapsulation=0x0000).
    // v135: Include all valid CDR encapsulations from parse_sedp():
    //   CDR_LE (0x0003), CDR_BE (0x0002), CDR2_LE (0x0103), CDR2_BE (0x0102)
    //   CDR_LE_VENDOR (0x8001), CDR_BE_VENDOR (0x8002), PLAIN_CDR_LE (0x0001)
    if cdr_payload.len() >= 2 {
        let enc = u16::from_be_bytes([cdr_payload[0], cdr_payload[1]]);
        if !(enc == 0x0001  // PLAIN_CDR_LE
            || enc == 0x0002  // CDR_BE (RTI)
            || enc == 0x0003  // CDR_LE
            || enc == 0x0102  // CDR2_BE
            || enc == 0x0103  // CDR2_LE
            || enc == 0x8001  // CDR_LE_VENDOR (FastDDS)
            || enc == 0x8002)
        // CDR_BE_VENDOR (FastDDS)
        {
            log::debug!(
                "[data-handler] Skip non-CDR payload encap=0x{:04x} len={} head={:02x?}",
                enc,
                cdr_payload.len(),
                &cdr_payload[..cdr_payload.len().min(16)]
            );
            return;
        }
    }

    // Try SPDP first (participant discovery)
    match parse_spdp_partial(cdr_payload) {
        Ok(spdp_data) => {
            log::debug!(
                "[callback] [OK] SPDP parsed: GUID={:?}",
                spdp_data.participant_guid
            );
            fsm.handle_spdp(spdp_data);
            return;
        }
        Err(e) => {
            log::debug!("[callback] SPDP parse failed: {:?}", e);
        }
    }

    // Try SEDP (endpoint discovery)
    match parse_sedp(cdr_payload) {
        Ok(sedp_data) => {
            let endpoint_guid_bytes = sedp_data.endpoint_guid.as_bytes();
            let endpoint_kind = EndpointKind::from_guid(&sedp_data.endpoint_guid);

            log::debug!(
                "[callback] [OK] SEDP parsed: topic={:?}, endpoint=GUID({:?}), kind={:?}",
                sedp_data.topic_name,
                sedp_data.endpoint_guid,
                endpoint_kind
            );

            // Register writer GUID -> topic mapping (RTI interop fix)
            // Only register Writers (entity_id 0x02, 0x03, 0xC2, etc.)
            if matches!(endpoint_kind, EndpointKind::Writer) {
                log::debug!(
                    "[callback] [*] Writer endpoint detected! Registering writer GUID {:02x?} -> topic '{}'",
                    &endpoint_guid_bytes[..],
                    sedp_data.topic_name
                );
                registry.register_writer_guid(endpoint_guid_bytes, sedp_data.topic_name.clone());
            } else {
                log::debug!("[callback] >>  Reader endpoint - not registering writer mapping");
            }

            fsm.handle_sedp(sedp_data);
        }
        Err(e) => {
            log::debug!("[callback] SEDP parse failed: {:?}", e);
        }
    }

    // If both SPDP and SEDP parsing failed, the packet is automatically
    // routed to DemuxRouter via rx_ring by MulticastListener.
    // No explicit action needed here.
}
