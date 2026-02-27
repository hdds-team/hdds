// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Fragment reassembly handler.
//!
//! Handles DATA_FRAG packets including:
//! - Fragment reassembly logic
//! - Complete message detection
//! - Recursive SPDP/SEDP/DATA handling after reassembly

use crate::core::discovery::{
    multicast::{DiscoveryFsm, FragmentMetadata},
    FragmentBuffer,
};
use crate::engine::TopicRegistry;
use crate::protocol::discovery::parse_spdp_partial;
use crate::transport::UdpTransport;
use parking_lot::Mutex;
use std::net::SocketAddr;
use std::sync::Arc;

use super::super::entity_registry::SedpAnnouncementsCache;
use super::sedp_handler::{handle_sedp_from_fragments, handle_sedp_from_single_fragment};
use super::spdp_handler::handle_spdp_from_fragments;

/// Handle DATA_FRAG packet with fragment reassembly.
///
/// # Arguments
/// - `frag_meta`: Fragment metadata (writer GUID, seq num, frag num, total frags)
/// - `payload`: Fragment payload
/// - `src_addr`: Source socket address (for SPDP locator inference)
/// - `our_guid_prefix`: Our participant GUID prefix (for loopback filtering)
/// - `fragment_buffer`: Fragment reassembly buffer
/// - `transport`: UDP transport for sending ACKNACKs (from SPDP)
/// - `fsm`: Discovery FSM for state updates
/// - `registry`: Topic registry for writer GUID -> topic mapping
/// - `sedp_cache`: SEDP announcements cache (for SPDP re-announcements)
/// - `dialect_detector`: Dialect detector for SPDP packet monitoring (Phase 1.6)
/// - `port_mapping`: Port mapping for RTI metatraffic locator inference
#[allow(clippy::too_many_arguments)]
pub(super) fn handle_fragment(
    frag_meta: FragmentMetadata,
    payload: &[u8],
    src_addr: SocketAddr,
    our_guid_prefix: [u8; 12],
    fragment_buffer: Arc<Mutex<FragmentBuffer>>,
    transport: Arc<UdpTransport>,
    fsm: Arc<DiscoveryFsm>,
    registry: Arc<TopicRegistry>,
    sedp_cache: SedpAnnouncementsCache,
    dialect_detector: Arc<
        std::sync::Mutex<crate::core::discovery::multicast::dialect_detector::DialectDetector>,
    >,
    port_mapping: crate::transport::PortMapping,
) {
    log::debug!(
        "[callback-builder] Received DATA_FRAG: writerGUID={:?} seqNum={} frag={}/{} len={}",
        frag_meta.writer_guid,
        frag_meta.seq_num,
        frag_meta.frag_num,
        frag_meta.total_frags,
        payload.len()
    );

    // RTI workaround: fragmentsInSubmessage=0 means single complete fragment
    // Parse directly without buffering
    if frag_meta.total_frags == 0 {
        log::debug!(
            "[callback-builder] RTI single-fragment DATA_FRAG (total_frags=0), parsing directly"
        );

        // Try SPDP parsing
        match parse_spdp_partial(payload) {
            Ok(spdp_data) => {
                log::debug!(
                    "[callback] [OK] SPDP parsed from single DATA_FRAG: GUID={:?}",
                    spdp_data.participant_guid
                );
                fsm.handle_spdp(spdp_data);
                return;
            }
            Err(e) => {
                log::debug!("[callback] SPDP parse failed on single DATA_FRAG: {:?}", e);
            }
        }

        // Try SEDP parsing
        handle_sedp_from_single_fragment(payload, fsm, registry);
        return;
    }

    // Multi-fragment reassembly (standard RTPS behavior)
    let complete_payload = {
        let mut buffer = fragment_buffer.lock();
        buffer.insert_fragment(
            frag_meta.writer_guid,
            frag_meta.seq_num,
            frag_meta.frag_num,
            frag_meta.total_frags,
            payload.to_vec(),
        )
    };

    // If reassembly complete, parse the complete payload
    if let Some(complete) = complete_payload {
        log::debug!(
            "[callback-builder] [OK] Fragment reassembly complete! Parsing {} bytes",
            complete.len()
        );

        // Try SPDP parsing
        match parse_spdp_partial(&complete) {
            Ok(_spdp_data) => {
                // Delegate to SPDP handler (which handles FSM, ACKNACKs, re-announcements)
                handle_spdp_from_fragments(
                    &complete,
                    src_addr,
                    our_guid_prefix,
                    transport,
                    fsm.clone(),
                    sedp_cache,
                    dialect_detector,
                    port_mapping,
                );
                return;
            }
            Err(e) => {
                log::debug!(
                    "[callback] SPDP parse failed on reassembled payload: {:?}",
                    e
                );
            }
        }

        // Try SEDP parsing
        handle_sedp_from_fragments(&complete, fsm, registry);
    } else {
        log::debug!(
            "[callback-builder] Fragment {}/{} buffered, waiting for more",
            frag_meta.frag_num,
            frag_meta.total_frags
        );
    }
}
