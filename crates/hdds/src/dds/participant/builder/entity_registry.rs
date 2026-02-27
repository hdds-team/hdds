// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Local entity tracking and SEDP announcements cache.
//!
//! This module manages:
//! - SEDP announcements cache for unicast replay to new peers
//! - GUID generation with RTPS v2.5 compliant structure
//! - Local entity ID tracking

use crate::core::discovery::multicast::SedpEndpointKind;
use crate::core::discovery::GUID;
use crate::protocol::discovery::SedpData;
use std::sync::{Arc, RwLock};

/// SEDP announcements cache type.
///
/// Stores local SEDP announcements for replaying to newly discovered participants
/// (RTI interop requirement).
pub(super) type SedpAnnouncementsCache = Arc<RwLock<Vec<(SedpData, SedpEndpointKind)>>>;

/// Create empty SEDP announcements cache.
///
/// This cache stores local endpoint announcements (readers/writers) for:
/// - Replaying to newly discovered participants (RTI interop)
/// - Unicast re-announcement when peers miss multicast SEDP
pub(super) fn create_sedp_cache() -> SedpAnnouncementsCache {
    Arc::new(RwLock::new(Vec::new()))
}

/// Generate RTPS v2.5 compliant GUID.
///
/// # GUID Structure (16 bytes)
/// - Bytes 0-11: GUID Prefix
///   - Bytes 0-1: Vendor ID (0x01aa for HDDS)
///   - Bytes 2-5: Host ID (IPv4 address or timestamp-based random)
///   - Bytes 6-9: App ID (Process ID)
///   - Bytes 10-11: Instance ID (participant_id)
/// - Bytes 12-15: Entity ID (provided by caller, e.g., RTPS_ENTITYID_PARTICIPANT)
///
/// # Arguments
/// - `participant_id`: Participant instance ID (0-255)
/// - `entity_id`: RTPS entity ID (4 bytes, e.g., [0x00, 0x00, 0x01, 0xc1])
///
/// # Returns
/// RTPS-compliant GUID with prefix and entity ID
///
/// # RTPS v2.5 Reference
/// Sec.9.3.1.1: GUID prefix structure
pub(super) fn generate_guid(participant_id: u8, entity_id: [u8; 4]) -> GUID {
    // Vendor ID: 0x01aa (HDDS)
    let vendor_id: [u8; 2] = [0x01, 0xaa];

    // Host ID: Try to get local IPv4, fallback to timestamp-based random
    let host_id: [u8; 4] = get_host_id();

    // App ID: Process ID (4 bytes)
    let pid = std::process::id();
    let app_id: [u8; 4] = [
        (pid >> 24) as u8,
        (pid >> 16) as u8,
        (pid >> 8) as u8,
        pid as u8,
    ];

    // Instance ID: participant_id (2 bytes, second byte is participant_id)
    let instance_id: [u8; 2] = [0, participant_id];

    // Construct GUID prefix (12 bytes)
    let prefix = [
        vendor_id[0],
        vendor_id[1],
        host_id[0],
        host_id[1],
        host_id[2],
        host_id[3],
        app_id[0],
        app_id[1],
        app_id[2],
        app_id[3],
        instance_id[0],
        instance_id[1],
    ];

    log::debug!(
        "[GUID] Generated RTPS-compliant GUID prefix: vendor={:02x?} host={:02x?} app={:02x?} instance={:02x?}",
        &vendor_id, &host_id, &app_id, &instance_id
    );

    GUID::new(prefix, entity_id)
}

/// Get host ID from local IPv4 or timestamp fallback.
///
/// Tries to connect to 8.8.8.8:80 to get local IPv4 address octets.
/// Falls back to timestamp-based random if network unavailable.
fn get_host_id() -> [u8; 4] {
    if let Ok(Ok(std::net::SocketAddr::V4(v4addr))) = std::net::UdpSocket::bind("0.0.0.0:0")
        .and_then(|s| s.connect("8.8.8.8:80").map(|_| s.local_addr()))
    {
        return v4addr.ip().octets();
    }

    // Fallback: use current timestamp as random seed
    use std::time::SystemTime;
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_else(|_| std::time::Duration::from_secs(0))
        .as_secs();

    [
        (now >> 24) as u8,
        (now >> 16) as u8,
        (now >> 8) as u8,
        now as u8,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sedp_cache_creation() {
        let cache = create_sedp_cache();
        let guard = cache.read().expect("RwLock should not be poisoned");
        assert_eq!(guard.len(), 0);
    }

    #[test]
    fn test_guid_generation() {
        let participant_id = 42;
        let entity_id = [0x00, 0x00, 0x01, 0xc1]; // RTPS_ENTITYID_PARTICIPANT
        let guid = generate_guid(participant_id, entity_id);

        let bytes = guid.as_bytes();

        // Check vendor ID
        assert_eq!(bytes[0], 0x01);
        assert_eq!(bytes[1], 0xaa);

        // Check instance ID
        assert_eq!(bytes[10], 0);
        assert_eq!(bytes[11], participant_id);

        // Check entity ID
        assert_eq!(&bytes[12..16], &entity_id);
    }

    #[test]
    fn test_get_host_id() {
        let host_id = get_host_id();
        // Just verify it returns 4 bytes (content varies by network)
        assert_eq!(host_id.len(), 4);
    }
}
