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
use std::sync::{Arc, OnceLock, RwLock};

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

/// Env var that restores the PID-only App ID (deterministic GUID).
const DETERMINISTIC_GUID_ENV: &str = "HDDS_DETERMINISTIC_GUID";

/// Vendor ID + Host ID + App ID (10 bytes), computed once per process.
static PROCESS_GUID_STEM: OnceLock<[u8; 10]> = OnceLock::new();

/// Generate RTPS v2.5 compliant GUID.
///
/// # GUID Structure (16 bytes)
/// - Bytes 0-11: GUID Prefix
///   - Bytes 0-1: Vendor ID (0x01aa for HDDS)
///   - Bytes 2-5: Host ID (IPv4 address or timestamp-based random)
///   - Bytes 6-9: App ID (process ID mixed with per-boot entropy)
///   - Bytes 10-11: Instance ID (participant_id)
/// - Bytes 12-15: Entity ID (provided by caller, e.g., RTPS_ENTITYID_PARTICIPANT)
///
/// Vendor/Host/App bytes are computed once per process and cached, so every
/// participant in this process shares them and each GUID is stable for the
/// process lifetime; participants stay distinct via Instance ID.
///
/// # Arguments
/// - `participant_id`: Participant instance ID (0-255)
/// - `entity_id`: RTPS entity ID (4 bytes, e.g., [0x00, 0x00, 0x01, 0xc1])
///
/// # Returns
/// RTPS-compliant GUID with prefix and entity ID
///
/// # RTPS v2.5 Reference
/// - Sec.9.3.1.1: GUID prefix structure
/// - Sec.8.2.4.2: GUIDs must be unique across time; a restarted participant
///   must not reuse the GUID of a previous incarnation, otherwise peers treat
///   it as the still-alive old participant and never re-run discovery.
pub(super) fn generate_guid(participant_id: u8, entity_id: [u8; 4]) -> GUID {
    let stem = *PROCESS_GUID_STEM.get_or_init(compute_process_guid_stem);

    // Instance ID: participant_id (2 bytes, second byte is participant_id)
    let instance_id: [u8; 2] = [0, participant_id];

    // Construct GUID prefix (12 bytes)
    let mut prefix = [0u8; 12];
    prefix[..10].copy_from_slice(&stem);
    prefix[10..].copy_from_slice(&instance_id);

    log::debug!(
        "[GUID] Generated RTPS-compliant GUID prefix: vendor={:02x?} host={:02x?} app={:02x?} instance={:02x?}",
        &stem[0..2], &stem[2..6], &stem[6..10], instance_id
    );

    GUID::new(prefix, entity_id)
}

/// Compute the per-process Vendor ID + Host ID + App ID bytes.
fn compute_process_guid_stem() -> [u8; 10] {
    // Vendor ID: 0x01aa (HDDS)
    let vendor_id: [u8; 2] = [0x01, 0xaa];

    // Host ID: Try to get local IPv4, fallback to timestamp-based random
    let host_id: [u8; 4] = get_host_id();

    // App ID: PID alone repeats across container restarts (usually PID 1),
    // so mix in per-boot entropy unless determinism is requested.
    let deterministic = std::env::var(DETERMINISTIC_GUID_ENV)
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let entropy = if deterministic { 0 } else { boot_entropy() };
    let app_id = app_id_bytes(std::process::id(), entropy);

    let mut stem = [0u8; 10];
    stem[0..2].copy_from_slice(&vendor_id);
    stem[2..6].copy_from_slice(&host_id);
    stem[6..10].copy_from_slice(&app_id);
    stem
}

/// Derive the 4 App ID bytes from the process ID and per-boot entropy.
fn app_id_bytes(pid: u32, entropy: u64) -> [u8; 4] {
    let folded = ((entropy >> 32) as u32) ^ (entropy as u32);
    (pid ^ folded).to_be_bytes()
}

/// Per-boot entropy: OS-seeded `RandomState` mixed with the current time and PID.
///
/// `RandomState` keys come from system randomness, so this differs on every
/// process start even when host, IP and PID are identical. No extra dependency.
fn boot_entropy() -> u64 {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hash, Hasher};
    use std::time::{SystemTime, UNIX_EPOCH};

    let mut hasher = RandomState::new().build_hasher();
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
        .hash(&mut hasher);
    std::process::id().hash(&mut hasher);
    hasher.finish()
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

    /// RTPS 8.2.4.2: a restart on the same host/IP/PID must not reuse the GUID.
    #[test]
    fn test_app_id_differs_across_simulated_boots() {
        let pid = 1; // typical container PID
        let boot_a = app_id_bytes(pid, 0x0123_4567_89ab_cdef);
        let boot_b = app_id_bytes(pid, 0x5a5a_1234_dead_beef);
        assert_ne!(
            boot_a, boot_b,
            "same host/IP/PID across boots must yield different App ID"
        );
        // App ID must not be the bare PID.
        assert_ne!(boot_a, pid.to_be_bytes());
        assert_ne!(boot_b, pid.to_be_bytes());
        // Same entropy -> same App ID (deterministic given its inputs).
        assert_eq!(boot_a, app_id_bytes(pid, 0x0123_4567_89ab_cdef));
    }

    #[test]
    fn test_boot_entropy_is_not_constant() {
        // Two independent draws must differ (64-bit space, OS-seeded RandomState).
        assert_ne!(boot_entropy(), boot_entropy());
    }

    #[test]
    fn test_app_id_is_pid_only_when_entropy_zero() {
        // Deterministic escape hatch path: entropy 0 -> legacy big-endian PID.
        assert_eq!(app_id_bytes(0x0001_0203, 0), [0x00, 0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_guid_stable_within_process() {
        let entity_id = [0x00, 0x00, 0x01, 0xc1];
        let first = generate_guid(7, entity_id);
        let second = generate_guid(7, entity_id);
        assert_eq!(
            first.as_bytes(),
            second.as_bytes(),
            "GUID must be stable for the process lifetime"
        );
    }

    #[test]
    fn test_participants_share_stem_and_differ_by_instance() {
        let entity_id = [0x00, 0x00, 0x01, 0xc1];
        let a = generate_guid(3, entity_id).as_bytes();
        let b = generate_guid(4, entity_id).as_bytes();

        // Vendor + Host + App identical within one process...
        assert_eq!(&a[0..10], &b[0..10]);
        // ...participants distinguished by Instance ID only.
        assert_eq!(a[11], 3);
        assert_eq!(b[11], 4);
        assert_ne!(a, b);
    }
}
