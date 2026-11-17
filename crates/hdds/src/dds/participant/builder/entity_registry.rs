// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Local entity tracking and SEDP announcements cache.
//!
//! This module manages:
//! - SEDP announcements cache for unicast replay to new peers
//! - GUID generation, unique per participant (RTPS v2.5 Sec.8.2.4)
//! - Local entity ID tracking

use crate::core::discovery::multicast::SedpHistory;
use crate::core::discovery::GUID;
use crate::core::rtps_constants::HDDS_VENDOR_ID;
use std::sync::{Arc, RwLock};

/// The history of the participant's SEDP built-in writers
/// (`SedpHistory`), shared with the discovery threads that replay and
/// retransmit it.
pub(super) type SedpAnnouncementsCache = Arc<RwLock<SedpHistory>>;

/// Create the empty SEDP history.
///
/// It holds the local endpoint announcements (readers/writers) for:
/// - Replaying to newly discovered participants (interop)
/// - Unicast re-announcement when peers miss multicast SEDP
/// - The retirement of a deleted endpoint (its dispose)
pub(super) fn create_sedp_cache() -> SedpAnnouncementsCache {
    Arc::new(RwLock::new(SedpHistory::new()))
}

/// Generate the GUID of a new participant that does not run DDS-Security,
/// and the candidate GUID of one that does (`participant_guid`).
///
/// # GUID prefix layout (12 bytes)
/// - Bytes 0-1: vendor id (0x011a for HDDS). Mandatory: RTPS v2.5
///   Sec.9.3.1.5 requires `guidPrefix[0..2] == vendorId`.
/// - Bytes 2-5: host id (local IPv4, or the low 32 bits of the epoch
///   seconds when no route exists; see `get_host_id`).
/// - Bytes 6-11: participant instance, `(process base + n) mod 2^48`,
///   where the base is drawn at random once per process and `n` counts
///   the participants this process has created (see
///   `participant_instance`).
///
/// Bytes 12-15 are the entity id given by the caller.
///
/// # Why not the process id and the participant id
/// RTPS v2.5 Sec.8.2.4.1 / Table 8.7: the prefix "uniquely identifies the
/// Participant within the Domain", and Sec.8.2.4.2 leaves its choice free
/// "as long as every Participant in the Domain has a unique GUID". The
/// previous layout, host + PID + participant id, was deterministic: a
/// participant deleted and created again in the same process with the same
/// participant id, or any participant of a restarted container (PID 1,
/// same address), came back under the GUID of its predecessor, and with
/// the entity counter starting at zero again every writer and reader did
/// too. A remote reader that still remembered the old writer took the new
/// one's samples for duplicates of the old one's and acknowledged them
/// without delivering them. The counter makes two participants of one
/// process differ by construction; the random base makes two processes
/// differ, including the same PID on the same host after a restart.
pub(super) fn generate_guid(entity_id: [u8; 4]) -> GUID {
    let vendor_id: [u8; 2] = HDDS_VENDOR_ID;
    let host_id: [u8; 4] = get_host_id();
    let instance: [u8; 6] = participant_instance();

    let mut prefix = [0u8; 12];
    prefix[0..2].copy_from_slice(&vendor_id);
    prefix[2..6].copy_from_slice(&host_id);
    prefix[6..12].copy_from_slice(&instance);

    log::debug!(
        "[GUID] Generated GUID prefix: vendor={:02x?} host={:02x?} instance={:02x?}",
        &vendor_id,
        &host_id,
        &instance
    );

    GUID::new(prefix, entity_id)
}

/// The GUID of a new participant whose identity certificate, when it runs
/// DDS-Security, has the SubjectName `identity_subject_name_der`.
///
/// Without security: [`generate_guid`]. With it, DDS-Security 1.1 Sec.9.3.3,
/// Table 52, `validate_local_identity`: the `adjusted_participant_guid`,
/// whose prefix begins with a 1 and 47 bits of the SubjectName's SHA-256 and
/// ends with 48 bits of the SHA-256 of that GUID
/// (`security::authentication::guid_binding`). Its first two octets are then
/// not the vendor id RTPS v2.5 Sec.9.3.1.5 asks for: DDS-Security takes the
/// place, and the peers that read the vendor read `PID_VENDORID`.
pub(super) fn participant_guid(
    entity_id: [u8; 4],
    identity_subject_name_der: Option<&[u8]>,
) -> GUID {
    #[cfg(all(test, feature = "security"))]
    if let Some(prefix) = PREFIX_FOR_TEST.with(std::cell::Cell::take) {
        return GUID::new(prefix, entity_id);
    }
    let candidate = generate_guid(entity_id);
    #[cfg(feature = "security")]
    if let Some(subject) = identity_subject_name_der {
        let prefix = crate::security::authentication::guid_binding::adjusted_participant_prefix(
            subject,
            &candidate.as_bytes(),
        );
        return GUID::new(prefix, entity_id);
    }
    #[cfg(not(feature = "security"))]
    let _ = identity_subject_name_der;
    candidate
}

#[cfg(all(test, feature = "security"))]
thread_local! {
    /// The prefix the next participant built on this thread takes, for the
    /// tests that model a peer reusing a GUID prefix (a foreign stack, or an
    /// HDDS release before prefixes were unique). Taken by one build only.
    static PREFIX_FOR_TEST: std::cell::Cell<Option<[u8; 12]>> =
        const { std::cell::Cell::new(None) };
}

/// Make the next participant built on this thread take `prefix`.
#[cfg(all(test, feature = "security"))]
pub(super) fn set_next_prefix_for_test(prefix: [u8; 12]) {
    PREFIX_FOR_TEST.with(|cell| cell.set(Some(prefix)));
}

/// The 48-bit instance part of a new participant's GUID prefix.
///
/// `(base + n) mod 2^48`, big-endian: `base` is drawn once per process,
/// `n` is the number of participants this process created before this
/// one. Distinct `n` give distinct values for the first 2^48 participants
/// of a process, whatever the base, so a recreated participant can never
/// take the prefix of one created earlier in the same process. Two
/// processes collide only if their bases fall within the number of
/// participants they create of each other.
fn participant_instance() -> [u8; 6] {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::OnceLock;
    const MASK_48: u64 = 0xFFFF_FFFF_FFFF;
    static BASE: OnceLock<u64> = OnceLock::new();
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let base = *BASE.get_or_init(process_random);
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    let value = base.wrapping_add(n) & MASK_48;
    let [_, _, b0, b1, b2, b3, b4, b5] = value.to_be_bytes();
    [b0, b1, b2, b3, b4, b5]
}

/// A random value drawn once for the process.
///
/// `RandomState` is seeded from the operating system's randomness (the
/// crate's existing source, see `local_writer_identity` in the writer
/// builder); the process id and the wall clock are mixed in as well, so a
/// platform whose seed were weak would still differ across restarts.
fn process_random() -> u64 {
    use std::hash::{BuildHasher, Hasher};
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    hasher.write_u32(std::process::id());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    hasher.write_u128(now);
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

    // The low 32 bits of the epoch seconds, big-endian: the high word is
    // constant for the life of the process and carries no entropy.
    let [_, _, _, _, b0, b1, b2, b3] = now.to_be_bytes();
    [b0, b1, b2, b3]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sedp_cache_creation() {
        let cache = create_sedp_cache();
        let guard = cache.read().expect("RwLock should not be poisoned");
        assert!(guard.is_empty());
    }

    #[test]
    fn test_guid_generation() {
        let entity_id = [0x00, 0x00, 0x01, 0xc1]; // RTPS_ENTITYID_PARTICIPANT
        let guid = generate_guid(entity_id);

        let bytes = guid.as_bytes();

        // Vendor id first (RTPS v2.5 Sec.9.3.1.5).
        assert_eq!(bytes[0..2], HDDS_VENDOR_ID);
        // The host where it always was.
        assert_eq!(bytes[2..6], get_host_id());
        assert_eq!(&bytes[12..16], &entity_id);
    }

    /// Successive participants of one process get successive instances:
    /// never the same one twice, whatever the random base.
    #[test]
    fn participant_instances_of_one_process_never_repeat() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..1_000 {
            assert!(seen.insert(participant_instance()), "instance reused");
        }
    }

    /// A participant deleted and created again in the same process, with
    /// the same participant id, is a new participant: its prefix differs,
    /// and so does the GUID of the first writer each creates, although
    /// the entity counter starts at zero in both. Under the old layout
    /// (host + PID + participant id) both were identical, byte for byte.
    #[test]
    fn a_recreated_participant_never_reuses_a_guid() {
        use crate::dds::participant::Participant;
        use crate::TransportMode;
        let build = || {
            Participant::builder("guid-recreated")
                .with_transport(TransportMode::IntraProcess)
                .participant_id(Some(7))
                .build()
                .expect("participant")
        };
        let first_writer = |p: &Participant| {
            let mut guid = p.guid().as_bytes();
            guid[12..16].copy_from_slice(&p.next_user_entity_id(0x02));
            guid
        };
        let a = build();
        let (prefix_a, writer_a) = (a.guid().prefix, first_writer(&a));
        drop(a);
        let b = build();
        let (prefix_b, writer_b) = (b.guid().prefix, first_writer(&b));
        assert_eq!(writer_a[12..16], writer_b[12..16], "same entity id");
        assert_ne!(prefix_a, prefix_b, "recreated participant reused a prefix");
        assert_ne!(writer_a, writer_b, "recreated writer reused a GUID");
        assert_eq!(prefix_a[0..6], prefix_b[0..6], "vendor and host kept");
    }

    #[test]
    fn test_get_host_id() {
        let host_id = get_host_id();
        // Just verify it returns 4 bytes (content varies by network)
        assert_eq!(host_id.len(), 4);
    }
}
