// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Shared Memory (SHM) transport for inter-process zero-copy communication.
//!
//! This module provides a high-performance transport layer using POSIX shared memory
//! and futex-based synchronization for ultra-low latency communication between
//! different processes on the same host.
//!
//! # Architecture
//!
//! ```text
//! +------------------+              +------------------+
//! |   Process A      |   Shared     |   Process B      |
//! |     Writer       |   Memory     |     Reader       |
//! |        |         |   (mmap)     |        |         |
//! |        v         |              |        v         |
//! |   ShmRingWriter -+--------------+-> ShmRingReader  |
//! +------------------+   Futex      +------------------+
//!                       (wake)
//! ```
//!
//! # Key Features
//!
//! - **Zero-copy**: Data is written directly to shared memory, no serialization overhead
//! - **Lock-free**: Uses atomic operations and futex for synchronization
//! - **Cache-aligned**: All structures are 64-byte aligned to prevent false sharing
//! - **Overrun detection**: Readers can detect and recover from being too slow
//!
//! # Latency targets (design, not measured)
//!
//! - Writer push: < 200 ns
//! - Reader poll: < 100 ns
//!
//! No shared-memory end-to-end latency has been measured; a reader woken from
//! sleep pays the kernel wake-up (the intra-process WaitSet arm measures about
//! 2.6 us p50, see docs/guides/performance/benchmarks.md).

mod futex;
mod integration;
mod metrics;
mod notify;
mod owner;
mod policy;
mod presence;
pub(crate) mod receiver;
mod ring;
mod segment;
mod slot;
#[cfg(test)]
pub(crate) mod test_support;

pub use futex::{futex_wait, futex_wake};
pub use integration::{
    ShmReaderTransport, ShmTransportRegistry, ShmWriterInfo, ShmWriterTransport,
};
pub use metrics::{global_metrics, ShmMetrics, ShmMetricsSnapshot};
pub use notify::{reclaim_dead_notify_segments, NotifyBucket, TopicNotify, NOTIFY_MAX_USERS};
pub use owner::reclaim_dead_ring_segments;
pub use policy::{select_transport, ShmPolicy, TransportSelection, TransportSelectionError};
pub(crate) use policy::{shm_data_path_is_wired, shm_require_is_honourable};
pub use ring::{ShmRingReader, ShmRingWriter};
pub use segment::{cleanup_domain_segments, cleanup_stale_segments, ShmSegment};
pub use slot::{ShmControl, ShmSlot, SLOT_PAYLOAD_SIZE};

use std::fmt;
use std::io;

/// Default ring capacity (must be power of 2)
pub const DEFAULT_RING_CAPACITY: usize = DEFAULT_RING_CAPACITY_U32 as usize;

/// `DEFAULT_RING_CAPACITY` in the width the control block stores it
/// (`ShmControl::capacity` is a u32 in the segment); see `SLOT_PAYLOAD_SIZE_U32`.
pub(crate) const DEFAULT_RING_CAPACITY_U32: u32 = 256;

/// Bytes of framed RTPS packet one ring slot holds.
///
/// An alias for [`SLOT_PAYLOAD_SIZE`], which is the value the ring actually
/// enforces. Kept in sync deliberately: a second literal claiming to be the
/// slot size is a trap for whoever sizes a buffer from the wrong one.
pub const DEFAULT_SLOT_PAYLOAD_SIZE: usize = SLOT_PAYLOAD_SIZE;

/// Number of notify buckets (reduces contention)
pub const NOTIFY_BUCKET_COUNT: usize = 256;

/// Errors that can occur in SHM transport operations
#[derive(Debug)]
pub enum ShmError {
    /// Shared memory segment creation failed
    SegmentCreate(io::Error),

    /// Shared memory segment open failed
    SegmentOpen(io::Error),

    /// Memory mapping failed
    Mmap(io::Error),

    /// Payload too large for slot
    PayloadTooLarge { size: usize, capacity: usize },

    /// Ring buffer overrun detected
    Overrun,

    /// Data corruption detected during read
    Corruption,

    /// Invalid segment name
    InvalidName(String),

    /// Segment not found
    NotFound(String),

    /// Invalid ring capacity (must be power of 2)
    InvalidCapacity(usize),

    /// The segment on disk is smaller than the geometry about to be mapped
    /// onto it. Refused rather than mapped: `mmap` succeeds past the end of
    /// the object, and the first access to a page beyond it raises SIGBUS,
    /// which kills the reader's poller thread. Reachable from a peer built
    /// with a different `SLOT_PAYLOAD_SIZE`, a truncated segment, or a local
    /// process that created the name first.
    SegmentTooSmall { actual: u64, expected: usize },
}

impl fmt::Display for ShmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SegmentCreate(e) => write!(f, "Shared memory segment creation failed: {e}"),
            Self::SegmentOpen(e) => write!(f, "Shared memory segment open failed: {e}"),
            Self::Mmap(e) => write!(f, "Memory mapping failed: {e}"),
            Self::PayloadTooLarge { size, capacity } => {
                write!(
                    f,
                    "Payload too large: {size} bytes exceeds slot capacity {capacity}"
                )
            }
            Self::Overrun => write!(f, "Ring buffer overrun detected"),
            Self::Corruption => write!(f, "Data corruption detected during read"),
            Self::InvalidName(name) => write!(f, "Invalid segment name: {name}"),
            Self::NotFound(name) => write!(f, "Segment not found: {name}"),
            Self::SegmentTooSmall { actual, expected } => write!(
                f,
                "shared-memory segment is {actual} bytes but the mapping needs {expected}; \
                 refusing rather than risking SIGBUS past the end of the object"
            ),
            Self::InvalidCapacity(cap) => {
                write!(f, "Invalid ring capacity: {cap} (must be power of 2)")
            }
        }
    }
}

impl std::error::Error for ShmError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::SegmentCreate(e) | Self::SegmentOpen(e) | Self::Mmap(e) => Some(e),
            _ => None,
        }
    }
}

/// Result type for SHM operations
pub type Result<T> = std::result::Result<T, ShmError>;

/// Generate deterministic SHM segment name for a writer
///
/// Format: `/hdds_d{domain}_w{writer_guid_hex}`
///
/// This naming scheme allows readers to reconstruct the segment name
/// from discovery information without coordination.
#[must_use]
pub fn segment_name(domain_id: u32, writer_guid: &[u8; 16]) -> String {
    let guid_hex: String = writer_guid.iter().map(|b| format!("{b:02x}")).collect();
    format!("/hdds_d{domain_id}_w{guid_hex}")
}

/// Identity of the namespaces that decide whether two processes can actually
/// see the same POSIX shared-memory objects, or `None` when that cannot be
/// established.
///
/// `/etc/machine-id` alone is NOT enough to conclude co-location, and the
/// failure mode is not theoretical: two containers started from the SAME
/// image carry the SAME baked-in `/etc/machine-id`, so a machine-id-only
/// host id makes them agree they are co-located. Without `--ipc=host` they
/// are not: each gets its own IPC namespace and its own `/dev/shm` tmpfs, so
/// `shm_open` on the writer's segment name opens nothing (or, worse, a
/// same-named segment belonging to an unrelated writer inside the reader's
/// own namespace). Both sides would then declare SHM and move no data.
///
/// Two links are read, not one:
///
/// * `/proc/self/ns/ipc` -- the lever Docker's `--ipc` flag moves. Sharing it
///   is what "these containers were told to share IPC" means.
/// * `/proc/self/ns/mnt` -- POSIX shared memory objects are files in the
///   `/dev/shm` tmpfs, and which `/dev/shm` a process sees is a property of
///   its mount namespace, not its IPC namespace. Including it can only turn
///   a would-be false positive into a false negative (SHM declined, UDP
///   used), which is the safe direction.
///
/// Returns `None` when either link cannot be read. A `None` here means
/// co-location is UNPROVABLE, and every SHM gate below then refuses SHM
/// rather than guessing (see [`colocation_is_provable`]).
fn namespace_tag() -> Option<&'static str> {
    use std::sync::OnceLock;
    static TAG: OnceLock<Option<String>> = OnceLock::new();
    TAG.get_or_init(|| {
        let ipc = std::fs::read_link("/proc/self/ns/ipc").ok()?;
        let mnt = std::fs::read_link("/proc/self/ns/mnt").ok()?;
        Some(format!(
            "{}|{}",
            ipc.to_string_lossy(),
            mnt.to_string_lossy()
        ))
    })
    .as_deref()
}

/// Whether this process can PROVE which shared-memory realm it lives in.
///
/// False when `/proc/self/ns/ipc` or `/proc/self/ns/mnt` cannot be read (no
/// `/proc` mounted, a sandbox that hides it). SHM is then refused outright:
/// a shared-memory transport that cannot establish co-location is a silent
/// false positive waiting to happen, and UDP always works.
#[must_use]
pub fn colocation_is_provable() -> bool {
    namespace_tag().is_some()
}

/// Generate host ID from machine identifier and shared-memory realm.
///
/// On Linux, reads `/etc/machine-id` and hashes it, then folds in the IPC
/// and mount namespace identities (see [`namespace_tag`]). Falls back to
/// hostname hash if machine-id is unavailable.
///
/// This narrows candidates; it does NOT prove two processes share a
/// `/dev/shm`. Namespace inode numbers carry no entropy BETWEEN hosts: two
/// different physical machines can report the identical
/// `/proc/self/ns/ipc` value `ipc:[4026531839]`, because
/// an un-containerized process's init namespace gets the same low inode on
/// most kernels regardless of which machine it boots on. Two cloned VM
/// images share `/etc/machine-id` on top of that. So two processes CAN agree
/// on this value while unable to reach the same `/dev/shm` at all.
/// Every caller of `host_id()` for a co-location DECISION
/// (as opposed to a display string) must also require a matching
/// [`local_nonce`]/announced peer nonce (see [`nonce_is_trustworthy`],
/// [`parse_shm_nonce`]) ahead of comparing this value, and the only actual
/// PROOF is a nonce-authenticated segment attach
/// (`ShmSlot::owner_matches`), which reads bytes the peer physically wrote.
///
/// When the namespaces cannot be read the machine-only hash is returned, but
/// [`colocation_is_provable`] is then false and no SHM gate accepts it.
#[must_use]
pub fn host_id() -> u32 {
    use std::sync::OnceLock;
    static HOST_ID: OnceLock<u32> = OnceLock::new();
    *HOST_ID.get_or_init(|| {
        let machine = std::fs::read_to_string("/etc/machine-id")
            .map(|content| content.trim().to_string())
            .or_else(|_| std::env::var("HOSTNAME"))
            // Last resort: use a fixed value (single-host scenario)
            // @audit-ok: fallback constant when /etc/machine-id and HOSTNAME are unavailable
            .unwrap_or_else(|_| "0xDEADBEEF".to_string());
        match namespace_tag() {
            Some(tag) => hash_string(&format!("{machine}|{tag}")),
            None => hash_string(&machine),
        }
    })
}

/// This process's shared-memory nonce: the secret that proves a segment was
/// created by the participant that announced it.
///
/// Without it a segment is authenticated by nothing. `/dev/shm` is typically
/// mode 1777 and the segment name derives from the domain id plus the writer
/// GUID, both of which are broadcast in discovery, so any local process can
/// create the name first and push arbitrary DATA into it. The reader would
/// forward those samples to the Router stamped with the legitimate peer's real
/// unicast locator, which is exactly the identity every per-peer check
/// upstream relies on.
///
/// So the participant draws a nonce once, publishes it in its shared-memory
/// capability alongside the host id, and writes it into every segment its
/// writers create. A reader refuses a segment whose nonce does not match the
/// one the peer announced in discovery. An attacker who cannot read the
/// discovery traffic cannot produce it; one who can read the traffic is
/// already inside the domain, which is what DDS Security is for.
///
/// Per process, not per writer: it identifies the participant, and one
/// participant's writers all share it.
#[must_use]
pub fn local_nonce() -> u64 {
    use std::sync::OnceLock;
    static NONCE: OnceLock<u64> = OnceLock::new();
    *NONCE.get_or_init(|| {
        let mut buf = [0u8; 8];
        // SAFETY: `getrandom` fills at most `buf.len()` bytes into a buffer we
        // own. A short or failed read falls through to the /dev/urandom path
        // below rather than being trusted.
        let got = unsafe { libc::getrandom(buf.as_mut_ptr().cast::<libc::c_void>(), buf.len(), 0) };
        if got == buf.len() as isize {
            return u64::from_le_bytes(buf);
        }
        if let Ok(bytes) = std::fs::read("/dev/urandom") {
            // `read` on /dev/urandom returns as much as the reader asked for;
            // take the first 8 bytes when there are 8 to take.
            if bytes.len() >= 8 {
                buf.copy_from_slice(&bytes[..8]);
                return u64::from_le_bytes(buf);
            }
        }
        // Neither source answered. Refuse to invent a nonce that looks
        // random but is not: zero is the one value `nonce_is_trustworthy`
        // treats as "no nonce", which makes every SHM gate decline rather
        // than authenticate a segment on a guessable secret.
        log::error!(
            "[SHM] no source of randomness for the segment nonce; shared memory will be \
             declined for every peer rather than run unauthenticated."
        );
        0
    })
}

/// Whether this process drew a usable nonce. False disables SHM outright:
/// an unauthenticated segment is worse than a UDP leg that always works.
#[must_use]
pub fn nonce_is_trustworthy() -> bool {
    local_nonce() != 0
}

/// Simple FNV-1a hash for strings
fn hash_string(s: &str) -> u32 {
    let mut hash: u32 = 2_166_136_261;
    for byte in s.bytes() {
        hash ^= u32::from(byte);
        hash = hash.wrapping_mul(16_777_619);
    }
    hash
}

/// Parse SHM capability from user_data string
///
/// Expected format: `shm=1;host_id=XXXXXXXX;v=1`
///
/// Returns `Some((host_id, version))` if SHM is supported, `None` otherwise.
#[must_use]
pub fn parse_shm_user_data(user_data: &str) -> Option<(u32, u32)> {
    let mut shm_enabled = false;
    let mut parsed_host_id = None;
    let mut version = 1u32;

    for part in user_data.split(';') {
        let mut kv = part.splitn(2, '=');
        match (kv.next(), kv.next()) {
            (Some("shm"), Some("1")) => shm_enabled = true,
            (Some("host_id"), Some(v)) => {
                parsed_host_id = u32::from_str_radix(v, 16).ok();
            }
            (Some("v"), Some(v)) => {
                version = v.parse().unwrap_or(1);
            }
            _ => {}
        }
    }

    if shm_enabled {
        parsed_host_id.map(|h| (h, version))
    } else {
        None
    }
}

/// Format SHM capability for user_data announcement
#[must_use]
pub fn format_shm_user_data() -> String {
    format!(
        "shm=1;host_id={:08x};nonce={:016x};v=1",
        host_id(),
        local_nonce()
    )
}

/// The `nonce` a peer announced in its shared-memory capability, if any.
///
/// `None` for a peer that predates the field or drew no usable randomness.
/// A reader with no expected nonce refuses to attach: an unauthenticated
/// segment is exactly what this field exists to stop, and the UDP leg is a
/// complete answer.
#[must_use]
pub fn parse_shm_nonce(user_data: &str) -> Option<u64> {
    for part in user_data.split(';') {
        let mut kv = part.splitn(2, '=');
        if let (Some("nonce"), Some(v)) = (kv.next(), kv.next()) {
            return u64::from_str_radix(v, 16).ok().filter(|n| *n != 0);
        }
    }
    None
}

/// Check if SHM transport can be used for a remote endpoint.
///
/// SHM is only usable when:
/// 1. Remote endpoint advertises `shm=1` in user_data
/// 2. Both endpoints use `BestEffort` reliability (SHM doesn't support retransmission)
/// 3. This process drew a trustworthy nonce AND the remote announced one (a
///    NECESSARY precondition for the attach to ever succeed -- see below)
/// 4. Remote `host_id` matches local `host_id` (same machine)
///
/// # host_id is a filter, not proof
///
/// Steps 1-2-4 are an inference-based check:
/// two integers agreeing does not mean the two processes can reach the
/// same `/dev/shm` (see [`host_id`]'s doc for the measured counter-example).
/// Step 3 is checked BEFORE the host_id comparison on purpose: a peer that
/// announced no usable nonce can never pass the nonce-authenticated attach
/// (`ShmSlot::owner_matches`) regardless of what `host_id` says, so
/// refusing here -- instead of granting a verdict that queues a guaranteed-
/// to-fail attach for `ATTACH_BUDGET` -- is strictly more honest and cheaper.
/// This function still does NOT prove co-location by itself: it decides
/// whether SHM is even worth PROPOSING. The proof is the attach.
///
/// # Arguments
///
/// * `remote_user_data` - The user_data string from SEDP
/// * `local_reliability_best_effort` - Whether local endpoint uses BestEffort
/// * `remote_reliability_best_effort` - Whether remote endpoint uses BestEffort
///
/// # Returns
///
/// * `Some(host_id)` if SHM is worth proposing (still unproven; the reader's
///   later nonce-authenticated attach is what actually proves co-location,
///   and a peer that fails it stays on UDP -- see `transport/shm/receiver.rs`)
/// * `None` if SHM should not even be proposed (fallback to UDP)
#[must_use]
pub fn can_use_shm_transport(
    remote_user_data: Option<&str>,
    local_reliability_best_effort: bool,
    remote_reliability_best_effort: bool,
) -> Option<u32> {
    // Gate 0a: the engine must actually have an SHM leg to hand a sample to.
    // Flipping `shm_data_path_is_wired` back to false disables SHM selection
    // everywhere in one edit, without touching any caller.
    if !shm_data_path_is_wired() {
        return None;
    }

    // Gate 0b: refuse SHM when this process cannot even read its own
    // namespace identity (see `colocation_is_provable`). This is a sanity
    // check on the LOCAL process, not a co-location proof -- see the nonce
    // gate below and `host_id`'s doc for why the identity itself is not one
    // either.
    if !colocation_is_provable() {
        return None;
    }

    // Gate 1: Both must be BestEffort
    if !local_reliability_best_effort || !remote_reliability_best_effort {
        return None;
    }

    // Gate 2: Remote must advertise SHM
    let remote_data = remote_user_data?;
    let (remote_host_id, _version) = parse_shm_user_data(remote_data)?;

    // Gate 3: nonce capability, checked AHEAD of the host_id
    // comparison. Neither side proves anything by drawing a nonce, but
    // WITHOUT one on both sides the attach that would actually prove
    // co-location can never succeed, so there is no point granting a
    // verdict that only wastes the reader's attach-retry budget before
    // falling back to UDP anyway.
    if !nonce_is_trustworthy() {
        log::debug!(
            "[SHM] declining to propose shared memory: this process drew no trustworthy nonce, \
             so a segment it creates could never be authenticated by a peer; staying on UDP"
        );
        return None;
    }
    if parse_shm_nonce(remote_data).is_none() {
        log::debug!(
            "[SHM] declining to propose shared memory for remote host_id={remote_host_id:08x}: \
             it announced no usable nonce, so this reader could never authenticate its segment; \
             staying on UDP for this pairing"
        );
        return None;
    }

    // Gate 4: host_id agreement. A necessary filter (it rules out the common
    // case of genuinely different machine identities), never sufficient by
    // itself -- see `host_id`'s doc. The actual proof is the nonce-
    // authenticated attach this verdict merely permits attempting.
    let local_host = host_id();
    if remote_host_id != local_host {
        return None;
    }

    Some(remote_host_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_segment_name() {
        let guid = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10,
        ];
        let name = segment_name(42, &guid);
        assert_eq!(name, "/hdds_d42_w0102030405060708090a0b0c0d0e0f10");
    }

    #[test]
    fn test_parse_shm_user_data_valid() {
        let data = "shm=1;host_id=deadbeef;v=1";
        let result = parse_shm_user_data(data);
        // @audit-ok: expected parse result matching "deadbeef" string above
        assert_eq!(result, Some((0xDEAD_BEEF, 1)));
    }

    #[test]
    fn test_parse_shm_user_data_no_shm() {
        let data = "host_id=deadbeef;v=1";
        let result = parse_shm_user_data(data);
        assert_eq!(result, None);
    }

    #[test]
    fn test_parse_shm_user_data_shm_disabled() {
        let data = "shm=0;host_id=deadbeef";
        let result = parse_shm_user_data(data);
        assert_eq!(result, None);
    }

    #[test]
    fn test_format_shm_user_data() {
        let data = format_shm_user_data();
        assert!(data.starts_with("shm=1;host_id="));
        assert!(data.ends_with(";v=1"));
    }

    #[test]
    fn test_host_id_deterministic() {
        let id1 = host_id();
        let id2 = host_id();
        assert_eq!(id1, id2);
    }

    /// `host_id()` agreement is an INFERENCE (folded `/etc/machine-id`
    /// and namespace identities), never a proof -- two different physical
    /// hosts can share the exact same `/proc/self/ns/ipc` inode
    /// (`ipc:[4026531839]` on un-containerized hosts). This test
    /// cannot construct two genuinely non-co-located peers that agree on
    /// `host_id()`: it is a per-process `OnceLock` seeded from this
    /// machine's own identity, so a real cross-host collision is not
    /// reachable from inside one test binary. The closest honest proof
    /// available here is this: a `remote_user_data` string with a correct
    /// `host_id` and no `nonce` field must NOT be granted an SHM verdict,
    /// because host_id is a filter, not proof, and only a nonce-authenticated
    /// attach (see `ring_test.rs`) can actually verify a peer can read what
    /// this process wrote.
    ///
    /// host_id agreement alone must not be treated as sufficient: the verdict
    /// is `None`.
    #[test]
    fn same_host_id_without_a_nonce_is_not_enough_for_shm() {
        let user_data = format!("shm=1;host_id={:08x};v=1", host_id());
        let result = can_use_shm_transport(Some(&user_data), true, true);
        assert!(
            result.is_none(),
            "a peer that announced no nonce must never be handed an SHM verdict, even when \
             host_id matches: host_id narrows candidates, it does not prove co-location"
        );
    }

    /// The positive counterpart: a matching host_id WITH a trustworthy,
    /// announced nonce still passes (this is what
    /// `test_can_use_shm_same_host_best_effort` below also exercises via
    /// `format_shm_user_data`, kept here to make the gate ORDER explicit --
    /// nonce is checked, then host_id, and both must hold).
    #[test]
    fn matching_host_id_with_a_nonce_still_grants_shm() {
        let user_data = format_shm_user_data();
        let result = can_use_shm_transport(Some(&user_data), true, true);
        assert_eq!(result, Some(host_id()));
    }

    /// A remote that matches on `host_id` but announced an untrustworthy
    /// (zero) nonce is refused, same as announcing none at all --
    /// `parse_shm_nonce` already treats zero as "no nonce"
    /// (`nonce_is_trustworthy` mirrors it for the local side).
    #[test]
    fn matching_host_id_with_a_zero_nonce_is_refused() {
        let user_data = format!("shm=1;host_id={:08x};nonce=0000000000000000;v=1", host_id());
        let result = can_use_shm_transport(Some(&user_data), true, true);
        assert!(result.is_none());
    }

    // ===== SEDP Integration Tests =====

    #[test]
    fn test_can_use_shm_same_host_best_effort() {
        // Same host, both BestEffort, a real (trustworthy) announced nonce
        // -> SHM OK. `format_shm_user_data` is what a real peer announces:
        // host_id alone (see `same_host_id_without_a_nonce_is_not_enough_for_shm`
        // above) is not enough by itself.
        let local_host = host_id();
        let user_data = format_shm_user_data();

        let result = can_use_shm_transport(Some(&user_data), true, true);
        assert!(result.is_some());
        assert_eq!(result.unwrap(), local_host);
    }

    #[test]
    fn test_can_use_shm_different_host() {
        // Different host -> No SHM
        let user_data = "shm=1;host_id=deadbeef;v=1"; // Different from local

        // Only works if local host_id happens to be 0xdeadbeef (unlikely)
        let result = can_use_shm_transport(Some(user_data), true, true);
        // @audit-ok: guard against unlikely collision with test sentinel
        if host_id() != 0xDEAD_BEEF {
            assert!(result.is_none());
        }
    }

    #[test]
    fn test_can_use_shm_reliable_qos_forces_udp() {
        // Same host but Reliable QoS -> No SHM
        let local_host = host_id();
        let user_data = format!("shm=1;host_id={:08x};v=1", local_host);

        // Local Reliable -> No SHM
        let result = can_use_shm_transport(Some(&user_data), false, true);
        assert!(result.is_none());

        // Remote Reliable -> No SHM
        let result = can_use_shm_transport(Some(&user_data), true, false);
        assert!(result.is_none());

        // Both Reliable -> No SHM
        let result = can_use_shm_transport(Some(&user_data), false, false);
        assert!(result.is_none());
    }

    #[test]
    fn test_can_use_shm_no_user_data() {
        // No user_data -> No SHM
        let result = can_use_shm_transport(None, true, true);
        assert!(result.is_none());
    }

    #[test]
    fn test_can_use_shm_no_shm_capability() {
        // user_data without shm=1 -> No SHM
        let user_data = "other=value;foo=bar";
        let result = can_use_shm_transport(Some(user_data), true, true);
        assert!(result.is_none());
    }

    #[test]
    fn test_sedp_roundtrip_user_data() {
        // Test that format/parse are symmetric
        let formatted = format_shm_user_data();
        let parsed = parse_shm_user_data(&formatted);

        assert!(parsed.is_some());
        let (parsed_host_id, parsed_version) = parsed.unwrap();
        assert_eq!(parsed_host_id, host_id());
        assert_eq!(parsed_version, 1);
    }
}
