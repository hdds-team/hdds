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
//! # Latency Target
//!
//! - Writer push: < 200 ns
//! - Reader poll: < 100 ns
//! - End-to-end (with wake): < 1 us

mod futex;
mod integration;
mod metrics;
mod notify;
mod policy;
mod ring;
mod segment;
mod slot;

pub use futex::{futex_wait, futex_wake};
pub use integration::{
    ShmReaderTransport, ShmTransportRegistry, ShmWriterInfo, ShmWriterTransport,
};
pub use metrics::{global_metrics, ShmMetrics, ShmMetricsSnapshot};
pub use notify::{NotifyBucket, TopicNotify};
pub use policy::{select_transport, ShmPolicy, TransportSelection, TransportSelectionError};
pub use ring::{ShmRingReader, ShmRingWriter};
pub use segment::{cleanup_domain_segments, cleanup_stale_segments, ShmSegment};
pub use slot::{ShmControl, ShmSlot, SLOT_PAYLOAD_SIZE};

use std::fmt;
use std::io;

/// Default ring capacity (must be power of 2)
pub const DEFAULT_RING_CAPACITY: usize = 256;

/// Default slot payload size (4KB - fits most DDS samples)
pub const DEFAULT_SLOT_PAYLOAD_SIZE: usize = 4096;

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

/// Generate host ID from machine identifier
///
/// On Linux, reads `/etc/machine-id` and hashes it.
/// Falls back to hostname hash if machine-id is unavailable.
#[must_use]
pub fn host_id() -> u32 {
    // Try /etc/machine-id first (Linux)
    if let Ok(content) = std::fs::read_to_string("/etc/machine-id") {
        return hash_string(content.trim());
    }

    // Fallback to hostname
    if let Ok(hostname) = std::env::var("HOSTNAME") {
        return hash_string(&hostname);
    }

    // Last resort: use a fixed value (single-host scenario)
    0xDEAD_BEEF
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
    format!("shm=1;host_id={:08x};v=1", host_id())
}

/// Check if SHM transport can be used for a remote endpoint.
///
/// SHM is only usable when:
/// 1. Remote endpoint advertises `shm=1` in user_data
/// 2. Remote `host_id` matches local `host_id` (same machine)
/// 3. Both endpoints use `BestEffort` reliability (SHM doesn't support retransmission)
///
/// # Arguments
///
/// * `remote_user_data` - The user_data string from SEDP
/// * `local_reliability_best_effort` - Whether local endpoint uses BestEffort
/// * `remote_reliability_best_effort` - Whether remote endpoint uses BestEffort
///
/// # Returns
///
/// * `Some(host_id)` if SHM can be used
/// * `None` if SHM should not be used (fallback to UDP)
#[must_use]
pub fn can_use_shm_transport(
    remote_user_data: Option<&str>,
    local_reliability_best_effort: bool,
    remote_reliability_best_effort: bool,
) -> Option<u32> {
    // Gate 1: Both must be BestEffort
    if !local_reliability_best_effort || !remote_reliability_best_effort {
        return None;
    }

    // Gate 2: Remote must advertise SHM
    let remote_data = remote_user_data?;
    let (remote_host_id, _version) = parse_shm_user_data(remote_data)?;

    // Gate 3: Must be same host
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

    // ===== SEDP Integration Tests =====

    #[test]
    fn test_can_use_shm_same_host_best_effort() {
        // Same host, both BestEffort -> SHM OK
        let local_host = host_id();
        let user_data = format!("shm=1;host_id={:08x};v=1", local_host);

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
