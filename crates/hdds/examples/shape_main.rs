// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com
//
// OMG DDS-RTPS Interoperability Test - shape_main
//
// HDDS implementation of the shape_main application used by the OMG DDS-RTPS
// interoperability test suite (https://github.com/omg-dds/dds-rtps).
//
// It prints specific strings on stdout that the Python test harness (pexpect)
// matches to determine test pass/fail. These strings MUST NOT be modified.
//
// Build: cargo build --example shape_main --release
// Rename: cp target/release/examples/shape_main hdds_<version>_shape_main_linux

#![allow(clippy::all, unused_imports, unused_assignments)]

use hdds::core::discovery::multicast::{DiscoveryListener, EndpointInfo, EndpointKind};
use hdds::core::ser::{Cdr2Decode, Cdr2Encode, CdrError};
use hdds::core::types::{FieldLayout, FieldType, PrimitiveKind, TypeDescriptor};
use hdds::dds::listener::*;
use hdds::dds::DDS;
use hdds::{Participant, QoS, TransportMode};

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

// ---------------------------------------------------------------------------
// Global signal flag
// ---------------------------------------------------------------------------
static ALL_DONE: AtomicBool = AtomicBool::new(false);
static PROCESS_START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();

fn install_signal_handlers() {
    unsafe {
        libc::signal(libc::SIGINT, sigint_handler as libc::sighandler_t);
    }
}

extern "C" fn sigint_handler(_sig: libc::c_int) {
    ALL_DONE.store(true, Ordering::SeqCst);
}

// ---------------------------------------------------------------------------
// MatchNotifier — bridges SEDP discovery to DDS listener callbacks
//
// Registered as a DiscoveryListener on the participant FSM. When a remote
// Reader is discovered for a topic we publish on, prints
// "on_publication_matched()" which the pexpect harness requires.
// When a remote Writer is discovered for a topic we subscribe to, prints
// "on_subscription_matched()".
// ---------------------------------------------------------------------------
/// Local endpoint info stored in MatchNotifier for QoS compatibility checking.
#[derive(Clone)]
struct LocalEndpoint {
    topic: String,
    qos: QoS,
    data_repr: DataRepresentation,
}

struct MatchNotifier {
    /// Topics we are PUBLISHING on (writer side)
    writer_endpoints: Mutex<Vec<LocalEndpoint>>,
    /// Topics we are SUBSCRIBING to (reader side)
    reader_endpoints: Mutex<Vec<LocalEndpoint>>,
    /// Our own GUID prefix (first 12 bytes) to ignore self-discovery
    local_prefix: [u8; 12],
    /// Discovery FSM for catch-up queries on already-discovered endpoints
    discovery_fsm: Option<Arc<hdds::core::discovery::multicast::DiscoveryFsm>>,
    /// Topics where QoS incompatibility was detected (suppress data output)
    incompatible_topics: Arc<Mutex<std::collections::HashSet<String>>>,
}

impl MatchNotifier {
    fn new(
        local_prefix: [u8; 12],
        fsm: Option<Arc<hdds::core::discovery::multicast::DiscoveryFsm>>,
    ) -> Self {
        Self {
            writer_endpoints: Mutex::new(Vec::new()),
            reader_endpoints: Mutex::new(Vec::new()),
            local_prefix,
            discovery_fsm: fsm,
            incompatible_topics: Arc::new(Mutex::new(std::collections::HashSet::new())),
        }
    }

    fn mark_incompatible(&self, topic: &str) {
        self.incompatible_topics
            .lock()
            .unwrap()
            .insert(topic.to_string());
    }

    fn add_writer_topic(&self, topic: String, qos: QoS, data_repr: DataRepresentation) {
        let ep = LocalEndpoint {
            topic: topic.clone(),
            qos: qos.clone(),
            data_repr,
        };
        self.writer_endpoints.lock().unwrap().push(ep.clone());

        // Catch-up: check already-discovered remote readers for incompatibility only.
        // Match notifications come from on_endpoint_discovered (DiscoveryListener) to avoid
        // false matches from stale SPDP entries of previous processes on the same domain.
        if let Some(ref fsm) = self.discovery_fsm {
            for remote in fsm.find_readers_for_topic(&topic) {
                let remote_prefix = &remote.endpoint_guid.as_bytes()[..12];
                if remote_prefix == &self.local_prefix {
                    continue;
                }
                // v250: Skip endpoints from unconfirmed participants (stale
                // SPDP/SEDP from killed processes). Belt-and-suspenders with
                // the probation purge in DiscoveryFsm::handle_spdp.
                if !fsm.is_endpoint_participant_confirmed(&remote.endpoint_guid) {
                    continue;
                }
                let remote_repr = infer_data_repr_from_qos(&remote.qos);
                if let Some(policy) = Self::check_writer_reader_compat(
                    &ep.qos,
                    ep.data_repr,
                    &remote.qos,
                    remote_repr,
                    true, // local writer: ownership always explicit
                    true, // local writer: strength always known
                ) {
                    if policy != "PARTITION" {
                        self.mark_incompatible(&ep.topic);
                        println!(
                            "on_offered_incompatible_qos() topic: '{}' policy: {}",
                            ep.topic, policy
                        );
                    }
                }
                // Note: compatible matches are NOT printed here to avoid stale false-positives.
                // They will be printed by on_endpoint_discovered when a real match occurs.
            }
        }
    }

    fn add_reader_topic(&self, topic: String, qos: QoS, data_repr: DataRepresentation) {
        let ep = LocalEndpoint {
            topic: topic.clone(),
            qos: qos.clone(),
            data_repr,
        };
        self.reader_endpoints.lock().unwrap().push(ep.clone());

        // Catch-up: check if there are already-discovered remote writers for this topic
        if let Some(ref fsm) = self.discovery_fsm {
            for remote in fsm.find_writers_for_topic(&topic) {
                let remote_prefix = &remote.endpoint_guid.as_bytes()[..12];
                if remote_prefix == &self.local_prefix {
                    continue;
                }
                // v250: Skip endpoints from unconfirmed participants.
                if !fsm.is_endpoint_participant_confirmed(&remote.endpoint_guid) {
                    continue;
                }
                let remote_repr = infer_data_repr_from_qos(&remote.qos);
                match Self::check_writer_reader_compat(
                    &remote.qos,
                    remote_repr,
                    &ep.qos,
                    ep.data_repr,
                    remote.has_explicit_ownership,
                    remote.has_ownership_strength,
                ) {
                    Some("PARTITION") => {
                        // Partition mismatch = no match, silent (not incompatible QoS)
                    }
                    Some(policy) => {
                        self.mark_incompatible(&ep.topic);
                        println!(
                            "on_requested_incompatible_qos() topic: '{}' policy: {}",
                            ep.topic, policy
                        );
                    }
                    None => {
                        println!(
                            "on_subscription_matched() topic: '{}'  type: '{}' : matched writers 1 (change = 1)",
                            ep.topic, remote.type_name
                        );
                    }
                }
            }
        }
    }

    /// Check QoS compatibility between a writer and a reader.
    /// Returns None if compatible, Some(policy_name) if incompatible.
    /// "PARTITION" means endpoints don't match at all (no notification).
    /// Other policies trigger on_*_incompatible_qos() notifications.
    fn check_writer_reader_compat(
        writer_qos: &QoS,
        _writer_repr: DataRepresentation,
        reader_qos: &QoS,
        _reader_repr: DataRepresentation,
        writer_has_explicit_ownership: bool,
        writer_has_ownership_strength: bool,
    ) -> Option<&'static str> {
        // Data representation compatibility check.
        // Only check when BOTH sides explicitly advertise data_representation
        // via PID_DATA_REPRESENTATION in SEDP. Empty = "not restricted" or
        // "not advertised" — always compatible to avoid false rejections
        // (vendors often omit PID_DATA_REPRESENTATION even when using XCDR2).
        if !writer_qos.data_representation.is_empty() && !reader_qos.data_representation.is_empty()
        {
            let has_common = writer_qos
                .data_representation
                .iter()
                .any(|w| reader_qos.data_representation.contains(w));
            if !has_common {
                return Some("DATA_REPRESENTATION");
            }
        }

        // Reliability: BEST_EFFORT writer cannot match RELIABLE reader
        if writer_qos.reliability == hdds::dds::qos::Reliability::BestEffort
            && reader_qos.reliability == hdds::dds::qos::Reliability::Reliable
        {
            return Some("RELIABILITY");
        }
        // Ownership: infer writer ownership from SEDP PIDs.
        // PID_OWNERSHIP present -> use directly.
        // PID_OWNERSHIP absent + PID_OWNERSHIP_STRENGTH present -> EXCLUSIVE.
        // Both absent -> SHARED (DDS default, Sec.2.2.3).
        let inferred_writer_ownership = if writer_has_explicit_ownership {
            writer_qos.ownership.kind
        } else if writer_has_ownership_strength {
            hdds::qos::ownership::OwnershipKind::Exclusive
        } else {
            hdds::qos::ownership::OwnershipKind::Shared
        };
        if inferred_writer_ownership != reader_qos.ownership.kind {
            return Some("OWNERSHIP");
        }

        // Deadline: offered (writer) must be <= requested (reader).
        // Skip if either side uses the default (infinite) deadline — means "no constraint".
        let default_deadline = std::time::Duration::from_secs(u64::MAX);
        if writer_qos.deadline.period != default_deadline
            && reader_qos.deadline.period != default_deadline
            && writer_qos.deadline.period > reader_qos.deadline.period
        {
            return Some("DEADLINE");
        }
        // Durability: writer durability must be >= reader durability
        let w_dur = durability_rank(&writer_qos.durability);
        let r_dur = durability_rank(&reader_qos.durability);
        if w_dur < r_dur {
            return Some("DURABILITY");
        }
        // Partition: must have at least one common partition (with fnmatch wildcards)
        let w_default = writer_qos.partition.names.is_empty();
        let r_default = reader_qos.partition.names.is_empty();
        if w_default && r_default {
            // both default -> compatible
        } else if w_default || r_default {
            return Some("PARTITION");
        } else {
            let has_intersection = writer_qos.partition.names.iter().any(|w| {
                reader_qos
                    .partition
                    .names
                    .iter()
                    .any(|r| w == r || fnmatch_glob(w, r) || fnmatch_glob(r, w))
            });
            if !has_intersection {
                return Some("PARTITION");
            }
        }
        None
    }
}

/// Simple fnmatch-style glob: '*' matches any sequence, '?' matches one char.
fn fnmatch_glob(pattern: &str, text: &str) -> bool {
    let pat = pattern.as_bytes();
    let txt = text.as_bytes();
    let mut px = 0usize;
    let mut tx = 0usize;
    let mut star_px: Option<usize> = None;
    let mut star_tx: usize = 0;
    while tx < txt.len() {
        if px < pat.len() && (pat[px] == b'?' || pat[px] == txt[tx]) {
            px += 1;
            tx += 1;
        } else if px < pat.len() && pat[px] == b'*' {
            star_px = Some(px);
            star_tx = tx;
            px += 1;
        } else if let Some(spx) = star_px {
            px = spx + 1;
            star_tx += 1;
            tx = star_tx;
        } else {
            return false;
        }
    }
    while px < pat.len() && pat[px] == b'*' {
        px += 1;
    }
    px == pat.len()
}

/// Rank durability levels for compatibility checking.
fn durability_rank(d: &hdds::dds::qos::Durability) -> u8 {
    match d {
        hdds::dds::qos::Durability::Volatile => 0,
        hdds::dds::qos::Durability::TransientLocal => 1,
        hdds::dds::qos::Durability::Transient => 2,
        hdds::dds::qos::Durability::Persistent => 3,
    }
}

impl DiscoveryListener for MatchNotifier {
    fn on_endpoint_discovered(&self, endpoint: EndpointInfo) {
        // Ignore our own endpoints
        let ep_prefix = &endpoint.endpoint_guid.as_bytes()[..12];
        if ep_prefix == &self.local_prefix {
            return;
        }

        match endpoint.kind {
            EndpointKind::Reader => {
                // Remote reader discovered — check if we have a local writer on that topic
                let endpoints = self.writer_endpoints.lock().unwrap();
                for ep in endpoints.iter() {
                    if ep.topic == endpoint.topic_name {
                        let remote_repr = infer_data_repr_from_qos(&endpoint.qos);
                        match MatchNotifier::check_writer_reader_compat(
                            &ep.qos,
                            ep.data_repr,
                            &endpoint.qos,
                            remote_repr,
                            true, // local writer: ownership always explicit
                            true, // local writer: strength always known
                        ) {
                            Some("PARTITION") => {
                                // Partition mismatch = no match, silent (not incompatible QoS)
                            }
                            Some(policy) => {
                                self.mark_incompatible(&ep.topic);
                                println!(
                                    "on_offered_incompatible_qos() topic: '{}' policy: {}",
                                    ep.topic, policy
                                );
                            }
                            None => {
                                if self.incompatible_topics.lock().unwrap().contains(&ep.topic) {
                                    continue;
                                }
                                // v249: No deferral needed — stale endpoints are filtered
                                // at the library level (SEDP startup probation in DiscoveryFsm
                                // + blocked_writers in router).
                                println!(
                                    "on_publication_matched() topic: '{}'  type: '{}' : matched readers 1 (change = 1)",
                                    ep.topic, endpoint.type_name
                                );
                            }
                        }
                    }
                }
            }
            EndpointKind::Writer => {
                // Remote writer discovered — check if we have a local reader on that topic
                let endpoints = self.reader_endpoints.lock().unwrap();
                for ep in endpoints.iter() {
                    if ep.topic == endpoint.topic_name {
                        let remote_repr = infer_data_repr_from_qos(&endpoint.qos);
                        match MatchNotifier::check_writer_reader_compat(
                            &endpoint.qos,
                            remote_repr,
                            &ep.qos,
                            ep.data_repr,
                            endpoint.has_explicit_ownership,
                            endpoint.has_ownership_strength,
                        ) {
                            Some("PARTITION") => {
                                // Partition mismatch = no match, silent (not incompatible QoS)
                            }
                            Some(policy) => {
                                self.mark_incompatible(&ep.topic);
                                println!(
                                    "on_requested_incompatible_qos() topic: '{}' policy: {}",
                                    ep.topic, policy
                                );
                            }
                            None => {
                                println!(
                                    "on_subscription_matched() topic: '{}'  type: '{}' : matched writers 1 (change = 1)",
                                    ep.topic, endpoint.type_name
                                );
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Infer data representation from remote endpoint.
/// Since SEDP doesn't carry data_representation reliably for all vendors,
/// we cannot know the remote's XCDR version from discovery alone.
/// For self-interop (HDDS vs HDDS), both sides use the same shape_main,
/// so the -x flag controls this. For cross-vendor, we default to the
/// representation they announce or assume XCDR1.
fn infer_data_repr_from_qos(qos: &QoS) -> DataRepresentation {
    // Use data_representation from QoS if available (parsed from PID_DATA_REPRESENTATION in SEDP)
    if qos.data_representation.contains(&0x0002) && !qos.data_representation.contains(&0x0000) {
        DataRepresentation::Xcdr2
    } else {
        DataRepresentation::Xcdr1 // default or XCDR1 present
    }
}

// ---------------------------------------------------------------------------
// PRNG — xorshift64 with global state, seeded once
// FIX #1: the old version re-seeded from SystemTime on every call
// ---------------------------------------------------------------------------
static RNG_STATE: AtomicU64 = AtomicU64::new(0);

fn rng_seed_once() {
    use std::time::SystemTime;
    let seed = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    // Ensure non-zero seed
    RNG_STATE.store(if seed == 0 { 1 } else { seed }, Ordering::SeqCst);
}

fn rng_next_u32() -> u32 {
    loop {
        let old = RNG_STATE.load(Ordering::SeqCst);
        let mut x = old;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        if RNG_STATE
            .compare_exchange(old, x, Ordering::SeqCst, Ordering::Relaxed)
            .is_ok()
        {
            return x as u32;
        }
    }
}

// ---------------------------------------------------------------------------
// Verbosity — matches C++ ERROR/DEBUG levels
// FIX #12: was accepted but ignored
// ---------------------------------------------------------------------------
const VERBOSITY_ERROR: u8 = 1;
const VERBOSITY_DEBUG: u8 = 2;
static VERBOSITY: AtomicU8 = AtomicU8::new(VERBOSITY_ERROR);

fn log_debug(msg: &str) {
    if VERBOSITY.load(Ordering::Relaxed) >= VERBOSITY_DEBUG {
        println!("{}", msg);
    }
}

// ---------------------------------------------------------------------------
// ShapeType — IDL definition:
//
//   @appendable
//   struct ShapeType {
//     @key string<128> color;
//     int32 x;
//     int32 y;
//     int32 shapesize;
//     sequence<uint8> additional_payload_size;
//   };
// ---------------------------------------------------------------------------
#[derive(Debug, Clone)]
struct ShapeType {
    color: String,
    x: i32,
    y: i32,
    shapesize: i32,
    additional_payload_size: Vec<u8>,
}

impl Cdr2Encode for ShapeType {
    fn encode_cdr2_le(&self, dst: &mut [u8]) -> Result<usize, CdrError> {
        let mut offset: usize = 0;

        // DHEADER placeholder for @appendable (4 bytes LE, filled at end)
        if dst.len() < 4 {
            return Err(CdrError::BufferTooSmall);
        }
        let dheader_pos = offset;
        offset += 4;
        let payload_start = offset;

        // Field: color (string<128>) — CDR: 4-byte length (including NUL) + chars + NUL + padding
        let color_bytes = self.color.as_bytes();
        let str_len = color_bytes.len() + 1; // include NUL terminator
        if dst.len() < offset + 4 + str_len {
            return Err(CdrError::BufferTooSmall);
        }
        dst[offset..offset + 4].copy_from_slice(&(str_len as u32).to_le_bytes());
        offset += 4;
        dst[offset..offset + color_bytes.len()].copy_from_slice(color_bytes);
        offset += color_bytes.len();
        dst[offset] = 0; // NUL
        offset += 1;

        // Align to 4 bytes for x
        let padding = (4 - (offset % 4)) % 4;
        for i in 0..padding {
            dst[offset + i] = 0;
        }
        offset += padding;

        // Fields: x, y, shapesize (int32 each)
        if dst.len() < offset + 12 {
            return Err(CdrError::BufferTooSmall);
        }
        dst[offset..offset + 4].copy_from_slice(&self.x.to_le_bytes());
        offset += 4;
        dst[offset..offset + 4].copy_from_slice(&self.y.to_le_bytes());
        offset += 4;
        dst[offset..offset + 4].copy_from_slice(&self.shapesize.to_le_bytes());
        offset += 4;

        // Field: additional_payload_size (sequence<uint8>)
        let seq_len = self.additional_payload_size.len();
        if dst.len() < offset + 4 + seq_len {
            return Err(CdrError::BufferTooSmall);
        }
        dst[offset..offset + 4].copy_from_slice(&(seq_len as u32).to_le_bytes());
        offset += 4;
        if seq_len > 0 {
            dst[offset..offset + seq_len].copy_from_slice(&self.additional_payload_size);
            offset += seq_len;
        }

        // Fill DHEADER
        let payload_size = (offset - payload_start) as u32;
        dst[dheader_pos..dheader_pos + 4].copy_from_slice(&payload_size.to_le_bytes());

        Ok(offset)
    }

    fn max_cdr2_size(&self) -> usize {
        4 + // DHEADER
        4 + self.color.len() + 1 + 3 + // string with max padding
        12 + // x, y, shapesize
        4 + self.additional_payload_size.len() // sequence
    }

    // SAFETY: type has no internal alignment requirement that depends on
    // the global cursor — encode_cdr2_le emits its own DHEADER + per-field
    // alignment relative to local offset 0, byte-identical to what would
    // be emitted at the global *offset for the wire ranges this type
    // produces.
    fn encode_cdr2_le_at(&self, dst: &mut [u8], offset: &mut usize) -> Result<(), CdrError> {
        let len = self.encode_cdr2_le(&mut dst[*offset..])?;
        *offset += len;
        Ok(())
    }
}

impl ShapeType {
    /// CDR1 PLAIN_CDR_LE encoder (DDS-XTypes v1.3 §7.4.1.4).
    /// Differs from `encode_cdr2_le` only by omitting the DHEADER; per-field
    /// layout and 4-byte alignment rules are identical for this primitive
    /// struct.
    fn encode_cdr1_le(&self, dst: &mut [u8]) -> Result<usize, CdrError> {
        let mut offset: usize = 0;

        let color_bytes = self.color.as_bytes();
        let str_len = color_bytes.len() + 1;
        if dst.len() < offset + 4 + str_len {
            return Err(CdrError::BufferTooSmall);
        }
        dst[offset..offset + 4].copy_from_slice(&(str_len as u32).to_le_bytes());
        offset += 4;
        dst[offset..offset + color_bytes.len()].copy_from_slice(color_bytes);
        offset += color_bytes.len();
        dst[offset] = 0;
        offset += 1;

        let padding = (4 - (offset % 4)) % 4;
        for i in 0..padding {
            dst[offset + i] = 0;
        }
        offset += padding;

        if dst.len() < offset + 12 {
            return Err(CdrError::BufferTooSmall);
        }
        dst[offset..offset + 4].copy_from_slice(&self.x.to_le_bytes());
        offset += 4;
        dst[offset..offset + 4].copy_from_slice(&self.y.to_le_bytes());
        offset += 4;
        dst[offset..offset + 4].copy_from_slice(&self.shapesize.to_le_bytes());
        offset += 4;

        let seq_len = self.additional_payload_size.len();
        if dst.len() < offset + 4 + seq_len {
            return Err(CdrError::BufferTooSmall);
        }
        dst[offset..offset + 4].copy_from_slice(&(seq_len as u32).to_le_bytes());
        offset += 4;
        if seq_len > 0 {
            dst[offset..offset + seq_len].copy_from_slice(&self.additional_payload_size);
            offset += seq_len;
        }

        Ok(offset)
    }

    /// CDR1 PLAIN_CDR_LE decoder. Mirror of `decode_cdr2_le` minus the
    /// DHEADER skip — XCDR1 has no per-struct delimiter.
    fn decode_cdr1_le(src: &[u8]) -> Result<(Self, usize), CdrError> {
        let mut offset: usize = 0;

        if src.len() < offset + 4 {
            return Err(CdrError::UnexpectedEof);
        }
        let str_len = u32::from_le_bytes(src[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;
        if src.len() < offset + str_len {
            return Err(CdrError::UnexpectedEof);
        }
        let color_end = if str_len > 0 { str_len - 1 } else { 0 };
        let color = String::from_utf8_lossy(&src[offset..offset + color_end]).to_string();
        offset += str_len;

        offset = (offset + 3) & !3;

        if src.len() < offset + 12 {
            return Err(CdrError::UnexpectedEof);
        }
        let x = i32::from_le_bytes(src[offset..offset + 4].try_into().unwrap());
        offset += 4;
        let y = i32::from_le_bytes(src[offset..offset + 4].try_into().unwrap());
        offset += 4;
        let shapesize = i32::from_le_bytes(src[offset..offset + 4].try_into().unwrap());
        offset += 4;

        if src.len() < offset + 4 {
            return Err(CdrError::UnexpectedEof);
        }
        let seq_len = u32::from_le_bytes(src[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;
        let additional_payload_size = if seq_len > 0 {
            if src.len() < offset + seq_len {
                return Err(CdrError::UnexpectedEof);
            }
            let data = src[offset..offset + seq_len].to_vec();
            offset += seq_len;
            data
        } else {
            Vec::new()
        };

        Ok((
            ShapeType {
                color,
                x,
                y,
                shapesize,
                additional_payload_size,
            },
            offset,
        ))
    }
}

impl Cdr2Decode for ShapeType {
    fn decode_cdr2_le(src: &[u8]) -> Result<(Self, usize), CdrError> {
        let mut offset: usize = 0;

        // DHEADER detection for @appendable D_CDR2 encoding.
        // A DHEADER is a u32 size field covering the CDR2 data that follows.
        // Heuristic: first_u32 >= 16 (min CDR size for ShapeType) and
        // first_u32 + 4 fits within the payload. A CDR string length for
        // a color name would be < 16, so this distinguishes reliably.
        if src.len() < 4 {
            return Err(CdrError::UnexpectedEof);
        }
        let first_u32 = u32::from_le_bytes(src[0..4].try_into().unwrap());
        if first_u32 as usize >= 16 && (first_u32 as usize + 4) <= src.len() {
            // DHEADER present — skip it
            offset += 4;
        }

        // color (string)
        if src.len() < offset + 4 {
            return Err(CdrError::UnexpectedEof);
        }
        let str_len = u32::from_le_bytes(src[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;
        if src.len() < offset + str_len {
            return Err(CdrError::UnexpectedEof);
        }
        let color_end = if str_len > 0 { str_len - 1 } else { 0 };
        let color = String::from_utf8_lossy(&src[offset..offset + color_end]).to_string();
        offset += str_len;

        // Align to 4
        offset = (offset + 3) & !3;

        // x, y, shapesize
        if src.len() < offset + 12 {
            return Err(CdrError::UnexpectedEof);
        }
        let x = i32::from_le_bytes(src[offset..offset + 4].try_into().unwrap());
        offset += 4;
        let y = i32::from_le_bytes(src[offset..offset + 4].try_into().unwrap());
        offset += 4;
        let shapesize = i32::from_le_bytes(src[offset..offset + 4].try_into().unwrap());
        offset += 4;

        // additional_payload_size (sequence<uint8>)
        if src.len() < offset + 4 {
            return Err(CdrError::UnexpectedEof);
        }
        let seq_len = u32::from_le_bytes(src[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;
        let additional_payload_size = if seq_len > 0 {
            if src.len() < offset + seq_len {
                return Err(CdrError::UnexpectedEof);
            }
            let data = src[offset..offset + seq_len].to_vec();
            offset += seq_len;
            data
        } else {
            Vec::new()
        };

        Ok((
            ShapeType {
                color,
                x,
                y,
                shapesize,
                additional_payload_size,
            },
            offset,
        ))
    }

    fn decode_cdr2_le_at(src: &[u8], offset: &mut usize) -> Result<Self, CdrError> {
        let (value, consumed) = Self::decode_cdr2_le(&src[*offset..])?;
        *offset += consumed;
        Ok(value)
    }
}

impl ShapeType {
    /// CDR-serialize only the @key fields (color) for key hash computation.
    /// Compute the 16-byte instance key hash used in PID_KEY_HASH.
    ///
    /// RTPS v2.5 §9.6.3.8 allows two forms:
    ///   - If CDR-serialized key <= 16 bytes: place it directly, zero-pad.
    ///   - Otherwise: MD5 hash of the CDR-serialized key.
    ///
    /// HDDS previously used form #1 for short string keys (`BLUE` fits in
    /// 9 bytes). Connext and FastDDS subscribers do not recognise that
    /// form on the wire — they always expect form #2 (MD5) regardless of
    /// size, so HDDS pub -> Connext sub disposes were silently ignored,
    /// leaving FinalInstanceState tests stuck with `DATA_NOT_CORRECT`.
    /// Picking form #2 unconditionally is the conservative interop
    /// choice: it stays spec-compliant for keys of any length, and
    /// receivers that decode form #1 (HDDS itself) get the same answer
    /// via the learn-map fallback in `color_from_key_hash_with_map`.
    fn compute_key_hash(&self) -> [u8; 16] {
        let color_bytes = self.color.as_bytes();
        let str_len = (color_bytes.len() + 1) as u32; // including NUL
        let serialized_len = 4 + str_len as usize;

        let mut key_buf = vec![0u8; serialized_len];
        // RTPS 9.6.3.8: KeyHash uses CDR Big-Endian encapsulation
        key_buf[0..4].copy_from_slice(&str_len.to_be_bytes());
        key_buf[4..4 + color_bytes.len()].copy_from_slice(color_bytes);
        // NUL terminator already zero from vec![0u8; ...]

        md5_hash(&key_buf)
    }
}

/// Decode a ShapeType key hash back to the color string.
///
/// Two on-wire forms must be recognized so cross-vendor FinalInstanceState
/// dispose lines emit `Square <COLOR> NOT_ALIVE_*` rather than a raw hex
/// prefix (the harness compares the COLOR set, not the hex set).
///
/// 1. HDDS form: CDR Big-Endian of the serialized key, zero-padded to 16
///    bytes when it fits (string keys <= 11 chars + NUL).
/// 2. Connext form: MD5 of the CDR-BE serialized key, regardless of size
///    (observed on the wire as `cac217c3:18363f8e:...` in PID_KEY_HASH).
///
/// `known_colors` is the learned color set seen on the data path; we hash
/// each candidate string in both forms and pick the one whose digest
/// matches. Falls back to a hex prefix if no candidate matches (kept for
/// diagnostics and for keys that genuinely have no readable representation).
fn color_from_key_hash_with_map(key_hash: &[u8; 16], known_colors: &[String]) -> String {
    // Form 1: CDR-BE zero-padded short string.
    let str_len = u32::from_be_bytes([key_hash[0], key_hash[1], key_hash[2], key_hash[3]]) as usize;
    if str_len > 1 && str_len <= 12 && 4 + str_len <= 16 {
        let color_bytes = &key_hash[4..4 + str_len - 1];
        if let Ok(s) = std::str::from_utf8(color_bytes) {
            return s.to_string();
        }
    }
    // Form 2: try each learned color via the Connext MD5 hashing path.
    for color in known_colors {
        if compute_color_key_hash_md5(color) == *key_hash {
            return color.clone();
        }
    }
    // Unknown hash form — preserve hex for debug.
    format!(
        "{:02x}{:02x}{:02x}{:02x}",
        key_hash[0], key_hash[1], key_hash[2], key_hash[3]
    )
}

/// Compute the Connext-style key hash for a ShapeType color: MD5 of the
/// CDR-BE serialized key (`u32 BE length || bytes || NUL`). Matches the
/// PID_KEY_HASH values Connext emits for both per-instance dispose DATA
/// and SEDP DCPSPublication DATA (observed via tcpdump 2026-05-17).
fn compute_color_key_hash_md5(color: &str) -> [u8; 16] {
    let bytes = color.as_bytes();
    let str_len = (bytes.len() + 1) as u32; // include NUL
    let mut buf = vec![0u8; 4 + str_len as usize];
    buf[0..4].copy_from_slice(&str_len.to_be_bytes());
    buf[4..4 + bytes.len()].copy_from_slice(bytes);
    md5_hash(&buf)
}

/// Minimal MD5 for key hashing (only needed for color strings > 11 chars)
fn md5_hash(data: &[u8]) -> [u8; 16] {
    // Use the md-5 crate if available, otherwise fall back to a simple implementation
    // For now, this is a placeholder — HDDS already depends on md-5 (feature "xtypes")
    #[cfg(feature = "xtypes")]
    {
        use md5::{Digest, Md5};
        let mut hasher = Md5::new();
        hasher.update(data);
        let result = hasher.finalize();
        let mut out = [0u8; 16];
        out.copy_from_slice(&result);
        out
    }
    #[cfg(not(feature = "xtypes"))]
    {
        let _ = data;
        panic!(
            "MD5 key hash requires feature 'xtypes' (md-5 crate). \
                This only triggers for key fields > 12 bytes serialized."
        );
    }
}

impl DDS for ShapeType {
    fn type_descriptor() -> &'static TypeDescriptor {
        static DESC: TypeDescriptor = TypeDescriptor {
            type_id: 0x4A8A_B543, // FNV-1a of "ShapeType"
            type_name: "ShapeType",
            size_bytes: 0,
            alignment: 4,
            is_variable_size: true,
            fields: &[
                FieldLayout {
                    name: "color",
                    offset_bytes: 0,
                    field_type: FieldType::Sequence,
                    alignment: 4,
                    size_bytes: 0, // variable
                    element_type: None,
                },
                FieldLayout {
                    name: "x",
                    offset_bytes: 0, // variable due to color
                    field_type: FieldType::Primitive(PrimitiveKind::I32),
                    alignment: 4,
                    size_bytes: 4,
                    element_type: None,
                },
                FieldLayout {
                    name: "y",
                    offset_bytes: 0,
                    field_type: FieldType::Primitive(PrimitiveKind::I32),
                    alignment: 4,
                    size_bytes: 4,
                    element_type: None,
                },
                FieldLayout {
                    name: "shapesize",
                    offset_bytes: 0,
                    field_type: FieldType::Primitive(PrimitiveKind::I32),
                    alignment: 4,
                    size_bytes: 4,
                    element_type: None,
                },
            ],
        };
        &DESC
    }

    fn encode(&self, buf: &mut [u8], version: hdds::CdrVersion) -> hdds::dds::Result<usize> {
        let result = match version {
            hdds::CdrVersion::Xcdr1 => Self::encode_cdr1_le(self, buf),
            hdds::CdrVersion::Xcdr2 => self.encode_cdr2_le(buf),
        };
        result.map_err(|e| match e {
            CdrError::BufferTooSmall => hdds::Error::BufferTooSmall,
            _ => hdds::Error::SerializationError,
        })
    }

    fn decode(buf: &[u8], version: hdds::CdrVersion) -> hdds::dds::Result<Self> {
        let result = match version {
            hdds::CdrVersion::Xcdr1 => Self::decode_cdr1_le(buf).map(|(val, _)| val),
            hdds::CdrVersion::Xcdr2 => Self::decode_cdr2_le(buf).map(|(val, _)| val),
        };
        result.map_err(|_| hdds::Error::SerializationError)
    }

    fn compute_key(&self) -> [u8; 16] {
        self.compute_key_hash()
    }

    fn has_key() -> bool {
        true
    }

    fn encode_key(&self, _version: hdds::CdrVersion) -> Vec<u8> {
        // ShapeType has a single @key field (color, string<128>). Bound is
        // enforced at a UTF-8 character boundary so the truncated bytes still
        // form a valid string for strict deserializers. The full encode()
        // path uses D_CDR2_LE with a leading DHEADER so the key-only encoding
        // mirrors it. DDS-XTypes v1.3 §7.4.3.5.2 specifies DHEADER as the
        // length of the inner CDR data NOT including any RTPS submessage
        // alignment padding; the outer packet builder is responsible for
        // padding the SerializedPayload as a whole.
        let mut cutoff = self.color.len().min(128);
        while cutoff > 0 && !self.color.is_char_boundary(cutoff) {
            cutoff -= 1;
        }
        let color_bytes = &self.color.as_bytes()[..cutoff];
        let str_len = color_bytes.len() + 1;
        let inner_len = 4 + str_len;
        let dheader = inner_len as u32;
        let mut buf = Vec::with_capacity(4 + inner_len);
        buf.extend_from_slice(&dheader.to_le_bytes());
        buf.extend_from_slice(&(str_len as u32).to_le_bytes());
        buf.extend_from_slice(color_bytes);
        buf.push(0);
        buf
    }

    fn get_fields(&self) -> HashMap<String, hdds::dds::FieldValue> {
        let mut fields = HashMap::new();
        fields.insert(
            "color".to_string(),
            hdds::dds::FieldValue::String(self.color.clone()),
        );
        fields.insert("x".to_string(), hdds::dds::FieldValue::from_i32(self.x));
        fields.insert("y".to_string(), hdds::dds::FieldValue::from_i32(self.y));
        fields.insert(
            "shapesize".to_string(),
            hdds::dds::FieldValue::from_i32(self.shapesize),
        );
        fields
    }

    fn get_type_object() -> Option<hdds::xtypes::CompleteTypeObject> {
        use hdds::xtypes::*;
        Some(CompleteTypeObject::Struct(CompleteStructType {
            struct_flags: StructTypeFlag::IS_APPENDABLE,
            header: CompleteStructHeader {
                base_type: None,
                detail: CompleteTypeDetail::new("ShapeType"),
            },
            member_seq: vec![
                CompleteStructMember {
                    common: CommonStructMember {
                        member_id: 0,
                        member_flags: MemberFlag::IS_KEY,
                        member_type_id: TypeIdentifier::TK_STRING8,
                    },
                    detail: CompleteMemberDetail::new("color"),
                },
                CompleteStructMember {
                    common: CommonStructMember {
                        member_id: 1,
                        member_flags: MemberFlag::empty(),
                        member_type_id: TypeIdentifier::TK_INT32,
                    },
                    detail: CompleteMemberDetail::new("x"),
                },
                CompleteStructMember {
                    common: CommonStructMember {
                        member_id: 2,
                        member_flags: MemberFlag::empty(),
                        member_type_id: TypeIdentifier::TK_INT32,
                    },
                    detail: CompleteMemberDetail::new("y"),
                },
                CompleteStructMember {
                    common: CommonStructMember {
                        member_id: 3,
                        member_flags: MemberFlag::empty(),
                        member_type_id: TypeIdentifier::TK_INT32,
                    },
                    detail: CompleteMemberDetail::new("shapesize"),
                },
                // FIX #10: sequence<uint8> needs a proper sequence type identifier
                // For now, TK_UINT8 signals the element type; proper PlainSequenceSElemDefn
                // would be needed for strict XTypes implementations.
                CompleteStructMember {
                    common: CommonStructMember {
                        member_id: 4,
                        member_flags: MemberFlag::empty(),
                        member_type_id: TypeIdentifier::TK_UINT8,
                    },
                    detail: CompleteMemberDetail::new("additional_payload_size"),
                },
            ],
        }))
    }
}

// ---------------------------------------------------------------------------
// Enums for QoS options
// ---------------------------------------------------------------------------
#[derive(Debug, Clone, Copy, PartialEq)]
enum ReliabilityKind {
    BestEffort,
    Reliable,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum DurabilityKind {
    Volatile,
    TransientLocal,
    Transient,
    Persistent,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum DataRepresentation {
    Default, // No restriction — advertise both XCDR1 and XCDR2
    Xcdr1,
    Xcdr2,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum AccessScope {
    Instance,
    Topic,
    Group,
}

impl std::fmt::Display for ReliabilityKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BestEffort => write!(f, "BEST_EFFORT"),
            Self::Reliable => write!(f, "RELIABLE"),
        }
    }
}

impl std::fmt::Display for DurabilityKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Volatile => write!(f, "VOLATILE"),
            Self::TransientLocal => write!(f, "TRANSIENT_LOCAL"),
            Self::Transient => write!(f, "TRANSIENT"),
            Self::Persistent => write!(f, "PERSISTENT"),
        }
    }
}

impl std::fmt::Display for DataRepresentation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Default => write!(f, "DEFAULT"),
            Self::Xcdr1 => write!(f, "XCDR"),
            Self::Xcdr2 => write!(f, "XCDR2"),
        }
    }
}

// ---------------------------------------------------------------------------
// ShapeOptions — mirrors the C++ ShapeOptions exactly
// ---------------------------------------------------------------------------
struct ShapeOptions {
    domain_id: u32,
    reliability_kind: ReliabilityKind,
    durability_kind: DurabilityKind,
    data_representation: DataRepresentation,
    history_depth: i32,      // -1 = default, 0 = KEEP_ALL, >0 = KEEP_LAST(depth)
    ownership_strength: i32, // -1 = SHARED, >=0 = EXCLUSIVE with strength

    topic_name: Option<String>,
    color: Option<String>,
    partition: Option<String>,

    publish: bool,
    subscribe: bool,

    timebasedfilter_interval_ms: u32,
    deadline_interval_ms: u32,
    lifespan_ms: u32,

    da_width: i32,
    da_height: i32,

    shapesize: i32,

    print_writer_samples: bool,
    use_read: bool,

    write_period_ms: u32,
    read_period_ms: u32,

    num_iterations: u32,
    num_instances: u32,
    num_topics: u32,

    unregister: bool,
    dispose: bool,

    coherent_access_scope: AccessScope,
    coherent_access_scope_set: bool,
    coherent_set_enabled: bool,
    ordered_access_enabled: bool,
    coherent_set_sample_count: u32,

    additional_payload_size: u32,

    take_read_next_instance: bool,

    periodic_announcement_period_ms: u32,

    // FIX #8: was missing
    datafrag_size: u32,

    cft_expression: Option<String>,
    size_modulo: u32,
}

impl Default for ShapeOptions {
    fn default() -> Self {
        Self {
            domain_id: 0,
            reliability_kind: ReliabilityKind::Reliable,
            durability_kind: DurabilityKind::Volatile,
            data_representation: DataRepresentation::Default,
            history_depth: -1,
            ownership_strength: -1,
            topic_name: None,
            color: None,
            partition: None,
            publish: false,
            subscribe: false,
            timebasedfilter_interval_ms: 0,
            deadline_interval_ms: 0,
            lifespan_ms: 0,
            da_width: 240,
            da_height: 270,
            shapesize: 20,
            print_writer_samples: false,
            use_read: false,
            write_period_ms: 33,
            read_period_ms: 100,
            num_iterations: 0,
            num_instances: 1,
            num_topics: 1,
            unregister: false,
            dispose: false,
            coherent_access_scope: AccessScope::Instance,
            coherent_access_scope_set: false,
            coherent_set_enabled: false,
            ordered_access_enabled: false,
            coherent_set_sample_count: 0,
            additional_payload_size: 0,
            take_read_next_instance: true,
            periodic_announcement_period_ms: 0,
            datafrag_size: 0,
            cft_expression: None,
            size_modulo: 0,
        }
    }
}

impl ShapeOptions {
    fn print_usage(prog: &str) {
        println!("{}: ", prog);
        println!("   --help, -h      : print this menu");
        println!("   -v [e|d]        : set log message verbosity [e: ERROR, d: DEBUG]");
        println!("   -P              : publish samples");
        println!("   -S              : subscribe samples");
        println!("   -d <int>        : domain id (default: 0)");
        println!("   -b              : BEST_EFFORT reliability");
        println!("   -r              : RELIABLE reliability");
        println!("   -k <depth>      : keep history depth [0: KEEP_ALL]");
        println!("   -f <interval>   : set a 'deadline' with interval (ms) [0: OFF]");
        println!("   -s <strength>   : set ownership strength [-1: SHARED]");
        println!("   -t <topic_name> : set the topic name");
        println!("   -c <color>      : set color to publish (filter if subscriber)");
        println!("   -p <partition>  : set a 'partition' string");
        println!("   -D [v|l|t|p]    : set durability [v: VOLATILE,  l: TRANSIENT_LOCAL]");
        println!("                                     t: TRANSIENT, p: PERSISTENT]");
        println!("   -x [1|2]        : set data representation [1: XCDR, 2: XCDR2]");
        println!("   -w              : print Publisher's samples");
        println!("   -z <int>        : set shapesize (0: increase the size for every sample)");
        println!("   -R              : use 'read()' instead of 'take()'");
        println!("   --write-period <ms>: waiting period between 'write()' operations in ms.");
        println!("                        Default: 33ms");
        println!("   --read-period <ms> : waiting period between 'read()' or 'take()' operations");
        println!("                        in ms. Default: 100ms");
        println!("   --time-filter <interval> : apply 'time based filter' with interval");
        println!("                              in ms [0: OFF]");
        println!("   --lifespan <int>      : indicates the lifespan of a sample in ms");
        println!("   --num-iterations <int>: indicates the number of iterations of the main loop");
        println!("                           After that, the application will exit.");
        println!("                           Default: infinite");
        println!("   --num-instances <int>: indicates the number of instances a DataWriter writes");
        println!("   --num-topics <int>: indicates the number of topics created");
        println!("   --final-instance-state [u|d]: indicates the action performed after the");
        println!("                                 DataWriter finishes its execution");
        println!("   --access-scope [i|t|g]: sets Presentation.access_scope");
        println!("   --coherent            : sets Presentation.coherent_access = true");
        println!("   --ordered             : sets Presentation.ordered_access = true");
        println!("   --coherent-sample-count <int>: amount of samples grouped in a coherent set");
        println!("   --additional-payload-size <bytes>: amount of bytes added to samples");
        println!("   --take-read           : uses take()/read() instead of take_next_instance()");
        println!("   --periodic-announcement <ms> : participant announcement period");
        println!("   --datafrag-size <bytes> : set the data fragment size");
        println!("   --cft <expression> : ContentFilteredTopic filter expression");
        println!("   --size-modulo <int> : modulo operation applied to shapesize");
    }

    fn parse(args: &[String]) -> Option<Self> {
        let mut opts = ShapeOptions::default();
        let mut i = 1;

        while i < args.len() {
            match args[i].as_str() {
                "-h" | "--help" => {
                    Self::print_usage(&args[0]);
                    std::process::exit(0);
                }
                "-P" => opts.publish = true,
                "-S" => opts.subscribe = true,
                "-b" => opts.reliability_kind = ReliabilityKind::BestEffort,
                "-r" => opts.reliability_kind = ReliabilityKind::Reliable,
                "-R" => opts.use_read = true,
                "-w" => opts.print_writer_samples = true,
                "-v" => {
                    i += 1;
                    if i >= args.len() {
                        return None;
                    }
                    match args[i].chars().next()? {
                        'd' => VERBOSITY.store(VERBOSITY_DEBUG, Ordering::Relaxed),
                        'e' => VERBOSITY.store(VERBOSITY_ERROR, Ordering::Relaxed),
                        _ => {
                            eprintln!("unrecognized value for verbosity {}", args[i]);
                            return None;
                        }
                    }
                }
                "-d" => {
                    i += 1;
                    if i >= args.len() {
                        return None;
                    }
                    opts.domain_id = args[i].parse().ok()?;
                }
                "-t" => {
                    i += 1;
                    if i >= args.len() {
                        return None;
                    }
                    opts.topic_name = Some(args[i].clone());
                }
                "-c" => {
                    i += 1;
                    if i >= args.len() {
                        return None;
                    }
                    opts.color = Some(args[i].clone());
                }
                "-p" => {
                    i += 1;
                    if i >= args.len() {
                        return None;
                    }
                    opts.partition = Some(args[i].clone());
                }
                "-k" => {
                    i += 1;
                    if i >= args.len() {
                        return None;
                    }
                    opts.history_depth = args[i].parse().ok()?;
                }
                "-s" => {
                    i += 1;
                    if i >= args.len() {
                        return None;
                    }
                    opts.ownership_strength = args[i].parse().ok()?;
                }
                "-f" => {
                    i += 1;
                    if i >= args.len() {
                        return None;
                    }
                    opts.deadline_interval_ms = args[i].parse().ok()?;
                }
                "-z" => {
                    i += 1;
                    if i >= args.len() {
                        return None;
                    }
                    opts.shapesize = args[i].parse().ok()?;
                }
                "-x" => {
                    i += 1;
                    if i >= args.len() {
                        return None;
                    }
                    match args[i].as_str() {
                        "1" => opts.data_representation = DataRepresentation::Xcdr1,
                        "2" => opts.data_representation = DataRepresentation::Xcdr2,
                        _ => return None,
                    }
                }
                "-D" => {
                    i += 1;
                    if i >= args.len() {
                        return None;
                    }
                    match args[i].chars().next()? {
                        'v' => opts.durability_kind = DurabilityKind::Volatile,
                        'l' => opts.durability_kind = DurabilityKind::TransientLocal,
                        't' => opts.durability_kind = DurabilityKind::Transient,
                        'p' => opts.durability_kind = DurabilityKind::Persistent,
                        _ => return None,
                    }
                }
                "--write-period" => {
                    i += 1;
                    if i >= args.len() {
                        return None;
                    }
                    opts.write_period_ms = args[i].parse().ok()?;
                }
                "--read-period" => {
                    i += 1;
                    if i >= args.len() {
                        return None;
                    }
                    opts.read_period_ms = args[i].parse().ok()?;
                }
                "--time-filter" => {
                    i += 1;
                    if i >= args.len() {
                        return None;
                    }
                    opts.timebasedfilter_interval_ms = args[i].parse().ok()?;
                }
                "--lifespan" => {
                    i += 1;
                    if i >= args.len() {
                        return None;
                    }
                    opts.lifespan_ms = args[i].parse().ok()?;
                }
                "--num-iterations" => {
                    i += 1;
                    if i >= args.len() {
                        return None;
                    }
                    opts.num_iterations = args[i].parse().ok()?;
                }
                "--num-instances" => {
                    i += 1;
                    if i >= args.len() {
                        return None;
                    }
                    opts.num_instances = args[i].parse().ok()?;
                }
                "--num-topics" => {
                    i += 1;
                    if i >= args.len() {
                        return None;
                    }
                    opts.num_topics = args[i].parse().ok()?;
                }
                "--final-instance-state" => {
                    i += 1;
                    if i >= args.len() {
                        return None;
                    }
                    match args[i].chars().next()? {
                        'u' => opts.unregister = true,
                        'd' => opts.dispose = true,
                        _ => return None,
                    }
                }
                "--access-scope" => {
                    i += 1;
                    if i >= args.len() {
                        return None;
                    }
                    opts.coherent_access_scope_set = true;
                    match args[i].chars().next()? {
                        'i' => opts.coherent_access_scope = AccessScope::Instance,
                        't' => opts.coherent_access_scope = AccessScope::Topic,
                        'g' => opts.coherent_access_scope = AccessScope::Group,
                        _ => return None,
                    }
                }
                "--coherent" => opts.coherent_set_enabled = true,
                "--ordered" => opts.ordered_access_enabled = true,
                "--coherent-sample-count" => {
                    i += 1;
                    if i >= args.len() {
                        return None;
                    }
                    opts.coherent_set_sample_count = args[i].parse().ok()?;
                }
                "--additional-payload-size" => {
                    i += 1;
                    if i >= args.len() {
                        return None;
                    }
                    opts.additional_payload_size = args[i].parse().ok()?;
                }
                "--take-read" => opts.take_read_next_instance = false,
                "--periodic-announcement" => {
                    i += 1;
                    if i >= args.len() {
                        return None;
                    }
                    opts.periodic_announcement_period_ms = args[i].parse().ok()?;
                }
                "--datafrag-size" => {
                    i += 1;
                    if i >= args.len() {
                        return None;
                    }
                    opts.datafrag_size = args[i].parse().ok()?;
                }
                "--cft" => {
                    i += 1;
                    if i >= args.len() {
                        return None;
                    }
                    opts.cft_expression = Some(args[i].clone());
                }
                "--size-modulo" => {
                    i += 1;
                    if i >= args.len() {
                        return None;
                    }
                    opts.size_modulo = args[i].parse().ok()?;
                }
                _ => {
                    eprintln!("Error: Unknown option {}", args[i]);
                    return None;
                }
            }
            i += 1;
        }

        // Validation (matches C++ validate())
        if opts.topic_name.is_none() {
            eprintln!("please specify topic name [-t]");
            return None;
        }
        if !opts.publish && !opts.subscribe {
            eprintln!("please specify publish [-P] or subscribe [-S]");
            return None;
        }
        if opts.publish && opts.subscribe {
            eprintln!("please specify only one of: publish [-P] or subscribe [-S]");
            return None;
        }
        if opts.publish && opts.color.is_none() {
            eprintln!("warning: color was not specified, defaulting to \"BLUE\"");
            opts.color = Some("BLUE".to_string());
        }
        if opts.subscribe && opts.color.is_some() && opts.cft_expression.is_some() {
            eprintln!("error: cannot specify both --cft and -c for subscriber applications");
            return None;
        }
        if opts.unregister && opts.dispose {
            eprintln!("error, cannot configure unregister and dispose at the same time");
            return None;
        }

        // Log parsed options in debug mode
        log_debug(&format!(
            "Shape Options:\n    This application is a {}\n    DomainId = {}\n    ReliabilityKind = {}\n    DurabilityKind = {}\n    DataRepresentation = {}",
            if opts.publish { "publisher" } else { "subscriber" },
            opts.domain_id, opts.reliability_kind, opts.durability_kind, opts.data_representation
        ));

        Some(opts)
    }

    fn build_qos(&self) -> QoS {
        let mut qos = match self.reliability_kind {
            ReliabilityKind::BestEffort => QoS::best_effort(),
            ReliabilityKind::Reliable => QoS::reliable(),
        };

        qos = match self.durability_kind {
            DurabilityKind::Volatile => qos.volatile(),
            DurabilityKind::TransientLocal => qos.transient_local(),
            DurabilityKind::Transient => qos.transient(),
            DurabilityKind::Persistent => qos.persistent(),
        };

        match self.history_depth {
            d if d > 0 => {
                qos = qos.keep_last(d as u32);
            }
            0 => {
                qos = qos.keep_all();
            }
            _ => {} // -1 = default
        }

        // Data representation: Default leaves QoS empty (SEDP advertises both XCDR1+XCDR2)
        match self.data_representation {
            DataRepresentation::Default => {} // no restriction — compatible with all vendors
            DataRepresentation::Xcdr1 => qos = qos.data_representation_xcdr1(),
            DataRepresentation::Xcdr2 => qos = qos.data_representation_xcdr2(),
        }

        if self.ownership_strength >= 0 {
            qos = qos
                .ownership_exclusive()
                .ownership_strength(self.ownership_strength);
        } else {
            qos = qos.ownership_shared();
        }

        if self.deadline_interval_ms > 0 {
            qos = qos.deadline_millis(self.deadline_interval_ms as u64);
        }
        if self.lifespan_ms > 0 {
            qos = qos.lifespan_millis(self.lifespan_ms as u64);
        }
        if self.timebasedfilter_interval_ms > 0 {
            qos = qos.time_based_filter_millis(self.timebasedfilter_interval_ms as u64);
        }
        if let Some(ref partition) = self.partition {
            qos = qos.partition_single(partition);
        }

        // Presentation QoS: only set when the user provided --coherent, --ordered,
        // or --access-scope. Honor the exact combination (do not bundle flags into
        // a preset, or --ordered --access-scope i would silently become
        // coherent=false/ordered=false and the test would fail).
        if self.coherent_set_enabled
            || self.ordered_access_enabled
            || self.coherent_access_scope_set
        {
            let scope = match self.coherent_access_scope {
                AccessScope::Instance => hdds::dds::qos::PresentationAccessScope::Instance,
                AccessScope::Topic => hdds::dds::qos::PresentationAccessScope::Topic,
                AccessScope::Group => hdds::dds::qos::PresentationAccessScope::Group,
            };
            let presentation = hdds::dds::qos::Presentation::new(
                scope,
                self.coherent_set_enabled,
                self.ordered_access_enabled,
            );
            qos = qos.presentation(presentation);
        }

        qos
    }
}

// ---------------------------------------------------------------------------
// Listeners — print the EXACT strings pexpect expects
// FIX #9: messages now match C++ format exactly
// ---------------------------------------------------------------------------

/// Writer listener that holds the actual topic name for correct printf output.
struct WriterListener {
    topic_name: String,
}

impl DataWriterListener<ShapeType> for WriterListener {
    fn on_publication_matched(&self, status: PublicationMatchedStatus) {
        // Suppressed: MatchNotifier::on_endpoint_discovered() handles this with
        // full QoS compatibility checking (incl. DataRepresentation + local -x flag).
        // The library MatchNotificationRegistry may fire false matches when either
        // side has empty data_representation QoS (skips the check entirely).
        let _ = status;
    }

    fn on_offered_incompatible_qos(&self, policy_id: u32, policy_name: &str) {
        // pexpect matches: "on_offered_incompatible_qos"
        println!(
            "on_offered_incompatible_qos() topic: '{}'  type: 'ShapeType' : {} ({})",
            self.topic_name, policy_id, policy_name
        );
    }

    fn on_offered_deadline_missed(&self, status: OfferedDeadlineMissedStatus) {
        // pexpect matches: "on_offered_deadline_missed"
        println!(
            "on_offered_deadline_missed() topic: '{}'  type: 'ShapeType' : (total = {}, change = {})",
            self.topic_name, status.total_count, status.total_count_change
        );
    }

    fn on_liveliness_lost(&self) {
        println!(
            "on_liveliness_lost() topic: '{}'  type: 'ShapeType' : (total = 1, change = 1)",
            self.topic_name
        );
    }
}

struct ReaderListener {
    topic_name: String,
}

impl DataReaderListener<ShapeType> for ReaderListener {
    fn on_data_available(&self, _sample: &ShapeType) {
        // Data is handled in the main polling loop, not here
    }

    fn on_subscription_matched(&self, status: SubscriptionMatchedStatus) {
        // Suppressed: MatchNotifier::on_endpoint_discovered() handles this with
        // full QoS compatibility checking (incl. DataRepresentation + local -x flag).
        // The library MatchNotificationRegistry may fire false matches when either
        // side has empty data_representation QoS (skips the check entirely).
        let _ = status;
    }

    fn on_requested_incompatible_qos(&self, status: RequestedIncompatibleQosStatus) {
        // pexpect matches: "on_requested_incompatible_qos()"
        // FIX #9: include policy name. HDDS status only has policy_id currently.
        let policy_name = qos_policy_name(status.last_policy_id);
        println!(
            "on_requested_incompatible_qos() topic: '{}'  type: 'ShapeType' : {} ({})",
            self.topic_name, status.last_policy_id, policy_name
        );
    }

    fn on_requested_deadline_missed(&self, status: RequestedDeadlineMissedStatus) {
        // pexpect matches: "on_requested_deadline_missed"
        println!(
            "on_requested_deadline_missed() topic: '{}'  type: 'ShapeType' : (total = {}, change = {})",
            self.topic_name, status.total_count, status.total_count_change
        );
    }

    fn on_liveliness_changed(&self, status: LivelinessChangedStatus) {
        println!(
            "on_liveliness_changed() topic: '{}'  type: 'ShapeType' : (alive = {}, not_alive = {})",
            self.topic_name, status.alive_count, status.not_alive_count
        );
    }
}

/// Map QoS policy ID to name (DDS spec Table 3)
fn qos_policy_name(id: u32) -> &'static str {
    match id {
        1 => "DURABILITY",
        2 => "PRESENTATION",
        3 => "DEADLINE",
        4 => "LATENCY_BUDGET",
        5 => "OWNERSHIP",
        6 => "OWNERSHIP_STRENGTH",
        7 => "LIVELINESS",
        8 => "TIME_BASED_FILTER",
        9 => "PARTITION",
        10 => "RELIABILITY",
        11 => "DESTINATION_ORDER",
        12 => "HISTORY",
        13 => "RESOURCE_LIMITS",
        14 => "ENTITY_FACTORY",
        15 => "WRITER_DATA_LIFECYCLE",
        16 => "READER_DATA_LIFECYCLE",
        17 => "TOPIC_DATA",
        18 => "GROUP_DATA",
        19 => "TRANSPORT_PRIORITY",
        20 => "LIFESPAN",
        21 => "DURABILITY_SERVICE",
        23 => "DATA_REPRESENTATION",
        _ => "UNKNOWN",
    }
}

// ---------------------------------------------------------------------------
// Helper: generate topic names for multi-topic (Square, Square1, Square2, ...)
// ---------------------------------------------------------------------------
fn topic_name_at(base: &str, idx: u32) -> String {
    if idx == 0 {
        base.to_string()
    } else {
        format!("{}{}", base, idx)
    }
}

// ---------------------------------------------------------------------------
// Publisher
// FIX #5: multi-topic properly creates N writers
// FIX #6: coherent sets implemented
// ---------------------------------------------------------------------------
fn run_publisher(
    participant: &Arc<Participant>,
    options: &ShapeOptions,
    notifier: &Arc<MatchNotifier>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Emit the "not supported" marker before any other expected stdout
    // pattern (e.g. "Create topic:") so the OMG harness classifies the
    // run as PUB_UNSUPPORTED_FEATURE rather than FAILED. begin/end
    // coherent_changes runtime is not implemented yet.
    if options.coherent_set_sample_count > 0 {
        println!("coherent set runtime not supported in HDDS");
        use std::io::Write;
        let _ = std::io::stdout().flush();
        std::thread::sleep(std::time::Duration::from_millis(500));
        return Ok(());
    }
    let qos = options.build_qos();
    let base_topic = options.topic_name.as_ref().unwrap();
    let color = options.color.as_deref().unwrap_or("BLUE");

    // Publisher entity for coherent sets / ordered access (DDS 2.2.2.4.2.6)
    let publisher = if options.coherent_set_enabled || options.ordered_access_enabled {
        Some(participant.create_publisher(qos.clone())?)
    } else {
        None
    };

    // Create topics and writers for each topic index
    let mut writers: Vec<hdds::dds::DataWriter<ShapeType>> = Vec::new();
    let mut topic_names: Vec<String> = Vec::new();

    for idx in 0..options.num_topics {
        let tname = topic_name_at(base_topic, idx);
        // pexpect matches: "Create topic:"
        println!("Create topic: {}", tname);
        topic_names.push(tname);
    }

    for idx in 0..options.num_topics {
        let tname = &topic_names[idx as usize];
        let topic = participant.topic::<ShapeType>(tname)?;

        // pexpect matches: "Create writer for topic"
        println!("Create writer for topic: {} color: {}", tname, color);

        let writer = topic
            .writer()
            .qos(qos.clone())
            .with_listener(Arc::new(WriterListener {
                topic_name: tname.clone(),
            }))
            .build()?;
        writers.push(writer);
    }

    // Register topics with MatchNotifier AFTER "Create writer for topic:" is printed.
    // The catch-up may print on_offered_incompatible_qos() which pexpect expects
    // to see AFTER the "Create writer" line.
    for tname in &topic_names {
        notifier.add_writer_topic(tname.clone(), qos.clone(), options.data_representation);
    }

    // Initialize shape
    let mut shape = ShapeType {
        color: color.to_string(),
        x: (rng_next_u32() % options.da_width as u32) as i32,
        y: (rng_next_u32() % options.da_height as u32) as i32,
        shapesize: options.shapesize,
        additional_payload_size: if options.additional_payload_size > 0 {
            vec![255u8; options.additional_payload_size as usize]
        } else {
            Vec::new()
        },
    };

    let mut xvel: i32 =
        ((rng_next_u32() % 5 + 1) as i32) * if rng_next_u32() % 2 == 0 { 1 } else { -1 };
    let mut yvel: i32 =
        ((rng_next_u32() % 5 + 1) as i32) * if rng_next_u32() % 2 == 0 { 1 } else { -1 };

    let mut n: u32 = 0;

    while !ALL_DONE.load(Ordering::SeqCst) {
        // Move shape (bouncing box)
        shape.x += xvel;
        shape.y += yvel;
        if shape.x < 0 {
            shape.x = 0;
            xvel = -xvel;
        }
        if shape.x > options.da_width {
            shape.x = options.da_width;
            xvel = -xvel;
        }
        if shape.y < 0 {
            shape.y = 0;
            yvel = -yvel;
        }
        if shape.y > options.da_height {
            shape.y = options.da_height;
            yvel = -yvel;
        }

        if options.shapesize == 0 {
            if options.size_modulo > 0 {
                shape.shapesize = (shape.shapesize % options.size_modulo as i32) + 1;
            } else {
                shape.shapesize += 1;
            }
        }

        // FIX #6: coherent sets — begin
        if (options.coherent_set_enabled || options.ordered_access_enabled)
            && options.coherent_set_sample_count != 0
            && n % options.coherent_set_sample_count == 0
        {
            println!("Started Coherent Set");
            if let Some(ref pub_entity) = publisher {
                let _ = pub_entity.begin_coherent_changes();
            }
        }

        // Write to all topics x all instances
        for (idx, writer) in writers.iter().enumerate() {
            for j in 0..options.num_instances {
                if options.num_instances > 1 {
                    let instance_color = if j > 0 {
                        format!("{}{}", color, j)
                    } else {
                        color.to_string()
                    };
                    shape.color = instance_color;
                }

                writer.write(&shape)?;

                // pexpect matches "[<digits>]" for shapesize
                if options.print_writer_samples {
                    print!(
                        "{:<10} {:<10} {:03} {:03} [{}]",
                        topic_names[idx], shape.color, shape.x, shape.y, shape.shapesize
                    );
                    if options.additional_payload_size > 0 {
                        let last_idx = options.additional_payload_size as usize - 1;
                        print!(" {{{}}}", shape.additional_payload_size[last_idx]);
                    }
                    println!();
                }
            }
        }

        // FIX #6: coherent sets — end
        if (options.coherent_set_enabled || options.ordered_access_enabled)
            && options.coherent_set_sample_count != 0
            && n % options.coherent_set_sample_count == options.coherent_set_sample_count - 1
        {
            println!("Finished Coherent Set");
            if let Some(ref pub_entity) = publisher {
                let _ = pub_entity.end_coherent_changes();
            }
        }

        n += 1;
        if options.num_iterations != 0 && options.num_iterations <= n {
            break;
        }

        thread::sleep(Duration::from_millis(options.write_period_ms as u64));
    }

    // FIX #7: Dispose/Unregister instances
    if options.dispose || options.unregister {
        for writer in &writers {
            for j in 0..options.num_instances {
                if options.num_instances > 1 {
                    let instance_color = if j > 0 {
                        format!("{}{}", color, j)
                    } else {
                        color.to_string()
                    };
                    shape.color = instance_color;
                }
                if options.unregister {
                    let _ = writer.unregister_instance(&shape);
                }
                if options.dispose {
                    let _ = writer.dispose(&shape);
                }
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Subscriber
// FIX #3: drain ALL available samples per iteration (not just one)
// FIX #4: instance state messages (structure for when HDDS provides SampleInfo)
// FIX #5: multi-topic properly creates N readers
// ---------------------------------------------------------------------------
fn run_subscriber(
    participant: &Arc<Participant>,
    options: &ShapeOptions,
    notifier: &Arc<MatchNotifier>,
) -> Result<(), Box<dyn std::error::Error>> {
    // `--take-read` flips `take_read_next_instance` from its default
    // (true) to false (see option parser). Aliasing it here so the
    // condition reads in flag-direction: CoherentSets_10/11/12 and
    // OrderedAccess_10 set `--take-read`; the matching-layer tests
    // (0-9) do not.
    let take_read_flag_set = !options.take_read_next_instance;
    let requires_coherent_runtime = options.coherent_set_sample_count > 0
        || ((options.coherent_set_enabled || options.ordered_access_enabled) && take_read_flag_set);
    if requires_coherent_runtime {
        println!("coherent / ordered access runtime not supported in HDDS");
        use std::io::Write;
        let _ = std::io::stdout().flush();
        std::thread::sleep(std::time::Duration::from_millis(500));
        return Ok(());
    }
    let qos = options.build_qos();
    let base_topic = options.topic_name.as_ref().unwrap();

    // Subscriber entity for coherent access / ordered access (DDS 2.2.2.4.2.7)
    let subscriber = if options.coherent_set_enabled || options.ordered_access_enabled {
        Some(participant.create_subscriber(qos.clone())?)
    } else {
        None
    };

    let mut readers: Vec<hdds::dds::DataReader<ShapeType>> = Vec::new();
    let mut topic_names: Vec<String> = Vec::new();

    // Create topics and readers
    for idx in 0..options.num_topics {
        let tname = topic_name_at(base_topic, idx);
        // pexpect matches: "Create topic:"
        println!("Create topic: {}", tname);
        topic_names.push(tname);
    }

    // Create readers (with or without content filter)
    for idx in 0..options.num_topics {
        let tname = &topic_names[idx as usize];

        if options.color.is_some() || options.cft_expression.is_some() {
            // Content Filtered Topic
            let filter_expr = if let Some(ref cft) = options.cft_expression {
                cft.clone()
            } else {
                "color = %0".to_string()
            };
            let params = if let Some(ref color) = options.color {
                vec![format!("'{}'", color)]
            } else {
                Vec::new()
            };

            let filtered_name = format!("{}_filtered", tname);

            match participant.create_content_filtered_topic::<ShapeType>(
                &filtered_name,
                tname,
                &filter_expr,
                params,
            ) {
                Ok(filtered_topic) => {
                    // pexpect matches: "Create reader for topic:"
                    println!("Create reader for topic: {}", filtered_name);
                    let reader = filtered_topic
                        .reader()
                        .qos(qos.clone())
                        .with_listener(Arc::new(ReaderListener {
                            topic_name: tname.clone(),
                        }))
                        .build()?;
                    readers.push(reader);
                }
                Err(_) => {
                    // pexpect matches: "failed to create content filtered topic"
                    eprintln!("failed to create content filtered topic");
                    return Ok(());
                }
            }
        } else {
            let topic = participant.topic::<ShapeType>(tname)?;
            // pexpect matches: "Create reader for topic:"
            println!("Create reader for topic: {}", tname);
            let reader = topic
                .reader()
                .qos(qos.clone())
                .with_listener(Arc::new(ReaderListener {
                    topic_name: tname.clone(),
                }))
                .build()?;
            readers.push(reader);
        }
    }

    // Register topics with MatchNotifier AFTER "Create reader for topic:" is printed.
    // The catch-up may print on_requested_incompatible_qos() which pexpect expects
    // to see AFTER the "Create reader" line.
    for tname in &topic_names {
        notifier.add_reader_topic(tname.clone(), qos.clone(), options.data_representation);
    }

    // Main subscriber loop
    let mut n: u32 = 0;

    // Learn the set of instance colors as samples arrive so cross-vendor
    // dispose events (whose PID_KEY_HASH is MD5 of the key, not the
    // CDR-padded short string) can still be resolved back to a readable
    // color in the dispose-state output line the OMG harness scrapes.
    let mut known_colors: Vec<String> = Vec::new();

    while !ALL_DONE.load(Ordering::SeqCst) {
        // FIX #6: coherent sets — begin_access
        if options.coherent_set_enabled || options.ordered_access_enabled {
            if let Some(ref sub_entity) = subscriber {
                let _ = sub_entity.begin_access();
            }
            if options.coherent_set_enabled {
                println!("Reading coherent sets, iteration {}", n);
            }
            if options.ordered_access_enabled {
                println!("Reading with ordered access, iteration {}", n);
            }
        }

        // FIX #3: drain ALL samples from ALL readers (not just one)
        for (idx, reader) in readers.iter().enumerate() {
            loop {
                let result = if options.use_read {
                    reader.read()
                } else {
                    reader.take()
                };

                match result {
                    Ok(Some(sample)) => {
                        // pexpect matches "[<digits>]" — shapesize in brackets
                        print!(
                            "{:<10} {:<10} {:03} {:03} [{}]",
                            topic_names[idx], sample.color, sample.x, sample.y, sample.shapesize
                        );
                        if !sample.additional_payload_size.is_empty() {
                            let last_idx = sample.additional_payload_size.len() - 1;
                            print!(" {{{}}}", sample.additional_payload_size[last_idx]);
                        }
                        println!();

                        if !known_colors.iter().any(|c| c == &sample.color) {
                            known_colors.push(sample.color.clone());
                        }
                    }
                    Ok(None) => break, // No more samples available
                    Err(_) => break,
                }
            }
        }

        // FIX #4: Check for dispose/unregister events from all readers (P1.2)
        for (idx, reader) in readers.iter().enumerate() {
            for event in reader.get_dispose_events() {
                let state_str = match event.kind {
                    hdds::engine::DisposeKind::Disposed => "NOT_ALIVE_DISPOSED_INSTANCE_STATE",
                    hdds::engine::DisposeKind::Unregistered => {
                        "NOT_ALIVE_NO_WRITERS_INSTANCE_STATE"
                    }
                    hdds::engine::DisposeKind::DisposedUnregistered => {
                        "NOT_ALIVE_DISPOSED_INSTANCE_STATE"
                    }
                };
                let color = color_from_key_hash_with_map(&event.key_hash, &known_colors);
                println!("{:<10} {:<10} {}", topic_names[idx], color, state_str);
            }
        }

        // Coherent sets / ordered access — end_access
        if options.coherent_set_enabled || options.ordered_access_enabled {
            if let Some(ref sub_entity) = subscriber {
                let _ = sub_entity.end_access();
            }
        }

        n += 1;
        if options.num_iterations != 0 && options.num_iterations <= n {
            break;
        }

        thread::sleep(Duration::from_millis(options.read_period_ms as u64));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
fn main() {
    PROCESS_START.set(std::time::Instant::now()).ok();
    install_signal_handlers();
    rng_seed_once();

    let args: Vec<String> = std::env::args().collect();
    let options = match ShapeOptions::parse(&args) {
        Some(opts) => opts,
        None => {
            ShapeOptions::print_usage(&args[0]);
            std::process::exit(1);
        }
    };

    let participant = match Participant::builder("hdds_shape_main")
        .domain_id(options.domain_id)
        .with_transport(TransportMode::UdpMulticast)
        .build()
    {
        Ok(p) => p,
        Err(e) => {
            eprintln!("failed to create participant: {:?}", e);
            std::process::exit(2);
        }
    };

    // Wire up MatchNotifier for on_publication_matched / on_subscription_matched
    let notifier = {
        let guid_bytes = participant.guid().as_bytes();
        let mut prefix = [0u8; 12];
        prefix.copy_from_slice(&guid_bytes[..12]);
        let fsm = participant.discovery();
        Arc::new(MatchNotifier::new(prefix, fsm.clone()))
    };

    if let Some(fsm) = participant.discovery() {
        fsm.register_listener(notifier.clone());
    }

    let result = if options.publish {
        run_publisher(&participant, &options, &notifier)
    } else {
        run_subscriber(&participant, &options, &notifier)
    };

    if let Err(e) = result {
        eprintln!("Error: {:?}", e);
        std::process::exit(3);
    }

    println!("Done.");
}
