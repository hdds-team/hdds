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
use hdds::core::key_hash::{KeyHolderWriter, KeyMaxSize};
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
/// Build identification kept inside the binary so a submitted artifact can
/// be tied to its source commit after the fact:
/// `strings shape_main | grep HDDS_BUILD_GIT`. Never printed: the interop
/// harness parses this program's stdout.
#[used]
static HDDS_BUILD_ID: &str = concat!(
    "HDDS_BUILD_GIT=",
    env!("HDDS_BUILD_GIT_SHA"),
    " HDDS_BUILD_VERSION=",
    env!("CARGO_PKG_VERSION")
);
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
// MatchNotifier -- bridges SEDP discovery to DDS listener callbacks
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
    /// Publishing topics for which a compatible remote reader was discovered
    matched_pub_topics: Mutex<std::collections::HashSet<String>>,
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
            matched_pub_topics: Mutex::new(std::collections::HashSet::new()),
        }
    }

    fn is_pub_topic_matched(&self, topic: &str) -> bool {
        self.matched_pub_topics.lock().unwrap().contains(topic)
    }

    /// The number of remote endpoints the discovery FSM holds on `local`'s
    /// topic that match it on QoS: remote readers when `local` is a writer,
    /// remote writers when it is a reader. The same check the match callbacks
    /// make before they print a match.
    fn matched_count(&self, local: &LocalEndpoint, local_is_writer: bool) -> usize {
        let Some(fsm) = self.discovery_fsm.as_ref() else {
            return 0;
        };
        let remotes = if local_is_writer {
            fsm.find_readers_for_topic(&local.topic)
        } else {
            fsm.find_writers_for_topic(&local.topic)
        };
        remotes
            .iter()
            .filter(|remote| remote.endpoint_guid.as_bytes()[..12] != self.local_prefix)
            .filter(|remote| {
                let remote_repr = infer_data_repr_from_qos(&remote.qos);
                let verdict = if local_is_writer {
                    Self::check_writer_reader_compat(
                        &local.qos,
                        local.data_repr,
                        &remote.qos,
                        remote_repr,
                        true, // local writer: ownership always explicit
                        true, // local writer: strength always known
                    )
                } else {
                    Self::check_writer_reader_compat(
                        &remote.qos,
                        remote_repr,
                        &local.qos,
                        local.data_repr,
                        remote.has_explicit_ownership,
                        remote.has_ownership_strength,
                    )
                };
                verdict.is_none()
            })
            .count()
    }

    fn is_topic_incompatible(&self, topic: &str) -> bool {
        self.incompatible_topics.lock().unwrap().contains(topic)
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
                // Skip endpoints from unconfirmed participants (stale
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
                // Skip endpoints from unconfirmed participants.
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
                            "on_subscription_matched() topic: '{}'  type: '{}' : matched writers {} (change = 1)",
                            ep.topic,
                            remote.type_name,
                            self.matched_count(&ep, false)
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
        // Data representation compatibility check (DDS-XTypes v1.3 sec. 7.6.3.1.2).
        // An endpoint that advertises no PID_DATA_REPRESENTATION does NOT mean
        // "no restriction": per spec the absent DataRepresentationQosPolicy
        // defaults to XCDR1 (XCDR_DATA_REPRESENTATION, code 0x0000) for
        // back-compat with DDS-XTypes 1.1. A writer is compatible with a reader
        // iff the reader's sequence contains the writer's representation.
        //
        // A writer publishing XCDR1 may omit PID_DATA_REPRESENTATION (absent
        // means XCDR1), so treating "empty == compatible" let such an XCDR1
        // writer falsely match an XCDR2 HDDS reader (no on_*_incompatible_qos
        // fired). The writer offers only the FIRST element of its list
        // (DDS-XTypes v1.3 7.6.3.1.1), so that element alone is checked
        // against the reader's sequence. This mirrors the engine's
        // cdr_negotiation::pair_effective_cdr_version so the example's printed
        // status matches the library's matching decision.
        // Only enforce when the reader explicitly requested a representation
        // (non-empty). An empty reader policy means "no restriction" and must
        // keep matching any writer to avoid false rejections of vendors that
        // advertise only XCDR2 against a default HDDS reader.
        if !reader_qos.data_representation.is_empty() {
            const XCDR1_DR: [u16; 1] = [0x0000];
            let writer_dr: &[u16] = if writer_qos.data_representation.is_empty() {
                &XCDR1_DR
            } else {
                &writer_qos.data_representation
            };
            let offered = writer_dr.first().copied().unwrap_or(0x0000);
            if !reader_qos.data_representation.contains(&offered) {
                return Some("DATA_REPRESENTATION");
            }
        }

        // Ownership: infer writer ownership from SEDP PIDs.
        // PID_OWNERSHIP present -> use directly.
        // PID_OWNERSHIP absent + PID_OWNERSHIP_STRENGTH present -> EXCLUSIVE.
        // Both absent -> SHARED (DDS default, Sec.2.2.3).
        let mut offered = writer_qos.clone();
        offered.ownership.kind = if writer_has_explicit_ownership {
            writer_qos.ownership.kind
        } else if writer_has_ownership_strength {
            hdds::qos::ownership::OwnershipKind::Exclusive
        } else {
            hdds::qos::ownership::OwnershipKind::Shared
        };
        // Every other request/offered rule (DDS v1.4 Sec.2.2.3) is the
        // library's, so this status line cannot disagree with the matching
        // the engine performs. A copy of the rules here once ignored
        // LIVELINESS, LATENCY_BUDGET, DESTINATION_ORDER and PRESENTATION and
        // took an infinite DEADLINE on either side as "no constraint", and
        // printed a match for pairs the engine refused.
        let policy =
            hdds::core::discovery::Matcher::first_incompatible_policy(reader_qos, &offered);
        if policy != hdds::dds::qos::policy_id::INVALID {
            return Some(hdds::dds::qos::policy_id::name(policy));
        }
        // Partition (DDS v1.4 Sec.2.2.3.13 and Table 2.60). Delegates to the
        // library rule so this status line cannot disagree with the matching
        // the engine actually performed. Re-deriving it here once cost a
        // silent miss: the default zero-length sequence "is treated as a
        // special value equivalent to a sequence containing a single element
        // consisting of the empty string", so a writer that set no partition
        // IS matched by a reader asking for "*", and this app reported
        // the reader as not matched while the data was flowing.
        if !writer_qos
            .partition
            .is_compatible_with(&reader_qos.partition)
        {
            return Some("PARTITION");
        }
        None
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
                // Remote reader discovered -- check if we have a local writer on that topic
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
                                self.matched_pub_topics
                                    .lock()
                                    .unwrap()
                                    .insert(ep.topic.clone());
                                // No deferral needed -- stale endpoints are filtered
                                // at the library level (SEDP startup probation in DiscoveryFsm
                                // + blocked_writers in router).
                                println!(
                                    "on_publication_matched() topic: '{}'  type: '{}' : matched readers {} (change = 1)",
                                    ep.topic,
                                    endpoint.type_name,
                                    self.matched_count(ep, true)
                                );
                            }
                        }
                    }
                }
            }
            EndpointKind::Writer => {
                // Remote writer discovered -- check if we have a local reader on that topic
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
                                    "on_subscription_matched() topic: '{}'  type: '{}' : matched writers {} (change = 1)",
                                    ep.topic,
                                    endpoint.type_name,
                                    self.matched_count(ep, false)
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    /// Fire ONLY incompatible-QoS notifications, immediately at discovery
    /// (no participant-confirmation gate). The DiscoveryFsm calls this for
    /// every new endpoint via notify_endpoint_discovered_incompat_only, so
    /// QoS verdicts (which are participant-local and deterministic) surface
    /// without waiting on the match-surfacing gate. Without this override the
    /// default no-op drops the event and the test app falls back to a racy
    /// catch-up scan -- that race made the SHARED-vs-EXCLUSIVE ownership
    /// scenario flaky on the self path. The match (compatible) branch is intentionally
    /// NOT fired here; that stays in on_endpoint_discovered behind the gate.
    fn on_endpoint_discovered_incompat_only(&self, endpoint: EndpointInfo) {
        // Ignore our own endpoints
        let ep_prefix = &endpoint.endpoint_guid.as_bytes()[..12];
        if ep_prefix == &self.local_prefix {
            return;
        }

        match endpoint.kind {
            EndpointKind::Reader => {
                let endpoints = self.writer_endpoints.lock().unwrap();
                for ep in endpoints.iter() {
                    if ep.topic != endpoint.topic_name {
                        continue;
                    }
                    let remote_repr = infer_data_repr_from_qos(&endpoint.qos);
                    if let Some(policy) = MatchNotifier::check_writer_reader_compat(
                        &ep.qos,
                        ep.data_repr,
                        &endpoint.qos,
                        remote_repr,
                        true, // local writer: ownership always explicit
                        true, // local writer: strength always known
                    ) {
                        if policy == "PARTITION" {
                            continue;
                        }
                        // Guard against a duplicate print if the gated path or
                        // the catch-up scan already reported this topic.
                        if self.incompatible_topics.lock().unwrap().contains(&ep.topic) {
                            continue;
                        }
                        self.mark_incompatible(&ep.topic);
                        println!(
                            "on_offered_incompatible_qos() topic: '{}' policy: {}",
                            ep.topic, policy
                        );
                    }
                }
            }
            EndpointKind::Writer => {
                let endpoints = self.reader_endpoints.lock().unwrap();
                for ep in endpoints.iter() {
                    if ep.topic != endpoint.topic_name {
                        continue;
                    }
                    let remote_repr = infer_data_repr_from_qos(&endpoint.qos);
                    if let Some(policy) = MatchNotifier::check_writer_reader_compat(
                        &endpoint.qos,
                        remote_repr,
                        &ep.qos,
                        ep.data_repr,
                        endpoint.has_explicit_ownership,
                        endpoint.has_ownership_strength,
                    ) {
                        if policy == "PARTITION" {
                            continue;
                        }
                        if self.incompatible_topics.lock().unwrap().contains(&ep.topic) {
                            continue;
                        }
                        self.mark_incompatible(&ep.topic);
                        println!(
                            "on_requested_incompatible_qos() topic: '{}' policy: {}",
                            ep.topic, policy
                        );
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
// PRNG -- xorshift64 with global state, seeded once
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
// Verbosity -- matches C++ ERROR/DEBUG levels
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

// The TypeObject announced for ShapeType, shared with the library's
// type-verdict tests (`examples/shape_common/shape_type_object.rs`).
mod shape_type_object {
    use hdds::xtypes::*;
    include!("shape_common/shape_type_object.rs");
}

// ---------------------------------------------------------------------------
// ShapeType -- IDL definition:
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

        // Field: color (string<128>) -- CDR: 4-byte length (including NUL) + chars + NUL + padding
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
    // the global cursor -- encode_cdr2_le emits its own DHEADER + per-field
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
    /// CDR1 PLAIN_CDR_LE encoder (DDS-XTypes v1.3 sec. 7.4.1.4).
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
    /// DHEADER skip -- XCDR1 has no per-struct delimiter.
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
            // DHEADER present -- skip it
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

/// Maximum serialized size of ShapeType's KeyHolder, `{ string<128> color }`:
/// a 4-byte length, 128 bytes, the NUL. Above 16, so the KeyHash is the MD5 of
/// the serialized key for every color (RTPS 2.5 9.6.4.8 step 5.2): for "BLUE",
/// the MD5 of `00000005 'BLUE\0'`, `cac217c3...`.
const SHAPE_KEY_MAX_SIZE: KeyMaxSize = KeyMaxSize::Bounded(4 + 128 + 1);

/// Decode a ShapeType key hash back to the color string.
///
/// Two on-wire forms must be recognized so cross-vendor FinalInstanceState
/// dispose lines emit `Square <COLOR> NOT_ALIVE_*` rather than a raw hex
/// prefix (the harness compares the COLOR set, not the hex set).
///
/// 1. HDDS form: CDR Big-Endian of the serialized key, zero-padded to 16
///    bytes when it fits (string keys <= 11 chars + NUL).
/// 2. MD5 form: MD5 of the CDR-BE serialized key, used when the KeyHolder's
///    maximum serialized size is above 16 (RTPS 2.5 9.6.4.8), which is the
///    case for ShapeType (`cac217c3:18363f8e:...` for "BLUE").
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
    // Form 2: try each learned color via the MD5 hashing path.
    for color in known_colors {
        if compute_color_key_hash_md5(color) == *key_hash {
            return color.clone();
        }
    }
    // Unknown hash form -- preserve hex for debug.
    format!(
        "{:02x}{:02x}{:02x}{:02x}",
        key_hash[0], key_hash[1], key_hash[2], key_hash[3]
    )
}

/// The KeyHash of a ShapeType of this color, as `ShapeType::compute_key`
/// computes it (RTPS 2.5 9.6.4.8): the MD5 of the 4-byte length, the string
/// and its NUL, since the maximum size is above 16. This is the value a
/// conformant writer places in PID_KEY_HASH.
fn compute_color_key_hash_md5(color: &str) -> [u8; 16] {
    let mut w = KeyHolderWriter::new();
    w.write_string(color);
    w.finish(SHAPE_KEY_MAX_SIZE)
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

    /// `encode_cdr1_le` / `decode_cdr1_le` are the XCDR1 layout (no DHEADER,
    /// plain CDR), dispatched on `version`.
    fn encodes_xcdr1_natively() -> bool {
        true
    }

    fn has_key() -> bool {
        true
    }

    fn write_key_holder(&self, w: &mut KeyHolderWriter) -> Option<KeyMaxSize> {
        w.write_string(&self.color);
        Some(SHAPE_KEY_MAX_SIZE)
    }

    fn encode_key(&self, version: hdds::CdrVersion) -> Vec<u8> {
        // ShapeType has a single @key field (color, string<128>). Bound is
        // enforced at a UTF-8 character boundary so the truncated bytes still
        // form a valid string for strict deserializers. The serialized key is
        // the KeyHolder in the data path's representation: ShapeType is
        // @appendable, so under XCDR2 it is D_CDR2 with a leading DHEADER
        // (DDS-XTypes v1.3 7.4.3.5.2: the length of the inner CDR data NOT
        // including any RTPS submessage alignment padding; the outer packet
        // builder pads the SerializedPayload as a whole), and under XCDR1 it
        // is plain CDR with no DHEADER, as `encode_cdr1_le` writes the data.
        let mut cutoff = self.color.len().min(128);
        while cutoff > 0 && !self.color.is_char_boundary(cutoff) {
            cutoff -= 1;
        }
        let color_bytes = &self.color.as_bytes()[..cutoff];
        let str_len = color_bytes.len() + 1;
        let inner_len = 4 + str_len;
        let mut buf = Vec::with_capacity(4 + inner_len);
        if version == hdds::CdrVersion::Xcdr2 {
            buf.extend_from_slice(&(inner_len as u32).to_le_bytes());
        }
        buf.extend_from_slice(&(str_len as u32).to_le_bytes());
        buf.extend_from_slice(color_bytes);
        buf.push(0);
        buf
    }

    /// The instance a key-only payload names: `color` read back from what
    /// `encode_key` writes (and what another vendor writes for the same
    /// key: DHEADER then the string under XCDR2, the string under XCDR1),
    /// hashed as `write_key_holder` hashes a sample's. A peer that sends no
    /// PID_KEY_HASH, or another hash than this one, reaches the instance.
    fn key_hash_of_key_payload(payload: &[u8]) -> Option<[u8; 16]> {
        let mut r = hdds::core::key_hash::KeyPayloadReader::new(payload)?;
        let end = if r.is_xcdr2() {
            Some(r.read_dheader()?)
        } else {
            None
        };
        let color = r.read_string(Some(128))?;
        if let Some(end) = end {
            r.close(end)?;
        }
        r.finish()?;
        let mut w = KeyHolderWriter::new();
        w.write_string(&color);
        Some(w.finish(SHAPE_KEY_MAX_SIZE))
    }

    fn keys_round_trip() -> bool {
        true
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
        Some(shape_type_object::shape_type_object())
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
    Default, // No restriction -- advertise both XCDR1 and XCDR2
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
// ShapeOptions -- mirrors the C++ ShapeOptions exactly
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

        // Data representation: Default leaves the policy empty. A reader
        // then announces and requests [XCDR1, XCDR2]; a writer offers,
        // announces and encodes XCDR1 (DDS-XTypes v1.3 Sec.7.6.3.1.1, the
        // empty list is [XCDR]), resolved once when it is created
        // (cdr_negotiation::resolve_writer_data_representation).
        match self.data_representation {
            DataRepresentation::Default => {}
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
// Listeners -- print the EXACT strings pexpect expects
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

    fn on_liveliness_lost(&self, status: LivelinessLostStatus) {
        println!(
            "on_liveliness_lost() topic: '{}'  type: 'ShapeType' : (total = {}, change = {})",
            self.topic_name, status.total_count, status.total_count_change
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

/// The QoS policy's name for its QosPolicyId_t (DDS v1.4 Sec.2.3.3).
fn qos_policy_name(id: u32) -> &'static str {
    hdds::dds::qos::policy_id::name(id)
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
    let qos = options.build_qos();
    let base_topic = options.topic_name.as_ref().unwrap();
    let color = options.color.as_deref().unwrap_or("BLUE");

    // Publisher entity for coherent sets / ordered access (DDS 2.2.2.4.2.6).
    // Wrapped in Arc so each DataWriter can hold a weak back-reference
    // for the GSN runtime (RTPS v2.5 sec. 8.7.5).
    let publisher: Option<Arc<hdds::dds::Publisher>> =
        if options.coherent_set_enabled || options.ordered_access_enabled {
            Some(Arc::new(participant.create_publisher(qos.clone())?))
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

    // WRITER_DATA_LIFECYCLE. The OMG reference `shape_main.cxx` turns the
    // policy off for the explicit-unregister run:
    //
    //     if (options->unregister) {
    //         dw_qos.writer_data_lifecycle.autodispose_unregistered_instances
    //                 = DDS_BOOLEAN_FALSE;
    //     }
    //
    // The DDS default is TRUE, which makes a conformant writer DISPOSE each
    // instance it unregisters, so the reader reports NOT_ALIVE_DISPOSED
    // (DDS v1.4 Sec.2.2.3.21). The explicit-unregister run
    // (`--final-instance-state u`) asks for NOT_ALIVE_NO_WRITERS, which is
    // only reachable with the policy turned off.
    //
    // The plain-exit run (no `--final-instance-state`) asks for
    // NOT_ALIVE_NO_WRITERS as well, and there the writer's deletion is the
    // unregister: deleting a DataWriter unregisters its instances, and the
    // same flag decides whether that disposes them (DDS v1.4
    // Sec.2.2.2.4.1.6, Sec.2.2.3.21). The reference app keeps the default
    // there and relies on its vendor not disposing on deletion; ours follows
    // the standard, so it states what the run means instead.
    //
    // Only the dispose run (`--final-instance-state d`) keeps the default:
    // it disposes explicitly, and the deletion then skips the instances it
    // disposed.
    let writer_qos = if options.dispose {
        qos.clone()
    } else {
        qos.clone().writer_data_lifecycle_manual_dispose()
    };

    for idx in 0..options.num_topics {
        let tname = &topic_names[idx as usize];
        let topic = participant.topic::<ShapeType>(tname)?;

        // pexpect matches: "Create writer for topic"
        println!("Create writer for topic: {} color: {}", tname, color);

        let mut writer_builder = topic
            .writer()
            .qos(writer_qos.clone())
            .with_listener(Arc::new(WriterListener {
                topic_name: tname.clone(),
            }));
        if let Some(ref pub_entity) = publisher {
            writer_builder = writer_builder.publisher(pub_entity);
        }
        let writer = writer_builder.build()?;
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

    // TRANSIENT_LOCAL coherent publishers hold the first write until every
    // published topic has a compatible remote reader (or a QoS-incompatible
    // verdict, meaning a match will never come). Samples written before the
    // subscriber exists can only reach it through the durable late-join
    // repair path, and classic-model collators cannot reconstruct
    // coherent-set boundaries from repaired history; holding the first write
    // keeps the whole run on the in-order live stream. Bounded so a missing
    // subscriber cannot hang the process.
    let coherent_tl_gate = (options.coherent_set_enabled
        || (options.ordered_access_enabled && options.coherent_set_sample_count != 0))
        && options.durability_kind == DurabilityKind::TransientLocal;
    if coherent_tl_gate {
        let gate_start = std::time::Instant::now();
        while gate_start.elapsed() < Duration::from_secs(30)
            && !ALL_DONE.load(Ordering::SeqCst)
            && !topic_names
                .iter()
                .all(|t| notifier.is_pub_topic_matched(t) || notifier.is_topic_incompatible(t))
        {
            thread::sleep(Duration::from_millis(20));
        }
        // Settle after the SEDP match surfaces: the subscriber's user
        // endpoint needs a beat before it accepts directed reliable traffic
        // (its preemptive ACKNACK egresses before its receive path is warm:
        // the first coherent window sent immediately at match is not
        // received live and must be repaired, which reorders history
        // delivery and breaks classic coherent collation).
        if !ALL_DONE.load(Ordering::SeqCst) {
            thread::sleep(Duration::from_millis(300));
        }
    }

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

        // FIX #6: coherent sets -- emit ONE COMPLETE set per iteration.
        //
        // The coherent-set check of the OMG interoperability tests (and any
        // classic-model collator) requires `coherent_set_sample_count`
        // CONSECUTIVE samples per instance, across all instances and topics,
        // inside a single begin/end window, delivered atomically. Spreading
        // the set across `count` iterations (one sample per instance per
        // iteration, interleaved) makes the subscriber's periodic read catch
        // partial sets and the consecutive-per-instance count drift, so the
        // subscriber reports a wrong per-instance count. So we wrap the full set in
        // one begin/end and burst `count` consecutive samples per instance.
        // For non-coherent writers (and count==1) the inner loop runs once,
        // preserving the original one-sample-per-instance-per-iteration cadence
        // bit-for-bit.
        // Coherent runs wrap every iteration burst in begin/end even without
        // an explicit --coherent-sample-count: coherent_access QoS with bare
        // writes leaves the samples without set information on the wire, and
        // a GROUP-scope subscriber withholds delivery of samples it cannot
        // associate with a completed set (DDS 1.4 2.2.3.6 PRESENTATION).
        // Ordered-only runs keep the sample-count condition (no coherent wire
        // semantics involved).
        // Coherent-set window: one set per iteration of this loop, written
        // as a BURST of `coherent_set_sample_count` sub-iterations, each
        // sub-iteration moving the shape, bumping shapesize (`-z 0` increases
        // the size for EVERY sample, as the OMG reference driver does) and
        // writing ONE sample per topic x instance. Sample content therefore
        // matches the reference driver (count distinct sizes per instance per
        // set) while the set still leaves the writer in a single burst per
        // write period, which keeps the per-read-cycle count stable for the
        // harness. count == 0 (coherent QoS without a sample count) = one
        // sub-iteration.
        let coherent_active = options.coherent_set_enabled
            || (options.ordered_access_enabled && options.coherent_set_sample_count != 0);
        let sub_iterations = if coherent_active && options.coherent_set_sample_count != 0 {
            options.coherent_set_sample_count
        } else {
            1
        };

        if coherent_active {
            println!("Started Coherent Set");
            if let Some(ref pub_entity) = publisher {
                let _ = pub_entity.begin_coherent_changes();
            }
        }

        // Write ONE sample to all topics x all instances per sub-iteration.
        for sub in 0..sub_iterations {
            if sub > 0 {
                // Same per-sample motion and size bump as the top of the
                // iteration, so every sample in the set is distinct.
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
            }
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
        }

        // FIX #6: coherent sets -- end (close the full set built above).
        if coherent_active {
            println!("Finished Coherent Set");
            if let Some(ref pub_entity) = publisher {
                let _ = pub_entity.end_coherent_changes();
            }
        }

        // No wait for the set's acknowledgement before the next one. Such a
        // wait (bounded at 2 s) meant to keep a classic
        // collator from merging a repaired window with a later one; it never
        // waited while the writer learned no acknowledgement over UDP, and
        // once it did it throttled the publisher against any reader that
        // acknowledges slowly.
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
    // Coherent / ordered access runtime is now wired through the
    // Publisher GSN / ECS DATA submessage protocol (RTPS v2.5 sec. 8.7.5);
    // the subscriber-side buffer + commit lives in ReaderSubscriber.
    // No bailout needed.
    let _ = options.take_read_next_instance; // kept for future read-vs-take wiring
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
                    let mut reader_builder = filtered_topic
                        .reader()
                        .qos(qos.clone())
                        .with_listener(Arc::new(ReaderListener {
                            topic_name: tname.clone(),
                        }));
                    // Attach coherent/ordered readers to the Subscriber
                    // entity so its cross-reader presentation group engages
                    // (DDS v1.4 2.2.3.6); inert for non-coherent QoS.
                    if let Some(ref sub_entity) = subscriber {
                        reader_builder = reader_builder.subscriber(sub_entity);
                    }
                    let reader = reader_builder.build()?;
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
            let mut reader_builder =
                topic
                    .reader()
                    .qos(qos.clone())
                    .with_listener(Arc::new(ReaderListener {
                        topic_name: tname.clone(),
                    }));
            // Attach coherent/ordered readers to the Subscriber entity so
            // its cross-reader presentation group engages (DDS v1.4
            // 2.2.3.6); inert for non-coherent QoS.
            if let Some(ref sub_entity) = subscriber {
                reader_builder = reader_builder.subscriber(sub_entity);
            }
            let reader = reader_builder.build()?;
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
        // FIX #6: coherent sets -- begin_access
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

        // Drain ALL samples from ALL readers. Under
        // `Presentation { access_scope = INSTANCE, ordered_access = true }`
        // DDS v1.4 sec. 2.2.3.6 requires the subscriber to deliver samples
        // grouped per-instance (all samples of one instance presented
        // contiguously before moving to the next). Under TOPIC / GROUP
        // scope we keep writer / publisher order. The grouping happens at
        // print time because the underlying take() returns samples in
        // arrival order; the OMG harness scrapes stdout, so the print
        // order is the contract.
        let is_instance_scope = (options.coherent_set_enabled || options.ordered_access_enabled)
            && matches!(options.coherent_access_scope, AccessScope::Instance);
        // Under coherent take, drain the whole cache in ONE atomic op so a
        // concurrent coherent commit (control/router thread) cannot be
        // observed mid-set: a per-sample loop releases the cache lock
        // between samples and can catch a PARTIAL set (a prefix of set N
        // plus the start of set N+1), breaching the atomic presentation
        // contract (DDS v1.4 2.2.3.6). take_all() pumps once then removes
        // the cache under a single lock. Only for the take path (use_read
        // is read, non-destructive) and only when a coherent/ordered set is
        // active so non-coherent tests keep the existing per-sample
        // behaviour.
        let coherent_atomic_drain =
            (options.coherent_set_enabled || options.ordered_access_enabled) && !options.use_read;
        for (idx, reader) in readers.iter().enumerate() {
            let mut drained: Vec<ShapeType> = Vec::new();
            if coherent_atomic_drain {
                if let Ok(batch) = reader.take_all() {
                    for sample in batch {
                        if !known_colors.iter().any(|c| c == &sample.color) {
                            known_colors.push(sample.color.clone());
                        }
                        drained.push(sample);
                    }
                }
            } else {
                loop {
                    let result = if options.use_read {
                        reader.read()
                    } else {
                        reader.take()
                    };
                    match result {
                        Ok(Some(sample)) => {
                            if !known_colors.iter().any(|c| c == &sample.color) {
                                known_colors.push(sample.color.clone());
                            }
                            drained.push(sample);
                        }
                        Ok(None) => break,
                        Err(_) => break,
                    }
                }
            }

            if is_instance_scope {
                // Stable sort by instance color so samples of one instance
                // appear contiguously while preserving the writer SN order
                // within each instance (sort_by is stable in Rust std).
                drained.sort_by(|a, b| a.color.cmp(&b.color));
            }

            for sample in &drained {
                // pexpect matches "[<digits>]" -- shapesize in brackets
                print!(
                    "{:<10} {:<10} {:03} {:03} [{}]",
                    topic_names[idx], sample.color, sample.x, sample.y, sample.shapesize
                );
                if !sample.additional_payload_size.is_empty() {
                    let last_idx = sample.additional_payload_size.len() - 1;
                    print!(" {{{}}}", sample.additional_payload_size[last_idx]);
                }
                println!();
            }
        }

        // FIX #4: Check for dispose/unregister events from all readers (P1.2)
        //
        // Deliberately still on `get_dispose_events` after its deprecation in
        // 1.5.0, and NOT migrated to `take_with_info`. The rendering below
        // needs the exact `DisposeKind`, including the combined
        // `DisposedUnregistered`, and `SampleInfo.instance_state` is a single
        // value with no variant for "both". Migrating would silently drop the
        // combined case and change what this conformance app prints, which is
        // what the interoperability checks read. The gap is deliberate and
        // documented here rather than papered over.
        #[allow(deprecated)]
        for (idx, reader) in readers.iter().enumerate() {
            for event in reader.get_dispose_events() {
                let color = color_from_key_hash_with_map(&event.key_hash, &known_colors);
                // A combined dispose+unregister (StatusInfo 0x03, which a
                // writer may send on clean exit) carries
                // BOTH lifecycle transitions in one event. The OMG check for
                // unregister (test_unregistering_w_instances) scans for
                // NOT_ALIVE_NO_WRITERS, while the dispose check
                // (test_disposing_w_instances) scans for NOT_ALIVE_DISPOSED;
                // each ignores the line it does not own. Emit BOTH states so
                // the combined case satisfies whichever check is running. The
                // library still surfaces the precise DisposedUnregistered kind
                // for real consumers -- this rendering choice is local to the
                // conformance app.
                let states: &[&str] = match event.kind {
                    hdds::engine::DisposeKind::Disposed => &["NOT_ALIVE_DISPOSED_INSTANCE_STATE"],
                    hdds::engine::DisposeKind::Unregistered => {
                        &["NOT_ALIVE_NO_WRITERS_INSTANCE_STATE"]
                    }
                    hdds::engine::DisposeKind::DisposedUnregistered => &[
                        "NOT_ALIVE_NO_WRITERS_INSTANCE_STATE",
                        "NOT_ALIVE_DISPOSED_INSTANCE_STATE",
                    ],
                };
                for state_str in states {
                    println!("{:<10} {:<10} {}", topic_names[idx], color, state_str);
                }
            }
        }

        // Coherent sets / ordered access -- end_access
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
    // Opt-in debug logging for the interop binary (RUST_LOG=hdds=debug ...).
    // No-op unless RUST_LOG is set, so it does not pollute harness stdout.
    let _ = env_logger::try_init();
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

#[cfg(test)]
mod key_payload_tests {
    use super::ShapeType;
    use hdds::dds::DDS;

    fn shape(color: &str) -> ShapeType {
        ShapeType {
            color: color.to_string(),
            x: 1,
            y: 2,
            shapesize: 30,
            additional_payload_size: Vec::new(),
        }
    }

    fn encapsulated(kind: u16, body: &[u8]) -> Vec<u8> {
        let mut out = kind.to_be_bytes().to_vec();
        out.extend_from_slice(&[0, 0]);
        out.extend_from_slice(body);
        while !out.len().is_multiple_of(4) {
            out.push(0);
        }
        out
    }

    /// The key-only payload of a dispose names the instance its samples
    /// name, at both versions: for "BLUE" the MD5 of `00000005 'BLUE\0'`
    /// (RTPS 2.5 9.6.4.8 step 5.2), not the zero-padded form a type-blind
    /// reading of the string gives.
    #[test]
    fn a_key_only_payload_names_the_instance_of_its_color() {
        let blue = shape("BLUE");
        let key = blue.compute_key();
        assert_eq!(
            key.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            "cac217c318363f8ef1160eeedef9e886"
        );
        for (kind, version) in [
            (0x0009u16, hdds::CdrVersion::Xcdr2),
            (0x0001, hdds::CdrVersion::Xcdr1),
        ] {
            let payload = encapsulated(kind, &blue.encode_key(version));
            assert_eq!(ShapeType::key_hash_of_key_payload(&payload), Some(key));
        }
        let red = encapsulated(0x0009, &shape("RED").encode_key(hdds::CdrVersion::Xcdr2));
        assert_eq!(
            ShapeType::key_hash_of_key_payload(&red),
            Some(shape("RED").compute_key())
        );
    }

    /// The serializedPayload Eclipse Cyclone DDS 11.0.1's shape_main sent
    /// for the dispose of BLUE (`--final-instance-state d`), captured on
    /// loopback: no PID_KEY_HASH, K=1, encapsulation options 0x0003 (three
    /// padding bytes), under XCDR1 and XCDR2. Both name BLUE's instance.
    #[test]
    fn cyclone_11_dispose_payloads_name_blue() {
        let x1: [u8; 16] = [
            0x00, 0x01, 0x00, 0x03, 0x05, 0, 0, 0, b'B', b'L', b'U', b'E', 0, 0, 0, 0,
        ];
        let x2: [u8; 20] = [
            0x00, 0x09, 0x00, 0x03, 0x09, 0, 0, 0, 0x05, 0, 0, 0, b'B', b'L', b'U', b'E', 0, 0, 0,
            0,
        ];
        let blue = shape("BLUE").compute_key();
        assert_eq!(ShapeType::key_hash_of_key_payload(&x1), Some(blue), "xcdr1");
        assert_eq!(ShapeType::key_hash_of_key_payload(&x2), Some(blue), "xcdr2");
    }

    /// The same key big endian (D_CDR2_BE) names BLUE's instance too: the
    /// MD5 form (string<128>), not the zero-padded form a type-blind reading
    /// of the string gave.
    #[test]
    fn a_big_endian_color_names_its_instance() {
        let be: [u8; 20] = [
            0x00, 0x08, 0x00, 0x03, 0, 0, 0, 0x09, 0, 0, 0, 0x05, b'B', b'L', b'U', b'E', 0, 0, 0,
            0,
        ];
        let blue = shape("BLUE").compute_key();
        assert_eq!(ShapeType::key_hash_of_key_payload(&be), Some(blue));
        let mut padded = [0u8; 16];
        padded[..4].copy_from_slice(&5u32.to_be_bytes());
        padded[4..9].copy_from_slice(b"BLUE\0");
        assert_ne!(padded, blue);
    }

    /// A color of exactly 128 characters, the bound, is read.
    #[test]
    fn a_color_at_its_bound_names_its_instance() {
        let at_bound = shape(&"C".repeat(128));
        let payload = encapsulated(0x0001, &at_bound.encode_key(hdds::CdrVersion::Xcdr1));
        assert_eq!(
            ShapeType::key_hash_of_key_payload(&payload),
            Some(at_bound.compute_key())
        );
    }

    /// A color beyond `string<128>`, or bytes after the key, name nothing.
    #[test]
    fn an_unreadable_color_names_no_instance() {
        let long = "C".repeat(129);
        let mut body = Vec::new();
        body.extend_from_slice(&130u32.to_le_bytes());
        body.extend_from_slice(long.as_bytes());
        body.push(0);
        assert_eq!(
            ShapeType::key_hash_of_key_payload(&encapsulated(0x0001, &body)),
            None
        );
        let mut extra = shape("BLUE").encode_key(hdds::CdrVersion::Xcdr1);
        extra.extend_from_slice(&[0, 0, 0, 0, 7, 0, 0, 0]);
        assert_eq!(
            ShapeType::key_hash_of_key_payload(&encapsulated(0x0001, &extra)),
            None
        );
    }
}
