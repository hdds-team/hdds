// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! RTPS packet routing engine
//!
//! Routes incoming RTPS packets (DATA, Heartbeat, AckNack) from the multicast ring
//! to registered topic subscribers. Provides background thread orchestration and
//! telemetry for packet processing.

// The submessage chain is walked HERE the way it is walked everywhere else.
// Hand-written copies of that loop drift apart: some realign to the 4-octet
// boundary of Sec.9.4.1 and some do not, so on a sender that under-declares
// its padding they disagree about whether the datagram contains a DATA at
// all. There is one traversal, and the question each caller asks is the only
// thing that differs. A second copy here is a defect, not a shortcut.
use crate::core::discovery::fragment_buffer::SampleAudience;
use crate::core::discovery::multicast::classifier::walk;
use crate::core::discovery::multicast::control_types::ENTITYID_UNKNOWN;
use crate::core::discovery::multicast::{
    scan_all_addressed_data_frags_with_qos, FragmentMetadata, Origin, PacketKind, RxMeta, RxPool,
};
use crate::core::discovery::{EndpointRegistry, FragmentBuffer, GUID};
use crate::core::reader::ReaderProxyRegistry;
use crate::core::rtps_constants::INTERCOM_VENDOR_ID_U16;
use crate::engine::demux::TopicRegistry;
use crate::engine::router_spin::RouterSpinner;
use crate::engine::subscriber::LifecycleKey;
use crate::engine::wake::WakeNotifier;
use crate::engine::writer_control::route_ring_controls;
use crate::protocol::builder;
use crossbeam::queue::ArrayQueue;
use std::io;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::thread::JoinHandle;
use std::time::Duration;

/// Default configuration for user DATA_FRAG fragment buffer.
///
/// The timeout is an IDLE bound (no NEW fragment stored for this long), not
/// a total reassembly deadline: NACK_FRAG-driven repair from slow peers can
/// trickle in at a few fragments per second, so a large sample legitimately
/// takes many seconds to complete. 15s idle with the 256-entry pending cap
/// bounds worst-case memory at roughly 256 x ~100KB ~= 25MB.
const USER_FRAG_MAX_PENDING: usize = 256;
const USER_FRAG_TIMEOUT_MS: u64 = 15000;

// ============================================================================
// Metrics
// ============================================================================

/// Latency-friendly counters updated by the demux router to track packet handling outcomes.
///
/// All fields use relaxed atomics which is sufficient because consumers only need
/// monotonic snapshots for observability.
#[derive(Debug)]
pub struct RouterMetrics {
    pub packets_routed: AtomicU64,
    pub packets_orphaned: AtomicU64,
    pub delivery_errors: AtomicU64,
    pub bytes_delivered: AtomicU64,
    /// Number of NACK_FRAG requests generated (fragments missing after timeout)
    pub nack_frag_requests: AtomicU64,
    /// Number of fragment sequences that timed out completely
    pub fragment_timeouts: AtomicU64,
    /// Always 0: the router does not drop a DATA as a duplicate; each
    /// reader's per-writer duplicate window does (see the router loop). Kept
    /// so the public struct and `snapshot` keep their shape.
    pub packets_deduplicated: AtomicU64,
    /// DATA packets for which the router had to substitute sequence number zero.
    pub missing_sequence_fallbacks: AtomicU64,
    /// Times the router thread found its receive ring empty, spun, and
    /// popped a datagram before its spin budget ran out (a park and a wake
    /// avoided). Written by the router thread only.
    pub spin_hits: AtomicU64,
    /// Times a spin ran its whole budget without a datagram and the router
    /// thread parked afterwards. A zero budget does not spin, so it counts
    /// no miss.
    pub spin_misses: AtomicU64,
    /// Wall-clock nanoseconds spent in the missed spins counted by
    /// `spin_misses`: CPU burnt for nothing.
    pub spin_ns_wasted: AtomicU64,
    /// Times the router thread parked (waited for the receive thread's
    /// wake, or for its 10 ms idle timeout).
    pub parks: AtomicU64,
    /// The spin budget, in nanoseconds, the router thread used for its
    /// latest spin: the learned value under the default adaptive spin (0
    /// while the waste cap holds it off), or the fixed one configured via
    /// `HDDS_ROUTER_SPIN_US` otherwise.
    pub spin_budget_ns: AtomicU64,
    /// Lifecycle changes (dispose, unregister) that named no instance for a
    /// subscriber: no PID_KEY_HASH, and a serialized key the subscriber's
    /// type does not read (or none). Dropped, never named by a guess.
    pub lifecycle_unnamed: AtomicU64,
}

impl RouterMetrics {
    /// Create a zeroed metrics struct ready for concurrent updates.
    #[inline]
    pub fn new() -> Self {
        Self {
            packets_routed: AtomicU64::new(0),
            packets_orphaned: AtomicU64::new(0),
            delivery_errors: AtomicU64::new(0),
            bytes_delivered: AtomicU64::new(0),
            nack_frag_requests: AtomicU64::new(0),
            fragment_timeouts: AtomicU64::new(0),
            packets_deduplicated: AtomicU64::new(0),
            missing_sequence_fallbacks: AtomicU64::new(0),
            spin_hits: AtomicU64::new(0),
            spin_misses: AtomicU64::new(0),
            spin_ns_wasted: AtomicU64::new(0),
            parks: AtomicU64::new(0),
            spin_budget_ns: AtomicU64::new(0),
            lifecycle_unnamed: AtomicU64::new(0),
        }
    }

    /// Return the current metrics counters without synchronisation penalties.
    #[inline]
    #[must_use]
    pub fn snapshot(&self) -> (u64, u64, u64, u64, u64, u64, u64) {
        (
            self.packets_routed.load(Ordering::Relaxed),
            self.packets_orphaned.load(Ordering::Relaxed),
            self.delivery_errors.load(Ordering::Relaxed),
            self.bytes_delivered.load(Ordering::Relaxed),
            self.nack_frag_requests.load(Ordering::Relaxed),
            self.fragment_timeouts.load(Ordering::Relaxed),
            self.packets_deduplicated.load(Ordering::Relaxed),
        )
    }
}

impl Default for RouterMetrics {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Route Status
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Outcome of routing a single RTPS data packet through the demux registry.
pub enum RouteStatus {
    Delivered,
    Orphaned,
    Dropped,
}

// ============================================================================
// Routing Logic (HOT PATH)
// ============================================================================

/// Deliver EVERY per-instance dispose/unregister DATA submessage carried in a
/// single datagram, not just the first.
///
/// A writer may put several per-instance disposes into ONE UDP datagram
/// (RTPS v2.5 8.3.3: a message carries any number of submessages). The
/// classifier picks only the first DATA submessage, and before `route_data_packet` split a
/// datagram of several DATA into one synthetic datagram per DATA
/// (`route_multi_data_datagram`), this walk was what delivered the other
/// disposes. Since that split, every datagram it is handed carries a single
/// DATA, so it finds that DATA's dispose and no other; it is kept as the
/// reader of the dispose's key, not for the batching.
///
/// The walk is confined to the dispose lifecycle: it scans submessages from the
/// RTPS header end (offset 20), and for each DATA (0x15) carrying a `K` flag and
/// a dispose/unregister `PID_STATUS_INFO`, it resolves the instance key (from
/// `PID_KEY_HASH` or, when that is absent, the serialized key) and delivers a dispose
/// event on the already-resolved `topic`. Normal sample routing is untouched.
/// Returns the number of dispose events delivered.
///
/// Each dispose is delivered under ITS DATA's writerSN. RTPS v2.5 Sec.8.3.8.2:
/// the writerSN "uniquely identifies the change and the relative order for all
/// changes made by the RTPS Writer", and a dispose is such a change
/// (Sec.8.7.4). The reader orders the transition against the writer's samples
/// by that number and lets only a sample sent AFTER it revive the instance
/// (DDS v1.4 Sec.2.2.2.5.1.3). Delivered as 0, every key-only dispose sat
/// before all of its writer's samples, and a reliable repair of a sample the
/// writer sent BEFORE the dispose brought the disposed instance back to ALIVE.
///
/// And under ITS DATA's writer: an unregister says that one writer stops
/// writing the instance, which leaves it NOT_ALIVE_NO_WRITERS only "if no other
/// DataWriter entities are writing the instance" (DDS v1.4 Sec.2.2.2.4.2.7).
/// Without the sender the reader cannot tell the last writer from one of
/// several.
///
/// Everything a DATA says, it says inside its own submessage: the inline QoS
/// and the serialized key are read from the datagram cut at the DATA's end
/// (RTPS v2.5 Sec.9.4.5.1.3), never from the submessages behind it.
fn deliver_all_disposes_in_datagram(
    payload: &[u8],
    topic: &crate::engine::demux::Topic,
    registry: &TopicRegistry,
    metrics: &RouterMetrics,
) -> usize {
    let mut delivered = 0usize;
    walk::for_each_submessage(payload, |found| {
        let offset = found.offset;
        let flags = found.flags;
        let is_le = flags & 0x01 != 0;

        // Only DATA submessages with the K (serialized-key) flag are dispose
        // candidates; everything else is skipped without interpretation.
        if found.id != 0x15 || (flags & 0x08) == 0 {
            return walk::Step::Continue;
        }
        // The datagram up to the end of THIS DATA: what lies behind it is
        // another submessage, not this one's inline QoS or key.
        let Some(submessage) = payload.get(..found.body_end) else {
            return walk::Step::Continue;
        };
        // Sec.8.3.8.2 / 9.4.5.3: header(4) extraFlags(2) octetsToInlineQos(2)
        // readerId(4) writerId(4), then writerSN(8) as high:i32, low:u32 in
        // the submessage's byte order.
        let Some(fixed) = submessage.get(offset..offset + 24) else {
            return walk::Step::Continue;
        };
        let read_u32 = |at: usize| {
            let b = [fixed[at], fixed[at + 1], fixed[at + 2], fixed[at + 3]];
            if is_le {
                u32::from_le_bytes(b)
            } else {
                u32::from_be_bytes(b)
            }
        };
        let writer_sn = (u64::from(read_u32(16)) << 32) | u64::from(read_u32(20));
        // The writer that sent THIS DATA: the sender's prefix (the RTPS
        // header; a datagram behind an INFO_SRC is split on it before this
        // point) and the DATA's own writerId (Sec.8.3.8.2).
        let Some(prefix) = payload.get(8..20) else {
            return walk::Step::Continue;
        };
        let mut writer_guid = [0u8; 16];
        writer_guid[..12].copy_from_slice(prefix);
        writer_guid[12..].copy_from_slice(&fixed[12..16]);
        // Inline QoS is a ParameterList terminated by PID_SENTINEL (0x0001).
        let Some((iq, _)) = builder::extract_inline_qos_at(submessage, offset) else {
            return walk::Step::Continue;
        };
        let Some(status) = builder::extract_status_info(iq, is_le) else {
            return walk::Step::Continue;
        };
        if (status & 0x03) == 0 {
            return walk::Step::Continue;
        }
        let key_hash = builder::extract_key_hash(iq, is_le);
        // Resolved ONLY for a writer flagged legacy (vendor HDDS, pre-
        // `CAP_CONFORMANT_KEY_HASH`): see `LifecycleKey::legacy_resolved`'s
        // doc and `TopicRegistry::resolve_legacy_key_hash_instance`.
        let legacy_resolved = key_hash
            .filter(|_| registry.writer_uses_legacy_key_hash(&writer_guid))
            .and_then(|kh| registry.resolve_legacy_key_hash_instance(&writer_guid, &kh));
        let key = LifecycleKey {
            key_hash,
            serialized_key: builder::extract_key_payload_at(submessage, offset),
            legacy_resolved,
        };
        if key.is_some() {
            let kind = match status & 0x03 {
                0x03 => crate::engine::subscriber::DisposeKind::DisposedUnregistered,
                0x02 => crate::engine::subscriber::DisposeKind::Unregistered,
                _ => crate::engine::subscriber::DisposeKind::Disposed,
            };
            let (errors, unnamed) = topic.deliver_lifecycle_coherent(
                writer_guid,
                writer_sn,
                key,
                kind,
                None,
                None,
                None,
            );
            if errors > 0 {
                metrics
                    .delivery_errors
                    .fetch_add(errors as u64, Ordering::Relaxed);
            }
            note_unnamed_lifecycle(metrics, unnamed, topic);
            delivered += 1;
        }

        walk::Step::Continue
    });
    delivered
}

/// Count the subscribers a lifecycle change named no instance for (no
/// PID_KEY_HASH, and a serialized key their type does not read, or none),
/// and say so once per process: the change is dropped for them.
fn note_unnamed_lifecycle(
    metrics: &RouterMetrics,
    unnamed: usize,
    topic: &crate::engine::demux::Topic,
) {
    static WARNED: AtomicBool = AtomicBool::new(false);
    if unnamed == 0 {
        return;
    }
    metrics
        .lifecycle_unnamed
        .fetch_add(unnamed as u64, Ordering::Relaxed);
    if !WARNED.swap(true, Ordering::Relaxed) {
        log::warn!(
            "[ROUTER] topic='{}': a dispose or unregister named no instance (no PID_KEY_HASH, \
             and a serialized key the reader's type does not read): dropped, counted in \
             RouterMetrics::lifecycle_unnamed; logged once",
            topic.name()
        );
    }
}

/// The fragment data the classifier's `meta` names, bounded by the
/// DATA_FRAG that carries it: from `payload_offset` when the classifier
/// computed one, else from that DATA_FRAG's own layout.
fn fragment_bytes<'a>(
    payload: &'a [u8],
    payload_offset: Option<usize>,
    meta: &FragmentMetadata,
) -> Option<&'a [u8]> {
    let offset = match payload_offset {
        Some(offset) => offset,
        // The DATA_FRAG `meta` was read from, laid out by the one layout
        // reader (RTPS v2.5 Sec.9.4.5.5). The DATA extractor must not be
        // asked: it finds a DATA, never a DATA_FRAG, so beside one in the
        // datagram its payload would go to reassembly as this fragment.
        None => {
            let at = builder::find_data_frag(
                payload,
                meta.writer_guid.entity_id,
                meta.seq_num,
                meta.frag_num,
            )?;
            builder::data_submessage_layout(payload, at)?.payload
        }
    };
    if offset >= payload.len() {
        return None;
    }
    let end =
        crate::core::discovery::multicast::classifier::submessage_end_for_payload(payload, offset)
            .unwrap_or(payload.len());
    Some(&payload[offset..end.max(offset)])
}

/// The DATA submessages `data_submessages` counts, for a test.
#[cfg(test)]
fn count_data_submessages(payload: &[u8]) -> usize {
    data_submessages(payload).0
}

/// Count DATA (0x15) submessages carried in one RTPS datagram, walking from the
/// 20-byte header end, and say where the first one's header is. The count
/// decides whether the multi-DATA split path is needed; `<= 1` keeps the
/// zero-allocation single-DATA fast path, which reads the first DATA at the
/// offset this walk found. Only `<= 1` and `> 1` are told apart, so the scan
/// stops as soon as the count reaches 2: the count saturates at 2 and is not
/// exact for datagrams carrying 3 or more DATA submessages.
fn data_submessages(payload: &[u8]) -> (usize, Option<usize>) {
    let mut count = 0usize;
    let mut first = None;
    walk::for_each_submessage(payload, |found| {
        if found.id == 0x15 {
            count += 1;
            first.get_or_insert(found.offset);
            if count >= 2 {
                return walk::Step::Stop;
            }
        }
        walk::Step::Continue
    });
    (count, first)
}

/// Offset of the serialized payload (encapsulation-header start) for the DATA
/// submessage beginning at `data_off`. Mirrors the classifier so a synthetic
/// single-DATA datagram strips encapsulation identically to the normal path.
/// Returns `None` if the inline-QoS ParameterList has no PID_SENTINEL in range.
fn data_submsg_payload_offset(payload: &[u8], data_off: usize) -> Option<usize> {
    builder::data_submessage_layout(payload, data_off).map(|layout| layout.payload)
}

/// End (exclusive) of the serialized data in a SerializedPayload whose
/// encapsulation header starts at `header` and whose bytes run to `end`:
/// `end` less the padding counted in the two low bits of the options.
///
/// DDS-XTypes 1.3 7.6.3.1.2: those bits encode "the number of padding bytes
/// needed after the end of the serialized payload in order to reach the next
/// 4-byte aligned offset" and "shall be interpreted by the receiver to
/// determine where the serialized data exactly ended". Every typed decoder
/// stops at its last member and never noticed the padding; a byte-exact
/// consumer did (an opaque payload got up to three zero octets more than
/// was written, and a sealed one carries its tag at the end). A count that
/// would leave no serialized data behind the header is not believed: padding
/// follows data, so a count as large as the body is not a count of padding.
/// Nor is a count behind a payload that does not end on four octets: the
/// padding exists only to reach that boundary, so a sender that counts it
/// without sending it (OpenDDS 3.35 on its last submessage) left the counted
/// octets out, and cutting them would cut serialized data.
fn serialized_data_end(payload: &[u8], header: usize, end: usize) -> usize {
    let Some(&options_low) = payload.get(header + 3) else {
        return end;
    };
    let padding = usize::from(options_low & 0x03);
    if !end.saturating_sub(header).is_multiple_of(4) {
        return end;
    }
    if end > header + 4 + padding {
        end - padding
    } else {
        end
    }
}

/// End offset (exclusive) of the DATA submessage whose serialized payload
/// contains `payload_offset`, per RTPS v2.5 sec. 8.3.3: a submessage spans
/// `[off, off + 4 + octetsToNextHeader)`, and `octetsToNextHeader == 0` on
/// the LAST submessage means "extends to the end of the message".
///
/// The serialized payload of a DATA submessage ends at the submessage end, NOT at
/// the datagram end: a writer may piggyback HEARTBEAT (and other) submessages after
/// DATA in the same datagram. Slicing to the datagram end leaks those trailing
/// submessage bytes into the delivered payload; decoders that are strictly
/// field/DHEADER driven never read them, but any length-sensitive decode (XCDR1
/// appendable truncation semantics) misreads them as data.
///
/// Returns `payload.len()` when no DATA submessage containing
/// `payload_offset` is found, so malformed or vendor-header-recovered
/// datagrams are taken whole.
fn data_submsg_end_for(payload: &[u8], payload_offset: usize) -> usize {
    let mut found_end = None;
    walk::for_each_submessage(payload, |found| {
        if found.id == 0x15
            && payload_offset >= found.offset + 4
            && payload_offset <= found.body_end
        {
            found_end = Some(found.body_end);
            return walk::Step::Stop;
        }
        walk::Step::Continue
    });
    found_end.unwrap_or(payload.len())
}

/// Build the synthetic single-DATA datagram for the DATA spanning `data`, and
/// say where that DATA landed in it.
///
/// The result is `payload`'s leading context - the RTPS header and every
/// submessage before the first DATA - followed by whatever INFO_DST and
/// INFO_TS have REPLACED part of that context further down the chain, then
/// the DATA itself.
///
/// The newer INFO_TS is appended after the prefix's own rather than spliced
/// over it, which is correct because `parse_info_ts_ns` answers with the LAST
/// one before the DATA. That coupling is the reason this is one commit with
/// the `parse_info_ts_ns` rewrite: apply either half alone and samples 2..N
/// keep the first sample's timestamp.
///
/// The returned offset is `first` only for the datagram's FIRST DATA. Reading
/// the payload offset at `first` unconditionally lands in the middle of the
/// appended context as soon as there is any.
fn synthesise_single_data(
    payload: &[u8],
    first: usize,
    ctx_info_dst: Option<(usize, usize)>,
    ctx_info_ts: Option<(usize, usize)>,
    data: (usize, usize),
) -> (Vec<u8>, usize) {
    let (data_start, data_end) = data;
    let ctx_len = ctx_info_dst.map_or(0, |(s, e)| e - s) + ctx_info_ts.map_or(0, |(s, e)| e - s);

    let mut syn = Vec::with_capacity(first + ctx_len + (data_end - data_start));
    syn.extend_from_slice(&payload[..first]);
    if let Some((s, e)) = ctx_info_dst {
        syn.extend_from_slice(&payload[s..e]);
    }
    if let Some((s, e)) = ctx_info_ts {
        syn.extend_from_slice(&payload[s..e]);
    }

    let data_at = syn.len();
    syn.extend_from_slice(&payload[data_start..data_end]);
    (syn, data_at)
}

/// RTPS v2.5 sec. 8.3.4: a single datagram MAY carry several DATA submessages.
/// A writer may batch many per-instance samples this way; routing only the
/// first would drop every other sample and -- under RELIABLE -- leave their
/// sequence numbers un-acked, which triggers an endless retransmit storm.
///
/// This walks every DATA submessage and re-routes each as a synthetic
/// single-DATA datagram carrying the RTPS header, the leading context
/// (HEADER_EXTENSION + INFO_DST + INFO_TS) and any INFO_TS
/// or INFO_DST that REPLACED part of that context further down the chain - so
/// each sample is delivered and acked exactly as if it had arrived alone,
/// with its own timestamp rather than the first sample's. This is GLOBAL RTPS correctness, not a
/// vendor accommodation: the path is chosen on the SHAPE of the datagram and
/// not on who sent it, so a datagram carrying a single DATA never reaches it
/// (`data_submessages` counts one).
///
/// Which vendors batch is something to measure, and the routing decision does
/// not need the answer.
fn route_multi_data_datagram(
    payload: &[u8],
    registry: &TopicRegistry,
    metrics: &RouterMetrics,
) -> RouteStatus {
    // Leading context spans the RTPS header and all submessages preceding the
    // first DATA (INFO_TS / INFO_DST / HEADER_EXTENSION), which apply to every
    // DATA that follows per RTPS v2.5 sec. 8.3.7.
    let mut first_data_off = None;
    walk::for_each_submessage(payload, |found| {
        if found.id == 0x15 {
            first_data_off = Some(found.offset);
            return walk::Step::Stop;
        }
        walk::Step::Continue
    });
    let first = match first_data_off {
        Some(f) => f,
        None => return RouteStatus::Dropped,
    };

    let mut any_delivered = false;

    // The INFO_TS and INFO_DST reached AFTER the first DATA. RTPS v2.5
    // Sec.8.3.8.11 and Sec.8.3.8.8 make both apply to the submessages that
    // FOLLOW them, so every DATA is entitled to the context in force when IT
    // was reached. Copying `payload[..first]` alone gave samples 2..N the
    // FIRST DATA's timestamp and destination, and silently: an INFO_TS sitting
    // between two DATA was never recopied. That is the defect
    // `classifier::walk` was written to end on the discovery path, here on the
    // user-data path.
    //
    // Spans rather than copies: nothing is allocated until a DATA is actually
    // rebuilt.
    let mut ctx_info_ts: Option<(usize, usize)> = None;
    let mut ctx_info_dst: Option<(usize, usize)> = None;

    walk::for_each_submessage(payload, |found| {
        // The leading context is copied wholesale by `synthesise_single_data`,
        // so the submessages before the first DATA are stepped over rather
        // than re-applied: re-applying them would append the prefix's own
        // INFO_TS to the synthetic datagram a second time.
        if found.offset < first {
            return walk::Step::Continue;
        }
        let off = found.offset;
        let end = found.body_end;

        match found.id {
            0x09 => ctx_info_ts = Some((off, end)),
            0x0e => ctx_info_dst = Some((off, end)),
            0x15 => {
                // Synthetic single-DATA datagram: the leading context, then
                // whatever has replaced part of it since, then this DATA.
                // Appending the newer INFO_TS AFTER the prefix's own is
                // enough rather than splicing it out, because
                // `parse_info_ts_ns` answers with the LAST one before the
                // DATA. Nothing on this path reads INFO_DST today; it is
                // carried so the synthetic datagram does not misdescribe the
                // one it stands for.
                let (syn, data_at) =
                    synthesise_single_data(payload, first, ctx_info_dst, ctx_info_ts, (off, end));
                let syn_off = data_submsg_payload_offset(&syn, data_at);
                let status = route_data_packet(&syn, syn.len(), syn_off, registry, metrics);
                if matches!(status, RouteStatus::Delivered) {
                    any_delivered = true;
                }
            }
            _ => {}
        }

        walk::Step::Continue
    });

    if any_delivered {
        RouteStatus::Delivered
    } else {
        RouteStatus::Dropped
    }
}

/// The legacy hash belongs only to the DATA currently being prepared. A scoped
/// carrier, like INFO_TS, avoids teaching from a separate, unadmitted decode.
#[derive(Debug, Clone, Copy)]
pub(crate) struct LegacyHashContext {
    writer: [u8; 16],
    seq: u64,
    hash: [u8; 16],
}

thread_local! {
    static ROUTE_LEGACY_HASH: std::cell::Cell<Option<LegacyHashContext>> =
        const { std::cell::Cell::new(None) };
}

pub(crate) struct LegacyHashScope(Option<LegacyHashContext>);

impl LegacyHashScope {
    pub(crate) fn enter(context: Option<LegacyHashContext>) -> Self {
        Self(ROUTE_LEGACY_HASH.with(|c| c.replace(context)))
    }
}

impl Drop for LegacyHashScope {
    fn drop(&mut self) {
        ROUTE_LEGACY_HASH.with(|c| c.set(self.0));
    }
}

pub(crate) fn route_legacy_hash_context(
    writer: Option<[u8; 16]>,
    seq: u64,
) -> Option<LegacyHashContext> {
    ROUTE_LEGACY_HASH.with(|c| {
        c.get()
            .filter(|ctx| Some(ctx.writer) == writer && ctx.seq == seq)
    })
}

pub(crate) fn route_legacy_hash(writer: Option<[u8; 16]>, seq: u64) -> Option<[u8; 16]> {
    ROUTE_LEGACY_HASH.with(|c| {
        c.get()
            .filter(|ctx| Some(ctx.writer) == writer && ctx.seq == seq)
            .map(|ctx| ctx.hash)
    })
}

/// The router's framing decision for the DATA currently being delivered
/// (`Topic::payload_framing_for_writer`), carried to the reader so that the
/// reader reads the bytes as the router left them and never decides again.
#[cfg(feature = "security")]
#[derive(Debug, Clone, Copy)]
pub(crate) struct PayloadFramingContext {
    writer: [u8; 16],
    seq: u64,
    framing: crate::engine::subscriber::PayloadFraming,
}

#[cfg(feature = "security")]
thread_local! {
    static ROUTE_PAYLOAD_FRAMING: std::cell::Cell<Option<PayloadFramingContext>> =
        const { std::cell::Cell::new(None) };
}

#[cfg(feature = "security")]
pub(crate) struct PayloadFramingScope(Option<PayloadFramingContext>);

#[cfg(feature = "security")]
impl PayloadFramingScope {
    pub(crate) fn enter(
        writer: [u8; 16],
        seq: u64,
        framing: crate::engine::subscriber::PayloadFraming,
    ) -> Self {
        let context = PayloadFramingContext {
            writer,
            seq,
            framing,
        };
        Self(ROUTE_PAYLOAD_FRAMING.with(|c| c.replace(Some(context))))
    }
}

#[cfg(feature = "security")]
impl Drop for PayloadFramingScope {
    fn drop(&mut self) {
        ROUTE_PAYLOAD_FRAMING.with(|c| c.set(self.0));
    }
}

/// How the router framed `writer`'s change `seq`, when this thread is
/// delivering it; `None` outside a routed delivery of that change.
#[cfg(feature = "security")]
pub(crate) fn route_payload_framing(
    writer: &[u8; 16],
    seq: u64,
) -> Option<crate::engine::subscriber::PayloadFraming> {
    ROUTE_PAYLOAD_FRAMING.with(|c| {
        c.get()
            .filter(|ctx| ctx.writer == *writer && ctx.seq == seq)
            .map(|ctx| ctx.framing)
    })
}

/// The lifecycle half of one D=1 DATA travels with the DATA through admission.
#[derive(Debug, Clone, Copy)]
pub(crate) struct InlineLifecycleContext {
    writer: [u8; 16],
    seq: u64,
    key: [u8; 16],
    kind: crate::engine::subscriber::DisposeKind,
    coherent: bool,
}

thread_local! {
    static ROUTE_INLINE_LIFECYCLE: std::cell::Cell<Option<InlineLifecycleContext>> =
        const { std::cell::Cell::new(None) };
}

pub(crate) struct InlineLifecycleScope(Option<InlineLifecycleContext>);

impl InlineLifecycleScope {
    pub(crate) fn enter(context: Option<InlineLifecycleContext>) -> Self {
        Self(ROUTE_INLINE_LIFECYCLE.with(|c| c.replace(context)))
    }
}

impl Drop for InlineLifecycleScope {
    fn drop(&mut self) {
        ROUTE_INLINE_LIFECYCLE.with(|c| c.set(self.0));
    }
}

#[cfg(test)]
pub(crate) fn inline_lifecycle_scope_for_test(
    writer: [u8; 16],
    seq: u64,
    key: [u8; 16],
    kind: crate::engine::subscriber::DisposeKind,
    coherent: bool,
) -> InlineLifecycleScope {
    InlineLifecycleScope::enter(Some(InlineLifecycleContext {
        writer,
        seq,
        key,
        kind,
        coherent,
    }))
}

pub(crate) fn route_inline_lifecycle_context(
    writer: Option<[u8; 16]>,
    seq: u64,
) -> Option<InlineLifecycleContext> {
    ROUTE_INLINE_LIFECYCLE.with(|c| c.get().filter(|v| Some(v.writer) == writer && v.seq == seq))
}

pub(crate) fn route_inline_lifecycle(
    writer: Option<[u8; 16]>,
    seq: u64,
) -> Option<([u8; 16], crate::engine::subscriber::DisposeKind)> {
    route_inline_lifecycle_context(writer, seq).map(|v| (v.key, v.kind))
}

/// A refused value of a staged set cannot publish its lifecycle on its own.
pub(crate) fn route_unstaged_inline_lifecycle(
    writer: Option<[u8; 16]>,
    seq: u64,
) -> Option<([u8; 16], crate::engine::subscriber::DisposeKind)> {
    route_inline_lifecycle_context(writer, seq)
        .filter(|v| !v.coherent)
        .map(|v| (v.key, v.kind))
}

fn inline_lifecycle_context(
    writer: [u8; 16],
    seq: u64,
    inline_qos: Option<(&[u8], bool)>,
    registry: &TopicRegistry,
) -> Option<InlineLifecycleContext> {
    let (iq, is_le) = inline_qos?;
    let kind = match builder::extract_status_info(iq, is_le)? & 3 {
        1 => crate::engine::subscriber::DisposeKind::Disposed,
        2 => crate::engine::subscriber::DisposeKind::Unregistered,
        3 => crate::engine::subscriber::DisposeKind::DisposedUnregistered,
        _ => return None,
    };
    let key = builder::extract_key_hash(iq, is_le)?;
    let key = if registry.writer_uses_legacy_key_hash(&writer) {
        registry
            .resolve_legacy_key_hash_instance(&writer, &key)
            .unwrap_or(key)
    } else {
        key
    };
    Some(InlineLifecycleContext {
        writer,
        seq,
        key,
        kind,
        coherent: builder::extract_coherent_set(iq, is_le).is_some()
            || builder::extract_group_coherent_set(iq, is_le).is_some(),
    })
}

/// Classification belongs to this change, including while metadata callbacks
/// run. Discovery updates and nested deliveries cannot reinterpret its DATA.
#[derive(Clone, Copy)]
struct GroupRouteContext {
    writer: [u8; 16],
    seq: u64,
    spec: bool,
    /// A writer recorded as `GroupDialect::SpecReceive` (Dust DDS).
    spec_receive: bool,
    writer_set: Option<[u8; 4]>,
    order: Option<OrderedGroupChange>,
    set_first_gsn: Option<u64>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct OrderedGroupChange {
    pub publisher: [u8; 16],
    pub gsn: u64,
    pub writer_set: [u8; 4],
}

#[derive(Clone, Copy)]
struct OrderedRouteContext {
    writer: [u8; 16],
    seq: u64,
    change: OrderedGroupChange,
    set_first_gsn: Option<u64>,
}

thread_local! {
    static ROUTE_ORDER: std::cell::Cell<Option<OrderedRouteContext>> =
        const { std::cell::Cell::new(None) };
    static ROUTE_ORDER_PENDING: std::cell::Cell<Option<([u8; 16], u64)>> =
        const { std::cell::Cell::new(None) };
}

pub(crate) struct OrderedGroupScope(Option<OrderedRouteContext>, Option<([u8; 16], u64)>);

pub(crate) struct SuppressedOrderScope {
    _group: Option<GroupRouteScope>,
    _order: OrderedGroupScope,
}

impl OrderedGroupScope {
    #[cfg(test)]
    pub(crate) fn enter(writer: [u8; 16], seq: u64, change: Option<OrderedGroupChange>) -> Self {
        Self::enter_with_set(writer, seq, change, None)
    }

    pub(crate) fn enter_with_set(
        writer: [u8; 16],
        seq: u64,
        change: Option<OrderedGroupChange>,
        set_first_gsn: Option<u64>,
    ) -> Self {
        Self(
            ROUTE_ORDER.with(|context| {
                context.replace(change.map(|change| OrderedRouteContext {
                    writer,
                    seq,
                    change,
                    set_first_gsn,
                }))
            }),
            ROUTE_ORDER_PENDING.with(|context| context.replace(None)),
        )
    }

    /// Consume a terminal change without creating another order owner.
    /// The coherent route context is a separate fallback and must be
    /// suppressed for this exact change as well, then restored on return.
    pub(crate) fn suppress(writer: [u8; 16], seq: u64) -> SuppressedOrderScope {
        let order = Self::enter_with_set(writer, seq, None, None);
        let group = ROUTE_GROUP.with(|context| {
            context
                .get()
                .filter(|context| context.writer == writer && context.seq == seq)
                .map(|mut context| {
                    context.order = None;
                    context.set_first_gsn = None;
                    GroupRouteScope::enter(context)
                })
        });
        SuppressedOrderScope {
            _group: group,
            _order: order,
        }
    }
}

impl Drop for OrderedGroupScope {
    fn drop(&mut self) {
        ROUTE_ORDER.with(|context| context.set(self.0));
        ROUTE_ORDER_PENDING.with(|context| context.set(self.1));
    }
}

pub(crate) fn route_order_needs_context(writer: [u8; 16], seq: u64) -> bool {
    ROUTE_ORDER_PENDING.with(|context| context.get() == Some((writer, seq)))
}

pub(crate) fn route_ordered_group(writer: [u8; 16], seq: u64) -> Option<OrderedGroupChange> {
    ROUTE_ORDER
        .with(|context| {
            context
                .get()
                .filter(|context| context.writer == writer && context.seq == seq)
                .map(|context| context.change)
        })
        .or_else(|| {
            ROUTE_GROUP.with(|context| {
                context
                    .get()
                    .filter(|context| context.writer == writer && context.seq == seq)
                    .and_then(|context| context.order)
            })
        })
}

/// A coherent wire change keeps its set identity even if this reader does
/// not request coherent access. Missing identity denotes an ordinary change.
pub(crate) fn route_ordered_group_set_first(change: OrderedGroupChange) -> Option<u64> {
    let same = |other: OrderedGroupChange| {
        other.publisher == change.publisher
            && other.gsn == change.gsn
            && other.writer_set == change.writer_set
    };
    if let Some(context) = ROUTE_ORDER.with(|slot| slot.get()) {
        return same(context.change)
            .then_some(context.set_first_gsn)
            .flatten();
    }
    ROUTE_GROUP.with(|slot| {
        slot.get().and_then(|context| {
            context.order.filter(|other| same(*other))?;
            context.set_first_gsn
        })
    })
}

#[inline(always)]
fn ordered_group_scope<R>(
    topic: &crate::engine::demux::Topic,
    registry: &TopicRegistry,
    writer: [u8; 16],
    seq: u64,
    qos: Option<(&[u8], bool)>,
    receive: impl FnOnce() -> R,
) -> R {
    if !topic.requires_ordered_group() {
        return receive();
    }
    receive_with_group_scope(registry, writer, seq, qos, receive)
}

// Keep the guard and its cleanup entirely off the ordinary receive path.
#[cold]
#[inline(never)]
fn receive_with_group_scope<R>(
    registry: &TopicRegistry,
    writer: [u8; 16],
    seq: u64,
    qos: Option<(&[u8], bool)>,
    receive: impl FnOnce() -> R,
) -> R {
    // Every reader of this wire event must observe the same availability cut.
    let _arrival = crate::dds::GroupArrivalScope::enter(
        writer,
        Some(seq),
        registry.capture_group_arrival(&writer),
    );
    let pending = qos.is_some_and(|(qos, le)| {
        builder::extract_group_seq_num(qos, le).is_some()
            && builder::extract_writer_group_info(qos, le).is_some()
    }) && registry.writer_group_context_pending(&writer);
    let change = qos.and_then(|(qos, le)| {
        let gsn = builder::extract_group_seq_num(qos, le)?;
        if !registry.writer_speaks_spec_group(&writer) {
            return None;
        }
        let entity = builder::extract_group_entity_id(qos, le)
            .or_else(|| registry.writer_spec_group(&writer))?;
        let mut publisher = writer;
        publisher[12..].copy_from_slice(&entity);
        Some(OrderedGroupChange {
            publisher,
            gsn,
            writer_set: builder::extract_writer_group_info(qos, le)?,
        })
    });
    let set_first_gsn = qos.and_then(|(qos, le)| builder::extract_group_coherent_set(qos, le));
    let _scope = OrderedGroupScope::enter_with_set(writer, seq, change, set_first_gsn);
    if pending {
        ROUTE_ORDER_PENDING.with(|context| context.set(Some((writer, seq))));
    }
    receive()
}

thread_local! {
    static ROUTE_GROUP: std::cell::Cell<Option<GroupRouteContext>> =
        const { std::cell::Cell::new(None) };
}

struct GroupRouteScope(Option<GroupRouteContext>);

impl GroupRouteScope {
    fn enter(context: GroupRouteContext) -> Self {
        Self(ROUTE_GROUP.with(|slot| slot.replace(Some(context))))
    }
}

impl Drop for GroupRouteScope {
    fn drop(&mut self) {
        ROUTE_GROUP.with(|slot| slot.set(self.0));
    }
}

fn route_group_context(writer: [u8; 16], seq: u64) -> Option<GroupRouteContext> {
    ROUTE_GROUP.with(|slot| {
        slot.get()
            .filter(|ctx| ctx.writer == writer && ctx.seq == seq)
    })
}

pub(crate) fn route_group_is_spec(writer: [u8; 16], seq: u64) -> Option<bool> {
    route_group_context(writer, seq).map(|ctx| ctx.spec)
}

/// Whether the change being routed is of a writer recorded as Dust DDS
/// (`GroupDialect::SpecReceive`), decided at its discovery and read once per
/// change with the spec flag above.
pub(crate) fn route_group_is_spec_receive(writer: [u8; 16], seq: u64) -> bool {
    route_group_context(writer, seq).is_some_and(|ctx| ctx.spec_receive)
}

pub(crate) fn route_group_writer_set(writer: [u8; 16], seq: u64) -> Option<[u8; 4]> {
    route_group_context(writer, seq).and_then(|ctx| ctx.writer_set)
}

thread_local! {
    /// Per-thread carrier for the source timestamp (RTPS INFO_TS) of the
    /// datagram currently being routed. Set by `route_data_packet` before it
    /// delivers into a subscriber and read by the reader pipeline so sample
    /// LIFESPAN is measured from the writer's source timestamp (DDS v1.4
    /// sec. 2.2.3 + RTPS v2.5 sec. 8.7.7) rather than reception time. `None` when the
    /// datagram carries no INFO_TS -> the reader falls back to reception time.
    static ROUTE_SOURCE_TS_NS: std::cell::Cell<Option<u64>> =
        const { std::cell::Cell::new(None) };
}

/// Store the source timestamp (epoch ns) of the datagram being routed on this
/// thread. Set to `None` for datagrams without a valid INFO_TS submessage.
pub(crate) fn set_route_source_ts_ns(ts: Option<u64>) {
    ROUTE_SOURCE_TS_NS.with(|c| c.set(ts));
}

/// The Publisher of a GROUP change of `writer_guid`: its
/// `PID_GROUP_ENTITY_ID` when the change carries one (HDDS 1.4.x and the
/// foreign dialects), else, for a writer of the spec GROUP class, the group
/// its SEDP announced (G11: the spec form carries no such inline PID). Only
/// a GROUP change (`group_sn`) looks the writer up.
fn group_publisher(
    registry: &TopicRegistry,
    writer_guid: &[u8; 16],
    group_sn: Option<u64>,
    inline: Option<[u8; 4]>,
) -> Option<[u8; 4]> {
    inline.or_else(|| group_sn.and_then(|_| registry.writer_spec_group(writer_guid)))
}

/// A writer of the spec GROUP dialect names the writer set and the GSN of
/// each change of a GROUP set (RTPS v2.5 Sec.8.7.5, Sec.8.7.6, D5): handed
/// to the topic's readers before the change (change `seq`), with, for its
/// end of the set, the first SN of its part (`part_first_sn`). Nothing
/// for a change of no GROUP set, nor for a writer of any other dialect
/// (one lookup of a flag decided at pairing, for GROUP changes only).
#[allow(clippy::too_many_arguments)]
fn announce_group_writer_set(
    topic: &crate::engine::demux::Topic,
    registry: &TopicRegistry,
    writer_guid: [u8; 16],
    seq: u64,
    group_sn: Option<u64>,
    publisher_entity_id: Option<[u8; 4]>,
    inline_qos: Option<(&[u8], bool)>,
    part_first_sn: Option<u64>,
) -> GroupRouteScope {
    let spec = registry.writer_speaks_spec_group(&writer_guid);
    let writer_set =
        inline_qos.and_then(|(iq, is_le)| builder::extract_writer_group_info(iq, is_le));
    let scope = GroupRouteScope::enter(GroupRouteContext {
        writer: writer_guid,
        seq,
        spec,
        spec_receive: spec && registry.writer_is_spec_receive(&writer_guid),
        writer_set,
        set_first_gsn: group_sn.filter(|_| spec),
        order: publisher_entity_id
            .and_then(|entity| {
                let gsn =
                    inline_qos.and_then(|(qos, le)| builder::extract_group_seq_num(qos, le))?;
                let mut publisher = writer_guid;
                publisher[12..].copy_from_slice(&entity);
                Some(OrderedGroupChange {
                    publisher,
                    gsn,
                    writer_set: writer_set?,
                })
            })
            .filter(|_| spec),
    });
    if let (true, Some(group_sn), Some(publisher), Some(writer_set)) =
        (spec, group_sn, publisher_entity_id, writer_set)
    {
        topic.deliver_group_change(
            writer_guid,
            crate::engine::subscriber::GroupChange {
                seq,
                group_sn,
                publisher_entity_id: publisher,
                writer_set,
                gsn: inline_qos.and_then(|(iq, is_le)| builder::extract_group_seq_num(iq, is_le)),
                part_first_sn,
            },
        );
    }
    scope
}

pub(crate) fn route_source_ts_ns() -> Option<u64> {
    ROUTE_SOURCE_TS_NS.with(|c| c.get())
}

thread_local! {
    /// Per-thread flag: `true` when the datagram currently being routed
    /// originated from an HDDS writer (RTPS header vendorId == 0x011A).
    /// Coherent-set delivery uses this to pick the set-completion model:
    /// HDDS tags each sample with `PID_COHERENT_SET = own SN` and closes
    /// the set with a dedicated ECS DATA submessage (RTPS v2.5 sec. 8.7.5),
    /// whereas in the classic model every sample
    /// in a set shares `PID_COHERENT_SET = first SN of the set` and the
    /// set closes implicitly when a higher set-SN appears (no ECS marker).
    /// Set by `route_data_packet` from the datagram header on each call.
    static ROUTE_WRITER_IS_HDDS: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };

    /// Per-thread flag: `true` when the datagram currently being routed came
    /// from a writer with vendor id 0x0101 (RTPS header); see
    /// `route_writer_is_connext`.
    static ROUTE_WRITER_IS_CONNEXT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// HDDS RTPS vendorId (`PID_VENDOR_ID` / RTPS header), big-endian on the wire.
/// Official DDS Foundation assignment: 0x011A.
const HDDS_VENDOR_ID: [u8; 2] = [0x01, 0x1A];

/// RTPS vendorId 0x0101 (`PID_VENDOR_ID` / RTPS header), big-endian.
const CONNEXT_VENDOR_ID: [u8; 2] = [0x01, 0x01];

/// Record whether the datagram being routed on this thread came from an
/// HDDS writer, read from the RTPS header vendorId (bytes 6..8).
fn set_route_writer_is_hdds(payload: &[u8]) {
    let is_hdds =
        payload.len() >= 8 && payload[6] == HDDS_VENDOR_ID[0] && payload[7] == HDDS_VENDOR_ID[1];
    ROUTE_WRITER_IS_HDDS.with(|c| c.set(is_hdds));
    let is_connext = payload.len() >= 8
        && payload[6] == CONNEXT_VENDOR_ID[0]
        && payload[7] == CONNEXT_VENDOR_ID[1];
    ROUTE_WRITER_IS_CONNEXT.with(|c| c.set(is_connext));
}

/// Test seam: pretend the datagram routed on this thread came (or did not
/// come) from an HDDS writer, as `set_route_writer_is_hdds` records it.
#[cfg(test)]
pub(crate) fn set_route_writer_is_hdds_for_test(is_hdds: bool) {
    ROUTE_WRITER_IS_HDDS.with(|c| c.set(is_hdds));
}

#[cfg(test)]
pub(crate) fn set_route_writer_is_connext_for_test(b: bool) {
    ROUTE_WRITER_IS_CONNEXT.with(|c| c.set(b));
}

/// Whether the datagram currently being routed on this thread came from an
/// HDDS writer. The coherent-set reader path reads this to choose between
/// the HDDS ECS model and the classic shared-set-SN model.
pub(crate) fn route_writer_is_hdds() -> bool {
    ROUTE_WRITER_IS_HDDS.with(|c| c.get())
}

/// Whether the datagram currently being routed came from a writer with vendor
/// id 0x0101. A GROUP-scope reader steps its gate over the hole below a set
/// such a writer flushes (that vendor's durable replay neither re-emits nor
/// GAPs the sequence numbers its end markers took).
pub(crate) fn route_writer_is_connext() -> bool {
    ROUTE_WRITER_IS_CONNEXT.with(|c| c.get())
}

/// Decode the source timestamp an INFO_TS submessage at `off` puts in force,
/// or `None` when it puts none there.
///
/// Three ways to put none in force, and all three mean the same thing to a
/// reader - fall back to reception time: the INVALIDATE flag is set (RTPS
/// v2.5 Sec.8.3.8.11, "the following submessages have no valid timestamp"),
/// the body is truncated, or the seconds field is negative (pre-epoch, so
/// unusable for an age comparison).
pub(crate) fn info_ts_ns_at(payload: &[u8], off: usize, flags: u8, is_le: bool) -> Option<u64> {
    if flags & 0x02 != 0 || off + 12 > payload.len() {
        return None;
    }

    let secs = if is_le {
        i32::from_le_bytes([
            payload[off + 4],
            payload[off + 5],
            payload[off + 6],
            payload[off + 7],
        ])
    } else {
        i32::from_be_bytes([
            payload[off + 4],
            payload[off + 5],
            payload[off + 6],
            payload[off + 7],
        ])
    };
    let frac = if is_le {
        u32::from_le_bytes([
            payload[off + 8],
            payload[off + 9],
            payload[off + 10],
            payload[off + 11],
        ])
    } else {
        u32::from_be_bytes([
            payload[off + 8],
            payload[off + 9],
            payload[off + 10],
            payload[off + 11],
        ])
    };

    let secs = u64::try_from(secs).ok()?;
    Some(secs * 1_000_000_000 + ((u64::from(frac) * 1_000_000_000) >> 32))
}

/// Parse the source timestamp in force at this datagram's first DATA or
/// DATA_FRAG, in epoch nanoseconds.
///
/// RTPS v2.5 Sec.8.3.8.11: an INFO_TS sets the source timestamp for the
/// submessages that FOLLOW it, until the next INFO_TS replaces it. The answer
/// is therefore the LAST INFO_TS before the DATA, and the walk stops AT the
/// DATA so a later one cannot reach back.
///
/// Two traps are avoided. Returning on the FIRST INFO_TS met would stamp
/// both samples of `[INFO_TS(a), DATA, INFO_TS(b), DATA]` with `a` (the same
/// trap `classifier::walk` avoids on the discovery path). And a first INFO_TS
/// carrying the INVALIDATE flag must not make the whole datagram return
/// `None`, discarding a second, valid one: that flag clears the context, it
/// does not end the parse.
///
/// `None` means no usable timestamp is in force at the DATA, and the reader
/// falls back to reception time.
fn parse_info_ts_ns(payload: &[u8]) -> Option<u64> {
    let mut current = None;
    walk::for_each_submessage(payload, |found| {
        match found.id {
            // The context in force when the DATA is reached is the answer.
            0x15 | 0x16 => return walk::Step::Stop,
            0x09 => {
                current = info_ts_ns_at(payload, found.offset, found.flags, found.flags & 0x01 != 0)
            }
            _ => {}
        }
        walk::Step::Continue
    });
    current
}

/// A DATA of `writer_guid` addressed to every reader (readerId
/// ENTITYID_UNKNOWN, as on multicast) dropped because no binding names the
/// writer's topic yet: a writer that has discovered a reader here sends it
/// DATA before this participant has discovered the writer, and sends it
/// again. Recorded so the topic's readers owe it once the writer is bound
/// (`TopicRegistry::note_dropped_before_discovery`); joined at the first
/// DATA routed after the binding instead, a VOLATILE reader judged the
/// writer's resends of it history, and acknowledged them undelivered. A
/// DATA addressed to a reader that is not here is owed to nobody here.
#[cold]
fn note_dropped_before_discovery(payload: &[u8], writer_guid: [u8; 16], registry: &TopicRegistry) {
    if builder::extract_reader_entity_id(payload) != Some(ENTITYID_UNKNOWN) {
        return;
    }
    let Some(seq) = builder::extract_sequence_number(payload).filter(|&seq| seq > 0) else {
        return;
    };
    // A coherent set's member is owed from the set's start.
    let set_start = builder::extract_inline_qos(payload)
        .and_then(|(iq, is_le)| builder::extract_coherent_set(iq, is_le))
        .filter(|&start| start > 0);
    let seq = set_start.map_or(seq, |start| start.min(seq));
    registry.note_dropped_before_discovery(writer_guid, seq);
}

/// Route an RTPS data packet to the matching topic subscribers, updating metrics.
///
/// Returns [`RouteStatus::Delivered`] on success, or an error variant when the packet
/// could not be associated with a known topic.
///
/// # Topic binding
///
/// A DATA is routed by its writer GUID, which the writer's SEDP announcement
/// binds to a topic (`TopicRegistry::register_writer_guid`); a PID_TOPIC_NAME
/// in its inline QoS is not used (many writers send none).
///
/// # Performance
/// This is a HOT PATH function called for every incoming DATA packet.
/// All operations are optimized for minimal latency.
#[inline]
pub fn route_data_packet(
    payload: &[u8],
    packet_len: usize,
    payload_offset: Option<usize>,
    registry: &TopicRegistry,
    metrics: &RouterMetrics,
) -> RouteStatus {
    // RTPS v2.5 sec. 8.3.4: when a datagram batches several DATA submessages
    // split it into per-DATA synthetic datagrams so every
    // sample is delivered and acked. Single-DATA datagrams skip this entirely
    // and keep the fast path below.
    let (data_count, first_data) = data_submessages(payload);
    if data_count > 1 {
        return route_multi_data_datagram(payload, registry, metrics);
    }

    // Carry this datagram's INFO_TS source timestamp on the routing thread so
    // the reader pipeline can expire samples by source time (lifespan). Set
    // unconditionally (None when absent) so a previous datagram's value never
    // leaks into one without an INFO_TS.
    set_route_source_ts_ns(parse_info_ts_ns(payload));

    // Carry the source vendor (HDDS vs. other) so the coherent-set reader
    // path picks the right set-completion model (HDDS ECS vs. classic
    // shared-set-SN). Set unconditionally per datagram.
    set_route_writer_is_hdds(payload);

    // The topic is the one the writer's SEDP announcement bound its GUID to,
    // never a PID_TOPIC_NAME the DATA carries in its inline QoS: discovery
    // decides which topic a writer writes.
    let guid = match builder::extract_writer_guid(payload) {
        Some(g) => g,
        None => {
            log::debug!("[ROUTER] DROP: Cannot extract writer GUID from DATA packet");
            metrics.delivery_errors.fetch_add(1, Ordering::Relaxed);
            return RouteStatus::Dropped;
        }
    };

    // Lookup topic name via GUID mapping (populated by SEDP)
    let topic_name = match registry.get_topic_by_guid(&guid) {
        Some(name) => {
            log::debug!(
                "[ROUTER] GUID-based routing: writer={:02x?} -> topic='{}'",
                &guid[..],
                name
            );
            name
        }
        None => {
            // Discovery is asymmetric: a writer can know this
            // reader and send directed DATA before its own SEDP
            // reaches us. The readerId already identifies the
            // destination (RTPS 2.5 8.3.8.2). Let that reader's
            // bounded unresolved-writer gate keep the sample,
            // without delivery or ACK credit before the QoS/type
            // verdict. Do not cache this as a writer-topic binding.
            if let Some(name) = builder::extract_reader_entity_id(payload)
                .and_then(|reader| registry.topic_for_reader(reader))
            {
                name
            } else if let Some(name) = registry.fallback_map_unknown_writer_to_single_topic(guid) {
                // Optional fallback for peers that omit SEDP:
                // explicitly enabled, single-topic deployments only.
                log::debug!(
                    "[ROUTER] fallback GUID routing writer={:02x?} -> topic='{}'",
                    &guid[..],
                    name
                );
                name
            } else {
                log::debug!(
                    "[ROUTER] DROP: Topic unavailable for writer GUID {:02x?} (not announced via SEDP yet)",
                    &guid[..]
                );
                note_dropped_before_discovery(payload, guid, registry);
                metrics.delivery_errors.fetch_add(1, Ordering::Relaxed);
                return RouteStatus::Dropped;
            }
        }
    };

    let topic = match registry.get_topic(&topic_name) {
        Some(topic) => topic,
        None => {
            log::debug!(
                "[ROUTER] orphaned DATA topic='{}' (registry miss)",
                topic_name
            );
            metrics.packets_orphaned.fetch_add(1, Ordering::Relaxed);
            return RouteStatus::Orphaned;
        }
    };

    // RTPS 2.5 8.3.8.2: a DATA is for the reader its readerId names, or for
    // every reader of the topic here when it is ENTITYID_UNKNOWN. Every
    // delivery below, samples and lifecycle alike, goes to this narrowed
    // topic (`Topic::addressed_to` says why it matters).
    let Some(reader_entity_id) = builder::extract_reader_entity_id(payload) else {
        log::debug!(
            "[ROUTER] DROP: DATA topic='{}' stops before its readerId",
            topic_name
        );
        metrics.delivery_errors.fetch_add(1, Ordering::Relaxed);
        return RouteStatus::Dropped;
    };
    let topic = topic.addressed_to(reader_entity_id);
    if reader_entity_id != ENTITYID_UNKNOWN && topic.subscriber_count() == 0 {
        log::debug!(
            "[ROUTER] orphaned DATA topic='{}': no reader here is {:02x?}",
            topic_name,
            reader_entity_id
        );
        metrics.packets_orphaned.fetch_add(1, Ordering::Relaxed);
        return RouteStatus::Orphaned;
    }

    let seq = match builder::extract_sequence_number(payload) {
        Some(s) => s,
        None => {
            // A resolved but malformed DATA can still reach this point with an
            // incomplete writerSN. Preserve the existing best-effort fallback,
            // but make every occurrence measurable and diagnose each writer once.
            let writer_guid = builder::extract_writer_guid(payload);
            metrics
                .missing_sequence_fallbacks
                .fetch_add(1, Ordering::Relaxed);
            if registry.should_warn_missing_sequence_fallback(writer_guid) {
                log::warn!(
                    "[ROUTER] DATA topic='{}' writer={:02x?} has no decodable writerSN; attempting seq=0 fallback",
                    topic_name,
                    writer_guid
                );
            }
            0
        }
    };

    // RTPS v2.5 sec. 8.7.5: detect End-of-Coherent-Set DATA submessage
    // (D=0 K=0 Q=1 + PID_COHERENT_SET [+ PID_GROUP_COHERENT_SET], no
    // PID_STATUS_INFO dispose bits). When matched, route through
    // `deliver_ecs` so coherent-access readers flush their buffered
    // per-(writer, gsn) samples. Checked BEFORE `is_key_only_data` so
    // an ECS marker without StatusInfo is never mistaken for a
    // dispose form (both wire encodings share D=0 K=0 Q=1 bits).
    if let Some((coherent_sn, group_sn)) = builder::extract_ecs_marker(payload) {
        let writer_guid = match builder::extract_writer_guid(payload) {
            Some(g) => g,
            None => {
                log::debug!(
                    "[ROUTER] ECS DATA missing writer GUID topic='{}'",
                    topic_name
                );
                return RouteStatus::Dropped;
            }
        };
        return ordered_group_scope(
            &topic,
            registry,
            writer_guid,
            seq,
            builder::extract_inline_qos(payload),
            {
                #[inline(always)]
                || {
                    // PID_GROUP_ENTITY_ID is the owning Publisher's EntityId
                    // (RTPS v2.5 sec. 9.3.2.1). GROUP-scope coherent_access subscribers
                    // bucket per (publisher_entity_id, group_sn) so two Publishers
                    // in the same Participant don't alias on the same GSN
                    // (DDS v1.4 sec. 2.2.3.6). `extract_inline_qos` returns the QoS slice
                    // and the matching E flag in one pass per RTPS v2.5 sec. 9.4.5.3.3.
                    let publisher_entity_id = group_publisher(
                        registry,
                        &writer_guid,
                        group_sn,
                        builder::extract_inline_qos(payload)
                            .and_then(|(iq, is_le)| builder::extract_group_entity_id(iq, is_le)),
                    );
                    // A writer of the spec GROUP class (D18) ends a group set in the RTPS
                    // v2.5 form (Table 9.23): its PID_COHERENT_SET is the writer's FIRST
                    // SN in the set, and its part ends just before the end of set. The
                    // reader's set ends on the writer's last SN.
                    let part_first_sn = coherent_sn;
                    let coherent_sn =
                        if group_sn.is_some() && registry.writer_speaks_spec_group(&writer_guid) {
                            seq.saturating_sub(1)
                        } else {
                            coherent_sn
                        };
                    log::debug!(
                    "[ROUTER] ECS topic='{}' seq={} writer={:02x?} coherent_sn={} group_sn={:?} \
             publisher_entity_id={:?}",
                    topic_name,
                    seq,
                    &writer_guid[..4],
                    coherent_sn,
                    group_sn,
                    publisher_entity_id,
                );
                    let _group_scope = announce_group_writer_set(
                        &topic,
                        registry,
                        writer_guid,
                        seq,
                        group_sn,
                        publisher_entity_id,
                        builder::extract_inline_qos(payload),
                        Some(part_first_sn),
                    );
                    let errors = topic.deliver_ecs(
                        writer_guid,
                        seq,
                        coherent_sn,
                        group_sn,
                        publisher_entity_id,
                    );
                    metrics.packets_routed.fetch_add(1, Ordering::Relaxed);
                    if errors > 0 {
                        metrics
                            .delivery_errors
                            .fetch_add(errors as u64, Ordering::Relaxed);
                    }
                    RouteStatus::Delivered
                }
            },
        );
    }

    // A STANDALONE end-of-coherent-set marker from a writer with vendor id 0x0101:
    // a D=0 K=0 Q=1 DATA submessage carrying the vendor-specific parameter 0x8022
    // (vendor 0x0101, parsed by the RTI dialect) but NOT PID_COHERENT_SET (so it
    // is distinct from the HDDS-native ECS marker handled just above). HDDS closes
    // the writer's set on it; without it the set would commit only on the next
    // set's first sample, after the reader may already have read part of it. The
    // marker has no payload, so it would otherwise be dropped at the
    // payload-extraction stage and the set would never commit. This is checked
    // BEFORE `is_key_only_data` and the payload-missing drop. Implicitly
    // vendor-scoped: 0x8022 is a vendor-specific PID (0x8000 bit set) that
    // HDDS-self and the classic coherent model never send on a standalone marker,
    // so their byte-paths are untouched without a hot-path vendorId branch.
    if let Some((end_sn, end_count, group_sn)) = builder::extract_end_coherent_marker(payload) {
        let writer_guid = match builder::extract_writer_guid(payload) {
            Some(g) => g,
            None => {
                log::debug!(
                    "[ROUTER] coherent-END marker missing writer GUID topic='{}'",
                    topic_name
                );
                return RouteStatus::Dropped;
            }
        };
        let publisher_entity_id = builder::extract_inline_qos(payload)
            .and_then(|(iq, is_le)| builder::extract_group_entity_id(iq, is_le));
        log::debug!(
            "[ROUTER] coherent-END marker topic='{}' seq={} writer={:02x?} end_sn={} group_sn={:?} \
             publisher_entity_id={:?}",
            topic_name,
            seq,
            &writer_guid[..4],
            end_sn,
            group_sn,
            publisher_entity_id,
        );
        // A marker whose writerSN could not be read (`seq` 0, never a valid
        // sequence number) closes its set without a number to acknowledge.
        let errors = if seq == 0 {
            topic.deliver_coherent_end(
                writer_guid,
                group_sn,
                publisher_entity_id,
                Some(end_sn),
                end_count,
            )
        } else {
            topic.deliver_coherent_end_marker(
                writer_guid,
                group_sn,
                publisher_entity_id,
                end_sn,
                end_count,
                seq,
            )
        };
        metrics.packets_routed.fetch_add(1, Ordering::Relaxed);
        if errors > 0 {
            metrics
                .delivery_errors
                .fetch_add(errors as u64, Ordering::Relaxed);
        }
        return RouteStatus::Delivered;
    }

    // The bare end of a GROUP set of a Dust DDS writer (`SpecReceive`, decided
    // at its discovery): D=0 K=0 Q=1 with PID_GROUP_COHERENT_SET and
    // PID_WRITER_GROUP_INFO, and no PID_COHERENT_SET, so the ECS branch above
    // does not take it. It closes the writer's part of the set exactly as an
    // ECS does: its end is the writer's SN just before the marker, and it
    // announces the writer set and GSN like the spec form. Only a writer
    // recorded as Dust is looked at, once per set and writer, after the
    // cheap shape check.
    if let Some(group_sn) = builder::extract_group_end_without_coherent_set(payload) {
        if let Some(writer_guid) = builder::extract_writer_guid(payload) {
            if registry.writer_is_spec_receive(&writer_guid)
                && registry.writer_speaks_spec_group(&writer_guid)
            {
                return ordered_group_scope(
                    &topic,
                    registry,
                    writer_guid,
                    seq,
                    builder::extract_inline_qos(payload),
                    {
                        #[inline(always)]
                        || {
                            let publisher_entity_id = group_publisher(
                                registry,
                                &writer_guid,
                                Some(group_sn),
                                builder::extract_inline_qos(payload).and_then(|(iq, is_le)| {
                                    builder::extract_group_entity_id(iq, is_le)
                                }),
                            );
                            // The end's part first SN is not on this wire form
                            // (no PID_COHERENT_SET): it is None, and the
                            // part's first SN comes from its members.
                            let _group_scope = announce_group_writer_set(
                                &topic,
                                registry,
                                writer_guid,
                                seq,
                                Some(group_sn),
                                publisher_entity_id,
                                builder::extract_inline_qos(payload),
                                None,
                            );
                            let errors = topic.deliver_ecs(
                                writer_guid,
                                seq,
                                seq.saturating_sub(1),
                                Some(group_sn),
                                publisher_entity_id,
                            );
                            metrics.packets_routed.fetch_add(1, Ordering::Relaxed);
                            if errors > 0 {
                                metrics
                                    .delivery_errors
                                    .fetch_add(errors as u64, Ordering::Relaxed);
                            }
                            RouteStatus::Delivered
                        }
                    },
                );
            }
        }
    }

    // P1.2: Detect key-only DATA (K flag) for dispose/unregister lifecycle.
    // When K flag is set, the payload contains only the serialized key (not full data).
    // We extract StatusInfo + KeyHash from inline QoS and route via deliver_dispose().
    if builder::is_key_only_data(payload) {
        let writer_guid = match builder::extract_writer_guid(payload) {
            Some(guid) => guid,
            None => {
                log::debug!(
                    "[ROUTER] K-flag DATA missing writer GUID topic='{}' seq={}",
                    topic_name,
                    seq
                );
                metrics.delivery_errors.fetch_add(1, Ordering::Relaxed);
                return RouteStatus::Dropped;
            }
        };

        // Single-scan: `extract_inline_qos` yields the QoS slice and the
        // matching E flag. Both helpers consume the same flag the slice was
        // decoded with, so a malformed packet cannot land here with a
        // mismatched endianness fallback.
        let inline_qos_with_le = builder::extract_inline_qos(payload);
        return ordered_group_scope(&topic, registry, writer_guid, seq, inline_qos_with_le, {
            #[inline(always)]
            || {
                let status_info = inline_qos_with_le
                    .and_then(|(iq, is_le)| builder::extract_status_info(iq, is_le));
                let key_hash =
                    inline_qos_with_le.and_then(|(iq, is_le)| builder::extract_key_hash(iq, is_le));

                // A per-instance dispose/unregister may carry the instance key in the
                // serialized payload (K flag), with or without PID_KEY_HASH. The key
                // names the instance for a reader whose type reads it, whatever
                // PID_KEY_HASH says (a hint, RTPS v2.5 8.7.10; the key "identifies
                // the registered instance", 8.3.7.2); PID_KEY_HASH names it
                // otherwise; with neither, the change names no instance for that
                // reader and is dropped, never named by a type-blind guess.
                // Resolved ONLY for a writer flagged legacy (vendor HDDS, pre-
                // `CAP_CONFORMANT_KEY_HASH`): see `LifecycleKey::legacy_resolved`'s
                // doc and `TopicRegistry::resolve_legacy_key_hash_instance`.
                let legacy_resolved = key_hash
                    .filter(|_| registry.writer_uses_legacy_key_hash(&writer_guid))
                    .and_then(|kh| registry.resolve_legacy_key_hash_instance(&writer_guid, &kh));
                let key = LifecycleKey {
                    key_hash,
                    serialized_key: builder::extract_key_payload(payload),
                    legacy_resolved,
                };

                let lifecycle_kind = status_info.and_then(|status| match status & 0x03 {
                    0x03 => Some(crate::engine::subscriber::DisposeKind::DisposedUnregistered),
                    0x02 => Some(crate::engine::subscriber::DisposeKind::Unregistered),
                    0x01 => Some(crate::engine::subscriber::DisposeKind::Disposed),
                    _ => None,
                });

                if let Some(kind) = lifecycle_kind {
                    log::debug!(
                        "[ROUTER] dispose/unregister topic='{}' seq={} kind={:?} key_hash={:02x?} \
                 serialized_key={}",
                        topic_name,
                        seq,
                        kind,
                        key.key_hash.map(|kh| [kh[0], kh[1], kh[2], kh[3]]),
                        key.serialized_key.is_some()
                    );

                    // A lifecycle change written inside a coherent set carries the
                    // set's tags like any change of the set (RTPS v2.5 Sec.8.7.6):
                    // a member of the set, staged and delivered with it.
                    let coherent_sn = inline_qos_with_le
                        .and_then(|(iq, is_le)| builder::extract_coherent_set(iq, is_le));
                    let group_sn = inline_qos_with_le
                        .and_then(|(iq, is_le)| builder::extract_group_coherent_set(iq, is_le));
                    if coherent_sn.is_some() || group_sn.is_some() {
                        let publisher_entity_id = group_publisher(
                            registry,
                            &writer_guid,
                            group_sn,
                            inline_qos_with_le.and_then(|(iq, is_le)| {
                                builder::extract_group_entity_id(iq, is_le)
                            }),
                        );
                        let _group_scope = announce_group_writer_set(
                            &topic,
                            registry,
                            writer_guid,
                            seq,
                            group_sn,
                            publisher_entity_id,
                            inline_qos_with_le,
                            None,
                        );
                        let (errors, unnamed) = topic.deliver_lifecycle_coherent(
                            writer_guid,
                            seq,
                            key,
                            kind,
                            coherent_sn,
                            group_sn,
                            publisher_entity_id,
                        );
                        note_unnamed_lifecycle(metrics, unnamed, &topic);
                        metrics.packets_routed.fetch_add(1, Ordering::Relaxed);
                        if errors > 0 {
                            metrics
                                .delivery_errors
                                .fetch_add(errors as u64, Ordering::Relaxed);
                        }
                        return RouteStatus::Delivered;
                    }

                    // A datagram of several DATA is split before this point
                    // (`route_multi_data_datagram`), so the walk sees this DATA
                    // alone. Falls back to the dispose read above if the walk
                    // delivers none.
                    let mut count =
                        deliver_all_disposes_in_datagram(payload, &topic, registry, metrics);
                    if count == 0 {
                        let (errors, unnamed) = topic.deliver_lifecycle_coherent(
                            writer_guid,
                            seq,
                            key,
                            kind,
                            None,
                            None,
                            None,
                        );
                        note_unnamed_lifecycle(metrics, unnamed, &topic);
                        if errors > 0 {
                            metrics
                                .delivery_errors
                                .fetch_add(errors as u64, Ordering::Relaxed);
                        }
                        count = 1;
                    }
                    metrics
                        .packets_routed
                        .fetch_add(count as u64, Ordering::Relaxed);
                    return RouteStatus::Delivered;
                }

                log::debug!(
                    "[ROUTER] K-flag non-data sequence topic='{}' seq={} status={:?} key_hash={}",
                    topic_name,
                    seq,
                    status_info,
                    key_hash.is_some(),
                );
                let errors =
                    topic.deliver_key_only(writer_guid, seq, builder::extract_key_payload(payload));
                metrics.packets_routed.fetch_add(1, Ordering::Relaxed);
                if errors > 0 {
                    metrics
                        .delivery_errors
                        .fetch_add(errors as u64, Ordering::Relaxed);
                }
                RouteStatus::Delivered
            }
        });
    }

    // A DATA with neither payload nor key (D=0, K=0) that none of the forms
    // above claimed is a change without a sample: a writer's end of its open
    // coherent set (RTPS v2.5 Sec.8.7.6), or a change with nothing for the
    // application. It is still a change of the writer's: delivered as one,
    // it is acknowledged and the reader's order passes it. Dropped, it was
    // repaired for as long as the writer kept it, and the set it ended
    // stayed open. An invalid DATA (`is_data_at_without_sample`) is no
    // change at all, on this path as on the split path that routes each DATA
    // of a datagram here alone.
    if seq != 0
        && first_data.is_some_and(|data_off| builder::is_data_at_without_sample(payload, data_off))
    {
        let Some(writer_guid) = builder::extract_writer_guid(payload) else {
            log::debug!(
                "[ROUTER] DATA without a sample missing writer GUID topic='{}'",
                topic_name
            );
            metrics.delivery_errors.fetch_add(1, Ordering::Relaxed);
            return RouteStatus::Dropped;
        };
        log::debug!(
            "[ROUTER] change without a sample topic='{}' seq={} writer={:02x?}",
            topic_name,
            seq,
            &writer_guid[..4]
        );
        let errors = ordered_group_scope(
            &topic,
            registry,
            writer_guid,
            seq,
            builder::extract_inline_qos(payload),
            || topic.deliver_change_without_sample(writer_guid, seq),
        );
        metrics.packets_routed.fetch_add(1, Ordering::Relaxed);
        if errors > 0 {
            metrics
                .delivery_errors
                .fetch_add(errors as u64, Ordering::Relaxed);
        }
        return RouteStatus::Delivered;
    }

    let writer_guid = builder::extract_writer_guid(payload);
    // Protected SerializedPayload replaces the CDR encapsulation entirely.
    // Preserve even an invalid clear prefix for the crypto decoder to reject.
    // Decided ONCE for this sample and carried to the reader
    // (`PayloadFramingScope`): a writer resolved between here and the reader
    // must not turn bytes kept whole into a plain sample.
    let framing = writer_guid
        .as_ref()
        .map_or(crate::engine::subscriber::PayloadFraming::Clear, |writer| {
            topic.payload_framing_for_writer(writer)
        });
    let payload_protected = framing != crate::engine::subscriber::PayloadFraming::Clear;

    // Parse the CDR encapsulation header (4 bytes at `offset`) to strip it
    // from the delivered slice and capture the `representation_id` for the
    // downstream dispatch per DDS-RTPS v2.5 sec. 10.7.
    let mut encap_repr_id: Option<u16> = None;
    // ONE view of the sample, whoever said where its payload starts: the
    // classifier, or, when it did not, the same layout reader asked here
    // (`data_submessage_layout`). A second path would keep the encapsulation
    // header in the delivered bytes.
    let payload_offset = payload_offset.or_else(|| {
        builder::helpers::find_data_submsg_offset(payload)
            .and_then(|data_off| builder::data_submessage_layout(payload, data_off))
            .map(|layout| layout.payload)
    });
    let Some(offset) = payload_offset else {
        log::debug!(
            "[ROUTER] drop DATA topic='{}' reason=missing_payload",
            topic_name
        );
        metrics.delivery_errors.fetch_add(1, Ordering::Relaxed);
        return RouteStatus::Dropped;
    };
    let cdr2_payload = {
        // Offset already points to the serialized payload (or the CDR header).
        // Only skip the CDR encapsulation header when it is actually present.
        if offset >= payload.len() {
            log::debug!(
                "[ROUTER] drop DATA topic='{}' reason=missing_payload_offset",
                topic_name
            );
            metrics.delivery_errors.fetch_add(1, Ordering::Relaxed);
            return RouteStatus::Dropped;
        }

        let mut start = offset;
        if !payload_protected && start + 4 <= payload.len() {
            let enc = u16::from_be_bytes([payload[start], payload[start + 1]]);

            // XCDR1 encapsulations (CDR v1)
            let is_xcdr1 = matches!(enc, 0x0001 | 0x0003 | 0x8001 | 0x8003);
            // XCDR2 encapsulations (CDR v2) - non-delimited
            let is_xcdr2 = matches!(enc, 0x0006 | 0x0007);
            // D_CDR2 encapsulations (Delimited CDR v2) - has DHEADER
            let is_d_cdr2 = matches!(enc, 0x0008 | 0x0009);
            // PL_CDR2 encapsulations (Mutable CDR v2) - has EMHEADER stream
            // 0x000A = PL_CDR2_BE, 0x000B = PL_CDR2_LE (XTypes v1.3 Table 60, sec. 7.6.3.1.2).
            // The 4-byte representation header is stripped here; the EMHEADER stream
            // that follows is preserved for the MUTABLE struct decoder.
            let is_pl_cdr2 = matches!(enc, 0x000A | 0x000B);

            // NOTE: the options word is NOT required to be zero. DDS-XTypes v1.3
            // 7.6.3.1.2 uses its two low bits to carry the count of trailing pad
            // bytes (e.g. 0x0003; HDDS sets it too). Gating the strip on options
            // == 0 delivered the raw header + body to the decoder for any padded
            // sample. The pad is cut from the end below (`serialized_data_end`).
            if is_xcdr1 || is_xcdr2 {
                // Skip 4-byte encapsulation header
                start += 4;
                encap_repr_id = Some(enc);
            } else if is_d_cdr2 {
                // D_CDR2: Skip ONLY the 4-byte encapsulation header.
                // The DHEADER (4 bytes, size of serialized data) is part of the
                // CDR2 encoding and must be preserved for the decoder.
                start += 4;
                encap_repr_id = Some(enc);
                log::trace!(
                    "[ROUTER] D_CDR2 detected (enc={:#06x}), skipped 4 bytes (encap only, DHEADER preserved)",
                    enc
                );
            } else if is_pl_cdr2 {
                // PL_CDR2: Skip ONLY the 4-byte encapsulation header.
                // The EMHEADER stream that follows is preserved for the MUTABLE
                // struct decoder (DDS-XTypes v1.3 sec. 7.4.3.4.2).
                start += 4;
                encap_repr_id = Some(enc);
                log::trace!(
                    "[ROUTER] PL_CDR2 detected (enc={:#06x}), skipped 4 bytes (encap only, EMHEADER stream preserved)",
                    enc
                );
            }
        }

        if start >= payload.len() {
            log::debug!(
                "[ROUTER] drop DATA topic='{}' reason=missing_payload_after_header",
                topic_name
            );
            metrics.delivery_errors.fetch_add(1, Ordering::Relaxed);
            return RouteStatus::Dropped;
        }

        // Bound the payload at the DATA submessage end (RTPS v2.5 sec. 8.3.3),
        // not the datagram end: piggybacked submessages (a HEARTBEAT after
        // the DATA, say) must never leak into the sample bytes.
        // Behind a recognised encapsulation, the padding its options count
        // is not sample bytes either.
        let mut end = data_submsg_end_for(payload, offset).max(start);
        if encap_repr_id.is_some() {
            end = serialized_data_end(payload, offset, end).max(start);
        }

        if crate::config::env_flags::interop_diagnostics() {
            let head_len = (end - start).min(16);
            log::debug!(
                "[ROUTER] DATA payload(len={}, offset={}) head={:02x?}",
                end - start,
                start,
                &payload[start..start + head_len]
            );
        }

        &payload[start..end]
    };
    let cdr_version = encap_repr_id
        .and_then(|id| crate::dds::cdr_negotiation::cdr_version_from_representation_id(id).ok())
        .unwrap_or(crate::dds::CdrVersion::Xcdr2);

    // A writer an application blocked by hand (`TopicRegistry::block_writer`,
    // deprecated). A writer's QoS is not judged here: each reader drops what
    // a writer it is not matched with sends (`ReaderSubscriber::
    // writer_refused`, the per-pair verdict, DDS v1.4 Sec.2.2.3).
    if let Some(ref guid) = writer_guid {
        if registry.blocked_by_hand(guid) {
            log::debug!(
                "[ROUTER] dropping DATA from writer {:02x?} blocked by hand",
                &guid[..4]
            );
            return RouteStatus::Dropped;
        }
    }

    // EXCLUSIVE ownership is not decided here: each EXCLUSIVE reader
    // arbitrates on the instance key it decodes (DDS v1.4 Sec.2.2.3.10),
    // after its reliability bookkeeping has received the sample.

    // Extract coherent-set tags from inline QoS (RTPS v2.5 sec. 8.7.5)
    // so coherent_access readers can buffer per-(publisher, set) and
    // flush atomically on ECS receipt. Non-coherent samples have all
    // these as `None` and skip the buffering overhead.
    // `publisher_entity_id` (PID_GROUP_ENTITY_ID, RTPS sec. 9.3.2.1) is
    // required for GROUP-scope bucketing so two Publishers in the
    // same Participant don't alias on the same GSN.
    // `extract_inline_qos` returns the QoS slice and the matching
    // ParameterList PID/length endianness E flag in a single scan
    // (RTPS v2.5 sec. 9.4.5.3.3).
    let inline_qos_opt = builder::extract_inline_qos(payload);
    let coherent_sn =
        inline_qos_opt.and_then(|(iq, is_le)| builder::extract_coherent_set(iq, is_le));
    let group_sn =
        inline_qos_opt.and_then(|(iq, is_le)| builder::extract_group_coherent_set(iq, is_le));
    let publisher_entity_id =
        inline_qos_opt.and_then(|(iq, is_le)| builder::extract_group_entity_id(iq, is_le));

    let legacy_hash = writer_guid
        .filter(|guid| registry.writer_uses_legacy_key_hash(guid))
        .and_then(|writer| {
            inline_qos_opt
                .and_then(|(iq, is_le)| builder::extract_key_hash(iq, is_le))
                .map(|hash| LegacyHashContext { writer, seq, hash })
        });
    let _legacy_scope = LegacyHashScope::enter(legacy_hash);
    let inline_lifecycle = writer_guid
        .and_then(|writer| inline_lifecycle_context(writer, seq, inline_qos_opt, registry));
    let _inline_scope = InlineLifecycleScope::enter(inline_lifecycle);
    #[cfg(feature = "security")]
    let _framing_scope = writer_guid.map(|writer| PayloadFramingScope::enter(writer, seq, framing));

    let errors = match writer_guid {
        Some(guid) => ordered_group_scope(&topic, registry, guid, seq, inline_qos_opt, {
            #[inline(always)]
            || {
                if coherent_sn.is_some() || group_sn.is_some() {
                    let publisher_entity_id =
                        group_publisher(registry, &guid, group_sn, publisher_entity_id);
                    let _group_scope = announce_group_writer_set(
                        &topic,
                        registry,
                        guid,
                        seq,
                        group_sn,
                        publisher_entity_id,
                        inline_qos_opt,
                        None,
                    );
                    topic.deliver_keyed(
                        guid,
                        seq,
                        cdr2_payload,
                        cdr_version,
                        inline_qos_opt.and_then(|(iq, is_le)| builder::extract_key_hash(iq, is_le)),
                        coherent_sn,
                        group_sn,
                        publisher_entity_id,
                    )
                } else {
                    topic.deliver_keyed(
                        guid,
                        seq,
                        cdr2_payload,
                        cdr_version,
                        inline_qos_opt.and_then(|(iq, is_le)| builder::extract_key_hash(iq, is_le)),
                        None,
                        None,
                        None,
                    )
                }
            }
        }),
        None => topic.deliver(seq, cdr2_payload, cdr_version),
    };

    metrics.packets_routed.fetch_add(1, Ordering::Relaxed);
    metrics
        .bytes_delivered
        .fetch_add(packet_len as u64, Ordering::Relaxed);
    if errors > 0 {
        metrics
            .delivery_errors
            .fetch_add(errors as u64, Ordering::Relaxed);
    }

    // RTPS v2.5 sec. 9.6.4.9: a live data sample (D=1) MAY carry a PID_STATUS_INFO
    // marking the instance disposed/unregistered in the SAME submessage, rather
    // than a separate key-only DATA: a writer's final keyed sample for an instance
    // may ride the unregister flag. The key-only dispose path above
    // (`is_key_only_data`) never sees these, so without this branch the reader
    // never transitions the instance to NOT_ALIVE_*. Fire the lifecycle change
    // AFTER delivering the sample value, keyed by the inline PID_KEY_HASH.
    // Ordinary samples carry no StatusInfo (extract returns None) and skip this.
    if let Some((iq, is_le)) = inline_qos_opt {
        if let Some(status) = builder::extract_status_info(iq, is_le) {
            let kind = match status & 0x03 {
                0x03 => Some(crate::engine::subscriber::DisposeKind::DisposedUnregistered),
                0x02 => Some(crate::engine::subscriber::DisposeKind::Unregistered),
                0x01 => Some(crate::engine::subscriber::DisposeKind::Disposed),
                _ => None,
            };
            if let (Some(kind), Some(kh)) = (kind, builder::extract_key_hash(iq, is_le)) {
                // The writer is carried with the change: an unregister is a
                // fact about the writer that sent it (DDS v1.4
                // Sec.2.2.2.4.2.7).
                let d_errors = match writer_guid {
                    Some(guid) => topic.deliver_dispose_from_writer(guid, seq, kh, kind),
                    None => topic.deliver_dispose(seq, kh, kind),
                };
                if d_errors > 0 {
                    metrics
                        .delivery_errors
                        .fetch_add(d_errors as u64, Ordering::Relaxed);
                }
            }
        }
    }

    // The vendor-specific parameter 0x8022 (vendor 0x0101, parsed by the RTI
    // dialect) may also ride on a data sample (D=1) of a coherent set
    // (samples sharing PID_COHERENT_SET, RTPS v2.5 Sec.8.7.5). When it does,
    // HDDS treats the set as closed and commits the writer's whole buffered
    // set atomically (the sample carrying it was just staged above) rather
    // than waiting for the next set's first sample, after which the reader
    // could already have read part of the set. HDDS writers (dedicated ECS
    // submessage) never send this parameter, so no vendorId check is needed.
    if coherent_sn.is_some() || group_sn.is_some() {
        if let Some(guid) = writer_guid {
            let end_sn =
                inline_qos_opt.and_then(|(iq, is_le)| builder::extract_end_coherent_set(iq, is_le));
            let end_count = inline_qos_opt
                .and_then(|(iq, is_le)| builder::extract_end_coherent_set_count(iq, is_le));
            if end_sn.is_some() {
                let end_errors = topic.deliver_coherent_end(
                    guid,
                    group_sn,
                    publisher_entity_id,
                    end_sn,
                    end_count,
                );
                if end_errors > 0 {
                    metrics
                        .delivery_errors
                        .fetch_add(end_errors as u64, Ordering::Relaxed);
                }
            }
        }
    }

    RouteStatus::Delivered
}

/// Route a DATA_FRAG datagram: buffer every fragment it carries, and route
/// the sample as soon as one completes.
///
/// The datagram is read by `scan_all_data_frags`, the one traversal that knows
/// what a DATA_FRAG actually carries: a datagram may bundle several of them,
/// and a single submessage may pack `fragmentsInSubmessage > 1` fragments
/// (RTPS v2.5 Sec.8.3.8.3). The classifier publishes metadata for ONE
/// submessage and ONE fragment number, so reading it alone saw a 32-octet
/// sample sent as four packed fragments as "fragment 1 of 4" holding all 32
/// octets, and waited for fragments 2, 3 and 4 it was already holding.
/// Symptom on this door: status `Delivered`, one fragment pending, no sample
/// ever delivered - a conforming peer's data lost in silence. The multicast
/// receive path has scanned since the bundling fix; this door
/// never received it, which is one remedy and two doors again.
///
/// The classifier's metadata stays as the fallback, for the datagrams the scan
/// declines to read - that is what this function did for ALL of them before.
///
/// `origin`, when the caller knows it, is remembered with the fragment so a
/// NACK_FRAG can be addressed back to the sender -- `resolve_nack_frag_dest`
/// is where a relayed origin (RTPS 2.5 8.3.8.10) is refused a destination
/// derived from the forwarder rather than the writer's own registered one.
fn route_data_frag_datagram(
    payload: &[u8],
    payload_offset: Option<usize>,
    frag_meta: Option<&FragmentMetadata>,
    origin: Option<Origin>,
    fragment_buffer: &Mutex<FragmentBuffer>,
    registry: &TopicRegistry,
    metrics: &RouterMetrics,
) -> RouteStatus {
    let scanned = scan_all_addressed_data_frags_with_qos(payload);
    if !scanned.is_empty() {
        // RTPS v2.5 Sec.8.3.7.9: INFO_TS is RECEIVER CONTEXT, updated as
        // submessages are traversed, NOT a datagram-wide constant --
        // `scan_all_addressed_data_frags_with_qos` tracks it in the SAME
        // walk that finds the fragments, so each one already carries the
        // timestamp in force when the walk reached IT specifically. A
        // datagram batching `[INFO_TS(a), DATA_FRAG, INFO_TS(b),
        // DATA_FRAG]` stamps the first fragment `a` and the second `b`;
        // a single `parse_info_ts_ns(payload)` call here (which stops at
        // the FIRST DATA/DATA_FRAG it meets) stamped BOTH with `a`.
        let completed = {
            let mut buffer = lock_fragment_buffer(fragment_buffer);
            let mut done: Vec<CompletedSample> = Vec::new();
            for (frag, reader_entity_id, inline_qos, frag_ts_ns) in scanned {
                let writer_guid = frag.meta.writer_guid.as_bytes();
                if let Some((sample, audience, inline_qos, source_ts_ns)) = buffer
                    .insert_addressed_fragment_with_qos(
                        frag.meta.writer_guid,
                        frag.meta.seq_num,
                        frag.meta.frag_num,
                        frag.meta.geometry,
                        frag.payload,
                        origin,
                        reader_entity_id,
                        inline_qos,
                        frag_ts_ns,
                        || registry.local_reader_ids(&writer_guid),
                    )
                {
                    done.push(CompletedSample {
                        writer_guid: frag.meta.writer_guid,
                        seq: frag.meta.seq_num,
                        sample,
                        audience,
                        inline_qos,
                        source_ts_ns,
                    });
                }
            }
            done
        };

        // A datagram can complete more than one sample. Every completion is
        // routed; the status reported is the FIRST one that was not a plain
        // delivery, so an orphan or a drop is never hidden by a later success.
        let mut status = RouteStatus::Delivered;
        for done in &completed {
            log::debug!(
                "[ROUTER] DATA_FRAG COMPLETE: seq={} reassembled_len={}",
                done.seq,
                done.sample.len()
            );
            let routed = route_reassembled_data(
                &done.writer_guid,
                done.seq,
                &done.sample,
                &done.audience,
                done.inline_qos
                    .as_ref()
                    .map(|(qos, is_le)| (qos.as_slice(), *is_le)),
                done.source_ts_ns,
                registry,
                metrics,
            );
            if status == RouteStatus::Delivered {
                status = routed;
            }
        }
        return status;
    }

    // Nothing the scan would read. Fall back to the one submessage and one
    // fragment number the classifier named.
    let meta = match frag_meta {
        Some(m) => m,
        None => {
            log::debug!("[ROUTER] DROP DATA_FRAG: missing fragment metadata");
            metrics.delivery_errors.fetch_add(1, Ordering::Relaxed);
            return RouteStatus::Dropped;
        }
    };

    // Extract fragment payload data, bounded by the submessage that carries
    // it. Slicing to the end of the datagram swallowed whatever followed the
    // DATA_FRAG - the HEARTBEAT every reliable writer batches behind it, or
    // the next fragment of the very same sample - and handed it to reassembly
    // as sample bytes.
    let Some(frag_data) = fragment_bytes(payload, payload_offset, meta) else {
        log::debug!("[ROUTER] DROP DATA_FRAG: cannot extract fragment payload");
        metrics.delivery_errors.fetch_add(1, Ordering::Relaxed);
        return RouteStatus::Dropped;
    };
    let frag_data = frag_data.to_vec();

    // The readerId of the DATA_FRAG the classifier's metadata was read from:
    // the one carrying this writer, sequence number and first fragment. The
    // first DATA_FRAG of the datagram is not it when the classifier kept a
    // later one, and then its reader is not this fragment's.
    let Some(reader_entity_id) = builder::extract_frag_reader_entity_id(
        payload,
        meta.writer_guid.entity_id,
        meta.seq_num,
        meta.frag_num,
    ) else {
        log::debug!("[ROUTER] DROP DATA_FRAG: no DATA_FRAG matches the classifier's metadata");
        metrics.delivery_errors.fetch_add(1, Ordering::Relaxed);
        return RouteStatus::Dropped;
    };

    log::debug!(
        "[ROUTER] DATA_FRAG: guid={:02x?} seq={} frag={}/{} payload_len={} src={:?}",
        &meta.writer_guid.as_bytes()[..],
        meta.seq_num,
        meta.frag_num,
        meta.total_frags(),
        frag_data.len(),
        origin.map(|o| o.from())
    );

    // Same RTPS v2.5 Sec.8.3.7.9 rule as the multi-fragment scan above,
    // for this single DATA_FRAG's own datagram.
    let source_ts_ns = parse_info_ts_ns(payload);

    let complete = lock_fragment_buffer(fragment_buffer).insert_addressed_fragment_with_qos(
        meta.writer_guid,
        meta.seq_num,
        meta.frag_num,
        meta.geometry,
        frag_data,
        origin,
        reader_entity_id,
        None,
        source_ts_ns,
        || registry.local_reader_ids(&meta.writer_guid.as_bytes()),
    );

    if let Some((reassembled, audience, inline_qos, source_ts_ns)) = complete {
        log::debug!(
            "[ROUTER] DATA_FRAG COMPLETE: seq={} reassembled_len={}",
            meta.seq_num,
            reassembled.len()
        );
        return route_reassembled_data(
            &meta.writer_guid,
            meta.seq_num,
            &reassembled,
            &audience,
            inline_qos
                .as_ref()
                .map(|(qos, is_le)| (qos.as_slice(), *is_le)),
            source_ts_ns,
            registry,
            metrics,
        );
    }

    // Fragment buffered, waiting for more
    RouteStatus::Delivered
}

/// A sample one datagram completed, and whom it is for.
struct CompletedSample {
    writer_guid: GUID,
    seq: u64,
    sample: Vec<u8>,
    audience: SampleAudience,
    /// The inline QoS its DATA_FRAGs carried.
    inline_qos: Option<crate::core::discovery::multicast::FragInlineQos>,
    /// Its source timestamp (RTPS v2.5 Sec.8.3.7.9 INFO_TS), from the
    /// datagram that opened its reassembly sequence
    /// (`FragmentSet::source_ts_ns`'s doc).
    source_ts_ns: Option<u64>,
}

/// Take the reassembly buffer, recovering from a poisoned lock.
fn lock_fragment_buffer(
    fragment_buffer: &Mutex<FragmentBuffer>,
) -> std::sync::MutexGuard<'_, FragmentBuffer> {
    match fragment_buffer.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            log::warn!("[ROUTER] fragment_buffer lock poisoned; recovering");
            poisoned.into_inner()
        }
    }
}

/// Route a DATA_FRAG packet with no known source address.
///
/// # Returns
///
/// * `RouteStatus::Delivered` - Fragment buffered (or complete sample delivered)
/// * `RouteStatus::Dropped` - Invalid fragment metadata
#[inline]
pub fn route_data_frag_packet(
    payload: &[u8],
    _packet_len: usize,
    payload_offset: Option<usize>,
    frag_meta: Option<&FragmentMetadata>,
    fragment_buffer: &Mutex<FragmentBuffer>,
    registry: &TopicRegistry,
    metrics: &RouterMetrics,
) -> RouteStatus {
    route_data_frag_datagram(
        payload,
        payload_offset,
        frag_meta,
        None,
        fragment_buffer,
        registry,
        metrics,
    )
}

/// Route a DATA_FRAG packet, remembering the source address for NACK_FRAG.
#[inline]
#[allow(clippy::too_many_arguments)]
pub fn route_data_frag_packet_with_addr(
    payload: &[u8],
    _packet_len: usize,
    payload_offset: Option<usize>,
    frag_meta: Option<&FragmentMetadata>,
    origin: Origin,
    fragment_buffer: &Mutex<FragmentBuffer>,
    registry: &TopicRegistry,
    metrics: &RouterMetrics,
) -> RouteStatus {
    route_data_frag_datagram(
        payload,
        payload_offset,
        frag_meta,
        Some(origin),
        fragment_buffer,
        registry,
        metrics,
    )
}

/// Route a reassembled DATA_FRAG payload to its `audience` (`SampleAudience`:
/// the readers its fragments were sent to).
///
/// This is similar to route_data_packet but uses pre-extracted GUID and sequence.
#[inline]
#[allow(clippy::too_many_arguments)]
fn route_reassembled_data(
    writer_guid: &GUID,
    seq: u64,
    payload: &[u8],
    audience: &SampleAudience,
    inline_qos: Option<(&[u8], bool)>,
    source_ts_ns: Option<u64>,
    registry: &TopicRegistry,
    metrics: &RouterMetrics,
) -> RouteStatus {
    let guid_bytes = writer_guid.as_bytes();

    // Lookup topic name via GUID mapping (populated by SEDP)
    let topic_name = match registry.get_topic_by_guid(&guid_bytes) {
        Some(name) => {
            log::debug!(
                "[ROUTER] route_reassembled: GUID {:02x?} -> topic '{}' seq={} audience={:02x?}",
                &guid_bytes[..],
                name,
                seq,
                audience
            );
            name
        }
        None => {
            // Try fallback mapping
            if let Some(name) = registry.fallback_map_unknown_writer_to_single_topic(guid_bytes) {
                log::debug!("[ROUTER] Reassembled DATA: fallback -> topic '{}'", name);
                name
            } else {
                log::debug!(
                    "[ROUTER] DROP reassembled DATA: unknown GUID {:02x?}",
                    &guid_bytes[..]
                );
                // Sent to every reader: owed once the writer is bound
                // (`note_dropped_before_discovery`).
                if audience.reaches_unnamed() && seq > 0 {
                    let set_start = inline_qos
                        .and_then(|(iq, is_le)| builder::extract_coherent_set(iq, is_le))
                        .filter(|&start| start > 0);
                    registry.note_dropped_before_discovery(
                        guid_bytes,
                        set_start.map_or(seq, |start| start.min(seq)),
                    );
                }
                metrics.delivery_errors.fetch_add(1, Ordering::Relaxed);
                return RouteStatus::Dropped;
            }
        }
    };

    let topic = match registry.get_topic(&topic_name) {
        Some(topic) => topic,
        None => {
            log::debug!(
                "[ROUTER] orphaned reassembled DATA topic='{}' (registry miss)",
                topic_name
            );
            metrics.packets_orphaned.fetch_add(1, Ordering::Relaxed);
            return RouteStatus::Orphaned;
        }
    };
    let topic = topic.for_audience(audience);
    if !audience.reaches_unnamed() && topic.subscriber_count() == 0 {
        log::debug!(
            "[ROUTER] orphaned reassembled DATA topic='{}': no reader here is in {:02x?}",
            topic_name,
            audience
        );
        metrics.packets_orphaned.fetch_add(1, Ordering::Relaxed);
        return RouteStatus::Orphaned;
    }

    // Strip CDR encapsulation header if present (same logic as route_data_packet)
    // CDR header format: [encoding_kind: u16 BE][options: u16] = 4 bytes
    let mut encap_repr_id: Option<u16> = None;
    // One decision per sample, carried to the reader (`route_data_packet`).
    let framing = topic.payload_framing_for_writer(&guid_bytes);
    let payload_to_deliver =
        if framing == crate::engine::subscriber::PayloadFraming::Clear && payload.len() >= 4 {
            let enc = u16::from_be_bytes([payload[0], payload[1]]);

            // XCDR1 encapsulations (CDR v1): 0x0001 (PLAIN_CDR_LE), 0x0003 (PL_CDR_LE), etc.
            let is_xcdr1 = matches!(enc, 0x0001 | 0x0003 | 0x8001 | 0x8003);
            // XCDR2 encapsulations (CDR v2) - non-delimited
            let is_xcdr2 = matches!(enc, 0x0006 | 0x0007);
            // D_CDR2 encapsulations (Delimited CDR v2) - has DHEADER
            let is_d_cdr2 = matches!(enc, 0x0008 | 0x0009);
            // PL_CDR2 encapsulations (Mutable CDR v2) - has EMHEADER stream
            let is_pl_cdr2 = matches!(enc, 0x000A | 0x000B);

            // The options word is NOT gated on zero here: XCDR2 uses its two low
            // bits for the trailing-pad count (see route_data_packet). Large
            // fragmented samples carry it too.
            if is_xcdr1 || is_xcdr2 || is_d_cdr2 || is_pl_cdr2 {
                // Skip 4-byte encap header; DHEADER/EMHEADER stream preserved
                // for the decoder. The padding the options count, at the end
                // of the reassembled sample, is not sample bytes.
                encap_repr_id = Some(enc);
                &payload[4..serialized_data_end(payload, 0, payload.len())]
            } else {
                payload
            }
        } else {
            payload
        };
    let cdr_version = encap_repr_id
        .and_then(|id| crate::dds::cdr_negotiation::cdr_version_from_representation_id(id).ok())
        .unwrap_or(crate::dds::CdrVersion::Xcdr2);

    // EXCLUSIVE ownership: arbitrated by each reader (see route_data_packet).

    // A fragmented change of a coherent set carries the set's tags in the
    // inline QoS of its DATA_FRAGs (RTPS v2.5 Sec.8.7.6), read as a DATA's
    // (`route_data_packet`). A change with none pays one `Option` test.
    let coherent_sn = inline_qos.and_then(|(iq, is_le)| builder::extract_coherent_set(iq, is_le));
    let group_sn =
        inline_qos.and_then(|(iq, is_le)| builder::extract_group_coherent_set(iq, is_le));
    // Carry this reassembled sample's own source timestamp
    // (`CompletedSample::source_ts_ns`'s doc) on the routing thread for
    // the duration of delivery ONLY: `route_data_packet` does this once
    // per ordinary DATA datagram, but DATA_FRAG reassembly completes
    // asynchronously, possibly many unrelated ordinary DATA datagrams
    // after the fragment that actually carried the INFO_TS -- reading
    // `route_source_ts_ns()` without this would hand the reader pipeline
    // whatever datagram happened to run on this thread last. Cleared
    // unconditionally afterward so it cannot leak into whatever this
    // thread routes next.
    set_route_source_ts_ns(source_ts_ns);
    let inline_lifecycle = inline_lifecycle_context(guid_bytes, seq, inline_qos, registry);
    let _inline_scope = InlineLifecycleScope::enter(inline_lifecycle);
    let legacy_hash = registry
        .writer_uses_legacy_key_hash(&guid_bytes)
        .then(|| {
            inline_qos
                .and_then(|(qos, le)| builder::extract_key_hash(qos, le))
                .map(|hash| LegacyHashContext {
                    writer: guid_bytes,
                    seq,
                    hash,
                })
        })
        .flatten();
    let _legacy_scope = LegacyHashScope::enter(legacy_hash);
    #[cfg(feature = "security")]
    let _framing_scope = PayloadFramingScope::enter(guid_bytes, seq, framing);
    ordered_group_scope(&topic, registry, guid_bytes, seq, inline_qos, {
        #[inline(always)]
        || {
            let errors = if coherent_sn.is_some() || group_sn.is_some() {
                let publisher_entity_id = group_publisher(
                    registry,
                    &guid_bytes,
                    group_sn,
                    inline_qos.and_then(|(iq, is_le)| builder::extract_group_entity_id(iq, is_le)),
                );
                let _group_scope = announce_group_writer_set(
                    &topic,
                    registry,
                    guid_bytes,
                    seq,
                    group_sn,
                    publisher_entity_id,
                    inline_qos,
                    None,
                );
                topic.deliver_keyed(
                    guid_bytes,
                    seq,
                    payload_to_deliver,
                    cdr_version,
                    inline_qos.and_then(|(iq, is_le)| builder::extract_key_hash(iq, is_le)),
                    coherent_sn,
                    group_sn,
                    publisher_entity_id,
                )
            } else {
                topic.deliver_keyed(
                    guid_bytes,
                    seq,
                    payload_to_deliver,
                    cdr_version,
                    inline_qos.and_then(|(iq, is_le)| builder::extract_key_hash(iq, is_le)),
                    None,
                    None,
                    None,
                )
            };
            if let Some(lifecycle) = inline_lifecycle {
                let errors = topic.deliver_dispose_from_writer(
                    guid_bytes,
                    seq,
                    lifecycle.key,
                    lifecycle.kind,
                );
                metrics
                    .delivery_errors
                    .fetch_add(errors as u64, Ordering::Relaxed);
            }
            set_route_source_ts_ns(None);

            metrics.packets_routed.fetch_add(1, Ordering::Relaxed);
            metrics
                .bytes_delivered
                .fetch_add(payload.len() as u64, Ordering::Relaxed);
            if errors > 0 {
                metrics
                    .delivery_errors
                    .fetch_add(errors as u64, Ordering::Relaxed);
            }

            RouteStatus::Delivered
        }
    })
}

/// Exercise the production completed-fragment routing door without a socket.
#[cfg(test)]
pub(crate) fn route_reassembled_data_for_test(
    writer: [u8; 16],
    seq: u64,
    payload: &[u8],
    inline_qos: Option<&[u8]>,
    source_ts_ns: Option<u64>,
    registry: &TopicRegistry,
    metrics: &RouterMetrics,
) -> RouteStatus {
    let guid = GUID::from_bytes(writer);
    let mut fragments = FragmentBuffer::new(1, 1_000);
    let (payload, audience) = fragments
        .insert_addressed_fragment(
            guid,
            seq,
            1,
            crate::core::discovery::multicast::FragmentGeometry {
                fragment_size: u16::try_from(payload.len()).expect("small test payload"),
                sample_size: u32::try_from(payload.len()).expect("small test payload"),
            },
            payload.to_vec(),
            None,
            ENTITYID_UNKNOWN,
            Vec::new,
        )
        .expect("completed fragment");
    route_reassembled_data(
        &guid,
        seq,
        &payload,
        &audience,
        inline_qos.map(|qos| (qos, true)),
        source_ts_ns,
        registry,
        metrics,
    )
}

// ============================================================================
// Background Router Thread
// ============================================================================

/// Background thread that routes RTPS packets from the multicast ring to the topic registry.
///
/// The router owns the worker thread lifecycle and exposes telemetry gathered during routing.
pub struct Router {
    stop_flag: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
    pub metrics: Arc<RouterMetrics>,
    /// The registry the loop requests fragments from (see
    /// `NackFragEmitter`), kept so a test can check the participant wired
    /// its readers' own.
    #[cfg(test)]
    reader_proxies: ReaderProxyRegistry,
}

impl Router {
    /// Start a router without transport (test/intra-process only).
    ///
    /// Self-loopback suppression is disabled (zero GUID prefix never matches
    /// a real participant). Use `start_with_transport` or `start_with_notifier`
    /// for production paths where a real GUID prefix is required.
    #[cfg(test)]
    pub fn start(
        ring: Arc<ArrayQueue<(RxMeta, u8)>>,
        pool: Arc<RxPool>,
        registry: Arc<TopicRegistry>,
    ) -> io::Result<Self> {
        Self::start_with_transport(ring, pool, registry, None, [0u8; 12])
    }

    /// Start router with transport for NACK_FRAG sending.
    ///
    /// A router started here knows no local reader, so it requests no
    /// missing fragment: a NACK_FRAG is sent in the name of a matched reader
    /// the sample is for (see `NackFragEmitter`). Before 1.5.0 it sent them
    /// under an identifier derived from the writer's, which no reader had.
    pub fn start_with_transport(
        ring: Arc<ArrayQueue<(RxMeta, u8)>>,
        pool: Arc<RxPool>,
        registry: Arc<TopicRegistry>,
        transport: Option<Arc<crate::transport::UdpTransport>>,
        our_guid_prefix: [u8; 12],
    ) -> io::Result<Self> {
        Self::start_with_notifier(ring, pool, registry, transport, our_guid_prefix, None, None)
    }

    /// Start router with wake notifier for zero-latency packet processing.
    ///
    /// When notifier is provided, the router uses efficient condvar wait
    /// instead of polling, reducing latency from ~100us to ~1-10us.
    ///
    /// # Arguments
    /// * `ring` - Lock-free ring buffer from multicast listener
    /// * `pool` - Buffer pool for zero-copy packet handling
    /// * `registry` - Topic registry for subscriber dispatch
    /// * `transport` - Optional transport for NACK_FRAG sending
    /// * `our_guid_prefix` - Our GUID prefix for NACK_FRAG
    /// * `notifier` - Optional wake notifier for low-latency wake
    /// * `endpoint_registry` - Peer participant unicast locators (SPDP) so
    ///   NACK_FRAG repair requests target the advertised locator instead of
    ///   the source address of the triggering datagram
    #[allow(clippy::too_many_arguments)]
    ///
    /// A router started here knows no local reader, so it requests no
    /// missing fragment: a NACK_FRAG is sent in a matched reader's name
    /// (see `NackFragEmitter`).
    pub fn start_with_notifier(
        ring: Arc<ArrayQueue<(RxMeta, u8)>>,
        pool: Arc<RxPool>,
        registry: Arc<TopicRegistry>,
        transport: Option<Arc<crate::transport::UdpTransport>>,
        our_guid_prefix: [u8; 12],
        notifier: Option<Arc<WakeNotifier>>,
        endpoint_registry: Option<EndpointRegistry>,
    ) -> io::Result<Self> {
        Self::start_with_reader_proxies(
            ring,
            pool,
            registry,
            transport,
            our_guid_prefix,
            notifier,
            endpoint_registry,
            ReaderProxyRegistry::new(),
            None,
        )
    }

    /// [`start_with_notifier`](Self::start_with_notifier) for a participant
    /// whose reliable readers keep their writer proxies in `reader_proxies`:
    /// the router requests missing fragments in their names. `known_sources`
    /// ranks the sources of user DATA_FRAGs (see `FragmentBuffer::
    /// with_known_sources`); without it, the participants `endpoint_registry`
    /// holds are the known ones.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn start_with_reader_proxies(
        ring: Arc<ArrayQueue<(RxMeta, u8)>>,
        pool: Arc<RxPool>,
        registry: Arc<TopicRegistry>,
        transport: Option<Arc<crate::transport::UdpTransport>>,
        our_guid_prefix: [u8; 12],
        notifier: Option<Arc<WakeNotifier>>,
        endpoint_registry: Option<EndpointRegistry>,
        reader_proxies: ReaderProxyRegistry,
        known_sources: Option<Arc<dyn crate::core::discovery::KnownSources>>,
    ) -> io::Result<Self> {
        let stop_flag = Arc::new(AtomicBool::new(false));
        let metrics = Arc::new(RouterMetrics::new());

        let stop_flag_clone = Arc::clone(&stop_flag);
        let metrics_clone = Arc::clone(&metrics);

        #[cfg(test)]
        let kept_proxies = reader_proxies.clone();
        let handle = thread::spawn(crate::core::rt::shutdown::owned(move || {
            router_loop_with_transport(
                ring,
                pool,
                registry,
                stop_flag_clone,
                metrics_clone,
                transport,
                our_guid_prefix,
                notifier,
                endpoint_registry,
                reader_proxies,
                known_sources,
            );
        }));

        Ok(Self {
            stop_flag,
            handle: Some(handle),
            metrics,
            #[cfg(test)]
            reader_proxies: kept_proxies,
        })
    }

    /// The registry the loop requests fragments from.
    #[cfg(test)]
    pub(crate) fn reader_proxies(&self) -> &ReaderProxyRegistry {
        &self.reader_proxies
    }

    pub fn stop(mut self) -> io::Result<()> {
        self.stop_flag.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            handle
                .join()
                .map_err(|_| io::Error::other("Router thread panicked"))?;
        }
        Ok(())
    }
}

impl Drop for Router {
    fn drop(&mut self) {
        // Signal the router thread to stop
        self.stop_flag.store(true, Ordering::Relaxed);
        // Join the thread to ensure clean shutdown
        if let Some(handle) = self.handle.take() {
            crate::core::rt::shutdown::join_bounded(handle, "router");
        }
    }
}

/// Interval for checking stale fragment sequences (ms)
const NACK_FRAG_CHECK_INTERVAL_MS: u64 = 50;

/// Age threshold for considering a fragment sequence stale (ms)
/// After this time, we would send NACK_FRAG to request missing fragments
const NACK_FRAG_STALE_THRESHOLD_MS: u64 = 100;

/// Minimum interval between NACK_FRAGs for the same (writer, seq) (ms).
/// Without this, the 50ms stale-check timer re-NACKs every tick and storms
/// a slow-repair peer (observed: ~787 NACK_FRAGs in 16s), amplifying load
/// on the very writer we are waiting for.
const NACK_FRAG_BACKOFF_MS: u64 = 200;

/// Resolve the destination for a NACK_FRAG repair request.
///
/// A NACK_FRAG is a reader's request to the matched writer, so it goes where
/// the WriterProxy says the writer can be reached (RTPS 2.5 8.4.10.4,
/// `WriterProxy::unicastLocatorList`): the unicast locator the writer
/// announced in SEDP (PID_UNICAST_LOCATOR), and only when it announced none
/// the participant's default unicast locator from SPDP (8.5.3.1: the
/// participant defaults apply to an endpoint that lists no locator of its
/// own). A peer may announce a participant default nobody listens on and
/// carry its user traffic on the endpoint locator; a repair aimed at the
/// default is then lost. Never the source address of the triggering
/// datagram while a locator is registered: some vendors send from an
/// ephemeral socket they never read. Falls back to the reply address (when
/// one exists) when the writer and its participant are not (yet) in the
/// registry or advertise no usable unicast locator. An unspecified locator
/// address (0.0.0.0) means "use the source IP" with the advertised port --
/// which needs a reply address to combine with.
///
/// RTPS 2.5 8.3.4 / 8.3.8.10: `origin.reply()` is `None` behind an INFO_SRC.
/// Every fallback above that reads the source address needs one; the ONE
/// exception is a registry entry with a real, usable locator, which needs
/// nothing from `origin` at all -- a peer already known from SPDP/SEDP is
/// reachable however this datagram got here. No usable destination at all
/// (relayed, and either unknown or unusably registered) is `None`: no
/// NACK_FRAG leaves, rather than one aimed at the forwarder.
fn resolve_nack_frag_dest(
    writer_guid: &GUID,
    origin: Origin,
    endpoints: Option<&EndpointRegistry>,
) -> Option<std::net::SocketAddr> {
    const ENTITYID_PARTICIPANT: [u8; 4] = [0x00, 0x00, 0x01, 0xC1];
    let reply = origin.reply();
    let Some(reg) = endpoints else {
        return reply;
    };
    let peer_guid_prefix = &writer_guid.prefix;
    let participant = GUID::new(*peer_guid_prefix, ENTITYID_PARTICIPANT);
    let resolved = reg
        .get_writer_locator(writer_guid)
        .or_else(|| reg.get(&participant))
        .or_else(|| {
            // Some peers announce a non-standard participant entity id; match
            // on the prefix alone before giving up.
            reg.entries()
                .into_iter()
                .find(|(g, _)| g.as_bytes()[..12] == *peer_guid_prefix)
                .map(|(_, ep)| ep)
        });
    match resolved {
        // A locator without a usable port cannot be a repair destination.
        Some(ep) if ep.port() == 0 => reply,
        Some(ep) if ep.ip().is_unspecified() => {
            reply.map(|r| std::net::SocketAddr::new(r.ip(), ep.port()))
        }
        Some(ep) => Some(ep),
        None => reply,
    }
}

/// Check for stale fragment sequences and send NACK_FRAG requests.
///
/// When transport is available, actually sends NACK_FRAG packets to request
/// retransmission of missing fragments.
#[allow(clippy::too_many_arguments)]
fn check_stale_fragments_with_transport(
    fragment_buffer: &Mutex<FragmentBuffer>,
    metrics: &RouterMetrics,
    emitter: Option<&NackFragEmitter<'_>>,
    nack_frag_count: &mut u32,
    peer_is_intercom: &std::collections::HashMap<[u8; 12], bool>,
) {
    let mut buffer = match fragment_buffer.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };

    // Get sequences that have been waiting longer than threshold
    let stale = buffer.get_stale_sequences(NACK_FRAG_STALE_THRESHOLD_MS);

    for (guid, seq_num, missing_count, total_frags, age_ms, source_origin) in stale {
        // Per-seq backoff: skip sequences NACKed within the last
        // NACK_FRAG_BACKOFF_MS (the stale timer fires every 50ms).
        if !buffer.try_mark_nacked(&guid, seq_num, Duration::from_millis(NACK_FRAG_BACKOFF_MS)) {
            continue;
        }
        // Get the specific missing fragment numbers
        if let Some((missing_frags, _total)) = buffer.get_missing_fragments(&guid, seq_num) {
            log::debug!(
                "[ROUTER] NACK_FRAG needed: guid={:02x?} seq={} missing={}/{} frags={:?} age={}ms src={:?}",
                &guid.as_bytes()[..8],
                seq_num,
                missing_count,
                total_frags,
                &missing_frags[..missing_frags.len().min(8)], // Log first 8 missing
                age_ms,
                source_origin.map(|o| o.from())
            );

            // Send NACK_FRAG if transport available and a fragment of this
            // sequence actually recorded where it came from.
            if let (Some(emitter), Some(origin)) = (emitter, source_origin) {
                let is_intercom = peer_is_intercom.get(&guid.prefix).copied().unwrap_or(false);
                let audience = buffer.pending_audience(&guid, seq_num).cloned();
                emitter.request(
                    &guid,
                    seq_num,
                    &missing_frags,
                    is_intercom,
                    origin,
                    nack_frag_count,
                    |reader| audience.as_ref().is_some_and(|a| a.names(reader)),
                );
            }
        }
    }

    // Also evict expired sequences (cleanup)
    let evicted = buffer.evict_expired();
    if evicted > 0 {
        log::debug!("[ROUTER] Evicted {} expired fragment sequences", evicted);
        metrics
            .fragment_timeouts
            .fetch_add(evicted as u64, Ordering::Relaxed);
    }
}

/// What a NACK_FRAG needs to leave: the socket, our prefix, where the
/// writer's participant listens, and the readers it can be sent for.
///
/// A NACK_FRAG is a READER's request: its readerId names "the Reader entity
/// that requests to receive certain fragments" (RTPS 2.5 8.3.8.12), and the
/// writer answers the reader it names, from that reader's proxy (8.4.9.2).
/// The reassembly buffer is the participant's and a completed sample goes to
/// its whole audience, so a missing fragment is requested ONCE, in the name
/// of one local reliable reader matched with the writer that the sample is
/// for. Asking in the name of every matched reader made a writer repair the
/// sample for readers it was never sent to (a VOLATILE one included), and
/// multiplied the repairs. No such reader, no request: nobody here asked. The
/// id is never DERIVED from the writer's (its key, the reader kind): that is a
/// reader nobody announced, which the writer would answer all the same, and
/// which could be the real id of a VOLATILE reader created first - so that
/// reader would receive history repaired in its name.
struct NackFragEmitter<'a> {
    transport: &'a crate::transport::UdpTransport,
    our_guid_prefix: [u8; 12],
    endpoint_registry: Option<&'a EndpointRegistry>,
    reader_proxies: &'a ReaderProxyRegistry,
    metrics: &'a RouterMetrics,
}

impl NackFragEmitter<'_> {
    /// Request `missing` fragments of `writer_guid`'s `seq` in the name of
    /// the first local reliable reader matched with it that still awaits
    /// that sequence and that `is_for` accepts. Returns whether a NACK_FRAG
    /// left. A reader that received the sequence, or was told it is not
    /// relevant to it, would be answered with a GAP and complete nothing.
    #[allow(clippy::too_many_arguments)]
    fn request(
        &self,
        writer_guid: &GUID,
        seq: u64,
        missing: &[u32],
        peer_is_intercom: bool,
        origin: Origin,
        nack_frag_count: &mut u32,
        is_for: impl Fn([u8; 4]) -> bool,
    ) -> bool {
        use crate::protocol::builder::build_nack_frag_packet;

        let Some(dest_addr) = resolve_nack_frag_dest(writer_guid, origin, self.endpoint_registry)
        else {
            log::debug!(
                "[ROUTER] relayed origin and writer {:02x?} has no usable registered locator: \
                 no reply address, dropping NACK_FRAG",
                &writer_guid.prefix[..4]
            );
            return false;
        };
        let writer = writer_guid.as_bytes();
        let requester = self
            .reader_proxies
            .readers_of(&writer)
            .into_iter()
            .filter(|reader| self.reader_proxies.awaits(&writer, reader, seq))
            .map(|[.., e0, e1, e2, e3]| [e0, e1, e2, e3])
            .find(|reader| is_for(*reader));
        let mut sent = false;
        if let Some(reader) = requester {
            let reader_entity_id = gate_nack_frag_reader_kind(reader, peer_is_intercom);
            let nack_frag = build_nack_frag_packet(
                self.our_guid_prefix,
                writer_guid.prefix,
                reader_entity_id,
                writer_guid.entity_id,
                seq,
                missing,
                *nack_frag_count,
            );
            *nack_frag_count = nack_frag_count.wrapping_add(1);
            match self.transport.send_to_endpoint(&nack_frag, &dest_addr) {
                Ok(_) => {
                    sent = true;
                    self.metrics
                        .nack_frag_requests
                        .fetch_add(1, Ordering::Relaxed);
                    log::debug!(
                        "[ROUTER] Sent NACK_FRAG to {} for reader {:02x?} seq={} frags={:?}",
                        dest_addr,
                        reader_entity_id,
                        seq,
                        &missing[..missing.len().min(4)]
                    );
                }
                Err(e) => log::debug!("[ROUTER] Failed to send NACK_FRAG: {}", e),
            }
        }
        sent
    }
}

/// Vendor-gate the NACK_FRAG readerId kind for peers with vendor id 0x0105.
///
/// The dialect for vendor id 0x0105 (RTPS header vendorId, resolved once per
/// peer at pairing) writes the NO_KEY (0x04) reader kind in the NACK_FRAG
/// readerId instead of the WITH_KEY (0x07) kind the reader really has: that
/// peer's fragment repair is driven by the 0x04 form, and with 0x07 reliable
/// KEEP_ALL large-data repair stalls. Self (0x011A) and every other vendor
/// keep the truthful 0x07 byte-identical.
fn gate_nack_frag_reader_kind(reader_id: [u8; 4], peer_is_intercom: bool) -> [u8; 4] {
    let mut gated = reader_id;
    if peer_is_intercom && gated[3] == 0x07 {
        gated[3] = 0x04;
    }
    gated
}

/// Whether an RTPS datagram originated from an intercom_dds peer, read from
/// the RTPS header vendorId (bytes 6..8, big-endian). Cheap header check used
/// on the fragment-repair path only (never on the intra hot path).
fn payload_is_intercom(payload: &[u8]) -> bool {
    payload.len() >= 8 && u16::from_be_bytes([payload[6], payload[7]]) == INTERCOM_VENDOR_ID_U16
}

/// Record a peer's intercom-vendor flag once, keyed by GUID prefix, so the
/// timer-driven NACK_FRAG path (which only holds the writer GUID) can gate the
/// reader kind O(1). Populated from the fragment paths only, so the intra
/// latency path takes no per-message vendorId branch.
fn record_peer_vendor(payload: &[u8], map: &mut std::collections::HashMap<[u8; 12], bool>) {
    if payload.len() >= 20 {
        if let Ok(prefix) = <[u8; 12]>::try_from(&payload[8..20]) {
            map.entry(prefix)
                .or_insert_with(|| payload_is_intercom(payload));
        }
    }
}

/// Handle incoming HEARTBEAT_FRAG and respond with NACK_FRAG if fragments are missing.
///
/// This provides faster recovery than the timeout-based stale detection (100ms).
/// When the writer announces "I have fragments 1-64 for seq=5", we immediately
/// check our buffer and send NACK_FRAG for any missing fragments.
#[allow(clippy::too_many_arguments)]
fn handle_heartbeat_frag(
    payload: &[u8],
    origin: Origin,
    fragment_buffer: &Mutex<FragmentBuffer>,
    emitter: &NackFragEmitter<'_>,
    nack_frag_count: &mut u32,
) {
    let our_guid_prefix = emitter.our_guid_prefix;

    // Parse HEARTBEAT_FRAG
    let Some(HeartbeatFrag {
        peer_guid_prefix,
        reader_entity_id: addressed,
        writer_entity_id,
        writer_sn,
        last_frag: _last_frag,
    }) = parse_heartbeat_frag(payload)
    else {
        log::debug!("[ROUTER] Failed to parse HEARTBEAT_FRAG");
        return;
    };

    // Skip our own HEARTBEAT_FRAGs (multicast loopback)
    if peer_guid_prefix == our_guid_prefix {
        return;
    }

    // Build writer GUID
    let writer_guid = GUID::new(peer_guid_prefix, writer_entity_id);

    // Check FragmentBuffer for missing fragments
    // A pending sample speaks for its audience; one never seen, for the
    // reader(s) the HEARTBEAT_FRAG addresses.
    let audience;
    let missing_frags = {
        let mut buffer = match fragment_buffer.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        audience = buffer.pending_audience(&writer_guid, writer_sn).cloned();
        match buffer.get_missing_fragments(&writer_guid, writer_sn) {
            Some((missing, _total)) => {
                // Same per-seq backoff as the timer-driven stale path: a
                // HEARTBEAT_FRAG burst must not multiply NACK_FRAGs for a
                // sequence we already requested within the backoff window.
                if !missing.is_empty()
                    && !buffer.try_mark_nacked(
                        &writer_guid,
                        writer_sn,
                        Duration::from_millis(NACK_FRAG_BACKOFF_MS),
                    )
                {
                    return;
                }
                missing
            }
            None => {
                // No entry = we haven't received ANY fragment
                // for this seq. The first fragment(s) were lost. Request ALL.
                // The HEARTBEAT_FRAG tells us how many fragments exist (_last_frag).
                // No FragmentSet exists to hold a per-seq backoff stamp for a
                // never-seen sequence, so this branch is gated by the global
                // NACK_FRAG spacing only: without it, a HEARTBEAT_FRAG burst
                // covering many never-seen sequences fires one NACK_FRAG per
                // HEARTBEAT_FRAG with no throttle at all (the dominant NACK_FRAG
                // source in a cold-start storm of large samples).
                if !buffer.try_mark_nacked_global_only() {
                    return;
                }
                log::debug!(
                    "[ROUTER] HEARTBEAT_FRAG: seq={} unknown - requesting all {} fragments",
                    writer_sn,
                    _last_frag
                );
                // Request all fragments 1.._last_frag
                (1..=_last_frag).collect::<Vec<u32>>()
            }
        }
    };

    if missing_frags.is_empty() {
        return; // All fragments received
    }

    log::debug!(
        "[ROUTER] HEARTBEAT_FRAG: seq={} missing={:?} - sending NACK_FRAG",
        writer_sn,
        &missing_frags[..missing_frags.len().min(8)]
    );

    // The triggering HEARTBEAT_FRAG datagram carries the peer vendorId in
    // its RTPS header, so gate the reader kind directly.
    emitter.request(
        &writer_guid,
        writer_sn,
        &missing_frags,
        payload_is_intercom(payload),
        origin,
        nack_frag_count,
        |reader| {
            (addressed == ENTITYID_UNKNOWN || addressed == reader)
                && audience.as_ref().is_none_or(|a| a.names(reader))
        },
    );
}

/// The fields of a HEARTBEAT_FRAG this router acts on.
#[derive(Debug, PartialEq)]
struct HeartbeatFrag {
    peer_guid_prefix: [u8; 12],
    /// The reader the HEARTBEAT_FRAG informs, ENTITYID_UNKNOWN for all.
    reader_entity_id: [u8; 4],
    writer_entity_id: [u8; 4],
    writer_sn: u64,
    last_frag: u32,
}

/// Parse HEARTBEAT_FRAG submessage.
///
/// Returns (peer_guid_prefix, writer_entity_id, writer_sn, last_fragment_num)
fn parse_heartbeat_frag(payload: &[u8]) -> Option<HeartbeatFrag> {
    // Need RTPS header (20) + submessage header (4) + HEARTBEAT_FRAG payload (24)
    if payload.len() < 48 || !crate::core::discovery::multicast::classifier::is_rtps_magic(payload)
    {
        return None;
    }

    let peer_guid_prefix: [u8; 12] = payload[8..20].try_into().ok()?;

    // Find HEARTBEAT_FRAG (0x13) submessage
    let mut found_frag = None;
    walk::for_each_submessage(payload, |found| {
        if found.id != 0x13 {
            return walk::Step::Continue;
        }
        // Submessage-scoped fields all follow the submessage E flag per
        // RTPS v2.5 Sec.8.3.3.3; centralise the LE/BE dispatch via
        // read_u16/u32.
        let is_le = found.flags & 0x01 != 0;
        let hbf = found.offset + 4;
        if hbf + 24 > payload.len() {
            return walk::Step::Stop;
        }

        let Ok(reader_entity_id) = <[u8; 4]>::try_from(&payload[hbf..hbf + 4]) else {
            return walk::Step::Stop;
        };
        let Ok(writer_entity_id) = <[u8; 4]>::try_from(&payload[hbf + 4..hbf + 8]) else {
            return walk::Step::Stop;
        };

        // writerSN (SequenceNumber_t) per RTPS v2.5 Sec.8.3.5.5 +
        // Sec.9.4.5.3.1: high u32, low u32, both honouring the E flag.
        // HEARTBEAT_FRAG never legitimately carries SEQUENCENUMBER_UNKNOWN
        // (no live writer can lack a sample SN), so we keep the previous
        // unsigned composition for behaviour parity with the previous code.
        let high = builder::read_u32(payload, hbf + 8, is_le);
        let low = builder::read_u32(payload, hbf + 12, is_le);
        let writer_sn = ((high as u64) << 32) | (low as u64);

        let last_frag = builder::read_u32(payload, hbf + 16, is_le);

        found_frag = Some(HeartbeatFrag {
            peer_guid_prefix,
            reader_entity_id,
            writer_entity_id,
            writer_sn,
            last_frag,
        });
        walk::Step::Stop
    });
    found_frag
}

/// Router loop with transport for NACK_FRAG sending
#[allow(clippy::too_many_arguments)]
fn router_loop_with_transport(
    ring: Arc<ArrayQueue<(RxMeta, u8)>>,
    pool: Arc<RxPool>,
    registry: Arc<TopicRegistry>,
    stop_flag: Arc<AtomicBool>,
    metrics: Arc<RouterMetrics>,
    transport: Option<Arc<crate::transport::UdpTransport>>,
    our_guid_prefix: [u8; 12],
    notifier: Option<Arc<WakeNotifier>>,
    endpoint_registry: Option<EndpointRegistry>,
    reader_proxies: ReaderProxyRegistry,
    known_sources: Option<Arc<dyn crate::core::discovery::KnownSources>>,
) {
    use std::collections::HashMap;
    use std::time::Instant;

    let emitter = transport.as_deref().map(|transport| NackFragEmitter {
        transport,
        our_guid_prefix,
        endpoint_registry: endpoint_registry.as_ref(),
        reader_proxies: &reader_proxies,
        metrics: &metrics,
    });

    // Create fragment buffer for user DATA_FRAG reassembly. The participants
    // discovery knows are told apart from forged prefixes, which share a
    // pool of their own (`fragment_buffer::UNKNOWN_POOL_DIVISOR`), and the
    // participant's `known_sources` rank the authenticated ones above.
    let mut user_fragment_buffer = FragmentBuffer::new(USER_FRAG_MAX_PENDING, USER_FRAG_TIMEOUT_MS);
    if let Some(sources) = known_sources {
        user_fragment_buffer = user_fragment_buffer.with_known_sources(sources);
    } else if let Some(registry) = endpoint_registry.as_ref() {
        user_fragment_buffer = user_fragment_buffer.with_known_sources(std::sync::Arc::new(
            crate::core::discovery::DiscoveredParticipants::new(our_guid_prefix, registry.clone()),
        ));
    }
    let user_fragment_buffer = Mutex::new(user_fragment_buffer);

    // Timer for periodic NACK_FRAG checks
    let mut last_nack_frag_check = Instant::now();
    let mut nack_frag_count: u32 = 1;

    // No duplicate cache here. What is a duplicate is decided in ONE place,
    // each reader's per-writer duplicate window (`ReaderSubscriber`'s seen
    // set), which also knows what the reader refused. A cache here dropped
    // for 2 s every copy of a sequence it had routed once, including the
    // retransmission a full RELIABLE reader had refused unacknowledged so
    // that it would be sent again (DDS v1.4 Sec.2.2.3.19, footnote 28).

    // Per-peer intercom-vendor flag (GUID prefix -> is_intercom), resolved once
    // per peer at pairing from the fragment-path datagram headers. The
    // timer-driven NACK_FRAG path reads it O(1) to vendor-gate the reader kind.
    // Bounded by the number of distinct participants, so no eviction needed.
    let mut peer_is_intercom: HashMap<[u8; 12], bool> = HashMap::new();

    // Log whether using notifier or polling
    if notifier.is_some() {
        log::debug!("[ROUTER] Using WakeNotifier for low-latency wake");
    } else {
        log::debug!("[ROUTER] Using polling (100us interval)");
    }

    let mut spinner = RouterSpinner::new(crate::config::env_flags::router_spin(), &metrics);
    'router: while !stop_flag.load(Ordering::Relaxed) {
        // Periodic check for stale fragment sequences
        if last_nack_frag_check.elapsed().as_millis() >= NACK_FRAG_CHECK_INTERVAL_MS as u128 {
            check_stale_fragments_with_transport(
                &user_fragment_buffer,
                &metrics,
                emitter.as_ref(),
                &mut nack_frag_count,
                &peer_is_intercom,
            );
            last_nack_frag_check = Instant::now();
        }

        // Pop, or spin and then park when the ring stays empty (see
        // `engine::router_spin`; `HDDS_ROUTER_SPIN_US` chooses the spin).
        let Some(item) = spinner.pop(&ring, &metrics) else {
            spinner.park(&metrics);
            if let Some(ref n) = notifier {
                n.wait_timeout(Duration::from_millis(10));
            } else {
                thread::sleep(Duration::from_micros(100));
            }
            continue 'router;
        };

        let (meta, buffer_id) = item;
        // A remote writer's departure, behind its data (`engine::departures`):
        // no buffer.
        if meta.kind == PacketKind::Departure {
            registry.apply_next_departure();
            continue 'router;
        }
        if let Some(route) = registry.departure_route() {
            for departure in route.take_overflow() {
                registry.apply_departure(departure);
            }
        }
        let buffer = pool.get_buffer(buffer_id);
        let payload = &buffer[..meta.len as usize];

        match meta.kind {
            PacketKind::Data => {
                // The writer GUID names our own writers (self-loopback below).
                let writer_guid = builder::extract_writer_guid(payload);

                // Self-loopback suppression: skip DATA from our own writers.
                // When both intra-process (TopicMerger) and UDP transport are active,
                // the writer delivers locally via merger AND sends via UDP. The UDP
                // packet loops back to us; delivering it again would cause duplicates.
                if let Some(guid) = writer_guid {
                    if guid[..12] == our_guid_prefix {
                        log::trace!(
                            "[ROUTER] self-loopback: dropping DATA from own writer {:02x?}",
                            &guid[..8]
                        );
                        if let Err(e) = pool.release(buffer_id) {
                            log::debug!(
                                "[hdds-router] Failed to release self-loopback buffer {}: {}",
                                buffer_id,
                                e
                            );
                        }
                        continue;
                    }
                }

                let status = route_data_packet(
                    payload,
                    meta.len as usize,
                    meta.data_payload_offset.map(|off| off as usize),
                    Arc::as_ref(&registry),
                    Arc::as_ref(&metrics),
                );
                // The user writers' controls riding with this DATA follow it in
                // the datagram, so they are applied after it, whatever became of
                // the DATA: the order the control thread cannot keep
                // (`engine::writer_control`).
                if meta.controls_may_ride {
                    route_ring_controls(
                        payload,
                        Arc::as_ref(&registry),
                        Arc::as_ref(&metrics),
                        PacketKind::Data,
                        meta.origin,
                        meta.control_answers,
                    );
                }
                if matches!(status, RouteStatus::Dropped) {
                    if let Err(e) = pool.release(buffer_id) {
                        log::debug!(
                            "[hdds-router] CRITICAL: Failed to release dropped buffer {}: {}",
                            buffer_id,
                            e
                        );
                    }
                    continue;
                }
            }
            PacketKind::DataFrag => {
                // Self-loopback suppression for fragments. The sender is the
                // RTPS header's guidPrefix (RTPS 2.5 8.3.6.4: the Receiver's
                // sourceGuidPrefix), which every DATA_FRAG of the datagram
                // shares. It is not taken from `extract_writer_guid`, which
                // reads a DATA and finds none in a datagram of fragments, so
                // our own fragments would never be suppressed.
                if payload.get(8..20) == Some(&our_guid_prefix[..]) {
                    if let Err(e) = pool.release(buffer_id) {
                        log::debug!(
                            "[hdds-router] Failed to release self-loopback DATA_FRAG buffer {}: {}",
                            buffer_id,
                            e
                        );
                    }
                    continue;
                }

                // Resolve the peer vendor once so the timer-driven NACK_FRAG
                // path can vendor-gate the reader kind (intercom fix).
                record_peer_vendor(payload, &mut peer_is_intercom);

                // No duplicate cache on this arm. The one it had took its key
                // from the datagram's first DATA (`extract_sequence_number`
                // reads no DATA_FRAG), so it never ran on a datagram of
                // fragments alone, and on a datagram mixing a DATA already
                // seen with fragments of ANOTHER sample it dropped those
                // fragments with it. A reader keeps its own duplicate window.

                // The one DATA_FRAG door (`route_data_frag_datagram`), which
                // every other receive path takes. A private copy of it that
                // stopped at the FIRST sample a datagram completed would never
                // insert the fragments behind it, so a datagram completing two
                // samples would lose the second one's pieces.
                let status = route_data_frag_packet_with_addr(
                    payload,
                    meta.len as usize,
                    meta.data_payload_offset.map(|off| off as usize),
                    meta.frag_meta.as_ref(),
                    meta.origin,
                    &user_fragment_buffer,
                    Arc::as_ref(&registry),
                    Arc::as_ref(&metrics),
                );
                if meta.controls_may_ride {
                    route_ring_controls(
                        payload,
                        Arc::as_ref(&registry),
                        Arc::as_ref(&metrics),
                        PacketKind::DataFrag,
                        meta.origin,
                        meta.control_answers,
                    );
                }
                if matches!(status, RouteStatus::Dropped) {
                    if let Err(e) = pool.release(buffer_id) {
                        log::debug!(
                            "[hdds-router] CRITICAL: Failed to release dropped DATA_FRAG buffer {}: {}",
                            buffer_id,
                            e
                        );
                    }
                    continue;
                }
            }
            PacketKind::Heartbeat | PacketKind::Gap => {
                // A user writer's HEARTBEATs and GAPs ride the ring, in the order
                // the datagrams arrived: their reorder-gate effects are applied
                // here, and the ACKNACK answer is the control thread's when it
                // received the datagram (`engine::writer_control`). Builtin
                // writers' controls are the control thread's alone.
                // Our own writers' controls are not ours to apply: the DATA arms
                // drop our own datagrams the same way (the self-loopback guards).
                if payload.get(8..20) != Some(&our_guid_prefix[..]) {
                    route_ring_controls(
                        payload,
                        Arc::as_ref(&registry),
                        Arc::as_ref(&metrics),
                        meta.kind,
                        meta.origin,
                        meta.control_answers,
                    );
                }
            }
            PacketKind::AckNack => {
                // For raw RTPS ACKNACK packets the NackHandler extracts the reader
                // GUID prefix from bytes 8..20 internally (via parse_acknack_submessage).
                // Pass None here; the handler resolves the GUID from the packet itself.
                let errors = registry.deliver_nack(payload, None);
                if errors > 0 {
                    metrics
                        .delivery_errors
                        .fetch_add(errors as u64, Ordering::Relaxed);
                }
            }
            PacketKind::HeartbeatFrag => {
                // Handle HEARTBEAT_FRAG: check for missing fragments and send NACK_FRAG
                if let Some(ref emitter) = emitter {
                    // Resolve the peer vendor once (belt-and-suspenders for the
                    // timer path when only HEARTBEAT_FRAGs have arrived).
                    record_peer_vendor(payload, &mut peer_is_intercom);
                    handle_heartbeat_frag(
                        payload,
                        meta.origin,
                        &user_fragment_buffer,
                        emitter,
                        &mut nack_frag_count,
                    );
                }
            }
            other => {
                log::debug!(
                    "[hdds-router] [!]  Unhandled PacketKind: {:?} - packet dropped!",
                    other
                );
            }
        }

        if let Err(e) = pool.release(buffer_id) {
            log::debug!(
                "[hdds-router] CRITICAL: Failed to release buffer {}: {}",
                buffer_id,
                e
            );
        }
    }
}

#[cfg(test)]
mod nack_frag_dest_tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    const PREFIX: [u8; 12] = [0x01, 0x23, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

    fn src() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 49033)
    }

    /// A user writer of the participant `PREFIX`.
    fn writer() -> GUID {
        GUID::new(PREFIX, [0x00, 0x00, 0x00, 0x02])
    }

    /// RTPS 2.5 8.4.10.4 / 8.5.3.1: a NACK_FRAG goes to the WriterProxy's
    /// unicast locator, the one the writer announced in SEDP; the participant
    /// default only stands in for a writer that announced none.
    #[test]
    fn the_writers_own_locator_wins_over_the_participant_default() {
        let reg = EndpointRegistry::new();
        let default = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 7411);
        let at_writer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 53436);
        reg.register(GUID::new(PREFIX, [0x00, 0x00, 0x01, 0xC1]), default);
        reg.register_writer_locator(writer(), at_writer);
        assert_eq!(
            resolve_nack_frag_dest(&writer(), Origin::direct(src()), Some(&reg)),
            Some(at_writer)
        );
        let other = GUID::new(PREFIX, [0x00, 0x00, 0x01, 0x02]);
        assert_eq!(
            resolve_nack_frag_dest(&other, Origin::direct(src()), Some(&reg)),
            Some(default),
            "a writer that announced no locator of its own uses the participant default"
        );
    }

    /// Discovery as a peer put it on the wire: its SPDP announces a default
    /// unicast locator 127.0.0.1:12345 where nothing listens, and the SEDP
    /// publication of its writer announces the locator it reads, 172.25.0.2
    /// port 53436. Both serialized payloads are taken byte for byte from a
    /// capture. The NACK_FRAG must reach the writer's locator.
    #[test]
    fn a_captured_writer_is_repaired_at_its_sedp_locator() {
        use crate::core::discovery::multicast::DiscoveryFsm;
        use crate::protocol::discovery::sedp::parse::parse_sedp;
        use crate::protocol::discovery::spdp::parse::parse_spdp;

        const SPDP: &str =
            "0003000077000400000000000f000400000000001500040002040000500010000103fe8b\
            10a97e02000fc1f4000001c11600040001030000440004003f0c0000580004003f0c0000\
            320018000100000017870000000000000000000000000000ac1900023300180001000000\
            ea1c0000000000000000000000000000efff000131001800010000003930000000000000\
            00000000000000007f000001480018000100000039300000000000000000000000000000\
            7f000001340004000000000005b004000b000000020008002c0100000000000001000000";
        const SEDP: &str =
            "0003000005000c00070000005371756172650000070010000a0000005368617065547970\
            650000001a000c000200000000000000999999197300080001000000020000005a001000\
            0103fe8b10a97e02000fc1f4000000023000180001000000e91c00000000000000000000\
            00000000efff00022f00180001000000bcd00000000000000000000000000000ac190002\
            01000000";
        fn bytes(hex: &str) -> Vec<u8> {
            let hex: String = hex.split_whitespace().collect();
            (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
                .collect()
        }

        let fsm = DiscoveryFsm::new(GUID::zero(), 100_000);
        fsm.handle_spdp(parse_spdp(&bytes(SPDP)).expect("captured SPDP"));
        let sedp = parse_sedp(&bytes(SEDP)).expect("captured SEDP publication");
        let writer = sedp.endpoint_guid;
        fsm.handle_sedp(sedp);
        let reg = fsm.endpoint_registry();

        let sender = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(172, 25, 0, 2)), 53436);
        let at_writer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(172, 25, 0, 2)), 53436);
        let unread_default = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345);
        assert_eq!(
            reg.get(&GUID::new(writer.prefix, [0x00, 0x00, 0x01, 0xC1])),
            Some(unread_default),
            "the fixture is the peer whose participant default is unread"
        );
        assert_eq!(
            resolve_nack_frag_dest(&writer, Origin::direct(sender), Some(&reg)),
            Some(at_writer)
        );
        assert_eq!(
            resolve_nack_frag_dest(&writer, Origin::relayed(sender), Some(&reg)),
            Some(at_writer)
        );
    }

    #[test]
    fn resolves_advertised_participant_locator() {
        let reg = EndpointRegistry::new();
        let advertised = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 7411);
        reg.register(GUID::new(PREFIX, [0x00, 0x00, 0x01, 0xC1]), advertised);
        assert_eq!(
            resolve_nack_frag_dest(&writer(), Origin::direct(src()), Some(&reg)),
            Some(advertised)
        );
    }

    #[test]
    fn falls_back_to_source_when_unknown() {
        let reg = EndpointRegistry::new();
        assert_eq!(
            resolve_nack_frag_dest(&writer(), Origin::direct(src()), Some(&reg)),
            Some(src())
        );
        assert_eq!(
            resolve_nack_frag_dest(&writer(), Origin::direct(src()), None),
            Some(src())
        );
    }

    #[test]
    fn unspecified_locator_ip_uses_source_ip() {
        let reg = EndpointRegistry::new();
        let advertised = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 7411);
        reg.register(GUID::new(PREFIX, [0x00, 0x00, 0x01, 0xC1]), advertised);
        assert_eq!(
            resolve_nack_frag_dest(&writer(), Origin::direct(src()), Some(&reg)),
            Some(SocketAddr::new(src().ip(), 7411))
        );
    }

    /// RTPS 2.5 8.3.8.9 / 8.4.8.2.6: an INFO_REPLY naming another address
    /// redirects no NACK_FRAG: the registry's locator, else the source.
    #[test]
    fn an_info_reply_locator_never_redirects_a_nack_frag() {
        let named: std::net::SocketAddrV4 = "198.51.100.4:7999".parse().expect("addr");
        let reg = EndpointRegistry::new();
        let advertised = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 7411);
        reg.register(GUID::new(PREFIX, [0x00, 0x00, 0x01, 0xC1]), advertised);
        let empty = EndpointRegistry::new();
        let replying = Origin::direct(src()).replying_to(Some(named));
        assert_eq!(
            resolve_nack_frag_dest(&writer(), replying, Some(&reg)),
            Some(advertised)
        );
        assert_eq!(
            resolve_nack_frag_dest(&writer(), replying, Some(&empty)),
            Some(src())
        );
        assert_eq!(
            resolve_nack_frag_dest(
                &writer(),
                Origin::relayed(src()).replying_to(Some(named)),
                Some(&empty)
            ),
            None
        );
    }

    #[test]
    fn prefix_scan_matches_nonstandard_participant_entity() {
        let reg = EndpointRegistry::new();
        let advertised = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 7420);
        reg.register(GUID::new(PREFIX, [0x00, 0x00, 0x02, 0xC1]), advertised);
        assert_eq!(
            resolve_nack_frag_dest(&writer(), Origin::direct(src()), Some(&reg)),
            Some(advertised)
        );
    }

    /// RTPS 2.5 8.3.4 / 8.3.8.10: `Origin::relayed` carries no reply address.
    /// A fully usable registered locator (real IP, nonzero port) needs
    /// nothing from it and is still returned; every case that would
    /// otherwise fall back to the source address instead returns `None`
    /// -- no NACK_FRAG may be aimed at the forwarder.
    #[test]
    fn a_relayed_origin_never_yields_the_forwarders_address() {
        let advertised = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 7411);

        // Fully resolved: still returned, the forwarder's address is not
        // even consulted.
        let reg = EndpointRegistry::new();
        reg.register(GUID::new(PREFIX, [0x00, 0x00, 0x01, 0xC1]), advertised);
        assert_eq!(
            resolve_nack_frag_dest(&writer(), Origin::relayed(src()), Some(&reg)),
            Some(advertised),
            "a peer already known from SPDP/SEDP stays reachable when relayed"
        );

        // Unknown to the registry: no reply address to fall back to.
        let empty = EndpointRegistry::new();
        assert_eq!(
            resolve_nack_frag_dest(&writer(), Origin::relayed(src()), Some(&empty)),
            None,
            "a relayed forwarder must never stand in for an unknown writer"
        );
        assert_eq!(
            resolve_nack_frag_dest(&writer(), Origin::relayed(src()), None),
            None
        );

        // Registered but with an unspecified IP: needs the reply address to
        // combine with the advertised port, and relayed has none.
        let unspecified_reg = EndpointRegistry::new();
        unspecified_reg.register(
            GUID::new(PREFIX, [0x00, 0x00, 0x01, 0xC1]),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 7411),
        );
        assert_eq!(
            resolve_nack_frag_dest(&writer(), Origin::relayed(src()), Some(&unspecified_reg)),
            None,
            "the unspecified-IP fallback needs a reply address to complete the locator"
        );

        // Registered with a zero port: not a usable destination either way.
        let zero_port_reg = EndpointRegistry::new();
        zero_port_reg.register(
            GUID::new(PREFIX, [0x00, 0x00, 0x01, 0xC1]),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 0),
        );
        assert_eq!(
            resolve_nack_frag_dest(&writer(), Origin::relayed(src()), Some(&zero_port_reg)),
            None
        );
    }
}

#[cfg(test)]
mod multi_data_dedup_tests {
    use super::*;

    /// Minimal 20-byte RTPS header (magic + version + vendor + zero guidPrefix).
    /// `count_data_submessages` never inspects these bytes; they
    /// only anchor the submessage scan, which starts at offset 20.
    fn rtps_header() -> Vec<u8> {
        let mut v = Vec::with_capacity(20);
        v.extend_from_slice(b"RTPS");
        v.extend_from_slice(&[2, 3, 0x01, 0x1a]); // version 2.3, vendor id
        v.extend_from_slice(&[0u8; 12]); // guidPrefix
        v
    }

    /// Minimal 24-byte DATA (0x15) submessage: E=LE, D=1, Q=0,
    /// octetsToNextHeader=20 (RTPS v2.5 Sec.8.3.8.2 body: extraFlags(2) +
    /// octetsToInlineQos(2) + readerId(4) + writerId(4) + writerSN(8) = 20),
    /// so consecutive instances chain cleanly back-to-back.
    fn minimal_data_submsg() -> [u8; 24] {
        let mut b = [0u8; 24];
        b[0] = 0x15;
        b[1] = 0x05;
        b[2..4].copy_from_slice(&20u16.to_le_bytes());
        b[6..8].copy_from_slice(&16u16.to_le_bytes()); // octetsToInlineQos
        b
    }

    /// INFO_TS (0x09) submessage carrying `secs` whole seconds, LE.
    /// `invalidate` sets the I flag (RTPS v2.5 Sec.8.3.8.11): the submessages
    /// that follow have NO valid timestamp.
    fn info_ts_submsg(secs: i32, invalidate: bool) -> [u8; 12] {
        let mut b = [0u8; 12];
        b[0] = 0x09;
        b[1] = 0x01 | if invalidate { 0x02 } else { 0x00 };
        b[2..4].copy_from_slice(&8u16.to_le_bytes());
        b[4..8].copy_from_slice(&secs.to_le_bytes());
        // fraction stays 0, so the value is a whole number of seconds
        b
    }

    /// The same, as whole nanoseconds, for the assertions.
    fn secs_as_ns(secs: u64) -> Option<u64> {
        Some(secs * 1_000_000_000)
    }

    /// `[INFO_TS(a), DATA, INFO_TS(b), DATA]` - the shape a batching vendor
    /// sends and the one that must not stamp both samples with `a`.
    fn two_data_two_timestamps() -> Vec<u8> {
        let mut pkt = rtps_header();
        pkt.extend_from_slice(&info_ts_submsg(11, false));
        pkt.extend_from_slice(&minimal_data_submsg());
        pkt.extend_from_slice(&info_ts_submsg(22, false));
        pkt.extend_from_slice(&minimal_data_submsg());
        assert_eq!(
            count_data_submessages(&pkt),
            2,
            "the fixture must take the multi-DATA path"
        );
        pkt
    }

    #[test]
    fn the_timestamp_in_force_is_the_last_info_ts_before_the_data() {
        let mut pkt = rtps_header();
        pkt.extend_from_slice(&info_ts_submsg(11, false));
        pkt.extend_from_slice(&info_ts_submsg(22, false));
        pkt.extend_from_slice(&minimal_data_submsg());

        assert_eq!(
            parse_info_ts_ns(&pkt),
            secs_as_ns(22),
            "Sec.8.3.8.11: an INFO_TS applies until the next one replaces it"
        );
    }

    #[test]
    fn an_info_ts_after_the_data_does_not_reach_back() {
        let mut pkt = rtps_header();
        pkt.extend_from_slice(&info_ts_submsg(11, false));
        pkt.extend_from_slice(&minimal_data_submsg());
        pkt.extend_from_slice(&info_ts_submsg(22, false));

        assert_eq!(parse_info_ts_ns(&pkt), secs_as_ns(11));
    }

    #[test]
    fn an_invalidating_info_ts_does_not_discard_a_later_valid_one() {
        let mut pkt = rtps_header();
        pkt.extend_from_slice(&info_ts_submsg(0, true));
        pkt.extend_from_slice(&info_ts_submsg(22, false));
        pkt.extend_from_slice(&minimal_data_submsg());

        assert_eq!(
            parse_info_ts_ns(&pkt),
            secs_as_ns(22),
            "the I flag clears the context, it does not end the parse"
        );
    }

    #[test]
    fn an_invalidating_info_ts_clears_an_earlier_valid_one() {
        let mut pkt = rtps_header();
        pkt.extend_from_slice(&info_ts_submsg(11, false));
        pkt.extend_from_slice(&info_ts_submsg(0, true));
        pkt.extend_from_slice(&minimal_data_submsg());

        assert_eq!(
            parse_info_ts_ns(&pkt),
            None,
            "the I flag means the following submessages have no timestamp"
        );
    }

    #[test]
    fn each_batched_data_is_rebuilt_with_the_timestamp_in_force_at_it() {
        let pkt = two_data_two_timestamps();
        let header_and_first_ts = 20 + 12;
        let data_len = 24;

        // DATA 1: nothing has replaced the leading context yet.
        let (syn1, at1) = synthesise_single_data(
            &pkt,
            header_and_first_ts,
            None,
            None,
            (header_and_first_ts, header_and_first_ts + data_len),
        );
        assert_eq!(at1, header_and_first_ts, "the first DATA lands at `first`");
        assert_eq!(parse_info_ts_ns(&syn1), secs_as_ns(11));

        // DATA 2: the INFO_TS between the two DATA is in force.
        let second_ts = header_and_first_ts + data_len;
        let second_data = second_ts + 12;
        let (syn2, at2) = synthesise_single_data(
            &pkt,
            header_and_first_ts,
            None,
            Some((second_ts, second_ts + 12)),
            (second_data, second_data + data_len),
        );
        assert_eq!(
            parse_info_ts_ns(&syn2),
            secs_as_ns(22),
            "sample 2 must carry its OWN timestamp, not sample 1's"
        );
        assert_eq!(
            at2,
            header_and_first_ts + 12,
            "the DATA moved by the appended INFO_TS, so its payload offset must move too"
        );
        assert_eq!(
            count_data_submessages(&syn2),
            1,
            "a synthetic datagram must carry exactly one DATA"
        );
    }

    #[test]
    fn a_rebuilt_data_keeps_its_own_bytes() {
        let pkt = two_data_two_timestamps();
        let first = 20 + 12;
        let second_ts = first + 24;
        let second_data = second_ts + 12;

        let (syn, at) = synthesise_single_data(
            &pkt,
            first,
            None,
            Some((second_ts, second_ts + 12)),
            (second_data, second_data + 24),
        );
        assert_eq!(
            &syn[at..],
            &pkt[second_data..second_data + 24],
            "the DATA must be copied whole and land last"
        );
    }

    /// The WIRING, not the primitive: the tests above call
    /// `synthesise_single_data` directly, so they stay green even if the
    /// routing loop forgets to track the context and hands it `None`. This
    /// one drives the real entry point and reads the side effect the reader
    /// pipeline actually consumes - the per-thread source timestamp
    /// `route_data_packet` stamps for every DATA it routes. After the whole
    /// datagram, that thread-local holds the LAST sample's timestamp.
    ///
    /// It must not hold the FIRST sample's, which would be the case if every
    /// synthetic datagram were rebuilt from `payload[..first]` alone.
    #[test]
    fn the_last_batched_sample_is_routed_with_its_own_timestamp() {
        let pkt = two_data_two_timestamps();
        let registry = TopicRegistry::new();
        let metrics = RouterMetrics::new();

        // No subscriber is registered, so delivery is refused - the stamping
        // happens on the way in and is what this asserts.
        set_route_source_ts_ns(None);
        let _ = route_multi_data_datagram(&pkt, &registry, &metrics);

        assert_eq!(
            route_source_ts_ns(),
            secs_as_ns(22),
            "the second sample must be routed under the INFO_TS that precedes IT"
        );
    }

    #[test]
    fn count_data_submessages_single_data_is_one() {
        let mut pkt = rtps_header();
        pkt.extend_from_slice(&minimal_data_submsg());
        assert_eq!(count_data_submessages(&pkt), 1);
    }

    #[test]
    fn count_data_submessages_counts_two_batched_data() {
        // Batching: [DATA seq-carrying, DATA seq-carrying]
        // in one datagram, as in [INFO_TS, DATA seq=n, DATA seq=n+1, ...].
        let mut pkt = rtps_header();
        pkt.extend_from_slice(&minimal_data_submsg());
        pkt.extend_from_slice(&minimal_data_submsg());
        assert_eq!(count_data_submessages(&pkt), 2);
    }
}

#[cfg(test)]
mod missing_sequence_observability_tests {
    use super::*;

    fn truncated_data_packet(prefix: [u8; 12], writer_id: [u8; 4]) -> Vec<u8> {
        let mut packet = Vec::with_capacity(36);
        packet.extend_from_slice(b"RTPS");
        packet.extend_from_slice(&[2, 3, 0x01, 0x1a]);
        packet.extend_from_slice(&prefix);
        packet.extend_from_slice(&[0x15, 0x05, 0, 0]); // DATA, LE, data flag
        packet.extend_from_slice(&[0, 0]); // extraFlags
        packet.extend_from_slice(&16u16.to_le_bytes()); // octetsToInlineQos
                                                        // ENTITYID_UNKNOWN: the topic has no subscriber, and a DATA naming
                                                        // a reader that is not here stops at the readerId, before the
                                                        // writerSN this fixture is about.
        packet.extend_from_slice(&[0, 0, 0, 0]); // readerEntityId
        packet.extend_from_slice(&writer_id);
        packet
    }

    #[test]
    fn missing_sequence_warning_is_once_per_writer() {
        let registry = TopicRegistry::new();
        let writer_a = [0x11; 16];
        let writer_b = [0x22; 16];

        assert!(registry.should_warn_missing_sequence_fallback(Some(writer_a)));
        assert!(!registry.should_warn_missing_sequence_fallback(Some(writer_a)));
        assert!(registry.should_warn_missing_sequence_fallback(Some(writer_b)));
    }

    #[test]
    fn truncated_data_reaches_missing_sequence_metric_before_payload_drop() {
        let prefix = [0x33; 12];
        let writer_id = [0, 0, 0, 2];
        let mut writer_guid = [0u8; 16];
        writer_guid[..12].copy_from_slice(&prefix);
        writer_guid[12..].copy_from_slice(&writer_id);

        let packet = truncated_data_packet(prefix, writer_id);
        assert_eq!(packet.len(), 36);
        assert_eq!(builder::extract_writer_guid(&packet), Some(writer_guid));
        assert_eq!(builder::extract_sequence_number(&packet), None);

        let registry = TopicRegistry::new();
        registry
            .register_topic("seq0-observability".to_string(), None)
            .expect("topic registration must succeed");
        registry.register_writer_guid(writer_guid, "seq0-observability".to_string());
        let metrics = RouterMetrics::new();

        let status = route_data_packet(&packet, packet.len(), None, &registry, &metrics);

        assert_eq!(status, RouteStatus::Dropped);
        assert_eq!(
            metrics.missing_sequence_fallbacks.load(Ordering::Relaxed),
            1
        );
        assert_eq!(metrics.delivery_errors.load(Ordering::Relaxed), 1);
    }
}

/// A key-only DATA that is not a lifecycle change still consumes a sequence
/// number. DDSI-RTPS 2.5 8.3.8.2: with KeyFlag set and DataFlag clear the
/// serializedPayload is the key of the data-object, not its value; the
/// change is still identified by its writerSN. When its PID_STATUS_INFO
/// carries neither the Disposed nor the Unregistered flag (9.6.4.9) there is
/// no dispose to deliver and no sample to hand to the application, but the
/// reader must still learn that the SN was used, or its reliable state waits
/// for a sample that will never come.
#[cfg(test)]
mod key_only_data_tests {
    use super::*;
    use crate::engine::Subscriber;
    use std::sync::atomic::AtomicUsize;

    /// GUID prefix of the test writer, chosen for the test.
    const WRITER_PREFIX: [u8; 12] = [
        0x6b, 0x65, 0x79, 0x2d, 0x6f, 0x6e, 0x6c, 0x79, 0x00, 0x00, 0x00, 0x05,
    ];
    /// Entity id of the test writer: key 0x000031, kind 0x02 (user writer
    /// with key, DDSI-RTPS 2.5 9.3.1.2).
    const WRITER_ENTITY: [u8; 4] = [0x00, 0x00, 0x31, 0x02];
    /// The writerSN the key-only DATA carries, chosen for the test (high
    /// half 0, low half 23).
    const WRITER_SN: u64 = 23;

    fn writer_guid() -> [u8; 16] {
        let mut guid = [0u8; 16];
        guid[..12].copy_from_slice(&WRITER_PREFIX);
        guid[12..].copy_from_slice(&WRITER_ENTITY);
        guid
    }

    /// A datagram built for the test: RTPS header, INFO_TS, then one DATA
    /// with flags E|Q|K (D clear) whose inline QoS carries PID_STATUS_INFO
    /// with no flag set and whose serializedPayload is a key. The rule is
    /// exercised only if K is the one thing that makes this DATA key-only:
    /// with K ignored, a D=0 Q=1 DATA whose StatusInfo carries no D/U bit is
    /// not a lifecycle marker either, and the router does not advance the
    /// writer's sequence on it.
    fn key_only_data_datagram() -> Vec<u8> {
        let mut p = Vec::new();
        // Header (DDSI-RTPS 2.5 8.3.3.1, 9.4.4): protocol "RTPS", version
        // 2.5, the HDDS vendor id (this path does not branch on it), prefix.
        p.extend_from_slice(b"RTPS");
        p.extend_from_slice(&[0x02, 0x05]);
        p.extend_from_slice(&HDDS_VENDOR_ID);
        p.extend_from_slice(&WRITER_PREFIX);

        // INFO_TS (8.3.8.11, 9.4.5.12): id 0x09, flags E, 8 octets of Time_t
        // (seconds, fraction), values chosen for the test.
        p.extend_from_slice(&[0x09, 0x01]);
        p.extend_from_slice(&8u16.to_le_bytes());
        p.extend_from_slice(&0x6000_0000u32.to_le_bytes());
        p.extend_from_slice(&0x8000_0000u32.to_le_bytes());

        // DATA (8.3.8.2, 9.4.5.4): id 0x15, flags E (0x01) | Q (0x02) |
        // K (0x08); octetsToNextHeader 0: the last submessage extends to the
        // end of the message (9.4.5.1.3).
        p.extend_from_slice(&[0x15, 0x01 | 0x02 | 0x08]);
        p.extend_from_slice(&0u16.to_le_bytes());
        p.extend_from_slice(&0u16.to_le_bytes()); // extraFlags
        p.extend_from_slice(&16u16.to_le_bytes()); // octetsToInlineQos
        p.extend_from_slice(&[0, 0, 0, 0]); // readerId: ENTITYID_UNKNOWN
        p.extend_from_slice(&WRITER_ENTITY); // writerId
        p.extend_from_slice(&0u32.to_le_bytes()); // writerSN high
        p.extend_from_slice(&(WRITER_SN as u32).to_le_bytes()); // writerSN low

        // inlineQos (9.4.2.11): PID_STATUS_INFO 0x0071, length 4, the
        // StatusInfo_t octets with no flag set (9.6.4.9), then PID_SENTINEL.
        p.extend_from_slice(&0x0071u16.to_le_bytes());
        p.extend_from_slice(&4u16.to_le_bytes());
        p.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        p.extend_from_slice(&0x0001u16.to_le_bytes());
        p.extend_from_slice(&0u16.to_le_bytes());

        // serializedPayload, the key (8.3.8.2): encapsulation CDR2_LE
        // {0x00, 0x07} with options 0 (DDS-XTypes 1.3 7.6.3.1.2), then the
        // key of a FINAL type with one `long` key member, value 0x2a.
        p.extend_from_slice(&[0x00, 0x07, 0x00, 0x00]);
        p.extend_from_slice(&0x2au32.to_le_bytes());

        assert_eq!(p[20 + 12 + 1] & 0x0c, 0x08, "K set, D clear");
        p
    }

    struct ProbeSubscriber {
        topic: String,
        data_calls: AtomicUsize,
        non_data_seqs: Mutex<Vec<u64>>,
    }

    impl ProbeSubscriber {
        fn new(topic: &str) -> Self {
            Self {
                topic: topic.to_string(),
                data_calls: AtomicUsize::new(0),
                non_data_seqs: Mutex::new(Vec::new()),
            }
        }
    }

    impl Subscriber for ProbeSubscriber {
        fn on_data(&self, _topic: &str, _seq: u64, _data: &[u8]) {
            self.data_calls.fetch_add(1, Ordering::Relaxed);
        }

        fn on_writer_non_data(&self, _writer_guid: [u8; 16], seq: u64) {
            self.non_data_seqs.lock().expect("probe lock").push(seq);
        }

        fn topic_name(&self) -> &str {
            &self.topic
        }
    }

    #[test]
    fn key_only_data_without_lifecycle_advances_without_user_delivery() {
        let packet = key_only_data_datagram();
        let writer_guid = writer_guid();
        let registry = TopicRegistry::new();
        let probe = Arc::new(ProbeSubscriber::new("KeyOnlyProbe"));
        registry
            .register_subscriber(probe.clone())
            .expect("register subscriber");
        registry.register_writer_guid(writer_guid, "KeyOnlyProbe".to_string());
        let metrics = RouterMetrics::new();

        assert!(builder::is_key_only_data(&packet));
        assert_eq!(builder::extract_writer_guid(&packet), Some(writer_guid));
        assert_eq!(builder::extract_sequence_number(&packet), Some(WRITER_SN));
        assert_eq!(
            registry.get_topic_by_guid(&writer_guid).as_deref(),
            Some("KeyOnlyProbe")
        );

        let status = route_data_packet(&packet, packet.len(), None, &registry, &metrics);

        assert_eq!(status, RouteStatus::Delivered);
        assert_eq!(probe.data_calls.load(Ordering::Relaxed), 0);
        assert_eq!(
            *probe.non_data_seqs.lock().expect("probe lock"),
            vec![WRITER_SN]
        );
    }

    /// A writer's end of its open coherent set as a peer sends it on the
    /// wire (RTPS v2.5 Sec.8.7.6: a change that carries no PID_COHERENT_SET
    /// is no member of the set): a DATA with flags E only (D=0 K=0 Q=0), no
    /// inline QoS, no payload, behind a HEADER_EXTENSION, writerSN 52.
    /// Captured from a foreign publisher's UDP payload, verbatim.
    #[rustfmt::skip]
    const BARE_DATA: [u8; 64] = [
        0x52, 0x54, 0x50, 0x53, 0x02, 0x05, 0x01, 0x06, 0x01, 0x06, 0xac, 0x19, 0x00, 0x02, 0x00, 0x00,
        0x00, 0x0f, 0x00, 0x01, 0x00, 0x03, 0x04, 0x00, 0x40, 0x00, 0x00, 0x00, 0x09, 0x01, 0x08, 0x00,
        0x86, 0x9c, 0xe5, 0x6a, 0xa6, 0xe2, 0xdc, 0x89, 0x15, 0x01, 0x14, 0x00, 0x00, 0x00, 0x10, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00,
    ];

    #[test]
    fn data_without_payload_or_key_is_a_change_without_a_sample() {
        let packet = BARE_DATA;
        let mut guid = [0u8; 16];
        guid[..12].copy_from_slice(&packet[8..20]);
        guid[12..].copy_from_slice(&[0x00, 0x00, 0x01, 0x02]);
        let registry = TopicRegistry::new();
        let probe = Arc::new(ProbeSubscriber::new("BareDataProbe"));
        registry
            .register_subscriber(probe.clone())
            .expect("register subscriber");
        registry.register_writer_guid(guid, "BareDataProbe".to_string());
        let metrics = RouterMetrics::new();
        let (_, offset, _, _) = crate::core::discovery::multicast::classify_rtps(&packet);

        assert!(builder::is_data_without_sample(&packet));
        assert_eq!(builder::extract_sequence_number(&packet), Some(52));

        let status = route_data_packet(&packet, packet.len(), offset, &registry, &metrics);

        assert_eq!(status, RouteStatus::Delivered);
        assert_eq!(probe.data_calls.load(Ordering::Relaxed), 0);
        assert_eq!(*probe.non_data_seqs.lock().expect("probe lock"), vec![52]);
    }

    #[test]
    fn a_sampleless_change_captures_group_arrival_only_for_ordered_readers() {
        struct ArrivalProbe {
            ordered: bool,
            captured: Mutex<Vec<bool>>,
        }
        impl Subscriber for ArrivalProbe {
            fn topic_name(&self) -> &str {
                "BareDataArrival"
            }
            fn requires_ordered_group(&self) -> bool {
                self.ordered
            }
            fn on_data(&self, _: &str, _: u64, _: &[u8]) {}
            fn on_change_without_sample(&self, writer: [u8; 16], _: u64) {
                self.captured
                    .lock()
                    .expect("arrival probe")
                    .push(crate::dds::GroupArrivalScope::captured(writer).is_some());
            }
        }

        for ordered in [false, true] {
            let packet = BARE_DATA;
            let writer = builder::extract_writer_guid(&packet).expect("writer GUID");
            let registry = TopicRegistry::new();
            let probe = Arc::new(ArrivalProbe {
                ordered,
                captured: Mutex::new(Vec::new()),
            });
            registry.register_subscriber(probe.clone()).unwrap();
            registry.register_writer_guid(writer, "BareDataArrival".to_string());
            registry.record_writer_group_dialect(
                writer,
                crate::protocol::group::GroupDialect::Spec,
                Some([0x00, 0x00, 0x02, 0x09]),
            );
            let (_, offset, _, _) = crate::core::discovery::multicast::classify_rtps(&packet);
            assert_eq!(
                route_data_packet(
                    &packet,
                    packet.len(),
                    offset,
                    &registry,
                    &RouterMetrics::new(),
                ),
                RouteStatus::Delivered
            );
            assert_eq!(
                *probe.captured.lock().expect("arrival probe"),
                vec![ordered],
                "a sample-less ordered change needs the same arrival frame as its samples"
            );
            assert!(crate::dds::GroupArrivalScope::captured(writer).is_none());
        }
    }

    /// `BARE_DATA`'s DATA as writerSN 53, flags E|Q (D=0 K=0), its inline
    /// QoS one PID_PAD and no PID_SENTINEL inside the submessage: an invalid
    /// DATA (RTPS v2.5 Sec.8.3.8.2, "inlineQos is invalid"; Sec.9.6.2.2),
    /// which is ignored (Sec.8.3.4.1), never a change.
    fn unterminated_inline_qos_data() -> Vec<u8> {
        let mut data = BARE_DATA[40..].to_vec();
        data[1] = 0x03;
        data[2..4].copy_from_slice(&24u16.to_le_bytes());
        data[20..24].copy_from_slice(&53u32.to_le_bytes());
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        data
    }

    fn bare_data_probe() -> (TopicRegistry, Arc<ProbeSubscriber>) {
        let mut guid = [0u8; 16];
        guid[..12].copy_from_slice(&BARE_DATA[8..20]);
        guid[12..].copy_from_slice(&[0x00, 0x00, 0x01, 0x02]);
        let registry = TopicRegistry::new();
        let probe = Arc::new(ProbeSubscriber::new("BareDataProbe"));
        registry
            .register_subscriber(probe.clone())
            .expect("register subscriber");
        registry.register_writer_guid(guid, "BareDataProbe".to_string());
        (registry, probe)
    }

    #[test]
    fn an_invalid_data_without_payload_or_key_is_no_change() {
        let mut packet = BARE_DATA[..40].to_vec();
        packet.extend_from_slice(&unterminated_inline_qos_data());
        let (registry, probe) = bare_data_probe();
        let metrics = RouterMetrics::new();

        assert!(!builder::is_data_without_sample(&packet));
        let _ = route_data_packet(&packet, packet.len(), None, &registry, &metrics);

        assert_eq!(probe.data_calls.load(Ordering::Relaxed), 0);
        assert!(
            probe.non_data_seqs.lock().expect("probe lock").is_empty(),
            "an invalid DATA was taken for a change"
        );
    }

    /// The same invalid DATA behind a valid one in one datagram: each DATA
    /// is routed alone (`route_multi_data_datagram`), and only the valid
    /// one is a change.
    #[test]
    fn an_invalid_data_without_payload_or_key_batched_behind_a_valid_one_is_no_change() {
        let mut packet = BARE_DATA.to_vec();
        packet.extend_from_slice(&unterminated_inline_qos_data());
        let (registry, probe) = bare_data_probe();
        let metrics = RouterMetrics::new();
        let (_, offset, _, _) = crate::core::discovery::multicast::classify_rtps(&packet);

        let _ = route_data_packet(&packet, packet.len(), offset, &registry, &metrics);

        assert_eq!(probe.data_calls.load(Ordering::Relaxed), 0);
        assert_eq!(
            *probe.non_data_seqs.lock().expect("probe lock"),
            vec![52],
            "only the valid DATA is a change"
        );
    }
}

/// a standalone coherent END marker is a change with its own
/// sequence number; the reader must be told which, or it never acknowledges
/// it. The marker is a DATA with no payload whose inline QoS carries the
/// vendor-specific parameters (vendor 0x0101) the RTI dialect parses:
/// 0x8022, the sequence number that identifies the set, and 0x8024, the
/// number of samples in it. They are in the vendor-specific PID range (0x8000 bit
/// set, DDSI-RTPS 2.5 9.6.2.2.1), not defined by RTPS; their meaning here is
/// the one `protocol::builder::extract` gives them.
#[cfg(test)]
mod standalone_end_marker_tests {
    use super::*;
    use crate::engine::Subscriber;

    /// GUID of the test writer: a prefix starting with vendor id 0x0101 (the
    /// router reads the vendor-specific parameters only under that vendor
    /// id), the rest chosen for the test, and a user writer with key, entity
    /// 0x000007 kind 0x02 (DDSI-RTPS 2.5 9.3.1.2).
    const WRITER_GUID: [u8; 16] = [
        0x01, 0x01, 0xc0, 0xff, 0xee, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2a, 0x00, 0x00, 0x07,
        0x02,
    ];

    /// The marker's own sequence number, the sequence number identifying the
    /// set it closes, and the set's sample count, chosen for the test.
    const MARKER_SN: u32 = 9;
    const SET_SN: u32 = 5;
    const SET_COUNT: u32 = 3;

    /// Offset of the writerSN low word in `end_marker`'s datagram: 20-byte
    /// message header, 4-byte submessage header, then extraFlags (2),
    /// octetsToInlineQos (2), readerId (4), writerId (4), writerSN.high (4).
    const WRITER_SN_LOW: usize = 20 + 4 + 2 + 2 + 4 + 4 + 4;

    /// A datagram built here, field by field: the RTPS message header
    /// (DDSI-RTPS 2.5 9.4.4) with vendor id 0x0101, then one DATA submessage
    /// (9.4.5.3), flags E (little endian) and Q (inline QoS), no payload,
    /// from `WRITER_GUID`, writerSN `writer_sn`, whose inline QoS (a
    /// ParameterList, 9.4.2.11) carries 0x8022 = SET_SN and 0x8024 =
    /// SET_COUNT, then PID_SENTINEL.
    fn end_marker(writer_sn: u32) -> Vec<u8> {
        let mut qos = Vec::new();
        qos.extend(0x8022u16.to_le_bytes());
        qos.extend(8u16.to_le_bytes());
        qos.extend(0u32.to_le_bytes());
        qos.extend(SET_SN.to_le_bytes());
        qos.extend(0x8024u16.to_le_bytes());
        qos.extend(4u16.to_le_bytes());
        qos.extend(SET_COUNT.to_le_bytes());
        qos.extend([0x01, 0x00, 0x00, 0x00]);

        let mut body = Vec::new();
        body.extend(0u16.to_le_bytes()); // extraFlags
        body.extend(16u16.to_le_bytes()); // octetsToInlineQos
        body.extend([0u8; 4]); // readerId ENTITYID_UNKNOWN
        body.extend(&WRITER_GUID[12..]);
        body.extend(0u32.to_le_bytes()); // writerSN.high
        body.extend(writer_sn.to_le_bytes()); // writerSN.low
        body.extend(qos);

        let mut m = b"RTPS".to_vec();
        m.extend([0x02, 0x05]);
        m.extend(&WRITER_GUID[..2]);
        m.extend(&WRITER_GUID[..12]);
        m.extend([0x15, 0x03]);
        m.extend(u16::try_from(body.len()).expect("length").to_le_bytes());
        m.extend(body);
        m
    }

    type EndCall = ([u8; 16], Option<u64>, Option<u32>, Option<u64>);

    struct EndProbe {
        topic: String,
        ends: Mutex<Vec<EndCall>>,
    }

    impl Subscriber for EndProbe {
        fn on_data(&self, _topic: &str, _seq: u64, _data: &[u8]) {
            panic!("an END marker carries no sample");
        }

        fn on_coherent_end(
            &self,
            _topic: &str,
            writer_guid: [u8; 16],
            _group_sn: Option<u64>,
            _publisher_entity_id: Option<[u8; 4]>,
            end_sn: Option<u64>,
            end_count: Option<u32>,
        ) {
            self.ends
                .lock()
                .expect("probe lock")
                .push((writer_guid, end_sn, end_count, None));
        }

        fn on_coherent_end_marker(
            &self,
            _topic: &str,
            writer_guid: [u8; 16],
            _group_sn: Option<u64>,
            _publisher_entity_id: Option<[u8; 4]>,
            end_sn: u64,
            end_count: Option<u32>,
            marker_seq: u64,
        ) {
            self.ends.lock().expect("probe lock").push((
                writer_guid,
                Some(end_sn),
                end_count,
                Some(marker_seq),
            ));
        }

        fn topic_name(&self) -> &str {
            &self.topic
        }
    }

    /// A marker whose writerSN is 0 (never a valid sequence number, RTPS
    /// v2.5 Sec.8.3.5.4; also what the router falls back to when it cannot
    /// read one) still closes its set, but has no number to acknowledge: it
    /// is not handed over as a marker.
    #[test]
    fn a_marker_without_a_valid_sequence_number_is_a_plain_end() {
        let frame = end_marker(0);
        assert_eq!(frame[WRITER_SN_LOW..WRITER_SN_LOW + 4], [0u8; 4]);
        let registry = TopicRegistry::new();
        let probe = Arc::new(EndProbe {
            topic: "Square".to_string(),
            ends: Mutex::new(Vec::new()),
        });
        registry
            .register_subscriber(probe.clone())
            .expect("register subscriber");
        registry.register_writer_guid(WRITER_GUID, "Square".to_string());
        let metrics = RouterMetrics::new();

        let status = route_data_packet(&frame, frame.len(), None, &registry, &metrics);

        assert_eq!(status, RouteStatus::Delivered);
        assert_eq!(
            *probe.ends.lock().expect("probe lock"),
            vec![(WRITER_GUID, Some(u64::from(SET_SN)), Some(SET_COUNT), None)]
        );
    }

    /// A subscriber written before `on_coherent_end_marker` existed: it
    /// implements `on_coherent_end` only.
    struct PlainEndProbe {
        topic: String,
        ends: Mutex<Vec<EndCall>>,
    }

    impl Subscriber for PlainEndProbe {
        fn on_data(&self, _topic: &str, _seq: u64, _data: &[u8]) {
            panic!("an END marker carries no sample");
        }

        fn on_coherent_end(
            &self,
            _topic: &str,
            writer_guid: [u8; 16],
            _group_sn: Option<u64>,
            _publisher_entity_id: Option<[u8; 4]>,
            end_sn: Option<u64>,
            end_count: Option<u32>,
        ) {
            self.ends
                .lock()
                .expect("probe lock")
                .push((writer_guid, end_sn, end_count, None));
        }

        fn topic_name(&self) -> &str {
            &self.topic
        }
    }

    /// A subscriber that implements `on_coherent_end` only still hears of
    /// a standalone END marker, though the marker has a hook of its own.
    #[test]
    fn a_subscriber_without_the_marker_hook_still_hears_the_end() {
        let frame = end_marker(MARKER_SN);
        let registry = TopicRegistry::new();
        let probe = Arc::new(PlainEndProbe {
            topic: "Square".to_string(),
            ends: Mutex::new(Vec::new()),
        });
        registry
            .register_subscriber(probe.clone())
            .expect("register subscriber");
        registry.register_writer_guid(WRITER_GUID, "Square".to_string());
        let metrics = RouterMetrics::new();

        let status = route_data_packet(&frame, frame.len(), None, &registry, &metrics);

        assert_eq!(status, RouteStatus::Delivered);
        assert_eq!(
            *probe.ends.lock().expect("probe lock"),
            vec![(WRITER_GUID, Some(u64::from(SET_SN)), Some(SET_COUNT), None)]
        );
    }

    #[test]
    fn a_standalone_end_marker_reaches_the_reader_with_its_sequence_number() {
        let frame = end_marker(MARKER_SN);
        let registry = TopicRegistry::new();
        let probe = Arc::new(EndProbe {
            topic: "Square".to_string(),
            ends: Mutex::new(Vec::new()),
        });
        registry
            .register_subscriber(probe.clone())
            .expect("register subscriber");
        registry.register_writer_guid(WRITER_GUID, "Square".to_string());
        let metrics = RouterMetrics::new();

        let status = route_data_packet(&frame, frame.len(), None, &registry, &metrics);

        assert_eq!(status, RouteStatus::Delivered);
        assert_eq!(
            *probe.ends.lock().expect("probe lock"),
            vec![(
                WRITER_GUID,
                Some(u64::from(SET_SN)),
                Some(SET_COUNT),
                Some(u64::from(MARKER_SN))
            )]
        );
    }
}

/// Site 1 of the silent-swallow audit fixes: the router's own `is_xcdr1` match (this
/// file, two call sites) treats the vendor-flagged encapsulations 0x8001 and
/// 0x8003 (CDR_LE / PL_CDR_LE with the 0x8000 bit set) as CDR v1 and strips
/// the 4-byte header accordingly.
/// `cdr_negotiation::cdr_version_from_representation_id` used not to
/// recognize those ids, returning `Err`, so the `.ok().unwrap_or(Xcdr2)`
/// fallback silently handed the subscriber the WRONG version for genuinely
/// XCDR1 bytes. XCDR1 and XCDR2 disagree on the alignment of an 8-byte
/// primitive following a variable-size member (see
/// `dynamic::cdr_dynamic::primitive_alignment`), so this corrupted
/// application data rather than merely dropping it. So
/// `cdr_version_from_representation_id` must agree with the router's own
/// classification (see `cdr_negotiation.rs`); this test pins that.
#[cfg(test)]
mod vendor_flagged_xcdr1_tests {
    use super::*;
    use crate::dds::CdrVersion;
    use crate::dynamic::{
        decode_dynamic_with_version, encode_dynamic_with_version, DynamicData, PrimitiveKind,
        TypeDescriptorBuilder,
    };
    use crate::engine::Subscriber;
    use std::sync::Mutex as StdMutex;

    const VENDOR_FLAGGED_WRITER_GUID: [u8; 16] = [
        0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x00, 0x00, 0x00,
        0x02,
    ];

    /// Captures exactly what the router hands to the subscriber: the
    /// stripped payload bytes and the `CdrVersion` it computed for them.
    struct CapturingSubscriber {
        topic: String,
        captured: StdMutex<Option<(Vec<u8>, CdrVersion)>>,
    }

    impl CapturingSubscriber {
        fn new(topic: &str) -> Self {
            Self {
                topic: topic.to_string(),
                captured: StdMutex::new(None),
            }
        }
    }

    impl Subscriber for CapturingSubscriber {
        fn on_data(&self, _topic: &str, _seq: u64, _data: &[u8]) {
            panic!("expected on_data_with_writer, not the versionless on_data");
        }

        fn on_data_with_writer(
            &self,
            _topic: &str,
            _writer_guid: [u8; 16],
            _seq: u64,
            data: &[u8],
            version: CdrVersion,
        ) {
            *self.captured.lock().expect("capture lock") = Some((data.to_vec(), version));
        }

        fn topic_name(&self) -> &str {
            &self.topic
        }
    }

    /// Build a minimal single-DATA RTPS datagram whose serializedPayload
    /// carries `payload_body` behind a vendor-flagged CDR_LE encapsulation
    /// header (0x8001 = CDR_LE 0x0001 with the 0x8000 bit set -- HDDS decodes
    /// the body as plain CDR_LE: the flag does not name a new encoding).
    fn vendor_flagged_xcdr1_packet(payload_body: &[u8]) -> Vec<u8> {
        let guid_prefix = &VENDOR_FLAGGED_WRITER_GUID[..12];
        let writer_entity_id = &VENDOR_FLAGGED_WRITER_GUID[12..];

        let mut packet = Vec::new();
        packet.extend_from_slice(b"RTPS");
        packet.extend_from_slice(&[2, 3, 0x01, 0x02]); // protocol version, arbitrary vendorId
        packet.extend_from_slice(guid_prefix);

        // DATA submessage: id=0x15, flags = E(LE) | D(data present) = 0x05.
        // octetsToNextHeader=0: this is the only/last submessage, extends to
        // the datagram end (RTPS v2.5 8.3.3.3.3).
        packet.extend_from_slice(&[0x15, 0x05, 0x00, 0x00]);
        packet.extend_from_slice(&[0, 0]); // extraFlags
        packet.extend_from_slice(&16u16.to_le_bytes()); // octetsToInlineQos (Q=0, unused)
        packet.extend_from_slice(&[0, 0, 0, 0]); // readerEntityId = ENTITYID_UNKNOWN
        packet.extend_from_slice(writer_entity_id);
        packet.extend_from_slice(&[0, 0, 0, 0]); // writerSN high
        packet.extend_from_slice(&1u32.to_le_bytes()); // writerSN low = 1

        // serializedPayload: vendor-flagged CDR_LE (0x8001) + options.
        packet.extend_from_slice(&[0x80, 0x01, 0x00, 0x00]);
        packet.extend_from_slice(payload_body);
        packet
    }

    #[test]
    fn vendor_flagged_encapsulation_decodes_correctly() {
        // A struct shaped exactly like the audit's example: a variable-length
        // member (a string) followed by an 8-byte-aligned primitive (an
        // i64). XCDR1 aligns the i64 on 8; XCDR2 caps alignment at 4. The
        // string field ends at byte offset 12, which is 4-aligned but not
        // 8-aligned, so the two versions disagree on where the i64 starts.
        let desc = Arc::new(
            TypeDescriptorBuilder::new("Confused")
                .string_field("name")
                .field("value", PrimitiveKind::I64)
                .build()
                .with_extensibility(crate::dynamic::Extensibility::Final),
        );

        let expected_value: i64 = 0x1122_3344_5566_7788;
        let mut data = DynamicData::new(&desc);
        data.set("name", "Flagged").expect("set name");
        data.set("value", expected_value).expect("set value");

        // HDDS reads the body under 0x8001 as XCDR1 (natural 8-byte
        // alignment): 0x8001 is CDR_LE (0x0001) with the 0x8000 bit set,
        // not a different body encoding.
        let wire_body =
            encode_dynamic_with_version(&data, CdrVersion::Xcdr1).expect("encode xcdr1");
        // Sanity-check the fixture actually exercises the disputed
        // alignment: 4 (length prefix) + 8 ("Flagged\0") = 12, which is
        // 4-aligned (XCDR2 would add no padding) but not 8-aligned (XCDR1
        // must add 4 bytes of padding before the i64).
        assert_eq!(wire_body.len(), 24, "fixture layout assumption changed");

        let packet = vendor_flagged_xcdr1_packet(&wire_body);
        // The encapsulation header sits right after the fixed DATA
        // submessage header: 20-byte RTPS header + 24-byte DATA header.
        let payload_offset = 44;
        assert_eq!(&packet[payload_offset..payload_offset + 2], [0x80, 0x01]);

        let registry = TopicRegistry::new();
        let probe = Arc::new(CapturingSubscriber::new("VendorFlaggedXcdr1Topic"));
        registry
            .register_subscriber(probe.clone())
            .expect("register subscriber");
        registry.register_writer_guid(
            VENDOR_FLAGGED_WRITER_GUID,
            "VendorFlaggedXcdr1Topic".to_string(),
        );
        let metrics = RouterMetrics::new();

        let status = route_data_packet(
            &packet,
            packet.len(),
            Some(payload_offset),
            &registry,
            &metrics,
        );
        assert_eq!(status, RouteStatus::Delivered);

        let (captured_body, captured_version) = probe
            .captured
            .lock()
            .expect("capture lock")
            .clone()
            .expect("subscriber was not invoked");

        // The router strips the 0x8001 header as XCDR1 (its own `is_xcdr1`
        // match includes 0x8001) and `cdr_version_from_representation_id`
        // agrees (cdr_negotiation.rs), so the
        // subscriber receives CdrVersion::Xcdr1 -- matching the router's own
        // classification of the very same byte, instead of silently
        // contradicting it.
        assert_eq!(
            captured_version,
            CdrVersion::Xcdr1,
            "the router must agree with its own is_xcdr1 classification of 0x8001"
        );

        let decoded = decode_dynamic_with_version(&captured_body, &desc, captured_version)
            .expect("decode with the router-reported version");
        assert_eq!(
            decoded.get::<i64>("value").expect("decoded value field"),
            expected_value
        );

        // Proof that a version mismatch is corruption, not a difference
        // without a symptom: decoding the SAME bytes with the wrong version
        // (XCDR2) reads the i64 from the
        // wrong offset (no 8-byte padding skipped after the string) and
        // returns a different value.
        let decoded_with_stale_version =
            decode_dynamic_with_version(&captured_body, &desc, CdrVersion::Xcdr2)
                .expect("decode with the pre-fix (wrong) version");
        let corrupted_value: i64 = decoded_with_stale_version
            .get("value")
            .expect("decoded value field");
        assert_ne!(
            corrupted_value, expected_value,
            "XCDR1 bytes decoded as XCDR2 must corrupt the i64 following the string \
             (this is what the router used to hand every subscriber before the fix)"
        );
    }
}

#[cfg(test)]
mod submessage_walk_alignment_tests {
    use super::*;
    use crate::engine::demux::Topic;

    const PID_STATUS_INFO: u16 = 0x0071;
    const PID_KEY_HASH: u16 = 0x0070;
    const PID_SENTINEL: u16 = 0x0001;

    /// 20-octet RTPS header; neither walk inspects it past the guid prefix.
    fn header() -> Vec<u8> {
        let mut v = Vec::with_capacity(20);
        v.extend_from_slice(b"RTPS");
        v.extend_from_slice(&[2, 5, 0x01, 0x1a]);
        v.extend_from_slice(&[0xAAu8; 12]);
        assert_eq!(v.len(), 20, "RTPS header is 20 octets");
        v
    }

    /// Append one little-endian submessage declaring exactly the body it
    /// carries, then pad to the next 4-octet boundary WITHOUT counting the
    /// padding in `octetsToNextHeader`.
    ///
    /// That is a NON-conforming sender: Sec.8.3.3.3.3 counts the field up to
    /// the next submessage header, padding included. It is deliberate here,
    /// because it is exactly the shape the realignment recovers - a
    /// conforming datagram would exercise nothing. The fixture asserts both
    /// invariants, so a drifting builder fails HERE rather than making a test
    /// pass for the wrong reason.
    fn push_submessage(packet: &mut Vec<u8>, id: u8, flags: u8, body: &[u8]) {
        assert_eq!(
            packet.len() % 4,
            0,
            "Sec.9.4.1: submessage headers are 4-byte aligned"
        );
        packet.push(id);
        packet.push(flags | 0x01); // E flag: little-endian
        packet.extend_from_slice(&u16::try_from(body.len()).expect("body fits").to_le_bytes());
        packet.extend_from_slice(body);
        while !packet.len().is_multiple_of(4) {
            packet.push(0x00);
        }
    }

    fn push_parameter(qos: &mut Vec<u8>, pid: u16, value: &[u8]) {
        qos.extend_from_slice(&pid.to_le_bytes());
        qos.extend_from_slice(
            &u16::try_from(value.len())
                .expect("value fits")
                .to_le_bytes(),
        );
        qos.extend_from_slice(value);
        assert_eq!(qos.len() % 4, 0, "a ParameterList entry is 4-octet aligned");
    }

    /// A DATA body carrying one dispose: K and Q flags (0x0A, the inline QoS
    /// is only read under Q, RTPS v2.5 Sec.9.4.5.4), inline QoS with
    /// `StatusInfo` (flags in octet 3 per Sec.9.6.4.9) and a key hash, then
    /// `tail_len` octets of serialized key - the tail is what makes the body
    /// length a NON-multiple of four.
    fn dispose_data_body(key_byte: u8, tail_len: usize) -> Vec<u8> {
        let mut qos = Vec::new();
        push_parameter(&mut qos, PID_STATUS_INFO, &[0x00, 0x00, 0x00, 0x03]);
        push_parameter(&mut qos, PID_KEY_HASH, &[key_byte; 16]);
        push_parameter(&mut qos, PID_SENTINEL, &[]);

        let mut body = Vec::new();
        body.extend_from_slice(&0u16.to_le_bytes()); // extraFlags
        body.extend_from_slice(&16u16.to_le_bytes()); // octetsToInlineQos
        body.extend_from_slice(&[0x00, 0x00, 0x01, 0x07]); // readerEntityId
        body.extend_from_slice(&[0x00, 0x00, 0x01, 0x02]); // writerEntityId
        body.extend_from_slice(&1i32.to_le_bytes()); // writerSN high
        body.extend_from_slice(&1u32.to_le_bytes()); // writerSN low
        assert_eq!(body.len(), 20, "DATA fixed fields are 20 octets");
        body.extend_from_slice(&qos);
        body.extend_from_slice(&vec![0xEE; tail_len]);
        body
    }

    #[test]
    fn a_dispose_behind_a_misaligned_submessage_is_still_delivered() {
        // Several per-instance disposes may share ONE datagram, which is why
        // this walk exists at all. A body whose length is not a multiple of
        // four left the walk 2 octets short of the next header, so every
        // dispose behind it was lost and those instances stayed ALIVE.
        let mut packet = header();
        push_submessage(&mut packet, 0x15, 0x0A, &dispose_data_body(0xA1, 6));
        // 20 + 4 + 58 = 82, padded to 84: a boundary that is a multiple of
        // FOUR and not of eight, so realigning on the wrong power fails here.
        assert_eq!(packet.len(), 84);
        assert_eq!(
            packet.len() % 8,
            4,
            "the next header must discriminate 4 from 8"
        );
        push_submessage(&mut packet, 0x15, 0x0A, &dispose_data_body(0xB2, 0));

        let topic = Topic::new("t".to_string(), None);
        let metrics = RouterMetrics::default();
        assert_eq!(
            deliver_all_disposes_in_datagram(&packet, &topic, &TopicRegistry::new(), &metrics),
            2,
            "both batched disposes must be delivered"
        );
    }

    #[test]
    fn nothing_behind_the_sentinel_is_a_submessage() {
        // Sec.8.3.3.3: octetsToNextHeader == 0 means this submessage is the
        // LAST one and runs to the end of the datagram. What follows is its
        // body, not a header - even when those octets spell a second
        // dispose. Pinned because the realignment above shares this loop and
        // nothing else defended the branch.
        let body = dispose_data_body(0xA1, 0);
        let mut packet = header();
        packet.push(0x15);
        packet.push(0x0A | 0x01);
        packet.extend_from_slice(&0u16.to_le_bytes()); // the sentinel length
        packet.extend_from_slice(&body);
        // A second, well-formed dispose submessage APPENDED behind it.
        push_submessage(&mut packet, 0x15, 0x0A, &dispose_data_body(0xB2, 0));

        let topic = Topic::new("t".to_string(), None);
        let metrics = RouterMetrics::default();
        assert_eq!(
            deliver_all_disposes_in_datagram(&packet, &topic, &TopicRegistry::new(), &metrics),
            1,
            "the sentinel ends the chain; what follows it is body"
        );
    }

    #[test]
    fn a_heartbeat_frag_behind_a_misaligned_submessage_is_still_found() {
        // Without the realignment the walk lands 3 octets short of the
        // HEARTBEAT_FRAG header, reads whatever is there, and the reader
        // never NACKs the fragments it is missing.
        let mut hbf = Vec::new();
        hbf.extend_from_slice(&[0x00, 0x00, 0x01, 0x07]); // readerEntityId
        hbf.extend_from_slice(&[0x00, 0x00, 0x03, 0x02]); // writerEntityId
        hbf.extend_from_slice(&0i32.to_le_bytes()); // writerSN high
        hbf.extend_from_slice(&7u32.to_le_bytes()); // writerSN low
        hbf.extend_from_slice(&4u32.to_le_bytes()); // lastFragmentNum
        hbf.extend_from_slice(&1u32.to_le_bytes()); // count
        assert_eq!(hbf.len(), 24, "HEARTBEAT_FRAG body is 24 octets");

        let mut packet = header();
        push_submessage(&mut packet, 0x09, 0x00, &[0x00; 25]); // INFO_TS, 25 octets
                                                               // 20 + 4 + 25 = 49, padded to 52: again 4-aligned and not 8-aligned.
        assert_eq!(packet.len(), 52);
        assert_eq!(
            packet.len() % 8,
            4,
            "the next header must discriminate 4 from 8"
        );
        push_submessage(&mut packet, 0x13, 0x00, &hbf);

        let found = parse_heartbeat_frag(&packet).expect("the HEARTBEAT_FRAG must be found");
        assert_eq!(found.peer_guid_prefix, [0xAAu8; 12]);
        assert_eq!(found.writer_entity_id, [0x00, 0x00, 0x03, 0x02]);
        assert_eq!(found.writer_sn, 7);
        assert_eq!(found.last_frag, 4);
    }
    /// The datagram on which two of this file's walks disagreed.
    ///
    /// A sender writes a PAD submessage declaring five octets of contents,
    /// then inserts three more so that the next header lands on a 4-octet
    /// boundary - and does NOT count them in octetsToNextHeader. That sender
    /// is NON-CONFORMING: Sec.9.4.5.1.3 defines the field as the octets from
    /// the first octet of the contents "until the first octet of the header of
    /// the next Submessage", padding included, so a conforming sender would
    /// have declared eight. This fixture is constructed for exactly that
    /// reason, and says so rather than pretending to be observed traffic.
    ///
    /// On these bytes every walk must find the DATA at offset 32, after
    /// realigning. A walk that advanced by the declared length alone would
    /// land at 29 in the middle of the padding, read a zero byte as a
    /// submessage id and a length of 21 out of the DATA header, and jump clean
    /// past the end of the datagram - so `count_data_submessages` would report
    /// that this datagram carries NO DATA at all, and it is
    /// `count_data_submessages` that picks the routing path.
    #[test]
    fn the_seven_walks_of_this_file_agree_on_a_sender_that_under_declares_its_padding() {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(b"RTPS");
        pkt.extend_from_slice(&[0x02, 0x05, 0x01, 0x1A]);
        pkt.extend_from_slice(&[0x0A; 12]);
        assert_eq!(pkt.len(), 20);

        // PAD declaring 5, carrying 5 + 3 uncounted octets of padding.
        pkt.extend_from_slice(&[0x01, 0x01]);
        pkt.extend_from_slice(&5u16.to_le_bytes());
        pkt.extend_from_slice(&[0x00; 5]);
        pkt.extend_from_slice(&[0x00; 3]);
        let data_at = pkt.len();
        assert_eq!(data_at, 32, "the real next header sits on the boundary");

        // DATA with the twenty fixed fields and nothing else.
        pkt.extend_from_slice(&[0x15, 0x01]);
        pkt.extend_from_slice(&20u16.to_le_bytes());
        pkt.extend_from_slice(&[0x00; 20]);
        assert_eq!(pkt.len(), 56);

        assert_eq!(
            count_data_submessages(&pkt),
            1,
            "the DATA is there; reporting 0 sent this datagram down the wrong path"
        );
        assert_eq!(
            data_submsg_end_for(&pkt, data_at + 4),
            pkt.len(),
            "the DATA is the last submessage, so its body runs to the end"
        );
        assert_eq!(
            parse_info_ts_ns(&pkt),
            None,
            "no INFO_TS precedes the DATA, and the walk must REACH the DATA to say so"
        );
        assert_eq!(
            parse_heartbeat_frag(&pkt),
            None,
            "no HEARTBEAT_FRAG here, and this walk already realigned"
        );
    }
    /// A DATA followed by a HEARTBEAT in the same datagram: the payload stops
    /// at the DATA.
    ///
    /// This is what `data_submsg_end_for` exists for - a writer may append
    /// a HEARTBEAT to a sample - and it had no fixture. Replacing its
    /// answer with `payload.len()`, which is the defect it was written to
    /// close, left all 3519 tests of this crate green. A function whose whole
    /// purpose is to cut cannot be told apart from one that never cuts.
    #[test]
    fn a_heartbeat_riding_behind_a_data_is_not_part_of_the_sample() {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(b"RTPS");
        pkt.extend_from_slice(&[0x02, 0x05, 0x01, 0x1A]);
        pkt.extend_from_slice(&[0x0A; 12]);

        // DATA: twenty fixed fields then an eight-octet serialized payload.
        let data_at = pkt.len();
        pkt.extend_from_slice(&[0x15, 0x01]);
        pkt.extend_from_slice(&28u16.to_le_bytes());
        pkt.extend_from_slice(&[0x00; 20]);
        pkt.extend_from_slice(&[0xAA; 8]);
        let data_end = pkt.len();
        assert_eq!(data_end, data_at + 4 + 28);

        // HEARTBEAT riding behind it in the same message.
        pkt.extend_from_slice(&[0x07, 0x01]);
        pkt.extend_from_slice(&28u16.to_le_bytes());
        pkt.extend_from_slice(&[0xBB; 28]);
        assert!(pkt.len() > data_end, "the fixture really carries a tail");

        // The serialized payload starts after the DATA's twenty fixed fields.
        let payload_offset = data_at + 4 + 20;
        assert_eq!(
            data_submsg_end_for(&pkt, payload_offset),
            data_end,
            "the sample ends with its own submessage, not with the datagram"
        );
        assert_ne!(
            data_submsg_end_for(&pkt, payload_offset),
            pkt.len(),
            "and the whole point is that those two differ here"
        );

        // Two DATA in one datagram, and the offset belongs to the SECOND.
        // With a single DATA the containment test cannot be told from "the
        // first DATA wins": widening it to accept any offset left the
        // one-DATA fixture green.
        let mut batched = pkt[..data_end].to_vec();
        let second_at = batched.len();
        batched.extend_from_slice(&[0x15, 0x01]);
        batched.extend_from_slice(&28u16.to_le_bytes());
        batched.extend_from_slice(&[0x00; 20]);
        batched.extend_from_slice(&[0xCC; 8]);
        let second_end = batched.len();
        batched.extend_from_slice(&[0x07, 0x01]);
        batched.extend_from_slice(&28u16.to_le_bytes());
        batched.extend_from_slice(&[0xBB; 28]);

        assert_eq!(
            data_submsg_end_for(&batched, second_at + 4 + 20),
            second_end,
            "the second sample ends with the second DATA, not with the first"
        );
        assert_eq!(
            data_submsg_end_for(&batched, data_at + 4 + 20),
            data_end,
            "and the first still ends with the first"
        );
    }
}

#[cfg(test)]
mod data_reaches_the_reader_it_names_tests {
    use super::*;
    use crate::engine::Subscriber;

    type Log = Arc<Mutex<Vec<(&'static str, u64)>>>;

    struct Named(&'static str, Option<[u8; 4]>, Log);

    impl Subscriber for Named {
        fn on_data(&self, _: &str, seq: u64, _: &[u8]) {
            self.2.lock().expect("log").push((self.0, seq));
        }
        fn topic_name(&self) -> &str {
            TOPIC
        }
        fn reader_entity_id(&self) -> Option<[u8; 4]> {
            self.1
        }
        fn on_dropped_before_discovery(&self, _: [u8; 16], seq: u64, _: u64) {
            self.2.lock().expect("log").push(("owed", seq));
        }
    }

    const TOPIC: &str = "NamedData";
    const PREFIX: [u8; 12] = [0x44; 12];
    const WRITER: [u8; 4] = [0x00, 0x00, 0x01, 0x02];
    const A: [u8; 4] = [0x00, 0x00, 0x01, 0x07];
    const B: [u8; 4] = [0x00, 0x00, 0x02, 0x07];
    const UNKNOWN: [u8; 4] = [0x00; 4];
    /// The serialized sample: an XCDR1 encapsulation header, then 4 octets.
    const SAMPLE: [u8; 8] = [0x00, 0x01, 0x00, 0x00, 1, 2, 3, 4];

    fn writer_guid() -> [u8; 16] {
        let mut guid = [0u8; 16];
        guid[..12].copy_from_slice(&PREFIX);
        guid[12..].copy_from_slice(&WRITER);
        guid
    }

    /// A registry with readers `a` (A), `b` (B) and one naming no reader.
    fn readers() -> (Arc<TopicRegistry>, Log) {
        let (registry, log) = readers_of_an_unbound_writer();
        registry.register_writer_guid(writer_guid(), TOPIC.to_string());
        (registry, log)
    }

    /// `readers`, before discovery has bound the writer to the topic.
    fn readers_of_an_unbound_writer() -> (Arc<TopicRegistry>, Log) {
        let registry = Arc::new(TopicRegistry::new());
        registry
            .register_topic(TOPIC.to_string(), None)
            .expect("topic");
        let log: Log = Arc::new(Mutex::new(Vec::new()));
        for (name, id) in [("a", Some(A)), ("b", Some(B)), ("anonymous", None)] {
            registry
                .register_subscriber(Arc::new(Named(name, id, Arc::clone(&log))))
                .expect("subscriber");
        }
        (registry, log)
    }

    fn taken(log: &Log) -> Vec<(&'static str, u64)> {
        let mut seen = std::mem::take(&mut *log.lock().expect("log"));
        seen.sort_unstable();
        seen
    }

    fn header() -> Vec<u8> {
        let mut packet = Vec::new();
        packet.extend_from_slice(b"RTPS");
        packet.extend_from_slice(&[2, 5, 0x01, 0x1a]);
        packet.extend_from_slice(&PREFIX);
        packet
    }

    fn push(packet: &mut Vec<u8>, id: u8, flags: u8, body: &[u8]) {
        assert_eq!(body.len() % 4, 0, "a conforming body, no padding");
        packet.extend_from_slice(&[id, flags | 0x01]);
        packet.extend_from_slice(&u16::try_from(body.len()).expect("fits").to_le_bytes());
        packet.extend_from_slice(body);
    }

    fn data(reader: [u8; 4], seq: u32) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&0u16.to_le_bytes()); // extraFlags
        body.extend_from_slice(&16u16.to_le_bytes()); // octetsToInlineQos
        body.extend_from_slice(&reader);
        body.extend_from_slice(&WRITER);
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&seq.to_le_bytes());
        body.extend_from_slice(&SAMPLE);
        let mut packet = header();
        push(&mut packet, 0x15, 0x04, &body); // DATA, D flag
        packet
    }

    /// One DATA_FRAG submessage body: fragment `frag` of a `sample_size`
    /// sample cut in `fragment_size` pieces, carrying `payload`.
    fn frag_body(
        reader: [u8; 4],
        seq: u32,
        frag: u32,
        fragment_size: u16,
        sample_size: u32,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&0u16.to_le_bytes()); // extraFlags
        body.extend_from_slice(&28u16.to_le_bytes()); // octetsToInlineQos
        body.extend_from_slice(&reader);
        body.extend_from_slice(&WRITER);
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&seq.to_le_bytes());
        body.extend_from_slice(&frag.to_le_bytes()); // fragmentStartingNum
        body.extend_from_slice(&1u16.to_le_bytes()); // fragmentsInSubmessage
        body.extend_from_slice(&fragment_size.to_le_bytes());
        body.extend_from_slice(&sample_size.to_le_bytes());
        body.extend_from_slice(payload);
        body
    }

    /// Fragment `frag` (1 or 2) of the two-fragment `SAMPLE` numbered `seq`.
    fn half(reader: [u8; 4], seq: u32, frag: u32) -> Vec<u8> {
        let piece = if frag == 1 {
            &SAMPLE[..4]
        } else {
            &SAMPLE[4..]
        };
        let mut packet = header();
        push(
            &mut packet,
            0x16,
            0x00,
            &frag_body(reader, seq, frag, 4, 8, piece),
        );
        packet
    }

    #[test]
    fn a_data_reaches_the_reader_its_reader_id_names() {
        let (registry, log) = readers();
        let metrics = RouterMetrics::new();
        let route =
            |packet: &[u8]| route_data_packet(packet, packet.len(), None, &registry, &metrics);

        assert_eq!(route(&data(A, 1)), RouteStatus::Delivered);
        assert_eq!(taken(&log), vec![("a", 1)]);
        assert_eq!(route(&data(B, 2)), RouteStatus::Delivered);
        assert_eq!(taken(&log), vec![("b", 2)]);

        assert_eq!(route(&data(UNKNOWN, 3)), RouteStatus::Delivered);
        assert_eq!(taken(&log), vec![("a", 3), ("anonymous", 3), ("b", 3)]);

        // A reader that is not here: nobody receives it, and it is counted.
        assert_eq!(route(&data([0, 0, 9, 7], 4)), RouteStatus::Orphaned);
        assert!(taken(&log).is_empty());
        assert_eq!(metrics.packets_orphaned.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn a_data_that_stops_before_its_reader_id_is_dropped() {
        let (registry, log) = readers();
        let metrics = RouterMetrics::new();
        let mut packet = header();
        // Four body octets: extraFlags and octetsToInlineQos, no readerId.
        push(&mut packet, 0x15, 0x04, &[0, 0, 16, 0]);
        // A PAD behind it whose body starts with the writer's id: the
        // writer GUID is read against the datagram, so the topic resolves
        // and the DATA reaches the readerId question. Its readerId would be
        // the PAD's own header, a reader that is not here.
        let mut pad = WRITER.to_vec();
        pad.extend_from_slice(&[0; 4]);
        push(&mut packet, 0x01, 0x00, &pad);
        assert_eq!(builder::extract_writer_guid(&packet), Some(writer_guid()));

        let status = route_data_packet(&packet, packet.len(), None, &registry, &metrics);
        assert_eq!(
            status,
            RouteStatus::Dropped,
            "not Orphaned: no readerId was read"
        );
        assert_eq!(metrics.delivery_errors.load(Ordering::Relaxed), 1);
        assert!(taken(&log).is_empty());
    }

    /// A DATA is bound to its topic by its writer's SEDP announcement
    /// (`TopicRegistry::register_writer_guid`), never by a PID_TOPIC_NAME in
    /// its inline QoS: a writer discovery has not bound is not routed by
    /// the topic name it carries. This crate's own writer puts one there.
    #[test]
    fn an_inline_topic_name_does_not_bind_a_data_to_its_topic() {
        let (registry, log) = readers_of_an_unbound_writer();
        let metrics = RouterMetrics::new();
        let context = builder::RtpsEndpointContext {
            guid_prefix: PREFIX,
            reader_entity_id: UNKNOWN,
            writer_entity_id: WRITER,
            encapsulation_kind: 0x0007,
            publisher_entity_id: [0, 0, 0x01, 0x08],
        };
        let packet = builder::build_data_packet_with_context(
            &context,
            TOPIC,
            1,
            &[1, 2, 3, 4],
            crate::dds::CdrVersion::Xcdr2,
        );
        // The inline QoS opens with PID_TOPIC_NAME (0x0005) naming TOPIC.
        let (qos, is_le) = builder::extract_inline_qos(&packet).expect("inline QoS");
        assert!(is_le);
        assert_eq!(&qos[..2], &[0x05, 0x00]);
        let len = u32::from_le_bytes([qos[4], qos[5], qos[6], qos[7]]) as usize;
        assert_eq!(&qos[8..8 + len - 1], TOPIC.as_bytes());

        assert_eq!(
            route_data_packet(&packet, packet.len(), None, &registry, &metrics),
            RouteStatus::Dropped
        );
        assert!(taken(&log).iter().all(|(name, _)| *name == "owed"));
        registry.register_writer_guid(writer_guid(), TOPIC.to_string());
        let _ = taken(&log);
        assert_eq!(
            route_data_packet(&packet, packet.len(), None, &registry, &metrics),
            RouteStatus::Delivered
        );
        assert_eq!(taken(&log), vec![("a", 1), ("anonymous", 1), ("b", 1)]);
    }

    /// A fragmented sample of a writer discovery has not bound yet is
    /// dropped once reassembled; sent to every reader, it is owed to the
    /// topic's readers when the writer is bound, from the lowest dropped.
    /// Sent to a named reader only, it is owed to nobody else.
    #[test]
    fn a_reassembled_sample_dropped_before_its_writer_is_bound_is_owed_once_it_is() {
        let (registry, log) = readers_of_an_unbound_writer();
        let metrics = RouterMetrics::new();
        let buffer = Mutex::new(FragmentBuffer::new(16, 1_000));
        let route = |packet: &[u8]| {
            route_data_frag_packet(
                packet,
                packet.len(),
                None,
                None,
                &buffer,
                &registry,
                &metrics,
            )
        };
        route(&half(A, 1, 1));
        assert_eq!(route(&half(A, 1, 2)), RouteStatus::Dropped);
        assert_eq!(registry.dropped_before_discovery_count(), 0, "sent to A");
        for seq in [3, 2] {
            route(&half(UNKNOWN, seq, 1));
            assert_eq!(route(&half(UNKNOWN, seq, 2)), RouteStatus::Dropped);
        }
        assert_eq!(registry.dropped_before_discovery_count(), 1);
        assert!(taken(&log).is_empty());
        registry.register_writer_guid(writer_guid(), TOPIC.to_string());
        assert_eq!(
            taken(&log),
            vec![("owed", 2), ("owed", 2), ("owed", 2)],
            "every reader of the topic, from the lowest"
        );
        assert_eq!(registry.dropped_before_discovery_count(), 0);
    }

    #[test]
    fn a_reassembled_sample_reaches_the_readers_its_fragments_were_sent_to() {
        let (registry, log) = readers();
        let metrics = RouterMetrics::new();
        let buffer = Mutex::new(FragmentBuffer::new(16, 1_000));
        let route = |packet: &[u8]| {
            route_data_frag_packet(
                packet,
                packet.len(),
                None,
                None,
                &buffer,
                &registry,
                &metrics,
            )
        };

        // Both fragments sent to A.
        route(&half(A, 1, 1));
        route(&half(A, 1, 2));
        assert_eq!(taken(&log), vec![("a", 1)]);

        // One sent to A, one to B: the sample was sent to both.
        route(&half(A, 2, 1));
        route(&half(B, 2, 2));
        assert_eq!(taken(&log), vec![("a", 2), ("b", 2)]);

        // One of them to every reader: every reader.
        route(&half(A, 3, 1));
        route(&half(UNKNOWN, 3, 2));
        assert_eq!(taken(&log), vec![("a", 3), ("anonymous", 3), ("b", 3)]);

        // Sent to a reader that is not here: nobody, counted.
        route(&half([0, 0, 9, 7], 4, 1));
        assert_eq!(
            route(&half([0, 0, 9, 7], 4, 2)),
            RouteStatus::Orphaned,
            "the completing fragment reports where its sample went"
        );
        assert!(taken(&log).is_empty());
        assert_eq!(metrics.packets_orphaned.load(Ordering::Relaxed), 1);
    }

    /// An idle router publishes its parks, and a spin that found nothing
    /// before a park is a miss whose time is counted as wasted.
    #[test]
    fn an_idle_router_counts_its_parks_and_missed_spins() {
        let pool = Arc::new(RxPool::new(4, 256).expect("pool"));
        let ring = Arc::new(ArrayQueue::new(8));
        let registry = Arc::new(TopicRegistry::new());
        let router = Router::start(ring, pool, registry).expect("router");
        let metrics = Arc::clone(&router.metrics);
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while metrics.parks.load(Ordering::Relaxed) < 2 && std::time::Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
        }
        router.stop().expect("router stop");
        let parks = metrics.parks.load(Ordering::Relaxed);
        let misses = metrics.spin_misses.load(Ordering::Relaxed);
        let wasted = metrics.spin_ns_wasted.load(Ordering::Relaxed);
        assert!(parks >= 2, "an idle router parks, got {parks}");
        assert_eq!(
            metrics.spin_hits.load(Ordering::Relaxed),
            0,
            "nothing to pop"
        );
        assert!(misses <= parks, "every miss is followed by a park");
        assert_eq!(misses == 0, wasted == 0, "a miss is wasted time");
    }

    #[test]
    fn the_router_loop_delivers_every_sample_a_datagram_completes() {
        let (registry, log) = readers();
        // Two one-fragment samples in one datagram, both sent to A.
        let mut packet = header();
        push(&mut packet, 0x16, 0x00, &frag_body(A, 1, 1, 8, 8, &SAMPLE));
        push(&mut packet, 0x16, 0x00, &frag_body(A, 2, 1, 8, 8, &SAMPLE));

        let mut pool = RxPool::new(4, 256).expect("pool");
        let buffer_id = pool.acquire_for_listener().expect("a buffer");
        pool.get_buffer_mut(buffer_id)[..packet.len()].copy_from_slice(&packet);
        let pool = Arc::new(pool);
        let ring = Arc::new(ArrayQueue::new(8));
        let router = Router::start(Arc::clone(&ring), Arc::clone(&pool), Arc::clone(&registry))
            .expect("router");
        let meta = RxMeta::new(
            Origin::direct("127.0.0.1:7400".parse().expect("address")),
            packet.len(),
            PacketKind::DataFrag,
        );
        ring.push((meta, buffer_id)).expect("ring room");

        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while log.lock().expect("log").len() < 2 && std::time::Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
        }
        router.stop().expect("router stop");
        assert_eq!(taken(&log), vec![("a", 1), ("a", 2)]);
    }

    /// Our own fragments, looped back by multicast, are not reassembled:
    /// the router knows its own GUID prefix. The same datagram from another
    /// participant is delivered (the test above).
    #[test]
    fn the_router_loop_drops_its_own_fragments() {
        let (registry, log) = readers();
        let mut packet = header();
        push(&mut packet, 0x16, 0x00, &frag_body(A, 1, 1, 8, 8, &SAMPLE));

        let run = |our_prefix: [u8; 12]| {
            let mut pool = RxPool::new(4, 256).expect("pool");
            let buffer_id = pool.acquire_for_listener().expect("a buffer");
            pool.get_buffer_mut(buffer_id)[..packet.len()].copy_from_slice(&packet);
            let pool = Arc::new(pool);
            let ring = Arc::new(ArrayQueue::new(8));
            let router = Router::start_with_transport(
                Arc::clone(&ring),
                Arc::clone(&pool),
                Arc::clone(&registry),
                None,
                our_prefix,
            )
            .expect("router");
            let meta = RxMeta::new(
                Origin::direct("127.0.0.1:7400".parse().expect("address")),
                packet.len(),
                PacketKind::DataFrag,
            );
            ring.push((meta, buffer_id)).expect("ring room");
            let deadline = std::time::Instant::now() + Duration::from_millis(500);
            while log.lock().expect("log").is_empty() && std::time::Instant::now() < deadline {
                thread::sleep(Duration::from_millis(5));
            }
            router.stop().expect("router stop");
            taken(&log)
        };

        assert_eq!(run(PREFIX), vec![], "sent by this participant");
        assert_eq!(run([0x45; 12]), vec![("a", 1)], "sent by another one");
    }

    #[test]
    fn a_missing_fragment_is_requested_once_under_the_name_of_a_reader_it_is_for() {
        let lease = crate::test_support::domains::unique_domain();
        let mapping = crate::transport::PortMapping::calculate(lease.id(), 0).expect("mapping");
        let transport =
            crate::transport::UdpTransport::new(lease.id(), 0, mapping).expect("transport");
        let writer = GUID::from_bytes(writer_guid());
        let named = |id: [u8; 4]| {
            let mut guid = [0x55u8; 16];
            guid[12..].copy_from_slice(&id);
            guid
        };
        let proxies = ReaderProxyRegistry::new();
        let metrics = RouterMetrics::new();
        let peer = std::net::UdpSocket::bind("127.0.0.1:0").expect("peer socket");
        peer.set_read_timeout(Some(Duration::from_millis(500)))
            .expect("timeout");
        let emitter = NackFragEmitter {
            transport: &transport,
            our_guid_prefix: [0x55; 12],
            endpoint_registry: None,
            reader_proxies: &proxies,
            metrics: &metrics,
        };
        let dest = peer.local_addr().expect("address");
        let mut count = 1;
        let mut datagram = [0u8; 256];
        let mut requester = || {
            let len = peer.recv(&mut datagram).ok()?;
            let mut reader = None;
            walk::for_each_submessage(&datagram[..len], |found| {
                if found.id == 0x12 {
                    let at = found.offset + 4;
                    assert_eq!(&datagram[at + 4..at + 8], &WRITER, "writerId");
                    reader = <[u8; 4]>::try_from(&datagram[at..at + 4]).ok();
                }
                walk::Step::Continue
            });
            reader
        };

        // No reader here is matched with the writer: nobody asks.
        assert!(!emitter.request(
            &writer,
            7,
            &[2],
            false,
            Origin::direct(dest),
            &mut count,
            |_| true
        ));
        assert_eq!(requester(), None);

        proxies.match_writer(writer_guid(), named(A));
        proxies.match_writer(writer_guid(), named(B));
        // Matched, but the sample is not for them: nobody asks.
        assert!(!emitter.request(
            &writer,
            7,
            &[2],
            false,
            Origin::direct(dest),
            &mut count,
            |_| false
        ));
        assert_eq!(requester(), None);
        // For B only: one request, in B's name.
        assert!(emitter.request(
            &writer,
            7,
            &[2],
            false,
            Origin::direct(dest),
            &mut count,
            |r| r == B
        ));
        assert_eq!(requester(), Some(B));
        assert_eq!(requester(), None, "once, not once per reader");
        // For both: still one request.
        assert!(emitter.request(
            &writer,
            7,
            &[2],
            false,
            Origin::direct(dest),
            &mut count,
            |_| true
        ));
        assert_eq!(requester(), Some(A));
        assert_eq!(requester(), None, "once, not once per reader");
        // A holds seq 7 already: it would be answered with a GAP. B asks.
        proxies.on_data_for(&writer_guid(), &named(A), 7);
        assert!(emitter.request(
            &writer,
            7,
            &[2],
            false,
            Origin::direct(dest),
            &mut count,
            |_| true
        ));
        assert_eq!(requester(), Some(B));
        assert_eq!(metrics.nack_frag_requests.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn the_router_loop_delivers_each_readers_copy_of_a_sample() {
        // A writer sends one copy of a sample per matched reader; two
        // readers of this participant receive two datagrams with the same
        // writer and sequence number. Neither is a duplicate of the other.
        let (registry, log) = readers();
        // Then a copy to every reader, and one named to b behind it: not a
        // duplicate at this door (the reader it names may have arrived since
        // the first; b's own duplicate window drops it).
        let copies = [data(A, 9), data(B, 9), data(UNKNOWN, 10), data(B, 10)];

        let mut pool = RxPool::new(4, 256).expect("pool");
        let mut queued = Vec::new();
        for copy in &copies {
            let buffer_id = pool.acquire_for_listener().expect("a buffer");
            pool.get_buffer_mut(buffer_id)[..copy.len()].copy_from_slice(copy);
            queued.push((buffer_id, copy.len()));
        }
        let pool = Arc::new(pool);
        let ring = Arc::new(ArrayQueue::new(8));
        let router = Router::start(Arc::clone(&ring), Arc::clone(&pool), Arc::clone(&registry))
            .expect("router");
        for (buffer_id, len) in queued {
            let meta = RxMeta::new(
                Origin::direct("127.0.0.1:7400".parse().expect("address")),
                len,
                PacketKind::Data,
            );
            ring.push((meta, buffer_id)).expect("ring room");
        }

        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while log.lock().expect("log").len() < 6 && std::time::Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
        }
        // Past the last datagram: a seventh delivery would show here.
        thread::sleep(Duration::from_millis(50));
        router.stop().expect("router stop");
        assert_eq!(
            taken(&log),
            vec![
                ("a", 9),
                ("a", 10),
                ("anonymous", 10),
                ("b", 9),
                ("b", 10),
                ("b", 10)
            ]
        );
    }

    #[test]
    fn the_classifier_fallback_door_honours_the_reader_id() {
        // DATA_FRAGs the scan declines (their submessages hold no payload),
        // so the router falls back on the classifier's metadata and the
        // payload offset it was handed - here, the body of the PAD behind.
        // The metadata names the SECOND DATA_FRAG, sent to b: the readerId
        // is that one's, not the datagram's first.
        let (registry, log) = readers();
        let metrics = RouterMetrics::new();
        let buffer = Mutex::new(FragmentBuffer::new(16, 1_000));
        let mut packet = header();
        push(&mut packet, 0x16, 0x00, &frag_body(A, 5, 1, 8, 8, &[]));
        push(&mut packet, 0x16, 0x00, &frag_body(B, 6, 1, 8, 8, &[]));
        push(&mut packet, 0x16, 0x00, &frag_body(A, 6, 2, 8, 16, &[]));
        // The same fragment twice: the classifier keeps the last, b's.
        push(&mut packet, 0x16, 0x00, &frag_body(A, 7, 1, 8, 8, &[]));
        push(&mut packet, 0x16, 0x00, &frag_body(B, 7, 1, 8, 8, &[]));
        let pad_body_at = packet.len() + 4;
        push(&mut packet, 0x01, 0x00, &SAMPLE);
        assert!(
            crate::core::discovery::multicast::scan_all_data_frags(&packet).is_empty(),
            "the fixture must reach the fallback"
        );
        let meta = |seq_num, frag_num, sample_size| FragmentMetadata {
            writer_guid: GUID::from_bytes(writer_guid()),
            seq_num,
            frag_num,
            geometry: crate::core::discovery::multicast::FragmentGeometry {
                fragment_size: 8,
                sample_size,
            },
        };
        let route = |meta: &FragmentMetadata| {
            route_data_frag_packet(
                &packet,
                packet.len(),
                Some(pad_body_at),
                Some(meta),
                &buffer,
                &registry,
                &metrics,
            )
        };
        assert_eq!(route(&meta(6, 1, 8)), RouteStatus::Delivered);
        assert_eq!(taken(&log), vec![("b", 6)]);
        assert_eq!(route(&meta(5, 1, 8)), RouteStatus::Delivered);
        assert_eq!(taken(&log), vec![("a", 5)]);
        assert_eq!(route(&meta(7, 1, 8)), RouteStatus::Delivered);
        assert_eq!(taken(&log), vec![("b", 7)]);
        // Metadata no DATA_FRAG of the datagram carries: dropped.
        assert_eq!(route(&meta(9, 1, 8)), RouteStatus::Dropped);
    }

    #[test]
    fn a_reader_created_while_a_sample_is_in_fragments_does_not_receive_it() {
        // The first fragment of seq 6 reaches every reader then: a, b and the
        // unnamed one. A reader created before the second fragment was not
        // matched when the sample was written.
        let (registry, log) = readers();
        let metrics = RouterMetrics::new();
        let buffer = Mutex::new(FragmentBuffer::new(16, 1_000));
        let route = |packet: &[u8]| {
            route_data_frag_packet(
                packet,
                packet.len(),
                None,
                None,
                &buffer,
                &registry,
                &metrics,
            )
        };
        route(&half(UNKNOWN, 6, 1));
        registry
            .register_subscriber(Arc::new(Named(
                "late",
                Some([0, 0, 3, 7]),
                Arc::clone(&log),
            )))
            .expect("subscriber");
        // Completed by a copy named to b, as a replay or repair would be.
        route(&half(B, 6, 2));
        assert_eq!(taken(&log), vec![("a", 6), ("anonymous", 6), ("b", 6)]);

        // A sample that opens after it was created reaches it.
        route(&half(UNKNOWN, 7, 1));
        route(&half(UNKNOWN, 7, 2));
        assert_eq!(
            taken(&log),
            vec![("a", 7), ("anonymous", 7), ("b", 7), ("late", 7)]
        );
    }

    #[test]
    fn an_rtpx_datagram_is_read_like_an_rtps_one() {
        // The classifier accepts "RTPX"; the fragment scan and the
        // HEARTBEAT_FRAG parser must too, or they disagree on the datagram.
        let mut packet = header();
        push(&mut packet, 0x16, 0x00, &frag_body(A, 1, 1, 8, 8, &SAMPLE));
        push(&mut packet, 0x16, 0x00, &frag_body(A, 2, 1, 8, 8, &SAMPLE));
        packet[..4].copy_from_slice(b"RTPX");
        assert_eq!(scan_all_addressed_data_frags_with_qos(&packet).len(), 2);

        let mut body = Vec::new();
        body.extend_from_slice(&A);
        body.extend_from_slice(&WRITER);
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&3u32.to_le_bytes()); // writerSN
        body.extend_from_slice(&4u32.to_le_bytes()); // lastFragmentNum
        body.extend_from_slice(&1u32.to_le_bytes()); // count
        let mut heartbeat = header();
        push(&mut heartbeat, 0x13, 0x00, &body);
        heartbeat[..4].copy_from_slice(b"RTPX");
        let found = parse_heartbeat_frag(&heartbeat).expect("an RTPX HEARTBEAT_FRAG");
        assert_eq!(found.reader_entity_id, A, "and it names its reader");
        assert_eq!((found.writer_sn, found.last_frag), (3, 4));
    }

    #[test]
    fn the_local_readers_are_the_writers_topic_s_once_it_is_known() {
        struct Other;
        impl Subscriber for Other {
            fn on_data(&self, _: &str, _: u64, _: &[u8]) {}
            fn topic_name(&self) -> &str {
                "AnotherTopic"
            }
            fn reader_entity_id(&self) -> Option<[u8; 4]> {
                Some([0, 0, 9, 7])
            }
        }
        let (registry, _log) = readers();
        registry
            .register_subscriber(Arc::new(Other))
            .expect("subscriber");
        let mut ids = registry.local_reader_ids(&writer_guid());
        ids.sort_unstable();
        assert_eq!(ids, vec![A, B], "the writer's topic only");
        // A writer not known yet: every reader here, until the mapping.
        let mut ids = registry.local_reader_ids(&[0x99; 16]);
        ids.sort_unstable();
        assert_eq!(ids, vec![A, B, [0, 0, 9, 7]]);
    }

    /// A NACK_FRAG leaves in the name of a reader the pending sample is for:
    /// the timer path asks the sequence's audience, the HEARTBEAT_FRAG path
    /// the reader the HEARTBEAT_FRAG informs when nothing is pending.
    #[test]
    fn a_fragment_request_speaks_for_a_reader_the_sample_is_for() {
        let lease = crate::test_support::domains::unique_domain();
        let mapping = crate::transport::PortMapping::calculate(lease.id(), 0).expect("mapping");
        let transport =
            crate::transport::UdpTransport::new(lease.id(), 0, mapping).expect("transport");
        let named = |id: [u8; 4]| {
            let mut guid = [0x55u8; 16];
            guid[12..].copy_from_slice(&id);
            guid
        };
        let proxies = ReaderProxyRegistry::new();
        proxies.match_writer(writer_guid(), named(A));
        proxies.match_writer(writer_guid(), named(B));
        let metrics = RouterMetrics::new();
        let peer = std::net::UdpSocket::bind("127.0.0.1:0").expect("peer socket");
        peer.set_read_timeout(Some(Duration::from_millis(500)))
            .expect("timeout");
        let src = peer.local_addr().expect("address");
        let emitter = NackFragEmitter {
            transport: &transport,
            our_guid_prefix: [0x55; 12],
            endpoint_registry: None,
            reader_proxies: &proxies,
            metrics: &metrics,
        };
        let mut datagram = [0u8; 256];
        let mut requester = || {
            let len = peer.recv(&mut datagram).ok()?;
            let mut reader = None;
            walk::for_each_submessage(&datagram[..len], |found| {
                if found.id == 0x12 {
                    let at = found.offset + 4;
                    reader = <[u8; 4]>::try_from(&datagram[at..at + 4]).ok();
                }
                walk::Step::Continue
            });
            reader
        };
        let mut count = 1;

        // Timer path: fragment 1 of 2 of seq 3, sent to b, gone stale.
        let buffer = Mutex::new(FragmentBuffer::new(16, 60_000));
        lock_fragment_buffer(&buffer).insert_addressed_fragment(
            GUID::from_bytes(writer_guid()),
            3,
            1,
            crate::core::discovery::multicast::FragmentGeometry {
                fragment_size: 4,
                sample_size: 8,
            },
            SAMPLE[..4].to_vec(),
            Some(Origin::direct(src)),
            B,
            || vec![A, B],
        );
        thread::sleep(Duration::from_millis(NACK_FRAG_STALE_THRESHOLD_MS + 50));
        check_stale_fragments_with_transport(
            &buffer,
            &metrics,
            Some(&emitter),
            &mut count,
            &std::collections::HashMap::new(),
        );
        assert_eq!(requester(), Some(B), "the sample was sent to b");

        // HEARTBEAT_FRAG path, nothing pending for seq 9: its readerId.
        let mut body = Vec::new();
        body.extend_from_slice(&B);
        body.extend_from_slice(&WRITER);
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&9u32.to_le_bytes()); // writerSN
        body.extend_from_slice(&2u32.to_le_bytes()); // lastFragmentNum
        body.extend_from_slice(&1u32.to_le_bytes()); // count
        let mut heartbeat = header();
        push(&mut heartbeat, 0x13, 0x00, &body);
        // Past the buffer's global spacing between two approved requests.
        thread::sleep(Duration::from_millis(20));
        handle_heartbeat_frag(
            &heartbeat,
            Origin::direct(src),
            &buffer,
            &emitter,
            &mut count,
        );
        assert_eq!(requester(), Some(B), "the HEARTBEAT_FRAG informs b");
    }
}

/// A key-only (K flag) dispose or unregister is a change of its writer like
/// any other, with its own writerSN (RTPS v2.5 Sec.8.3.8.2, Sec.8.7.4), and
/// it is read from its own submessage only (Sec.9.4.5.1.3).
#[cfg(test)]
mod key_only_dispose_sequence_tests {
    use super::*;
    use crate::engine::subscriber::DisposeKind;
    use crate::engine::Subscriber;

    const PID_SENTINEL: u16 = 0x0001;
    const PID_KEY_HASH: u16 = 0x0070;
    const PID_STATUS_INFO: u16 = 0x0071;
    const TOPIC: &str = "KeyOnlyDisposeTopic";
    const WRITER_GUID: [u8; 16] = [
        0x01, 0x03, 0x4b, 0x7d, 0x04, 0xd6, 0x00, 0x0e, 0x5c, 0x5d, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x02,
    ];

    type Dispose = (u64, [u8; 16], DisposeKind);
    /// A lifecycle change's tags: (seq, PID_COHERENT_SET, group set).
    type CoherentTags = (u64, Option<u64>, Option<u64>);

    struct DisposeProbe {
        disposes: Mutex<Vec<Dispose>>,
        /// The coherent tags each lifecycle change of a set came with
        /// (`on_lifecycle_coherent`): (seq, PID_COHERENT_SET, group set).
        coherent: Mutex<Vec<CoherentTags>>,
        /// The writer each dispose was delivered under, `None` when it came
        /// without one.
        writers: Mutex<Vec<Option<[u8; 16]>>>,
    }

    impl Subscriber for DisposeProbe {
        fn on_data(&self, _topic: &str, _seq: u64, _data: &[u8]) {}

        fn on_dispose(&self, _topic: &str, seq: u64, key_hash: [u8; 16], kind: DisposeKind) {
            self.disposes
                .lock()
                .expect("probe lock")
                .push((seq, key_hash, kind));
            self.writers.lock().expect("probe lock").push(None);
        }

        fn on_dispose_from_writer(
            &self,
            _topic: &str,
            writer_guid: [u8; 16],
            seq: u64,
            key_hash: [u8; 16],
            kind: DisposeKind,
        ) {
            self.disposes
                .lock()
                .expect("probe lock")
                .push((seq, key_hash, kind));
            self.writers
                .lock()
                .expect("probe lock")
                .push(Some(writer_guid));
        }

        fn on_lifecycle_coherent(
            &self,
            topic: &str,
            writer_guid: [u8; 16],
            seq: u64,
            key_hash: [u8; 16],
            kind: DisposeKind,
            coherent_sn: Option<u64>,
            group_sn: Option<u64>,
            _publisher_entity_id: Option<[u8; 4]>,
        ) {
            // As the trait's default does, an untagged change is the plain
            // dispose it is; only a change carrying a set tag is recorded
            // as a member of that set.
            if coherent_sn.is_none() && group_sn.is_none() {
                self.on_dispose_from_writer(topic, writer_guid, seq, key_hash, kind);
                return;
            }
            self.coherent
                .lock()
                .expect("probe lock")
                .push((seq, coherent_sn, group_sn));
        }

        /// A reader of a type keyed by one string: reads a CDR_LE string
        /// key, which ends its payload (up to three bytes of padding), and
        /// names it by [`short_string_hash`].
        fn instance_of_key_payload(&self, payload: &[u8]) -> Option<[u8; 16]> {
            if payload.get(..4)? != [0x00, 0x01, 0x00, 0x00] {
                return None;
            }
            let len =
                usize::try_from(u32::from_le_bytes(payload.get(4..8)?.try_into().ok()?)).ok()?;
            let text = payload.get(8..8 + len)?;
            if payload.len() - (8 + len) > 3 || text.last() != Some(&0) {
                return None;
            }
            let s = std::str::from_utf8(&text[..len - 1]).ok()?;
            (s.len() <= 11).then(|| short_string_hash(s))
        }

        fn topic_name(&self) -> &str {
            TOPIC
        }
    }

    fn new_probe() -> Arc<DisposeProbe> {
        Arc::new(DisposeProbe {
            disposes: Mutex::new(Vec::new()),
            coherent: Mutex::new(Vec::new()),
            writers: Mutex::new(Vec::new()),
        })
    }

    fn header() -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(b"RTPS");
        v.extend_from_slice(&[2, 5, 0x01, 0x03]);
        v.extend_from_slice(&WRITER_GUID[..12]);
        v
    }

    fn u16_in(v: u16, le: bool) -> [u8; 2] {
        if le {
            v.to_le_bytes()
        } else {
            v.to_be_bytes()
        }
    }

    fn u32_in(v: u32, le: bool) -> [u8; 4] {
        if le {
            v.to_le_bytes()
        } else {
            v.to_be_bytes()
        }
    }

    fn parameter(out: &mut Vec<u8>, pid: u16, value: &[u8], le: bool) {
        out.extend_from_slice(&u16_in(pid, le));
        out.extend_from_slice(&u16_in(u16::try_from(value.len()).expect("fits"), le));
        out.extend_from_slice(value);
        assert_eq!(out.len() % 4, 0, "a ParameterList entry is 4-octet aligned");
    }

    /// The body of a key-only DATA (Sec.9.4.5.3: D=0 K=1 Q=1): readerId
    /// ENTITYID_UNKNOWN, the writer's entity id, `sn`, an inline QoS of
    /// StatusInfo (flags in the last octet, Sec.9.6.4.9) and optionally a
    /// KeyHash (Sec.9.6.4.8), the sentinel unless `sentinel` is false, then
    /// `key`, the serialized key.
    fn key_only_body(
        sn: u64,
        status: u8,
        key_hash: Option<[u8; 16]>,
        sentinel: bool,
        key: &[u8],
        le: bool,
    ) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0, 0]); // extraFlags
        body.extend_from_slice(&u16_in(16, le)); // octetsToInlineQos
        body.extend_from_slice(&[0, 0, 0, 0]); // readerId: ENTITYID_UNKNOWN
        body.extend_from_slice(&WRITER_GUID[12..]);
        body.extend_from_slice(&u32_in(u32::try_from(sn >> 32).expect("high"), le));
        body.extend_from_slice(&u32_in(u32::try_from(sn & 0xFFFF_FFFF).expect("low"), le));
        assert_eq!(body.len(), 20);
        parameter(&mut body, PID_STATUS_INFO, &[0, 0, 0, status], le);
        if let Some(kh) = key_hash {
            parameter(&mut body, PID_KEY_HASH, &kh, le);
        }
        if sentinel {
            parameter(&mut body, PID_SENTINEL, &[], le);
        }
        body.extend_from_slice(key);
        body
    }

    /// One submessage whose octetsToNextHeader counts exactly its body
    /// (a conforming sender; every body here is 4-octet aligned).
    fn push_submessage(packet: &mut Vec<u8>, id: u8, flags: u8, body: &[u8]) {
        assert_eq!(
            body.len() % 4,
            0,
            "conforming bodies keep the next header aligned"
        );
        let le = flags & 0x01 != 0;
        packet.push(id);
        packet.push(flags);
        packet.extend_from_slice(&u16_in(u16::try_from(body.len()).expect("fits"), le));
        packet.extend_from_slice(body);
    }

    /// CDR_LE encapsulation of a key whose single member is the string `s`.
    fn string_key(s: &str) -> Vec<u8> {
        let mut key = vec![0x00, 0x01, 0x00, 0x00];
        key.extend_from_slice(&u32::try_from(s.len() + 1).expect("fits").to_le_bytes());
        key.extend_from_slice(s.as_bytes());
        key.push(0);
        while !key.len().is_multiple_of(4) {
            key.push(0);
        }
        key
    }

    /// The KeyHash of a string key whose bound keeps it padded: the
    /// big-endian length then the characters, zero-padded (what the probe's
    /// type names a string key by).
    fn short_string_hash(s: &str) -> [u8; 16] {
        let mut kh = [0u8; 16];
        kh[..4].copy_from_slice(&u32::try_from(s.len() + 1).expect("fits").to_be_bytes());
        kh[4..4 + s.len()].copy_from_slice(s.as_bytes());
        kh
    }

    fn route(packet: &[u8], probe: &Arc<DisposeProbe>) -> RouteStatus {
        let registry = TopicRegistry::new();
        registry
            .register_subscriber(probe.clone())
            .expect("register subscriber");
        registry.register_writer_guid(WRITER_GUID, TOPIC.to_string());
        route_data_packet(packet, packet.len(), None, &registry, &RouterMetrics::new())
    }

    /// A key-only dispose that carries PID_COHERENT_SET (RTPS v2.5
    /// Sec.8.7.6: a change of the set, like every change between begin and
    /// end_coherent_changes) reaches its subscribers as a member of that set
    /// (`on_lifecycle_coherent`), with the set's first sequence number;
    /// taken as an untagged dispose, it ended the set in its middle. One
    /// without the tag is the plain dispose it was.
    #[test]
    fn a_k_flag_dispose_tagged_with_its_set_is_a_member_of_it() {
        const PID_COHERENT_SET: u16 = 0x0056;
        for le in [true, false] {
            let mut body = key_only_body(12, 0x01, Some([0xC1; 16]), false, &[], le);
            // The set started at 10: SequenceNumber_t {high, low}.
            let mut sn = Vec::new();
            sn.extend_from_slice(&u32_in(0, le));
            sn.extend_from_slice(&u32_in(10, le));
            parameter(&mut body, PID_COHERENT_SET, &sn, le);
            parameter(&mut body, PID_SENTINEL, &[], le);
            let mut packet = header();
            push_submessage(&mut packet, 0x15, if le { 0x0b } else { 0x0a }, &body);
            let probe = new_probe();
            assert_eq!(route(&packet, &probe), RouteStatus::Delivered);
            assert_eq!(
                probe.coherent.lock().expect("probe lock").clone(),
                vec![(12, Some(10), None)],
                "le={le}"
            );
            assert!(
                probe.disposes.lock().expect("probe lock").is_empty(),
                "le={le}: not delivered as a dispose of no set"
            );
        }
        let mut packet = header();
        let body = key_only_body(13, 0x01, Some([0xC1; 16]), true, &[], true);
        push_submessage(&mut packet, 0x15, 0x0b, &body);
        let probe = new_probe();
        assert_eq!(route(&packet, &probe), RouteStatus::Delivered);
        assert!(probe.coherent.lock().expect("probe lock").is_empty());
        assert_eq!(probe.disposes.lock().expect("probe lock").len(), 1);
    }

    /// What an HDDS writer emits for a dispose inside a coherent set (the
    /// writer's own builder, TOPIC then GROUP scope) reaches the reader as a
    /// member of the set, with the tags it was written with.
    #[test]
    fn a_dispose_our_writer_tags_reaches_the_reader_as_a_set_member() {
        let mut prefix = [0u8; 12];
        prefix.copy_from_slice(&WRITER_GUID[..12]);
        let mut writer_entity_id = [0u8; 4];
        writer_entity_id.copy_from_slice(&WRITER_GUID[12..]);
        let ctx = crate::protocol::builder::RtpsEndpointContext {
            guid_prefix: prefix,
            reader_entity_id: [0, 0, 0, 0],
            writer_entity_id,
            encapsulation_kind: 0x0007,
            publisher_entity_id: [0x00, 0x00, 0x01, 0x08],
        };
        for (group_sn, expected) in [
            (None, (21, Some(20), None)),
            (Some(5), (21, Some(20), Some(5))),
        ] {
            let packet = crate::protocol::builder::build_dispose_packet_with_context_coherent_ts(
                &ctx,
                TOPIC,
                21,
                &[0xC1; 16],
                &[],
                crate::protocol::builder::StatusInfoKind::Disposed,
                crate::dds::CdrVersion::Xcdr2,
                (0, 0),
                Some(20),
                group_sn,
                None,
                false,
            );
            let probe = new_probe();
            assert_eq!(route(&packet, &probe), RouteStatus::Delivered);
            assert_eq!(
                probe.coherent.lock().expect("probe lock").clone(),
                vec![expected],
                "group_sn={group_sn:?}"
            );
            assert!(probe.disposes.lock().expect("probe lock").is_empty());
        }
    }

    #[test]
    fn a_k_flag_dispose_keeps_its_sequence_number() {
        // K flag, StatusInfo, no KeyHash, the key serialized.
        let mut packet = header();
        let body = key_only_body(11, 0x01, None, true, &string_key("RED"), true);
        push_submessage(&mut packet, 0x15, 0x0b, &body);
        assert_eq!(builder::extract_sequence_number(&packet), Some(11));

        let probe = new_probe();
        assert_eq!(route(&packet, &probe), RouteStatus::Delivered);
        let disposes = probe.disposes.lock().expect("probe lock").clone();
        assert_eq!(disposes.len(), 1, "one dispose: {disposes:?}");
        let (seq, kh, kind) = disposes[0];
        assert_eq!(seq, 11, "the dispose is the writer's change 11, not 0");
        assert_eq!(kh, short_string_hash("RED"));
        assert_eq!(&kh[4..8], b"RED\0");
        assert_eq!(kind, DisposeKind::Disposed);
    }

    #[test]
    fn two_k_flag_disposes_in_one_datagram_keep_their_own_sequence_numbers() {
        // One little-endian DATA and one big-endian DATA, so each byte order
        // of the writerSN is read; the second carries a non-zero high word.
        let mut packet = header();
        let first = key_only_body(5, 0x01, None, true, &string_key("RED"), true);
        push_submessage(&mut packet, 0x15, 0x0b, &first);
        let second_sn = (1u64 << 32) | 6;
        let second = key_only_body(second_sn, 0x02, Some([0xB2; 16]), true, &[], false);
        push_submessage(&mut packet, 0x15, 0x0a, &second);
        assert_eq!(count_data_submessages(&packet), 2);

        let probe = new_probe();
        assert_eq!(route(&packet, &probe), RouteStatus::Delivered);
        let disposes = probe.disposes.lock().expect("probe lock").clone();
        assert_eq!(
            disposes,
            vec![
                (5, short_string_hash("RED"), DisposeKind::Disposed),
                (second_sn, [0xB2; 16], DisposeKind::Unregistered),
            ]
        );

        // The walk handed the whole datagram reads each DATA's own SN too.
        let mut topic = crate::engine::demux::Topic::new(TOPIC.to_string(), None);
        let direct = new_probe();
        assert!(topic.add_subscriber(direct.clone()));
        assert_eq!(
            deliver_all_disposes_in_datagram(
                &packet,
                &topic,
                &TopicRegistry::new(),
                &RouterMetrics::new()
            ),
            2
        );
        let seqs: Vec<u64> = direct
            .disposes
            .lock()
            .expect("probe lock")
            .iter()
            .map(|d| d.0)
            .collect();
        assert_eq!(seqs, vec![5, second_sn]);
    }

    /// A HEARTBEAT body (Sec.9.4.5.6): readerId, writerId, firstSN, lastSN,
    /// count, little-endian.
    fn heartbeat_body() -> Vec<u8> {
        let mut hb = Vec::new();
        hb.extend_from_slice(&[0, 0, 0, 0]);
        hb.extend_from_slice(&WRITER_GUID[12..]);
        hb.extend_from_slice(&0u32.to_le_bytes());
        hb.extend_from_slice(&1u32.to_le_bytes());
        hb.extend_from_slice(&0u32.to_le_bytes());
        hb.extend_from_slice(&11u32.to_le_bytes());
        hb.extend_from_slice(&3u32.to_le_bytes());
        hb
    }

    #[test]
    fn the_walk_reads_no_key_past_its_submessage() {
        // An int key (CDR_LE, value 5) whose first four octets read like the
        // length of a short string. Its own submessage holds no such string;
        // the HEARTBEAT behind it holds the octets that would complete one.
        let mut key = vec![0x00, 0x01, 0x00, 0x00];
        key.extend_from_slice(&5i32.to_le_bytes());
        let mut packet = header();
        push_submessage(
            &mut packet,
            0x15,
            0x0b,
            &key_only_body(11, 0x01, None, true, &key, true),
        );
        let heartbeat_at = packet.len();
        push_submessage(&mut packet, 0x07, 0x01, &heartbeat_body());
        assert_eq!(packet[heartbeat_at], 0x07);

        let mut topic = crate::engine::demux::Topic::new(TOPIC.to_string(), None);
        let probe = new_probe();
        assert!(topic.add_subscriber(probe.clone()));
        let metrics = RouterMetrics::new();
        assert_eq!(
            deliver_all_disposes_in_datagram(&packet, &topic, &TopicRegistry::new(), &metrics),
            1,
            "the walk saw one dispose"
        );
        assert_eq!(
            *probe.disposes.lock().expect("probe lock"),
            vec![],
            "an int key is no string key; the HEARTBEAT is not its tail"
        );
        assert_eq!(metrics.lifecycle_unnamed.load(Ordering::Relaxed), 1);
    }

    /// No PID_KEY_HASH and a key the subscriber does not read: the change
    /// names no instance for it, whatever the key's bytes look like (here a
    /// string, big endian, which a type-blind reading took for "RED").
    #[test]
    fn a_key_no_subscriber_reads_without_a_key_hash_names_nothing() {
        let mut key = vec![0x00, 0x00, 0x00, 0x00];
        key.extend_from_slice(&4u32.to_be_bytes());
        key.extend_from_slice(b"RED\0");
        let mut packet = header();
        push_submessage(
            &mut packet,
            0x15,
            0x0b,
            &key_only_body(11, 0x01, None, true, &key, true),
        );
        let probe = new_probe();
        assert_eq!(route(&packet, &probe), RouteStatus::Delivered);
        assert!(probe.disposes.lock().expect("probe lock").is_empty());
    }

    #[test]
    fn the_walk_reads_no_inline_qos_past_its_submessage() {
        // The DATA's ParameterList ends without its sentinel. The PAD behind
        // it (id 0x01, flags 0x00) reads, little-endian, as PID_SENTINEL:
        // only a list read past its submessage finds one.
        let mut packet = header();
        let body = key_only_body(11, 0x01, Some([0xC3; 16]), false, &[], true);
        push_submessage(&mut packet, 0x15, 0x0b, &body);
        let pad_at = packet.len();
        packet.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);
        assert_eq!(
            u16::from_le_bytes([packet[pad_at], packet[pad_at + 1]]),
            PID_SENTINEL
        );

        let mut topic = crate::engine::demux::Topic::new(TOPIC.to_string(), None);
        let probe = new_probe();
        assert!(topic.add_subscriber(probe.clone()));
        assert_eq!(
            deliver_all_disposes_in_datagram(
                &packet,
                &topic,
                &TopicRegistry::new(),
                &RouterMetrics::new()
            ),
            0
        );
        assert_eq!(*probe.disposes.lock().expect("probe lock"), vec![]);
    }

    #[test]
    fn a_payload_offset_is_not_found_past_its_submessage() {
        // The layout reader, on the same bytes: the DATA's
        // list has no sentinel, so it has no payload offset, whatever the
        // PAD behind it spells.
        let mut packet = header();
        let body = key_only_body(11, 0x01, Some([0xC3; 16]), false, &[], true);
        push_submessage(&mut packet, 0x15, 0x0b, &body);
        packet.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);
        assert_eq!(data_submsg_payload_offset(&packet, 20), None);

        // With its sentinel, the payload starts right behind it.
        let mut packet = header();
        let body = key_only_body(11, 0x01, Some([0xC3; 16]), true, &[], true);
        push_submessage(&mut packet, 0x15, 0x0b, &body);
        assert_eq!(data_submsg_payload_offset(&packet, 20), Some(packet.len()));
    }

    /// `body` as sent by the writer whose entity id is `writer_id`.
    fn from_writer_id(mut body: Vec<u8>, writer_id: [u8; 4]) -> Vec<u8> {
        body[8..12].copy_from_slice(&writer_id);
        body
    }

    /// The writer of WRITER_GUID's participant whose entity id is `id`.
    fn writer_with_id(id: [u8; 4]) -> [u8; 16] {
        let mut guid = WRITER_GUID;
        guid[12..].copy_from_slice(&id);
        guid
    }

    /// An unregister is a fact about the writer that sent it (DDS v1.4
    /// Sec.2.2.2.4.2.7), so every dispose and unregister reaches the reader
    /// with its writer: the RTPS header's prefix and its own DATA's
    /// writerId (RTPS v2.5 Sec.8.3.8.2).
    #[test]
    fn a_k_flag_dispose_carries_its_writer() {
        let mut packet = header();
        let body = key_only_body(11, 0x02, Some([0xA1; 16]), true, &[], true);
        push_submessage(&mut packet, 0x15, 0x0b, &body);
        let probe = new_probe();
        assert_eq!(route(&packet, &probe), RouteStatus::Delivered);
        assert_eq!(
            *probe.disposes.lock().expect("probe lock"),
            vec![(11, [0xA1; 16], DisposeKind::Unregistered)]
        );
        assert_eq!(
            *probe.writers.lock().expect("probe lock"),
            vec![Some(WRITER_GUID)]
        );

        // Two writers of one participant in one datagram: each DATA under
        // its own writerId, routed and walked.
        let second_id = [0x00, 0x00, 0x02, 0x02];
        let mut packet = header();
        let first = key_only_body(5, 0x01, Some([0xA2; 16]), true, &[], true);
        push_submessage(&mut packet, 0x15, 0x0b, &first);
        let second = from_writer_id(
            key_only_body(6, 0x02, Some([0xB2; 16]), true, &[], false),
            second_id,
        );
        push_submessage(&mut packet, 0x15, 0x0a, &second);
        let probe = new_probe();
        let registry = TopicRegistry::new();
        registry
            .register_subscriber(probe.clone())
            .expect("register subscriber");
        registry.register_writer_guid(WRITER_GUID, TOPIC.to_string());
        registry.register_writer_guid(writer_with_id(second_id), TOPIC.to_string());
        assert_eq!(
            route_data_packet(
                &packet,
                packet.len(),
                None,
                &registry,
                &RouterMetrics::new()
            ),
            RouteStatus::Delivered
        );
        assert_eq!(
            *probe.writers.lock().expect("probe lock"),
            vec![Some(WRITER_GUID), Some(writer_with_id(second_id))]
        );

        let mut topic = crate::engine::demux::Topic::new(TOPIC.to_string(), None);
        let direct = new_probe();
        assert!(topic.add_subscriber(direct.clone()));
        assert_eq!(
            deliver_all_disposes_in_datagram(
                &packet,
                &topic,
                &TopicRegistry::new(),
                &RouterMetrics::new()
            ),
            2
        );
        assert_eq!(
            *direct.writers.lock().expect("probe lock"),
            vec![Some(WRITER_GUID), Some(writer_with_id(second_id))]
        );
    }

    /// A sample that carries the unregister of its own instance (D=1 with
    /// StatusInfo, RTPS v2.5 Sec.9.6.4.9) delivers it under its writer too.
    #[test]
    fn an_unregister_riding_a_sample_carries_its_writer() {
        let mut body = Vec::new();
        body.extend_from_slice(&[0, 0]); // extraFlags
        body.extend_from_slice(&16u16.to_le_bytes()); // octetsToInlineQos
        body.extend_from_slice(&[0, 0, 0, 0]); // readerId: ENTITYID_UNKNOWN
        body.extend_from_slice(&WRITER_GUID[12..]);
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&9u32.to_le_bytes());
        parameter(&mut body, PID_STATUS_INFO, &[0, 0, 0, 0x02], true);
        parameter(&mut body, PID_KEY_HASH, &[0xD4; 16], true);
        parameter(&mut body, PID_SENTINEL, &[], true);
        body.extend_from_slice(&[0x00, 0x07, 0x00, 0x00]); // CDR2_LE
        body.extend_from_slice(&5i64.to_le_bytes());
        let mut packet = header();
        push_submessage(&mut packet, 0x15, 0x07, &body);

        let probe = new_probe();
        let registry = TopicRegistry::new();
        registry
            .register_subscriber(probe.clone())
            .expect("register subscriber");
        registry.register_writer_guid(WRITER_GUID, TOPIC.to_string());
        let (_, offset, _, _) = crate::core::discovery::multicast::classify_rtps(&packet);
        assert_eq!(
            route_data_packet(
                &packet,
                packet.len(),
                offset,
                &registry,
                &RouterMetrics::new()
            ),
            RouteStatus::Delivered
        );
        assert_eq!(
            *probe.disposes.lock().expect("probe lock"),
            vec![(9, [0xD4; 16], DisposeKind::Unregistered)]
        );
        assert_eq!(
            *probe.writers.lock().expect("probe lock"),
            vec![Some(WRITER_GUID)]
        );
    }
}

/// The padding a SerializedPayload's options count (DDS-XTypes 1.3
/// 7.6.3.1.2) is cut at both doors a received sample takes, the single DATA
/// and the reassembled DATA_FRAG.
#[cfg(test)]
mod serialized_payload_padding_tests {
    use super::*;
    use crate::core::discovery::multicast::classify_rtps;
    use crate::dds::CdrVersion;
    use crate::engine::Subscriber;
    use std::sync::Mutex as StdMutex;

    const TOPIC: &str = "PaddingTopic";

    /// `@final struct { unsigned short a; double b; octet c; }` =
    /// {0x2233, 1.5, 0x44} serialized as XCDR2 little-endian (DDS-XTypes 1.3
    /// 7.4.3.5): `a` (2 octets), 2 octets of padding (XCDR2 aligns an 8-octet
    /// primitive to 4), `b` (IEEE 754 1.5 = 0x3FF8_0000_0000_0000), `c`. 13
    /// octets, so the sample carries 3 octets of padding counted by the
    /// options `0007 0003` (7.6.3.1.2).
    const FINAL_STRUCT_BODY: [u8; 13] = [
        0x33, 0x22, // a
        0x00, 0x00, // padding to 4
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0x3f, // b
        0x44, // c
    ];

    struct Capture {
        captured: StdMutex<Vec<(Vec<u8>, CdrVersion)>>,
    }

    impl Subscriber for Capture {
        fn on_data(&self, _topic: &str, _seq: u64, _data: &[u8]) {
            panic!("expected on_data_with_writer");
        }

        fn on_data_with_writer(
            &self,
            _topic: &str,
            _writer_guid: [u8; 16],
            _seq: u64,
            data: &[u8],
            version: CdrVersion,
        ) {
            self.captured
                .lock()
                .expect("capture lock")
                .push((data.to_vec(), version));
        }

        fn topic_name(&self) -> &str {
            TOPIC
        }
    }

    fn registry_with_capture(writer_guid: [u8; 16]) -> (TopicRegistry, Arc<Capture>) {
        let registry = TopicRegistry::new();
        let capture = Arc::new(Capture {
            captured: StdMutex::new(Vec::new()),
        });
        registry
            .register_subscriber(capture.clone())
            .expect("register subscriber");
        registry.register_writer_guid(writer_guid, TOPIC.to_string());
        (registry, capture)
    }

    fn delivered(capture: &Capture) -> Vec<(Vec<u8>, CdrVersion)> {
        capture.captured.lock().expect("capture lock").clone()
    }

    #[test]
    fn the_counted_padding_ends_the_serialized_data() {
        let mut payload = vec![0x00, 0x07, 0x00, 0x00];
        payload.extend_from_slice(&[1, 2, 3, 4, 5, 0, 0, 0]);
        for (options_low, end) in [(0u8, 12usize), (1, 11), (2, 10), (3, 9)] {
            payload[3] = options_low;
            assert_eq!(serialized_data_end(&payload, 0, 12), end);
        }
        // Only the two low bits count.
        payload[3] = 0xFC;
        assert_eq!(serialized_data_end(&payload, 0, 12), 12);
        // A count larger than the octets behind the header is not believed.
        let short = [0x00, 0x07, 0x00, 0x03, 0xAA, 0xBB];
        assert_eq!(serialized_data_end(&short, 0, 6), 6);
        assert_eq!(serialized_data_end(&short[..4], 0, 4), 4);
        // Nor is one exactly as large as the body: it would deliver an empty
        // sample. One octet less than the body leaves one octet of data.
        let all = [0x00, 0x07, 0x00, 0x03, 0xAA, 0xBB, 0xCC];
        assert_eq!(serialized_data_end(&all, 0, 7), 7);
        let one = [0x00, 0x07, 0x00, 0x03, 0xAA, 0x00, 0x00, 0x00];
        assert_eq!(serialized_data_end(&one, 0, 8), 5);
    }

    /// A count of padding the sender never sent: the payload stops short of
    /// the four-octet boundary the padding would reach, so nothing is cut.
    /// Bytes from an OpenDDS 3.35 DATA (options 0x0003, last submessage): a
    /// string "Hello there." (length 13 with its NUL), 17 octets of data.
    #[test]
    fn a_counted_padding_the_sender_left_out_cuts_nothing() {
        let mut payload = vec![0x00, 0x07, 0x00, 0x03, 0x0d, 0x00, 0x00, 0x00];
        payload.extend_from_slice(b"Hello there.\0");
        assert_eq!(payload.len(), 21);
        assert_eq!(serialized_data_end(&payload, 0, 21), 21);
        // The same payload with its three octets of padding is cut back to 21.
        payload.extend_from_slice(&[0, 0, 0]);
        assert_eq!(serialized_data_end(&payload, 0, 24), 21);
        // The rule reads the length from the encapsulation header, not from 0.
        let mut framed = vec![0xEE; 6];
        framed.extend_from_slice(&payload[..21]);
        assert_eq!(serialized_data_end(&framed, 6, 27), 27);
    }

    /// A foreign sample: the 13 octets reach the reader, not 16.
    #[test]
    fn a_foreign_writers_padding_is_not_delivered_as_sample_bytes() {
        let writer_guid = [
            0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x00, 0x00,
            0x01, 0x02,
        ];
        let mut packet = Vec::new();
        packet.extend_from_slice(b"RTPS");
        // Version 2.3, vendor id VENDORID_UNKNOWN {0x00, 0x00} (RTPS v2.5
        // 9.3.2.1): any writer that is not HDDS; the padding path does not
        // branch on the vendor.
        packet.extend_from_slice(&[2, 3, 0x00, 0x00]);
        packet.extend_from_slice(&writer_guid[..12]);
        // DATA, E|D, last submessage (octetsToNextHeader 0), no inline QoS.
        packet.extend_from_slice(&[0x15, 0x05, 0x00, 0x00]);
        packet.extend_from_slice(&[0, 0]);
        packet.extend_from_slice(&16u16.to_le_bytes());
        packet.extend_from_slice(&[0, 0, 0, 0]);
        packet.extend_from_slice(&writer_guid[12..]);
        packet.extend_from_slice(&[0, 0, 0, 0]);
        packet.extend_from_slice(&1u32.to_le_bytes());
        packet.extend_from_slice(&[0x00, 0x07, 0x00, 0x03]);
        packet.extend_from_slice(&FINAL_STRUCT_BODY);
        packet.extend_from_slice(&[0, 0, 0]);

        let (registry, capture) = registry_with_capture(writer_guid);
        let metrics = RouterMetrics::new();
        let status = route_data_packet(&packet, packet.len(), Some(44), &registry, &metrics);
        assert_eq!(status, RouteStatus::Delivered);
        assert_eq!(
            delivered(&capture),
            vec![(FINAL_STRUCT_BODY.to_vec(), CdrVersion::Xcdr2)]
        );
    }

    fn hdds_ctx(writer_guid: [u8; 16]) -> builder::RtpsEndpointContext {
        let mut guid_prefix = [0u8; 12];
        guid_prefix.copy_from_slice(&writer_guid[..12]);
        let mut writer_entity_id = [0u8; 4];
        writer_entity_id.copy_from_slice(&writer_guid[12..]);
        builder::RtpsEndpointContext {
            guid_prefix,
            reader_entity_id: [0, 0, 0, 0],
            writer_entity_id,
            encapsulation_kind: 0x0007,
            publisher_entity_id: [0x00, 0x00, 0x01, 0x08],
        }
    }

    /// HDDS to HDDS: what the writer pads, the reader takes back off.
    #[test]
    fn an_hdds_sample_reaches_the_reader_exactly_as_encoded() {
        let writer_guid = [
            0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x00, 0x00,
            0x01, 0x03,
        ];
        let packet = builder::build_data_packet_with_context(
            &hdds_ctx(writer_guid),
            TOPIC,
            1,
            &FINAL_STRUCT_BODY,
            CdrVersion::Xcdr2,
        );
        let (_kind, payload_offset, _frag, _ctx) = classify_rtps(&packet);
        let (registry, capture) = registry_with_capture(writer_guid);
        let metrics = RouterMetrics::new();
        let status = route_data_packet(&packet, packet.len(), payload_offset, &registry, &metrics);
        assert_eq!(status, RouteStatus::Delivered);
        assert_eq!(
            delivered(&capture),
            vec![(FINAL_STRUCT_BODY.to_vec(), CdrVersion::Xcdr2)]
        );
    }

    /// Protected bytes replace the complete SerializedPayload, on ordinary
    /// DATA and after DATA_FRAG reassembly (DDS-Security 1.1 Sec.9.5.3.3.4.4).
    #[cfg(feature = "security")]
    mod sealed {
        use super::*;
        use crate::security::crypto::data_keys::WriterKey;
        use crate::security::crypto::peer_keys::SecretKey;
        use crate::security::crypto::user_data::{
            decode_serialized_payload, encode_serialized_payload, serialized_body,
        };

        fn key() -> WriterKey {
            WriterKey::for_tests(SecretKey::from_bytes([0x5a; 32]))
        }
        fn writer_guid() -> [u8; 16] {
            [0x33; 16]
        }

        #[test]
        fn protected_data_replaces_encapsulation_and_routes_exactly() {
            for len in 13..=16 {
                for repr in [0x0001u16, 0x0007, 0x0009, 0x000b] {
                    let plain = vec![0x5b; len];
                    let serialized = builder::encapsulate_serialized_payload(repr, &plain, false);
                    let sealed = encode_serialized_payload(7, &key(), &serialized).unwrap();
                    let packet = builder::build_data_packet_with_context_full_keyed_ts(
                        &hdds_ctx(writer_guid()),
                        TOPIC,
                        1,
                        &sealed,
                        CdrVersion::Xcdr2,
                        builder::now_rtps_timestamp(),
                        None,
                        None,
                        None,
                        true,
                    );
                    let (_, offset, _, _) = classify_rtps(&packet);
                    assert_eq!(&packet[offset.unwrap()..], sealed);
                    let (registry, capture) = registry_with_capture(writer_guid());
                    let metrics = RouterMetrics::new();
                    assert_eq!(
                        route_data_packet(&packet, packet.len(), offset, &registry, &metrics),
                        RouteStatus::Delivered
                    );
                    let got = delivered(&capture);
                    assert_eq!(got[0].0, sealed);
                    let opened = decode_serialized_payload(7, &key(), &got[0].0).unwrap();
                    assert_eq!(opened, serialized);
                    assert_eq!(serialized_body(&opened).unwrap().0, plain);
                }
            }
        }

        #[test]
        fn protected_fragments_reassemble_the_complete_crypto_elements() {
            let plain = vec![0x5b; builder::DEFAULT_MAX_UNFRAGMENTED_SIZE + 1];
            let serialized = builder::encapsulate_serialized_payload(0x0001, &plain, false);
            let sealed = encode_serialized_payload(7, &key(), &serialized).unwrap();
            let frags = builder::build_data_frag_packets_ts(
                &hdds_ctx(writer_guid()),
                1,
                &sealed,
                builder::DEFAULT_FRAGMENT_SIZE,
                CdrVersion::Xcdr1,
                builder::now_rtps_timestamp(),
                true,
            );
            assert!(frags.len() > 1);
            let whole: Vec<u8> = frags.iter().flat_map(|f| f[68..].to_vec()).collect();
            assert_eq!(whole, sealed);
            let (registry, capture) = registry_with_capture(writer_guid());
            let metrics = RouterMetrics::new();
            let buffer = Mutex::new(FragmentBuffer::new(8, 5000));
            for frag in frags.iter().rev() {
                let (_, offset, meta, _) = classify_rtps(frag);
                let _ = route_data_frag_packet(
                    frag,
                    frag.len(),
                    offset,
                    meta.as_ref(),
                    &buffer,
                    &registry,
                    &metrics,
                );
            }
            let got = delivered(&capture);
            assert_eq!(got.len(), 1);
            assert_eq!(got[0].0, sealed);
            assert_eq!(
                decode_serialized_payload(7, &key(), &got[0].0).unwrap(),
                serialized
            );
        }
    }

    /// The reassembled door: the count is in fragment 1, the padding at the
    /// end of the last fragment.
    #[test]
    fn a_reassembled_sample_reaches_the_reader_exactly_as_encoded() {
        let writer_guid = [
            0x32, 0x32, 0x32, 0x32, 0x32, 0x32, 0x32, 0x32, 0x32, 0x32, 0x32, 0x32, 0x00, 0x00,
            0x01, 0x03,
        ];
        let body: Vec<u8> = (0..builder::DEFAULT_MAX_UNFRAGMENTED_SIZE + 1)
            .map(|i| (i % 251) as u8)
            .collect();
        let frags = builder::build_data_frag_packets(
            &hdds_ctx(writer_guid),
            1,
            &body,
            builder::DEFAULT_FRAGMENT_SIZE,
            CdrVersion::Xcdr2,
        );
        assert!(frags.len() > 1, "fixture must fragment");

        let (registry, capture) = registry_with_capture(writer_guid);
        let metrics = RouterMetrics::new();
        let buffer = Mutex::new(FragmentBuffer::new(8, 5000));
        for frag in &frags {
            let (_kind, payload_offset, meta, _ctx) = classify_rtps(frag);
            let meta = meta.expect("fragment metadata");
            let _ = route_data_frag_packet(
                frag,
                frag.len(),
                payload_offset,
                Some(&meta),
                &buffer,
                &registry,
                &metrics,
            );
        }
        let got = delivered(&capture);
        assert_eq!(got.len(), 1, "one sample");
        assert_eq!(got[0].1, CdrVersion::Xcdr2);
        assert_eq!(
            got[0].0.len(),
            body.len(),
            "the three padding octets were delivered"
        );
        assert_eq!(got[0].0, body);
    }
}

#[cfg(test)]
mod spec_group_end_of_set_tests {
    use super::*;
    use crate::engine::Subscriber;
    use std::sync::Mutex;

    const TOPIC: &str = "SpecEndOfSet";

    struct EcsProbe(Mutex<Vec<(u64, u64, Option<u64>)>>);

    impl Subscriber for EcsProbe {
        fn on_data(&self, _topic: &str, _seq: u64, _data: &[u8]) {}
        fn on_ecs(
            &self,
            _topic: &str,
            _writer_guid: [u8; 16],
            ecs_seq: u64,
            coherent_sn: u64,
            group_sn: Option<u64>,
            _publisher_entity_id: Option<[u8; 4]>,
        ) {
            self.0
                .lock()
                .expect("probe lock")
                .push((ecs_seq, coherent_sn, group_sn));
        }
        fn topic_name(&self) -> &str {
            TOPIC
        }
    }

    /// What `on_group_change` was told.
    type WriterSets = Mutex<Vec<crate::engine::subscriber::GroupChange>>;

    struct WriterSetProbe(WriterSets);

    impl Subscriber for WriterSetProbe {
        fn on_data(&self, _topic: &str, _seq: u64, _data: &[u8]) {}
        fn on_group_change(
            &self,
            _writer_guid: [u8; 16],
            change: crate::engine::subscriber::GroupChange,
        ) {
            self.0.lock().expect("probe lock").push(change);
        }
        fn topic_name(&self) -> &str {
            TOPIC
        }
    }

    /// A writer of the spec class names, on each change of a GROUP set, the
    /// set's writer set (PID_WRITER_GROUP_INFO, RTPS v2.5 Sec.9.6.4.5, D5)
    /// and its GSN (PID_GROUP_SEQ_NUM), and on its end of the set the first
    /// SN of its part: the readers are
    /// told before the change. A writer of no spec class tells nothing.
    #[test]
    fn a_spec_writers_group_changes_name_their_writer_set() {
        let ctx = builder::RtpsEndpointContext {
            guid_prefix: [0x62; 12],
            reader_entity_id: [0, 0, 0, 0],
            writer_entity_id: [0, 0, 0x13, 0x02],
            encapsulation_kind: 0x0007,
            publisher_entity_id: [0, 0, 0x22, 0x08],
        };
        let mut writer = [0u8; 16];
        writer[..12].copy_from_slice(&ctx.guid_prefix);
        writer[12..].copy_from_slice(&ctx.writer_entity_id);
        let member_tag = crate::protocol::group::GroupTag {
            gsn: 10,
            writer_set: [9, 8, 7, 6],
            set_first_gsn: Some(10),
            part_first_sn: None,
        };
        let member = builder::build_data_packet_grouped_ts(
            &ctx,
            TOPIC,
            6,
            &[1, 0, 0, 0, 2, 0, 0, 0],
            crate::dds::CdrVersion::Xcdr2,
            (0, 0),
            Some(6),
            Some(10),
            Some(&member_tag),
            None,
            false,
        );
        let end = builder::build_ecs_spec_ts(
            &ctx,
            TOPIC,
            7,
            &crate::protocol::group::GroupTag {
                gsn: 11,
                writer_set: [9, 8, 7, 6],
                set_first_gsn: Some(10),
                part_first_sn: Some(6),
            },
            (0, 0),
        );
        for spec in [true, false] {
            let registry = TopicRegistry::new();
            let probe = Arc::new(WriterSetProbe(Mutex::new(Vec::new())));
            registry
                .register_subscriber(probe.clone())
                .expect("register subscriber");
            registry.register_writer_guid(writer, TOPIC.to_string());
            if spec {
                registry.record_writer_group_dialect(
                    writer,
                    crate::protocol::group::GroupDialect::Spec,
                    Some(ctx.publisher_entity_id),
                );
            }
            // The member's serialized payload: its encapsulation and the
            // eight octets above, at the end of the datagram.
            let payload_offset = member.len() - 12;
            for (packet, offset) in [(&member, Some(payload_offset)), (&end, None)] {
                route_data_packet(
                    packet,
                    packet.len(),
                    offset,
                    &registry,
                    &RouterMetrics::new(),
                );
            }
            let told = probe.0.lock().expect("probe lock").clone();
            if spec {
                let change = |seq, gsn, part_first_sn| crate::engine::subscriber::GroupChange {
                    seq,
                    group_sn: 10,
                    publisher_entity_id: [0, 0, 0x22, 0x08],
                    writer_set: [9, 8, 7, 6],
                    gsn: Some(gsn),
                    part_first_sn,
                };
                assert_eq!(
                    told,
                    vec![change(6, 10, None), change(7, 11, Some(6))],
                    "SN, set, writer set, PID_GROUP_SEQ_NUM, part's first SN"
                );
            } else {
                assert!(told.is_empty(), "no spec class, nothing told: {told:?}");
            }
        }
    }

    /// The end of a group set of a writer of the spec class (D18) carries
    /// the writer's FIRST SN in PID_COHERENT_SET (RTPS v2.5 Table 9.23): the
    /// reader is told the writer's part ends just before it. The same bytes
    /// from a writer of no spec class are read as today (its LAST SN).
    #[test]
    fn a_spec_writers_end_of_set_ends_its_part_before_it() {
        let ctx = builder::RtpsEndpointContext {
            guid_prefix: [0x61; 12],
            reader_entity_id: [0, 0, 0, 0],
            writer_entity_id: [0, 0, 0x12, 0x02],
            encapsulation_kind: 0x0007,
            publisher_entity_id: [0, 0, 0x21, 0x08],
        };
        let mut writer = [0u8; 16];
        writer[..12].copy_from_slice(&ctx.guid_prefix);
        writer[12..].copy_from_slice(&ctx.writer_entity_id);
        let packet = builder::build_ecs_spec_ts(
            &ctx,
            TOPIC,
            9,
            &crate::protocol::group::GroupTag {
                gsn: 12,
                writer_set: [1, 2, 3, 4],
                set_first_gsn: Some(10),
                part_first_sn: Some(6),
            },
            (0, 0),
        );
        for (spec, expected) in [(true, 8), (false, 6)] {
            let registry = TopicRegistry::new();
            let probe = Arc::new(EcsProbe(Mutex::new(Vec::new())));
            registry
                .register_subscriber(probe.clone())
                .expect("register subscriber");
            registry.register_writer_guid(writer, TOPIC.to_string());
            if spec {
                registry.record_writer_group_dialect(
                    writer,
                    crate::protocol::group::GroupDialect::Spec,
                    Some(ctx.publisher_entity_id),
                );
            }
            route_data_packet(
                &packet,
                packet.len(),
                None,
                &registry,
                &RouterMetrics::new(),
            );
            assert_eq!(
                probe.0.lock().expect("probe lock").clone(),
                vec![(9, expected, Some(10))],
                "spec={spec}"
            );
        }
    }
}

#[cfg(test)]
mod fragment_fallback_tests {
    use super::*;
    use crate::core::discovery::multicast::FragmentGeometry;

    const PREFIX: [u8; 12] = [0x5A; 12];
    const WRITER: [u8; 4] = [0x00, 0x00, 0x01, 0x02];

    /// A datagram whose first submessage is a DATA (SN 5, its payload of
    /// 0xD1 octets) and whose second is a DATA_FRAG (SN 6, fragment 1 of a
    /// 16-octet sample, its 8 octets of 0xF2), both laid out by hand as
    /// RTPS v2.5 Sec.9.4.5.4 and Sec.9.4.5.5 draw them, little-endian.
    fn data_then_data_frag() -> (Vec<u8>, usize) {
        let mut pkt = b"RTPS".to_vec();
        pkt.extend_from_slice(&[2, 5, 0x01, 0x1A]);
        pkt.extend_from_slice(&PREFIX);
        // DATA: E|D, body 20 fixed + 8 payload.
        pkt.extend_from_slice(&[0x15, 0x05]);
        pkt.extend_from_slice(&28u16.to_le_bytes());
        pkt.extend_from_slice(&[0x00, 0x00]);
        pkt.extend_from_slice(&16u16.to_le_bytes());
        pkt.extend_from_slice(&[0x00; 4]);
        pkt.extend_from_slice(&WRITER);
        pkt.extend_from_slice(&0u32.to_le_bytes());
        pkt.extend_from_slice(&5u32.to_le_bytes());
        pkt.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 0xD1, 0xD1, 0xD1, 0xD1]);
        // DATA_FRAG: E, body 32 fixed + 8 fragment data.
        let frag_at = pkt.len();
        pkt.extend_from_slice(&[0x16, 0x01]);
        pkt.extend_from_slice(&40u16.to_le_bytes());
        pkt.extend_from_slice(&[0x00, 0x00]);
        pkt.extend_from_slice(&28u16.to_le_bytes());
        pkt.extend_from_slice(&[0x00; 4]);
        pkt.extend_from_slice(&WRITER);
        pkt.extend_from_slice(&0u32.to_le_bytes());
        pkt.extend_from_slice(&6u32.to_le_bytes());
        pkt.extend_from_slice(&1u32.to_le_bytes()); // fragmentStartingNum
        pkt.extend_from_slice(&1u16.to_le_bytes()); // fragmentsInSubmessage
        pkt.extend_from_slice(&8u16.to_le_bytes()); // fragmentSize
        pkt.extend_from_slice(&16u32.to_le_bytes()); // sampleSize
        pkt.extend_from_slice(&[0xF2; 8]);
        assert_eq!(pkt.len(), frag_at + 4 + 40, "fixture: declared lengths");
        (pkt, frag_at)
    }

    fn meta() -> FragmentMetadata {
        FragmentMetadata {
            writer_guid: GUID::new(PREFIX, WRITER),
            seq_num: 6,
            frag_num: 1,
            geometry: FragmentGeometry {
                fragment_size: 8,
                sample_size: 16,
            },
        }
    }

    /// With no payload offset from the classifier, the fragment comes from
    /// the DATA_FRAG the metadata names, never from the DATA beside it: a
    /// fallback asking the DATA extractor would find the first DATA and hand
    /// its payload to reassembly as fragment 1 of sample 6.
    #[test]
    fn a_fragment_without_an_offset_is_read_from_its_own_data_frag() {
        let (pkt, frag_at) = data_then_data_frag();
        assert_eq!(
            fragment_bytes(&pkt, None, &meta()),
            Some([0xF2; 8].as_slice())
        );
        // The same as with the offset the classifier would give.
        assert_eq!(
            fragment_bytes(&pkt, Some(frag_at + 36), &meta()),
            Some([0xF2; 8].as_slice())
        );
    }

    /// No DATA_FRAG matches the metadata: no fragment, whatever else the
    /// datagram carries.
    #[test]
    fn a_fragment_the_metadata_does_not_name_is_not_read() {
        let (pkt, _) = data_then_data_frag();
        let mut other = meta();
        other.seq_num = 7;
        assert_eq!(fragment_bytes(&pkt, None, &other), None);
    }
}

#[cfg(test)]
mod group_route_scope_tests {
    use super::*;

    struct ReclassifyingProbe {
        registry: Arc<TopicRegistry>,
        observed: Mutex<Vec<Option<bool>>>,
    }

    impl crate::engine::Subscriber for ReclassifyingProbe {
        fn topic_name(&self) -> &str {
            "group-route-snapshot"
        }
        fn on_data(&self, _: &str, _: u64, _: &[u8]) {}
        fn on_group_change(&self, writer: [u8; 16], change: crate::engine::GroupChange) {
            assert_eq!(route_group_is_spec(writer, change.seq), Some(true));
            self.registry.record_writer_group_dialect(
                writer,
                crate::protocol::group::GroupDialect::HddsLegacy,
                None,
            );
        }
        fn on_data_coherent(
            &self,
            _: &str,
            writer: [u8; 16],
            seq: u64,
            _: &[u8],
            _: crate::dds::CdrVersion,
            _: Option<u64>,
            _: Option<u64>,
            _: Option<[u8; 4]>,
        ) {
            self.observed
                .lock()
                .expect("observed")
                .push(route_group_is_spec(writer, seq));
        }
    }

    #[test]
    fn group_route_keeps_announced_classification_through_data_dispatch() {
        let registry = Arc::new(TopicRegistry::new());
        let probe = Arc::new(ReclassifyingProbe {
            registry: Arc::clone(&registry),
            observed: Mutex::new(Vec::new()),
        });
        // The probe holds the registry and the registry the probe: the token
        // unregisters it when the test ends.
        let _registration = registry
            .register_subscriber_scoped(probe.clone())
            .expect("subscriber");
        let ctx = builder::RtpsEndpointContext {
            guid_prefix: [0x62; 12],
            reader_entity_id: [0; 4],
            writer_entity_id: [0, 0, 0x13, 2],
            encapsulation_kind: 7,
            publisher_entity_id: [0, 0, 0x22, 8],
        };
        let mut writer = [0; 16];
        writer[..12].copy_from_slice(&ctx.guid_prefix);
        writer[12..].copy_from_slice(&ctx.writer_entity_id);
        registry.register_writer_guid(writer, "group-route-snapshot".to_string());
        registry.record_writer_group_dialect(
            writer,
            crate::protocol::group::GroupDialect::Spec,
            Some(ctx.publisher_entity_id),
        );
        let tag = crate::protocol::group::GroupTag {
            gsn: 10,
            writer_set: [1; 4],
            set_first_gsn: Some(10),
            part_first_sn: None,
        };
        let packet = builder::build_data_packet_grouped_ts(
            &ctx,
            "group-route-snapshot",
            6,
            &[1, 0, 0, 0, 2, 0, 0, 0],
            crate::dds::CdrVersion::Xcdr2,
            (0, 0),
            Some(6),
            Some(10),
            Some(&tag),
            None,
            false,
        );
        assert_eq!(
            route_data_packet(
                &packet,
                packet.len(),
                Some(packet.len() - 12),
                &registry,
                &RouterMetrics::new()
            ),
            RouteStatus::Delivered
        );
        assert_eq!(*probe.observed.lock().expect("observed"), vec![Some(true)]);
        assert_eq!(
            route_group_is_spec(writer, 6),
            None,
            "dispatch restores its context"
        );
    }

    #[test]
    fn group_route_classification_survives_discovery_updates_and_nested_delivery() {
        let registry = TopicRegistry::new();
        let writer = [7; 16];
        let other = [8; 16];
        let _outer = GroupRouteScope::enter(GroupRouteContext {
            writer,
            seq: 4,
            spec: true,
            spec_receive: false,
            writer_set: Some([1; 4]),
            order: None,
            set_first_gsn: None,
        });
        registry.record_writer_group_dialect(
            writer,
            crate::protocol::group::GroupDialect::HddsLegacy,
            None,
        );
        assert_eq!(route_group_is_spec(writer, 4), Some(true));
        assert_eq!(route_group_writer_set(writer, 4), Some([1; 4]));
        assert_eq!(route_group_is_spec(writer, 5), None);
        {
            let _inner = GroupRouteScope::enter(GroupRouteContext {
                writer: other,
                seq: 9,
                spec: false,
                spec_receive: false,
                writer_set: None,
                order: None,
                set_first_gsn: None,
            });
            assert_eq!(route_group_is_spec(writer, 4), None);
            assert_eq!(route_group_is_spec(other, 9), Some(false));
            registry.record_writer_group_dialect(
                other,
                crate::protocol::group::GroupDialect::Spec,
                Some([1; 4]),
            );
            assert_eq!(route_group_is_spec(other, 9), Some(false));
        }
        assert_eq!(route_group_is_spec(writer, 4), Some(true));
        assert_eq!(route_group_is_spec(other, 9), None);
        drop(_outer);
        assert_eq!(route_group_is_spec(writer, 4), None);
    }
}

#[cfg(test)]
mod ordered_interest_tests {
    use super::*;
    use crate::engine::demux::Topic;
    use crate::engine::Subscriber;
    use std::sync::Arc;

    struct Sink {
        ordered: bool,
    }

    impl Subscriber for Sink {
        fn topic_name(&self) -> &str {
            "ordered-interest"
        }
        fn requires_ordered_group(&self) -> bool {
            self.ordered
        }
        fn on_data(&self, _: &str, _: u64, _: &[u8]) {}
    }

    #[test]
    fn one_data_event_cannot_revive_a_departure_between_its_readers() {
        use crate::dds::GroupArrivalScope;
        use crate::engine::demux::GroupWriterTerminal;
        use crate::engine::subscriber::{DisposeKind, WriterDeparture};

        let registry = TopicRegistry::new();
        let writer = [0x51; 16];
        let publisher = [0x42; 4];
        registry.record_writer_group_dialect(
            writer,
            crate::protocol::group::GroupDialect::Spec,
            Some(publisher),
        );
        let state = registry.group_writer_terminal(&writer, publisher).unwrap();
        let mut topic = Topic::new("ordered-interest".to_string(), None);
        topic.add_subscriber(Arc::new(Sink { ordered: true }));
        ordered_group_scope(&topic, &registry, writer, 1, None, || {
            if let Some(first) = GroupArrivalScope::captured(writer) {
                assert!(registry.note_group_writer_alive_stamped(&writer, &first));
            }
            registry.notify_writer_departure(
                writer,
                DisposeKind::Unregistered,
                WriterDeparture::Unheard,
            );
            if let Some(second) = GroupArrivalScope::captured(writer) {
                assert!(
                    !registry.note_group_writer_alive_stamped(&writer, &second),
                    "an old DATA event revoked a newer departure"
                );
            }
        });
        assert!(GroupWriterTerminal::all_departed(std::slice::from_ref(&state)).is_some());
        ordered_group_scope(&topic, &registry, writer, 2, None, || {
            if let Some(fresh) = GroupArrivalScope::captured(writer) {
                assert!(registry.note_group_writer_alive_stamped(&writer, &fresh));
            }
        });
        assert!(
            GroupWriterTerminal::all_departed(&[state]).is_none(),
            "a fresh accepted DATA event did not revoke the prior absence proof"
        );
    }

    #[test]
    fn a_topic_without_ordered_readers_does_not_touch_route_order_context() {
        let registry = TopicRegistry::new();
        let mut topic = Topic::new("ordered-interest".to_string(), None);
        let ordinary: Arc<dyn Subscriber> = Arc::new(Sink { ordered: false });
        topic.add_subscriber(ordinary);
        let writer = [0x51; 16];
        let change = OrderedGroupChange {
            publisher: [0x52; 16],
            gsn: 7,
            writer_set: [3; 4],
        };
        let _outer = OrderedGroupScope::enter(writer, 9, Some(change));
        let untouched = ordered_group_scope(&topic, &registry, [0x53; 16], 1, None, || {
            route_ordered_group(writer, 9).map(|v| v.gsn)
        });
        assert_eq!(
            untouched,
            Some(7),
            "an ordinary topic entered the GROUP parser/TLS path"
        );
        assert_eq!(route_ordered_group(writer, 9).map(|v| v.gsn), Some(7));
    }

    #[test]
    fn coherent_route_identity_is_scoped_to_the_exact_change() {
        let writer = [0x61; 16];
        let change = OrderedGroupChange {
            publisher: [0x62; 16],
            gsn: 4,
            writer_set: [3; 4],
        };
        assert_eq!(route_ordered_group_set_first(change), None);
        {
            let _announced = GroupRouteScope::enter(GroupRouteContext {
                writer,
                seq: 9,
                spec: true,
                spec_receive: false,
                writer_set: Some(change.writer_set),
                order: Some(change),
                set_first_gsn: Some(2),
            });
            assert_eq!(route_ordered_group_set_first(change), Some(2));
            // An ordinary nested change cannot inherit the enclosing set.
            {
                let _ordinary = OrderedGroupScope::enter(writer, 9, Some(change));
                assert_eq!(route_ordered_group_set_first(change), None);
            }
            assert_eq!(route_ordered_group_set_first(change), Some(2));
            {
                let _coherent = OrderedGroupScope::enter_with_set(writer, 9, Some(change), Some(2));
                assert_eq!(route_ordered_group_set_first(change), Some(2));
                for other in [
                    OrderedGroupChange { gsn: 5, ..change },
                    OrderedGroupChange {
                        publisher: [0x63; 16],
                        ..change
                    },
                    OrderedGroupChange {
                        writer_set: [4; 4],
                        ..change
                    },
                ] {
                    assert_eq!(route_ordered_group_set_first(other), None);
                }
            }
        }
        assert_eq!(route_ordered_group_set_first(change), None);
    }

    #[test]
    fn ordered_interest_tracks_registration_and_exact_removal() {
        let registry = Arc::new(TopicRegistry::new());
        let ordinary: Arc<dyn Subscriber> = Arc::new(Sink { ordered: false });
        let ordered: Arc<dyn Subscriber> = Arc::new(Sink { ordered: true });
        let ordinary_token = registry.register_subscriber_scoped(ordinary).unwrap();
        assert!(!registry
            .get_topic("ordered-interest")
            .unwrap()
            .requires_ordered_group());
        let ordered_token = registry
            .register_subscriber_scoped(ordered.clone())
            .unwrap();
        registry.register_subscriber(ordered).unwrap();
        assert_eq!(
            registry
                .get_topic("ordered-interest")
                .unwrap()
                .subscriber_count(),
            2
        );
        assert!(registry
            .get_topic("ordered-interest")
            .unwrap()
            .requires_ordered_group());
        drop(ordered_token);
        assert!(!registry
            .get_topic("ordered-interest")
            .unwrap()
            .requires_ordered_group());
        drop(ordinary_token);
        assert!(!registry
            .get_topic("ordered-interest")
            .unwrap()
            .requires_ordered_group());
    }

    #[test]
    fn terminal_suppression_masks_and_restores_the_coherent_order_fallback() {
        let writer = [0x71; 16];
        let change = OrderedGroupChange {
            publisher: [0x72; 16],
            gsn: 2,
            writer_set: [3; 4],
        };
        let _group = GroupRouteScope::enter(GroupRouteContext {
            writer,
            seq: 9,
            spec: true,
            spec_receive: false,
            writer_set: Some(change.writer_set),
            order: Some(change),
            set_first_gsn: Some(1),
        });
        let _order = OrderedGroupScope::enter_with_set(writer, 9, Some(change), Some(1));
        assert_eq!(route_ordered_group(writer, 9).map(|c| c.gsn), Some(2));
        {
            let _suppressed = OrderedGroupScope::suppress(writer, 9);
            assert!(route_ordered_group(writer, 9).is_none());
            assert!(route_ordered_group_set_first(change).is_none());
            {
                let _nested = OrderedGroupScope::enter(writer, 10, Some(change));
                assert_eq!(route_ordered_group(writer, 10).map(|c| c.gsn), Some(2));
            }
            assert!(route_ordered_group(writer, 9).is_none());
        }
        assert_eq!(route_ordered_group(writer, 9).map(|c| c.gsn), Some(2));
        assert_eq!(route_ordered_group_set_first(change), Some(1));
    }
}
