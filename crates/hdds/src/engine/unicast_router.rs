// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Standalone RTPS message router for unicast transports (TCP, QUIC).
//!
//! This module provides a transport-agnostic function that takes
//! a raw RTPS message (header + submessages) and routes it through the existing
//! `TopicRegistry` / demux infrastructure.
//!
//! Unlike the multicast `router_loop` which consumes from an `ArrayQueue<(RxMeta, u8)>`,
//! this function is called directly by TCP/QUIC event handlers -- no ring buffer,
//! no dedicated thread. The caller owns the dispatch loop.
//!
//! # Data flow
//! ```text
//! TCP poll()  --> MessageReceived { payload } --> route_raw_rtps_message_from_stream()
//! QUIC event  --> MessageReceived { payload } --> route_raw_rtps_message_from_stream()
//!                                                   |-- classify_rtps(payload)
//!                                                   |-- Data      -> route_data_packet()
//!                                                   |-- DataFrag  -> route_data_frag_packet()
//!                                                   |-- Heartbeat -> reorder gates seeded,
//!                                                   |                registry.deliver_heartbeat()
//!                                                   |-- Gap       -> reorder gates released,
//!                                                   |                embedded HEARTBEATs answered
//!                                                   |-- AckNack   -> registry.deliver_nack()
//!                                                   `-- the rest  -> dropped/ignored, BY NAME
//! ```

use std::sync::atomic::Ordering;
use std::sync::Mutex;

use crate::core::discovery::multicast::classifier::walk::Part;
use crate::core::discovery::multicast::Origin;
use crate::core::discovery::multicast::{classify_rtps, PacketKind};
use crate::core::discovery::FragmentBuffer;
use crate::engine::demux::{StreamReply, TopicRegistry};
use crate::engine::router::{
    route_data_frag_packet, route_data_packet, RouteStatus, RouterMetrics,
};
use crate::engine::writer_control::{answer_piggybacked_control, apply_writer_control, Scope};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

// ============================================================================
// Result type
// ============================================================================

/// Outcome of routing a raw RTPS message from a unicast transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnicastRouteOutcome {
    /// Successfully delivered to at least one subscriber.
    Delivered,
    /// Packet was valid but no subscriber matched (orphaned).
    Orphaned,
    /// Packet was dropped (parse error, invalid submessage, etc.).
    Dropped,
    /// Packet type not handled by unicast router (SPDP, SEDP, NackFrag, etc.).
    Ignored,
}

// ============================================================================
// Main entry point
// ============================================================================

/// Route a raw RTPS message through the demux/topic registry.
///
/// This is the **single entry point** for TCP and QUIC transports to feed
/// received data into the HDDS routing engine.
///
/// # Arguments
/// * `payload`         -- Complete RTPS message (header at offset 0 + submessages)
/// * `registry`        -- Shared topic registry (thread-safe)
/// * `metrics`         -- Shared router metrics (atomic counters)
/// * `fragment_buffer` -- Optional fragment reassembly buffer for DATA_FRAG.
///   Pass `None` if fragmentation is not expected on this transport.
///
/// # Destination
/// This function knows no participant, so it applies every submessage of
/// `payload`, including one an INFO_DST destines to another participant
/// (RTPS 2.5 8.3.8.8). A participant's own TCP/QUIC receive thread removes
/// those first; a caller that receives for a participant must do the same.
///
/// # Source
/// Each submessage is routed with its own source: a message carrying
/// INFO_SRC (RTPS 2.5 8.3.8.10) is routed as one message per source, and
/// the outcome is the best of theirs.
///
/// # Answers
/// This entry point knows no connection: a HEARTBEAT whose sender is the
/// message's source is answered as one with no address at all (the
/// reader's multicast fallback). [`route_raw_rtps_message_from_stream`]
/// answers it on the connection instead. Behind an INFO_SRC the other end
/// is not the source (8.3.8.10): the reader answers through its WriterProxy
/// alone, whichever entry point is used. An INFO_REPLY changes none of
/// this: only a Reliable StatelessWriter reads the locator it names
/// (8.4.8.2.6), and every answering endpoint here is stateful.
///
/// # Thread safety
/// All arguments are designed for concurrent access. This function can be called
/// from any thread or async task without external synchronisation.
///
pub fn route_raw_rtps_message(
    payload: &[u8],
    registry: &TopicRegistry,
    metrics: &RouterMetrics,
    fragment_buffer: Option<&Mutex<FragmentBuffer>>,
) -> UnicastRouteOutcome {
    route(
        payload,
        registry,
        metrics,
        fragment_buffer,
        Answer::NoAddress,
    )
}

/// [`route_raw_rtps_message`] for a message received on `connection`, a
/// stream (TCP, QUIC) whose other end sent it: every answer the message's
/// source is owed goes back on `connection` (RTPS 2.5 8.3.4: the reply
/// locator starts as the source of the message). A part behind an
/// INFO_SRC came from someone the other end only forwarded for, and is
/// answered through the reader's WriterProxy, not on the connection
/// (8.3.8.10). An INFO_REPLY does not redirect anything (see
/// [`route_raw_rtps_message`]).
pub fn route_raw_rtps_message_from_stream(
    payload: &[u8],
    registry: &TopicRegistry,
    metrics: &RouterMetrics,
    fragment_buffer: Option<&Mutex<FragmentBuffer>>,
    connection: &dyn StreamReply,
) -> UnicastRouteOutcome {
    route(
        payload,
        registry,
        metrics,
        fragment_buffer,
        Answer::Stream(connection),
    )
}

/// A stream has no datagram sender: the `from` of an `Origin` built for a
/// part of a stream message, for logs only (`Origin::from` is never a
/// destination). Its `reply` is never used for a direct part either: such
/// a part is answered as `Answer::Stream` or `Answer::NoAddress`.
const NO_DATAGRAM_SENDER: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0));

/// Where the answers to one message (one part of a received message) go.
#[derive(Clone, Copy)]
pub(crate) enum Answer<'a> {
    /// The message's source sent it, on no connection this door knows:
    /// the handlers' no-address fallback.
    NoAddress,
    /// The message's source sent it on this connection.
    Stream(&'a dyn StreamReply),
    /// Behind an INFO_SRC: the other end only forwarded the message, so
    /// the answer goes through the reader's WriterProxy, never the
    /// connection.
    Origin(Origin),
}

impl<'a> Answer<'a> {
    /// The answer for `part` of a message received with `base`.
    fn for_part(base: Self, part: &Part) -> Self {
        if part.relayed {
            Answer::Origin(part.origin(NO_DATAGRAM_SENDER))
        } else {
            base
        }
    }

    /// Hand the message's HEARTBEATs to the handlers that answer them.
    pub(crate) fn deliver_heartbeat(self, registry: &TopicRegistry, payload: &[u8]) -> usize {
        match self {
            Answer::NoAddress => registry.deliver_heartbeat(payload, None),
            Answer::Stream(connection) => {
                registry.deliver_heartbeat_over_stream(payload, connection)
            }
            Answer::Origin(origin) => registry.deliver_heartbeat(payload, Some(origin)),
        }
    }
}

fn route(
    payload: &[u8],
    registry: &TopicRegistry,
    metrics: &RouterMetrics,
    fragment_buffer: Option<&Mutex<FragmentBuffer>>,
    base: Answer<'_>,
) -> UnicastRouteOutcome {
    use crate::core::discovery::multicast::classifier::walk::{split_by_receiver_state, Sources};
    match split_by_receiver_state(payload) {
        Sources::One(message) => {
            route_one_source(message, registry, metrics, fragment_buffer, base)
        }
        Sources::Split(parts) => parts
            .iter()
            .map(|part| {
                route_one_source(
                    &part.message,
                    registry,
                    metrics,
                    fragment_buffer,
                    Answer::for_part(base, part),
                )
            })
            .min_by_key(|outcome| match outcome {
                UnicastRouteOutcome::Delivered => 0,
                UnicastRouteOutcome::Orphaned => 1,
                UnicastRouteOutcome::Ignored => 2,
                UnicastRouteOutcome::Dropped => 3,
            })
            .unwrap_or(UnicastRouteOutcome::Ignored),
    }
}

/// `route_raw_rtps_message` for a message whose submessages all have the
/// source its header names.
fn route_one_source(
    payload: &[u8],
    registry: &TopicRegistry,
    metrics: &RouterMetrics,
    fragment_buffer: Option<&Mutex<FragmentBuffer>>,
    answer: Answer<'_>,
) -> UnicastRouteOutcome {
    // Step 1: Classify the RTPS message
    let (kind, data_offset, frag_meta, _rtps_ctx) = classify_rtps(payload);

    let len = payload.len();

    // Step 2: Dispatch based on submessage type
    match kind {
        // The commonest HEARTBEAT on the wire is not a standalone one: a
        // reliable writer piggybacks it on its DATA, `[INFO_TS, DATA,
        // HEARTBEAT]`, and a replay trails a GAP the same way. The classifier
        // names such a datagram by its DATA, so its controls arrive HERE and
        // are applied after the sample, as the UDP listener does for every
        // kind but HEARTBEAT, ACKNACK and NACK_FRAG.
        PacketKind::Data => {
            let status = route_data_packet(payload, len, data_offset, registry, metrics);
            answer_piggybacked_control(payload, registry, metrics, kind, answer, Scope::All);
            outcome_of(status)
        }

        PacketKind::DataFrag => {
            let outcome = match fragment_buffer {
                Some(fb) => outcome_of(route_data_frag_packet(
                    payload,
                    len,
                    data_offset,
                    frag_meta.as_ref(),
                    fb,
                    registry,
                    metrics,
                )),
                None => {
                    log::warn!(
                        "[unicast-router] DATA_FRAG received but no fragment buffer configured"
                    );
                    metrics.delivery_errors.fetch_add(1, Ordering::Relaxed);
                    UnicastRouteOutcome::Dropped
                }
            };
            // Whatever became of the fragment, the controls riding with it
            // still describe the writer; the UDP listener applies them either
            // way, and so does this door.
            answer_piggybacked_control(payload, registry, metrics, kind, answer, Scope::All);
            outcome
        }

        // A HEARTBEAT tells two different things to two different parties:
        // the reader's reliability state machine (answered with an ACKNACK,
        // `deliver_heartbeat`) and the reader's reorder gate (where the
        // writer's history starts). This door must tell both: a non-volatile
        // reader's gate is seeded by nothing else, so without it every sample
        // received through TCP or QUIC would be held forever.
        PacketKind::Heartbeat => {
            apply_writer_control(payload, registry, PacketKind::Heartbeat, Scope::All);
            let errors = answer.deliver_heartbeat(registry, payload);
            if errors > 0 {
                metrics
                    .delivery_errors
                    .fetch_add(errors as u64, Ordering::Relaxed);
            }
            UnicastRouteOutcome::Delivered
        }

        // A GAP says which sequences the writer will never send (RTPS v2.5
        // Sec.8.3.8.4); a reader waiting on them waits forever without it.
        // This door had no arm for it: the GAP fell into the wildcard below
        // and was dropped with a debug line.
        //
        // A durable replay sends `[INFO_DST, GAP, HEARTBEAT]`, and the
        // classifier names that datagram by its first submessage, so the
        // HEARTBEAT behind the GAP arrives HERE. It is answered like one that
        // leads its datagram - `deliver_heartbeat` services every HEARTBEAT in
        // the datagram, wherever it sits.
        PacketKind::Gap => {
            answer_piggybacked_control(payload, registry, metrics, kind, answer, Scope::All);
            UnicastRouteOutcome::Delivered
        }

        PacketKind::AckNack => {
            // For raw RTPS ACKNACK packets the NackHandler extracts the reader
            // GUID prefix from bytes 8..20 internally (via parse_acknack_submessage).
            // Pass None here; the handler resolves the GUID from the packet itself.
            // The repairs take the writer's own data path (UDP, see
            // `transport::tcp`), to the reader's discovered locator: a
            // StatefulWriter answers through its ReaderProxy (RTPS 2.5
            // 8.4.9.2), never an INFO_REPLY locator.
            let errors = registry.deliver_nack(payload, None);
            if errors > 0 {
                metrics
                    .delivery_errors
                    .fetch_add(errors as u64, Ordering::Relaxed);
            }
            UnicastRouteOutcome::Delivered
        }

        // NackFrag and HeartbeatFrag require response generation (sending NACK_FRAG back)
        // which needs transport handle + our_guid_prefix. Not handled here yet.
        PacketKind::NackFrag | PacketKind::HeartbeatFrag => {
            log::debug!(
                "[unicast-router] {:?} ({} bytes) -- deferred (needs transport for response)",
                kind,
                len
            );
            UnicastRouteOutcome::Ignored
        }

        // Discovery packets (SPDP, SEDP) should be handled by discovery FSM, not user router
        PacketKind::SPDP | PacketKind::SEDP | PacketKind::TypeLookup => {
            log::trace!(
                "[unicast-router] {:?} packet ({} bytes) -- ignored (discovery layer)",
                kind,
                len
            );
            UnicastRouteOutcome::Ignored
        }

        // INFO submessages are context-setting, not routable
        PacketKind::InfoTs | PacketKind::InfoSrc | PacketKind::InfoDst | PacketKind::InfoReply => {
            log::trace!("[unicast-router] {:?} -- context submessage, ignored", kind);
            UnicastRouteOutcome::Ignored
        }

        PacketKind::Invalid => {
            log::debug!(
                "[unicast-router] Invalid RTPS packet ({} bytes), dropping",
                len
            );
            metrics.delivery_errors.fetch_add(1, Ordering::Relaxed);
            UnicastRouteOutcome::Dropped
        }

        // A well-formed RTPS datagram in which nothing could be believed:
        // every submessage the classifier looked at either declared a body
        // too short to hold its own fields or described no fragment. Counted
        // with `Invalid`, because the two are the same event for whoever
        // reads these numbers - a datagram arrived and carried nothing.
        //
        // The counter is here because such a datagram could otherwise be
        // classified `DataFrag`, go to the fragment path, find no fragment and
        // be counted there. Refusing it earlier is right, and dropping it
        // earlier WITHOUT a counter would trade a counted drop for a silent one.
        PacketKind::Unknown => {
            log::debug!(
                "[unicast-router] no submessage of this {}-byte datagram described itself, dropping",
                len
            );
            metrics.delivery_errors.fetch_add(1, Ordering::Relaxed);
            UnicastRouteOutcome::Dropped
        }

        // Builtin traffic this door has no consumer for, and padding. NAMED,
        // not swept up by a wildcard: a wildcard here could silently swallow
        // a GAP, and a new `PacketKind` must not compile until somebody
        // decides what this door does with it.
        PacketKind::Pad
        | PacketKind::Departure
        | PacketKind::ParticipantMessage
        | PacketKind::UnknownBuiltin
        | PacketKind::SecureSPDP
        | PacketKind::SecureSEDP
        | PacketKind::SecureVolatile
        | PacketKind::Stateless => {
            log::debug!(
                "[unicast-router] Unhandled {:?} ({} bytes), dropping",
                kind,
                len
            );
            UnicastRouteOutcome::Dropped
        }
    }
}

fn outcome_of(status: RouteStatus) -> UnicastRouteOutcome {
    match status {
        RouteStatus::Delivered => UnicastRouteOutcome::Delivered,
        RouteStatus::Orphaned => UnicastRouteOutcome::Orphaned,
        RouteStatus::Dropped => UnicastRouteOutcome::Dropped,
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::discovery::multicast::scan_all_data_frags;

    fn make_metrics() -> RouterMetrics {
        RouterMetrics::new()
    }

    /// One DATA_FRAG submessage, behind the INFO_TS every writer stamps.
    ///
    /// The four framing fields are arguments because they travel together on
    /// the wire and the readers derive everything from them as a group
    /// (RTPS v2.5 Sec.8.3.8.3); a fixture that sets one in isolation describes
    /// a submessage no writer emits. `payload_len` is separate on purpose:
    /// a submessage that carries FEWER octets than it declares is the shape
    /// that proves a slice is clipped against its own submessage.
    ///
    /// The INFO_TS in front is not decoration: a bound that answers with the
    /// FIRST submessage of the datagram is right by accident when the
    /// DATA_FRAG is first, and a mutation proved exactly that once.
    fn a_data_frag(
        frags_in_submessage: u16,
        frag_size: u16,
        sample_size: u32,
        payload_len: usize,
    ) -> (Vec<u8>, usize) {
        use crate::core::rtps_constants::{RTPS_VERSION_MAJOR, RTPS_VERSION_MINOR};

        // 4 submessage header + extraFlags 2 + octetsToInlineQos 2 +
        // readerEntityId 4 + writerEntityId 4 + writerSN 8 +
        // fragmentStartingNum 4 + fragmentsInSubmessage 2 + fragmentSize 2 +
        // sampleSize 4.
        const FIXED: usize = 32;

        let mut p = vec![0u8; 20];
        p[0..4].copy_from_slice(b"RTPS");
        p[4] = RTPS_VERSION_MAJOR;
        p[5] = RTPS_VERSION_MINOR;
        p[6..8].copy_from_slice(&crate::protocol::constants::HDDS_VENDOR_ID);
        p[8..20].copy_from_slice(&[0x11u8; 12]);

        p.push(0x09); // INFO_TS
        p.push(0x01);
        p.extend_from_slice(&8u16.to_le_bytes());
        p.extend_from_slice(&0i32.to_le_bytes()); // Time_t seconds
        p.extend_from_slice(&0u32.to_le_bytes()); // Time_t fraction

        let data_frag_start = p.len();
        p.push(0x16); // DATA_FRAG
        p.push(0x01); // E only: little-endian, no inline QoS
        p.extend_from_slice(&((FIXED + payload_len) as u16).to_le_bytes());
        p.extend_from_slice(&0u16.to_le_bytes()); // extraFlags
        p.extend_from_slice(&28u16.to_le_bytes()); // octetsToInlineQos
        p.extend_from_slice(&[0x00, 0x00, 0x12, 0x07]); // readerEntityId
        p.extend_from_slice(&[0x00, 0x00, 0x12, 0x02]); // writerEntityId
        p.extend_from_slice(&[0u8; 8]); // writerSN
        p.extend_from_slice(&1u32.to_le_bytes()); // fragmentStartingNum
        p.extend_from_slice(&frags_in_submessage.to_le_bytes());
        p.extend_from_slice(&frag_size.to_le_bytes());
        p.extend_from_slice(&sample_size.to_le_bytes());
        let payload_offset = p.len();
        for i in 0..payload_len {
            let step = usize::from(frag_size).max(1);
            p.push(0xA1u8.wrapping_add((i / step) as u8));
        }

        assert_eq!(
            p.len() - payload_offset,
            payload_len,
            "fixture: the submessage must carry the octets it was asked for"
        );
        assert!(
            data_frag_start > 20,
            "fixture: a submessage must precede the DATA_FRAG, or a bound that \
             answers with the first submessage of the datagram passes by accident"
        );
        (p, payload_offset)
    }

    /// Append the HEARTBEAT a reliable writer batches behind its fragments,
    /// and answer where it starts. 32 octets, distinct from any payload byte.
    fn then_a_heartbeat(p: &mut Vec<u8>) -> usize {
        let start = p.len();
        p.push(0x07); // HEARTBEAT
        p.push(0x01);
        p.extend_from_slice(&28u16.to_le_bytes());
        p.extend_from_slice(&[0xBBu8; 28]);
        assert_eq!(p.len() - start, 32, "fixture: a HEARTBEAT is 4 + 28 octets");
        start
    }

    /// Fragment 1 of 2 of a 16-octet sample, 8 octets of payload, then a
    /// HEARTBEAT - the ordinary shape of a reliable writer's datagram.
    fn a_fragment_followed_by_a_heartbeat() -> (Vec<u8>, usize) {
        const FRAG_SIZE: u16 = 8;
        let (mut p, payload_offset) = a_data_frag(1, FRAG_SIZE, 16, usize::from(FRAG_SIZE));
        let heartbeat_start = then_a_heartbeat(&mut p);
        assert_eq!(
            heartbeat_start - payload_offset,
            usize::from(FRAG_SIZE),
            "fixture: the fragment payload must stop where the HEARTBEAT starts"
        );
        (p, payload_offset)
    }

    /// One DATA_FRAG carrying `frags_in_submessage` fragments of `frag_size`
    /// octets: how a peer sends a sample that fits one datagram but is cut
    /// into several fragments (RTPS v2.5 Sec.8.3.8.3).
    fn a_datagram_packing(frags_in_submessage: u16, frag_size: u16) -> (Vec<u8>, usize) {
        let payload_len = usize::from(frags_in_submessage) * usize::from(frag_size);
        a_data_frag(
            frags_in_submessage,
            frag_size,
            payload_len as u32,
            payload_len,
        )
    }

    /// Drive one datagram into both router entry points and answer what each
    /// door's reassembly buffer holds afterwards.
    ///
    /// For the fixtures whose fragment must be REFUSED: a refusal has no
    /// sample to complete, and a test that can only read a completed sample
    /// cannot tell "refused" from "buffered and still waiting".
    fn what_both_doors_buffered(
        datagram: &[u8],
        payload_offset: usize,
    ) -> Vec<(&'static str, usize)> {
        let (_kind, classified_offset, frag_meta, _ctx) = classify_rtps(datagram);
        assert_eq!(
            classified_offset,
            Some(payload_offset),
            "fixture: the classifier must find the payload where we put it"
        );
        let meta = frag_meta.expect("the classifier publishes fragment metadata");

        let registry = TopicRegistry::new();
        let metrics = make_metrics();
        let from_unicast = Mutex::new(FragmentBuffer::new(8, 5000));
        let from_multicast = Mutex::new(FragmentBuffer::new(8, 5000));
        let peer = crate::core::discovery::multicast::Origin::direct(
            "198.51.100.9:7410".parse().expect("test peer address"),
        );

        let _ = route_data_frag_packet(
            datagram,
            datagram.len(),
            Some(payload_offset),
            Some(&meta),
            &from_unicast,
            &registry,
            &metrics,
        );
        let _ = crate::engine::router::route_data_frag_packet_with_addr(
            datagram,
            datagram.len(),
            Some(payload_offset),
            Some(&meta),
            peer,
            &from_multicast,
            &registry,
            &metrics,
        );

        [
            ("unicast", &from_unicast),
            ("multicast fallback", &from_multicast),
        ]
        .into_iter()
        .map(|(door, buffer)| {
            (
                door,
                buffer.lock().expect("fragment buffer lock").pending_count(),
            )
        })
        .collect()
    }

    /// A fragment shorter than its geometry is refused, not completed short.
    ///
    /// `fragmentSize` is 16 and only 8 octets are there, with a HEARTBEAT
    /// behind, and the datagram goes through the SCAN (asserted below).
    ///
    /// Two rules meet here and both are needed. The scan clips the slice to
    /// the submessage that carries it, so fragment 1 arrives with 8 octets
    /// rather than 8 of sample and 8 of the HEARTBEAT's header. The buffer
    /// then refuses it, because 8 is not the 16 the geometry gives a
    /// non-last fragment - and completion is a COUNT, so a short fragment
    /// admitted is a sample completed short with every octet behind the hole
    /// in the wrong place.
    ///
    /// Remove either one and this fixture passes for the wrong reason:
    /// without the clip the slice is exactly 16 octets and the length rule
    /// waves it through with the neighbour's header inside it; without the
    /// length rule the sample completes at 24 octets for a declared 32.
    #[test]
    fn a_fragment_shorter_than_its_geometry_is_refused_at_both_doors() {
        let (mut datagram, payload_offset) = a_data_frag(1, 16, 32, 8);
        then_a_heartbeat(&mut datagram);
        assert_eq!(
            scan_all_data_frags(&datagram).len(),
            1,
            "fixture: this datagram must go through the SCAN, or the test \
             proves a rule on a door it never reaches"
        );
        assert_eq!(
            scan_all_data_frags(&datagram)[0].payload.len(),
            8,
            "fixture: the scan clips the slice to the submessage, which is \
             what leaves it short of the declared fragmentSize"
        );

        for (door, pending) in what_both_doors_buffered(&datagram, payload_offset) {
            assert_eq!(
                pending, 0,
                "{door}: a fragment short of its declared fragmentSize leaves \
                 nothing waiting to be completed around it"
            );
        }
    }

    /// The same rule on the FALLBACK path, which the scan never reaches.
    ///
    /// A DATA_FRAG whose body stops at its own 36th octet carries no payload
    /// at all. Its geometry is perfectly ordinary - fragment 1 of 2, 8 octets
    /// each, a 16-octet sample - so the classifier names the fragment, while
    /// `scan_all_data_frags` declines the submessage for want of anything to
    /// slice. That is the way into the fallback, and the only fixture that
    /// can prove the fallback's own bound.
    ///
    /// Bounded, the slice is empty and the buffer refuses it: nothing waits.
    /// Unbounded, it runs to the end of the datagram and picks up the 32
    /// octets of the HEARTBEAT behind - which the length rule then trims to
    /// exactly the 8 a fragment of this sample holds, and admits. The two
    /// rules do not cover for each other here: only the bound knows those
    /// octets belong to somebody else.
    ///
    /// Written because making this door scan first made the previous proof
    /// VACUOUS: deleting the fallback's bound stopped failing any test, since
    /// every fixture then went down the scanned path. A bound belongs at the
    /// door every path takes, and its proof test at THAT door - the same
    /// lesson, from the other side.
    #[test]
    fn the_fallback_fragment_stops_where_its_submessage_does() {
        let (mut datagram, payload_offset) = a_data_frag(1, 8, 16, 0);
        then_a_heartbeat(&mut datagram);
        assert!(
            scan_all_data_frags(&datagram).is_empty(),
            "fixture: the scan must DECLINE this datagram, or the fallback is \
             never entered and the bound under test is never executed"
        );
        assert_eq!(
            crate::core::discovery::multicast::classifier::submessage_end_for_payload(
                &datagram,
                payload_offset
            ),
            Some(payload_offset),
            "fixture: the submessage ends exactly where its payload would start"
        );
        assert!(
            datagram.len() > payload_offset,
            "fixture: the octets an unbounded read would take must BE there, \
             or the bound passes for want of anything behind it"
        );

        for (door, pending) in what_both_doors_buffered(&datagram, payload_offset) {
            assert_eq!(
                pending, 0,
                "{door}: a submessage carrying no fragment must not be \
                 completed out of the submessage behind it"
            );
        }
    }

    /// A peer that packs its fragments must not be a peer whose samples never
    /// arrive.
    ///
    /// `fragmentsInSubmessage` exists so a writer can put several fragments of
    /// one sample in a single submessage; the whole 32-octet sample below is
    /// sent as four packed fragments of 8, in one datagram, and there is no
    /// fragment 2, 3 or 4 still to come - they are already here.
    ///
    /// This door read the classifier's metadata, which names ONE submessage
    /// and ONE fragment number. It therefore buffered "fragment 1 of 4"
    /// holding all 32 octets and waited for the three it was holding:
    /// `RouteStatus::Delivered`, one fragment pending, no sample ever
    /// delivered. The multicast receive path has scanned the datagram since
    /// the bundling fix; this door never received that remedy.
    ///
    /// HDDS never sends this shape itself - its own splitter writes
    /// `fragments_in_submessage = 1` - so nothing HDDS-to-HDDS could show it.
    #[test]
    fn a_datagram_that_packs_its_fragments_is_reassembled() {
        const FRAGS: u16 = 4;
        const FRAG_SIZE: u16 = 8;

        let (datagram, payload_offset) = a_datagram_packing(FRAGS, FRAG_SIZE);
        let (_kind, classified_offset, frag_meta, _ctx) = classify_rtps(&datagram);
        let meta = frag_meta.expect("the classifier publishes fragment metadata");
        assert_eq!(classified_offset, Some(payload_offset));
        assert_eq!(
            (meta.frag_num, meta.total_frags()),
            (1, u32::from(FRAGS)),
            "fixture: the classifier names one fragment out of four, which is \
             exactly why reading it alone loses the other three"
        );

        let registry = TopicRegistry::new();
        let metrics = make_metrics();
        let buffer = Mutex::new(FragmentBuffer::new(8, 5000));

        let status = route_data_frag_packet(
            &datagram,
            datagram.len(),
            Some(payload_offset),
            Some(&meta),
            &buffer,
            &registry,
            &metrics,
        );

        assert_eq!(
            buffer.lock().expect("fragment buffer lock").pending_count(),
            0,
            "the sample is whole in this datagram: nothing may be left waiting"
        );
        assert_ne!(
            status,
            RouteStatus::Delivered,
            "a reassembled sample reaches topic routing; `Delivered` here is \
             the old answer, which meant 'buffered, waiting for more'"
        );
    }

    /// The ordinary shape a reliable writer emits - one fragment with a
    /// HEARTBEAT batched behind it - reassembles to exactly its own octets,
    /// through both entry points.
    ///
    /// Without this bound, fragment 1 would arrive carrying its 8 octets plus
    /// the 32 octets of the HEARTBEAT, and the sample would come out 48
    /// octets long instead of 16.
    ///
    /// This fixture does not prove a BOUND: it declares exactly the octets
    /// it carries, so neither clip has anything to cut. The two bound rules
    /// have a test each, on the door that executes them -
    /// `a_fragment_shorter_than_its_geometry_is_refused_at_both_doors` and
    /// `the_fallback_fragment_stops_where_its_submessage_does`. What this
    /// one pins is the common case itself.
    #[test]
    fn a_fragment_stops_where_its_submessage_does() {
        let (datagram, payload_offset) = a_fragment_followed_by_a_heartbeat();
        let (kind, classified_offset, frag_meta, _ctx) = classify_rtps(&datagram);
        assert_eq!(kind, PacketKind::DataFrag);
        assert_eq!(
            classified_offset,
            Some(payload_offset),
            "fixture: the classifier must find the payload where we put it"
        );
        let meta = frag_meta.expect("the classifier publishes fragment metadata");
        assert_eq!((meta.frag_num, meta.total_frags()), (1, 2));

        // Both entry points, because they are two copies of the same body:
        // the unicast transport calls one, the multicast router's fallback
        // calls the other, and a bound written in only one of them is half a
        // rule.
        let registry = TopicRegistry::new();
        let metrics = make_metrics();
        let from_unicast = Mutex::new(FragmentBuffer::new(8, 5000));
        let from_multicast = Mutex::new(FragmentBuffer::new(8, 5000));
        let peer = crate::core::discovery::multicast::Origin::direct(
            "198.51.100.9:7410".parse().expect("test peer address"),
        );

        let _ = route_data_frag_packet(
            &datagram,
            datagram.len(),
            Some(payload_offset),
            Some(&meta),
            &from_unicast,
            &registry,
            &metrics,
        );
        let _ = crate::engine::router::route_data_frag_packet_with_addr(
            &datagram,
            datagram.len(),
            Some(payload_offset),
            Some(&meta),
            peer,
            &from_multicast,
            &registry,
            &metrics,
        );

        // Complete each sample from the other side and read what fragment 1
        // actually contributed.
        for (door, buffer) in [
            ("unicast", &from_unicast),
            ("multicast fallback", &from_multicast),
        ] {
            let sample = buffer
                .lock()
                .expect("fragment buffer lock")
                .insert_fragment(
                    meta.writer_guid,
                    meta.seq_num,
                    2,
                    meta.geometry,
                    vec![0xCCu8; 8],
                )
                .expect("the sample completes once both fragments are in");

            assert_eq!(
                sample.len(),
                16,
                "{door}: fragment 1 carried {} octets, so everything past its \
                 submessage came with it",
                sample.len() - 8
            );
            assert_eq!(&sample[..8], &[0xA1u8; 8], "{door}: fragment 1 bytes");
            assert_eq!(&sample[8..], &[0xCCu8; 8], "{door}: fragment 2 bytes");
        }
    }

    #[test]
    fn test_invalid_packet_returns_dropped() {
        let registry = TopicRegistry::new();
        let metrics = make_metrics();

        // Too short to be valid RTPS
        let result = route_raw_rtps_message(&[0u8; 4], &registry, &metrics, None);
        assert_eq!(result, UnicastRouteOutcome::Dropped);
    }

    #[test]
    fn test_empty_payload_returns_dropped() {
        let registry = TopicRegistry::new();
        let metrics = make_metrics();

        let result = route_raw_rtps_message(&[], &registry, &metrics, None);
        assert_eq!(result, UnicastRouteOutcome::Dropped);
    }

    #[test]
    fn test_valid_rtps_no_submessage() {
        let registry = TopicRegistry::new();
        let metrics = make_metrics();

        // Valid RTPS header but no submessages
        let mut pkt = vec![0u8; 20];
        pkt[0..4].copy_from_slice(b"RTPS");
        pkt[4] = 0x02; // version major
        pkt[5] = 0x03; // version minor

        let result = route_raw_rtps_message(&pkt, &registry, &metrics, None);
        // classify_rtps returns Unknown for header-only -> Dropped
        assert!(
            result == UnicastRouteOutcome::Dropped || result == UnicastRouteOutcome::Ignored,
            "Expected Dropped or Ignored for header-only RTPS, got {:?}",
            result
        );
    }

    #[test]
    fn test_data_packet_no_subscribers() {
        let registry = TopicRegistry::new();
        let metrics = make_metrics();

        // Minimal RTPS DATA packet:
        // 20-byte header + 4-byte submessage header (DATA=0x15) + 20-byte DATA fields
        let mut pkt = vec![0u8; 44];
        pkt[0..4].copy_from_slice(b"RTPS");
        pkt[4] = 0x02;
        pkt[5] = 0x03;
        // Submessage at offset 20: DATA (0x15)
        pkt[20] = 0x15;
        pkt[21] = 0x01; // flags: little-endian
                        // octetsToNextHeader = 20 (enough for DATA submessage fields)
        pkt[22] = 20;
        pkt[23] = 0;

        let result = route_raw_rtps_message(&pkt, &registry, &metrics, None);
        // No topic registered, so should be Dropped or Orphaned
        assert!(
            result == UnicastRouteOutcome::Dropped || result == UnicastRouteOutcome::Orphaned,
            "Expected Dropped or Orphaned, got {:?}",
            result
        );
    }

    #[test]
    fn test_outcome_enum_completeness() {
        let outcomes = [
            UnicastRouteOutcome::Delivered,
            UnicastRouteOutcome::Orphaned,
            UnicastRouteOutcome::Dropped,
            UnicastRouteOutcome::Ignored,
        ];
        for o in &outcomes {
            let _ = format!("{:?}", o);
        }
    }

    #[test]
    fn test_data_frag_without_buffer_is_dropped() {
        let registry = TopicRegistry::new();
        let metrics = make_metrics();

        // Build a minimal DATA_FRAG packet (0x16)
        let mut pkt = vec![0u8; 60];
        pkt[0..4].copy_from_slice(b"RTPS");
        pkt[4] = 0x02;
        pkt[5] = 0x03;
        pkt[20] = 0x16; // DATA_FRAG submessage ID
        pkt[21] = 0x01;
        pkt[22] = 36; // octetsToNextHeader
        pkt[23] = 0;

        let result = route_raw_rtps_message(&pkt, &registry, &metrics, None);
        assert_eq!(result, UnicastRouteOutcome::Dropped);
        assert!(metrics.delivery_errors.load(Ordering::Relaxed) > 0);
    }

    /// A DATA_FRAG that leaves its own fragment fields out of its body, and
    /// the submessage whose octets sit where those fields would be.
    ///
    /// The DATA_FRAG declares a 20-octet body: twelve short of the 32 fixed
    /// octets RTPS v2.5 Sec.8.3.8.3 gives it. The PAD behind it is four
    /// header octets and a body; read twelve octets early, its header is
    /// little-endian `01 00 00 00` = fragmentStartingNum 1, and its body
    /// then reads as fragmentsInSubmessage 1, fragmentSize 8, sampleSize 16.
    fn a_data_frag_described_by_the_submessage_behind_it() -> Vec<u8> {
        use crate::core::rtps_constants::{RTPS_VERSION_MAJOR, RTPS_VERSION_MINOR};

        let mut p = vec![0u8; 20];
        p[0..4].copy_from_slice(b"RTPS");
        p[4] = RTPS_VERSION_MAJOR;
        p[5] = RTPS_VERSION_MINOR;
        p[6..8].copy_from_slice(&crate::protocol::constants::HDDS_VENDOR_ID);
        p[8..20].copy_from_slice(&[0x11u8; 12]);

        p.push(0x16); // DATA_FRAG
        p.push(0x01); // E only
        p.extend_from_slice(&20u16.to_le_bytes()); // a body it cannot fill
        p.extend_from_slice(&0u16.to_le_bytes()); // extraFlags
        p.extend_from_slice(&28u16.to_le_bytes()); // octetsToInlineQos
        p.extend_from_slice(&[0x00, 0x00, 0x12, 0x07]); // readerEntityId
        p.extend_from_slice(&[0x00, 0x00, 0x12, 0x02]); // writerEntityId
        p.extend_from_slice(&[0u8; 4]); // writerSN high
        p.extend_from_slice(&5u32.to_le_bytes()); // writerSN low
        assert_eq!(p.len(), 44, "fixture: the DATA_FRAG body ends here");

        p.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]); // PAD
        p.extend_from_slice(&1u16.to_le_bytes());
        p.extend_from_slice(&8u16.to_le_bytes());
        p.extend_from_slice(&16u32.to_le_bytes());
        p.extend_from_slice(&[0xDEu8; 16]);
        assert!(
            p.len() >= 20 + 36,
            "fixture: the missing octets must be present in the DATAGRAM, or \
             the reader refuses this for the right answer by accident"
        );
        p
    }

    /// Nothing of the submessage next door reaches the reassembly buffer.
    ///
    /// Driven exactly as production does it: the classifier is asked what the
    /// datagram is, and whatever it answers is what the router is handed.
    /// Measured before the classifier bounded its reads, on this datagram:
    /// status Delivered, one pending sample, and completing it gave sixteen
    /// octets of the PAD followed by the peer's real fragment 2.
    #[test]
    fn a_data_frag_shorter_than_its_own_header_buffers_nothing() {
        let datagram = a_data_frag_described_by_the_submessage_behind_it();
        let (_kind, payload_offset, frag_meta, _ctx) = classify_rtps(&datagram);

        let registry = TopicRegistry::new();
        let metrics = make_metrics();
        let buffer = Mutex::new(FragmentBuffer::new(8, 5000));

        let status = crate::engine::router::route_data_frag_packet(
            &datagram,
            datagram.len(),
            payload_offset,
            frag_meta.as_ref(),
            &buffer,
            &registry,
            &metrics,
        );

        assert_eq!(
            buffer.lock().expect("fragment buffer").pending_count(),
            0,
            "a submessage that does not carry its own fragment fields must \
             leave nothing waiting for a fragment 2 that no writer will send"
        );
        assert_eq!(
            status,
            RouteStatus::Dropped,
            "and the datagram is dropped rather than reported as delivered"
        );
    }

    /// The two readers of one field group cannot disagree any more.
    ///
    /// `classify_data_frag` and `scan_all_data_frags` read the same four
    /// framing fields. The count is computed once: two copies, each with a
    /// `if fragmentSize > 0 { ceil } else { fragmentsInSubmessage }` fallback
    /// that the scan's own guards then refuse, would let the classifier
    /// announce a fragment the scan says does not exist, and the router's
    /// fallback would insert it on the classifier's word alone.
    ///
    /// The useful invariant is this one, not its converse: everything the scan
    /// emits, the classifier must have named a fragment. Stated as agreement,
    /// it holds in both directions and on the conforming row too.
    #[test]
    fn the_classifier_and_the_scan_agree_about_what_is_a_fragment() {
        // (fragmentsInSubmessage, fragmentSize, sampleSize, is a fragment)
        let grid: [(u16, u16, u32, bool); 8] = [
            (1, 8, 64, true),
            (1, 64, 64, true),
            (0, 0, 64, false),
            (1, 0, 64, false),
            (3, 0, 64, false),
            (0, 8, 64, false),
            (1, 8, 0, false),
            (0, 0, 0, false),
        ];

        for (frags_in, frag_size, sample_size, is_fragment) in grid {
            let payload_len = usize::from(frags_in.max(1)) * usize::from(frag_size.max(1));
            let (datagram, _at) = a_data_frag(frags_in, frag_size, sample_size, payload_len);
            let (_kind, _off, meta, _ctx) = classify_rtps(&datagram);
            let scanned = scan_all_data_frags(&datagram);

            assert_eq!(
                meta.is_some(),
                is_fragment,
                "fragmentsInSubmessage={frags_in} fragmentSize={frag_size} \
                 sampleSize={sample_size}: the classifier"
            );
            assert_eq!(
                !scanned.is_empty(),
                is_fragment,
                "fragmentsInSubmessage={frags_in} fragmentSize={frag_size} \
                 sampleSize={sample_size}: the scan"
            );
        }
    }

    /// One DATA_FRAG, one datagram, and a subscriber handed a complete sample.
    ///
    /// Regression guard for a payload-truncation defect.
    /// `fragmentSize = 0` with `fragmentsInSubmessage = 1` made the classifier
    /// announce "fragment 1 of 1"; the scan declines such a submessage, so the
    /// router took the fallback, and a set of one fragment out of one is
    /// complete on arrival. A subscriber received 28 octets - the submessage's
    /// body less its encapsulation header - as a whole sample of a declared
    /// sampleSize of 64, from a single datagram, with no loss and no second
    /// packet involved.
    #[test]
    fn a_datagram_declaring_a_zero_fragment_size_delivers_nothing() {
        let (datagram, _at) = a_data_frag(1, 0, 64, 32);
        let (_kind, payload_offset, frag_meta, _ctx) = classify_rtps(&datagram);
        assert!(
            frag_meta.is_none(),
            "a sample whose fragments are zero octets long has no fragments"
        );

        let registry = TopicRegistry::new();
        let metrics = make_metrics();
        let buffer = Mutex::new(FragmentBuffer::new(8, 5000));

        let status = crate::engine::router::route_data_frag_packet(
            &datagram,
            datagram.len(),
            payload_offset,
            frag_meta.as_ref(),
            &buffer,
            &registry,
            &metrics,
        );

        assert_eq!(
            status,
            RouteStatus::Dropped,
            "with nothing to name a fragment, the datagram is dropped"
        );
        assert_eq!(
            buffer.lock().expect("fragment buffer").pending_count(),
            0,
            "and nothing is delivered or left waiting"
        );
    }

    /// The TCP/QUIC door hands a HEARTBEAT or GAP to the reader its
    /// readerId names (RTPS v2.5 Sec.8.3.8.4, 8.3.8.6), as the UDP door
    /// does: a HEARTBEAT addressed to reader A seeds A's gate only, a GAP
    /// addressed to reader B releases B's only.
    #[test]
    fn an_addressed_heartbeat_or_gap_reaches_the_reader_it_names() {
        use crate::engine::Subscriber;
        use std::sync::Arc;

        type Log = Arc<Mutex<Vec<(&'static str, &'static str)>>>;
        struct Named(&'static str, [u8; 4], Log);
        impl Subscriber for Named {
            fn on_data(&self, _: &str, _: u64, _: &[u8]) {}
            fn topic_name(&self) -> &str {
                "Addressed"
            }
            fn reader_entity_id(&self) -> Option<[u8; 4]> {
                Some(self.1)
            }
            fn on_writer_heartbeat(&self, _: [u8; 16], _: u64) {
                self.2.lock().expect("log").push((self.0, "hb"));
            }
            fn on_writer_gap(&self, _: [u8; 16], _: u64, _: u64, _: Vec<u64>) {
                self.2.lock().expect("log").push((self.0, "gap"));
            }
        }
        const A: [u8; 4] = [0x00, 0x00, 0x05, 0x07];
        const B: [u8; 4] = [0x00, 0x00, 0x06, 0x07];
        const WRITER: [u8; 4] = [0x00, 0x00, 0x01, 0x02];
        const PREFIX: [u8; 12] = [0x0A; 12];

        let log: Log = Arc::new(Mutex::new(Vec::new()));
        let registry = TopicRegistry::new();
        for (name, id) in [("a", A), ("b", B)] {
            registry
                .register_subscriber(Arc::new(Named(name, id, Arc::clone(&log))))
                .expect("register");
        }
        let mut writer = [0u8; 16];
        writer[..12].copy_from_slice(&PREFIX);
        writer[12..].copy_from_slice(&WRITER);
        registry.register_writer_guid(writer, "Addressed".to_string());

        let mut packet = b"RTPS".to_vec();
        packet.extend_from_slice(&[0x02, 0x05, 0x01, 0xAA]);
        packet.extend_from_slice(&PREFIX);
        // HEARTBEAT to A: firstSN 1, lastSN 3, count 1.
        packet.extend_from_slice(&[0x07, 0x01]);
        packet.extend_from_slice(&28u16.to_le_bytes());
        packet.extend_from_slice(&A);
        packet.extend_from_slice(&WRITER);
        for word in [0u32, 1, 0, 3, 1] {
            packet.extend_from_slice(&word.to_le_bytes());
        }
        // GAP to B: gapStart 1, gapList.base 2, empty bitmap.
        packet.extend_from_slice(&[0x08, 0x01]);
        packet.extend_from_slice(&28u16.to_le_bytes());
        packet.extend_from_slice(&B);
        packet.extend_from_slice(&WRITER);
        for word in [0u32, 1, 0, 2, 0] {
            packet.extend_from_slice(&word.to_le_bytes());
        }

        let _ = route_raw_rtps_message(&packet, &registry, &make_metrics(), None);
        let mut seen = log.lock().expect("log").clone();
        seen.sort_unstable();
        assert_eq!(seen, vec![("a", "hb"), ("b", "gap")]);
    }

    /// RTPS v2.5 Sec.8.3.7.5: the HEARTBEAT Liveliness flag renews a
    /// MANUAL_BY_TOPIC writer's lease over TCP/QUIC too -- there is no
    /// transport exception. `apply_writer_control` must call
    /// `renew_heartbeat_liveliness` besides seeding the reorder gate, else a
    /// writer whose only matched reader sits behind TCP/QUIC is wrongly
    /// expired however often it asserts.
    /// Mutant: removing the `renew_heartbeat_liveliness` call from
    /// `apply_writer_control`'s `seed_all` makes this fail (the flag is
    /// parsed but never reaches the registry).
    #[test]
    fn a_heartbeat_liveliness_flag_reaches_the_writer_over_tcp_quic() {
        use crate::engine::Subscriber;
        use std::sync::Arc;

        type Log = Arc<Mutex<Vec<[u8; 16]>>>;
        struct Reader(Log);
        impl Subscriber for Reader {
            fn on_data(&self, _: &str, _: u64, _: &[u8]) {}
            fn topic_name(&self) -> &str {
                "LivelinessOverTcp"
            }
            fn on_writer_heartbeat_liveliness(&self, writer: [u8; 16]) {
                self.0.lock().expect("log").push(writer);
            }
        }
        const WRITER: [u8; 4] = [0x00, 0x00, 0x01, 0x02];
        const PREFIX: [u8; 12] = [0x0E; 12];

        let log: Log = Arc::new(Mutex::new(Vec::new()));
        let registry = TopicRegistry::new();
        registry
            .register_subscriber(Arc::new(Reader(Arc::clone(&log))))
            .expect("register");
        let mut writer = [0u8; 16];
        writer[..12].copy_from_slice(&PREFIX);
        writer[12..].copy_from_slice(&WRITER);
        registry.register_writer_guid(writer, "LivelinessOverTcp".to_string());

        let mut packet = b"RTPS".to_vec();
        packet.extend_from_slice(&[0x02, 0x05, 0x01, 0xAA]);
        packet.extend_from_slice(&PREFIX);
        // HEARTBEAT, Final + Liveliness + Endianness (0x01 | 0x02 | 0x04):
        // a MANUAL_BY_TOPIC writer asserting with nothing new to write.
        packet.extend_from_slice(&[0x07, 0x07]);
        packet.extend_from_slice(&28u16.to_le_bytes());
        packet.extend_from_slice(&[0, 0, 0, 0]);
        packet.extend_from_slice(&WRITER);
        for word in [0u32, 1, 0, 1, 1] {
            packet.extend_from_slice(&word.to_le_bytes());
        }

        let _ = route_raw_rtps_message(&packet, &registry, &make_metrics(), None);
        assert_eq!(
            *log.lock().expect("log"),
            vec![writer],
            "the Liveliness flag reached the writer over the TCP/QUIC door"
        );
    }

    /// RTPS 2.5 8.3.8.10: a HEARTBEAT forwarded behind an INFO_SRC comes from
    /// the writer of the participant the INFO_SRC names; the header names the
    /// forwarder. The TCP/QUIC door routes it under its source.
    #[test]
    fn a_heartbeat_behind_an_info_src_reaches_its_writers_reader() {
        use crate::engine::Subscriber;
        use std::sync::Arc;

        type Log = Arc<Mutex<Vec<[u8; 16]>>>;
        struct Reader(Log);
        impl Subscriber for Reader {
            fn on_data(&self, _: &str, _: u64, _: &[u8]) {}
            fn topic_name(&self) -> &str {
                "Forwarded"
            }
            fn on_writer_heartbeat(&self, writer: [u8; 16], _: u64) {
                self.0.lock().expect("log").push(writer);
            }
        }
        const WRITER: [u8; 4] = [0x00, 0x00, 0x01, 0x02];
        const FORWARDER: [u8; 12] = [0x0F; 12];
        const ORIGIN: [u8; 12] = [0x0D; 12];

        let log: Log = Arc::new(Mutex::new(Vec::new()));
        let registry = TopicRegistry::new();
        registry
            .register_subscriber(Arc::new(Reader(Arc::clone(&log))))
            .expect("register");
        let mut writer = [0u8; 16];
        writer[..12].copy_from_slice(&ORIGIN);
        writer[12..].copy_from_slice(&WRITER);
        registry.register_writer_guid(writer, "Forwarded".to_string());

        let mut packet = b"RTPS".to_vec();
        packet.extend_from_slice(&[0x02, 0x05, 0x01, 0xAA]);
        packet.extend_from_slice(&FORWARDER);
        // INFO_SRC: unused, version 2.5, vendor 01 0F, ORIGIN.
        packet.extend_from_slice(&[0x0c, 0x01]);
        packet.extend_from_slice(&20u16.to_le_bytes());
        packet.extend_from_slice(&[0, 0, 0, 0, 0x02, 0x05, 0x01, 0x0F]);
        packet.extend_from_slice(&ORIGIN);
        // HEARTBEAT to every reader: firstSN 1, lastSN 3, count 1.
        packet.extend_from_slice(&[0x07, 0x01]);
        packet.extend_from_slice(&28u16.to_le_bytes());
        packet.extend_from_slice(&[0, 0, 0, 0]);
        packet.extend_from_slice(&WRITER);
        for word in [0u32, 1, 0, 3, 1] {
            packet.extend_from_slice(&word.to_le_bytes());
        }

        let _ = route_raw_rtps_message(&packet, &registry, &make_metrics(), None);
        assert_eq!(*log.lock().expect("log"), vec![writer]);
    }

    /// RTPS 2.5 8.3.4 / 8.3.8.10 at the stream door. A HEARTBEAT whose
    /// sender is its message's source is answered on the connection it
    /// came on, whether it leads its message, rides behind a GAP, or sits
    /// behind an INFO_REPLY (8.3.8.9: only a Reliable StatelessWriter reads
    /// the locator it names, 8.4.8.2.6; the reader is stateful). One behind
    /// an INFO_SRC is not answered on the connection -- the other end only
    /// forwarded it -- but through the reader's WriterProxy (a relayed
    /// origin). The door that knows no connection keeps its no-address
    /// answer for the direct ones, and gives the relayed one its relayed
    /// origin too, not the same no-address (multicast) answer.
    #[test]
    fn a_stream_answers_only_the_heartbeats_its_sender_is_the_source_of() {
        use crate::core::discovery::multicast::Origin;
        use crate::engine::{HeartbeatHandler, StreamReply};
        use std::net::SocketAddr;
        use std::sync::Arc;

        #[derive(Debug, PartialEq)]
        enum Seen {
            Connection,
            NoAddress,
            ReplyTo(Option<SocketAddr>),
        }
        type Log = Arc<Mutex<Vec<Seen>>>;
        struct Handler(Log);
        impl HeartbeatHandler for Handler {
            fn on_heartbeat(&self, _: &[u8], origin: Option<Origin>) {
                self.0.lock().expect("log").push(match origin {
                    None => Seen::NoAddress,
                    Some(origin) => Seen::ReplyTo(origin.reply()),
                });
            }
            fn on_heartbeat_over_stream(&self, _: &[u8], connection: &dyn StreamReply) {
                connection.send_reply(b"answer").expect("the connection");
                self.0.lock().expect("log").push(Seen::Connection);
            }
        }
        struct Connection(Mutex<usize>);
        impl StreamReply for Connection {
            fn send_reply(&self, _: &[u8]) -> std::io::Result<()> {
                *self.0.lock().expect("count") += 1;
                Ok(())
            }
        }

        let header = || {
            let mut packet = b"RTPS".to_vec();
            packet.extend_from_slice(&[0x02, 0x05, 0x01, 0x1A]);
            packet.extend_from_slice(&[0x0F; 12]);
            packet
        };
        // HEARTBEAT, every reader, writer 0x00000102: firstSN 1, lastSN 3.
        let heartbeat = || {
            let mut sub = vec![0x07, 0x01];
            sub.extend_from_slice(&28u16.to_le_bytes());
            sub.extend_from_slice(&[0, 0, 0, 0, 0x00, 0x00, 0x01, 0x02]);
            for word in [0u32, 1, 0, 3, 1] {
                sub.extend_from_slice(&word.to_le_bytes());
            }
            sub
        };

        let mut led = header();
        led.extend(heartbeat());
        // INFO_REPLY_IP4: 10.1.2.3:7999, little-endian.
        led.extend_from_slice(&[0x0d, 0x01, 0x08, 0x00, 3, 2, 1, 10, 0x3f, 0x1f, 0, 0]);
        led.extend(heartbeat());
        // INFO_SRC: unused, version 2.5, vendor 01 0F, another participant.
        led.extend_from_slice(&[0x0c, 0x01, 0x14, 0x00, 0, 0, 0, 0, 0x02, 0x05, 0x01, 0x0F]);
        led.extend_from_slice(&[0x0D; 12]);
        led.extend(heartbeat());

        // A GAP ([1, 2) irrelevant) with the HEARTBEAT riding behind it.
        let mut behind_a_gap = header();
        behind_a_gap.extend_from_slice(&[0x08, 0x01]);
        behind_a_gap.extend_from_slice(&28u16.to_le_bytes());
        behind_a_gap.extend_from_slice(&[0, 0, 0, 0, 0x00, 0x00, 0x01, 0x02]);
        // gapStart 1, gapList base 2, numBits 0.
        for word in [0u32, 1, 0, 2, 0] {
            behind_a_gap.extend_from_slice(&word.to_le_bytes());
        }
        behind_a_gap.extend(heartbeat());

        let log: Log = Arc::new(Mutex::new(Vec::new()));
        let registry = TopicRegistry::new();
        let _ = registry.register_heartbeat_handler(Arc::new(Handler(Arc::clone(&log))));
        let take = || std::mem::take(&mut *log.lock().expect("log"));

        let connection = Connection(Mutex::new(0));
        for packet in [&led, &behind_a_gap] {
            let _ = route_raw_rtps_message_from_stream(
                packet,
                &registry,
                &make_metrics(),
                None,
                &connection,
            );
        }
        assert_eq!(
            take(),
            vec![
                Seen::Connection,
                Seen::Connection,
                Seen::ReplyTo(None),
                Seen::Connection,
            ]
        );
        assert_eq!(
            *connection.0.lock().expect("count"),
            3,
            "three answers on it"
        );

        for packet in [&led, &behind_a_gap] {
            let _ = route_raw_rtps_message(packet, &registry, &make_metrics(), None);
        }
        assert_eq!(
            take(),
            vec![
                Seen::NoAddress,
                Seen::NoAddress,
                Seen::ReplyTo(None),
                Seen::NoAddress,
            ]
        );
    }
}
