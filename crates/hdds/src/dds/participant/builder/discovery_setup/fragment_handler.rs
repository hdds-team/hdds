// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Reassembly of fragmented discovery announcements.
//!
//! A DATA_FRAG carries a SLICE of a sample (RTPS v2.5 Sec.8.3.8.3), so nothing
//! on this path may read what it is handed as an announcement: the
//! announcement exists only once every fragment of that sample has arrived.
//!
//! Two consequences shape this module.
//!
//! - The bytes that go into the buffer are the SAMPLE payload of each
//!   fragment, never the datagram that carried them. Until 1.5.0 the whole
//!   datagram went in, RTPS header included, so the reassembled buffer began
//!   with "RTPS" and every parse of it failed on the CDR encapsulation - which
//!   made `handle_spdp_from_fragments` unreachable and its "if the payload
//!   starts with RTPS" branch a workaround for its own caller.
//! - The reassembled sample is dispatched by its WRITER, not by the kind the
//!   delivery carried. A datagram may bundle fragments of more than one
//!   writer, and the classifier elects ONE kind for the datagram; naming the
//!   sample after its writer is the same rule the classifier itself follows
//!   for DATA and DATA_FRAG.

use crate::core::discovery::multicast::{scan_all_data_frags, FragmentMetadata, Origin};
use crate::core::discovery::SpdpPeerSet;
use crate::core::discovery::{multicast::DiscoveryFsm, FragmentBuffer, GUID};
use crate::engine::TopicRegistry;
use crate::transport::UdpTransport;
use parking_lot::Mutex;
use std::sync::Arc;

use super::super::entity_registry::SedpAnnouncementsCache;
use super::sedp_handler::handle_sedp_from_fragments;
use super::type_lookup_handler::{handle_type_lookup_sample, TypeLookupHandle};
use super::{spdp_handler::handle_spdp_from_fragments, SpdpSecurityTokens};

/// Everything the reassembled sample needs once it is whole.
///
/// Grouped because the dispatch below hands the same set to whichever handler
/// the writer names, and `handle_fragment` would otherwise carry fourteen
/// positional arguments.
pub(super) struct FragmentContext<'a> {
    pub origin: Origin,
    pub our_guid_prefix: [u8; 12],
    pub transport: Arc<UdpTransport>,
    pub fsm: Arc<DiscoveryFsm>,
    pub registry: Arc<TopicRegistry>,
    pub sedp_cache: SedpAnnouncementsCache,
    pub dialect_detector:
        Arc<std::sync::Mutex<crate::core::discovery::multicast::dialect_detector::DialectDetector>>,
    pub port_mapping: crate::transport::PortMapping,
    pub spdp_security_tokens: &'a SpdpSecurityTokens,
    pub discovered_peers: Option<&'a SpdpPeerSet>,
    pub type_lookup: &'a TypeLookupHandle,
    /// Where a reassembled handshake message goes (`dispatch_reassembled`).
    #[cfg(feature = "security")]
    pub secure_builtins: Option<&'a super::secure_builtins::SecureBuiltins>,
}

/// Handle a delivery the classifier marked as a fragment.
///
/// # Arguments
/// - `frag_meta`: metadata of the fragment the classifier elected for this
///   datagram. Only its geometry is read here, to recognise a datagram that
///   declares no fragment at all; the fragments actually buffered come from
///   the scan, which sees every DATA_FRAG of the datagram and every fragment
///   inside each of them.
/// - `packet`: the full RTPS datagram, as the callback received it. Where each
///   fragment's payload starts is the scan's answer, not the classifier's:
///   `cdr_offset` was a parameter here until the zero-fragment door stopped
///   parsing, and it was the only thing that read it.
/// - `fragment_buffer`: reassembly buffer, keyed by (writer GUID, sequence).
/// - `ctx`: what the completed announcement is handed to.
pub(super) fn handle_fragment(
    frag_meta: FragmentMetadata,
    packet: &[u8],
    fragment_buffer: Arc<Mutex<FragmentBuffer>>,
    ctx: &FragmentContext<'_>,
) {
    log::debug!(
        "[callback-builder] Received DATA_FRAG: writerGUID={:?} seqNum={} frag={}/{} len={}",
        frag_meta.writer_guid,
        frag_meta.seq_num,
        frag_meta.frag_num,
        frag_meta.total_frags(),
        packet.len()
    );

    // A DATA_FRAG that declares no fragment at all. `total_frags` is
    // `ceil(sampleSize / fragmentSize)`, so it is zero exactly when the
    // geometry describes nothing: a fragmentSize of 0, or a declared
    // sampleSize of 0. Neither is a sample, and there is nothing here to
    // reassemble or to parse.
    //
    // Such a datagram is refused here instead of being parsed: handing
    // `packet[cdr_offset..]` straight to the discovery handlers would bypass
    // the reassembly buffer entirely, and the bytes are not a sample. They
    // form a parameter list with no sentinel of its own, finished off by
    // whatever submessage follows: one HEARTBEAT's header would be read as the
    // tail of a metatraffic locator and register a peer at `0.0.0.0:7410`.
    // Bounding the slice would stop the invention; refusing the door stops the
    // parse, which is what a sample of no fragments deserves.
    //
    // REDUNDANT, and mutation-verified as such: deleting this branch turns no
    // test red, because `scan_all_data_frags` refuses the same geometry and
    // the empty-completion path below returns without parsing anything. It is
    // kept because it is THIS door's own rule and this function is
    // `pub(super)` - the classifier is not its only possible caller, and a
    // caller that hands it a geometry with no fragment in it should be
    // refused here rather than by the coincidence of a scan two calls away.
    if frag_meta.total_frags() == 0 {
        log::debug!(
            "[callback-builder] DATA_FRAG declares no fragment (fragmentSize={}, \
             sampleSize={}); datagram dropped",
            frag_meta.geometry.fragment_size,
            frag_meta.geometry.sample_size
        );
        return;
    }

    // ONE reader for the fragments of a datagram, the one the router already
    // uses. It sees every DATA_FRAG of the datagram - not just the one the
    // classifier elected - and splits a submessage that declares
    // `fragmentsInSubmessage > 1` into its individual fragments. Reading the
    // elected fragment alone lost both.
    let mut completed: Vec<(GUID, u64, Vec<u8>)> = Vec::new();
    {
        let mut buffer = fragment_buffer.lock();
        for frag in scan_all_data_frags(packet) {
            // Our own fragments are dropped before reassembly, as the
            // user-data router drops them (`engine::router`, self-loopback).
            // The prefix is the one the buffer would rank the sequence by:
            // the RTPS header's, or an INFO_SRC's before it. Nothing of ours
            // is reassembled here, and a fragment anyone may send with our
            // prefix takes no place in the buffer, or it would rank above
            // every authenticated peer.
            if frag.meta.writer_guid.prefix == ctx.our_guid_prefix {
                continue;
            }
            if let Some(sample) = buffer.insert_fragment(
                frag.meta.writer_guid,
                frag.meta.seq_num,
                frag.meta.frag_num,
                frag.meta.geometry,
                frag.payload,
            ) {
                completed.push((frag.meta.writer_guid, frag.meta.seq_num, sample));
            }
        }
    }

    if completed.is_empty() {
        log::debug!(
            "[callback-builder] fragment {}/{} buffered, waiting for more",
            frag_meta.frag_num,
            frag_meta.total_frags()
        );
        return;
    }

    for (writer_guid, seq_num, sample) in &completed {
        log::debug!(
            "[callback-builder] [OK] Fragment reassembly complete! Parsing {} bytes",
            sample.len()
        );
        dispatch_reassembled(writer_guid, *seq_num, sample, packet, ctx);
    }
}

/// Hand a reassembled sample to the handler its WRITER names.
///
/// `datagram` is the packet that carried the last fragment. It is not the
/// sample; it is passed on because the SPDP handler feeds the dialect detector
/// and reads the source GUID prefix out of the RTPS header, both of which are
/// properties of the packet, not of the announcement.
fn dispatch_reassembled(
    writer_guid: &GUID,
    seq_num: u64,
    sample: &[u8],
    datagram: &[u8],
    ctx: &FragmentContext<'_>,
) {
    use crate::core::rtps_constants::{
        RTPS_ENTITYID_BUILTIN_PARTICIPANT_STATELESS_MESSAGE_WRITER,
        RTPS_ENTITYID_SEDP_PUBLICATIONS_WRITER, RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_WRITER,
        RTPS_ENTITYID_SPDP_WRITER, RTPS_ENTITYID_TYPELOOKUP_REPLY_WRITER,
        RTPS_ENTITYID_TYPELOOKUP_REQUEST_WRITER,
    };

    match writer_guid.entity_id {
        w if w == RTPS_ENTITYID_SPDP_WRITER => {
            handle_spdp_from_fragments(
                sample,
                datagram,
                ctx.origin,
                ctx.our_guid_prefix,
                ctx.transport.clone(),
                ctx.fsm.clone(),
                ctx.sedp_cache.clone(),
                ctx.dialect_detector.clone(),
                ctx.port_mapping,
                ctx.spdp_security_tokens,
                ctx.discovered_peers,
            );
        }
        w if w == RTPS_ENTITYID_SEDP_PUBLICATIONS_WRITER
            || w == RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_WRITER =>
        {
            handle_sedp_from_fragments(sample, seq_num, ctx.fsm.clone(), ctx.registry.clone());
        }
        // A TypeObject is the largest sample discovery carries, so this is
        // the arm the fragmented form of TypeLookup needs most. Without it
        // the request was reassembled correctly and then dropped by the
        // `other` arm below as "not a discovery announcement".
        w if w == RTPS_ENTITYID_TYPELOOKUP_REQUEST_WRITER
            || w == RTPS_ENTITYID_TYPELOOKUP_REPLY_WRITER =>
        {
            handle_type_lookup_sample(
                ctx.type_lookup,
                sample,
                writer_guid.entity_id,
                writer_guid.prefix,
                super::type_lookup_handler::type_lookup_writer_sn(datagram),
                ctx.origin,
            );
        }
        // A handshake message too large for one DATA: an AuthReply of
        // Cyclone DDS (certificate, permissions document, participant data)
        // is five fragments.
        w if w == RTPS_ENTITYID_BUILTIN_PARTICIPANT_STATELESS_MESSAGE_WRITER => {
            #[cfg(feature = "security")]
            super::dispatch::handle_stateless_sample(
                sample,
                writer_guid.prefix,
                ctx.our_guid_prefix,
                &ctx.fsm,
                ctx.secure_builtins,
            );
        }
        other => {
            // A user writer's sample is the router's business, not discovery's.
            // It is not offered to the SPDP or the SEDP parser: that could only
            // fail, since the buffer holds datagrams.
            log::debug!(
                "[callback-builder] reassembled sample from writer entity {:02x?} is not a \
                 discovery announcement",
                other
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::wire_fixtures::*;
    use super::*;
    use crate::core::discovery::multicast::dialect_detector::DialectDetector;
    use crate::protocol::discovery::parse_spdp;
    use crate::test_support::domains::unique_domain;
    use std::sync::RwLock;

    struct Harness {
        fsm: Arc<DiscoveryFsm>,
        registry: Arc<TopicRegistry>,
        transport: Arc<UdpTransport>,
        detector: Arc<std::sync::Mutex<DialectDetector>>,
        port_mapping: crate::transport::PortMapping,
        tokens: SpdpSecurityTokens,
        type_lookup: TypeLookupHandle,
        buffer: Arc<Mutex<FragmentBuffer>>,
        _domain: crate::test_support::domains::DomainLease,
    }

    impl Harness {
        fn new() -> Self {
            let domain = unique_domain();
            let port_mapping =
                crate::transport::PortMapping::calculate(domain.id(), 0).expect("port mapping");
            let transport = Arc::new(
                UdpTransport::new(domain.id(), 0, port_mapping).expect("a test transport"),
            );
            Self {
                fsm: Arc::new(DiscoveryFsm::new(
                    GUID::new(OUR_PREFIX, [0, 0, 1, 0xC1]),
                    30_000,
                )),
                registry: Arc::new(TopicRegistry::new()),
                transport,
                detector: Arc::new(std::sync::Mutex::new(DialectDetector::new())),
                port_mapping,
                tokens: SpdpSecurityTokens::new(None, None, None),
                // This module's tests ask what reassembly does with an
                // ANNOUNCEMENT; the TypeLookup arm is driven end to end from
                // `dispatch`, where a real service can answer on a socket.
                type_lookup: None,
                buffer: Arc::new(Mutex::new(FragmentBuffer::new(16, 5_000))),
                _domain: domain,
            }
        }

        fn ctx(&self) -> FragmentContext<'_> {
            FragmentContext {
                // Deliberately NOT the announced locator: when the parameter
                // list is lost, the SPDP handler infers a metatraffic locator
                // from the source address, and a fixture whose source matches
                // its announcement cannot tell the two apart.
                origin: Origin::direct("198.51.100.9:7410".parse().unwrap()),
                our_guid_prefix: OUR_PREFIX,
                transport: self.transport.clone(),
                fsm: self.fsm.clone(),
                registry: self.registry.clone(),
                sedp_cache: Arc::new(RwLock::new(
                    crate::core::discovery::multicast::SedpHistory::new(),
                )),
                dialect_detector: self.detector.clone(),
                port_mapping: self.port_mapping,
                spdp_security_tokens: &self.tokens,
                discovered_peers: None,
                type_lookup: &self.type_lookup,
                #[cfg(feature = "security")]
                secure_builtins: None,
            }
        }

        fn feed(&self, datagram: &[u8], meta: FragmentMetadata) {
            handle_fragment(meta, datagram, self.buffer.clone(), &self.ctx());
        }
    }

    /// A fragment is not an announcement.
    ///
    /// Handing fragment 1 straight to the SPDP handler would fall back to the
    /// PARTIAL parser and register the peer from it: the right GUID, then a
    /// 100-second lease and domain 0 that are constants in that parser, no
    /// locators and no vendor id. Fragment 2 would then be refused on its
    /// first two octets - the middle of a parameter list is not a CDR
    /// encapsulation - and its contents, which is where the locators and the
    /// security tokens live, would be dropped.
    ///
    /// So the assertions are on the VALUES, not on the count: that defect
    /// would not lose the participant, it would replace its fields with
    /// constants.
    #[test]
    fn a_fragmented_announcement_is_reassembled_before_it_is_read() {
        let (announced, cdr) = announcement_from(SENDER_PREFIX);
        let (one, two, meta_one, meta_two) = two_fragments(SENDER_PREFIX, &SPDP, &cdr);

        // The lease is the discriminating field: it is the one the partial
        // parser replaces with a constant, and it lies past the cut, so a
        // reader that stops at fragment 1 cannot know it. Proven here rather
        // than assumed, because `build_spdp` decides the parameter order.
        let cut = usize::from((cdr.len().div_ceil(2)).next_multiple_of(4) as u16);
        let lease_at = pid_offset(&cdr, 0x0002).expect("the announcement carries a lease");
        assert!(
            lease_at >= cut,
            "PID_PARTICIPANT_LEASE_DURATION sits at {lease_at}, before the cut at {cut}: \
             this fixture would pass without ever reading the second fragment"
        );

        let h = Harness::new();

        h.feed(&one, meta_one);
        assert_eq!(
            h.fsm.participant_count(),
            0,
            "one fragment of an announcement is not an announcement"
        );

        h.feed(&two, meta_two);
        let found = h.fsm.get_participants();
        assert_eq!(
            found.len(),
            1,
            "the reassembled announcement names one peer"
        );
        let peer = &found[0];
        assert_eq!(peer.guid, announced.participant_guid);
        assert_eq!(
            peer.lease_duration_ms, 30_000,
            "the lease comes off the wire, not from the partial parser's 100 s constant"
        );
        assert_eq!(
            peer.endpoints, announced.metatraffic_unicast_locators,
            "the announced locator survives reassembly; an empty list here is \
             what made the receiver infer one from the source address"
        );
    }

    /// The reassembled sample is named by its WRITER.
    ///
    /// The same two datagrams from a user writer carry user data, which is the
    /// router's business. They must not be offered to the SPDP parser and then
    /// to the SEDP parser regardless of who sent them.
    #[test]
    fn a_reassembled_sample_from_a_user_writer_is_not_an_announcement() {
        let (_, cdr) = announcement_from(SENDER_PREFIX);
        let (one, two, meta_one, meta_two) = two_fragments(SENDER_PREFIX, &A_USER_ENDPOINT, &cdr);
        let h = Harness::new();

        h.feed(&one, meta_one);
        h.feed(&two, meta_two);

        assert_eq!(
            h.fsm.participant_count(),
            0,
            "a user writer's sample is not a participant announcement, whatever \
             its bytes happen to parse as"
        );
    }

    /// Our own announcement, coming back over multicast, is recognised as ours
    /// from the RTPS HEADER of the packet - not from the sample.
    ///
    /// Only the packet carries the sender's identity: the reassembled sample
    /// is a parameter list whose first octets are a CDR encapsulation, so a
    /// reader that looks for a GUID prefix there finds four bytes of
    /// something else and concludes the packet is a stranger's. The visible
    /// consequence is the dialect detector: it would score our own traffic and
    /// flip the participant into interop mode against itself. The fixture
    /// announces a foreign vendor id in the header precisely so that a single
    /// scored packet is enough to show.
    ///
    /// Written because mutating the prefix source from the packet to the
    /// sample changed nothing: every fixture here came from a stranger, so
    /// the self-loopback half of the rule had no fixture at all.
    #[test]
    fn our_own_fragmented_announcement_is_not_scored_against_us() {
        let (_, cdr) = announcement_from(OUR_PREFIX);
        let (one, two, meta_one, meta_two) = two_fragments(OUR_PREFIX, &SPDP, &cdr);
        let h = Harness::new();

        assert!(
            !h.detector.lock().unwrap().is_interop_mode(),
            "the detector starts in native mode"
        );

        h.feed(&one, meta_one);
        h.feed(&two, meta_two);

        assert!(
            !h.detector.lock().unwrap().is_interop_mode(),
            "our own announcement must not be scored as a foreign peer's"
        );
    }

    /// A fragment carrying our own prefix never enters the reassembly
    /// buffer: our own announcements are not reassembled, and one anyone
    /// may send with our prefix takes no place there.
    #[test]
    fn a_fragment_with_our_own_prefix_never_enters_the_buffer() {
        let (_, cdr) = announcement_from(OUR_PREFIX);
        let (one, _, meta_one, _) = two_fragments(OUR_PREFIX, &SPDP, &cdr);
        let h = Harness::new();
        h.feed(&one, meta_one);
        assert_eq!(h.buffer.lock().pending_count(), 0);

        let (_, cdr) = announcement_from(SENDER_PREFIX);
        let (one, _, meta_one, _) = two_fragments(SENDER_PREFIX, &SPDP, &cdr);
        h.feed(&one, meta_one);
        assert_eq!(h.buffer.lock().pending_count(), 1, "a peer's fragment does");
    }

    /// A DATA_FRAG that declares no fragment names no fragment.
    ///
    /// With `fragmentSize == 0` the classifier must not fall back on
    /// `fragmentsInSubmessage` for the count while `scan_all_data_frags`
    /// refuses the submessage outright - two readers of one field group
    /// answering differently. The classifier derives the count from the
    /// geometry alone, so both decline together, and a datagram whose only
    /// submessage names no fragment is classified as nothing at all.
    ///
    /// The second half is what makes the first safe: a DATA_FRAG the
    /// classifier declines to name must not reach `handle_spdp_packet` as a
    /// whole announcement instead: a fragment would be registered as a
    /// participant built from the partial parser's constants.
    #[test]
    fn a_datagram_declaring_no_fragment_names_no_fragment() {
        let (_announced, cdr) = announcement_from(SENDER_PREFIX);
        let (wire, _) =
            followed_by_a_heartbeat(&a_zero_fragment_datagram(SENDER_PREFIX, &SPDP, &cdr), &SPDP);

        let (kind, at, meta, _ctx) = crate::core::discovery::multicast::classify_rtps(&wire);
        assert!(
            meta.is_none(),
            "a geometry with no fragments in it must not announce one"
        );
        assert_eq!(at, None, "so there is no payload to point a parser at");

        // The KIND must not name the datagram after the writer of the
        // submessage the classifier just refused (`SPDP`): if the refusal
        // decided the payload offset and nothing else, the refused submessage
        // would still speak for the datagram, and being first it would speak
        // for good. This fixture is the demonstration, because it puts a
        // perfectly valid HEARTBEAT behind the refused DATA_FRAG, which must
        // not be classified away.
        assert_eq!(
            kind,
            crate::core::discovery::multicast::PacketKind::Heartbeat,
            "the submessage that describes something names the datagram, not \
             the one that describes nothing"
        );
    }

    /// And the door refuses it even when something hands it a fragment.
    ///
    /// The classifier is not the only caller: this asserts the door's own
    /// rule, so a future path that reaches `handle_fragment` with a
    /// hand-built metadata cannot resurrect the parse by handing
    /// `packet[cdr_offset..]` straight to the discovery handlers.
    #[test]
    fn the_door_refuses_a_geometry_with_no_fragment_in_it() {
        let (_announced, cdr) = announcement_from(SENDER_PREFIX);
        let wire = a_zero_fragment_datagram(SENDER_PREFIX, &SPDP, &cdr);

        let h = Harness::new();
        h.feed(
            &wire,
            FragmentMetadata {
                writer_guid: GUID::new(SENDER_PREFIX, SPDP.writer),
                seq_num: 7,
                frag_num: 1,
                geometry: crate::core::discovery::multicast::FragmentGeometry {
                    fragment_size: 0,
                    sample_size: cdr.len() as u32,
                },
            },
        );

        assert_eq!(
            h.fsm.participant_count(),
            0,
            "a sample of no fragments is not a sample: nothing is parsed and \
             nobody is registered"
        );
    }

    /// What the closed door is worth, stated where it can fail.
    ///
    /// The payload of a DATA_FRAG is a piece of a sample, cut at fragmentSize
    /// boundaries and not at parameter ones - so the realistic content this
    /// door could hand `parse_spdp` is a parameter list that stops in the
    /// middle of a parameter. The fixture cuts the announcement 16 octets into
    /// its metatraffic locator and puts behind it the HEARTBEAT a reliable
    /// writer sends with its fragments.
    ///
    /// Read to the end of its own submessage the parse FAILS: the locator
    /// declares 24 octets and 8 are there. Read past it the parse SUCCEEDS,
    /// and the peer is registered with a locator whose address is the
    /// HEARTBEAT's own readerId and writerId, the read landing on
    /// `firstSN.low` - whose four octets a parameter-list reader takes for
    /// PID_SENTINEL. Both halves are asserted rather than argued, so a fixture
    /// that stopped being able to tell them apart fails instead of passing.
    #[test]
    fn a_zero_fragment_datagram_is_a_parameter_list_with_no_sentinel() {
        let (_, cdr) = announcement_from(SENDER_PREFIX);

        // PID_METATRAFFIC_UNICAST_LOCATOR as a literal: a fixture built from
        // the constant it pins cannot notice that constant changing.
        let locator_at =
            pid_offset(&cdr, 0x0032).expect("the announcement carries a metatraffic locator");
        let declared = usize::from(u16::from_le_bytes([
            cdr[locator_at + 2],
            cdr[locator_at + 3],
        ]));
        assert_eq!(
            declared, 24,
            "a Locator_t is 24 octets: kind, port, and a 16-octet address \
             (RTPS v2.5 Sec.8.3.4.2)"
        );
        let locator_end = locator_at + 4 + declared;
        let cut = locator_end - 16;
        assert!(
            locator_at + 4 <= cut && cut < locator_end,
            "the cut must leave the parameter's header on the wire and its value short"
        );

        let (wire, heartbeat_at) = followed_by_a_heartbeat(
            &a_zero_fragment_datagram(SENDER_PREFIX, &SPDP, &cdr[..cut]),
            &SPDP,
        );
        assert_eq!(
            FRAGMENT_AT + locator_end,
            heartbeat_at + 16,
            "a read that runs past the fragment lands on the HEARTBEAT's firstSN low word"
        );

        assert!(
            parse_spdp(&wire[FRAGMENT_AT..FRAGMENT_AT + cut]).is_err(),
            "the fragment alone is a truncated parameter list and must be refused"
        );
        let past_the_end =
            parse_spdp(&wire[FRAGMENT_AT..]).expect("the unbounded read is the one that succeeds");
        assert_eq!(
            past_the_end.metatraffic_unicast_locators,
            vec!["0.0.0.0:7410".parse::<std::net::SocketAddr>().unwrap()],
            "unbounded, the locator's address is the HEARTBEAT's own header octets"
        );

        // And the door takes neither read: it does not parse at all.
        let h = Harness::new();
        h.feed(
            &wire,
            FragmentMetadata {
                writer_guid: GUID::new(SENDER_PREFIX, SPDP.writer),
                seq_num: 7,
                frag_num: 1,
                geometry: crate::core::discovery::multicast::FragmentGeometry {
                    fragment_size: 0,
                    sample_size: cut as u32,
                },
            },
        );
        assert_eq!(
            h.fsm.participant_count(),
            0,
            "a sample of no fragments registers nobody"
        );
    }
}
