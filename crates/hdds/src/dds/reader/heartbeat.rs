// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Heartbeat processing for DataReader.
//!
//! Handles incoming RTPS HEARTBEAT messages from writers and triggers
//! ACKNACK responses for missing samples via the NackScheduler.
//!
//! ## RTPS Reliable Protocol Flow
//!
//! ```text
//! Writer                              Reader
//!   +--DATA(1,2,3,4,5)------------------>  (3 lost)
//!   +--HEARTBEAT(first=1,last=5)-------->
//!   |                                   |
//!   <----------ACKNACK(missing={3})-----+  <- This module sends this
//!   |                                   |
//!   +--DATA(3) retransmit--------------->
//! ```

use crate::core::discovery::multicast::control_types::ENTITYID_UNKNOWN;
use crate::core::discovery::multicast::DiscoveryFsm;
use crate::core::discovery::multicast::Origin;
use crate::core::discovery::GUID;
use crate::core::reader::{HeartbeatSeen, ReaderAckCredit};
use crate::engine::{HeartbeatHandler, StreamReply};
use crate::protocol::builder::build_acknack_packet_with_final;
use crate::reliability::HeartbeatMsg;
use crate::transport::UdpTransport;
use std::net::SocketAddr;
use std::sync::Arc;

/// Context for sending ACKNACK responses to the writer.
pub(super) struct AcknackContext {
    /// Our GUID prefix (12 bytes)
    pub our_guid_prefix: [u8; 12],
    /// Reader entity ID (4 bytes), the one SEDP announces for this reader
    pub reader_entity_id: [u8; 4],
    /// This reader's handle on the proxy registry: the WriterProxy it
    /// answers from is the one its subscriber credits and the control
    /// thread answers from (RTPS 2.5 8.4.12), so both doors send one
    /// reader's one view, under one ACKNACK count.
    pub credit: ReaderAckCredit,
    /// UDP transport for sending ACKNACK
    pub transport: Arc<UdpTransport>,
    /// Discovery FSM for resolving peer metatraffic address.
    /// ACKNACKs must go to the metatraffic port, not the user data port.
    pub discovery_fsm: Option<Arc<DiscoveryFsm>>,
    /// The reader's topic: a writer of it the security plugins do not admit
    /// is not answered (`service_heartbeat`).
    #[cfg(feature = "security")]
    pub topic: String,
}

/// Where an ACKNACK answering one HEARTBEAT goes.
#[derive(Clone, Copy)]
enum Answer<'a> {
    /// A datagram transport: `None` has no address at all (the multicast
    /// fallback), `Some` answers per `resolve_metatraffic_dest`.
    Datagram(Option<Origin>),
    /// Back on the connection the HEARTBEAT arrived on (TCP, QUIC).
    Stream(&'a dyn StreamReply),
}

pub(super) struct ReaderHeartbeatHandler {
    /// ACKNACK context (None for intra-process mode)
    acknack_ctx: Option<AcknackContext>,
}

impl ReaderHeartbeatHandler {
    /// A handler with nothing to answer from (no transport, no participant).
    pub fn new() -> Self {
        Self { acknack_ctx: None }
    }

    /// Create with ACKNACK sending capability for cross-process RELIABLE.
    ///
    /// The reader answers under its own GUID, the one `credit` carries.
    pub fn with_acknack_context(
        credit: ReaderAckCredit,
        transport: Arc<UdpTransport>,
        discovery_fsm: Option<Arc<DiscoveryFsm>>,
        topic: &str,
    ) -> Self {
        #[cfg(not(feature = "security"))]
        let _ = topic;
        let [p0, p1, p2, p3, p4, p5, p6, p7, p8, p9, p10, p11, e0, e1, e2, e3] = credit.reader();
        Self {
            acknack_ctx: Some(AcknackContext {
                our_guid_prefix: [p0, p1, p2, p3, p4, p5, p6, p7, p8, p9, p10, p11],
                reader_entity_id: [e0, e1, e2, e3],
                credit,
                transport,
                discovery_fsm,
                #[cfg(feature = "security")]
                topic: topic.to_string(),
            }),
        }
    }

    /// Service ONE HEARTBEAT announcement: answer it with this reader's
    /// ACKNACK, built from this reader's WriterProxy for that writer.
    ///
    /// Split out of `on_heartbeat` so every HEARTBEAT of a batched datagram
    /// gets the same treatment: `writer_key`, the answer and the destination
    /// resolved for it all come from `hb`.
    ///
    /// The answer reflects what the reader RECEIVED, never what the writer
    /// announced: raising a per-writer high-water mark to every HEARTBEAT's
    /// lastSN would acknowledge the next HEARTBEAT up to there whether or not
    /// a single DATA had arrived.
    fn service_heartbeat(&self, hb: &HeartbeatMsg, reply_on: Answer<'_>) {
        let Some(ref ctx) = self.acknack_ctx else {
            return;
        };
        // A HEARTBEAT addressed to another reader is not this reader's to
        // answer; ENTITYID_UNKNOWN addresses them all.
        if hb.reader_entity_id != ENTITYID_UNKNOWN && hb.reader_entity_id != ctx.reader_entity_id {
            return;
        }
        let mut writer_key = [0u8; 16];
        writer_key[..12].copy_from_slice(&hb.writer_guid_prefix);
        writer_key[12..].copy_from_slice(&hb.writer_entity_id);

        // A sequence number is a signed 64-bit value on the wire (RTPS 2.5
        // 8.3.5.4): one past i64::MAX is not a sequence a writer has written.
        let (Ok(first_seq), Ok(last_seq)) =
            (i64::try_from(hb.first_seq), i64::try_from(hb.last_seq))
        else {
            return;
        };
        // DDS Security v1.1 Sec.8.8.7.1, 9.4.3: a writer the security
        // plugins do not admit gets no ACKNACK and moves no WriterProxy
        // state (the cached admission verdict).
        #[cfg(feature = "security")]
        if ctx.discovery_fsm.as_ref().is_some_and(|fsm| {
            fsm.admission_gate_active()
                && !fsm.admits_remote_endpoint(&ctx.topic, &GUID::from_bytes(writer_key), true)
        }) {
            return;
        }
        // `None` when this reader is not matched with the writer (every
        // registered handler is handed every HEARTBEAT), or has nothing to
        // send yet (duplicate count, rate limit).
        let Some(answer) = ctx.credit.answer_heartbeat(
            &writer_key,
            &HeartbeatSeen {
                first_seq,
                last_seq,
                count: hb.count,
                final_flag: false,
            },
        ) else {
            return;
        };

        let acknack_packet = build_acknack_packet_with_final(
            ctx.our_guid_prefix,
            hb.writer_guid_prefix,
            ctx.reader_entity_id,
            hb.writer_entity_id,
            answer.bitmap_base,
            &answer.missing,
            answer.count,
            answer.final_flag,
        );

        // Route ACKNACK to peer's METATRAFFIC unicast port.
        // The origin from the router carries the raw UDP source (often the
        // user-data port), or none at all (TCP/QUIC, intra). RTPS control
        // messages (HB, ACKNACK, GAP) must be sent to the metatraffic
        // channel. Resolve via DiscoveryFsm, falling back to the origin's
        // reply address if the peer is not yet discovered.
        //
        // RTPS 2.5 8.3.4 / 8.3.8.10: a relayed origin (behind an INFO_SRC)
        // has no reply address at all. `None` here keeps its existing
        // meaning -- no address, fall back to multicast -- and is NOT what a
        // relayed origin becomes: a relayed origin resolves by GUID prefix
        // alone, and a peer the FSM does not know gets no ACKNACK, never a
        // multicast one and never one aimed at the forwarder.
        let (send_result, dest) = match reply_on {
            // The connection the HEARTBEAT came on: its sender is at the
            // other end (RTPS 2.5 8.3.4).
            Answer::Stream(connection) => (connection.send_reply(&acknack_packet), None),
            Answer::Datagram(None) => {
                // Fallback to multicast (intra-vendor / legacy path, or a
                // transport with no address at all).
                let res = ctx.transport.send(&acknack_packet);
                (res, None)
            }
            Answer::Datagram(Some(origin)) => {
                match resolve_metatraffic_dest(
                    &hb.writer_guid_prefix,
                    &hb.writer_entity_id,
                    origin,
                    &ctx.discovery_fsm,
                ) {
                    Some(dest) => {
                        let res = ctx
                            .transport
                            .send_to_endpoint(&acknack_packet, &dest)
                            .map(|_| ());
                        (res, Some(dest))
                    }
                    None => {
                        log::debug!(
                            "[reader] relayed origin (behind an INFO_SRC) and writer {:02x?} \
                             with no discovered locator: no reply address, dropping ACKNACK",
                            &hb.writer_guid_prefix[..4]
                        );
                        return;
                    }
                }
            }
        };

        match send_result {
            Err(e) => log::debug!("[reader] Failed to send ACKNACK: {}", e),
            Ok(()) => {
                ctx.credit.mark_acknack_sent(&writer_key);
                log::trace!(
                    "[reader] Sent ACKNACK count={} base={} missing={} final={} dst={:?}",
                    answer.count,
                    answer.bitmap_base,
                    answer.missing.len(),
                    answer.final_flag,
                    dest,
                );
            }
        }
    }
}

/// Resolve peer's metatraffic unicast address from SPDP discovery data.
///
/// RTPS control messages (HEARTBEAT, ACKNACK, GAP) are exchanged on the
/// metatraffic channel. When a HEARTBEAT arrives on the user-data channel
/// (e.g. a compound [DATA+HEARTBEAT] datagram), the UDP source address
/// is the sender's user-data port -- NOT the metatraffic port. That source
/// port is not a locator the peer announced for receiving, so an ACKNACK
/// sent back to it may never be read.
///
/// This function looks up the peer's declared metatraffic unicast locator
/// from SPDP, falling back to `origin`'s reply address if the peer is not
/// yet known (`None` behind an INFO_SRC, RTPS 2.5 8.3.8.10), then to the
/// WriterProxy's other discovered locators (RTPS 2.5 8.4.10.4, 8.4.12.2:
/// a StatefulReader answers through the proxy of the matched writer): the
/// unicast locator the writer announced in SEDP, else its participant's
/// default unicast one. A matched writer relayed through an INFO_SRC is
/// thus answered whenever discovery recorded any locator for it; only a
/// writer with none at all gets no ACKNACK. An INFO_REPLY plays no part
/// (`Origin::reply`): only a Reliable StatelessWriter reads it (8.4.8.2.6).
fn resolve_metatraffic_dest(
    peer_guid_prefix: &[u8; 12],
    writer_entity_id: &[u8; 4],
    origin: Origin,
    fsm: &Option<Arc<DiscoveryFsm>>,
) -> Option<SocketAddr> {
    let resolved = fsm
        .as_ref()
        .and_then(|fsm| fsm.metatraffic_locator_for(peer_guid_prefix, origin));
    if let Some(ep) = resolved {
        log::debug!(
            "[reader] Resolved peer metatraffic {} (origin {:?})",
            ep,
            origin
        );
        return Some(ep);
    }
    // Peer not in FSM yet (startup race) -- fall back to the reply address,
    // when there is one; else to what discovery recorded for the writer.
    let fallback = origin.reply().or_else(|| {
        let registry = fsm.as_ref()?.endpoint_registry();
        let mut writer = [0u8; 16];
        writer[..12].copy_from_slice(peer_guid_prefix);
        writer[12..].copy_from_slice(writer_entity_id);
        let mut participant = writer;
        participant[12..].copy_from_slice(&crate::core::rtps_constants::RTPS_ENTITYID_PARTICIPANT);
        registry
            .get_writer_locator(&GUID::from_bytes(writer))
            .or_else(|| registry.get(&GUID::from_bytes(participant)))
    });
    log::debug!(
        "[reader] Peer has no metatraffic locator, fallback to {:?} (prefix={:02x?})",
        fallback,
        &peer_guid_prefix[..4]
    );
    fallback
}

impl HeartbeatHandler for ReaderHeartbeatHandler {
    // KEYSTONE NOTE (RTPS v2.5 Sec.8.4.12.2): with the Two-Ring architecture
    // (`ENABLE_TWO_RING_CONTROL = true`, the production default), user-data
    // HEARTBEATs arriving over UDP are routed to the control channel and
    // answered by the ControlHandler -- they never reach this handler (the
    // MulticastListener diverts HBs with `control_tx` present, bypassing
    // `deliver_heartbeat`). This handler answers the other doors: the
    // unicast TCP/QUIC router and the no-`control_tx` fallback. Both answer
    // from the same per-reader WriterProxy in the participant's registry.
    fn on_heartbeat(&self, heartbeat_bytes: &[u8], origin: Option<Origin>) {
        self.service_all(heartbeat_bytes, Answer::Datagram(origin));
    }

    fn on_heartbeat_over_stream(&self, heartbeat_bytes: &[u8], connection: &dyn StreamReply) {
        self.service_all(heartbeat_bytes, Answer::Stream(connection));
    }
}

impl ReaderHeartbeatHandler {
    /// Answer every HEARTBEAT of `heartbeat_bytes`, each at `answer`.
    fn service_all(&self, heartbeat_bytes: &[u8], answer: Answer<'_>) {
        // Use full packet decoder to extract GUID prefix and entity IDs.
        //
        // There is no fallback, and there must not be one. Every caller of
        // `deliver_heartbeat` hands over a whole datagram - `engine::router`,
        // `engine::unicast_router` and the registry's own tests - never a bare
        // submessage body. A fallback to `decode_cdr2_le` would be wrong: that
        // decoder reads its
        // first eight octets as firstSN and the next eight as lastSN: handed
        // a datagram it reads "RTPS" plus the version and vendor id as a
        // firstSN of ~7.2e16, and eight octets of the writer's guid prefix as
        // a lastSN. Those two numbers would then become a gap range. A refusal is
        // the only honest answer to a packet this function could not parse.
        //
        // Sec.8.3.3: submessages are independently valid, and a participant
        // batches one HEARTBEAT per writer it is announcing for, so one
        // datagram carries several. Servicing only the first would leave every
        // other writer unanswered (the second writer would never see an
        // ACKNACK).
        let heartbeats = HeartbeatMsg::decode_all_from_packet(heartbeat_bytes);
        if heartbeats.is_empty() {
            log::debug!("[reader] Failed to decode Heartbeat message");
            return;
        }

        for hb in &heartbeats {
            self.service_heartbeat(hb, answer);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::discovery::multicast::control_parser::parse_all_acknack_submessages;
    use crate::core::discovery::GUID;
    use crate::protocol::builder::{build_heartbeat_packet_with_context, RtpsEndpointContext};
    use crate::protocol::discovery::SpdpData;
    use crate::transport::{PortMapping, UdpTransport};
    use std::net::UdpSocket;
    use std::time::Duration;

    /// A GUID from its prefix and entity id.
    fn guid_of(prefix: [u8; 12], entity_id: [u8; 4]) -> [u8; 16] {
        let mut guid = [0u8; 16];
        guid[..12].copy_from_slice(&prefix);
        guid[12..].copy_from_slice(&entity_id);
        guid
    }

    /// A sender transport on a domain leased to this test alone. Probing
    /// domain 0 for a free participant id (`PortMapping::auto_assign`) and
    /// binding it afterwards raced the other tests of this module: 6 failed
    /// binds (`AddrInUse`) in 40 runs of the module.
    fn sender_transport() -> (crate::test_support::domains::DomainLease, Arc<UdpTransport>) {
        let lease = crate::test_support::domains::unique_domain();
        let mapping = PortMapping::calculate(lease.id(), 2).expect("port mapping");
        let transport = Arc::new(
            UdpTransport::new(lease.id(), 2, mapping).expect("sender transport must bind"),
        );
        (lease, transport)
    }

    /// The credit of reader `prefix` + `reader_entity_id`, matched with
    /// `writers`: the handler answers those writers only.
    fn matched_credit(
        prefix: [u8; 12],
        reader_entity_id: [u8; 4],
        writers: &[[u8; 16]],
    ) -> ReaderAckCredit {
        let credit = ReaderAckCredit::new(
            crate::core::reader::ReaderProxyRegistry::new(),
            guid_of(prefix, reader_entity_id),
        );
        for writer in writers {
            credit.match_writer(*writer);
        }
        credit
    }

    /// Drives a real `UdpTransport` end to end: a HEARTBEAT announcing
    /// [1, 5] to a reader that received nothing yet leaves 1..=5 all
    /// missing. Asserts the wire ACKNACK has `readerSNState.base == 1` with
    /// bits 1..=5 set.
    #[test]
    fn heartbeat_1_to_5_produces_acknack_base_1_bits_1_to_5() {
        let recv_socket = UdpSocket::bind("127.0.0.1:0").expect("bind receiver");
        recv_socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set read timeout");
        let recv_addr = recv_socket.local_addr().expect("receiver local addr");

        let (_lease, transport) = sender_transport();

        let our_guid_prefix = [0xAAu8; 12];
        let reader_entity_id = [0x01, 0x02, 0x03, 0x04];
        let writer_guid_prefix = [0xBBu8; 12];
        let writer_entity_id = [0x00, 0x00, 0x02, 0x02];

        let handler = ReaderHeartbeatHandler::with_acknack_context(
            matched_credit(
                our_guid_prefix,
                reader_entity_id,
                &[guid_of(writer_guid_prefix, writer_entity_id)],
            ),
            transport,
            None,
            "T",
        );

        let ctx = RtpsEndpointContext {
            guid_prefix: writer_guid_prefix,
            reader_entity_id,
            writer_entity_id,
            encapsulation_kind: 0,
            publisher_entity_id: [0x00, 0x00, 0x01, 0x08],
        };
        let hb_packet = build_heartbeat_packet_with_context(&ctx, 1, 5, 1);

        // `source_addr` stands in for the HEARTBEAT's UDP source: with no
        // discovery FSM attached, `resolve_metatraffic_dest` falls back to
        // it unchanged, so the ACKNACK goes straight to our receiver.
        handler.on_heartbeat(&hb_packet, Some(Origin::direct(recv_addr)));

        let mut buf = [0u8; 512];
        let (len, _from) = recv_socket
            .recv_from(&mut buf)
            .expect("the ACKNACK must arrive at the resolved destination");
        let packet = &buf[..len];

        assert_eq!(packet[36], 0x06, "ACKNACK submessage id at offset 36");
        let parsed = parse_all_acknack_submessages(packet)
            .into_iter()
            .next()
            .expect("valid ACKNACK packet");
        assert_eq!(parsed.bitmap_base, 1, "readerSNState.base must be 1");
        assert_eq!(
            parsed.missing_ranges,
            vec![1..6],
            "bits 1..=5 must be set missing"
        );

        // Hand-derived from RTPS v2.5 Sec.9.4.5.3 (AckNack Submessage) and
        // Sec.9.4.2.6 (SequenceNumberSet), not from `parse_acknack_submessage`
        // above: the proof this HEARTBEAT->ACKNACK response is wire-correct
        // must not rest solely on our own decoder agreeing with our own
        // encoder. Byte-for-byte:
        //   [0]     0x06            submessage id: ACKNACK
        //   [1]     0x01            flags: E(ndianness)=1, F(inal)=0 --
        //                           this reader has gaps, so it wants a
        //                           HEARTBEAT/ACKNACK reply, not silence
        //   [2..4]  0x1C, 0x00      octetsToNextHeader = 28 LE (everything
        //                           below except this 4-byte header)
        //   [4..8]  01 02 03 04     readerId = reader_entity_id
        //   [8..12] 00 00 02 02     writerId = writer_entity_id
        //   [12..16] 0,0,0,0        bitmapBase high i32 LE = 0
        //   [16..20] 1,0,0,0        bitmapBase low u32 LE = 1
        //   [20..24] 5,0,0,0        numBits = 5 (SNs 1..=5 all requested)
        //   [24..28] 0,0,0,0xF8     bitmap[0] = 0xF8000000 LE: RTPS
        //                           Sec.9.4.2.6 numbers bit 0 as the SET's
        //                           MSB, so missing SNs 1..=5 (bit_pos
        //                           0..=4 from the base) set bits 31..27
        //   [28..32] 1,0,0,0        count = 1 LE: the handler's first
        //                           ACKNACK ever (AtomicU32 seeded at 1)
        const EXPECTED_ACKNACK_SUBMSG: [u8; 32] = [
            0x06, 0x01, 0x1C, 0x00, // id, flags(E=1,F=0), octetsToNextHeader=28 LE
            0x01, 0x02, 0x03, 0x04, // readerId
            0x00, 0x00, 0x02, 0x02, // writerId
            0x00, 0x00, 0x00, 0x00, // bitmapBase high=0 LE
            0x01, 0x00, 0x00, 0x00, // bitmapBase low=1 LE
            0x05, 0x00, 0x00, 0x00, // numBits=5 LE
            0x00, 0x00, 0x00, 0xF8, // bitmap[0]=0xF8000000 LE (bits 0..=4 set, MSB-first)
            0x01, 0x00, 0x00, 0x00, // count=1 LE
        ];
        assert_eq!(
            &packet[36..68],
            &EXPECTED_ACKNACK_SUBMSG[..],
            "ACKNACK submessage bytes must match the RTPS v2.5 Sec.9.4.5.3 wire \
             layout exactly, independent of our own parser"
        );
    }

    /// A datagram this handler cannot decode must produce silence.
    ///
    /// There is no fallback to `HeartbeatMsg::decode_cdr2_le` on this input:
    /// that decoder reads its first sixteen octets as firstSN and lastSN, and
    /// on a whole datagram those octets are "RTPS", the protocol version, the
    /// vendor id and eight octets of the writer's guid prefix. It would answer
    /// a firstSN of some 7.2e16, and an ACKNACK would go out about a gap that
    /// never existed.
    #[test]
    fn a_heartbeat_the_decoder_refuses_sends_no_acknack() {
        let recv_socket = UdpSocket::bind("127.0.0.1:0").expect("bind receiver");
        recv_socket
            .set_read_timeout(Some(Duration::from_millis(400)))
            .expect("set read timeout");
        let recv_addr = recv_socket.local_addr().expect("receiver local addr");

        let (_lease, transport) = sender_transport();

        let reader_entity_id = [0x01, 0x02, 0x03, 0x04];
        let handler = ReaderHeartbeatHandler::with_acknack_context(
            matched_credit(
                [0xAAu8; 12],
                reader_entity_id,
                &[guid_of([0xBBu8; 12], [0x00, 0x00, 0x02, 0x02])],
            ),
            transport,
            None,
            "T",
        );

        let ctx = RtpsEndpointContext {
            guid_prefix: [0xBBu8; 12],
            reader_entity_id,
            writer_entity_id: [0x00, 0x00, 0x02, 0x02],
            encapsulation_kind: 0,
            publisher_entity_id: [0x00, 0x00, 0x01, 0x08],
        };
        let mut hb_packet = build_heartbeat_packet_with_context(&ctx, 1, 5, 1);

        // 51 octets is one short of the smallest datagram that can hold a
        // HEARTBEAT, so `decode_from_packet` refuses it. It is still well
        // past the twenty `decode_cdr2_le` was happy with.
        assert!(hb_packet.len() > 51, "the fixture must start out valid");
        hb_packet.truncate(51);

        handler.on_heartbeat(&hb_packet, Some(Origin::direct(recv_addr)));

        let mut buf = [0u8; 512];
        assert!(
            recv_socket.recv_from(&mut buf).is_err(),
            "a datagram we could not decode must not produce an ACKNACK"
        );
    }

    /// Every registered handler is handed every HEARTBEAT; a reader answers
    /// only the writers it is matched with (RTPS 2.5 8.4.12), and under the
    /// entity id its credit carries, the one SEDP announces.
    #[test]
    fn only_a_matched_writer_is_answered_and_under_the_readers_own_id() {
        let recv_socket = UdpSocket::bind("127.0.0.1:0").expect("bind receiver");
        recv_socket
            .set_read_timeout(Some(Duration::from_millis(400)))
            .expect("set read timeout");
        let recv_addr = recv_socket.local_addr().expect("receiver local addr");

        let (_lease, transport) = sender_transport();

        let reader_entity_id = [0x00, 0x00, 0x05, 0x07];
        let matched = [0x00, 0x00, 0x02, 0x02];
        let stranger = [0x00, 0x00, 0x03, 0x02];
        let handler = ReaderHeartbeatHandler::with_acknack_context(
            matched_credit(
                [0xAAu8; 12],
                reader_entity_id,
                &[guid_of([0xBBu8; 12], matched)],
            ),
            transport,
            None,
            "T",
        );
        let heartbeat_of = |writer_entity_id: [u8; 4]| {
            build_heartbeat_packet_with_context(
                &RtpsEndpointContext {
                    guid_prefix: [0xBBu8; 12],
                    reader_entity_id: [0; 4],
                    writer_entity_id,
                    encapsulation_kind: 0,
                    publisher_entity_id: [0x00, 0x00, 0x01, 0x08],
                },
                1,
                5,
                1,
            )
        };

        let mut buf = [0u8; 512];
        handler.on_heartbeat(&heartbeat_of(stranger), Some(Origin::direct(recv_addr)));
        assert!(
            recv_socket.recv_from(&mut buf).is_err(),
            "a writer this reader is not matched with gets no ACKNACK"
        );

        handler.on_heartbeat(&heartbeat_of(matched), Some(Origin::direct(recv_addr)));
        let (len, _) = recv_socket
            .recv_from(&mut buf)
            .expect("the matched writer is answered");
        let acknacks = parse_all_acknack_submessages(&buf[..len]);
        assert_eq!(acknacks.len(), 1);
        assert_eq!(acknacks[0].reader_entity_id, reader_entity_id);
        assert_eq!(acknacks[0].writer_entity_id, matched);
    }

    /// A receiver on 127.0.0.1 and a handler for reader 0x00000507 of
    /// participant 0xAA.., matched with writer 0x00000202 of 0xBB.., over a
    /// fresh registry the test can credit.
    fn handler_matched_with_one_writer(
        read_timeout: Duration,
    ) -> (
        crate::test_support::domains::DomainLease,
        UdpSocket,
        SocketAddr,
        ReaderHeartbeatHandler,
        ReaderAckCredit,
    ) {
        let recv_socket = UdpSocket::bind("127.0.0.1:0").expect("bind receiver");
        recv_socket
            .set_read_timeout(Some(read_timeout))
            .expect("set read timeout");
        let recv_addr = recv_socket.local_addr().expect("receiver local addr");
        let (_lease, transport) = sender_transport();
        let credit = matched_credit(
            [0xAAu8; 12],
            [0x00, 0x00, 0x05, 0x07],
            &[guid_of([0xBBu8; 12], [0x00, 0x00, 0x02, 0x02])],
        );
        let handler =
            ReaderHeartbeatHandler::with_acknack_context(credit.clone(), transport, None, "T");
        (_lease, recv_socket, recv_addr, handler, credit)
    }

    fn heartbeat_to(reader_entity_id: [u8; 4], first: u64, last: u64, count: u32) -> Vec<u8> {
        build_heartbeat_packet_with_context(
            &RtpsEndpointContext {
                guid_prefix: [0xBBu8; 12],
                reader_entity_id,
                writer_entity_id: [0x00, 0x00, 0x02, 0x02],
                encapsulation_kind: 0,
                publisher_entity_id: [0x00, 0x00, 0x01, 0x08],
            },
            first,
            last,
            count,
        )
    }

    /// The next ACKNACK the socket receives, with its count: the ACKNACK is
    /// the datagram's last submessage and closes on its little-endian count
    /// (RTPS 2.5 9.4.5.3).
    fn next_acknack(
        socket: &UdpSocket,
    ) -> (
        crate::core::discovery::multicast::control_types::AckNackInfo,
        u32,
    ) {
        let mut buf = [0u8; 512];
        let (len, _) = socket.recv_from(&mut buf).expect("an ACKNACK");
        let mut acknacks = parse_all_acknack_submessages(&buf[..len]);
        assert_eq!(acknacks.len(), 1);
        let mut count = [0u8; 4];
        count.copy_from_slice(&buf[len - 4..len]);
        (acknacks.remove(0), u32::from_le_bytes(count))
    }

    /// A HEARTBEAT is an announcement, not a delivery: two in a row with
    /// no DATA in between must both request 1..=5. Raising a high-water mark
    /// to each HEARTBEAT's lastSN would acknowledge the second one whole
    /// (base 6) with nothing received. Once the
    /// subscriber credits the five DATA, the answer acknowledges them.
    #[test]
    fn a_heartbeat_is_never_acknowledged_beyond_what_was_received() {
        let (_lease, socket, addr, handler, credit) =
            handler_matched_with_one_writer(Duration::from_secs(2));
        let writer = guid_of([0xBBu8; 12], [0x00, 0x00, 0x02, 0x02]);

        assert!(!credit.acknack_sent(&writer));
        handler.on_heartbeat(&heartbeat_to([0; 4], 1, 5, 1), Some(Origin::direct(addr)));
        let (first, first_count) = next_acknack(&socket);
        assert!(
            credit.acknack_sent(&writer),
            "the answer left: its window runs"
        );
        // Past the proxy's 10 ms rate limit.
        std::thread::sleep(Duration::from_millis(20));
        handler.on_heartbeat(&heartbeat_to([0; 4], 1, 5, 2), Some(Origin::direct(addr)));
        let (second, second_count) = next_acknack(&socket);
        for acknack in [&first, &second] {
            assert_eq!(acknack.bitmap_base, 1, "{acknack:?}");
            assert_eq!(acknack.missing_ranges, vec![1..6], "{acknack:?}");
        }

        for seq in 1..=5 {
            credit.on_data(writer, seq);
        }
        std::thread::sleep(Duration::from_millis(20));
        handler.on_heartbeat(&heartbeat_to([0; 4], 1, 5, 3), Some(Origin::direct(addr)));
        let (third, third_count) = next_acknack(&socket);
        assert_eq!(third.bitmap_base, 6);
        assert!(third.missing_ranges.is_empty());
        // One count sequence for the pair (RTPS 2.5 8.3.8.1).
        assert_eq!((first_count, second_count, third_count), (1, 2, 3));
    }

    /// A HEARTBEAT addressed to another reader is not this reader's to
    /// answer; one addressed to it, or to ENTITYID_UNKNOWN, is.
    #[test]
    fn a_heartbeat_addressed_to_another_reader_is_not_answered() {
        let (_lease, socket, addr, handler, _credit) =
            handler_matched_with_one_writer(Duration::from_millis(400));
        let mut buf = [0u8; 512];

        handler.on_heartbeat(
            &heartbeat_to([0x00, 0x00, 0x06, 0x07], 1, 5, 1),
            Some(Origin::direct(addr)),
        );
        assert!(
            socket.recv_from(&mut buf).is_err(),
            "addressed to reader 0x00000607, not to this one"
        );

        handler.on_heartbeat(
            &heartbeat_to([0x00, 0x00, 0x05, 0x07], 1, 5, 2),
            Some(Origin::direct(addr)),
        );
        assert_eq!(
            next_acknack(&socket).0.reader_entity_id,
            [0x00, 0x00, 0x05, 0x07]
        );
    }

    /// RTPS 2.5 8.3.4 / 8.3.8.10: behind an INFO_SRC there is no reply
    /// address. With no DiscoveryFsm to resolve the writer's participant by
    /// GUID prefix, a relayed HEARTBEAT must get NOTHING back at the
    /// address this test probes.
    ///
    /// What this test observes: nothing arrives at `addr`, the only
    /// destination it can watch. It does NOT observe multicast (there is no
    /// listener on the transport's multicast group here, joining it in a
    /// unit test is its own source of flakiness on hosts that route multicast
    /// through a VPN tunnel). The stronger claim
    /// -- that a relayed, unresolved origin never falls through to the
    /// multicast send either -- holds by construction, not by this test:
    /// `service_heartbeat`'s `Some(origin)` arm returns on an unresolved
    /// destination before it ever reaches the `ctx.transport.send(..)` call
    /// multicast uses, which only the `None` arm (`origin` field is a plain
    /// `Option`, not literally reachable from `Some`) can take.
    #[test]
    fn a_relayed_heartbeat_with_no_fsm_gets_no_acknack() {
        let (_lease, socket, addr, handler, _credit) =
            handler_matched_with_one_writer(Duration::from_millis(300));
        let mut buf = [0u8; 512];

        handler.on_heartbeat(&heartbeat_to([0; 4], 1, 5, 1), Some(Origin::relayed(addr)));

        assert!(
            socket.recv_from(&mut buf).is_err(),
            "no FSM to resolve the writer and no reply address: nothing must reach `addr`"
        );
    }

    /// The same relayed HEARTBEAT, but the writer's participant is already
    /// known from SPDP/SEDP: the ACKNACK goes to the FSM's own record of it
    /// (`peer_metatraffic`), never to `forwarder`. `next_acknack` reading
    /// from the socket bound at `peer_metatraffic` is itself the proof: had
    /// the handler used the forwarder's address, nothing would ever arrive
    /// there and the test would time out.
    #[test]
    fn a_relayed_heartbeat_from_a_known_writer_reaches_its_fsm_address() {
        let recv_socket = UdpSocket::bind("127.0.0.1:0").expect("bind receiver");
        recv_socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set read timeout");
        let peer_metatraffic = recv_socket.local_addr().expect("receiver local addr");
        let forwarder: SocketAddr = "203.0.113.9:9999".parse().expect("valid address");

        let (_lease, transport) = sender_transport();
        let credit = matched_credit(
            [0xAAu8; 12],
            [0x00, 0x00, 0x05, 0x07],
            &[guid_of([0xBBu8; 12], [0x00, 0x00, 0x02, 0x02])],
        );
        let fsm = Arc::new(DiscoveryFsm::new(
            GUID::new([0xAAu8; 12], [0, 0, 1, 0xC1]),
            30_000,
        ));
        fsm.handle_spdp(SpdpData {
            participant_guid: GUID::new([0xBBu8; 12], [0, 0, 1, 0xC1]),
            lease_duration_ms: 30_000,
            domain_id: 0,
            metatraffic_unicast_locators: vec![peer_metatraffic],
            default_unicast_locators: vec![],
            default_multicast_locators: vec![],
            metatraffic_multicast_locators: vec![],
            identity_token: None,
            permissions_token: None,
            participant_security_info: None,
            vendor_id: None,
            hdds_capabilities: None,
            builtin_endpoint_set: None,
        });
        let handler =
            ReaderHeartbeatHandler::with_acknack_context(credit, transport, Some(fsm), "T");

        handler.on_heartbeat(
            &heartbeat_to([0; 4], 1, 5, 1),
            Some(Origin::relayed(forwarder)),
        );

        let (acknack, _count) = next_acknack(&recv_socket);
        assert_eq!(acknack.bitmap_base, 1);
        assert_eq!(acknack.missing_ranges, vec![1..6]);
    }

    /// DDS Security v1.1 Sec.8.8.7.1: a HEARTBEAT from a writer the security
    /// plugins do not admit (an unauthenticated participant's, on a topic
    /// the governance protects) gets no ACKNACK and leaves the reader's
    /// WriterProxy as it was; the same writer on an unprotected topic, the
    /// control, is answered.
    #[test]
    #[cfg(feature = "security")]
    fn a_heartbeat_from_a_writer_not_admitted_is_not_answered() {
        use crate::security::access::{
            BasicProtectionKind, DiscoveryGovernance, DomainRule, ProtectionKind, TopicRule,
        };
        let writer = guid_of([0xBBu8; 12], [0x00, 0x00, 0x02, 0x02]);
        let answered = |topic: &str| {
            let recv_socket = UdpSocket::bind("127.0.0.1:0").expect("bind receiver");
            recv_socket
                .set_read_timeout(Some(Duration::from_millis(500)))
                .expect("set read timeout");
            let peer_metatraffic = recv_socket.local_addr().expect("receiver local addr");
            let (_lease, transport) = sender_transport();
            let credit = matched_credit([0xAAu8; 12], [0x00, 0x00, 0x05, 0x07], &[writer]);
            let mut fsm = DiscoveryFsm::new(GUID::new([0xAAu8; 12], [0, 0, 1, 0xC1]), 30_000);
            let rule = |expression: &str, access: bool| TopicRule {
                topic_expression: expression.to_string(),
                enable_discovery_protection: false,
                enable_liveliness_protection: false,
                enable_read_access_control: access,
                enable_write_access_control: access,
                metadata_protection_kind: ProtectionKind::None,
                data_protection_kind: BasicProtectionKind::None,
            };
            fsm.set_discovery_governance(Some(DiscoveryGovernance::new(DomainRule {
                domains: vec![0],
                domain_ranges: vec![],
                allow_unauthenticated: true,
                enable_join_access_control: true,
                discovery_protection_kind: ProtectionKind::None,
                liveliness_protection_kind: ProtectionKind::None,
                rtps_protection_kind: ProtectionKind::None,
                topic_rules: vec![rule("Open*", true), rule("Free*", false)],
            })));
            fsm.handle_spdp(SpdpData {
                participant_guid: GUID::new([0xBBu8; 12], [0, 0, 1, 0xC1]),
                lease_duration_ms: 30_000,
                domain_id: 0,
                metatraffic_unicast_locators: vec![peer_metatraffic],
                default_unicast_locators: vec![],
                default_multicast_locators: vec![],
                metatraffic_multicast_locators: vec![],
                identity_token: None,
                permissions_token: None,
                participant_security_info: None,
                vendor_id: None,
                hdds_capabilities: None,
                builtin_endpoint_set: None,
            });
            let handler = ReaderHeartbeatHandler::with_acknack_context(
                credit.clone(),
                transport,
                Some(Arc::new(fsm)),
                topic,
            );
            let forwarder: SocketAddr = "203.0.113.9:9999".parse().expect("valid address");
            handler.on_heartbeat(
                &heartbeat_to([0; 4], 1, 5, 1),
                Some(Origin::relayed(forwarder)),
            );
            let mut buf = [0u8; 512];
            let received = recv_socket.recv_from(&mut buf).is_ok();
            (received, credit.acknack_sent(&writer))
        };
        assert_eq!(answered("FreeData"), (true, true), "control: answered");
        assert_eq!(
            answered("OpenData"),
            (false, false),
            "a writer not admitted was answered, or moved the WriterProxy"
        );
    }

    /// RTPS 2.5 8.4.12.2 / 8.4.10.4: the reader answers through its
    /// WriterProxy's discovered locator. A HEARTBEAT behind an INFO_REPLY
    /// naming another address (8.3.8.9, read only by a Reliable
    /// StatelessWriter, 8.4.8.2.6) is answered there all the same: nothing
    /// reaches the INFO_REPLY locator, nor the source.
    #[test]
    fn a_heartbeat_behind_an_info_reply_is_answered_at_the_writers_locator() {
        let bound = || {
            let socket = UdpSocket::bind("127.0.0.1:0").expect("bind");
            socket
                .set_read_timeout(Some(Duration::from_millis(500)))
                .expect("set read timeout");
            let address = socket.local_addr().expect("local addr");
            (socket, address)
        };
        let (recorded, recorded_addr) = bound();
        let (source, source_addr) = bound();
        let (named, named_addr) = bound();
        let SocketAddr::V4(named_v4) = named_addr else {
            panic!("bound on IPv4");
        };

        let (_lease, transport) = sender_transport();
        let credit = matched_credit(
            [0xAAu8; 12],
            [0x00, 0x00, 0x05, 0x07],
            &[guid_of([0xBBu8; 12], [0x00, 0x00, 0x02, 0x02])],
        );
        let fsm = Arc::new(DiscoveryFsm::new(
            GUID::new([0xAAu8; 12], [0, 0, 1, 0xC1]),
            30_000,
        ));
        fsm.handle_spdp(SpdpData {
            participant_guid: GUID::new([0xBBu8; 12], [0, 0, 1, 0xC1]),
            lease_duration_ms: 30_000,
            domain_id: 0,
            metatraffic_unicast_locators: vec![recorded_addr],
            default_unicast_locators: vec![],
            default_multicast_locators: vec![],
            metatraffic_multicast_locators: vec![],
            identity_token: None,
            permissions_token: None,
            participant_security_info: None,
            vendor_id: None,
            hdds_capabilities: None,
            builtin_endpoint_set: None,
        });
        let handler =
            ReaderHeartbeatHandler::with_acknack_context(credit, transport, Some(fsm), "T");

        handler.on_heartbeat(
            &heartbeat_to([0; 4], 1, 5, 1),
            Some(Origin::direct(source_addr).replying_to(Some(named_v4))),
        );

        let (acknack, _count) = next_acknack(&recorded);
        assert_eq!(acknack.missing_ranges, vec![1..6]);
        let mut buf = [0u8; 512];
        assert!(
            named.recv_from(&mut buf).is_err(),
            "not the INFO_REPLY locator"
        );
        assert!(source.recv_from(&mut buf).is_err(), "not the source");
    }

    /// A HEARTBEAT that arrived on a connection is answered on it: the
    /// ACKNACK, decoded from the bytes the connection was handed, names
    /// what the reader misses; nothing goes to the UDP transport.
    #[test]
    fn a_heartbeat_over_a_stream_is_answered_on_it() {
        struct Connection(std::sync::Mutex<Vec<Vec<u8>>>);
        impl StreamReply for Connection {
            fn send_reply(&self, message: &[u8]) -> std::io::Result<()> {
                self.0.lock().expect("sent").push(message.to_vec());
                Ok(())
            }
        }
        let (_lease, transport) = sender_transport();
        let handler = ReaderHeartbeatHandler::with_acknack_context(
            matched_credit(
                [0xAAu8; 12],
                [0x00, 0x00, 0x05, 0x07],
                &[guid_of([0xBBu8; 12], [0x00, 0x00, 0x02, 0x02])],
            ),
            transport,
            None,
            "T",
        );
        let connection = Connection(std::sync::Mutex::new(Vec::new()));

        handler.on_heartbeat_over_stream(&heartbeat_to([0; 4], 1, 5, 1), &connection);

        let sent = connection.0.into_inner().expect("sent");
        assert_eq!(sent.len(), 1, "one ACKNACK, on the connection");
        let acknacks = parse_all_acknack_submessages(&sent[0]);
        assert_eq!(acknacks.len(), 1);
        assert_eq!(acknacks[0].writer_entity_id, [0x00, 0x00, 0x02, 0x02]);
        assert_eq!(acknacks[0].reader_entity_id, [0x00, 0x00, 0x05, 0x07]);
        assert_eq!(acknacks[0].missing_ranges, vec![1..6]);
    }

    /// RTPS 2.5 8.4.12.2 / 8.4.10.4: a relayed HEARTBEAT (behind an
    /// INFO_SRC, no reply locator, 8.3.8.10) from a matched writer whose
    /// participant announced no metatraffic locator is still answered,
    /// through the WriterProxy's other discovered locators: the one the
    /// writer announced in SEDP, else its participant's default unicast
    /// locator. Dropping that ACKNACK would stall the writer for good.
    #[test]
    fn a_relayed_heartbeat_is_answered_at_the_writer_proxys_other_locators() {
        const WRITER_PREFIX: [u8; 12] = [0xBBu8; 12];
        const WRITER_EID: [u8; 4] = [0x00, 0x00, 0x02, 0x02];
        let forwarder: SocketAddr = "203.0.113.9:9999".parse().expect("valid address");
        let bound = || {
            let socket = UdpSocket::bind("127.0.0.1:0").expect("bind");
            socket
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("set read timeout");
            let address = socket.local_addr().expect("local addr");
            (socket, address)
        };
        let (_lease, transport) = sender_transport();

        for announced in ["writer", "participant"] {
            let (socket, address) = bound();
            let fsm = Arc::new(DiscoveryFsm::new(
                GUID::new([0xAAu8; 12], [0, 0, 1, 0xC1]),
                30_000,
            ));
            let registry = fsm.endpoint_registry();
            if announced == "writer" {
                registry.register_writer_locator(GUID::new(WRITER_PREFIX, WRITER_EID), address);
            } else {
                registry.register(GUID::new(WRITER_PREFIX, [0, 0, 1, 0xC1]), address);
            }
            let handler = ReaderHeartbeatHandler::with_acknack_context(
                matched_credit(
                    [0xAAu8; 12],
                    [0x00, 0x00, 0x05, 0x07],
                    &[guid_of(WRITER_PREFIX, WRITER_EID)],
                ),
                Arc::clone(&transport),
                Some(fsm),
                "T",
            );

            handler.on_heartbeat(
                &heartbeat_to([0; 4], 1, 5, 1),
                Some(Origin::relayed(forwarder)),
            );

            let (acknack, _count) = next_acknack(&socket);
            assert_eq!(acknack.missing_ranges, vec![1..6], "{announced} locator");
        }
    }

    /// The door, not the primitive: `decode_all_from_packet` reading two
    /// HEARTBEATs proves nothing about the reader ANSWERING two. This
    /// drives the real handler over a real socket and counts the ACKNACKs.
    ///
    /// If the second writer's announcement were decoded away with the
    /// datagram, one ACKNACK would leave, addressed to writer 0x00000202, and
    /// writer 0x00000B02 would never learn the reader was missing 1..=3.
    #[test]
    fn a_datagram_carrying_two_heartbeats_is_answered_twice() {
        let recv_socket = UdpSocket::bind("127.0.0.1:0").expect("bind receiver");
        recv_socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set read timeout");
        let recv_addr = recv_socket.local_addr().expect("receiver local addr");

        let (_lease, transport) = sender_transport();

        let our_guid_prefix = [0xAAu8; 12];
        let reader_entity_id = [0x01, 0x02, 0x03, 0x04];
        let writer_guid_prefix = [0xBBu8; 12];
        const FIRST_WRITER: [u8; 4] = [0x00, 0x00, 0x02, 0x02];
        const SECOND_WRITER: [u8; 4] = [0x00, 0x00, 0x0B, 0x02];

        let handler = ReaderHeartbeatHandler::with_acknack_context(
            matched_credit(
                our_guid_prefix,
                reader_entity_id,
                &[
                    guid_of(writer_guid_prefix, FIRST_WRITER),
                    guid_of(writer_guid_prefix, SECOND_WRITER),
                ],
            ),
            transport,
            None,
            "T",
        );

        let heartbeat_of = |writer_entity_id: [u8; 4], first: u64, last: u64| {
            build_heartbeat_packet_with_context(
                &RtpsEndpointContext {
                    guid_prefix: writer_guid_prefix,
                    reader_entity_id,
                    writer_entity_id,
                    encapsulation_kind: 0,
                    publisher_entity_id: [0x00, 0x00, 0x01, 0x08],
                },
                first,
                last,
                1,
            )
        };

        // One datagram, two announcements: the header of the first, then the
        // HEARTBEAT submessage of each. The fixture asserts the shape it
        // relies on rather than assuming it - header 20 + 2 * (4 + 28).
        let first = heartbeat_of(FIRST_WRITER, 1, 5);
        let second = heartbeat_of(SECOND_WRITER, 1, 3);
        assert_eq!(first.len(), 52, "RTPS header 20 + HEARTBEAT 4 + 28");
        assert_eq!(second.len(), 52);
        let mut batched = first;
        batched.extend_from_slice(&second[20..]);
        assert_eq!(batched.len(), 84);
        assert_eq!(batched[20], 0x07, "first submessage is the HEARTBEAT");
        assert_eq!(batched[52], 0x07, "second submessage is the HEARTBEAT");

        handler.on_heartbeat(&batched, Some(Origin::direct(recv_addr)));

        // Collect by writerId rather than by arrival order: two datagrams on
        // loopback are not a sequence this test is entitled to assume.
        let mut answered = Vec::new();
        for _ in 0..2 {
            let mut buf = [0u8; 512];
            let (len, _from) = recv_socket
                .recv_from(&mut buf)
                .expect("every HEARTBEAT of the datagram is owed an ACKNACK");
            let packet = &buf[..len];
            assert_eq!(packet[36], 0x06, "ACKNACK submessage id at offset 36");
            let parsed = parse_all_acknack_submessages(packet)
                .into_iter()
                .next()
                .expect("valid ACKNACK packet");
            let writer_id: [u8; 4] = packet[44..48].try_into().expect("writerId is 4 octets");
            answered.push((writer_id, parsed.bitmap_base, parsed.missing_ranges));
        }
        answered.sort_by_key(|(writer_id, _, _)| *writer_id);

        assert_eq!(answered.len(), 2, "one ACKNACK per announcement");
        let (first_id, first_base, first_missing) = &answered[0];
        let (second_id, second_base, second_missing) = &answered[1];
        assert_eq!(*first_id, FIRST_WRITER);
        assert_eq!(*first_base, 1);
        assert_eq!(
            *first_missing,
            vec![1..6],
            "writer 0x00000202 announced 1..=5, so all five are missing"
        );
        assert_eq!(*second_id, SECOND_WRITER);
        assert_eq!(*second_base, 1);
        assert_eq!(
            *second_missing,
            vec![1..4],
            "writer 0x00000B02 announced 1..=3, and is answered for ITS OWN range"
        );
    }
}
