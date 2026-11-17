// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! The one traversal of an RTPS message's submessages.
//!
//! A datagram is a header followed by a chain of submessages (DDS-RTPS v2.5
//! Sec.8.3.3). Walking that chain is mechanical - read four header bytes,
//! honour the endianness flag, stop on the sentinel, realign, and try to
//! recover when a vendor writes a length that does not fit - and it is
//! exactly the part that must not be written twice in this module (in
//! `classify_rtps` and in `scan_all_data_frags`): two copies drift, and only
//! one of them would carry the recovery below.
//!
//! So the traversal lives here once and the callers bring their own
//! question. `classify_rtps` asks "what is this datagram", which forces it
//! to elect one winner among the submessages; `for_each_data_submessage`
//! asks "what does this datagram carry", which does not.
//!
//! INFO_DST and INFO_TS are applied here rather than by the callers,
//! because they are receiver state: RTPS v2.5 Sec.8.3.8.8 and Sec.8.3.8.11
//! make them apply to the submessages that FOLLOW them. Each visit
//! therefore gets a copy of the context as it stood when that submessage
//! was reached, not the datagram's running total - a datagram carrying
//! [INFO_TS(a), DATA, INFO_TS(b), DATA] gives the first DATA `a` and the
//! second `b`, where a single accumulator gives both of them `b`.

use super::super::meta::ReplyTo;
use super::super::{Origin, RtpsContext};
use super::submessage;
use crate::config::CLASSIFIER_SCAN_WINDOW;
use std::net::{Ipv4Addr, SocketAddrV4};

/// One submessage, as the walk found it.
pub(crate) struct Submessage {
    /// Offset of the submessage header in the datagram.
    pub offset: usize,
    /// Submessage id (RTPS v2.5 Table 8.13): 0x15 = DATA, 0x16 = DATA_FRAG...
    pub id: u8,
    /// Submessage flags; bit 0 is the endianness of every field that follows.
    pub flags: u8,
    /// Octets from the end of this header to the next one; 0 means "last",
    /// or for PAD and INFO_TS an empty body (RTPS 2.5 9.4.5.1.3).
    ///
    /// This is the DECLARED value, straight off the wire. Use `body_end` to
    /// bound a read: a visitor that computes `offset + 4 + octets_to_next`
    /// itself gets `offset + 4` for the last submessage of a datagram, which
    /// is an empty body where the spec says the body runs to the end.
    pub octets_to_next: u16,
    /// One past the last octet of this submessage's contents.
    ///
    /// RTPS 2.5 9.4.5.1.3: `octetsToNextHeader == 0` means this submessage is
    /// the last one and extends to the end of the message (for PAD and
    /// INFO_TS: an empty body); otherwise the contents end where the next
    /// header begins. Clamped to the datagram either way,
    /// so it is always a valid slice bound. The computation lives here once:
    /// written out again at every consumer that reads a body, it is how a body
    /// gets cut against the datagram instead of against its own submessage.
    pub body_end: usize,
    /// INFO_DST/INFO_TS in force when this submessage was reached.
    pub context: RtpsContext,
}

/// What the visitor wants the walk to do next.
pub(crate) enum Step {
    /// Carry on to the next submessage.
    Continue,
    /// Leave the rest of the datagram unread.
    Stop,
}

/// Visit every submessage of `buf`, in wire order.
///
/// `buf` must already have passed `header::validate_and_extract_header`:
/// the walk starts at offset 20 and reads no header field itself.
///
/// Allocates nothing.
pub(crate) fn for_each_submessage<F>(buf: &[u8], mut visit: F)
where
    F: FnMut(&Submessage) -> Step,
{
    let mut offset = 20;
    let mut context = RtpsContext::default();

    while offset + 4 <= buf.len() {
        let id = buf[offset];
        let flags = buf[offset + 1];

        // octetsToNextHeader, whose endianness is the E flag in bit 0.
        let octets_to_next = if flags & 0x01 != 0 {
            u16::from_le_bytes([buf[offset + 2], buf[offset + 3]])
        } else {
            u16::from_be_bytes([buf[offset + 2], buf[offset + 3]])
        };

        // RTPS 2.5 9.4.5.1.3: octetsToNextHeader == 0 makes a submessage the
        // last of the message, running to its end - except PAD and INFO_TS,
        // for which it means an empty body with the next header right
        // behind (or the end of the message). Read as "last" for every id, an
        // INFO_TS that only invalidates the timestamp, or an empty PAD, ended
        // the walk and everything behind it went unseen.
        let empty_not_last = octets_to_next == 0 && matches!(id, PAD | INFO_TS);
        let body_end = if empty_not_last {
            offset + 4
        } else if octets_to_next == 0 {
            buf.len()
        } else {
            (offset + 4 + octets_to_next as usize).min(buf.len())
        };
        let body = body_end - (offset + 4);

        // Apply the context submessages before the visit, so a visitor that
        // stops here still sees what was in force at this point.
        //
        // A known submessage too short for its contents is invalid, and a
        // known but invalid submessage invalidates the rest of the message
        // (8.3.4.1): nothing behind it is visited, by any consumer. Reading
        // the missing octets would take them from the submessage that
        // follows - aiming everything after it at a participant nobody named
        // (INFO_DST, 8.3.8.8), or dating it with somebody else's bytes
        // (INFO_TS, 8.3.8.11).
        match id {
            INFO_TS => {
                if flags & INFO_TS_INVALIDATE != 0 {
                    // 8.3.8.11: Receiver.haveTimestamp = false.
                    context.source_timestamp = None;
                } else if body < 8 {
                    log::debug!(
                        "[RTPS-WALK] INFO_TS at offset {} carries {} octets, not a Time_t: rest of the message invalid",
                        offset,
                        body
                    );
                    return;
                } else {
                    submessage::classify_info_ts(buf, offset, flags, &mut context);
                }
            }
            INFO_DST => {
                if body < 12 {
                    log::debug!(
                        "[RTPS-WALK] INFO_DST at offset {} carries {} octets, not a GuidPrefix: rest of the message invalid",
                        offset,
                        body
                    );
                    return;
                }
                submessage::classify_info_dst(buf, offset, &mut context);
            }
            INFO_SRC => {
                if body < INFO_SRC_BODY {
                    log::debug!(
                        "[RTPS-WALK] INFO_SRC at offset {} carries {} octets, not a source: rest of the message invalid",
                        offset,
                        body
                    );
                    return;
                }
                // 8.3.8.10: haveTimestamp = false. (The new source itself is
                // applied by `split_by_receiver_state`, before any consumer
                // reads.)
                context.source_timestamp = None;
            }
            INFO_REPLY | INFO_REPLY_IP4 => {
                // 8.3.8.9 Validity: submessageLength too small. The locators
                // themselves are applied by `split_by_receiver_state`.
                if !info_reply_fits(buf, offset, id, flags, body) {
                    log::debug!(
                        "[RTPS-WALK] INFO_REPLY 0x{:02x} at offset {} carries {} octets, fewer than its locators: rest of the message invalid",
                        id,
                        offset,
                        body
                    );
                    return;
                }
            }
            _ => {}
        }

        let found = Submessage {
            offset,
            id,
            flags,
            octets_to_next,
            body_end,
            context,
        };
        if matches!(visit(&found), Step::Stop) {
            return;
        }

        // 9.4.5.1.3: octetsToNextHeader == 0 marks the last submessage, bar
        // an empty PAD or INFO_TS, whose next header follows at once.
        if octets_to_next == 0 {
            if empty_not_last {
                offset += 4;
                continue;
            }
            log::debug!("[RTPS-WALK] Reached sentinel (octets_to_next=0)");
            return;
        }

        let next_offset = offset + 4 + octets_to_next as usize;

        if next_offset > buf.len() {
            log::debug!(
                "[RTPS-WALK] Invalid octets_to_next={} would exceed buffer (offset={}, buf.len={})",
                octets_to_next,
                offset,
                buf.len()
            );
            // 8.3.4.1 rules 5 and 6: an INFO_SRC or INFO_REPLY with a length
            // that does not fit is invalid, and so is the rest of the
            // message. No recovery past it: what follows would be applied
            // under a source or reply locator nobody can know, and
            // `split_by_receiver_state` (which cuts the message there) would
            // disagree with every other consumer of this walk.
            if matches!(id, INFO_SRC | INFO_REPLY | INFO_REPLY_IP4) {
                return;
            }
            match recover(buf, offset) {
                // Reprocess at the recovered offset without realigning: the
                // recovery only ever lands on a 4-byte boundary.
                Some(recovered) => {
                    offset = recovered;
                    continue;
                }
                None => return,
            }
        }

        // Sec.9.4.1: submessage headers are 4-byte aligned.
        offset = (next_offset + 3) & !3;
    }
}

/// Submessage id of PAD (RTPS 2.5 Table 8.13).
const PAD: u8 = 0x01;
/// Submessage id of INFO_DST.
const INFO_DST: u8 = 0x0e;
/// Submessage id of INFO_TS.
const INFO_TS: u8 = 0x09;
/// Submessage id of INFO_SRC.
const INFO_SRC: u8 = 0x0c;
/// Submessage id of INFO_REPLY (RTPS 2.5 Table 8.13, 9.4.5.10).
const INFO_REPLY: u8 = 0x0f;
/// Submessage id of INFO_REPLY_IP4 (RTPS 2.5 9.4.5.15).
const INFO_REPLY_IP4: u8 = 0x0d;
/// INFO_REPLY / INFO_REPLY_IP4 MulticastFlag (RTPS 2.5 9.4.5.10, 9.4.5.15):
/// a multicast locator (list) follows the unicast one.
const INFO_REPLY_MULTICAST: u8 = 0x02;
/// A Locator_t on the wire: long kind, unsigned long port, octet
/// address[16] (RTPS 2.5 9.4.2.10).
const LOCATOR_LEN: usize = 24;
/// A LocatorUDPv4 on the wire: unsigned long address, unsigned long port
/// (RTPS 2.5 9.4.3.1).
const LOCATOR_UDPV4_LEN: usize = 8;
/// LOCATOR_KIND_UDPv4 (RTPS 2.5 9.3.1).
const LOCATOR_KIND_UDPV4: u32 = 1;
/// INFO_SRC body (RTPS 2.5 9.4.5.11): unused long, ProtocolVersion,
/// VendorId, GuidPrefix.
const INFO_SRC_BODY: usize = 20;
/// INFO_TS InvalidateFlag (RTPS 2.5 9.4.5.12): no timestamp, and none for
/// the submessages that follow.
const INFO_TS_INVALIDATE: u8 = 0x02;

/// Whether a submessage acts on an endpoint of the participant it is
/// destined to (RTPS 2.5 8.3.4.1, second effect: Data, DataFrag,
/// HeartBeat, AckNack, Gap, HeartbeatFrag, NackFrag), or protects one
/// (DDS-Security 1.1 SEC_BODY, SEC_PREFIX, SEC_POSTFIX). The others change
/// the receiver's state or carry nothing, and apply whoever the
/// destination is.
fn acts_on_an_endpoint(id: u8) -> bool {
    matches!(
        id,
        0x06 | 0x07 | 0x08 | 0x12 | 0x13 | 0x15 | 0x16 | 0x30 | 0x31 | 0x32
    )
}

/// What part of a datagram is destined to one participant.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Destined {
    /// Every submessage: the datagram is used as received.
    Whole,
    /// A copy in which each submessage destined elsewhere is a PAD of the
    /// same length, so the chain of headers, and every walk over it, is
    /// unchanged.
    Part(Vec<u8>),
    /// No submessage that acts on an endpoint is destined here.
    Nothing,
}

/// The part of `buf` destined to the participant whose GUID prefix is
/// `ours`.
///
/// RTPS 2.5 8.3.8.8: INFO_DST sets `Receiver.destGuidPrefix` for the
/// submessages that follow it (GUIDPREFIX_UNKNOWN meaning the participant
/// receiving the message), and every submessage that acts on an endpoint
/// names that endpoint `{destGuidPrefix, entityId}` (8.3.8.1 AckNack,
/// 8.3.8.2 Data, 8.3.8.3 DataFrag, 8.3.8.4 Gap, 8.3.8.6 Heartbeat,
/// 8.3.8.7 HeartbeatFrag, 8.3.8.12 NackFrag). One destined to another
/// participant names none of ours, whatever its entityId: two
/// participants' endpoints share entityIds as a matter of course.
///
/// A submessage destined elsewhere that is the last one of the datagram
/// (octetsToNextHeader 0, 9.4.5.1.3) is cut rather than padded, because a
/// PAD of length 0 is not "last" but "the next header follows". (What an
/// invalid INFO_DST leaves behind it is never visited: the walk ends there,
/// for this function and every other consumer.)
///
/// `buf` that is not an RTPS message is returned `Whole`: rejecting it is
/// the classifier's business. Allocates only when something is removed.
pub(crate) fn destined_to(buf: &[u8], ours: &[u8; 12]) -> Destined {
    if buf.len() < 20 || !super::header::is_rtps_magic(&buf[..4]) {
        return Destined::Whole;
    }
    let mut end = buf.len();
    let mut elsewhere: Vec<usize> = Vec::new();
    let mut here = 0usize;
    for_each_submessage(buf, |sub| {
        if !acts_on_an_endpoint(sub.id) {
            return Step::Continue;
        }
        let destined_here = match sub.context.destination_guid_prefix {
            None => true,
            Some(prefix) => prefix == [0u8; 12] || prefix == *ours,
        };
        if destined_here {
            here += 1;
            return Step::Continue;
        }
        if sub.octets_to_next == 0 {
            end = sub.offset;
            return Step::Stop;
        }
        elsewhere.push(sub.offset);
        Step::Continue
    });
    if end == buf.len() && elsewhere.is_empty() {
        return Destined::Whole;
    }
    if here == 0 {
        return Destined::Nothing;
    }
    let mut part = buf[..end].to_vec();
    for offset in elsewhere {
        part[offset] = PAD;
    }
    Destined::Part(part)
}

/// Whether a submessage only changes the receiver's state or pads (RTPS 2.5
/// Table 8.13: PAD, INFO_TS, INFO_SRC, INFO_REPLY_IP4, INFO_DST, INFO_REPLY):
/// a message made of these alone carries nothing to apply.
fn changes_receiver_state_only(id: u8) -> bool {
    matches!(
        id,
        PAD | INFO_TS | INFO_SRC | INFO_REPLY_IP4 | INFO_DST | INFO_REPLY
    )
}

/// A 32-bit field of a submessage body, in the submessage's byte order
/// (bit 0 of its flags, RTPS 2.5 9.4.5.1.1). `at + 4` must be in `buf`.
fn read_u32(buf: &[u8], at: usize, flags: u8) -> u32 {
    let raw = [buf[at], buf[at + 1], buf[at + 2], buf[at + 3]];
    if flags & 0x01 != 0 {
        u32::from_le_bytes(raw)
    } else {
        u32::from_be_bytes(raw)
    }
}

/// Whether the INFO_REPLY or INFO_REPLY_IP4 at `offset`, whose body is
/// `body` octets, holds every locator it declares (RTPS 2.5 8.3.8.9
/// Validity, 9.4.5.10, 9.4.5.15).
fn info_reply_fits(buf: &[u8], offset: usize, id: u8, flags: u8, body: usize) -> bool {
    let multicast = flags & INFO_REPLY_MULTICAST != 0;
    if id == INFO_REPLY_IP4 {
        let needed = LOCATOR_UDPV4_LEN * if multicast { 2 } else { 1 };
        return body >= needed;
    }
    // A LocatorList: unsigned long numLocators, then that many Locator_t.
    let list_end = |start: usize| -> Option<usize> {
        if start.checked_add(4)? > body {
            return None;
        }
        let count = usize::try_from(read_u32(buf, offset + 4 + start, flags)).ok()?;
        let end = count.checked_mul(LOCATOR_LEN)?.checked_add(start + 4)?;
        (end <= body).then_some(end)
    };
    match list_end(0) {
        Some(unicast_end) if multicast => list_end(unicast_end).is_some(),
        Some(_) => true,
        None => false,
    }
}

/// The address and port of a locator, when a reply can be sent there:
/// RTPS 2.5 9.3.1 LOCATOR_ADDRESS_INVALID (all zeros) and
/// LOCATOR_PORT_INVALID (0) cannot, nor can a port past 16 bits.
fn usable(address: Ipv4Addr, port: u32) -> Option<SocketAddrV4> {
    let port = u16::try_from(port).ok().filter(|&port| port != 0)?;
    (!address.is_unspecified()).then(|| SocketAddrV4::new(address, port))
}

/// The reply locator an INFO_REPLY or INFO_REPLY_IP4 sets (RTPS 2.5
/// 8.3.8.9 "Change in state of Receiver"): the first usable UDPv4 locator of
/// its unicast list, else of its multicast list (8.4.8.2.6 answers to both
/// lists), else none -- the lists REPLACE the previous ones, so a list with
/// nothing usable in it leaves no reply locator at all, never the old one.
///
/// Reads only what the walk checked is there (`info_reply_fits`).
fn reply_locator(buf: &[u8], sub: &Submessage) -> ReplyTo {
    let body = sub.offset + 4;
    let multicast = sub.flags & INFO_REPLY_MULTICAST != 0;
    let found = if sub.id == INFO_REPLY_IP4 {
        let lists = if multicast { 2 } else { 1 };
        (0..lists).find_map(|i| {
            let at = body + i * LOCATOR_UDPV4_LEN;
            usable(
                Ipv4Addr::from(read_u32(buf, at, sub.flags)),
                read_u32(buf, at + 4, sub.flags),
            )
        })
    } else {
        let list = |start: usize| -> (Option<SocketAddrV4>, usize) {
            let count = usize::try_from(read_u32(buf, start, sub.flags)).unwrap_or(0);
            let first = (0..count).find_map(|i| {
                let at = start + 4 + i * LOCATOR_LEN;
                if read_u32(buf, at, sub.flags) != LOCATOR_KIND_UDPV4 {
                    return None;
                }
                let address = [buf[at + 20], buf[at + 21], buf[at + 22], buf[at + 23]];
                usable(Ipv4Addr::from(address), read_u32(buf, at + 4, sub.flags))
            });
            (first, start + 4 + count * LOCATOR_LEN)
        };
        let (unicast, unicast_end) = list(body);
        unicast.or_else(|| multicast.then(|| list(unicast_end).0).flatten())
    };
    found.map_or(ReplyTo::Invalid, ReplyTo::Locator)
}

/// One message `split_by_receiver_state` carved out of a datagram, and the
/// reply locator in force for it.
///
/// RTPS 2.5 8.3.4: the reply locator starts as the datagram's sender
/// (`ReplyTo::Sender`): the leading part of a datagram (before its first
/// INFO_SRC or INFO_REPLY, when it carries anything). 8.3.8.10: an INFO_SRC
/// sets it to LOCATOR_INVALID (`ReplyTo::Invalid`) -- the RTPS header now
/// names a source the datagram's sender only forwarded for, and the
/// received address must never be used as, or to derive, a reply locator
/// for it (see `Origin`, `meta.rs`). 8.3.8.9: an INFO_REPLY sets it to the
/// locator it names, until the next INFO_SRC or INFO_REPLY.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Part {
    /// The message, with its own RTPS header (see `split_by_receiver_state`).
    pub(crate) message: Vec<u8>,
    /// Whether `message` sits behind an INFO_SRC: its source is then not
    /// the datagram's sender.
    pub(crate) relayed: bool,
    /// The reply locator in force for every submessage of `message`.
    pub(crate) reply: ReplyTo,
}

impl Part {
    /// The origin of this part's submessages, for a datagram received
    /// from `from`.
    pub(crate) fn origin(&self, from: std::net::SocketAddr) -> Origin {
        Origin::with_reply(from, self.relayed, self.reply)
    }
}

/// The messages a datagram carries once its INFO_SRC and INFO_REPLY
/// submessages are applied.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Sources<'a> {
    /// No INFO_SRC and no INFO_REPLY: one source, the header's, and one
    /// reply locator, the sender; the datagram as received.
    One(&'a [u8]),
    /// One part per stretch of the datagram with its own source and reply
    /// locator, each with an RTPS header naming that source.
    Split(Vec<Part>),
}

/// Where one stretch of a datagram begins: at an INFO_SRC (a new source,
/// no reply locator) or at an INFO_REPLY (same source, a new reply
/// locator).
struct Boundary {
    /// Offset of the INFO_SRC or INFO_REPLY.
    offset: usize,
    /// Offset of the submessage behind it, `None` when it was the last.
    next: Option<usize>,
    /// `None` at an INFO_SRC, the reply locator set at an INFO_REPLY.
    reply: Option<ReplyTo>,
    /// Whether the stretch carries anything but receiver state.
    carries: bool,
    /// At an INFO_REPLY, the INFO_DST and INFO_TS in force (their offsets):
    /// an INFO_REPLY changes neither (8.3.8.9), so the stretch behind it
    /// starts with a copy of each.
    destination: Option<usize>,
    timestamp: Option<usize>,
}

/// Split `buf` at each INFO_SRC and each INFO_REPLY / INFO_REPLY_IP4, so
/// that every consumer reads the source of a submessage in the one place it
/// looks, the RTPS header, and finds the reply locator for it in the
/// `Origin` it is handed.
///
/// RTPS 2.5 8.3.8.10: INFO_SRC sets `Receiver.sourceGuidPrefix`,
/// `sourceVersion` and `sourceVendorId` for the submessages that follow it,
/// clears the reply locators and sets `haveTimestamp = false`. It leaves
/// `destGuidPrefix` alone. Each part after an INFO_SRC gets a header carrying
/// its version, vendor and prefix and starts with no INFO_TS, which is that
/// state; the part before the first INFO_SRC keeps the original header. A
/// GUID prefix read from the header (the writer of a DATA, the reader of an
/// ACKNACK, the peer of a HEARTBEAT) would otherwise be the forwarder's,
/// never the source's.
///
/// RTPS 2.5 8.3.8.9 / 9.4.5.15: INFO_REPLY and INFO_REPLY_IP4 set the reply
/// locators for the submessages that follow them and change nothing else.
/// The part behind one keeps the header in force and starts with a copy of
/// the INFO_DST and INFO_TS in force there (taken from the same stretch of
/// source), so its receiver state is the one the submessages had in the
/// datagram; its reply locator travels in `Part::reply`.
///
/// Apply it to what `destined_to` kept: that function reads INFO_DST across
/// the whole message, and INFO_SRC does not end an INFO_DST's scope.
///
/// Submessage headers are 4-byte aligned from the message start (9.4.1);
/// every part starts at an aligned offset behind a 20-octet header (and
/// copies of 16 and 12 octets), so the alignment of what it carries is
/// unchanged. A part that carries only receiver state (an INFO_DST or
/// INFO_TS before an INFO_SRC, say) has nothing to apply and is left out.
/// Each octet of `buf` lands in at most one part, plus at most 28 octets of
/// copied state per part. `buf` that is not an RTPS message is returned as
/// `One`. Allocates only when an INFO_SRC or INFO_REPLY is present.
pub(crate) fn split_by_receiver_state(buf: &[u8]) -> Sources<'_> {
    if buf.len() < 20 || !super::header::is_rtps_magic(&buf[..4]) {
        return Sources::One(buf);
    }
    let mut boundaries: Vec<Boundary> = Vec::new();
    // Whether the leading stretch carries anything but receiver state.
    let mut leading_carries = false;
    // INFO_DST and INFO_TS in force, since the last INFO_SRC.
    let mut destination = None;
    let mut timestamp = None;
    for_each_submessage(buf, |sub| {
        let reply = match sub.id {
            INFO_SRC => None,
            INFO_REPLY | INFO_REPLY_IP4 => Some(reply_locator(buf, sub)),
            INFO_DST => {
                destination = Some(sub.offset);
                return Step::Continue;
            }
            INFO_TS => {
                timestamp = Some(sub.offset);
                return Step::Continue;
            }
            id => {
                if !changes_receiver_state_only(id) {
                    match boundaries.last_mut() {
                        Some(last) => last.carries = true,
                        None => leading_carries = true,
                    }
                }
                return Step::Continue;
            }
        };
        if reply.is_none() {
            destination = None;
            timestamp = None;
        }
        let next = (sub.octets_to_next != 0)
            .then(|| (sub.offset + 4 + usize::from(sub.octets_to_next) + 3) & !3)
            .filter(|&next| next < buf.len());
        boundaries.push(Boundary {
            offset: sub.offset,
            next,
            reply,
            carries: false,
            destination,
            timestamp,
        });
        Step::Continue
    });
    if boundaries.is_empty() {
        return Sources::One(buf);
    }
    let mut parts = Vec::with_capacity(boundaries.len() + 1);
    if leading_carries {
        parts.push(Part {
            message: buf[..boundaries[0].offset].to_vec(),
            relayed: false,
            reply: ReplyTo::Sender,
        });
    }
    // The version, vendor and prefix in force (header octets 4..20): the
    // datagram's, or the last INFO_SRC's body behind its unused long.
    let mut source = &buf[4..20];
    let mut relayed = false;
    for (i, boundary) in boundaries.iter().enumerate() {
        if boundary.reply.is_none() {
            source = &buf[boundary.offset + 8..boundary.offset + 4 + INFO_SRC_BODY];
            relayed = true;
        }
        let Some(start) = boundary.next else { continue };
        if !boundary.carries {
            continue;
        }
        let end = boundaries
            .get(i + 1)
            .map_or(buf.len(), |following| following.offset);
        if start >= end {
            continue;
        }
        let mut message = Vec::with_capacity(20 + 28 + end - start);
        message.extend_from_slice(&buf[..4]);
        message.extend_from_slice(source);
        if let Some(at) = boundary.destination {
            copy_info_dst(buf, at, &mut message);
        }
        if let Some(at) = boundary.timestamp {
            copy_info_ts(buf, at, &mut message);
        }
        message.extend_from_slice(&buf[start..end]);
        parts.push(Part {
            message,
            relayed,
            reply: boundary.reply.unwrap_or(ReplyTo::Invalid),
        });
    }
    Sources::Split(parts)
}

/// The submessage header of a copied INFO_DST or INFO_TS: its id and flags,
/// and its exact body length in the byte order its E flag names.
fn copied_header(id: u8, flags: u8, body: u16, into: &mut Vec<u8>) {
    into.push(id);
    into.push(flags);
    into.extend_from_slice(&if flags & 0x01 != 0 {
        body.to_le_bytes()
    } else {
        body.to_be_bytes()
    });
}

/// Append the INFO_DST at `at`, its 12-octet GuidPrefix only (a declared
/// length past it carries nothing 8.3.8.8 reads). The walk checked it holds
/// them.
fn copy_info_dst(buf: &[u8], at: usize, into: &mut Vec<u8>) {
    copied_header(INFO_DST, buf[at + 1], 12, into);
    into.extend_from_slice(&buf[at + 4..at + 16]);
}

/// Append the INFO_TS at `at`: empty when it invalidates the timestamp
/// (9.4.5.12), else its 8-octet Time_t. The walk checked it holds them.
fn copy_info_ts(buf: &[u8], at: usize, into: &mut Vec<u8>) {
    let flags = buf[at + 1];
    if flags & INFO_TS_INVALIDATE != 0 {
        copied_header(INFO_TS, flags, 0, into);
    } else {
        copied_header(INFO_TS, flags, 8, into);
        into.extend_from_slice(&buf[at + 4..at + 12]);
    }
}

/// Look for the next plausible submessage header after a length that does
/// not fit the datagram.
///
/// This exists for a real packet shape, not for a hypothesis: an ACKNACK
/// whose octetsToNextHeader is far past the end of the datagram, followed by
/// a perfectly valid DATA_FRAG. Without this the scan stops at the ACKNACK
/// and the SPDP fragment behind it is never seen.
///
/// The test is deliberately weak - a plausible id, plausible flags, and a
/// length that fits - because the alternative is dropping the rest of the
/// datagram outright. It is bounded by `CLASSIFIER_SCAN_WINDOW`.
fn recover(buf: &[u8], offset: usize) -> Option<usize> {
    log::debug!("[RTPS-WALK] Attempting to recover: scanning forward for next submessage");

    let mut scan_offset = offset + 4;
    let scan_limit = (scan_offset + CLASSIFIER_SCAN_WINDOW).min(buf.len());

    while scan_offset + 4 <= scan_limit {
        scan_offset = (scan_offset + 3) & !3;

        if scan_offset + 4 > buf.len() {
            break;
        }

        let potential_id = buf[scan_offset];
        let potential_flags = buf[scan_offset + 1];

        // Valid ids are 0x01-0x16 and the vendor range 0x80-0xff (RTPS
        // v2.5 Table 8.13); the flag byte only has meaning in its low bits.
        //
        // The upper bound is 0x16 so that DATA_FRAG is included - the one
        // submessage this whole recovery exists to find, as the doc above
        // says. Excluding it, the scan would walk over it and give up, so a
        // fragmented SPDP announcement behind a poisoned length would be lost
        // and its participant never discovered.
        //
        // The lower bound is load-bearing: a test that accepts 0x00 would read
        // four zero bytes as a submessage whose id is 0, whose flags are
        // big-endian, and whose octetsToNextHeader is 0 - which the length
        // test below accepts as "last submessage". The recovery would land on
        // the first run of zeros it met, usually the body of the very
        // submessage it is recovering FROM, declare the datagram finished, and
        // drop everything behind it without a counter or a log. Zero padding
        // is common.
        let plausible_id = (0x01..=0x16).contains(&potential_id) || potential_id >= 0x80;
        if plausible_id && potential_flags < 0x20 {
            let test_octets = if potential_flags & 0x01 != 0 {
                u16::from_le_bytes([buf[scan_offset + 2], buf[scan_offset + 3]])
            } else {
                u16::from_be_bytes([buf[scan_offset + 2], buf[scan_offset + 3]])
            };

            let test_next = scan_offset + 4 + test_octets as usize;
            if test_next <= buf.len() || test_octets == 0 {
                log::debug!(
                    "[RTPS-WALK] Recovery successful: found potential submessage 0x{:02x} at offset {}",
                    potential_id,
                    scan_offset
                );
                return Some(scan_offset);
            }
        }

        scan_offset += 4;
    }

    log::debug!("[RTPS-WALK] Recovery failed: no valid submessage found, stopping scan");
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RTPS header, version 2.5, HDDS vendor, then whatever is appended.
    fn header() -> Vec<u8> {
        let mut packet = Vec::new();
        packet.extend_from_slice(b"RTPS");
        packet.extend_from_slice(&[0x02, 0x05]);
        packet.extend_from_slice(&[0x01, 0x1A]);
        packet.extend_from_slice(&[0x0A; 12]);
        packet
    }

    /// An INFO_SRC naming `prefix`, version 2.4 and vendor 01 0F (RTPS 2.5
    /// 9.4.5.11), its body declared `declared` octets long.
    fn info_src(prefix: [u8; 12], declared: u16) -> Vec<u8> {
        let mut submessage = vec![0x0c, 0x01];
        submessage.extend_from_slice(&declared.to_le_bytes());
        submessage.extend_from_slice(&[0x00; 4]);
        submessage.extend_from_slice(&[0x02, 0x04, 0x01, 0x0F]);
        submessage.extend_from_slice(&prefix);
        submessage.truncate(4 + usize::from(declared).min(20));
        submessage
    }

    /// An empty PAD, a submessage to carry through a split.
    fn marker(id: u8) -> Vec<u8> {
        vec![id, 0x01, 0x04, 0x00, 0xAA, 0xBB, 0xCC, 0xDD]
    }

    #[test]
    fn a_message_without_info_src_is_one_source_and_is_not_copied() {
        let mut packet = header();
        packet.extend(data());
        match split_by_receiver_state(&packet) {
            Sources::One(message) => assert!(std::ptr::eq(message, &packet[..])),
            other => panic!("expected the message as received, got {other:?}"),
        }
    }

    /// RTPS 2.5 8.3.8.10: each INFO_SRC gives what follows it a source of
    /// its own; the part before the first keeps the header's.
    #[test]
    fn each_info_src_starts_a_message_with_its_own_header() {
        const B: [u8; 12] = [0x0B; 12];
        const C: [u8; 12] = [0x0C; 12];
        let mut packet = header();
        packet.extend(marker(0x80));
        packet.extend(info_src(B, 20));
        packet.extend(marker(0x81));
        packet.extend(info_src(C, 20));
        packet.extend(marker(0x82));

        let mut first = header();
        first.extend(marker(0x80));
        let source = |prefix: [u8; 12], id: u8| {
            let mut message = b"RTPS".to_vec();
            message.extend_from_slice(&[0x02, 0x04, 0x01, 0x0F]);
            message.extend_from_slice(&prefix);
            message.extend(marker(id));
            message
        };
        assert_eq!(
            split_by_receiver_state(&packet),
            Sources::Split(vec![
                Part {
                    message: first,
                    relayed: false,
                    reply: ReplyTo::Sender
                },
                Part {
                    message: source(B, 0x81),
                    relayed: true,
                    reply: ReplyTo::Invalid
                },
                Part {
                    message: source(C, 0x82),
                    relayed: true,
                    reply: ReplyTo::Invalid
                },
            ])
        );
    }

    #[test]
    fn an_info_src_first_or_last_leaves_no_empty_message() {
        const B: [u8; 12] = [0x0B; 12];
        let mut packet = header();
        packet.extend(info_src(B, 20));
        packet.extend(marker(0x81));
        let mut last = info_src([0x0C; 12], 20);
        last[2] = 0;
        packet.extend(last);

        let mut only = b"RTPS".to_vec();
        only.extend_from_slice(&[0x02, 0x04, 0x01, 0x0F]);
        only.extend_from_slice(&B);
        only.extend(marker(0x81));
        assert_eq!(
            split_by_receiver_state(&packet),
            Sources::Split(vec![Part {
                message: only,
                relayed: true,
                reply: ReplyTo::Invalid
            }])
        );
    }

    /// 8.3.8.10 Validity: submessageLength too small. An INFO_SRC that cannot
    /// hold its 20 octets ends the message for every consumer; 20 is enough.
    #[test]
    fn an_info_src_too_short_ends_the_message() {
        for (declared, visited) in [(19u16, vec![0x80]), (20, vec![0x80, 0x0c, 0x81])] {
            let mut packet = header();
            packet.extend(marker(0x80));
            let mut src = info_src([0x0B; 12], declared);
            // keep the next header 4-byte aligned; the declared length stays
            while !src.len().is_multiple_of(4) {
                src.push(0);
            }
            packet.extend(src);
            packet.extend(marker(0x81));
            let mut seen = Vec::new();
            for_each_submessage(&packet, |sub| {
                seen.push(sub.id);
                Step::Continue
            });
            assert_eq!(seen, visited, "INFO_SRC declaring {declared} octets");
        }
    }

    /// A part made only of receiver state carries nothing to apply: the
    /// INFO_TS and INFO_DST ahead of the first INFO_SRC are not a message.
    #[test]
    fn a_part_of_receiver_state_alone_is_left_out() {
        const B: [u8; 12] = [0x0B; 12];
        let mut packet = header();
        packet.extend(info_ts(7, 0));
        let mut info_dst = vec![0x0e, 0x01, 0x0c, 0x00];
        info_dst.extend_from_slice(&[0x0A; 12]);
        packet.extend(info_dst);
        packet.extend(info_src(B, 20));
        packet.extend(marker(0x81));
        packet.extend(info_src([0x0C; 12], 20));
        packet.extend(info_ts(8, 0));

        let mut only = b"RTPS".to_vec();
        only.extend_from_slice(&[0x02, 0x04, 0x01, 0x0F]);
        only.extend_from_slice(&B);
        only.extend(marker(0x81));
        assert_eq!(
            split_by_receiver_state(&packet),
            Sources::Split(vec![Part {
                message: only,
                relayed: true,
                reply: ReplyTo::Invalid
            }])
        );
    }

    /// INFO_SRC does not end an INFO_DST's scope (8.3.8.10 changes the
    /// source only): what `destined_to` keeps behind an INFO_SRC is split
    /// under that source, and what it pads out stays out.
    #[test]
    fn destination_then_source_keep_what_is_ours_under_its_source() {
        const OURS: [u8; 12] = [0x0B; 12];
        const ORIGIN: [u8; 12] = [0x0D; 12];
        let info_dst = |prefix: [u8; 12]| {
            let mut sub = vec![0x0e, 0x01, 0x0c, 0x00];
            sub.extend_from_slice(&prefix);
            sub
        };
        let mut packet = header();
        packet.extend(info_dst([0x0C; 12]));
        packet.extend(info_src(ORIGIN, 20));
        packet.extend(data());
        packet.extend(info_dst(OURS));
        packet.extend(data());

        let kept = match destined_to(&packet, &OURS) {
            Destined::Part(part) => part,
            other => panic!("expected a part, got {other:?}"),
        };
        let Sources::Split(parts) = split_by_receiver_state(&kept) else {
            panic!("an INFO_SRC is kept by destined_to");
        };
        assert_eq!(parts.len(), 1);
        assert!(parts[0].relayed, "behind an INFO_SRC");
        assert_eq!(parts[0].reply, ReplyTo::Invalid, "and no reply locator");
        assert_eq!(parts[0].message[8..20], ORIGIN);
        let mut ids = Vec::new();
        for_each_submessage(&parts[0].message, |sub| {
            ids.push(sub.id);
            Step::Continue
        });
        assert_eq!(ids, vec![PAD, INFO_DST, 0x15], "theirs padded, ours kept");
    }

    /// RTPS 2.5 9.4.5.15 + 9.4.3.1, octet by octet: INFO_REPLY_IP4, E = 1,
    /// M = 0, octetsToNextHeader 8, LocatorUDPv4 address 127.0.0.9 and port
    /// 7411 as two little-endian unsigned longs.
    const INFO_REPLY_IP4_LE: [u8; 12] = [
        0x0d, 0x01, 0x08, 0x00, 0x09, 0x00, 0x00, 0x7f, 0xf3, 0x1c, 0x00, 0x00,
    ];

    /// RTPS 2.5 9.4.5.10 + 9.4.2.10, octet by octet: INFO_REPLY, E = 0,
    /// M = 1, a unicast list of one UDPv6 locator (unusable here) and a
    /// multicast list of one UDPv4 locator 239.255.0.1:7400, big-endian.
    const INFO_REPLY_BE_MULTICAST: [u8; 60] = [
        0x0f, 0x02, 0x00, 0x38, // id, flags (M), octetsToNextHeader 56
        0x00, 0x00, 0x00, 0x01, // unicast numLocators 1
        0x00, 0x00, 0x00, 0x02, // kind LOCATOR_KIND_UDPv6
        0x00, 0x00, 0x1c, 0xf3, // port 7411
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x00, 0x00, 0x00,
        0x01, // multicast numLocators 1
        0x00, 0x00, 0x00, 0x01, // kind LOCATOR_KIND_UDPv4
        0x00, 0x00, 0x1c, 0xe8, // port 7400
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 239, 255, 0, 1,
    ];

    fn reply_of(part: &Part) -> Option<std::net::SocketAddr> {
        part.origin("192.0.2.1:1".parse().expect("literal"))
            .receiver_reply_locator()
    }

    /// 8.3.8.9: an INFO_REPLY_IP4 ahead of the submessages sets the reply
    /// locator for all of them; the message keeps its header and
    /// everything behind the INFO_REPLY.
    #[test]
    fn an_info_reply_ip4_sets_the_reply_locator_for_what_follows() {
        let mut packet = header();
        packet.extend(INFO_REPLY_IP4_LE);
        packet.extend(data());

        let mut expected = header();
        expected.extend(data());
        let Sources::Split(parts) = split_by_receiver_state(&packet) else {
            panic!("an INFO_REPLY changes the receiver state");
        };
        assert_eq!(
            parts,
            vec![Part {
                message: expected,
                relayed: false,
                reply: ReplyTo::Locator("127.0.0.9:7411".parse().expect("literal")),
            }]
        );
        assert_eq!(
            reply_of(&parts[0]),
            Some("127.0.0.9:7411".parse().expect("literal"))
        );
    }

    /// 8.3.8.9: with M set, the multicast list is read too, and a unicast
    /// list with nothing usable in it (UDPv6 only, here) falls to it
    /// (8.4.8.2.6 answers to both lists).
    #[test]
    fn an_info_reply_falls_to_its_multicast_list() {
        let mut packet = header();
        packet.extend(INFO_REPLY_BE_MULTICAST);
        packet.extend(data());
        let Sources::Split(parts) = split_by_receiver_state(&packet) else {
            panic!("an INFO_REPLY changes the receiver state");
        };
        assert_eq!(parts.len(), 1);
        assert_eq!(
            reply_of(&parts[0]),
            Some("239.255.0.1:7400".parse().expect("literal"))
        );
    }

    /// 8.3.8.9 replaces the lists: an INFO_REPLY naming nothing usable
    /// (no locator, an invalid address, an invalid port) leaves no reply
    /// locator, never the sender's.
    #[test]
    fn an_info_reply_with_nothing_usable_leaves_no_reply_locator() {
        let empty_list = vec![0x0f, 0x01, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00];
        let mut no_address = INFO_REPLY_IP4_LE.to_vec();
        no_address[4..8].fill(0);
        let mut no_port = INFO_REPLY_IP4_LE.to_vec();
        no_port[8..12].fill(0);
        for info_reply in [empty_list, no_address, no_port] {
            let mut packet = header();
            packet.extend(&info_reply);
            packet.extend(data());
            let Sources::Split(parts) = split_by_receiver_state(&packet) else {
                panic!("an INFO_REPLY changes the receiver state");
            };
            assert_eq!(parts.len(), 1);
            assert_eq!(parts[0].reply, ReplyTo::Invalid, "{info_reply:02x?}");
            assert_eq!(reply_of(&parts[0]), None);
        }
    }

    /// 8.3.8.9 changes the reply locator only: the submessages behind an
    /// INFO_REPLY in the middle of a message keep the INFO_DST and INFO_TS
    /// in force, and the ones ahead of it keep the sender.
    #[test]
    fn an_info_reply_midway_keeps_destination_and_timestamp() {
        const DEST: [u8; 12] = [0x0B; 12];
        let mut info_dst = vec![0x0e, 0x01, 0x0c, 0x00];
        info_dst.extend_from_slice(&DEST);
        let mut packet = header();
        packet.extend(&info_dst);
        packet.extend(info_ts(7, 9));
        packet.extend(marker(0x80));
        packet.extend(INFO_REPLY_IP4_LE);
        packet.extend(marker(0x81));

        let mut ahead = header();
        ahead.extend(&info_dst);
        ahead.extend(info_ts(7, 9));
        ahead.extend(marker(0x80));
        let mut behind = header();
        behind.extend(&info_dst);
        behind.extend(info_ts(7, 9));
        behind.extend(marker(0x81));
        let Sources::Split(parts) = split_by_receiver_state(&packet) else {
            panic!("an INFO_REPLY changes the receiver state");
        };
        assert_eq!(
            parts,
            vec![
                Part {
                    message: ahead,
                    relayed: false,
                    reply: ReplyTo::Sender,
                },
                Part {
                    message: behind,
                    relayed: false,
                    reply: ReplyTo::Locator("127.0.0.9:7411".parse().expect("literal")),
                },
            ]
        );
        let mut seen = Vec::new();
        for_each_submessage(&parts[1].message, |sub| {
            if sub.id == 0x81 {
                seen.push(sub.context);
            }
            Step::Continue
        });
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].destination_guid_prefix, Some(DEST));
        assert_eq!(seen[0].source_timestamp, Some((7, 9)));
    }

    /// 8.3.8.10 after 8.3.8.9: an INFO_SRC clears the reply locator an
    /// INFO_REPLY set, and a later INFO_REPLY sets it again under the new
    /// source; the INFO_TS the INFO_SRC cleared is not brought back.
    #[test]
    fn an_info_src_clears_an_info_reply_and_a_later_one_applies() {
        const B: [u8; 12] = [0x0B; 12];
        let mut packet = header();
        packet.extend(info_ts(7, 0));
        packet.extend(INFO_REPLY_IP4_LE);
        packet.extend(marker(0x80));
        packet.extend(info_src(B, 20));
        packet.extend(marker(0x81));
        packet.extend(INFO_REPLY_BE_MULTICAST);
        packet.extend(marker(0x82));

        let Sources::Split(parts) = split_by_receiver_state(&packet) else {
            panic!("the message changes the receiver state");
        };
        let replies: Vec<_> = parts.iter().map(reply_of).collect();
        assert_eq!(
            replies,
            vec![
                Some("127.0.0.9:7411".parse().expect("literal")),
                None,
                Some("239.255.0.1:7400".parse().expect("literal")),
            ]
        );
        let mut source = b"RTPS".to_vec();
        source.extend_from_slice(&[0x02, 0x04, 0x01, 0x0F]);
        source.extend_from_slice(&B);
        let mut last = source.clone();
        last.extend(marker(0x82));
        assert_eq!(parts[2].message, last, "the INFO_SRC's header, no INFO_TS");
        assert!(parts[2].relayed, "an INFO_REPLY does not undo an INFO_SRC");
        assert_eq!(
            parts[2]
                .origin("192.0.2.1:1".parse().expect("literal"))
                .reply(),
            None,
            "the sender only forwarded it"
        );
    }

    /// 8.3.8.9 Validity: submessageLength too small. An INFO_REPLY that
    /// cannot hold the locators it declares ends the message for every
    /// consumer; exactly enough is valid.
    #[test]
    fn an_info_reply_too_short_ends_the_message() {
        let mut ip4_short = INFO_REPLY_IP4_LE.to_vec();
        ip4_short[2] = 4;
        ip4_short.truncate(8);
        let mut ip4_multicast_short = INFO_REPLY_IP4_LE.to_vec();
        ip4_multicast_short[1] |= 0x02; // M set, no multicast locator
        let mut list_short = INFO_REPLY_BE_MULTICAST.to_vec();
        list_short[3] = 52; // the multicast Locator_t does not fit
        list_short.truncate(56);
        let huge_count = vec![0x0f, 0x01, 0x04, 0x00, 0xff, 0xff, 0xff, 0xff];
        for (info_reply, valid) in [
            (INFO_REPLY_IP4_LE.to_vec(), true),
            (INFO_REPLY_BE_MULTICAST.to_vec(), true),
            (ip4_short, false),
            (ip4_multicast_short, false),
            (list_short, false),
            (huge_count, false),
        ] {
            let mut packet = header();
            packet.extend(marker(0x80));
            packet.extend(&info_reply);
            packet.extend(marker(0x81));
            let mut seen = Vec::new();
            for_each_submessage(&packet, |sub| {
                seen.push(sub.id);
                Step::Continue
            });
            let expected = if valid {
                vec![0x80, info_reply[0], 0x81]
            } else {
                vec![0x80]
            };
            assert_eq!(seen, expected, "{info_reply:02x?}");
        }
    }

    /// RTPS 2.5 8.3.4.1 rules 5 and 6: the next submessage is found by a
    /// VALID submessageLength, and a known submessage that is invalid
    /// invalidates the rest of the message. An INFO_SRC or INFO_REPLY whose
    /// declared length runs past the datagram ends it: no consumer applies
    /// what follows, under a source or reply locator that cannot be known.
    /// The walk and the split agree on it -- the walk must not recover past
    /// such a submessage and visit the DATA behind it, which the split leaves
    /// out.
    #[test]
    fn an_overlong_info_src_or_info_reply_ends_the_message() {
        // `body` in the byte order `flags` names; a declared length of 256.
        let overlong = |id: u8, flags: u8, body: &[u8]| {
            let mut sub = vec![id, flags];
            sub.extend_from_slice(&if flags & 0x01 != 0 {
                0x0100u16.to_le_bytes()
            } else {
                0x0100u16.to_be_bytes()
            });
            sub.extend_from_slice(body);
            sub
        };
        let mut src_body = vec![0, 0, 0, 0, 0x02, 0x05, 0x01, 0x0F];
        src_body.extend_from_slice(&[0x0B; 12]);
        for state in [
            overlong(0x0c, 0x01, &src_body),
            overlong(0x0d, INFO_REPLY_IP4_LE[1], &INFO_REPLY_IP4_LE[4..]),
            overlong(
                0x0f,
                INFO_REPLY_BE_MULTICAST[1],
                &INFO_REPLY_BE_MULTICAST[4..],
            ),
        ] {
            let mut packet = header();
            packet.extend(marker(0x80));
            packet.extend(&state);
            packet.extend(data());
            let mut walked = Vec::new();
            for_each_submessage(&packet, |sub| {
                walked.push(sub.id);
                Step::Continue
            });
            assert_eq!(walked, vec![0x80, state[0]], "{state:02x?}: the walk stops");
            let mut split = Vec::new();
            match split_by_receiver_state(&packet) {
                Sources::One(message) => for_each_submessage(message, |sub| {
                    split.push(sub.id);
                    Step::Continue
                }),
                Sources::Split(parts) => {
                    for part in &parts {
                        for_each_submessage(&part.message, |sub| {
                            split.push(sub.id);
                            Step::Continue
                        });
                    }
                }
            }
            assert_eq!(split, vec![0x80], "{state:02x?}: and so does the split");
        }
    }

    /// 8.3.8.10: haveTimestamp = false after an INFO_SRC.
    #[test]
    fn an_info_src_clears_the_timestamp() {
        let mut packet = header();
        packet.extend(info_ts(7, 0));
        packet.extend(marker(0x80));
        packet.extend(info_src([0x0B; 12], 20));
        packet.extend(marker(0x81));
        let mut dated = Vec::new();
        for_each_submessage(&packet, |sub| {
            if sub.id >= 0x80 {
                dated.push(sub.context.source_timestamp.is_some());
            }
            Step::Continue
        });
        assert_eq!(dated, vec![true, false]);
    }

    fn info_ts(seconds: i32, fraction: u32) -> Vec<u8> {
        let mut submessage = vec![0x09, 0x01];
        submessage.extend_from_slice(&8u16.to_le_bytes());
        submessage.extend_from_slice(&seconds.to_le_bytes());
        submessage.extend_from_slice(&fraction.to_le_bytes());
        submessage
    }

    /// A DATA submessage with nothing past its twenty fixed fields.
    fn data() -> Vec<u8> {
        let mut submessage = vec![0x15, 0x01];
        submessage.extend_from_slice(&20u16.to_le_bytes());
        submessage.extend_from_slice(&[0x00; 20]);
        submessage
    }

    /// The reason the snapshot is by value.
    ///
    /// Two DATA, each behind its own INFO_TS, in one datagram. Each visit
    /// must see the timestamp that was in force when IT was reached. An
    /// accumulator shared across the datagram gives both of them the last
    /// one, which silently backdates or postdates every sample of a batch.
    #[test]
    fn each_submessage_sees_the_context_in_force_when_it_was_reached() {
        let mut packet = header();
        packet.extend_from_slice(&info_ts(1, 1));
        packet.extend_from_slice(&data());
        packet.extend_from_slice(&info_ts(2, 2));
        packet.extend_from_slice(&data());

        let mut seen = Vec::new();
        for_each_submessage(&packet, |found| {
            seen.push((found.id, found.context.source_timestamp));
            Step::Continue
        });

        assert_eq!(
            seen,
            vec![
                (0x09, Some((1, 1))),
                (0x15, Some((1, 1))),
                (0x09, Some((2, 2))),
                (0x15, Some((2, 2))),
            ],
            "each submessage carries the context of its own position"
        );
    }

    /// A DATA_FRAG submessage with nothing past its thirty-two fixed fields.
    fn data_frag() -> Vec<u8> {
        let mut submessage = vec![0x16, 0x01];
        submessage.extend_from_slice(&32u16.to_le_bytes());
        submessage.extend_from_slice(&[0x00; 32]);
        submessage
    }

    /// The recovery exists for a real packet shape: an ACKNACK whose
    /// octetsToNextHeader is far past the end of the datagram, with a
    /// perfectly good DATA behind it. Without the forward
    /// scan the walk stops at the ACKNACK and that DATA is never seen.
    ///
    /// This is the one point where this walk and `scan_all_data_frags` must
    /// not drift apart.
    ///
    /// It pins the null-word refusal too: the twenty bytes of ACKNACK body
    /// the forward scan crosses are zeros, and four zero bytes must not read
    /// as a submessage whose length says "last one", or the scan would settle
    /// on them and the DATA below would be lost.
    #[test]
    fn a_length_past_the_end_of_the_datagram_is_recovered_from() {
        let mut packet = header();
        // ACKNACK claiming 55983 octets follow, which they do not.
        packet.push(0x06);
        packet.push(0x01);
        packet.extend_from_slice(&55983u16.to_le_bytes());
        packet.extend_from_slice(&[0x00; 20]);
        packet.extend_from_slice(&data());

        let mut seen = Vec::new();
        for_each_submessage(&packet, |found| {
            seen.push(found.id);
            Step::Continue
        });

        assert_eq!(
            seen,
            vec![0x06, 0x15],
            "the DATA behind the impossible length is still reached"
        );
    }

    /// The datagram the recovery exists for.
    ///
    /// `recover`'s own doc names it: an ACKNACK whose octetsToNextHeader is
    /// far past the end of the datagram, "followed by a perfectly valid
    /// DATA_FRAG". DATA_FRAG is 0x16, so the plausibility test must cover
    /// `0x01..=0x16`; stopping at 0x15 would walk straight over the one
    /// submessage the whole heuristic exists to find. The test above pins the
    /// same scenario with a DATA (0x15), which a narrower window would still
    /// admit - so only this one covers the packet in the doc comment.
    ///
    /// Fragmented SPDP is what rides in that DATA_FRAG, so the loss is a
    /// participant that is never discovered.
    #[test]
    fn the_datagram_the_recovery_was_written_for_carries_a_data_frag() {
        let mut packet = header();
        // ACKNACK claiming 55983 octets follow, which they do not.
        packet.push(0x06);
        packet.push(0x01);
        packet.extend_from_slice(&55983u16.to_le_bytes());
        packet.extend_from_slice(&[0x00; 20]);
        packet.extend_from_slice(&data_frag());

        let mut seen = Vec::new();
        for_each_submessage(&packet, |found| {
            seen.push(found.id);
            Step::Continue
        });

        assert_eq!(
            seen,
            vec![0x06, 0x16],
            "the DATA_FRAG behind the impossible length is still reached"
        );
    }

    /// What the recovery must REFUSE, which is the other half of the rule.
    ///
    /// The forward scan steps four octets at a time over whatever the
    /// poisoned submessage covered, and most of what it crosses is body, not
    /// headers. Two tests decide whether a word is a header: the id must be
    /// one the spec assigns (0x01-0x16, or the vendor range), and the flag
    /// byte only has meaning in its low bits. Drop either and the scan
    /// settles on the first word that merely has a plausible LENGTH -
    /// silently, since a recovered offset leaves no trace - and everything
    /// behind it is read at the wrong place.
    ///
    /// So the datagram below puts two decoys between the poisoned ACKNACK
    /// and the real DATA_FRAG: one whose id is unassigned, one whose flags
    /// are out of range. Both carry a length that fits. The walk must step
    /// over both.
    #[test]
    fn the_recovery_refuses_a_word_that_is_not_a_submessage_header() {
        let mut packet = header();
        // ACKNACK claiming 55983 octets follow, which they do not.
        packet.push(0x06);
        packet.push(0x01);
        packet.extend_from_slice(&55983u16.to_le_bytes());
        packet.extend_from_slice(&[0x00; 20]);

        // Decoy 1 at offset 44: id 0x1F is assigned to nothing, and sits
        // below the vendor range. Length 4, little-endian, so it fits.
        assert_eq!(packet.len(), 44, "decoy 1 sits where the scan looks");
        packet.extend_from_slice(&[0x1F, 0x01, 0x04, 0x00]);
        packet.extend_from_slice(&[0x00; 4]);

        // Decoy 2 at offset 52: a real DATA id, but flags 0x40 is a bit no
        // submessage defines. E is clear there, so its length reads
        // big-endian - and 4 fits too.
        assert_eq!(packet.len(), 52, "decoy 2 sits where the scan looks");
        packet.extend_from_slice(&[0x15, 0x40, 0x00, 0x04]);
        packet.extend_from_slice(&[0x00; 4]);

        assert_eq!(packet.len(), 60, "the DATA_FRAG sits where the scan looks");
        packet.extend_from_slice(&data_frag());
        assert_eq!(packet.len(), 96, "the fixture ends at the DATA_FRAG");

        let mut seen = Vec::new();
        for_each_submessage(&packet, |found| {
            seen.push(found.id);
            Step::Continue
        });

        assert_eq!(
            seen,
            vec![0x06, 0x16],
            "the scan steps over both decoys and lands on the DATA_FRAG"
        );
    }

    /// And the bound on that scan: past the window the walk gives up rather
    /// than trawling the whole datagram for something that looks like a
    /// submessage header.
    #[test]
    fn recovery_gives_up_past_the_scan_window() {
        let mut packet = header();
        packet.push(0x06);
        packet.push(0x01);
        packet.extend_from_slice(&55983u16.to_le_bytes());
        packet.extend_from_slice(&[0x00; 20]);
        // Push the DATA past the window. The filler is 0xff bytes, an id in
        // the vendor range, so it is the length test that rejects them.
        packet.extend_from_slice(&vec![0xff; CLASSIFIER_SCAN_WINDOW]);
        packet.extend_from_slice(&data());

        let mut seen = Vec::new();
        for_each_submessage(&packet, |found| {
            seen.push(found.id);
            Step::Continue
        });

        assert_eq!(seen, vec![0x06], "the walk stops rather than scanning on");
    }
    /// Where a submessage's contents END, including for the last one.
    ///
    /// RTPS 2.5 9.4.5.1.3 gives `octetsToNextHeader == 0` a meaning that is the
    /// opposite of its arithmetic: the submessage is the last one and its
    /// contents run to the end of the MESSAGE. A consumer that computes the
    /// bound itself writes `offset + 4 + octets_to_next` and gets an empty
    /// body for exactly that case, or - the mirror error - clamps to the
    /// datagram and swallows the submessage that follows. The walk answers it
    /// once.
    #[test]
    fn a_body_ends_at_its_own_submessage_or_at_the_datagram() {
        // Three submessages: a DATA of declared length 20, a second one, and
        // a last one that declares 0.
        let mut packet = header();
        packet.extend_from_slice(&data());
        packet.extend_from_slice(&data());
        let last_at = packet.len();
        let mut last = vec![0x15, 0x01];
        last.extend_from_slice(&0u16.to_le_bytes()); // "I am the last one"
        last.extend_from_slice(&[0xEE; 20]);
        packet.extend_from_slice(&last);

        let mut ends = Vec::new();
        for_each_submessage(&packet, |found| {
            ends.push((found.offset, found.octets_to_next, found.body_end));
            Step::Continue
        });

        assert_eq!(
            ends,
            vec![(20, 20, 44), (44, 20, 68), (last_at, 0, packet.len()),],
            "the last body runs to the end of the datagram, not to offset + 4"
        );
        assert_eq!(last_at, 68);

        // And an over-declared length is clamped to the datagram rather than
        // handed out as a slice bound nobody can use.
        let mut over = header();
        let mut greedy = vec![0x15, 0x01];
        greedy.extend_from_slice(&4000u16.to_le_bytes());
        greedy.extend_from_slice(&[0x00; 20]);
        over.extend_from_slice(&greedy);

        let mut seen = Vec::new();
        for_each_submessage(&over, |found| {
            seen.push(found.body_end);
            Step::Continue
        });
        assert_eq!(seen, vec![over.len()], "clamped, and still a valid bound");
    }

    /// RTPS 2.5 9.4.5.1.3: an empty PAD or INFO_TS (octetsToNextHeader 0)
    /// is not the last submessage; the next header follows at once. Any
    /// other submessage declaring 0 still runs to the end of the message.
    #[test]
    fn an_empty_pad_or_info_ts_is_not_the_last_submessage() {
        for id in [0x01u8, 0x09] {
            // INFO_TS with its InvalidateFlag: no timestamp, no contents.
            let flags = if id == 0x09 { 0x03 } else { 0x01 };
            let mut packet = header();
            packet.extend_from_slice(&[id, flags, 0x00, 0x00]);
            packet.extend_from_slice(&data());
            assert_eq!(
                chain(&packet),
                vec![(20, id, 0), (24, 0x15, 20)],
                "0x{id:02x} of length 0, then a DATA"
            );
        }
        // Ending the message is allowed too.
        let mut packet = header();
        packet.extend_from_slice(&data());
        packet.extend_from_slice(&[0x01, 0x01, 0x00, 0x00]);
        assert_eq!(chain(&packet).len(), 2);
    }

    /// 8.3.8.11: an INFO_TS with its InvalidateFlag leaves the submessages
    /// that follow without a timestamp; its absent contents are not read
    /// from the submessage behind it.
    #[test]
    fn an_invalidating_info_ts_clears_the_timestamp() {
        let mut packet = header();
        packet.extend_from_slice(&info_ts(1, 1));
        packet.extend_from_slice(&data());
        packet.extend_from_slice(&[0x09, 0x03, 0x00, 0x00]);
        packet.extend_from_slice(&data());

        // The flag decides, whatever the length: an INFO_TS that carries a
        // Time_t AND the InvalidateFlag leaves no timestamp either.
        packet.extend_from_slice(&info_ts(2, 2));
        packet.extend_from_slice(&[0x09, 0x03, 0x08, 0x00]);
        packet.extend_from_slice(&[0x05; 8]);
        packet.extend_from_slice(&data());

        let mut dated = Vec::new();
        for_each_submessage(&packet, |found| {
            if found.id == 0x15 {
                dated.push(found.context.source_timestamp);
            }
            Step::Continue
        });
        assert_eq!(dated, vec![Some((1, 1)), None, None]);
    }

    /// An INFO_TS without its InvalidateFlag and too short for a Time_t is
    /// invalid, and so is the rest of the message (8.3.4.1).
    #[test]
    fn an_info_ts_too_short_ends_the_message() {
        let mut packet = header();
        packet.extend_from_slice(&data());
        packet.extend_from_slice(&[0x09, 0x01, 0x04, 0x00, 0x07, 0x07, 0x07, 0x07]);
        packet.extend_from_slice(&data());
        assert_eq!(chain(&packet).len(), 1, "only the DATA before it");

        let mut empty = header();
        empty.extend_from_slice(&[0x09, 0x01, 0x00, 0x00]);
        empty.extend_from_slice(&data());
        assert!(chain(&empty).is_empty(), "no InvalidateFlag and no Time_t");

        // The bound from both sides: seven octets are not a Time_t, eight are.
        for (declared, visited) in [(7u8, 0usize), (8, 2)] {
            let mut packet = header();
            packet.extend_from_slice(&[0x09, 0x01, declared, 0x00]);
            packet.extend_from_slice(&[0x07; 8]); // contents, realigned
            packet.extend_from_slice(&data());
            assert_eq!(
                chain(&packet).len(),
                visited,
                "INFO_TS declaring {declared}"
            );
        }
    }

    // ------------------------------------------------------------------
    // The destination of a submessage (RTPS 2.5 8.3.8.8).
    // ------------------------------------------------------------------

    const OURS: [u8; 12] = [0x0B; 12];
    const THEIRS: [u8; 12] = [0x0C; 12];

    fn info_dst(prefix: [u8; 12]) -> Vec<u8> {
        let mut submessage = vec![0x0e, 0x01];
        submessage.extend_from_slice(&12u16.to_le_bytes());
        submessage.extend_from_slice(&prefix);
        submessage
    }

    /// A HEARTBEAT with its twenty-eight octets of fields.
    fn heartbeat() -> Vec<u8> {
        let mut submessage = vec![0x07, 0x01];
        submessage.extend_from_slice(&28u16.to_le_bytes());
        submessage.extend_from_slice(&[0x00; 28]);
        submessage
    }

    /// The ids and offsets a walk reports, to compare two datagrams' chains.
    fn chain(buf: &[u8]) -> Vec<(usize, u8, u16)> {
        let mut seen = Vec::new();
        for_each_submessage(buf, |found| {
            seen.push((found.offset, found.id, found.octets_to_next));
            Step::Continue
        });
        seen
    }

    #[test]
    fn a_datagram_with_no_foreign_destination_is_used_whole() {
        let mut none = header();
        none.extend_from_slice(&data());
        assert_eq!(destined_to(&none, &OURS), Destined::Whole);

        let mut ours = header();
        ours.extend_from_slice(&info_dst(OURS));
        ours.extend_from_slice(&data());
        assert_eq!(destined_to(&ours, &OURS), Destined::Whole);

        // GUIDPREFIX_UNKNOWN: the participant receiving the message.
        let mut unknown = header();
        unknown.extend_from_slice(&info_dst([0; 12]));
        unknown.extend_from_slice(&heartbeat());
        assert_eq!(destined_to(&unknown, &OURS), Destined::Whole);

        assert_eq!(destined_to(b"not rtps at all", &OURS), Destined::Whole);
    }

    /// A submessage behind an INFO_DST naming another participant becomes a
    /// PAD of the same length; the one behind an INFO_DST naming us is
    /// kept, and the chain of headers does not move.
    #[test]
    fn a_submessage_destined_to_another_participant_is_padded_out() {
        let mut packet = header();
        packet.extend_from_slice(&info_dst(THEIRS));
        let theirs_at = packet.len();
        packet.extend_from_slice(&data());
        packet.extend_from_slice(&info_dst(OURS));
        let ours_at = packet.len();
        packet.extend_from_slice(&data());

        let Destined::Part(part) = destined_to(&packet, &OURS) else {
            panic!("one DATA is ours, one is not");
        };
        assert_eq!(part.len(), packet.len());
        assert_eq!(part[theirs_at], PAD, "the DATA for the other participant");
        assert_eq!(part[ours_at], 0x15, "our DATA, untouched");
        assert_eq!(&part[theirs_at + 1..], &packet[theirs_at + 1..]);
        let ids: Vec<(usize, u16)> = chain(&part).iter().map(|c| (c.0, c.2)).collect();
        let original: Vec<(usize, u16)> = chain(&packet).iter().map(|c| (c.0, c.2)).collect();
        assert_eq!(ids, original, "every header where it was");
    }

    #[test]
    fn a_datagram_destined_entirely_elsewhere_is_nothing() {
        let mut packet = header();
        packet.extend_from_slice(&info_dst(THEIRS));
        packet.extend_from_slice(&heartbeat());
        packet.extend_from_slice(&data_frag());
        assert_eq!(destined_to(&packet, &OURS), Destined::Nothing);
    }

    /// INFO_TS is receiver state, not an endpoint's: one met in another
    /// participant's section still dates the samples that follow it.
    #[test]
    fn receiver_state_in_a_foreign_section_still_applies() {
        let mut packet = header();
        packet.extend_from_slice(&info_dst(THEIRS));
        packet.extend_from_slice(&info_ts(7, 7));
        packet.extend_from_slice(&data());
        packet.extend_from_slice(&info_dst(OURS));
        packet.extend_from_slice(&data());

        let Destined::Part(part) = destined_to(&packet, &OURS) else {
            panic!("the second DATA is ours");
        };
        let mut dated = Vec::new();
        for_each_submessage(&part, |found| {
            if found.id == 0x15 {
                dated.push(found.context.source_timestamp);
            }
            Step::Continue
        });
        assert_eq!(dated, vec![Some((7, 7))]);
    }

    /// The last submessage (octetsToNextHeader 0) destined elsewhere is cut,
    /// never turned into a PAD of length 0, which would mean "the next header
    /// follows" and have the rest of its body read as submessages.
    #[test]
    fn a_last_submessage_destined_elsewhere_is_cut() {
        let mut packet = header();
        packet.extend_from_slice(&data());
        packet.extend_from_slice(&info_dst(THEIRS));
        let last_at = packet.len();
        let mut last = vec![0x15, 0x01, 0x00, 0x00];
        last.extend_from_slice(&[0x07; 40]);
        packet.extend_from_slice(&last);

        assert_eq!(
            destined_to(&packet, &OURS),
            Destined::Part(packet[..last_at].to_vec())
        );
    }

    /// An INFO_DST too short for a GuidPrefix is invalid, and so is the rest
    /// of the message (8.3.4.1): no consumer visits anything behind it,
    /// whether or not it knows which participant it receives for.
    #[test]
    fn an_info_dst_too_short_ends_the_message() {
        for (declared, body) in [(8u16, 8usize), (0, 8), (11, 11)] {
            let mut packet = header();
            packet.extend_from_slice(&data());
            let short_at = packet.len();
            packet.extend_from_slice(&[0x0e, 0x01]);
            packet.extend_from_slice(&declared.to_le_bytes());
            packet.extend_from_slice(&vec![0x0C; body]);
            if declared != 0 {
                packet.extend_from_slice(&data());
            }
            assert_eq!(
                chain(&packet).iter().map(|c| c.0).collect::<Vec<_>>(),
                vec![20],
                "declared {declared}: only the DATA before the INFO_DST at {short_at}"
            );
        }

        // Twelve octets exactly is a GuidPrefix: the walk goes on.
        let mut packet = header();
        packet.extend_from_slice(&info_dst(THEIRS));
        packet.extend_from_slice(&data());
        assert_eq!(chain(&packet).len(), 2);
    }

    /// Each submessage that acts on an endpoint, and only those, is padded
    /// out when destined to another participant. The rows are literals.
    #[test]
    fn every_endpoint_submessage_and_no_other_is_padded_out() {
        let table: [(u8, bool); 16] = [
            (0x06, true),  // ACKNACK
            (0x07, true),  // HEARTBEAT
            (0x08, true),  // GAP
            (0x12, true),  // NACK_FRAG
            (0x13, true),  // HEARTBEAT_FRAG
            (0x15, true),  // DATA
            (0x16, true),  // DATA_FRAG
            (0x30, true),  // SEC_BODY
            (0x31, true),  // SEC_PREFIX
            (0x32, true),  // SEC_POSTFIX
            (0x01, false), // PAD
            (0x09, false), // INFO_TS
            (0x0c, false), // INFO_SRC
            (0x0d, false), // INFO_REPLY_IP4
            (0x0f, false), // INFO_REPLY
            (0x80, false), // vendor-specific
        ];
        for (id, padded) in table {
            let mut packet = header();
            packet.extend_from_slice(&info_dst(THEIRS));
            let at = packet.len();
            packet.extend_from_slice(&[id, 0x01, 0x08, 0x00]);
            packet.extend_from_slice(&[0x00; 8]);
            packet.extend_from_slice(&info_dst(OURS));
            packet.extend_from_slice(&data());
            let seen = match destined_to(&packet, &OURS) {
                Destined::Whole => packet[at],
                Destined::Part(part) => part[at],
                Destined::Nothing => panic!("0x{id:02x}: our DATA follows"),
            };
            assert_eq!(seen == PAD && id != PAD, padded, "submessage 0x{id:02x}");
        }
    }
}
