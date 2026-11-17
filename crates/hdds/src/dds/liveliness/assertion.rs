// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! This participant's AUTOMATIC liveliness on the wire (RTPS v2.5
//! Sec.8.4.13.5, Sec.8.7.2.2): a `ParticipantMessageData` of kind
//! AUTOMATIC from its BuiltinParticipantMessageWriter, every third of the
//! shortest finite AUTOMATIC lease of its writers (the scheduler times it),
//! to each discovered participant whose SPDP announces the
//! BuiltinParticipantMessageReader.
//!
//! The writer keeps one instance (the AUTOMATIC kind), so each assertion
//! replaces the previous one: its HEARTBEAT announces that sample alone.
//! The discovery handshakes of the dialects that send one announce the
//! same writer state (`handshake_heartbeat`).

use std::collections::HashMap;
use std::ops::Range;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};

use crate::core::discovery::multicast::{DiscoveryFsm, ParticipantInfo};
use crate::protocol::rtps::participant_message::{
    build_participant_message, build_participant_message_gap, writer_reply_to_acknack,
    BUILTIN_PARTICIPANT_MESSAGE_READER, BUILTIN_PARTICIPANT_MESSAGE_WRITER, KIND_AUTOMATIC,
    KIND_MANUAL,
};
use crate::transport::UdpTransport;

/// `KIND_AUTOMATIC`/`KIND_MANUAL` as a `u32`, for an atomic field.
fn kind_as_u32(kind: [u8; 4]) -> u32 {
    u32::from_be_bytes(kind)
}

fn kind_from_u32(kind: u32) -> [u8; 4] {
    kind.to_be_bytes()
}

/// The BuiltinParticipantMessageWriter of one participant: ONE writer, ONE
/// RTPS sequence-number space, shared between its two keyed instances
/// (AUTOMATIC, MANUAL_BY_PARTICIPANT -- RTPS v2.5 Sec.8.4.13.5,
/// Sec.9.6.3.1's key is `participantGuidPrefix || kind`; the sequence
/// number is the WRITER's, not per-instance).
pub(crate) struct AssertionWriter {
    prefix: [u8; 12],
    /// The sequence number of the last assertion, 0 before the first.
    last_sn: AtomicU64,
    /// The kind of the last assertion (`KIND_AUTOMATIC`/`KIND_MANUAL`, as
    /// a `u32`): a resend on ACKNACK (`answer_acknack`) must repeat that
    /// same instance, not assume AUTOMATIC.
    last_kind: AtomicU32,
    /// The last HEARTBEAT count used (Sec.8.3.8.6: increasing per writer),
    /// shared with the handshake heartbeats.
    count: AtomicU32,
}

// @audit-ok: process-wide by nature: a dialect's discovery handshake is
// built from the participant's GUID prefix alone and looks its writer up
// here; entries are removed when their participant's writer drops.
static WRITERS: OnceLock<Mutex<HashMap<[u8; 12], Weak<AssertionWriter>>>> = OnceLock::new();

fn writers() -> std::sync::MutexGuard<'static, HashMap<[u8; 12], Weak<AssertionWriter>>> {
    WRITERS
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

impl AssertionWriter {
    /// The writer of the participant `prefix`, known to its handshakes
    /// while it lives.
    pub(crate) fn register(prefix: [u8; 12]) -> Arc<Self> {
        let writer = Arc::new(Self {
            prefix,
            last_sn: AtomicU64::new(0),
            last_kind: AtomicU32::new(kind_as_u32(KIND_AUTOMATIC)),
            count: AtomicU32::new(0),
        });
        writers().insert(prefix, Arc::downgrade(&writer));
        writer
    }

    fn next_count(&self) -> u32 {
        self.count.fetch_add(1, Ordering::Relaxed).wrapping_add(1)
    }

    /// Assert this participant's AUTOMATIC liveliness to every discovered
    /// participant that reads assertions (RTPS v2.5 Sec.8.4.13.5).
    pub(crate) fn assert_to_peers(&self, fsm: &DiscoveryFsm, transport: &UdpTransport) {
        self.assert_kind_to_peers(fsm, transport, KIND_AUTOMATIC);
    }

    /// Assert this participant's MANUAL_BY_PARTICIPANT liveliness to every
    /// discovered participant that reads assertions (RTPS v2.5
    /// Sec.8.4.13.5): called only when due AND a writer of that kind
    /// acted since the last check (the scheduler's `ManualSendTimer`
    /// gates this, not this method).
    pub(crate) fn assert_manual_to_peers(&self, fsm: &DiscoveryFsm, transport: &UdpTransport) {
        self.assert_kind_to_peers(fsm, transport, KIND_MANUAL);
    }

    fn assert_kind_to_peers(&self, fsm: &DiscoveryFsm, transport: &UdpTransport, kind: [u8; 4]) {
        if !announces_participant_message_writer() {
            return;
        }
        let peers: Vec<ParticipantInfo> = fsm
            .get_participants()
            .into_iter()
            .filter(|peer| reads_assertions(peer, &self.prefix))
            .collect();
        if peers.is_empty() {
            return;
        }
        let sn = self.last_sn.fetch_add(1, Ordering::Relaxed) + 1;
        self.last_kind.store(kind_as_u32(kind), Ordering::Relaxed);
        let count = self.next_count();
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(crate::core::discovery::multicast::rtps_packet::rtps_time_from_unix)
            .unwrap_or((0, 0));
        for peer in peers {
            let packet = match build_participant_message(
                &self.prefix,
                &peer.guid.prefix,
                sn,
                kind,
                count,
                timestamp,
            ) {
                Ok(packet) => packet,
                Err(e) => {
                    log::debug!("[liveliness] assertion not built: {e}");
                    return;
                }
            };
            for endpoint in &peer.endpoints {
                if let Err(e) = transport.send_to_endpoint(&packet, endpoint) {
                    log::debug!("[liveliness] assertion to {endpoint} failed: {e}");
                }
            }
        }
    }

    /// What to send `destination` in answer to its ACKNACK of this writer
    /// (RTPS v2.5 Sec.8.4.13.3: `history.depth = 1`): a GAP for whatever it
    /// asked that this writer no longer holds, then a resend of the
    /// current sample while it is still what the peer lacks
    /// (`participant_message::writer_reply_to_acknack`). Empty when
    /// nothing was ever asserted, or the peer already holds it.
    fn answer_acknack(
        &self,
        destination: &[u8; 12],
        bitmap_base: u64,
        missing_ranges: &[Range<u64>],
        timestamp: (u32, u32),
    ) -> Vec<Vec<u8>> {
        let last = self.last_sn.load(Ordering::Relaxed);
        let reply = writer_reply_to_acknack(last, bitmap_base, missing_ranges);
        let mut packets = Vec::new();
        if let Some(gap_upto) = reply.gap_upto {
            match build_participant_message_gap(&self.prefix, destination, 1, gap_upto) {
                Ok(gap) => packets.push(gap),
                Err(e) => log::debug!("[liveliness] GAP to {destination:02x?} not built: {e}"),
            }
        }
        if reply.resend_last {
            let count = self.next_count();
            let kind = kind_from_u32(self.last_kind.load(Ordering::Relaxed));
            match build_participant_message(&self.prefix, destination, last, kind, count, timestamp)
            {
                Ok(resend) => packets.push(resend),
                Err(e) => log::debug!("[liveliness] resend to {destination:02x?} not built: {e}"),
            }
        }
        packets
    }
}

/// What the participant-message writer of `our_prefix` answers an ACKNACK
/// addressed to it with (`AssertionWriter::answer_acknack`); empty when
/// `our_prefix` has no writer registered, which the caller cannot tell
/// from "nothing to resend" but which has the same effect: nothing is
/// sent either way.
pub(crate) fn answer_participant_message_acknack(
    our_prefix: &[u8; 12],
    destination: &[u8; 12],
    bitmap_base: u64,
    missing_ranges: &[Range<u64>],
    timestamp: (u32, u32),
) -> Vec<Vec<u8>> {
    match writers().get(our_prefix).and_then(Weak::upgrade) {
        Some(writer) => writer.answer_acknack(destination, bitmap_base, missing_ranges, timestamp),
        None => Vec::new(),
    }
}

impl Drop for AssertionWriter {
    fn drop(&mut self) {
        let mut writers = writers();
        if writers
            .get(&self.prefix)
            .is_some_and(|w| w.strong_count() == 0)
        {
            writers.remove(&self.prefix);
        }
    }
}

/// Whether this participant's SPDP announces the participant-message
/// writer (bit 10): an assertion from an endpoint it does not announce is
/// one a peer has no proxy for. The announcement HDDS sends is the same in
/// every dialect (`protocol::discovery::spdp::build`).
fn announces_participant_message_writer() -> bool {
    crate::protocol::discovery::constants::BUILTIN_ENDPOINT_SET_DEFAULT
        & BUILTIN_PARTICIPANT_MESSAGE_WRITER
        != 0
}

/// Whether `peer`, another participant than `ours`, announced the
/// participant-message reader (bit 11): assertions go to it only.
fn reads_assertions(peer: &ParticipantInfo, ours: &[u8; 12]) -> bool {
    &peer.guid.prefix != ours
        && peer
            .builtin_endpoint_set
            .is_some_and(|set| set & BUILTIN_PARTICIPANT_MESSAGE_READER != 0)
}

/// `(firstSN, lastSN, count)` for a discovery handshake HEARTBEAT of the
/// participant-message writer of `our_prefix`: the last assertion alone,
/// or `(1, 0)` before the first (RTPS v2.5 Sec.8.3.8.6).
pub(crate) fn handshake_heartbeat(our_prefix: &[u8; 12]) -> (u64, u64, u32) {
    let writer = writers().get(our_prefix).and_then(Weak::upgrade);
    match writer {
        Some(writer) => {
            let count = writer.next_count();
            match writer.last_sn.load(Ordering::Relaxed) {
                0 => (1, 0, count),
                sn => (sn, sn, count),
            }
        }
        None => (1, 0, 1),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::discovery::GUID;

    fn peer(prefix: u8, set: Option<u32>) -> ParticipantInfo {
        let mut info = ParticipantInfo::new(
            GUID::new([prefix; 12], [0, 0, 1, 0xC1]),
            vec!["127.0.0.1:1".parse().expect("addr")],
            30_000,
        );
        info.builtin_endpoint_set = set;
        info
    }

    #[test]
    fn assertions_go_to_peers_that_announce_the_reader_only() {
        let ours = [7; 12];
        assert!(reads_assertions(&peer(1, Some(0x0000_0C3F)), &ours));
        assert!(reads_assertions(&peer(1, Some(0x0000_0800)), &ours));
        assert!(
            !reads_assertions(&peer(1, Some(0x0000_043F)), &ours),
            "writer bit only"
        );
        assert!(!reads_assertions(&peer(1, Some(0x0000_003F)), &ours));
        assert!(!reads_assertions(&peer(1, None), &ours), "no endpoint set");
        assert!(
            !reads_assertions(&peer(7, Some(0x0000_0C3F)), &ours),
            "not to ourselves"
        );
    }

    #[test]
    fn this_participant_announces_the_writer_it_asserts_from() {
        assert!(announces_participant_message_writer());
    }

    #[test]
    fn a_handshake_announces_the_last_assertion() {
        let prefix = [0x5A; 12];
        assert_eq!(handshake_heartbeat(&prefix), (1, 0, 1), "no writer: empty");
        let writer = AssertionWriter::register(prefix);
        let (first, last, c1) = handshake_heartbeat(&prefix);
        assert_eq!((first, last), (1, 0), "nothing asserted yet");
        writer.last_sn.store(4, Ordering::Relaxed);
        let (first, last, c2) = handshake_heartbeat(&prefix);
        assert_eq!((first, last), (4, 4));
        assert!(
            c2 > c1,
            "the count increases across the writer's heartbeats"
        );
        drop(writer);
        assert_eq!(handshake_heartbeat(&prefix), (1, 0, 1));
    }

    /// No writer registered for `our_prefix`: nothing to answer with,
    /// whatever the ACKNACK asks.
    #[test]
    fn no_writer_registered_answers_nothing() {
        let prefix = [0xB1; 12];
        let dest = [0xC1; 12];
        assert!(answer_participant_message_acknack(
            &prefix,
            &dest,
            1,
            &[Range { start: 0, end: 9 }],
            (0, 0)
        )
        .is_empty());
    }

    /// A writer that never asserted anything has nothing to resend and
    /// nothing to retire: RTPS v2.5 Sec.8.4.13.3's KEEP_LAST(1) has no
    /// sample yet.
    #[test]
    fn a_writer_with_nothing_asserted_answers_nothing() {
        let prefix = [0xB2; 12];
        let dest = [0xC1; 12];
        let writer = AssertionWriter::register(prefix);
        assert!(answer_participant_message_acknack(
            &prefix,
            &dest,
            1,
            &[Range { start: 1, end: 5 }],
            (0, 0)
        )
        .is_empty());
        drop(writer);
    }

    /// A peer behind on the current sample gets a GAP for everything
    /// before it and a resend of it alone (RTPS v2.5 Sec.8.3.8.4,
    /// Sec.8.4.13.3), addressed to the ACKNACKing peer.
    #[test]
    fn a_peer_behind_gets_a_gap_then_the_current_sample() {
        use crate::protocol::builder::extract_sequence_number;
        use crate::protocol::rtps::participant_message::decode_participant_message_data;

        let prefix = [0xB3; 12];
        let dest = [0xC1; 12];
        let writer = AssertionWriter::register(prefix);
        writer.last_sn.store(5, Ordering::Relaxed);

        let packets = answer_participant_message_acknack(&prefix, &dest, 1, &[], (10, 20));
        assert_eq!(packets.len(), 2, "a GAP for [1,5) then the resend of 5");

        let gap = &packets[0];
        assert_eq!(&gap[8..20], &prefix, "GAP from our writer's participant");
        assert_eq!(gap[20], 0x0E, "INFO_DST starts it, as any assertion");
        assert_eq!(&gap[24..36], &dest, "GAP addressed to the ACKNACKing peer");
        assert_eq!(gap[36], 0x08, "GAP submessage id");

        let resend = &packets[1];
        assert_eq!(&resend[8..20], &prefix);
        assert_eq!(
            resend[20], 0x0E,
            "INFO_DST starts the resend, as any assertion"
        );
        assert_eq!(&resend[24..36], &dest);
        assert_eq!(
            extract_sequence_number(resend),
            Some(5),
            "the current sample alone, never an older one"
        );
        let payload = decode_participant_message_data(&resend[72..]).expect("decodes");
        assert_eq!(payload.participant_guid_prefix, prefix);
        assert_eq!(payload.kind, KIND_AUTOMATIC);

        drop(writer);
    }

    /// A resend on ACKNACK repeats the LAST asserted instance, not always
    /// AUTOMATIC's: the writer's two keyed instances (RTPS v2.5
    /// Sec.9.6.3.1) share one SN space, so a resend of the current
    /// SN must carry whichever kind that SN actually was.
    /// Mutant: hardcoding `KIND_AUTOMATIC` in `answer_acknack`'s resend
    /// (as it did before `last_kind` existed) makes this fail.
    #[test]
    fn a_resend_repeats_the_last_assertions_actual_kind() {
        use crate::protocol::rtps::participant_message::decode_participant_message_data;

        let prefix = [0xB5; 12];
        let dest = [0xC1; 12];
        let writer = AssertionWriter::register(prefix);
        writer.last_sn.store(1, Ordering::Relaxed);
        writer
            .last_kind
            .store(kind_as_u32(KIND_MANUAL), Ordering::Relaxed);

        let packets = answer_participant_message_acknack(&prefix, &dest, 1, &[], (0, 0));
        assert_eq!(
            packets.len(),
            1,
            "only the resend: nothing to GAP before it"
        );
        let payload = decode_participant_message_data(&packets[0][72..]).expect("decodes");
        assert_eq!(payload.kind, KIND_MANUAL, "the last assertion was MANUAL");

        drop(writer);
    }

    /// A peer that already holds the current sample (a pure ACK) gets
    /// nothing back: there is nothing to repair.
    #[test]
    fn a_peer_already_synchronized_gets_no_answer() {
        let prefix = [0xB4; 12];
        let dest = [0xC1; 12];
        let writer = AssertionWriter::register(prefix);
        writer.last_sn.store(3, Ordering::Relaxed);
        assert!(answer_participant_message_acknack(&prefix, &dest, 4, &[], (0, 0)).is_empty());
        drop(writer);
    }
}
