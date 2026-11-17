// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! DATA and DATA_FRAG submessage handlers.
//!
//!
//! DATA submessages carry user data or discovery information (SPDP/SEDP).
//! DATA_FRAG submessages carry fragmented data with reassembly metadata.

use super::super::super::{FragmentGeometry, FragmentMetadata, PacketKind};
use super::super::walk;
use crate::core::discovery::GUID;

/// The one fragment-count bound, owned by the consumer that must enforce it
/// (`FragmentBuffer::insert_fragment_with_addr`). The scan below refuses
/// early with the same value; the buffer refuses again at admission, on every
/// path, including the classifier out-param fallback this scan does not see.
pub use crate::core::discovery::fragment_buffer::MAX_FRAGMENTS_PER_SAMPLE;

/// Mask isolating the entityKind namespace bits (RTPS v2.5 Sec.9.3.1.2).
const ENTITY_KIND_NAMESPACE_MASK: u8 = 0xC0;

/// The namespace the spec reserves for its own builtin entities.
const ENTITY_KIND_BUILTIN: u8 = 0xC0;

/// The builtin endpoint an entity id names, if any.
///
/// An RTPS entity id is what tells a discovery submessage from a user one, and
/// it means the same thing whether it was read out of a DATA or out of a
/// DATA_FRAG. The map lives ONCE, not once per submessage handler: two copies
/// drift, and a DATA_FRAG copy that knew only the three plaintext discovery
/// writers would name a fragmented TypeLookup reply - and a large
/// TypeObject is exactly what fragments - user data while its unfragmented
/// form is named TypeLookup, and the same would hold for the five secure
/// builtin endpoints. One reader, not two patches.
///
/// `None` means the id is not a builtin entity AT ALL - a user-defined or
/// vendor-specific writer, per the entityKind octet - and the caller names
/// the submessage it actually read: `Data` for a 0x15, `DataFrag` for a 0x16.
/// A builtin id with no arm here is a different answer:
/// `Some(PacketKind::UnknownBuiltin)`, so that it is dropped by name instead
/// of being taken for user data. The two must stay distinct answers: user data
/// goes to a parser that GUESSES a payload's type - see the variant's own doc
/// for what that registers.
///
/// Readers as well as writers are matched, because some vendors address the
/// secure reader directly - a SEDP ACKNACK reply routed through the secure
/// tunnel reuses the entity.
fn builtin_endpoint_kind(entity_id: &[u8]) -> Option<PacketKind> {
    use crate::core::rtps_constants::{
        RTPS_ENTITYID_BUILTIN_PARTICIPANT_STATELESS_MESSAGE_READER,
        RTPS_ENTITYID_BUILTIN_PARTICIPANT_STATELESS_MESSAGE_WRITER,
        RTPS_ENTITYID_BUILTIN_PARTICIPANT_VOLATILE_MESSAGE_SECURE_READER,
        RTPS_ENTITYID_BUILTIN_PARTICIPANT_VOLATILE_MESSAGE_SECURE_WRITER,
        RTPS_ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_READER,
        RTPS_ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_SECURE_READER,
        RTPS_ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_SECURE_WRITER,
        RTPS_ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_WRITER,
        RTPS_ENTITYID_SEDP_PUBLICATIONS_SECURE_READER,
        RTPS_ENTITYID_SEDP_PUBLICATIONS_SECURE_WRITER, RTPS_ENTITYID_SEDP_PUBLICATIONS_WRITER,
        RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_SECURE_READER,
        RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_SECURE_WRITER, RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_WRITER,
        RTPS_ENTITYID_SPDP_SECURE_READER, RTPS_ENTITYID_SPDP_SECURE_WRITER,
        RTPS_ENTITYID_SPDP_WRITER, RTPS_ENTITYID_TYPELOOKUP_REPLY_WRITER,
        RTPS_ENTITYID_TYPELOOKUP_REQUEST_WRITER,
    };

    let kind = match entity_id {
        w if w == RTPS_ENTITYID_SPDP_WRITER => PacketKind::SPDP,
        w if w == RTPS_ENTITYID_SEDP_PUBLICATIONS_WRITER
            || w == RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_WRITER =>
        {
            PacketKind::SEDP
        }
        // Both TypeLookup writers route to the same handler, which tells a
        // request from a reply by this very entity id. Without the REPLY arm
        // an incoming getTypes reply would be named user DATA and silently
        // dropped, leaving the requesting side inert.
        w if w == RTPS_ENTITYID_TYPELOOKUP_REQUEST_WRITER
            || w == RTPS_ENTITYID_TYPELOOKUP_REPLY_WRITER =>
        {
            PacketKind::TypeLookup
        }
        // RTPS v2.5 Sec.8.4.13. The plaintext pair, which our own
        // PID_BUILTIN_ENDPOINT_SET asks every peer for (bits 10 and 11). The
        // constants are read from the canonical module, not from the mirrored
        // `protocol::constants`. A builtin endpoint missing from the map is
        // not neutral: its DATA is named user data and taken to the content
        // guesser.
        w if w == RTPS_ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_WRITER
            || w == RTPS_ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_READER =>
        {
            PacketKind::ParticipantMessage
        }
        // DDS-Security v1.1 Sec.7.4.1.3 secure builtin endpoints.
        w if w == RTPS_ENTITYID_SPDP_SECURE_WRITER || w == RTPS_ENTITYID_SPDP_SECURE_READER => {
            PacketKind::SecureSPDP
        }
        w if w == RTPS_ENTITYID_SEDP_PUBLICATIONS_SECURE_WRITER
            || w == RTPS_ENTITYID_SEDP_PUBLICATIONS_SECURE_READER
            || w == RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_SECURE_WRITER
            || w == RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_SECURE_READER
            || w == RTPS_ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_SECURE_WRITER
            || w == RTPS_ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_SECURE_READER =>
        {
            PacketKind::SecureSEDP
        }
        w if w == RTPS_ENTITYID_BUILTIN_PARTICIPANT_VOLATILE_MESSAGE_SECURE_WRITER
            || w == RTPS_ENTITYID_BUILTIN_PARTICIPANT_VOLATILE_MESSAGE_SECURE_READER =>
        {
            PacketKind::SecureVolatile
        }
        w if w == RTPS_ENTITYID_BUILTIN_PARTICIPANT_STATELESS_MESSAGE_WRITER
            || w == RTPS_ENTITYID_BUILTIN_PARTICIPANT_STATELESS_MESSAGE_READER =>
        {
            PacketKind::Stateless
        }
        // RTPS v2.5 Sec.9.3.1.2 Table 9.1: the two most significant bits of
        // the entityKind octet say who NAMED the entity - 0b11 built-in,
        // 0b00 user-defined, 0b01 vendor-specific. Only the first is the
        // spec's own namespace, so only the first can be a builtin endpoint
        // we have simply not implemented. A vendor-specific id is the
        // vendor's own entity and is left with user data on purpose:
        // reclassifying it here would stop routing traffic that is routed
        // today, which is an interop regression traded for nothing.
        //
        // The length test is redundant for the current callers and stays
        // anyway: both slice exactly `buf[offset + 12..offset + 16]`, so no
        // fixture can tell it from its absence. What it guards is the
        // indexing of `w[3]`, which a third caller with a shorter slice would
        // turn into a panic on the receive thread.
        w if w.len() == 4 && w[3] & ENTITY_KIND_NAMESPACE_MASK == ENTITY_KIND_BUILTIN => {
            log::debug!(
                "[CLASSIFY] builtin endpoint {:02x?} has no handler here -> UnknownBuiltin",
                entity_id
            );
            return Some(PacketKind::UnknownBuiltin);
        }
        _ => return None,
    };

    log::debug!(
        "[CLASSIFY] builtin endpoint {:02x?} -> {:?}",
        entity_id,
        kind
    );
    Some(kind)
}

/// Handle DATA submessage with entity_id-based classification.
///
/// DATA submessage layout (RTPS v2.5 Sec.8.3.8.2):
/// - extraFlags (1) + octetsToInlineQos (1) + padding (2)
/// - readerEntityId (4)
/// - writerEntityId (4) <-- used for SPDP/SEDP classification
///
/// # Arguments
/// * `buf` - Raw packet buffer
/// * `offset` - Offset to DATA submessage start
/// * `body_end` - One past the last octet of THIS submessage, from the walk.
///   The writer entity id is read against it and never against the datagram:
///   a DATA declaring a body too short to hold that field must not read the
///   four octets that follow it, which belong to the submessage next door.
///   Otherwise a datagram whose DATA declares an eight-octet body, and so
///   carries no writer entity id at all, would borrow the four octets
///   behind it, be named SPDP, and REGISTER A PARTICIPANT. Same read, same
///   bound as `classify_data_frag` below.
///
/// # Returns
/// PacketKind::SPDP, PacketKind::SEDP, PacketKind::TypeLookup, or PacketKind::Data
pub(in crate::core::discovery::multicast::classifier) fn classify_data(
    buf: &[u8],
    offset: usize,
    body_end: usize,
) -> PacketKind {
    crate::trace_fn!("classify_data");
    // Extract writerEntityId to determine if this is discovery data
    if offset + 4 + 8 + 4 <= body_end {
        let writer_entity_id = &buf[offset + 4 + 8..offset + 4 + 12];

        builtin_endpoint_kind(writer_entity_id).unwrap_or(PacketKind::Data)
    } else {
        PacketKind::Data // Not enough data to check, assume user data
    }
}

/// Handle DATA_FRAG submessage with entity_id-based classification and fragment metadata extraction.
///
/// DATA_FRAG layout is similar to DATA but includes fragment metadata.
///
/// # Arguments
/// * `buf` - Raw packet buffer
/// * `offset` - Offset to DATA_FRAG submessage start
/// * `body_end` - One past the last octet of THIS submessage, from the walk.
///   Every field below is read against it rather than against the datagram: a
///   DATA_FRAG that declares a body shorter than its own 32 fixed octets must
///   not read the missing ones out of the submessage that follows, which would
///   publish fragment metadata - writer, sequence, fragment number, total, and
///   a payload offset past its own end - assembled from a neighbour it does
///   not own, and the router would buffer that neighbour's octets as sample
///   data.
/// * `flags` - Submessage flags (bit 0 = endianness)
/// * `guid_prefix` - GUID prefix from RTPS header (for constructing full writerGUID)
/// * `fragment_metadata` - Output parameter for fragment metadata
///
/// # Returns
/// (PacketKind, bool) - the classification, and whether THIS submessage
/// yielded fragment metadata. The caller must not re-derive the second half
/// from `fragment_metadata.is_some()`: that answers for the datagram, so a
/// DATA_FRAG the walk refused inherited its predecessor's verdict.
pub(in crate::core::discovery::multicast::classifier) fn classify_data_frag(
    buf: &[u8],
    offset: usize,
    body_end: usize,
    flags: u8,
    guid_prefix: [u8; 12],
    fragment_metadata: &mut Option<FragmentMetadata>,
) -> (PacketKind, bool) {
    crate::trace_fn!("classify_data_frag");
    // DATA_FRAG layout: check entity_id for SEDP classification
    if offset + 4 + 8 + 4 <= body_end {
        let writer_entity_id = &buf[offset + 4 + 8..offset + 4 + 12];

        let kind = builtin_endpoint_kind(writer_entity_id).unwrap_or(PacketKind::DataFrag);

        // Extract fragment metadata if the submessage really carries it
        if offset + 36 <= body_end {
            // Try reading writerSeqNum as two u32 instead of one u64
            let seq_high = if flags & 0x01 != 0 {
                u32::from_le_bytes([
                    buf[offset + 16],
                    buf[offset + 17],
                    buf[offset + 18],
                    buf[offset + 19],
                ])
            } else {
                u32::from_be_bytes([
                    buf[offset + 16],
                    buf[offset + 17],
                    buf[offset + 18],
                    buf[offset + 19],
                ])
            };

            let seq_low = if flags & 0x01 != 0 {
                u32::from_le_bytes([
                    buf[offset + 20],
                    buf[offset + 21],
                    buf[offset + 22],
                    buf[offset + 23],
                ])
            } else {
                u32::from_be_bytes([
                    buf[offset + 20],
                    buf[offset + 21],
                    buf[offset + 22],
                    buf[offset + 23],
                ])
            };

            log::debug!(
                "[FRAG-SEQ] seqHigh={} seqLow={} (combined={})",
                seq_high,
                seq_low,
                ((seq_high as u64) << 32) | (seq_low as u64)
            );

            // Parse fragment metadata (RTPS 2.5 Sec 8.3.8.3)
            // DATA_FRAG layout after submessage header (4 bytes):
            // +4-7: extraFlags(2) + octetsToInlineQos(2)
            // +8-11: readerEntityId
            // +12-15: writerEntityId
            // +16-23: writerSeqNum (high:4 + low:4)
            // +24-27: fragmentStartingNum (u32)
            // +28-29: fragmentsInSubmessage (u16)
            // +30-31: fragmentSize (u16)
            // +32-35: dataSize (u32)
            // +36+: SerializedData payload
            let frag_starting_num = if flags & 0x01 != 0 {
                u32::from_le_bytes([
                    buf[offset + 24],
                    buf[offset + 25],
                    buf[offset + 26],
                    buf[offset + 27],
                ])
            } else {
                u32::from_be_bytes([
                    buf[offset + 24],
                    buf[offset + 25],
                    buf[offset + 26],
                    buf[offset + 27],
                ])
            };

            let frags_in_submessage = if flags & 0x01 != 0 {
                u16::from_le_bytes([buf[offset + 28], buf[offset + 29]])
            } else {
                u16::from_be_bytes([buf[offset + 28], buf[offset + 29]])
            };

            let frag_size = if flags & 0x01 != 0 {
                u16::from_le_bytes([buf[offset + 30], buf[offset + 31]])
            } else {
                u16::from_be_bytes([buf[offset + 30], buf[offset + 31]])
            };

            // Read total data size (u32 at offset +32)
            let data_size = if flags & 0x01 != 0 {
                u32::from_le_bytes([
                    buf[offset + 32],
                    buf[offset + 33],
                    buf[offset + 34],
                    buf[offset + 35],
                ])
            } else {
                u32::from_be_bytes([
                    buf[offset + 32],
                    buf[offset + 33],
                    buf[offset + 34],
                    buf[offset + 35],
                ])
            };

            // The geometry the submessage declares. The fragment COUNT is
            // derived from it (`FragmentGeometry::total_fragments`), never
            // read from a second field: falling back on
            // `fragmentsInSubmessage` when `fragmentSize` is zero would be the
            // one case `scan_all_data_frags` refuses outright - the two
            // readers of one field group would answer differently and the
            // reassembly door would believe this one.
            let geometry = FragmentGeometry {
                fragment_size: frag_size,
                sample_size: data_size,
            };
            let total_frags = geometry.total_fragments();

            // Extract writerEntityId (offset +12-15) to construct full writerGUID
            let writer_entity_id = if flags & 0x01 != 0 {
                u32::from_le_bytes([
                    buf[offset + 12],
                    buf[offset + 13],
                    buf[offset + 14],
                    buf[offset + 15],
                ])
            } else {
                u32::from_be_bytes([
                    buf[offset + 12],
                    buf[offset + 13],
                    buf[offset + 14],
                    buf[offset + 15],
                ])
            };

            // Construct full writerGUID from GUID prefix + writerEntityId
            // Convert u32 entity_id to [u8; 4] bytes (preserve endianness from parsing)
            let entity_id_bytes = if flags & 0x01 != 0 {
                writer_entity_id.to_le_bytes()
            } else {
                writer_entity_id.to_be_bytes()
            };
            let writer_guid = GUID::new(guid_prefix, entity_id_bytes);
            let seq_num = ((seq_high as u64) << 32) | (seq_low as u64);

            // A submessage declaring no fragment carries none, whatever its
            // geometry says: `fragmentsInSubmessage` is how many fragments
            // THIS submessage holds (RTPS v2.5 Sec.8.3.8.3). `scan_all_data_frags`
            // refuses to emit an entry for zero, so announcing a fragment here
            // would leave the two readers disagreeing and the router's
            // fallback inserting a fragment the scan says does not exist.
            if frags_in_submessage == 0 || total_frags == 0 {
                log::debug!(
                    "[FRAG-META] writerGUID={:?} seqNum={} carries no fragment \
                     (fragmentsInSubmessage={}, fragmentSize={}, sampleSize={})",
                    writer_guid,
                    seq_num,
                    frags_in_submessage,
                    geometry.fragment_size,
                    geometry.sample_size
                );
                return (kind, false);
            }

            // Store fragment metadata for callback
            *fragment_metadata = Some(FragmentMetadata {
                writer_guid,
                seq_num,
                frag_num: frag_starting_num,
                geometry,
            });

            log::debug!(
                "[FRAG-META] writerGUID={:?} seqNum={} frag={}/{}",
                writer_guid,
                seq_num,
                frag_starting_num,
                total_frags
            );

            // Accept ALL fragments for the fragment reassembly buffer
            (kind, true)
        } else {
            (kind, false) // Buffer too small, skip
        }
    } else {
        (PacketKind::DataFrag, false) // Not enough data to check, assume user data
    }
}

/// One logical fragment extracted from a DATA_FRAG submessage.
///
/// When `fragmentsInSubmessage > 1` (RTPS v2.5 Sec.8.3.8.3), a single DATA_FRAG
/// submessage carries N consecutive fragments.  `scan_all_data_frags` splits each
/// submessage into individual `ScannedFrag` entries so the reassembly buffer can
/// track per-fragment completeness with a simple key count.
pub struct ScannedFrag {
    /// Writer GUID + per-fragment sequence/number fields (one fragment only)
    pub meta: FragmentMetadata,
    /// Raw payload bytes for this single fragment
    pub payload: Vec<u8>,
}

/// Scan an RTPS packet and return every DATA_FRAG fragment it contains.
///
/// Two cases are covered that a single `frag_meta` cannot express:
///
/// 1. A datagram may bundle multiple DATA_FRAG submessages (RTPS v2.5
///    Sec.8.3.3 lets a message carry any number of submessages).
///    The classifier's `Option<FragmentMetadata>` only preserves the LAST one,
///    so earlier fragments would be dropped.  This function re-scans the raw
///    packet and collects ALL of them.
///
/// 2. `fragmentsInSubmessage > 1` -- a single submessage may carry N
///    consecutive fragments.  We split the submessage payload into N slices of
///    `fragmentSize` bytes (last slice may be shorter) and emit one
///    `ScannedFrag` per logical fragment.
///
/// # Arguments
/// * `packet` - Complete raw RTPS datagram (starting at byte 0, "RTPS" magic)
///
/// # Returns
/// One `ScannedFrag` per logical fragment, in wire order.  Empty when the packet
/// is not a valid RTPS message or contains no DATA_FRAG submessages.
pub fn scan_all_data_frags(packet: &[u8]) -> Vec<ScannedFrag> {
    scan_all_addressed_data_frags(packet)
        .into_iter()
        .map(|(frag, _reader)| frag)
        .collect()
}

/// [`scan_all_data_frags`], each fragment paired with the readerId of the
/// DATA_FRAG that carried it (RTPS 2.5 8.3.8.3): the reader it was sent to,
/// or ENTITYID_UNKNOWN for every matched reader of this participant.
pub(crate) fn scan_all_addressed_data_frags(packet: &[u8]) -> Vec<(ScannedFrag, [u8; 4])> {
    scan_all_addressed_data_frags_with_qos(packet)
        .into_iter()
        .map(|(frag, reader, _, _)| (frag, reader))
        .collect()
}

/// The inline QoS a DATA_FRAG carried (its Q flag): the parameter list,
/// sentinel included, and whether it is little-endian (the submessage's E
/// flag, RTPS v2.5 Sec.9.4.5.3.3).
pub(crate) type FragInlineQos = (Vec<u8>, bool);

/// The most octets of inline QoS kept from one DATA_FRAG for its sample.
const MAX_FRAG_INLINE_QOS: usize = 4096;

/// [`scan_all_addressed_data_frags`], the first fragment of each DATA_FRAG
/// that carries inline QoS also paired with it (RTPS v2.5 Sec.8.3.8.3: the
/// inline QoS of a fragmented change, its coherent set and GROUP tags among
/// them, travels with its fragments).
/// One scanned fragment, the readerId it was addressed to, the inline
/// QoS its first fragment carried (if any), and the INFO_TS in force
/// when the walk reached it (RTPS v2.5 Sec.8.3.7.9).
pub(crate) type ScannedFragWithContext = (ScannedFrag, [u8; 4], Option<FragInlineQos>, Option<u64>);

pub(crate) fn scan_all_addressed_data_frags_with_qos(packet: &[u8]) -> Vec<ScannedFragWithContext> {
    // Minimum RTPS packet: 20-byte header + at least one 4-byte submessage header.
    if packet.len() < 24 {
        return Vec::new();
    }

    // Validate RTPS magic, as the classifier does.
    if !crate::core::discovery::multicast::classifier::is_rtps_magic(packet) {
        return Vec::new();
    }

    // GUID prefix lives at bytes [8..20].
    let mut guid_prefix = [0u8; 12];
    guid_prefix.copy_from_slice(&packet[8..20]);

    let mut result: Vec<ScannedFragWithContext> = Vec::new();
    // RTPS v2.5 Sec.8.3.7.9: INFO_TS is RECEIVER CONTEXT, updated as
    // submessages are traversed -- it applies to every submessage that
    // follows it in the SAME message, until the next INFO_TS (or the
    // INVALIDATE flag clears it), NOT to the whole datagram. A datagram
    // batching `[INFO_TS(a), DATA_FRAG, INFO_TS(b), DATA_FRAG]` must stamp
    // the first fragment `a` and the second `b`; calling a single
    // datagram-wide timestamp parse once (which stops at the FIRST
    // DATA/DATA_FRAG it meets) stamped BOTH with `a`. Tracked in the SAME
    // walk that finds the fragments, so each one is stamped with whatever
    // was in force when the walk reached it.
    let mut current_ts: Option<u64> = None;

    // ONE traversal, the classifier's own. A second copy of the submessage
    // walk here would disagree with it on the one thing that separates them:
    // a length running past the end of the datagram, which the walk recovers
    // from. The same datagram would then yield a fragment through discovery
    // and nothing through the router's DataFrag path.
    walk::for_each_submessage(packet, |found| {
        let offset = found.offset;
        let submessage_id = found.id;
        let flags = found.flags;
        let little_endian = (flags & 0x01) != 0;

        // Where THIS submessage's body ends. Sec.8.3.3.3: a zero length marks
        // the last submessage, which runs to the end of the datagram; and a
        // length that does not fit is clamped rather than trusted, so a
        // submessage announcing an impossible octetsToNextHeader is still
        // read, up to the end of the datagram.
        //
        // Everything below reads the body against THIS, not against the whole
        // datagram. Bounding a body by the datagram lets a submessage that
        // over-declares its contents read the NEXT submessage's bytes and
        // deliver them as sample data.
        //
        // Of the four places that bound against the submessage rather than
        // `packet.len()`, only TWO are load-bearing: the two bounds on the
        // fragment slices. The inline-QoS `scan_limit` and the payload-presence
        // guard are redundant behind them - a payload start outside the
        // submessage makes every slice start outside it too, so the slice bound
        // refuses first, and no fixture can tell the difference. They are kept
        // because they stop foreign octets from being READ at all and because
        // the intent belongs where the read happens; they are recorded as
        // redundant so nobody deletes them believing a test would notice.
        // The walk owns this computation; recomputing it here would let the
        // two disagree.
        let submsg_end = found.body_end;

        if submessage_id == 0x09 {
            // INFO_TS (RTPS v2.5 Sec.8.3.7.9): updates the context in
            // force for every submessage from here on in this message,
            // `None` when it carries the INVALIDATE flag (Sec.8.3.8.11)
            // or an otherwise unusable body -- the same decode the
            // ordinary (non-fragmented) DATA path uses.
            current_ts = crate::engine::router::info_ts_ns_at(packet, offset, flags, little_endian);
            return walk::Step::Continue;
        }

        if submessage_id == 0x16 {
            // DATA_FRAG submessage (RTPS v2.5 Sec.8.3.8.3).
            // Minimum header including fragment metadata fields: 4 (submsg hdr) + 32 = 36,
            // and they must fit in THIS submessage. Bounded by the
            // datagram instead, a DATA_FRAG declaring a shorter body would read
            // its fragment number, count and size out of the submessage that
            // follows it, and the router would buffer that as sample payload.
            //
            // Here it is REDUNDANT:
            // when the fixed fields do not fit, `payload_start` (offset + 36,
            // or further on when Q is set) is never below `submsg_end`, so the
            // payload-presence guard below refuses first and no fixture can
            // tell the two apart. It is kept for the same reason as the other
            // redundant bounds in this function: it stops foreign octets from
            // being READ at all, and the intent belongs where the read happens.
            // Recorded so nobody deletes it believing a test would notice.
            if offset + 36 <= submsg_end {
                // Parse writerSeqNum (high u32 at +16, low u32 at +20).
                let seq_high = read_u32(packet, offset + 16, little_endian);
                let seq_low = read_u32(packet, offset + 20, little_endian);
                let seq_num = ((seq_high as u64) << 32) | (seq_low as u64);

                let frag_starting_num = read_u32(packet, offset + 24, little_endian);
                let frags_in_submessage = read_u16(packet, offset + 28, little_endian);
                let frag_size = read_u16(packet, offset + 30, little_endian);
                let data_size = read_u32(packet, offset + 32, little_endian);

                // The same geometry the classifier reads, through the same
                // type, so the count cannot differ between the two readers.
                let geometry = FragmentGeometry {
                    fragment_size: frag_size,
                    sample_size: data_size,
                };
                let total_frags: u32 = geometry.total_fragments();

                // Writer entity-id bytes at +12..+16 (wire order preserved).
                let entity_id_bytes: [u8; 4] = [
                    packet[offset + 12],
                    packet[offset + 13],
                    packet[offset + 14],
                    packet[offset + 15],
                ];
                let writer_guid = GUID::new(guid_prefix, entity_id_bytes);
                // readerId at +8..+12, inside the fixed fields checked above.
                let reader_entity_id: [u8; 4] = [
                    packet[offset + 8],
                    packet[offset + 9],
                    packet[offset + 10],
                    packet[offset + 11],
                ];

                // The fragment data and the inline QoS, read by the one
                // reader of the layout: an invalid DATA_FRAG (Sec.8.3.4.1)
                // yields nothing.
                let Some(layout) = crate::protocol::builder::data_submessage_layout(packet, offset)
                else {
                    return walk::Step::Continue;
                };
                let payload_start = layout.payload;
                let inline_qos: Option<FragInlineQos> = layout
                    .inline_qos
                    .filter(|(start, end)| end - start <= MAX_FRAG_INLINE_QOS)
                    .map(|(start, end)| (packet[start..end].to_vec(), little_endian));

                // Guard: payload must actually be present in the buffer.
                if payload_start < submsg_end
                    && frag_size > 0
                    && frags_in_submessage > 0
                    && total_frags > 0
                    && total_frags <= MAX_FRAGMENTS_PER_SAMPLE
                {
                    let frag_size_usize = frag_size as usize;

                    // Split submessage payload into individual fragments
                    // (`fragmentsInSubmessage` may exceed 1).
                    for i in 0..frags_in_submessage {
                        let slice_start = payload_start + usize::from(i) * frag_size_usize;
                        if slice_start >= submsg_end {
                            break;
                        }
                        // Last fragment may be shorter than frag_size - but it
                        // stops at the end of THIS submessage. Clamping to the
                        // datagram instead would fill the trailing fragments of an
                        // over-declaring DATA_FRAG with the next submessage's
                        // header and body, and hand them to reassembly as
                        // sample payload.
                        let slice_end = (slice_start + frag_size_usize).min(submsg_end);
                        let frag_payload = packet[slice_start..slice_end].to_vec();

                        // fragmentStartingNum is wire input: a value near the top
                        // of FragmentNumber_t must not overflow the numbering, so
                        // the fragments past the end of the space are not scanned.
                        let Some(this_frag_num) = frag_starting_num.checked_add(u32::from(i))
                        else {
                            break;
                        };
                        result.push((
                            ScannedFrag {
                                meta: FragmentMetadata {
                                    writer_guid,
                                    seq_num,
                                    frag_num: this_frag_num,
                                    geometry,
                                },
                                payload: frag_payload,
                            },
                            reader_entity_id,
                            if i == 0 { inline_qos.clone() } else { None },
                            current_ts,
                        ));
                    }
                }
            }
        }

        // The sentinel, the impossible length and the 4-octet realignment of
        // Sec.9.4.1 all live in the walk.
        walk::Step::Continue
    });

    result
}

/// Read a little- or big-endian u32 from `buf[pos..pos+4]`.
#[inline(always)]
fn read_u32(buf: &[u8], pos: usize, le: bool) -> u32 {
    if le {
        u32::from_le_bytes([buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]])
    } else {
        u32::from_be_bytes([buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]])
    }
}

/// Read a little- or big-endian u16 from `buf[pos..pos+2]`.
#[inline(always)]
fn read_u16(buf: &[u8], pos: usize, le: bool) -> u16 {
    if le {
        u16::from_le_bytes([buf[pos], buf[pos + 1]])
    } else {
        u16::from_be_bytes([buf[pos], buf[pos + 1]])
    }
}

/// Offset of the payload of the DATA or DATA_FRAG submessage at `offset`
/// (its serializedPayload's encapsulation header, or a DATA_FRAG's fragment
/// data), read by the one reader of that layout
/// (`builder::data_submessage_layout`, RTPS v2.5 Sec.9.4.5.4 and 9.4.5.5).
/// `None` when the submessage is invalid, which the classifier then ignores
/// (Sec.8.3.4.1).
pub(in crate::core::discovery::multicast::classifier) fn calculate_payload_offset(
    buf: &[u8],
    offset: usize,
) -> Option<usize> {
    crate::trace_fn!("calculate_payload_offset");
    crate::protocol::builder::data_submessage_layout(buf, offset).map(|layout| layout.payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal valid RTPS DATA_FRAG submessage starting at packet offset 20.
    ///
    /// Layout (LE, no inline QoS):
    ///   [0..3]   RTPS magic
    ///   [4]      major=2 [5] minor=5
    ///   [6..7]   vendorId
    ///   [8..19]  GUID prefix (12 bytes)
    ///   [20]     submsgId=0x16 (DATA_FRAG)
    ///   [21]     flags=0x01 (LE)
    ///   [22..23] octetsToNextHeader (LE u16)
    ///   [24..27] extra_flags(2) + octetsToInlineQos(2)
    ///   [28..31] readerEntityId
    ///   [32..35] writerEntityId
    ///   [36..43] writerSeqNum (high u32 + low u32 LE)
    ///   [44..47] fragmentStartingNum (u32 LE)
    ///   [48..49] fragmentsInSubmessage (u16 LE)
    ///   [50..51] fragmentSize (u16 LE)
    ///   [52..55] dataSize (u32 LE)
    ///   [56..]   payload bytes
    ///
    /// Offsets relative to submessage start (packet[20]):
    ///   +0   submsgId
    ///   +4   extraFlags/octetsToInlineQos
    ///   +8   readerEntityId
    ///   +12  writerEntityId
    ///   +16  seqHigh
    ///   +20  seqLow
    ///   +24  fragmentStartingNum
    ///   +28  fragmentsInSubmessage
    ///   +30  fragmentSize
    ///   +32  dataSize
    ///   +36  payload
    fn build_rtps_data_frag(
        frag_start: u32,
        frags_in_sub: u16,
        frag_size: u16,
        data_size: u32,
        seq: u64,
        payload: &[u8],
    ) -> Vec<u8> {
        build_rtps_data_frag_endian(
            true,
            frag_start,
            frags_in_sub,
            frag_size,
            data_size,
            seq,
            payload,
        )
    }

    /// The same submessage in either byte order.
    ///
    /// The other fixtures in this module are little-endian, so a scan forced
    /// to read little-endian regardless of the E flag would go unnoticed by
    /// them. The E flag is Sec.8.3.3.3's rule and big-endian peers are real.
    #[allow(clippy::too_many_arguments)]
    fn build_rtps_data_frag_endian(
        little_endian: bool,
        frag_start: u32,
        frags_in_sub: u16,
        frag_size: u16,
        data_size: u32,
        seq: u64,
        payload: &[u8],
    ) -> Vec<u8> {
        fn u16b(v: u16, le: bool) -> [u8; 2] {
            if le {
                v.to_le_bytes()
            } else {
                v.to_be_bytes()
            }
        }
        fn u32b(v: u32, le: bool) -> [u8; 4] {
            if le {
                v.to_le_bytes()
            } else {
                v.to_be_bytes()
            }
        }
        // Submessage body size (octetsToNextHeader): from byte +4 to end of
        // payload. RTPS v2.5 Sec.8.3.8.3: extraFlags(2) + octetsToInlineQos(2)
        // + readerEntityId(4) + writerEntityId(4) + writerSN(8) +
        // fragmentStartingNum(4) + fragmentsInSubmessage(2) + fragmentSize(2)
        // + sampleSize(4) = 32, then the payload.
        //
        // Adding 36 here would make every fixture declare FOUR OCTETS more
        // than it carried, and a scan bounded by the datagram would not
        // notice. A fixture that over-declares its own length
        // cannot prove anything about a bound on that length.
        let body_size = 32 + payload.len();
        let mut pkt = vec![0u8; 20 + 4 + body_size];
        pkt[0..4].copy_from_slice(b"RTPS");
        pkt[4] = 2;
        pkt[5] = 5;
        pkt[6] = 0x01;
        pkt[7] = 0x1a;
        // GUID prefix at [8..20]: leave as zeros (test writer GUID)

        let sm = 20usize; // submessage start
        pkt[sm] = 0x16; // DATA_FRAG
        pkt[sm + 1] = if little_endian { 0x01 } else { 0x00 }; // E flag
        let otn = body_size as u16;
        pkt[sm + 2..sm + 4].copy_from_slice(&u16b(otn, little_endian));
        // extraFlags=0; octetsToInlineQos=28: the fixed fields that follow
        // it, up to sampleSize (RTPS v2.5 Sec.9.4.5.5). 0 points into them.
        pkt[sm + 6..sm + 8].copy_from_slice(&u16b(28, little_endian));
        // readerEntityId at sm+8..sm+12: zeros
        // writerEntityId at sm+12..sm+16: [0x01, 0x00, 0x00, 0x02]
        pkt[sm + 12] = 0x01;
        pkt[sm + 15] = 0x02;
        // seqNum = high(32) | low(32)
        let seq_high = (seq >> 32) as u32;
        let seq_low = seq as u32;
        pkt[sm + 16..sm + 20].copy_from_slice(&u32b(seq_high, little_endian));
        pkt[sm + 20..sm + 24].copy_from_slice(&u32b(seq_low, little_endian));
        pkt[sm + 24..sm + 28].copy_from_slice(&u32b(frag_start, little_endian));
        pkt[sm + 28..sm + 30].copy_from_slice(&u16b(frags_in_sub, little_endian));
        pkt[sm + 30..sm + 32].copy_from_slice(&u16b(frag_size, little_endian));
        pkt[sm + 32..sm + 36].copy_from_slice(&u32b(data_size, little_endian));
        pkt[sm + 36..sm + 36 + payload.len()].copy_from_slice(payload);

        // The builder asserts its own wire invariant: the declared length must
        // be the length of what follows it, to the octet.
        assert_eq!(
            sm + 4 + usize::from(otn),
            pkt.len(),
            "octetsToNextHeader must describe the body exactly"
        );
        pkt
    }

    /// A big-endian peer's fragment is read in ITS byte order.
    ///
    /// Sec.8.3.3.3: bit 0 of the flags is the endianness of every field that
    /// follows, `octetsToNextHeader` included. Every other fixture in this
    /// module is little-endian, so a scan hard-coded to little-endian would
    /// pass them. A big-endian sequence number read the wrong way round is
    /// 42 becoming 704643072.
    #[test]
    fn a_big_endian_fragment_is_read_in_its_own_byte_order() {
        let payload_bytes = [0xAAu8, 0xBB, 0xCC, 0xDD];
        let pkt = build_rtps_data_frag_endian(false, 1, 1, 4, 4, 42, &payload_bytes);

        assert_eq!(pkt[21] & 0x01, 0, "the fixture clears the E flag");
        assert_eq!(
            &pkt[22..24],
            &36u16.to_be_bytes(),
            "and writes its own length big-endian"
        );

        let frags = scan_all_data_frags(&pkt);
        assert_eq!(frags.len(), 1, "the big-endian fragment is found");
        assert_eq!(frags[0].meta.seq_num, 42, "and its sequence number is 42");
        assert_eq!(frags[0].meta.frag_num, 1);
        assert_eq!(frags[0].meta.total_frags(), 1);
        assert_eq!(frags[0].payload, payload_bytes);
    }

    /// The packet this scan and the classifier's walk answer differently.
    ///
    /// A vendor sends an ACKNACK whose octetsToNextHeader runs far past the
    /// end of the datagram, with a perfectly good DATA_FRAG behind it.
    /// `classifier::walk::recover` exists for exactly that packet and finds
    /// the fragment; this scan gives up on the impossible length and returns
    /// nothing. So the SAME datagram yields a fragment through the discovery
    /// classifier and no fragment through the router's DataFrag path, which
    /// is the drift `walk.rs` exists to prevent.
    #[test]
    fn a_fragment_behind_an_impossible_length_is_still_scanned() {
        let payload_bytes = [0xAAu8, 0xBB, 0xCC, 0xDD];
        let one = build_rtps_data_frag(1, 1, 4, 4, 42, &payload_bytes);

        let mut pkt = one[..20].to_vec();
        pkt.push(0x06); // ACKNACK
        pkt.push(0x01); // flags: LE
        pkt.extend_from_slice(&55983u16.to_le_bytes());
        pkt.extend_from_slice(&[0x00; 20]);
        assert_eq!(pkt.len(), 44, "the DATA_FRAG starts on a 4-octet boundary");
        pkt.extend_from_slice(&one[20..]);

        let frags = scan_all_data_frags(&pkt);
        assert_eq!(
            frags.len(),
            1,
            "the fragment behind the impossible length is still found"
        );
        assert_eq!(frags[0].meta.seq_num, 42);
    }

    #[test]
    fn test_scan_single_datafrag_one_fragment() {
        // One DATA_FRAG submessage with fragmentsInSubmessage=1.
        let payload_bytes = [0xAAu8, 0xBB, 0xCC];
        let pkt = build_rtps_data_frag(1, 1, 3, 3, 42, &payload_bytes);

        let frags = scan_all_data_frags(&pkt);
        assert_eq!(frags.len(), 1, "expected 1 scanned fragment");
        assert_eq!(frags[0].meta.frag_num, 1);
        assert_eq!(frags[0].meta.seq_num, 42);
        assert_eq!(frags[0].meta.total_frags(), 1);
        assert_eq!(frags[0].payload, payload_bytes);
    }

    /// A sample of 100 MB in 1024-byte fragments is 102400 fragments, more
    /// than a u16 can count. Carried in 16 bits, this header would scan as
    /// 102400 mod 65536 = 36864, so the reassembly buffer would declare the
    /// sample complete after 36864 fragments and deliver a truncated payload.
    /// sampleSize is a u32 and fragmentSize can be 1, so the count has to be
    /// carried in 32 bits (RTPS v2.5 Sec.8.3.8.3).
    #[test]
    fn test_scan_datafrag_total_frags_exceeding_u16_is_not_wrapped() {
        let frag_size: u16 = 1024;
        let data_size: u32 = 100 * 1024 * 1024;
        let payload = [0x5Au8; 1024];
        let pkt = build_rtps_data_frag(1, 1, frag_size, data_size, 9, &payload);

        let frags = scan_all_data_frags(&pkt);
        assert_eq!(frags.len(), 1);
        assert_eq!(frags[0].meta.total_frags(), 102_400);
    }

    /// A remote peer controls both sampleSize and fragmentSize, so it controls
    /// total_frags, and a u32 count has no natural bound on the reassembly
    /// buffer's stale sweep: one 60-byte DATA_FRAG announcing
    /// sampleSize 0xFFFFFFFF at fragmentSize 1 would ask for 4_294_967_295
    /// fragments and a ~17 GB `missing` list under the buffer mutex.
    /// It is refused at admission, and this test goes red if that bound is
    /// ever removed.
    #[test]
    fn test_scan_datafrag_refuses_a_fragment_count_above_the_admission_bound() {
        let payload = [0x5Au8; 1];
        let pkt = build_rtps_data_frag(1, 1, 1, u32::MAX, 9, &payload);
        assert!(
            scan_all_data_frags(&pkt).is_empty(),
            "sampleSize u32::MAX at fragmentSize 1 announces 2^32-1 fragments and must be refused"
        );

        // The bound itself is inclusive: exactly MAX_FRAGMENTS_PER_SAMPLE is
        // admitted, one more is not.
        let at_bound = build_rtps_data_frag(1, 1, 1, MAX_FRAGMENTS_PER_SAMPLE, 9, &payload);
        assert_eq!(
            scan_all_data_frags(&at_bound).len(),
            1,
            "exactly the bound is admitted"
        );
        let over = build_rtps_data_frag(1, 1, 1, MAX_FRAGMENTS_PER_SAMPLE + 1, 9, &payload);
        assert!(
            scan_all_data_frags(&over).is_empty(),
            "one past the bound is refused"
        );
    }

    /// fragmentStartingNum is wire input. At the top of FragmentNumber_t the
    /// per-fragment numbering must stop rather than overflow: only the
    /// fragment that still has a number is scanned.
    #[test]
    fn test_scan_datafrag_numbering_stops_at_fragment_number_max() {
        let payload = [0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let pkt = build_rtps_data_frag(u32::MAX, 2, 4, 8, 3, &payload);

        let frags = scan_all_data_frags(&pkt);
        assert_eq!(
            frags.len(),
            1,
            "the second fragment has no FragmentNumber_t"
        );
        assert_eq!(frags[0].meta.frag_num, u32::MAX);
        assert_eq!(frags[0].payload, [0x01, 0x02, 0x03, 0x04]);
    }

    /// Append a marked HEARTBEAT behind `pkt`. These are the bytes an
    /// over-declaring DATA_FRAG in front of it must never reach.
    fn append_marked_heartbeat(pkt: &mut Vec<u8>, marker: u8) {
        pkt.push(0x07); // HEARTBEAT
        pkt.push(0x01); // E flag
        pkt.extend_from_slice(&28u16.to_le_bytes());
        pkt.extend_from_slice(&[marker; 28]);
    }

    /// A DATA_FRAG announcing more fragments than its body holds must stop at
    /// its own end, not at the datagram's.
    ///
    /// Declares `fragmentsInSubmessage = 3` at 4 octets each - 12 octets of
    /// payload - and carries 4. Bounding the slices by the DATAGRAM handed
    /// fragments 2 and 3 to reassembly built from the NEXT submessage:
    /// fragment 2 would be literally the HEARTBEAT's own header. Silent,
    /// because reassembly has no way to know.
    #[test]
    fn a_datafrag_declaring_more_fragments_than_it_carries_stops_at_its_own_end() {
        let mut pkt = build_rtps_data_frag(1, 3, 4, 12, 7, &[0xAA, 0xAA, 0xAA, 0xAA]);
        let submsg_end = pkt.len();
        append_marked_heartbeat(&mut pkt, 0xBB);
        assert!(
            pkt.len() > submsg_end,
            "the fixture must have something behind the DATA_FRAG to steal"
        );

        let frags = scan_all_data_frags(&pkt);

        assert_eq!(
            frags.len(),
            1,
            "only the fragment the submessage actually carries"
        );
        assert_eq!(frags[0].payload, [0xAA, 0xAA, 0xAA, 0xAA]);
    }

    /// A fragment that STARTS inside the submessage but would run past its end
    /// is cut at that end.
    ///
    /// Six octets of payload at `fragmentSize = 4` means the second fragment
    /// is two octets long. Clamped to the datagram it would be four, the last
    /// two lifted from whatever followed - the distinction the test above cannot
    /// make, because there the fragment started past the end and was dropped
    /// whole.
    #[test]
    fn a_fragment_running_past_the_submessage_is_cut_at_its_end() {
        let mut pkt = build_rtps_data_frag(1, 2, 4, 8, 7, &[0xAA; 6]);
        append_marked_heartbeat(&mut pkt, 0xBB);

        let frags = scan_all_data_frags(&pkt);

        assert_eq!(frags.len(), 2);
        assert_eq!(frags[0].payload, [0xAA; 4]);
        assert_eq!(
            frags[1].payload,
            [0xAA, 0xAA],
            "the tail fragment is what the submessage holds, no more"
        );
    }

    /// The inline-QoS scan that locates the payload is bounded by the
    /// submessage too.
    ///
    /// The DATA_FRAG below carries one non-sentinel parameter that fills its
    /// body exactly, so there is NO PID_SENTINEL inside it - and the bytes
    /// right behind it open with one. Scanning to the datagram found that
    /// foreign sentinel and put the payload start outside the submessage
    /// entirely, so every fragment emitted would be made of the following
    /// submessage's bytes. Bounded, the scan runs out inside the submessage,
    /// the payload start is not inside it, and nothing is emitted.
    #[test]
    fn the_inline_qos_scan_does_not_leave_the_submessage() {
        // pid = 0x1234 (not a sentinel), length 4, then its four octets.
        let qos = [0x34u8, 0x12, 0x04, 0x00, 0xAA, 0xAA, 0xAA, 0xAA];
        let mut pkt = build_rtps_data_frag(1, 2, 4, 8, 9, &qos);
        pkt[21] |= 0x02; // Q flag: the body starts with an inline-QoS ParameterList
                         // PID_SENTINEL, length 0 - belonging to no submessage of ours.
        pkt.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);
        pkt.extend_from_slice(&[0xCC; 16]);

        let frags = scan_all_data_frags(&pkt);

        for f in &frags {
            assert!(
                !f.payload.contains(&0xCC),
                "no fragment may carry a byte from behind the submessage: {:02x?}",
                f.payload
            );
        }
        assert!(
            frags.is_empty(),
            "no payload start inside the submessage means nothing to emit, \
             not a payload start taken from outside it"
        );
    }

    /// A length that cannot fit the datagram is still clamped to the datagram.
    ///
    /// A submessage header may announce an impossible `octetsToNextHeader`;
    /// the fragments behind such a header must still be read, up to the end of
    /// the datagram. Unclamped, the bound would be past the end of the
    /// buffer and the third declared fragment would slice out of range.
    #[test]
    fn an_impossible_length_is_clamped_to_the_datagram() {
        let mut pkt = build_rtps_data_frag(
            1,
            3,
            4,
            12,
            3,
            &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88],
        );
        pkt[22..24].copy_from_slice(&55983u16.to_le_bytes());

        let frags = scan_all_data_frags(&pkt);

        assert_eq!(frags.len(), 2, "the two fragments the datagram holds");
        assert_eq!(frags[0].payload, [0x11, 0x22, 0x33, 0x44]);
        assert_eq!(frags[1].payload, [0x55, 0x66, 0x77, 0x88]);
    }

    #[test]
    fn test_scan_single_datafrag_multi_frags_in_submessage() {
        // One DATA_FRAG submessage carrying 3 fragments of 4 bytes each.
        let payload_bytes = [
            0x01u8, 0x02, 0x03, 0x04, // frag 1
            0x05, 0x06, 0x07, 0x08, // frag 2
            0x09, 0x0A, 0x0B, 0x0C,
        ]; // frag 3
        let data_size = payload_bytes.len() as u32; // 12
        let frag_size: u16 = 4;
        let pkt = build_rtps_data_frag(1, 3, frag_size, data_size, 7, &payload_bytes);

        let frags = scan_all_data_frags(&pkt);
        assert_eq!(
            frags.len(),
            3,
            "expected 3 fragments split from frags_in_submessage=3"
        );
        assert_eq!(frags[0].meta.frag_num, 1);
        assert_eq!(frags[1].meta.frag_num, 2);
        assert_eq!(frags[2].meta.frag_num, 3);
        assert_eq!(frags[0].payload, [0x01, 0x02, 0x03, 0x04]);
        assert_eq!(frags[1].payload, [0x05, 0x06, 0x07, 0x08]);
        assert_eq!(frags[2].payload, [0x09, 0x0A, 0x0B, 0x0C]);
        // All should share the same seq_num and total_frags.
        for f in &frags {
            assert_eq!(f.meta.seq_num, 7);
            assert_eq!(f.meta.total_frags(), 3);
        }
    }

    #[test]
    fn test_scan_two_datafrag_submessages_in_one_datagram() {
        // Two DATA_FRAG submessages in one datagram.
        // Use frag_size=8 so each submessage body is 36+8=44 bytes (4-byte aligned),
        // which matches the alignment requirement for RTPS submessage chaining.
        let p1 = build_rtps_data_frag(1, 1, 8, 16, 99, &[0xAAu8; 8]);
        let p2 = build_rtps_data_frag(2, 1, 8, 16, 99, &[0xBBu8; 8]);

        // Construct a combined packet: RTPS header (20 bytes) + submsg1 body + submsg2 body.
        // sm1's octetsToNextHeader is already set to 44 (non-zero, non-sentinel) by the helper.
        // sm2 is the last submessage so its otn may be anything (scanner stops on buffer end).
        let sm1_body = &p1[20..]; // length = 4 + 44 = 48
        let sm2_body = &p2[20..]; // length = 4 + 44 = 48

        let mut combined = Vec::new();
        combined.extend_from_slice(b"RTPS");
        combined.push(2);
        combined.push(5); // version
        combined.push(0x01);
        combined.push(0x1a); // vendor
        combined.extend_from_slice(&[0u8; 12]); // GUID prefix
        combined.extend_from_slice(sm1_body);
        combined.extend_from_slice(sm2_body);

        let frags = scan_all_data_frags(&combined);
        assert_eq!(
            frags.len(),
            2,
            "expected 2 fragments from 2 DATA_FRAG submessages"
        );
        assert_eq!(frags[0].meta.frag_num, 1);
        assert_eq!(frags[1].meta.frag_num, 2);
        assert_eq!(frags[0].payload, [0xAAu8; 8]);
        assert_eq!(frags[1].payload, [0xBBu8; 8]);
    }

    #[test]
    fn test_scan_empty_and_invalid() {
        // Empty packet.
        assert!(scan_all_data_frags(&[]).is_empty());
        // Truncated.
        assert!(scan_all_data_frags(&[0u8; 10]).is_empty());
        // Bad magic.
        let mut bad = vec![0u8; 40];
        bad[0] = 0xFF;
        assert!(scan_all_data_frags(&bad).is_empty());
    }

    /// The entityKind octet says who NAMED the entity, and the three
    /// namespaces get three different answers (RTPS v2.5 Sec.9.3.1.2
    /// Table 9.1).
    ///
    /// Three questions need three answers: a builtin endpoint we simply have
    /// not implemented must not be named user data and routed to a parser that
    /// GUESSES a payload's type. The middle row pins that; the outer two are
    /// here so it cannot silently take either of them with it. A
    /// vendor-specific id in particular MUST stay user data: reclassifying it
    /// would stop routing traffic that is routed today.
    #[test]
    fn a_data_is_named_by_the_namespace_its_writer_belongs_to() {
        // entityKind 0xc2: builtin writer WITH_KEY.
        assert_eq!(
            builtin_endpoint_kind(&[0x00, 0x00, 0x03, 0xc2]),
            Some(PacketKind::SEDP),
            "a builtin endpoint we DO implement"
        );
        // 0x000002c2 is the SEDP Topic writer (DCPSTopic). Builtin, no
        // handler here, and a peer may announce it.
        assert_eq!(
            builtin_endpoint_kind(&[0x00, 0x00, 0x02, 0xc2]),
            Some(PacketKind::UnknownBuiltin),
            "a builtin endpoint we do NOT implement is still a builtin"
        );
        // entityKind 0x02: user-defined writer WITH_KEY.
        assert_eq!(
            builtin_endpoint_kind(&[0x00, 0x00, 0x12, 0x02]),
            None,
            "an application writer"
        );
        // entityKind 0x42: vendor-specific writer WITH_KEY.
        assert_eq!(
            builtin_endpoint_kind(&[0x00, 0x00, 0x12, 0x42]),
            None,
            "a vendor's own entity is the vendor's business, not a builtin"
        );
    }

    /// A minimal INFO_TS (0x09) submessage, LE, carrying `secs` whole
    /// seconds (fraction 0), same wire layout `info_ts_ns_at` decodes.
    fn info_ts_submsg_le(secs: i32) -> [u8; 12] {
        let mut b = [0u8; 12];
        b[0] = 0x09;
        b[1] = 0x01; // E flag (LE), not invalidating
        b[2..4].copy_from_slice(&8u16.to_le_bytes());
        b[4..8].copy_from_slice(&secs.to_le_bytes());
        b
    }

    /// RTPS v2.5 Sec.8.3.7.9: INFO_TS is RECEIVER CONTEXT, updated as
    /// submessages are traversed, NOT a datagram-wide constant. A
    /// datagram batching two fragmented samples behind two DIFFERENT
    /// INFO_TS boundaries --
    /// `[INFO_TS(100), DATA_FRAG(A), INFO_TS(300), DATA_FRAG(B)]` -- must
    /// stamp A with 100 and B with 300. A single, datagram-wide
    /// `parse_info_ts_ns(payload)` call stops at the FIRST DATA/DATA_FRAG
    /// it meets, so it answers 100 for the whole datagram and both
    /// fragments would be stamped with it.
    ///
    /// Computing `current_ts` once before the walk instead of updating it on
    /// every INFO_TS submessage the walk visits must fail this test: fragment
    /// B would report `Some(100_000_000_000)` instead of
    /// `Some(300_000_000_000)`.
    #[test]
    fn a_batched_datagram_stamps_each_data_frag_with_its_own_info_ts() {
        let packet_a = build_rtps_data_frag(1, 1, 8, 8, 1, &[0xAAu8; 8]);
        let packet_b = build_rtps_data_frag(1, 1, 8, 8, 2, &[0xBBu8; 8]);

        let mut pkt = packet_a[..20].to_vec();
        pkt.extend_from_slice(&info_ts_submsg_le(100));
        pkt.extend_from_slice(&packet_a[20..]);
        pkt.extend_from_slice(&info_ts_submsg_le(300));
        pkt.extend_from_slice(&packet_b[20..]);

        let scanned = scan_all_addressed_data_frags_with_qos(&pkt);
        assert_eq!(scanned.len(), 2, "both fragments must be found");
        assert_eq!(
            scanned[0].3,
            Some(100_000_000_000),
            "fragment A: the INFO_TS in force when the walk reached it"
        );
        assert_eq!(
            scanned[1].3,
            Some(300_000_000_000),
            "fragment B: the SECOND INFO_TS boundary, not the first one a \
             datagram-wide parse would have stopped at"
        );
    }

    /// The first fragment of a DATA_FRAG with the Q flag comes with the
    /// inline QoS it carried, the fragment's bytes unchanged; the others,
    /// and a DATA_FRAG without it, with none.
    #[test]
    fn a_data_frags_inline_qos_comes_with_its_first_fragment() {
        use crate::protocol::builder::{
            build_data_frag_packets_ts, data_frag_inline_qos, put_inline_qos_in_first_fragment,
            RtpsEndpointContext,
        };
        let ctx = RtpsEndpointContext {
            guid_prefix: [0x21; 12],
            reader_entity_id: [0, 0, 0, 0],
            writer_entity_id: [0, 0, 0x01, 0x02],
            encapsulation_kind: 0x0007,
            publisher_entity_id: [0, 0, 0x01, 0x08],
        };
        let payload = vec![0x33u8; 20_000];
        let plain = build_data_frag_packets_ts(
            &ctx,
            4,
            &payload,
            1024,
            crate::dds::CdrVersion::Xcdr2,
            (0, 0),
            false,
        );
        let qos = data_frag_inline_qos(&ctx, "T", Some(4), None, None, None);
        let mut packets = plain.clone();
        assert!(put_inline_qos_in_first_fragment(&mut packets, &qos));
        let first = scan_all_addressed_data_frags_with_qos(&packets[0]);
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].2, Some((qos.clone(), true)));
        let plain_first = scan_all_addressed_data_frags_with_qos(&plain[0]);
        assert_eq!(first[0].0.payload, plain_first[0].0.payload);
        assert_eq!(plain_first[0].2, None, "no Q, no inline QoS");
        let second = scan_all_addressed_data_frags_with_qos(&packets[1]);
        assert_eq!(second[0].2, None);
    }

    /// A DATA_FRAG's octetsToInlineQos counts the 28 octets of fixed fields
    /// behind it (RTPS v2.5 Sec.9.4.5.5); less points into them, and the
    /// submessage is invalid, ignored (Sec.8.3.4.1): no fragment from the
    /// scan nor from the classifier. From another vendor, always; from HDDS,
    /// below 16 (16..28 is our own legacy, read by the test below).
    #[test]
    fn a_data_frag_whose_octets_to_inline_qos_points_into_its_fixed_fields_yields_nothing() {
        for (vendor, otq) in [
            ([0x01, 0x10], 0u16),
            ([0x01, 0x10], 16),
            ([0x01, 0x10], 27),
            ([0x01, 0x1a], 0),
            ([0x01, 0x1a], 15),
            ([0x01, 0xaa], 12),
        ] {
            let mut pkt = build_rtps_data_frag(1, 1, 8, 8, 1, &[0xAA; 8]);
            pkt[6..8].copy_from_slice(&vendor);
            pkt[26..28].copy_from_slice(&otq.to_le_bytes());
            let what = format!("vendor {vendor:02x?}, octetsToInlineQos={otq}");
            assert!(scan_all_data_frags(&pkt).is_empty(), "{what}");
            let (_kind, offset, meta, _ctx) =
                crate::core::discovery::multicast::classifier::classify_rtps(&pkt);
            assert_eq!(offset, None, "{what}");
            assert!(meta.is_none(), "{what}");
        }
        let pkt = build_rtps_data_frag(1, 1, 8, 8, 1, &[0xAA; 8]);
        assert_eq!(scan_all_data_frags(&pkt).len(), 1, "28 reads");
    }

    /// A DATA_FRAG exactly as HDDS 1.1.5 (published) sent one, built here
    /// from that release's encoder (`protocol/rtps/data.rs`
    /// `encode_data_frag`, `protocol/builder/packet.rs`
    /// `build_single_data_frag_packet`), not from ours: RTPS 2.4, vendor
    /// 0x01aa, INFO_TS, then DATA_FRAG flags E only, octetsToInlineQos 16.
    /// Its fragment is read where that release's receivers read it, the end
    /// of the fixed fields; under another vendor id the same bytes are
    /// invalid.
    #[test]
    fn a_data_frag_of_hdds_1_1_5_is_read_and_a_foreign_one_alike_is_not() {
        let fragment: Vec<u8> = (0u8..40).collect();
        let mut pkt = b"RTPS".to_vec();
        pkt.extend_from_slice(&[0x02, 0x04, 0x01, 0xAA]);
        pkt.extend_from_slice(&[
            0x01, 0xAA, 0x37, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        ]);
        pkt.extend_from_slice(&[0x09, 0x01, 0x08, 0x00]); // INFO_TS
        pkt.extend_from_slice(&0x6A00_0000u32.to_le_bytes());
        pkt.extend_from_slice(&0x8000_0000u32.to_le_bytes());
        let frag_at = pkt.len();
        let submsg_len = u16::try_from(32 + fragment.len()).expect("small");
        pkt.extend_from_slice(&[0x16, 0x01]);
        pkt.extend_from_slice(&submsg_len.to_le_bytes());
        pkt.extend_from_slice(&0u16.to_le_bytes()); // extraFlags
        pkt.extend_from_slice(&16u16.to_le_bytes()); // octetsToInlineQos, as 1.1.5 wrote it
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // readerId
        pkt.extend_from_slice(&[0x00, 0x00, 0x01, 0x02]); // writerId
        pkt.extend_from_slice(&0i32.to_le_bytes()); // writerSN high
        pkt.extend_from_slice(&3u32.to_le_bytes()); // writerSN low
        pkt.extend_from_slice(&2u32.to_le_bytes()); // fragmentStartingNum
        pkt.extend_from_slice(&1u16.to_le_bytes()); // fragmentsInSubmessage
        pkt.extend_from_slice(&40u16.to_le_bytes()); // fragmentSize
        pkt.extend_from_slice(&100u32.to_le_bytes()); // sampleSize
        pkt.extend_from_slice(&fragment);
        assert_eq!(pkt.len(), frag_at + 4 + usize::from(submsg_len), "fixture");

        for vendor in [[0x01, 0xAA], [0x01, 0x1A]] {
            pkt[6..8].copy_from_slice(&vendor);
            let frags = scan_all_data_frags(&pkt);
            assert_eq!(frags.len(), 1, "vendor {vendor:02x?}");
            assert_eq!(frags[0].payload, fragment, "vendor {vendor:02x?}");
            assert_eq!((frags[0].meta.seq_num, frags[0].meta.frag_num), (3, 2));
            let (_kind, offset, meta, _ctx) =
                crate::core::discovery::multicast::classifier::classify_rtps(&pkt);
            assert_eq!(offset, Some(frag_at + 36), "vendor {vendor:02x?}");
            assert!(meta.is_some(), "vendor {vendor:02x?}");
        }
        pkt[6..8].copy_from_slice(&[0x01, 0x10]);
        assert!(
            scan_all_data_frags(&pkt).is_empty(),
            "another vendor: invalid"
        );
        let (_kind, offset, _meta, _ctx) =
            crate::core::discovery::multicast::classifier::classify_rtps(&pkt);
        assert_eq!(offset, None, "another vendor: invalid");
    }

    /// Only PID_SENTINEL (0x0001, Sec.9.6.2.2) ends a DATA_FRAG's inline QoS;
    /// 0x3F01..0x3F03 (DDS-XTypes 1.3 Table 34) do not end it. A list those
    /// end is unterminated: no fragment.
    #[test]
    fn only_pid_sentinel_ends_a_data_frag_inline_qos() {
        let with_list = |end_pid: u16| {
            let mut body = Vec::new();
            body.extend_from_slice(&0x0070u16.to_le_bytes());
            body.extend_from_slice(&16u16.to_le_bytes());
            body.extend_from_slice(&[0x42; 16]);
            body.extend_from_slice(&end_pid.to_le_bytes());
            body.extend_from_slice(&0u16.to_le_bytes());
            body.extend_from_slice(&[0xAA; 8]);
            let mut pkt = build_rtps_data_frag(1, 1, 8, 8, 1, &body);
            pkt[21] |= 0x02; // Q
            pkt
        };
        for not_a_sentinel in [0x3F01u16, 0x3F02, 0x3F03] {
            assert!(
                scan_all_data_frags(&with_list(not_a_sentinel)).is_empty(),
                "{not_a_sentinel:#06x}"
            );
        }
        let frags = scan_all_data_frags(&with_list(0x0001));
        assert_eq!(frags.len(), 1);
        assert_eq!(
            frags[0].payload,
            vec![0xAA; 8],
            "the data behind the sentinel"
        );
    }

    /// A DATA_FRAG of a later version, four octets of an unknown field
    /// behind sampleSize, octetsToInlineQos 32: its fragment data (Q clear)
    /// and its inline QoS (Q set) are where the field points (RTPS v2.5
    /// Sec.9.4.5.4, Sec.9.4.5.5), not at the end of the fields we know.
    #[test]
    fn a_data_frag_is_read_where_its_octets_to_inline_qos_points() {
        let mut body = vec![0xF0, 0xF1, 0xF2, 0xF3];
        body.extend_from_slice(&[0xAA; 8]);
        let mut pkt = build_rtps_data_frag(1, 1, 8, 8, 1, &body);
        pkt[26..28].copy_from_slice(&32u16.to_le_bytes());
        let frags = scan_all_data_frags(&pkt);
        assert_eq!(frags.len(), 1);
        assert_eq!(
            frags[0].payload,
            vec![0xAA; 8],
            "Q=0: behind the unknown field"
        );

        let mut body = vec![0xF0, 0xF1, 0xF2, 0xF3];
        body.extend_from_slice(&0x0070u16.to_le_bytes());
        body.extend_from_slice(&16u16.to_le_bytes());
        body.extend_from_slice(&[0x42; 16]);
        body.extend_from_slice(&0x0001u16.to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes());
        body.extend_from_slice(&[0xAA; 8]);
        let mut pkt = build_rtps_data_frag(1, 1, 8, 8, 1, &body);
        pkt[26..28].copy_from_slice(&32u16.to_le_bytes());
        pkt[21] |= 0x02; // Q
        let frags = scan_all_addressed_data_frags_with_qos(&pkt);
        assert_eq!(frags.len(), 1);
        assert_eq!(frags[0].0.payload, vec![0xAA; 8], "Q=1: behind the list");
        let (qos, _) = frags[0].2.as_ref().expect("the list");
        assert_eq!(
            &qos[..2],
            &0x0070u16.to_le_bytes(),
            "the list starts behind the field"
        );
    }

    /// RTPS v2.5 Sec.9.4.5.3: inline QoS precedes the payload, including
    /// on a secure SEDP DATA with NONE protection, for every vendor.
    #[test]
    fn secure_sedp_data_uses_the_same_inline_qos_layout_for_every_vendor() {
        let mut pkt = b"RTPS".to_vec();
        pkt.extend_from_slice(&[0x02, 0x05, 0x01, 0x10]);
        pkt.extend_from_slice(&[0x33; 12]);
        let data_at = pkt.len();
        let mut body = vec![0x00, 0x00];
        body.extend_from_slice(&16u16.to_le_bytes());
        body.extend_from_slice(&[0x00; 4]);
        body.extend_from_slice(&[0xff, 0x00, 0x03, 0xc2]);
        body.extend_from_slice(&0i32.to_le_bytes());
        body.extend_from_slice(&1u32.to_le_bytes());
        body.extend_from_slice(&0x0071u16.to_le_bytes());
        body.extend_from_slice(&4u16.to_le_bytes());
        body.extend_from_slice(&[0, 0, 0, 1]);
        body.extend_from_slice(&0x0001u16.to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes());
        body.extend_from_slice(&[0x00, 0x03, 0x00, 0x00, 0x5A, 0x5A, 0x5A, 0x5A]);
        pkt.extend_from_slice(&[0x15, 0x0B]); // E|Q|K
        pkt.extend_from_slice(&u16::try_from(body.len()).expect("small").to_le_bytes());
        pkt.extend_from_slice(&body);
        assert_eq!(
            calculate_payload_offset(&pkt, data_at),
            Some(data_at + 24 + 12),
            "another vendor: behind the sentinel"
        );
        pkt[6..8].copy_from_slice(&[0x01, 0x1a]);
        assert_eq!(
            calculate_payload_offset(&pkt, data_at),
            Some(data_at + 24 + 12),
            "HDDS: behind the sentinel too"
        );
    }
}
