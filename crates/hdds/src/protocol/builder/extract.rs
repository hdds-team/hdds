// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use super::helpers::{find_data_submsg_offset, validate_rtps_data_packet};
use crate::core::discovery::multicast::classifier::walk;
use crate::protocol::constants::{RTPS_MAGIC, RTPS_SUBMSG_DATA, RTPS_SUBMSG_DATA_FRAG};
use crate::protocol::discovery::constants::{
    PID_COHERENT_SET, PID_GROUP_COHERENT_SET, PID_GROUP_COHERENT_SET_HDDS, PID_GROUP_ENTITY_ID,
    PID_KEY_HASH, PID_SENTINEL, PID_STATUS_INFO,
};

/// Read a u16 from `buf` at `off` using the endianness flag `le`.
///
/// Centralises the LE/BE dispatch for all submessage-scoped fields so every
/// reader honours the containing DATA submessage's E flag
/// (RTPS v2.5 sec. 8.3.8.2).
///
/// In debug builds, asserts `off + 2 <= buf.len()`. Callers are expected to
/// have validated the slice length via [`validate_rtps_data_packet`] or a
/// PID/length scan before invoking; the debug assert guards future refactors
/// from silently introducing OOB reads.
#[inline]
pub(crate) fn read_u16(buf: &[u8], off: usize, le: bool) -> u16 {
    debug_assert!(
        off + 2 <= buf.len(),
        "read_u16 out of bounds at offset {}",
        off
    );
    if le {
        u16::from_le_bytes([buf[off], buf[off + 1]])
    } else {
        u16::from_be_bytes([buf[off], buf[off + 1]])
    }
}

/// Read a u32 from `buf` at `off` using the endianness flag `le`.
///
/// Companion to [`read_u16`] for 4-byte submessage-scoped fields.
///
/// In debug builds, asserts `off + 4 <= buf.len()`. Same caller contract as
/// [`read_u16`].
#[inline]
pub(crate) fn read_u32(buf: &[u8], off: usize, le: bool) -> u32 {
    debug_assert!(
        off + 4 <= buf.len(),
        "read_u32 out of bounds at offset {}",
        off
    );
    if le {
        u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
    } else {
        u32::from_be_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
    }
}

/// Where the inline QoS and the payload of one DATA (0x15) or DATA_FRAG
/// (0x16) submessage lie in its datagram: the one reader of that layout
/// every receive path asks (RTPS v2.5 Sec.9.4.5.4, Sec.9.4.5.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DataLayout {
    /// The submessage's E flag: the order of its fields and of its
    /// ParameterList (Sec.9.4.5.1.1).
    pub(crate) is_le: bool,
    /// `[start, end)` of the inline QoS ParameterList, its PID_SENTINEL
    /// included; `None` when the Q flag is clear.
    pub(crate) inline_qos: Option<(usize, usize)>,
    /// First octet of the serializedPayload (its encapsulation header), or
    /// of the fragment data of a DATA_FRAG; `end` when there is none.
    pub(crate) payload: usize,
    /// One past the submessage's last octet.
    pub(crate) end: usize,
}

/// Octets between the end of octetsToInlineQos and the first octet the
/// field can point to: readerId, writerId and writerSN for a DATA (16),
/// and fragmentStartingNum, fragmentsInSubmessage, fragmentSize and
/// sampleSize behind them for a DATA_FRAG (28). An octetsToInlineQos below
/// it points into those fields.
fn fixed_fields_after_octets_to_inline_qos(submessage_id: u8) -> Option<usize> {
    match submessage_id {
        RTPS_SUBMSG_DATA => Some(16),
        RTPS_SUBMSG_DATA_FRAG => Some(28),
        _ => None,
    }
}

/// The [`DataLayout`] of the DATA or DATA_FRAG submessage whose header is at
/// `sub_off`, or `None` when the submessage is invalid and must be ignored
/// (RTPS v2.5 Sec.8.3.4.1: an invalid submessage is skipped, the rest of
/// the message still read; Sec.8.3.8.2 Validity: "inlineQos is invalid"):
///
/// - octetsToInlineQos smaller than the fixed fields it must skip;
/// - fixed fields, or the element octetsToInlineQos points to, outside the
///   submessage;
/// - with Q set, a ParameterList with no PID_SENTINEL (exactly 0x0001,
///   Sec.9.6.2.2) inside the submessage.
pub(crate) fn data_submessage_layout(buf: &[u8], sub_off: usize) -> Option<DataLayout> {
    let (flags, is_le, pointed, end) = data_submessage_frame(buf, sub_off)?;
    // Where octetsToInlineQos points: the inline QoS, or what follows it
    // when Q is clear. A receiver "should always use" it, to skip the
    // header elements of a later version it does not know (Sec.9.4.5.4).
    if flags & 0x02 == 0 {
        return Some(DataLayout {
            is_le,
            inline_qos: None,
            payload: pointed,
            end,
        });
    }
    let qos_start = pointed;
    let mut at = qos_start;
    loop {
        if at + 4 > end {
            return None;
        }
        let pid = read_u16(buf, at, is_le);
        let len = usize::from(read_u16(buf, at + 2, is_le));
        if pid == PID_SENTINEL {
            return Some(DataLayout {
                is_le,
                inline_qos: Some((qos_start, at + 4)),
                payload: at + 4,
                end,
            });
        }
        // Sec.9.4.2.11: the next parameter starts 4-aligned.
        at += 4 + ((len + 3) & !3);
    }
}

/// The header checks every DATA and DATA_FRAG reading shares: `(flags,
/// is_le, where octetsToInlineQos points, the submessage's end)`.
fn data_submessage_frame(buf: &[u8], sub_off: usize) -> Option<(u8, bool, usize, usize)> {
    let fixed = fixed_fields_after_octets_to_inline_qos(*buf.get(sub_off)?)?;
    if sub_off + 8 > buf.len() {
        return None;
    }
    let flags = buf[sub_off + 1];
    let is_le = flags & 0x01 != 0;
    let end = data_submessage_end(buf, sub_off, is_le);
    let octets_to_inline_qos = usize::from(read_u16(buf, sub_off + 6, is_le));
    let after_fixed = sub_off + 8 + fixed;
    if after_fixed > end {
        return None;
    }
    let pointed = if octets_to_inline_qos >= fixed {
        sub_off + 8 + octets_to_inline_qos
    } else if is_legacy_hdds_data_frag(buf, sub_off, octets_to_inline_qos) {
        // Read where the receivers of that release read it.
        after_fixed
    } else {
        return None;
    };
    // Where octetsToInlineQos points: past the submessage, nothing it
    // could point to is there.
    if pointed > end {
        return None;
    }
    Some((flags, is_le, pointed, end))
}

/// A DATA_FRAG of HDDS 1.1.0 to 1.1.5 (published): its encoder wrote
/// octetsToInlineQos 16, the DATA value, where the DATA_FRAG's fixed fields
/// take 28 (RTPS v2.5 Sec.9.4.5.5), and its receivers read the fragment at
/// the end of those fields whatever the field said. Refused as invalid, a
/// large sample from such a writer would never be reassembled. Our own
/// defect, so our own zone: recognised by the datagram's HDDS vendor id
/// (0x011a, and 0x01aa that those releases sent) and a value in 16..28,
/// and only on the path that would otherwise refuse; any other vendor's
/// such DATA_FRAG is invalid, ignored.
fn is_legacy_hdds_data_frag(buf: &[u8], sub_off: usize, octets_to_inline_qos: usize) -> bool {
    buf.get(sub_off) == Some(&RTPS_SUBMSG_DATA_FRAG)
        && (16..28).contains(&octets_to_inline_qos)
        && matches!(buf.get(6..8), Some([0x01, 0x1a] | [0x01, 0xaa]))
}

/// Extract CDR payload from RTPS DATA submessage.
///
/// Returns the serializedPayload of the datagram's first DATA, from its
/// encapsulation header, as [`data_submessage_layout`] locates it: where
/// octetsToInlineQos points when Q is clear, behind the inline QoS
/// PID_SENTINEL when Q is set (RTPS v2.5 Sec.9.4.5.4). `None` on a
/// malformed packet or an invalid DATA (see that function).
///
/// A writer of this version always writes octetsToInlineQos 16 (readerId,
/// writerId, writerSN); every DATA in the captures on hand, ten vendor
/// ids, does. A later version may put header elements behind writerSN, which is why the
/// field, not a fixed 24, says where the payload is.
pub fn extract_data_payload(rtps_packet: &[u8]) -> Option<&[u8]> {
    if !validate_rtps_data_packet(rtps_packet, 24) {
        return None;
    }
    let data_off = find_data_submsg_offset(rtps_packet)?;
    let layout = data_submessage_layout(rtps_packet, data_off)?;
    if layout.payload >= rtps_packet.len() {
        return None;
    }
    Some(&rtps_packet[layout.payload..])
}

/// One past the last octet of the DATA submessage whose header is at
/// `data_off`, `is_le` being its E flag.
///
/// RTPS v2.5 Sec.9.4.5.1.3: octetsToNextHeader counts the octets from the
/// first octet of the contents to the next submessage header; 0 makes the
/// submessage (DATA is neither PAD nor INFO_TS) the last of the message,
/// running to its end. Clamped to the datagram, as `classifier::walk`'s
/// `body_end` is, so the result is always a valid slice bound. The caller
/// has checked that the 4-octet submessage header is in `rtps_packet`.
fn data_submessage_end(rtps_packet: &[u8], data_off: usize, is_le: bool) -> usize {
    let octets_to_next = read_u16(rtps_packet, data_off + 2, is_le) as usize;
    if octets_to_next == 0 {
        rtps_packet.len()
    } else {
        (data_off + 4 + octets_to_next).min(rtps_packet.len())
    }
}

/// Extract inline QoS from an RTPS DATA packet.
///
/// Returns `(inline_qos_slice, is_le)` in a single pass so callers feed the
/// matching endianness flag to [`extract_status_info`], [`extract_key_hash`],
/// [`extract_group_entity_id`], [`extract_coherent_set`], and
/// [`extract_group_coherent_set`] without a second scan of the packet.
///
/// Returns `None` when:
/// * the packet is not a valid RTPS DATA packet,
/// * the DATA submessage does not carry inline QoS (Q flag clear),
/// * `octetsToInlineQos` puts the parameter list past the end of the buffer,
/// * the parameter list has no PID_SENTINEL inside its DATA submessage.
///
/// RTPS DATA layout (offsets in full RTPS packet):
/// - \[20\]: submessageId (0x15)
/// - \[21\]: flags (bit 0 = E endianness, bit 1 = InlineQos present)
/// - \[22-23\]: submessageLength (endianness follows E)
/// - \[24-25\]: extraFlags
/// - \[26-27\]: octetsToInlineQos (typically 16)
/// - \[28-31\]: readerEntityId
/// - \[32-35\]: writerEntityId
/// - \[36-43\]: sequenceNumber
/// - \[44+\]: inline QoS (if flag set), then payload
pub(crate) fn extract_inline_qos(rtps_packet: &[u8]) -> Option<(&[u8], bool)> {
    if !validate_rtps_data_packet(rtps_packet, 44) {
        return None;
    }
    let data_off = find_data_submsg_offset(rtps_packet)?;
    extract_inline_qos_at(rtps_packet, data_off)
}

/// [`extract_inline_qos`] of the DATA submessage at `data_off`, for a
/// caller that knows WHICH DATA of the datagram it is handling: the first
/// one is not necessarily it.
///
/// The ParameterList is read inside THIS submessage only, and must end with
/// its PID_SENTINEL there. RTPS v2.5 Sec.9.4.2.11 requires the sentinel in
/// every ParameterList but the HeaderExtension's, because nothing else marks
/// where the list ends; a DATA whose list is not terminated inside its own
/// submessage has an invalid inlineQos, which makes the submessage invalid
/// (Sec.8.3.8.2, Validity). `None` then: no QoS at all. Walked to the end of
/// the datagram instead, an unterminated list would run on into the
/// submessage that follows, and a PAD or a HEARTBEAT whose octets read
/// as StatusInfo and KeyHash would dispose an instance this DATA never named.
pub(crate) fn extract_inline_qos_at(rtps_packet: &[u8], data_off: usize) -> Option<(&[u8], bool)> {
    let layout = data_submessage_layout(rtps_packet, data_off)?;
    let (start, end) = layout.inline_qos?;
    Some((&rtps_packet[start..end], layout.is_le))
}

/// Extract sequence number from RTPS DATA packet.
///
/// RTPS DATA submessage layout (per RTPS v2.5 Sec.8.3.8.2):
/// - Offset 20: Submessage header (4 bytes: id, flags, octetsToNext)
/// - Offset 24: extraFlags (2 bytes)
/// - Offset 26: octetsToInlineQos (2 bytes)
/// - Offset 28: readerEntityId (4 bytes)
/// - Offset 32: writerEntityId (4 bytes)
/// - Offset 36: writerSN (8 bytes) <- SequenceNumber_t
///
/// SequenceNumber_t is encoded as two 32-bit integers (high, low) whose
/// byte order follows the containing DATA submessage's E flag per
/// RTPS v2.5 sec. 8.3.8.2 / sec. 9.4.5.3.1.
pub fn extract_sequence_number(rtps_packet: &[u8]) -> Option<u64> {
    if !validate_rtps_data_packet(rtps_packet, 44) {
        return None;
    }
    let data_off = find_data_submsg_offset(rtps_packet)?;

    let is_le = rtps_packet[data_off + 1] & 0x01 != 0;

    // Relative to data_off: hdr(4) + extraFlags(2) + octetsToInlineQos(2) +
    // readerEntityId(4) + writerEntityId(4) = 16 -> writerSN at data_off + 16
    let sn_base = data_off + 16;
    if sn_base + 8 > rtps_packet.len() {
        return None;
    }
    let seq_high = read_u32(rtps_packet, sn_base, is_le);
    let seq_low = read_u32(rtps_packet, sn_base + 4, is_le);

    // RTPS SequenceNumber_t: value = high * 2^32 + low
    Some(((seq_high as u64) << 32) | (seq_low as u64))
}

/// Extract writer GUID from RTPS DATA packet.
///
/// The writer GUID consists of:
/// - guidPrefix (12 bytes): From RTPS header at offset 8
/// - writerEntityId (4 bytes): From DATA submessage at offset 28
///
/// Returns a 16-byte array representing the complete writer GUID.
///
/// # RTPS Specification
/// - RTPS v2.5 Sec.8.3.3.1: RTPS Header format (guidPrefix)
/// - RTPS v2.5 Sec.8.3.8.2: DATA Submessage format (writerEntityId)
pub fn extract_writer_guid(rtps_packet: &[u8]) -> Option<[u8; 16]> {
    // Validate RTPS/RTPX magic and minimum packet size
    if rtps_packet.len() < 20 {
        return None;
    }
    let magic_valid = &rtps_packet[0..4] == RTPS_MAGIC || &rtps_packet[0..4] == b"RTPX";
    if !magic_valid {
        return None;
    }

    // Extract guidPrefix from RTPS header (offset 8, 12 bytes)
    let guid_prefix = &rtps_packet[8..20];

    // Find the DATA through `classifier::walk`, the one traversal. A private
    // scanner that neither realigned nor recovered would answer None on
    // datagrams where the walk finds the DATA - and the router, which asks
    // this function who sent a sample, would have no writer to route it to.
    let mut guid = None;
    walk::for_each_submessage(rtps_packet, |submsg| {
        if submsg.id != RTPS_SUBMSG_DATA {
            return walk::Step::Continue;
        }
        // writerEntityId starts after:
        // - 4-byte submessage header
        // - extraFlags (1) + octetsToInlineQos (1) + 2 bytes padding
        // - readerEntityId (4 bytes)
        // See RTPS v2.5 Sec.8.3.8.2 (Data) and 9.4.5.4 (its wire layout)
        let writer_entity_id_offset = submsg.offset + 4 + 8;
        let Some(writer_entity_id) =
            rtps_packet.get(writer_entity_id_offset..writer_entity_id_offset + 4)
        else {
            return walk::Step::Stop;
        };

        // Combine into full 16-byte GUID
        let mut full = [0u8; 16];
        full[0..12].copy_from_slice(guid_prefix);
        full[12..16].copy_from_slice(writer_entity_id);
        guid = Some(full);
        walk::Step::Stop
    });

    guid
}

/// The readerId of the first DATA submessage of an RTPS packet: the reader
/// the DATA is sent to, or ENTITYID_UNKNOWN for every matched reader of the
/// receiving participant (RTPS 2.5 8.3.8.2, 9.3.1.2).
///
/// Found through `classifier::walk`, the same traversal as
/// [`extract_writer_guid`], so both name the same DATA. `None` when the packet
/// holds no DATA or the DATA stops before its readerId.
pub(crate) fn extract_reader_entity_id(rtps_packet: &[u8]) -> Option<[u8; 4]> {
    first_reader_entity_id(rtps_packet, RTPS_SUBMSG_DATA)
}

/// The readerId of the DATA_FRAG carrying fragment `frag_num` of sample
/// `seq` from writer entity `writer_entity_id` (RTPS 2.5 8.3.8.3): the one a
/// fragment's metadata was read from, not merely the first of the datagram.
/// Of several carrying the same fragment, the last, which is the one the
/// classifier keeps. `None` when no DATA_FRAG of the packet matches.
pub(crate) fn extract_frag_reader_entity_id(
    rtps_packet: &[u8],
    writer_entity_id: [u8; 4],
    seq: u64,
    frag_num: u32,
) -> Option<[u8; 4]> {
    let at = find_data_frag(rtps_packet, writer_entity_id, seq, frag_num)?;
    <[u8; 4]>::try_from(&rtps_packet[at + 8..at + 12]).ok()
}

/// Offset of the DATA_FRAG carrying fragment `frag_num` of sample `seq`
/// from writer entity `writer_entity_id` (RTPS 2.5 8.3.8.3); of several,
/// the last, which is the one the classifier keeps. `None` when no
/// DATA_FRAG of the packet matches.
pub(crate) fn find_data_frag(
    rtps_packet: &[u8],
    writer_entity_id: [u8; 4],
    seq: u64,
    frag_num: u32,
) -> Option<usize> {
    let mut found = None;
    walk::for_each_submessage(rtps_packet, |submsg| {
        // readerId (+8), writerId (+12), writerSN (+16), fragmentStartingNum
        // (+24), all inside this submessage.
        if submsg.id != RTPS_SUBMSG_DATA_FRAG || submsg.offset + 28 > submsg.body_end {
            return walk::Step::Continue;
        }
        let at = submsg.offset;
        let le = submsg.flags & 0x01 != 0;
        let high = u64::from(read_u32(rtps_packet, at + 16, le));
        let low = u64::from(read_u32(rtps_packet, at + 20, le));
        if rtps_packet[at + 12..at + 16] == writer_entity_id
            && (high << 32 | low) == seq
            && read_u32(rtps_packet, at + 24, le) == frag_num
        {
            // The LAST match, as the classifier keeps the last DATA_FRAG.
            found = Some(at);
        }
        walk::Step::Continue
    });
    found
}

fn first_reader_entity_id(rtps_packet: &[u8], submessage_id: u8) -> Option<[u8; 4]> {
    let mut reader = None;
    walk::for_each_submessage(rtps_packet, |submsg| {
        if submsg.id != submessage_id {
            return walk::Step::Continue;
        }
        // readerId follows the 4-byte submessage header, extraFlags (2) and
        // octetsToInlineQos (2), and must lie inside this submessage.
        let at = submsg.offset + 8;
        if at + 4 <= submsg.body_end {
            reader = rtps_packet
                .get(at..at + 4)
                .and_then(|id| <[u8; 4]>::try_from(id).ok());
        }
        walk::Step::Stop
    });
    reader
}

/// Whether the first DATA submessage of `rtps_packet` carries neither
/// serialized payload nor key (`D=0, K=0`, RTPS v2.5 Sec.9.4.5.3) and is
/// valid: a change without a sample, whatever its inline QoS.
pub fn is_data_without_sample(rtps_packet: &[u8]) -> bool {
    if rtps_packet.len() < 24 || (&rtps_packet[0..4] != RTPS_MAGIC && &rtps_packet[0..4] != b"RTPX")
    {
        return false;
    }
    find_data_submsg_offset(rtps_packet)
        .is_some_and(|data_off| is_data_at_without_sample(rtps_packet, data_off))
}

/// [`is_data_without_sample`] for the DATA submessage whose header is at
/// `data_off`, found already. Its flags first, so a DATA that carries a
/// sample costs one octet read; then its whole layout
/// ([`data_submessage_layout`]): an invalid DATA is ignored (RTPS v2.5
/// Sec.8.3.4.1, Sec.8.3.8.2 Validity), never taken for a change - an
/// inline QoS with no PID_SENTINEL inside the submessage, an
/// octetsToInlineQos pointing into the fixed fields or past the
/// submessage, fixed fields the submessage does not hold.
pub(crate) fn is_data_at_without_sample(rtps_packet: &[u8], data_off: usize) -> bool {
    rtps_packet.get(data_off) == Some(&RTPS_SUBMSG_DATA)
        && rtps_packet
            .get(data_off + 1)
            .is_some_and(|flags| flags & 0x0c == 0)
        && data_submessage_layout(rtps_packet, data_off).is_some()
}

/// Check if a DATA submessage carries a dispose/unregister lifecycle event.
///
/// Two on-wire forms are recognized (both spec-valid per RTPS v2.5 sec. 8.3.8.2):
///
/// 1. K-flag DATA (K=1, D=0): payload is the serialized key. This is HDDS's
///    own emission path (`build_dispose_packet_with_context`).
/// 2. Inline-QoS-only DATA (D=0, K=0, Q=1): empty payload, lifecycle bits
///    live in `PID_STATUS_INFO` carried in inline QoS. With neither D nor K
///    set the DATA has no serializedPayload (8.3.8.2), and a writer may use
///    this form for a per-instance unregister/dispose: flags E|Q, with
///    PID_STATUS_INFO=0x01/0x02/0x03 and PID_KEY_HASH naming the instance.
///    Without this branch HDDS would silently drop such a per-instance
///    dispose.
///
/// Either form gets routed through `deliver_dispose` so application
/// `get_dispose_events()` sees the per-instance state transition.
pub fn is_key_only_data(rtps_packet: &[u8]) -> bool {
    if !super::helpers::validate_rtps_data_packet(rtps_packet, 24) {
        return false;
    }
    let Some(data_off) = find_data_submsg_offset(rtps_packet) else {
        return false;
    };
    let flags = rtps_packet[data_off + 1];
    let has_key = flags & 0x08 != 0;
    if has_key {
        return true;
    }
    let has_payload = flags & 0x04 != 0;
    let has_inline_qos = flags & 0x02 != 0;
    if has_payload || !has_inline_qos {
        return false;
    }
    // D=0, K=0, Q=1 -- a dispose marker iff inline QoS carries PID_STATUS_INFO
    // with at least one of the D/U bits set (inline-QoS-only per-instance
    // dispose form). The E flag from the DATA submessage flags drives the
    // ParameterList PID/length endianness per RTPS v2.5 sec. 9.4.5.3.3 and is
    // returned by `extract_inline_qos` so the same E flag both helpers see
    // is the one actually used to decode the inline QoS bytes.
    let Some((inline_qos, is_le)) = extract_inline_qos(rtps_packet) else {
        return false;
    };
    matches!(extract_status_info(inline_qos, is_le), Some(s) if (s & 0x03) != 0)
}

/// Extract PID_STATUS_INFO (0x0071) value from inline QoS parameter list.
///
/// The inline QoS bytes are a `ParameterList` per RTPS v2.5 sec. 9.4.5.3.3 with
/// no CDR encapsulation header. Each parameter is PID(u16) + length(u16) +
/// data, where the PID and length follow the containing DATA submessage's
/// E flag (pass `is_le`). The PID_STATUS_INFO value itself is a 4-octet
/// array (DDS-RTPS v2.5 sec. 9.6.4.9: `typedef octet StatusInfo_t[4]`) and is
/// therefore positional, NOT endianness-dependent.
///
/// Returns the 4-byte StatusInfo value as a u32 with flag bits in the low
/// byte if PID 0x0071 is found. StatusInfo bits: 0x01 = DISPOSED,
/// 0x02 = UNREGISTERED.
pub(crate) fn extract_status_info(inline_qos: &[u8], is_le: bool) -> Option<u32> {
    let mut offset = 0;

    loop {
        if offset + 4 > inline_qos.len() {
            return None;
        }

        let pid = read_u16(inline_qos, offset, is_le);
        let len = read_u16(inline_qos, offset + 2, is_le) as usize;

        // PID_SENTINEL -- end of parameter list
        if pid == PID_SENTINEL {
            return None;
        }

        // PID_STATUS_INFO (0x0071) -- 4 bytes
        //
        // The field is a 4-octet array per DDS-RTPS v2.5 sec. 9.6.4.9
        // (`typedef octet StatusInfo_t[4]`), with the
        // D / U / F flag bits in OCTET 3. Reading via
        // `from_be_bytes` puts octet 3 in the low byte of the u32,
        // so callers can treat the result as the flag bitmask
        // `0x01 = Disposed`, `0x02 = Unregistered`, `0x03 = both`.
        // This mapping is positional (octet array, not an integer field)
        // and is independent of the containing submessage's E flag.
        if pid == PID_STATUS_INFO && len >= 4 && offset + 4 + 4 <= inline_qos.len() {
            let value = u32::from_be_bytes([
                inline_qos[offset + 4],
                inline_qos[offset + 5],
                inline_qos[offset + 6],
                inline_qos[offset + 7],
            ]);
            // Byte-order leniency for the StatusInfo D/U flags. The spec
            // (octet[4], flags in octet 3) is positional, which `from_be_bytes`
            // places in the low byte. A sender that serializes StatusInfo as a
            // little-endian `long` instead puts the flags in octet 0 -> the
            // high byte of the `from_be` u32.
            // Fold those high-byte flag bits back into the low bits so all
            // callers (`status & 0x03`) detect the lifecycle change regardless
            // of the sender's convention. Conformant senders keep octets 0..2
            // zero, so this never invents a flag for them.
            let folded = value | ((value >> 24) & 0x03);
            return Some(folded);
        }

        // RTPS v2.5 sec. 9.4.2.11: ParameterList step = 4 (PID header) +
        // 4-aligned value length.
        let aligned_len = (len + 3) & !3;
        offset += 4 + aligned_len;
    }
}

/// Extract a `SequenceNumber_t` carried in a PID from inline QoS.
///
/// Wire format per RTPS v2.5 sec. 9.4.5.4.2: parameter value is `high i32`
/// followed by `low u32`, both encoded with the containing DATA submessage's
/// E flag (pass `is_le`). Returns the combined u64 `((high << 32) | low)`
/// if the PID is present, has length >= 8, AND carries a non-negative high
/// half. SEQUENCENUMBER_UNKNOWN (`{-1, 0}` per RTPS v2.5 sec. 9.3.2.4) maps to
/// `None`; without this guard `(high as i64) << 32 | low as i64` would
/// sign-extend `-1` into `0xFFFF_FFFF_0000_0000`, which neither matches a
/// legitimate writer SN nor SEQUENCENUMBER_UNKNOWN downstream.
fn extract_sequence_number_pid(inline_qos: &[u8], target_pid: u16, is_le: bool) -> Option<u64> {
    let mut offset = 0;
    loop {
        if offset + 4 > inline_qos.len() {
            return None;
        }

        let pid = read_u16(inline_qos, offset, is_le);
        let len = read_u16(inline_qos, offset + 2, is_le) as usize;

        if pid == PID_SENTINEL {
            return None;
        }

        if pid == target_pid && len >= 8 && offset + 4 + 8 <= inline_qos.len() {
            // RTPS v2.5 sec. 9.3.2.4: SequenceNumber high half is signed i32. read_u32 already
            // decoded endianness; reinterpret bits (same width) via to/from_ne_bytes.
            let high = i32::from_ne_bytes(read_u32(inline_qos, offset + 4, is_le).to_ne_bytes());
            let low = read_u32(inline_qos, offset + 8, is_le);
            // RTPS v2.5 sec. 9.3.2.4: a negative `high` half encodes the
            // sentinel SEQUENCENUMBER_UNKNOWN (`high == -1`, `low == 0`),
            // which has no meaningful u64 representation here.
            if high < 0 {
                return None;
            }
            return Some(((high as u64) << 32) | (low as u64));
        }

        // RTPS v2.5 sec. 9.4.2.11: ParameterList step = 4 (PID header) +
        // 4-aligned value length.
        let aligned_len = (len + 3) & !3;
        offset += 4 + aligned_len;
    }
}

/// Extract `PID_COHERENT_SET` (0x0056) from inline QoS as a u64
/// SequenceNumber_t per RTPS v2.5 sec. 8.7.5. `is_le` MUST match the
/// containing DATA submessage's E flag.
pub(crate) fn extract_coherent_set(inline_qos: &[u8], is_le: bool) -> Option<u64> {
    extract_sequence_number_pid(inline_qos, PID_COHERENT_SET, is_le)
}

/// Extract the GROUP-scope coherent-set GSN from inline QoS as a u64 per
/// RTPS v2.5 sec. 8.7.5. `is_le` MUST match the containing DATA submessage's
/// E flag.
///
/// Tries `PID_GROUP_COHERENT_SET_HDDS` (0x8030, HDDS vendor-specific)
/// FIRST: HDDS-self keys its own GROUP member DATA and ECS marker on this
/// PID instead of the standard OMG `PID_GROUP_COHERENT_SET` (0x0063),
/// because HDDS closes a group set with a bare no-QoS DATA and never emits
/// a vendor-specific group END marker, so a member tagged 0x0063 can leave
/// a GROUP-scope subscriber waiting for an end that never comes (see
/// `protocol::builder::helpers::append_pid_group_coherent_set`). Falls
/// back to the standard `0x0063` so GROUP-scope member DATA from a
/// spec-compliant publisher that DOES use it (any non-HDDS publisher, when
/// HDDS is the subscriber) is still
/// recognised correctly -- the two PIDs never collide on the same packet
/// since only HDDS emits 0x8030 and HDDS does not emit 0x0063.
pub(crate) fn extract_group_coherent_set(inline_qos: &[u8], is_le: bool) -> Option<u64> {
    extract_sequence_number_pid(inline_qos, PID_GROUP_COHERENT_SET_HDDS, is_le)
        .or_else(|| extract_sequence_number_pid(inline_qos, PID_GROUP_COHERENT_SET, is_le))
}

/// Extract `PID_END_COHERENT_SET` (0x8022) from inline QoS as a u64
/// SequenceNumber_t. Vendor-range PID interpreted under RTPS vendorId
/// 0x0101: we accept it as explicit coherent-set completion on a STANDALONE
/// End-of-Coherent-Set marker DATA submessage (D=0, K=0, Q=1, no payload)
/// and read its value as the set's START sequence number. `is_le` MUST
/// match the containing DATA submessage's E flag. The END is matched on the
/// dedicated marker only, never on the last D=1 data sample.
pub(crate) fn extract_end_coherent_set(inline_qos: &[u8], is_le: bool) -> Option<u64> {
    // Vendor-specific PID (high bit set); not part of the standard PID set
    // declared in protocol::discovery::constants.
    const PID_END_COHERENT_SET: u16 = 0x8022;
    extract_sequence_number_pid(inline_qos, PID_END_COHERENT_SET, is_le)
}

/// Extract `PID_END_GROUP_COHERENT_SET` (0x8023) from inline QoS as a u64
/// SequenceNumber_t. Vendor-range PID interpreted under RTPS vendorId
/// 0x0101, accepted alongside `PID_END_COHERENT_SET` (0x8022) on a
/// standalone End-of-Coherent-Set marker for a GROUP access_scope set; we
/// read its value as the publisher-wide group sample number of the set's
/// FIRST sample (the value the member DATA carried in
/// `PID_GROUP_COHERENT_SET` 0x0063). We accept a GROUP end marker that
/// carries neither 0x0056 nor 0x0063. `is_le` MUST match the
/// containing DATA submessage's E flag. Mirrors `extract_end_coherent_set`.
pub(crate) fn extract_end_group_coherent_set(inline_qos: &[u8], is_le: bool) -> Option<u64> {
    // Vendor-specific PID (high bit set); not part of the standard PID set
    // declared in protocol::discovery::constants.
    const PID_END_GROUP_COHERENT_SET: u16 = 0x8023;
    extract_sequence_number_pid(inline_qos, PID_END_GROUP_COHERENT_SET, is_le)
}

/// Extract `PID_END_COHERENT_SET_SAMPLE_COUNT` (0x8024) from inline QoS as
/// a u32: the number of samples in the coherent set that the explicit END
/// marker closes. Vendor-range PID interpreted under RTPS vendorId 0x0101,
/// accepted alongside `PID_END_COHERENT_SET` (0x8022). Used to defer the explicit-end commit
/// until the whole set is staged, so an END that overtakes some of its own
/// DATA on the wire (UDP delivery reorder) does not commit a partial set --
/// coherent_access is an all-or-nothing presentation contract (DDS v1.4
/// sec. 2.2.3.6). Returns `None` when the PID is absent (it may be omitted
/// under loss); callers then fall back to committing what is staged.
/// `is_le` MUST match the containing DATA submessage's E flag.
pub(crate) fn extract_end_coherent_set_count(inline_qos: &[u8], is_le: bool) -> Option<u32> {
    // Vendor-specific PID (high bit set); not part of the standard PID set
    // declared in protocol::discovery::constants.
    const PID_END_COHERENT_SET_SAMPLE_COUNT: u16 = 0x8024;
    let mut offset = 0;
    loop {
        if offset + 4 > inline_qos.len() {
            return None;
        }

        let pid = read_u16(inline_qos, offset, is_le);
        let len = read_u16(inline_qos, offset + 2, is_le) as usize;

        if pid == PID_SENTINEL {
            return None;
        }

        if pid == PID_END_COHERENT_SET_SAMPLE_COUNT
            && len >= 4
            && offset + 4 + 4 <= inline_qos.len()
        {
            return Some(read_u32(inline_qos, offset + 4, is_le));
        }

        // RTPS v2.5 sec. 9.4.2.11: ParameterList step = 4 (PID header) +
        // 4-aligned value length.
        let aligned_len = (len + 3) & !3;
        offset += 4 + aligned_len;
    }
}

/// Extract `PID_GROUP_ENTITY_ID` (0x0053) from inline QoS as the
/// 4-byte EntityId of the owning Publisher (writer side) or
/// Subscriber (reader side) per RTPS v2.5 sec. 9.3.2.1. Returned in
/// wire order `[entityKey0, entityKey1, entityKey2, entityKind]`.
///
/// `is_le` MUST match the containing DATA submessage's E flag (it gates
/// the PID/length header reads; the 4-byte EntityId value is an octet
/// array and is positional).
///
/// Used by the GROUP-scope coherent-set aggregation to bucket
/// per-Publisher GSNs (two Publishers in the same Participant can
/// legitimately reuse the same GSN, so the key MUST include the
/// publisher EntityId to avoid cross-publisher aliasing --
/// DDS v1.4 sec. 2.2.3.6 GROUP Presentation).
pub(crate) fn extract_group_entity_id(inline_qos: &[u8], is_le: bool) -> Option<[u8; 4]> {
    extract_four_octets_pid(inline_qos, PID_GROUP_ENTITY_ID, is_le)
}

/// Extract `PID_GROUP_SEQ_NUM` (0x0064) from inline QoS: the change's
/// group sequence number (RTPS v2.5 Sec.8.7.5, Sec.9.6.4.4). `is_le` MUST
/// match the containing DATA submessage's E flag.
pub(crate) fn extract_group_seq_num(inline_qos: &[u8], is_le: bool) -> Option<u64> {
    const PID_GROUP_SEQ_NUM: u16 = 0x0064;
    extract_sequence_number_pid(inline_qos, PID_GROUP_SEQ_NUM, is_le)
}

/// Extract `PID_WRITER_GROUP_INFO` (0x0065) from inline QoS: the
/// WriterGroupInfo_t of a GROUP change, its writerSet GroupDigest_t
/// (RTPS v2.5 Sec.9.6.4.5, Sec.9.3.2.5), four octets in wire order.
/// `is_le` MUST match the containing DATA submessage's E flag.
pub(crate) fn extract_writer_group_info(inline_qos: &[u8], is_le: bool) -> Option<[u8; 4]> {
    const PID_WRITER_GROUP_INFO: u16 = 0x0065;
    extract_four_octets_pid(inline_qos, PID_WRITER_GROUP_INFO, is_le)
}

/// The first four octets of the value of parameter `wanted` in inline QoS,
/// an octet array (positional, whatever the endianness that `is_le` gives
/// the PID and length headers).
fn extract_four_octets_pid(inline_qos: &[u8], wanted: u16, is_le: bool) -> Option<[u8; 4]> {
    let mut offset = 0;

    loop {
        if offset + 4 > inline_qos.len() {
            return None;
        }

        let pid = read_u16(inline_qos, offset, is_le);
        let len = read_u16(inline_qos, offset + 2, is_le) as usize;

        if pid == PID_SENTINEL {
            return None;
        }

        if pid == wanted && len >= 4 && offset + 4 + 4 <= inline_qos.len() {
            let mut buf = [0u8; 4];
            buf.copy_from_slice(&inline_qos[offset + 4..offset + 8]);
            return Some(buf);
        }

        // RTPS v2.5 sec. 9.4.2.11: ParameterList step = 4 (PID header) +
        // 4-aligned value length.
        let aligned_len = (len + 3) & !3;
        offset += 4 + aligned_len;
    }
}

/// Recognise an End-of-Coherent-Set (ECS) DATA submessage per RTPS v2.5
/// sec. 8.7.5. Returns `(coherent_sn, group_sn)` when the packet is:
///
/// * a DATA submessage with flags `D=0, K=0, Q=1` (no payload, inline QoS
///   only),
/// * carrying `PID_COHERENT_SET` (mandatory) and optionally
///   `PID_GROUP_COHERENT_SET`,
/// * NOT carrying `PID_STATUS_INFO` with dispose/unregister bits set
///   (which is the inline-QoS-only dispose form recognised by
///   `is_key_only_data`).
///
/// Returns `None` otherwise. The caller routes ECS markers through the
/// per-(writer, gsn) commit path; regular DATA / K-flag DATA / dispose
/// markers go through the normal pipeline.
pub fn extract_ecs_marker(rtps_packet: &[u8]) -> Option<(u64, Option<u64>)> {
    use super::helpers::{find_data_submsg_offset, validate_rtps_data_packet};

    if !validate_rtps_data_packet(rtps_packet, 24) {
        return None;
    }
    let data_off = find_data_submsg_offset(rtps_packet)?;
    let flags = rtps_packet[data_off + 1];
    let has_data = flags & 0x04 != 0;
    let has_key = flags & 0x08 != 0;
    let has_inline_qos = flags & 0x02 != 0;
    if has_data || has_key || !has_inline_qos {
        return None;
    }

    let (inline_qos, is_le) = extract_inline_qos(rtps_packet)?;

    // If this carries a dispose/unregister StatusInfo bit it is the
    // inline-QoS-only dispose form, not an ECS marker.
    if let Some(status) = extract_status_info(inline_qos, is_le) {
        if (status & 0x03) != 0 {
            return None;
        }
    }

    let coherent_sn = extract_coherent_set(inline_qos, is_le)?;
    let group_sn = extract_group_coherent_set(inline_qos, is_le);
    Some((coherent_sn, group_sn))
}

/// Recognise a standalone End-of-Coherent-Set marker DATA submessage in the
/// vendorId 0x0101 form: vendor-specific parameters 0x8022-0x8024 (vendor
/// 0x0101, parsed by the RTI dialect; RTPS does not define them).
/// Returns `(end_sn, end_count, group_sn)` when the packet is:
///
/// * a DATA submessage with flags `D=0, K=0, Q=1` (no payload, inline QoS
///   only),
/// * carrying `PID_END_COHERENT_SET` (0x8022, mandatory; value = the set's
///   START sequence number) and optionally `PID_GROUP_COHERENT_SET` or
///   `PID_END_GROUP_COHERENT_SET` (0x8023, the vendorId 0x0101 GROUP-scope form),
/// * NOT carrying `PID_COHERENT_SET` (0x0056) -- that is the HDDS-native ECS
///   marker matched by `extract_ecs_marker`,
/// * NOT carrying `PID_STATUS_INFO` with dispose/unregister bits set.
///
/// Returns `None` otherwise. This is implicitly vendor-scoped: 0x8022 on a
/// standalone marker is matched only in the vendorId 0x0101 form (HDDS uses
/// PID_COHERENT_SET, and the classic model closes a set implicitly with no marker),
/// so the caller commits the writer's buffered classic coherent set without an
/// explicit vendorId branch on the hot path. The 0x8024 sample-count PID that rides
/// alongside is extracted opportunistically (`end_count`) so the commit path can
/// detect an END that overtook some of its own DATA; it is deliberately not
/// required.
pub fn extract_end_coherent_marker(rtps_packet: &[u8]) -> Option<(u64, Option<u32>, Option<u64>)> {
    use super::helpers::{find_data_submsg_offset, validate_rtps_data_packet};

    if !validate_rtps_data_packet(rtps_packet, 24) {
        return None;
    }
    let data_off = find_data_submsg_offset(rtps_packet)?;
    let flags = rtps_packet[data_off + 1];
    let has_data = flags & 0x04 != 0;
    let has_key = flags & 0x08 != 0;
    let has_inline_qos = flags & 0x02 != 0;
    if has_data || has_key || !has_inline_qos {
        return None;
    }

    let (inline_qos, is_le) = extract_inline_qos(rtps_packet)?;

    // A dispose/unregister StatusInfo bit means the inline-QoS-only dispose
    // form, not a coherent-end marker.
    if let Some(status) = extract_status_info(inline_qos, is_le) {
        if (status & 0x03) != 0 {
            return None;
        }
    }

    // The HDDS-native ECS marker carries PID_COHERENT_SET; never treat it as
    // a vendorId 0x0101 END marker (keeps the self path on `extract_ecs_marker`).
    if extract_coherent_set(inline_qos, is_le).is_some() {
        return None;
    }

    let end_sn = extract_end_coherent_set(inline_qos, is_le)?;
    let end_count = extract_end_coherent_set_count(inline_qos, is_le);
    // GROUP-scope end markers identify their group set via
    // PID_END_GROUP_COHERENT_SET (0x8023); a GROUP end marker in the
    // vendorId 0x0101 form may carry ONLY that form (no 0x0063), so
    // fall back to it when the standard PID is absent. TOPIC/INSTANCE
    // end markers carry neither and keep `group_sn = None`.
    let group_sn = extract_group_coherent_set(inline_qos, is_le)
        .or_else(|| extract_end_group_coherent_set(inline_qos, is_le));
    Some((end_sn, end_count, group_sn))
}

/// Recognise the bare end of a GROUP set that carries no PID_COHERENT_SET:
/// Dust DDS (vendor 0x0114) sends one such DATA per writer, flags E|Q
/// (D=0, K=0, no payload), with PID_GROUP_COHERENT_SET (the set's first GSN),
/// PID_GROUP_SEQ_NUM and PID_WRITER_GROUP_INFO (16 octets, of which the first 4
/// are the writer set). Returns the set's first GSN when the packet is such a
/// DATA: no PID_COHERENT_SET (0x0056), no vendor end PID (0x8022), no
/// dispose/unregister StatusInfo, and both PIDs present. Which writers may
/// send it is decided at their discovery, not here (`TopicRegistry`).
pub(crate) fn extract_group_end_without_coherent_set(rtps_packet: &[u8]) -> Option<u64> {
    use super::helpers::{find_data_submsg_offset, validate_rtps_data_packet};

    if !validate_rtps_data_packet(rtps_packet, 24) {
        return None;
    }
    let data_off = find_data_submsg_offset(rtps_packet)?;
    let flags = rtps_packet[data_off + 1];
    let has_data = flags & 0x04 != 0;
    let has_key = flags & 0x08 != 0;
    let has_inline_qos = flags & 0x02 != 0;
    if has_data || has_key || !has_inline_qos {
        return None;
    }

    let (inline_qos, is_le) = extract_inline_qos(rtps_packet)?;
    if let Some(status) = extract_status_info(inline_qos, is_le) {
        if (status & 0x03) != 0 {
            return None;
        }
    }
    if extract_coherent_set(inline_qos, is_le).is_some()
        || extract_end_coherent_set(inline_qos, is_le).is_some()
    {
        return None;
    }
    let group_sn = extract_group_coherent_set(inline_qos, is_le)?;
    extract_writer_group_info(inline_qos, is_le)?;
    Some(group_sn)
}

/// Extract PID_KEY_HASH (0x0070) from inline QoS parameter list.
///
/// `is_le` MUST match the containing DATA submessage's E flag (it gates
/// the PID/length header reads; the 16-byte key hash value is positional).
///
/// Returns the 16-byte key hash if PID 0x0070 is found.
pub(crate) fn extract_key_hash(inline_qos: &[u8], is_le: bool) -> Option<[u8; 16]> {
    // Inline QoS has no CDR encapsulation header (see extract_status_info).
    let mut offset = 0;

    loop {
        if offset + 4 > inline_qos.len() {
            return None;
        }

        let pid = read_u16(inline_qos, offset, is_le);
        let len = read_u16(inline_qos, offset + 2, is_le) as usize;

        // PID_SENTINEL
        if pid == PID_SENTINEL {
            return None;
        }

        // PID_KEY_HASH (0x0070) -- 16 bytes
        if pid == PID_KEY_HASH && len >= 16 && offset + 4 + 16 <= inline_qos.len() {
            let mut key_hash = [0u8; 16];
            key_hash.copy_from_slice(&inline_qos[offset + 4..offset + 4 + 16]);
            return Some(key_hash);
        }

        // RTPS v2.5 sec. 9.4.2.11: ParameterList step = 4 (PID header) +
        // 4-aligned value length.
        let aligned_len = (len + 3) & !3;
        offset += 4 + aligned_len;
    }
}

/// Extract the serialized-key payload from a K-flag dispose/unregister DATA.
///
/// A writer may signal a per-instance dispose/unregister with a DATA
/// submessage carrying `K=1` (serialized key present, RTPS v2.5 8.3.8.2),
/// `PID_STATUS_INFO` in inline QoS, and **no `PID_KEY_HASH`**: the key hash
/// is a hint, and a reader that does not receive it computes the key from the
/// data itself (8.7.10); the instance key then lives in the serialized
/// payload, not in inline QoS. Discovery reads the endpoint or participant
/// GUID out of it.
///
/// Returns the serialized-key slice (CDR-encapsulated, starting with the
/// 4-byte encapsulation header) when the packet is exactly this form, else
/// `None`. The key-hash form and the inline-QoS-only form are handled
/// elsewhere and deliberately rejected here.
pub(crate) fn extract_serialized_key_at(rtps_packet: &[u8], data_off: usize) -> Option<&[u8]> {
    if data_off + 8 > rtps_packet.len() {
        return None;
    }
    let flags = rtps_packet[data_off + 1];

    // Must carry the K flag (serialized key present).
    if flags & 0x08 == 0 {
        return None;
    }

    // Must carry a dispose/unregister StatusInfo and NOT carry a key hash;
    // the key-hash form is already handled by the existing dispose branch.
    // THIS DATA's inline QoS: a datagram carries several DATA, and the first
    // one's says nothing about this one.
    let (inline_qos, is_le) = extract_inline_qos_at(rtps_packet, data_off)?;
    let status = extract_status_info(inline_qos, is_le)?;
    if (status & 0x03) == 0 {
        return None;
    }
    if extract_key_hash(inline_qos, is_le).is_some() {
        return None;
    }

    // The serialized key occupies the DATA payload region, right after the
    // inline QoS PID_SENTINEL, and ends with its submessage.
    let layout = data_submessage_layout(rtps_packet, data_off)?;
    if layout.payload >= layout.end {
        return None;
    }
    Some(&rtps_packet[layout.payload..layout.end])
}

/// The serialized key of the DATA submessage at `data_off`: its
/// serializedPayload, encapsulation header included, when its K flag is set
/// ("D=0 and K=1 means that the serializedPayload SubmessageElement contains
/// the serialized Key", RTPS v2.5 9.4.5.3), whatever its inline QoS carries.
///
/// [`extract_serialized_key_at`] returns the key only when no PID_KEY_HASH
/// is present, for the readers that have nothing else; this one serves the
/// reader that names the instance by the key first and by the PID_KEY_HASH,
/// a hint (8.7.10), only when it cannot read the key. `None` when K is clear,
/// the payload holds no key beyond its encapsulation header.
pub(crate) fn extract_key_payload_at(rtps_packet: &[u8], data_off: usize) -> Option<&[u8]> {
    let flags = *rtps_packet.get(data_off + 1)?;
    if flags & 0x08 == 0 {
        return None;
    }
    let layout = data_submessage_layout(rtps_packet, data_off)?;
    let key = rtps_packet.get(layout.payload..layout.end)?;
    if key.len() <= 4 {
        return None;
    }
    Some(key)
}

/// [`extract_key_payload_at`] of the first DATA submessage of `rtps_packet`.
pub(crate) fn extract_key_payload(rtps_packet: &[u8]) -> Option<&[u8]> {
    use super::helpers::{find_data_submsg_offset, validate_rtps_data_packet};

    if !validate_rtps_data_packet(rtps_packet, 24) {
        return None;
    }
    let data_off = find_data_submsg_offset(rtps_packet)?;
    extract_key_payload_at(rtps_packet, data_off)
}

/// Extract `PID_ENDPOINT_GUID` (0x005a, 16 bytes) from a PL_CDR serialized key.
///
/// A clean writer departure may be signalled with a SEDP DATA(w) dispose in the
/// K-flag (serialized key) form carrying NO inline `PID_KEY_HASH` (a hint,
/// RTPS v2.5 8.7.10); the disposed writer's GUID then lives in the serialized
/// key as `PID_ENDPOINT_GUID`. This walks that ParameterList (after its 4-byte
/// PL_CDR encapsulation header) and returns the 16-byte GUID. Used as the
/// writer-identity fallback when `PID_KEY_HASH` is absent.
pub(crate) fn extract_endpoint_guid_from_serialized_key(serialized_key: &[u8]) -> Option<[u8; 16]> {
    guid_parameter_of_serialized_key(serialized_key, 0x005a)
}

/// The participant GUID (PID_PARTICIPANT_GUID, 0x0050) in the serialized
/// key of a DCPSParticipant instance: the key-only payload (K flag) another
/// implementation sends with the dispose of its participant, in place of a
/// PID_KEY_HASH (RTPS v2.5 Sec.9.6.4.8).
pub(crate) fn extract_participant_guid_from_serialized_key(
    serialized_key: &[u8],
) -> Option<[u8; 16]> {
    guid_parameter_of_serialized_key(serialized_key, 0x0050)
}

/// The 16-octet GUID parameter `wanted_pid` of a PL_CDR serialized key.
fn guid_parameter_of_serialized_key(serialized_key: &[u8], wanted_pid: u16) -> Option<[u8; 16]> {
    const PID_SENTINEL: u16 = 0x0001;
    if serialized_key.len() < 4 {
        return None;
    }
    let kind = u16::from_be_bytes([serialized_key[0], serialized_key[1]]);
    let is_le = (kind & 0x01) == 1;
    let mut off = 4; // skip PL_CDR encapsulation header
    loop {
        if off + 4 > serialized_key.len() {
            return None;
        }
        let pid = read_u16(serialized_key, off, is_le);
        let len = read_u16(serialized_key, off + 2, is_le) as usize;
        if pid == PID_SENTINEL {
            return None;
        }
        if pid == wanted_pid && len >= 16 && off + 4 + 16 <= serialized_key.len() {
            let mut guid = [0u8; 16];
            guid.copy_from_slice(&serialized_key[off + 4..off + 4 + 16]);
            return Some(guid);
        }
        let aligned = (len + 3) & !3;
        off += 4 + aligned;
    }
}

#[cfg(test)]
mod tests {
    use super::{
        extract_coherent_set, extract_data_payload, extract_ecs_marker, extract_group_coherent_set,
        extract_group_entity_id, extract_inline_qos, extract_key_hash, extract_sequence_number,
        extract_status_info, extract_writer_guid,
    };
    use crate::protocol::constants::RTPS_SUBMSG_DATA;

    /// A key-only DATA (E|Q|K) with a dispose/unregister StatusInfo and no
    /// key hash, its serialized key a PL_CDR list holding `guid` under
    /// PID_PARTICIPANT_GUID.
    fn key_only_data(guid: [u8; 16]) -> Vec<u8> {
        let inline_qos = [
            0x71, 0x00, 0x04, 0x00, 0, 0, 0, 0x03, 0x01, 0x00, 0x00, 0x00,
        ];
        let mut key = vec![0x00, 0x03, 0x00, 0x00, 0x50, 0x00, 0x10, 0x00];
        key.extend_from_slice(&guid);
        key.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);
        let body = 20 + inline_qos.len() + key.len();
        let mut data = vec![0x15, 0x0b];
        data.extend_from_slice(&u16::try_from(body).expect("small").to_le_bytes());
        data.extend_from_slice(&[0x00, 0x00, 0x10, 0x00]);
        data.extend_from_slice(&[0x00, 0x01, 0x00, 0xc7, 0x00, 0x01, 0x00, 0xc2]);
        data.extend_from_slice(&[0, 0, 0, 0, 7, 0, 0, 0]);
        data.extend_from_slice(&inline_qos);
        data.extend_from_slice(&key);
        data
    }

    fn rtps_header() -> Vec<u8> {
        let mut header = b"RTPS".to_vec();
        header.extend_from_slice(&[0x02, 0x04, 0x01, 0x03]);
        header.extend_from_slice(&[0x42; 12]);
        header
    }

    /// A serialized key ends with its DATA submessage: a HEARTBEAT that
    /// follows it in the datagram is not part of the key (the key hash a
    /// router derives from it named the wrong instance).
    #[test]
    fn a_serialized_key_ends_with_its_submessage() {
        let guid = [0x42; 16];
        let mut packet = rtps_header();
        let data = key_only_data(guid);
        packet.extend_from_slice(&data);
        packet.extend_from_slice(&[0x07, 0x01, 0x1c, 0x00]);
        packet.extend_from_slice(&[0u8; 28]);
        let key = super::extract_serialized_key_at(&packet, 20).expect("a serialized key");
        assert_eq!(
            key,
            &data[data.len() - 28..],
            "the key, and nothing after it"
        );
        assert_eq!(
            super::extract_participant_guid_from_serialized_key(key),
            Some(guid)
        );
    }

    /// The serialized key of the SECOND DATA of a datagram is read from that
    /// DATA's own inline QoS, not from the first DATA's (here an
    /// announcement-like DATA without StatusInfo).
    #[test]
    fn a_serialized_key_is_read_against_its_own_data() {
        let guid = [0x43; 16];
        let mut packet = rtps_header();
        let mut first = vec![0x15, 0x05, 0x18, 0x00, 0x00, 0x00, 0x10, 0x00];
        first.extend_from_slice(&[0x00, 0x01, 0x00, 0xc7, 0x00, 0x01, 0x00, 0xc2]);
        first.extend_from_slice(&[0, 0, 0, 0, 6, 0, 0, 0]);
        first.extend_from_slice(&[0x00, 0x03, 0x00, 0x00]);
        packet.extend_from_slice(&first);
        let second_at = packet.len();
        packet.extend_from_slice(&key_only_data(guid));
        let key = super::extract_serialized_key_at(&packet, second_at).expect("the second key");
        assert_eq!(
            super::extract_participant_guid_from_serialized_key(key),
            Some(guid)
        );
    }

    /// A key-only DATA (E|Q|K) with StatusInfo, `key_hash` as PID_KEY_HASH
    /// when given, and `key` as its serializedPayload.
    fn key_only_data_with(key_hash: Option<[u8; 16]>, key: &[u8]) -> Vec<u8> {
        let mut inline_qos = vec![0x71, 0x00, 0x04, 0x00, 0, 0, 0, 0x01];
        if let Some(kh) = key_hash {
            inline_qos.extend_from_slice(&[0x70, 0x00, 0x10, 0x00]);
            inline_qos.extend_from_slice(&kh);
        }
        inline_qos.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);
        let body = 20 + inline_qos.len() + key.len();
        let mut packet = rtps_header();
        packet.extend_from_slice(&[0x15, 0x0b]);
        packet.extend_from_slice(&u16::try_from(body).expect("small").to_le_bytes());
        packet.extend_from_slice(&[0x00, 0x00, 0x10, 0x00]);
        packet.extend_from_slice(&[0x00, 0x00, 0x01, 0x07, 0x00, 0x00, 0x01, 0x02]);
        packet.extend_from_slice(&[0, 0, 0, 0, 7, 0, 0, 0]);
        packet.extend_from_slice(&inline_qos);
        packet.extend_from_slice(key);
        packet
    }

    /// The serialized key a typed reader names the instance by is the
    /// payload of the K=1 DATA, encapsulation header included, with or
    /// without a PID_KEY_HASH beside it (a hint, RTPS v2.5 8.7.10), where
    /// `extract_serialized_key` answers only without one.
    #[test]
    fn the_key_payload_is_read_whatever_the_inline_qos_carries() {
        let key = [0x00, 0x09, 0x00, 0x00, 7, 0, 0, 0];
        for kh in [None, Some([0x5a; 16])] {
            let packet = key_only_data_with(kh, &key);
            assert_eq!(
                super::extract_key_payload(&packet),
                Some(&key[..]),
                "{kh:?}"
            );
            assert_eq!(super::extract_key_payload_at(&packet, 20), Some(&key[..]));
        }
        let with_hash = key_only_data_with(Some([0x5a; 16]), &key);
        assert_eq!(super::extract_serialized_key_at(&with_hash, 20), None);
    }

    /// No key: the K flag clear, or the encapsulation header alone (what a
    /// 1.4.x writer of a generated type sends).
    #[test]
    fn a_header_alone_or_a_clear_k_flag_is_no_key_payload() {
        let packet = key_only_data_with(None, &[0x00, 0x09, 0x00, 0x00]);
        assert_eq!(super::extract_key_payload(&packet), None);
        let mut data_flag = key_only_data_with(None, &[0x00, 0x09, 0x00, 0x00, 7, 0, 0, 0]);
        data_flag[21] = 0x07;
        assert_eq!(super::extract_key_payload_at(&data_flag, 20), None);
    }

    /// RTPS v2.5 Sec.9.4.5.1.3: an octetsToNextHeader of 0 (a submessage that
    /// is not PAD nor INFO_TS) makes the submessage the last of the message,
    /// running to its end. A key-only DATA declared that way keeps its whole
    /// key; it is not cut to nothing at its header.
    #[test]
    fn a_serialized_key_of_a_last_submessage_of_length_zero_runs_to_the_end() {
        let guid = [0x44; 16];
        let mut data = key_only_data(guid);
        data[2..4].copy_from_slice(&[0x00, 0x00]);
        let mut packet = rtps_header();
        packet.extend_from_slice(&data);
        let key = super::extract_serialized_key_at(&packet, 20).expect("a serialized key");
        assert_eq!(key, &data[data.len() - 28..], "the whole key");
        assert_eq!(
            super::extract_participant_guid_from_serialized_key(key),
            Some(guid)
        );
    }

    /// Sec.9.4.5.1: octetsToNextHeader is read in the submessage's own byte
    /// order (its E flag). A big-endian key-only DATA (E=0, PL_CDR_BE key)
    /// followed by a HEARTBEAT keeps its key, and only its key: read
    /// little-endian, its length (0x003c) would become 0x3c00 and the key
    /// would run on through the HEARTBEAT.
    #[test]
    fn a_serialized_key_is_bounded_by_a_big_endian_submessage_length() {
        let guid = [0x45; 16];
        let mut data = vec![0x15, 0x0a, 0x00, 0x3c]; // DATA, Q|K, BE, 20 + 12 + 28
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x10]);
        data.extend_from_slice(&[0x00, 0x01, 0x00, 0xc7, 0x00, 0x01, 0x00, 0xc2]);
        data.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 7]);
        data.extend_from_slice(&[
            0x00, 0x71, 0x00, 0x04, 0, 0, 0, 0x03, 0x00, 0x01, 0x00, 0x00,
        ]);
        let key_at = data.len();
        data.extend_from_slice(&[0x00, 0x02, 0x00, 0x00, 0x00, 0x50, 0x00, 0x10]);
        data.extend_from_slice(&guid);
        data.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]);
        assert_eq!(
            data.len(),
            4 + 0x3c,
            "fixture: the declared length is the body"
        );
        let mut packet = rtps_header();
        packet.extend_from_slice(&data);
        packet.extend_from_slice(&[0x07, 0x00, 0x00, 0x1c]);
        packet.extend_from_slice(&[0x45; 28]);
        let key = super::extract_serialized_key_at(&packet, 20).expect("a serialized key");
        assert_eq!(key, &data[key_at..], "the key, and nothing after it");
        assert_eq!(
            super::extract_participant_guid_from_serialized_key(key),
            Some(guid)
        );
    }

    /// A DATA whose declared length cuts its serialized key yields no key,
    /// whatever octets follow it in the datagram: neither a participant GUID
    /// (a departure) nor a user-data key past the declared end. Read to the
    /// end of the datagram, both were completed from the octets past the
    /// submessage.
    #[test]
    fn a_serialized_key_cut_by_its_submessage_length_yields_no_key() {
        // A departure: the GUID parameter loses its last 8 octets.
        let mut departure = key_only_data([0x46; 16]);
        let body = u16::from_le_bytes([departure[2], departure[3]]) - 8;
        departure[2..4].copy_from_slice(&body.to_le_bytes());
        let mut packet = rtps_header();
        packet.extend_from_slice(&departure);
        let key = super::extract_serialized_key_at(&packet, 20).expect("what the DATA declares");
        assert_eq!(key.len(), 20, "fixture: the key ends 8 octets early");
        assert_eq!(
            super::extract_participant_guid_from_serialized_key(key),
            None
        );

        // A user-data dispose (writer 0x00000102): CDR_LE key "BLUE", its
        // last 4 octets ("E", NUL, padding) past the declared end.
        let mut dispose = vec![0x15, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00];
        dispose.extend_from_slice(&[0, 0, 0, 0, 0x00, 0x00, 0x01, 0x02]);
        dispose.extend_from_slice(&[0, 0, 0, 0, 3, 0, 0, 0]);
        dispose.extend_from_slice(&[0x71, 0x00, 0x04, 0x00, 0, 0, 0, 0x01, 0x01, 0, 0, 0]);
        dispose.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 5, 0, 0, 0]);
        dispose.extend_from_slice(b"BLUE\0\0\0\0");
        let whole = u16::try_from(dispose.len() - 4).expect("small");
        dispose[2..4].copy_from_slice(&(whole - 4).to_le_bytes());
        let mut packet = rtps_header();
        packet.extend_from_slice(&dispose);
        let key = super::extract_serialized_key_at(&packet, 20).expect("what the DATA declares");
        assert_eq!(
            key,
            &[0x00, 0x01, 0x00, 0x00, 5, 0, 0, 0, b'B', b'L', b'U', b'E']
        );
        assert_eq!(super::extract_key_payload(&packet), Some(key));
    }

    /// Build an RTPS packet with a DATA submessage for testing.
    ///
    /// Parameters control the flags, inline QoS region, and an optional
    /// payload suffix. This lets us construct both Q=0 and Q=1 scenarios,
    /// and simulate the CoreDDS case (Q=0, non-zero octetsToInlineQos).
    fn build_data_test_packet(
        flags: u8,
        octets_to_inline_qos: u16,
        inline_qos_payload: &[u8],
        data_payload: &[u8],
    ) -> Vec<u8> {
        // RTPS header (20 bytes)
        let mut packet = Vec::new();
        packet.extend_from_slice(b"RTPS");
        packet.extend_from_slice(&[2, 3, 0x01, 0x1a]); // version, vendor
        packet.extend_from_slice(&[0u8; 12]); // guidPrefix

        // DATA submessage header
        let extra_flags: u16 = 0;
        let reader_id: u32 = 0; // ENTITYID_UNKNOWN
        let writer_id: u32 = 0x0102; // user DataWriter
        let seq_num: u64 = 1;

        let header_size: usize = 24; // submsg_hdr + extraFlags + octetsToInlineQos + readerId + writerId + seqNum
        let inline_qos_size = inline_qos_payload.len();
        let total_data_size = header_size + inline_qos_size + data_payload.len();

        // octets_to_next = total submessage size after the 4-byte header
        let octets_to_next = (total_data_size - 4) as u16;

        packet.push(0x15); // submsgId = DATA
        packet.push(flags);
        packet.extend_from_slice(&octets_to_next.to_le_bytes());
        packet.extend_from_slice(&extra_flags.to_le_bytes());
        packet.extend_from_slice(&octets_to_inline_qos.to_le_bytes());
        packet.extend_from_slice(&reader_id.to_le_bytes());
        packet.extend_from_slice(&writer_id.to_le_bytes());
        packet.extend_from_slice(&seq_num.to_le_bytes());

        // Inline QoS region (may be empty for Q=0)
        packet.extend_from_slice(inline_qos_payload);

        // Serialized data payload
        packet.extend_from_slice(data_payload);

        packet
    }

    fn build_data_packet(prefix: [u8; 12], writer_entity_id: [u8; 4]) -> Vec<u8> {
        // Minimal RTPS DATA packet layout required by extract_writer_guid
        let mut packet = vec![0u8; 48];
        packet[0..4].copy_from_slice(b"RTPS");
        packet[4] = 2; // version major
        packet[5] = 3; // version minor
        packet[6] = 0x01; // vendor id (arbitrary)
        packet[7] = 0x1a;
        packet[8..20].copy_from_slice(&prefix);

        // DATA submessage header
        packet[20] = RTPS_SUBMSG_DATA;
        packet[21] = 0x05; // little-endian + inline QoS
        packet[22..24].copy_from_slice(&(24u16).to_le_bytes()); // octets_to_next

        // extraFlags + octetsToInlineQos + padding
        packet[24] = 0;
        packet[25] = 0x10; // inline QoS starts after writerSN (default 16)
        packet[26] = 0;
        packet[27] = 0;

        // readerEntityId (ENTITYID_UNKNOWN)
        packet[28..32].copy_from_slice(&[0, 0, 0, 0]);

        // writerEntityId under test
        packet[32..36].copy_from_slice(&writer_entity_id);

        // writerSN (SequenceNumber_t, little-endian for test)
        packet[36..44].copy_from_slice(&1u64.to_le_bytes());

        packet
    }

    #[test]
    fn extracts_user_writer_entity_id() {
        let prefix = [0xAA; 12];
        let writer_entity_id = [0x00, 0x00, 0x01, 0x02]; // user DataWriter (kind=0x02)
        let packet = build_data_packet(prefix, writer_entity_id);

        let guid = extract_writer_guid(&packet).expect("writer GUID should be parsed");
        assert_eq!(&guid[..12], &prefix);
        assert_eq!(&guid[12..], &writer_entity_id);
    }

    #[test]
    fn extracts_builtin_publications_writer_entity_id() {
        let prefix = [
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC,
        ];
        let writer_entity_id = [0x00, 0x01, 0x00, 0xC2]; // SEDPbuiltinPublicationsWriter
        let packet = build_data_packet(prefix, writer_entity_id);

        let guid = extract_writer_guid(&packet).expect("writer GUID should be parsed");
        assert_eq!(&guid[..12], &prefix);
        assert_eq!(&guid[12..], &writer_entity_id);
    }

    // --- extract_data_payload tests ---

    #[test]
    fn extract_payload_q0_returns_data_after_the_fixed_fields() {
        // Q=0, octetsToInlineQos=16 (readerId, writerId, writerSN): the
        // serializedPayload follows them (RTPS v2.5 Sec.9.4.5.4).
        let payload = b"serialized_data_here";
        let packet = build_data_test_packet(0x01, 16, &[], payload);
        let result = extract_data_payload(&packet);
        assert_eq!(result, Some(payload.as_slice()));
    }

    /// "Implementations ... should always use the octetsToInlineQos to skip
    /// any submessage header elements it does not expect" (RTPS v2.5
    /// Sec.9.4.5.4): a DATA from a later version, four octets of a field we
    /// do not know behind writerSN, octetsToInlineQos 20. With Q clear the
    /// payload is where the field points, not at the end of the fields we
    /// know; with Q set, the list is.
    #[test]
    fn the_payload_is_where_octets_to_inline_qos_points() {
        let future = [0xF0, 0xF1, 0xF2, 0xF3];
        let mut q0 = future.to_vec();
        q0.extend_from_slice(b"payload!");
        let packet = build_data_test_packet(0x05, 20, &q0, &[]);
        assert_eq!(
            extract_data_payload(&packet),
            Some(b"payload!".as_slice()),
            "Q=0"
        );
        let (_, offset, _, _) =
            crate::core::discovery::multicast::classifier::classify_rtps(&packet);
        assert_eq!(offset, Some(20 + 28), "the classifier's offset, Q=0");

        let mut q1 = future.to_vec();
        q1.extend_from_slice(&0x0070u16.to_le_bytes());
        q1.extend_from_slice(&16u16.to_le_bytes());
        q1.extend_from_slice(&[0xAB; 16]);
        q1.extend_from_slice(&0x0001u16.to_le_bytes());
        q1.extend_from_slice(&0u16.to_le_bytes());
        let packet = build_data_test_packet(0x07, 20, &q1, b"payload!");
        assert_eq!(
            extract_data_payload(&packet),
            Some(b"payload!".as_slice()),
            "Q=1"
        );
        let (qos, _) = extract_inline_qos(&packet).expect("the list");
        assert_eq!(
            &qos[..2],
            &0x0070u16.to_le_bytes(),
            "the list starts behind the field"
        );
    }

    /// octetsToInlineQos counts from the octet after itself to the inline
    /// QoS, or to what follows it when Q is clear (Sec.9.4.5.4); below 16 it
    /// points into readerId, writerId and writerSN. Such a DATA is invalid
    /// and ignored (Sec.8.3.4.1), Q set or not - with Q set and 0 it used
    /// to come back with its inline QoS as the payload.
    #[test]
    fn extract_payload_refuses_an_octets_to_inline_qos_inside_the_fixed_fields() {
        let mut qos = Vec::new();
        qos.extend_from_slice(&0x0070u16.to_le_bytes());
        qos.extend_from_slice(&16u16.to_le_bytes());
        qos.extend_from_slice(&[0xAB; 16]);
        qos.extend_from_slice(&0x0001u16.to_le_bytes());
        qos.extend_from_slice(&0u16.to_le_bytes());
        for otq in [0u16, 4, 12, 15] {
            let q0 = build_data_test_packet(0x05, otq, &[], b"payload!");
            assert_eq!(
                extract_data_payload(&q0),
                None,
                "Q=0, octetsToInlineQos={otq}"
            );
            let q1 = build_data_test_packet(0x07, otq, &qos, b"payload!");
            assert_eq!(
                extract_data_payload(&q1),
                None,
                "Q=1, octetsToInlineQos={otq}"
            );
            assert_eq!(
                extract_inline_qos(&q1),
                None,
                "Q=1, octetsToInlineQos={otq}"
            );
        }
        // The same DATA with 16 reads.
        let q1 = build_data_test_packet(0x07, 16, &qos, b"payload!");
        assert_eq!(extract_data_payload(&q1), Some(b"payload!".as_slice()));
    }

    /// PID_SENTINEL is 0x0001 (Sec.9.6.2.2, Table 9.13); 0x3F01..0x3F03
    /// (PID_EXTENDED, PID_LIST_END, PID_IGNORE: DDS-XTypes 1.3 Table 34, the
    /// encapsulation of a type's members) are no sentinel of a ParameterList
    /// of RTPS. A list ended by one of them
    /// only is unterminated: an invalid inlineQos, so an invalid DATA
    /// (Sec.8.3.8.2 Validity), ignored.
    #[test]
    fn only_pid_sentinel_ends_an_inline_qos() {
        for not_a_sentinel in [0x3F01u16, 0x3F02, 0x3F03] {
            let mut qos = Vec::new();
            qos.extend_from_slice(&0x0070u16.to_le_bytes());
            qos.extend_from_slice(&16u16.to_le_bytes());
            qos.extend_from_slice(&[0xAB; 16]);
            qos.extend_from_slice(&not_a_sentinel.to_le_bytes());
            qos.extend_from_slice(&0u16.to_le_bytes());
            let packet = build_data_test_packet(0x07, 16, &qos, b"payload!");
            assert_eq!(extract_data_payload(&packet), None, "{not_a_sentinel:#06x}");
            assert_eq!(extract_inline_qos(&packet), None, "{not_a_sentinel:#06x}");
        }
    }

    #[test]
    fn extract_payload_q0_with_octets_to_qos_16() {
        // Q=0 (flags=0x05: D=1, Q=0, E=1), octetsToInlineQos=16: the payload
        // is where the field points, right behind writerSN, and no list is
        // scanned (a PID scan here would read the payload as parameters).
        let payload = b"SHAPE_DATA";
        let packet = build_data_test_packet(0x05, 16, &[], payload);
        let result = extract_data_payload(&packet);
        assert_eq!(result, Some(payload.as_slice()));
    }

    #[test]
    fn extract_payload_q0_truncated_returns_none() {
        // Q=0, packet too short for 24-byte DATA header
        let mut packet = vec![0u8; 42]; // barely enough for header but not for payload
        packet[20] = 0x15; // DATA submsg id
        packet[21] = 0x01; // Q=0, LE
        packet[22..24].copy_from_slice(&4u16.to_le_bytes()); // octets_to_next
                                                             // packet is 42 bytes = RTPS header(20) + DATA hdr start but truncated
        assert!(extract_data_payload(&packet).is_none());
    }

    #[test]
    fn extract_payload_q1_scan_inline_qos() {
        // Q=1, inline QoS present: a ParameterList (RTPS v2.5 Sec.9.4.2.11),
        // parameters from its first octet, ended by PID_SENTINEL. No
        // encapsulation header precedes it (Sec.9.4.5.4).
        let inline_qos: Vec<u8> = {
            let mut qos = Vec::new();
            // PID_KEY_HASH (0x0070), len=16, followed by 16 bytes
            qos.extend_from_slice(&0x0070u16.to_le_bytes());
            qos.extend_from_slice(&16u16.to_le_bytes());
            qos.extend_from_slice(&[0xABu8; 16]);
            // PID_SENTINEL (0x0001), len=0
            qos.extend_from_slice(&0x0001u16.to_le_bytes());
            qos.extend_from_slice(&0u16.to_le_bytes());
            qos
        };
        let payload = b"data_after_inline_qos";
        // octetsToInlineQos=16 covers readerId(4)+writerId(4)+seqNum(8)
        // The inline QoS list starts at data_off+24
        let packet = build_data_test_packet(0x03, 16, &inline_qos, payload);
        // flags=0x03: Q=1, E=1 (no D=0, K=0, but that's fine for extraction)
        let result = extract_data_payload(&packet);
        assert_eq!(result, Some(payload.as_slice()));
    }

    #[test]
    fn extract_payload_q0_be_endianness() {
        // Q=0, big-endian (E flag = 0): octetsToInlineQos read big-endian.
        let payload = b"big_endian_data";
        let mut packet = build_data_test_packet(0x00, 16, &[], payload);
        packet[26..28].copy_from_slice(&16u16.to_be_bytes());
        let result = extract_data_payload(&packet);
        assert_eq!(result, Some(payload.as_slice()));
    }

    // --- E-flag tests for the inline-QoS helpers ---

    /// Build a minimal RTPS DATA packet with `flags` (E bit drives endianness)
    /// and the supplied 8-byte writerSN bytes, plus optional inline QoS bytes
    /// (placed right after the 24-byte header). No payload bytes are appended.
    fn build_data_packet_with_flags(
        flags: u8,
        writer_sn_bytes: [u8; 8],
        inline_qos: &[u8],
    ) -> Vec<u8> {
        let mut packet = Vec::new();
        packet.extend_from_slice(b"RTPS");
        packet.extend_from_slice(&[2, 3, 0x01, 0x1a]); // version + vendor
        packet.extend_from_slice(&[0u8; 12]); // guidPrefix

        // Submessage header (4 bytes): id, flags, octetsToNext
        let is_le = flags & 0x01 != 0;
        let header_body = 20usize + inline_qos.len(); // extraFlags(2) + octetsToInlineQos(2) + readerId(4) + writerId(4) + writerSN(8) + inline QoS
        let octets_to_next = header_body as u16;
        packet.push(0x15); // DATA submessage id
        packet.push(flags);
        if is_le {
            packet.extend_from_slice(&octets_to_next.to_le_bytes());
        } else {
            packet.extend_from_slice(&octets_to_next.to_be_bytes());
        }

        // extraFlags (2 bytes) + octetsToInlineQos (2 bytes)
        packet.extend_from_slice(&[0u8; 2]);
        let octets_to_inline_qos: u16 = 16; // readerId(4) + writerId(4) + writerSN(8)
        if is_le {
            packet.extend_from_slice(&octets_to_inline_qos.to_le_bytes());
        } else {
            packet.extend_from_slice(&octets_to_inline_qos.to_be_bytes());
        }

        // readerEntityId (4) + writerEntityId (4)
        packet.extend_from_slice(&[0u8; 4]);
        packet.extend_from_slice(&[0u8; 4]);

        // writerSN (8 bytes, caller-supplied in wire order)
        packet.extend_from_slice(&writer_sn_bytes);

        // Inline QoS region (already laid out by the caller in wire order)
        packet.extend_from_slice(inline_qos);

        packet
    }

    /// Encode a `SequenceNumber_t` (high i32 + low u32) in the requested
    /// endianness, returning 8 bytes in wire order.
    fn encode_sn_t(high: i32, low: u32, is_le: bool) -> [u8; 8] {
        let mut bytes = [0u8; 8];
        if is_le {
            bytes[..4].copy_from_slice(&high.to_le_bytes());
            bytes[4..].copy_from_slice(&low.to_le_bytes());
        } else {
            bytes[..4].copy_from_slice(&high.to_be_bytes());
            bytes[4..].copy_from_slice(&low.to_be_bytes());
        }
        bytes
    }

    /// Build a ParameterList in the requested endianness containing the
    /// supplied (pid, value) pairs followed by PID_SENTINEL.
    ///
    /// Per RTPS v2.5 sec. 9.4.2.11 parameterLength MUST be a multiple of 4 and
    /// the encoded value is zero-padded up to that length. This helper
    /// pads the value bytes and writes the aligned length on the wire; the
    /// extractors must therefore step by `4 + aligned_len` to find the
    /// next parameter (`build_inline_qos_non_aligned_value` exercises the
    /// pure-padding path with an odd value length).
    fn build_inline_qos(params: &[(u16, &[u8])], is_le: bool) -> Vec<u8> {
        let mut buf = Vec::new();
        for (pid, value) in params {
            let aligned_len = (value.len() + 3) & !3;
            if is_le {
                buf.extend_from_slice(&pid.to_le_bytes());
                buf.extend_from_slice(&(aligned_len as u16).to_le_bytes());
            } else {
                buf.extend_from_slice(&pid.to_be_bytes());
                buf.extend_from_slice(&(aligned_len as u16).to_be_bytes());
            }
            buf.extend_from_slice(value);
            buf.extend(std::iter::repeat_n(0u8, aligned_len - value.len()));
        }
        // PID_SENTINEL
        if is_le {
            buf.extend_from_slice(&0x0001u16.to_le_bytes());
            buf.extend_from_slice(&0u16.to_le_bytes());
        } else {
            buf.extend_from_slice(&0x0001u16.to_be_bytes());
            buf.extend_from_slice(&0u16.to_be_bytes());
        }
        buf
    }

    #[test]
    fn extract_sequence_number_be_data_submessage() {
        // BE DATA submessage (flags & 0x01 == 0): writerSN must be decoded
        // big-endian. Writing high=0x0000_0001, low=0x0000_002a should
        // yield the u64 (1 << 32) | 0x2a regardless of host order.
        let writer_sn = encode_sn_t(0x0000_0001, 0x0000_002a, false);
        let packet = build_data_packet_with_flags(0x00, writer_sn, &[]);
        let seq = extract_sequence_number(&packet).expect("BE SN should decode");
        assert_eq!(seq, (1u64 << 32) | 0x2a);
    }

    /// A datagram built for the test: [GAP, INFO_TS, DATA] in one RTPS
    /// message, all little-endian, from one writer. RTPS 2.5 8.3.3 lets a
    /// message carry several submessages and nothing makes the DATA the first
    /// of them; a sender that closes a gap and sends the next change in the
    /// same message puts the GAP first. The rule exercised: the DATA is found
    /// by walking past every submessage that is not one, so its writerSN and
    /// writer GUID come from the DATA and not from the bytes at the fixed
    /// offset of a first submessage (where the GAP's readerId, writerId and
    /// gapStart sit instead).
    fn gap_info_ts_data_datagram(prefix: [u8; 12], writer: [u8; 4], sn: u32) -> Vec<u8> {
        let mut p = Vec::new();
        // Header (8.3.3.1, 9.4.4): "RTPS", version 2.5, the HDDS vendor id
        // (nothing here branches on it), the sender's GUID prefix.
        p.extend_from_slice(b"RTPS");
        p.extend_from_slice(&[0x02, 0x05]);
        p.extend_from_slice(&crate::protocol::constants::HDDS_VENDOR_ID);
        p.extend_from_slice(&prefix);

        // GAP (8.3.8.4, 9.4.5.6): id 0x08, flags E, 28 octets of body:
        // readerId, writerId, gapStart, gapList (bitmapBase + numBits 0).
        // It declares the two SNs before `sn` irrelevant.
        p.extend_from_slice(&[0x08, 0x01]);
        p.extend_from_slice(&28u16.to_le_bytes());
        p.extend_from_slice(&[0, 0, 0, 0]); // readerId: ENTITYID_UNKNOWN
        p.extend_from_slice(&writer); // writerId
        p.extend_from_slice(&0u32.to_le_bytes()); // gapStart high
        p.extend_from_slice(&(sn - 2).to_le_bytes()); // gapStart low
        p.extend_from_slice(&0u32.to_le_bytes()); // gapList.bitmapBase high
        p.extend_from_slice(&sn.to_le_bytes()); // gapList.bitmapBase low
        p.extend_from_slice(&0u32.to_le_bytes()); // gapList.numBits

        // INFO_TS (8.3.8.11, 9.4.5.12): id 0x09, flags E, Time_t.
        p.extend_from_slice(&[0x09, 0x01]);
        p.extend_from_slice(&8u16.to_le_bytes());
        p.extend_from_slice(&0x6100_0000u32.to_le_bytes()); // seconds
        p.extend_from_slice(&0x4000_0000u32.to_le_bytes()); // fraction

        // DATA (8.3.8.2, 9.4.5.4): id 0x15, flags E|D, octetsToNextHeader 0
        // (last submessage, 9.4.5.1.3), no inline QoS.
        p.extend_from_slice(&[0x15, 0x01 | 0x04]);
        p.extend_from_slice(&0u16.to_le_bytes());
        p.extend_from_slice(&0u16.to_le_bytes()); // extraFlags
        p.extend_from_slice(&16u16.to_le_bytes()); // octetsToInlineQos
        p.extend_from_slice(&[0, 0, 0, 0]); // readerId: ENTITYID_UNKNOWN
        p.extend_from_slice(&writer); // writerId
        p.extend_from_slice(&0u32.to_le_bytes()); // writerSN high
        p.extend_from_slice(&sn.to_le_bytes()); // writerSN low

        // serializedPayload: CDR2_LE {0x00, 0x07}, options 0 (DDS-XTypes
        // 1.3 7.6.3.1.2), then a FINAL struct of two `long`s chosen for the
        // test.
        p.extend_from_slice(&[0x00, 0x07, 0x00, 0x00]);
        p.extend_from_slice(&7i32.to_le_bytes());
        p.extend_from_slice(&(-7i32).to_le_bytes());

        assert_eq!(p[20], 0x08, "the first submessage is the GAP");
        assert_eq!(p[52], 0x09, "INFO_TS follows the GAP");
        assert_eq!(p[64], 0x15, "the DATA comes after GAP and INFO_TS");
        p
    }

    #[test]
    fn extract_sequence_number_gap_data_compound() {
        // The writer GUID's prefix and entity, and the SN, chosen for the
        // test. Entity: key 0x000044, kind 0x03 (user writer without key,
        // RTPS 2.5 9.3.1.2).
        let prefix = [
            0x67, 0x61, 0x70, 0x2b, 0x64, 0x61, 0x74, 0x61, 0x00, 0x00, 0x00, 0x0c,
        ];
        let writer = [0x00, 0x00, 0x44, 0x03];
        let sn = 91;
        let pkt = gap_info_ts_data_datagram(prefix, writer, sn);

        let seq = extract_sequence_number(&pkt).expect("DATA behind GAP must decode");
        assert_eq!(seq, u64::from(sn));
        let guid = extract_writer_guid(&pkt).expect("writer GUID must decode");
        assert_eq!(&guid[..12], &prefix);
        assert_eq!(&guid[12..16], &writer);
    }

    #[test]
    fn extract_status_info_be_inline_qos() {
        // BE DATA submessage carrying PID_STATUS_INFO=0x03 (Disposed+Unregistered).
        // The PID/length headers MUST be read as BE; the 4-octet value is
        // positional so its bytes are `[0x00, 0x00, 0x00, 0x03]` regardless.
        let status_value = [0x00u8, 0x00, 0x00, 0x03];
        let inline_qos = build_inline_qos(&[(0x0071, &status_value)], false);
        let status =
            extract_status_info(&inline_qos, false).expect("BE PID header should be decoded");
        assert_eq!(status & 0x03, 0x03);
    }

    #[test]
    fn extract_inline_qos_helpers_le_be_roundtrip() {
        // Exercise all 4 plumbed helpers in both endiannesses. The same
        // logical payload (status=0x02, key_hash=[0xAA; 16],
        // group_entity_id=[1, 2, 3, 0xC1], coherent_sn high=0x0000_0007 low=
        // 0x0000_0008) must decode identically through both LE and BE
        // inline QoS lists.
        let status_value = [0x00u8, 0x00, 0x00, 0x02]; // octet array, positional
        let key_hash = [0xAAu8; 16];
        let entity_id = [0x01u8, 0x02, 0x03, 0xC1];

        for is_le in [true, false] {
            let sn_value = encode_sn_t(0x0000_0007, 0x0000_0008, is_le);
            let inline_qos = build_inline_qos(
                &[
                    (0x0071, &status_value),
                    (0x0070, &key_hash),
                    (0x0053, &entity_id),
                    (0x0056, &sn_value),
                ],
                is_le,
            );

            let status =
                extract_status_info(&inline_qos, is_le).expect("status_info decode should succeed");
            assert_eq!(status & 0x03, 0x02);

            let kh = extract_key_hash(&inline_qos, is_le).expect("key_hash decode should succeed");
            assert_eq!(kh, key_hash);

            let eid = extract_group_entity_id(&inline_qos, is_le)
                .expect("group_entity_id decode should succeed");
            assert_eq!(eid, entity_id);

            let sn = extract_coherent_set(&inline_qos, is_le)
                .expect("coherent_set decode should succeed");
            assert_eq!(sn, (7u64 << 32) | 8);
        }
    }

    // --- Additional tests: padding edges, sentinel, OOO/unknown, BE pipeline ---

    /// Build a ParameterList byte sequence where one PID has a value whose
    /// length is NOT a multiple of 4. The wire `parameterLength` field is
    /// still 4-aligned per RTPS v2.5 sec. 9.4.2.11; this exercises the padding
    /// step that the extractor must apply to find the next parameter.
    fn build_inline_qos_with_padded_value(
        pid_short: u16,
        short_value: &[u8],
        pid_next: u16,
        next_value: &[u8],
        is_le: bool,
    ) -> Vec<u8> {
        let mut buf = Vec::new();
        let aligned_short = (short_value.len() + 3) & !3;
        if is_le {
            buf.extend_from_slice(&pid_short.to_le_bytes());
            buf.extend_from_slice(&(aligned_short as u16).to_le_bytes());
        } else {
            buf.extend_from_slice(&pid_short.to_be_bytes());
            buf.extend_from_slice(&(aligned_short as u16).to_be_bytes());
        }
        buf.extend_from_slice(short_value);
        buf.extend(std::iter::repeat_n(0u8, aligned_short - short_value.len()));

        let aligned_next = (next_value.len() + 3) & !3;
        if is_le {
            buf.extend_from_slice(&pid_next.to_le_bytes());
            buf.extend_from_slice(&(aligned_next as u16).to_le_bytes());
        } else {
            buf.extend_from_slice(&pid_next.to_be_bytes());
            buf.extend_from_slice(&(aligned_next as u16).to_be_bytes());
        }
        buf.extend_from_slice(next_value);
        buf.extend(std::iter::repeat_n(0u8, aligned_next - next_value.len()));

        // PID_SENTINEL
        if is_le {
            buf.extend_from_slice(&0x0001u16.to_le_bytes());
            buf.extend_from_slice(&0u16.to_le_bytes());
        } else {
            buf.extend_from_slice(&0x0001u16.to_be_bytes());
            buf.extend_from_slice(&0u16.to_be_bytes());
        }
        buf
    }

    #[test]
    fn extract_status_info_skips_unknown_pid_then_finds_target() {
        // Unknown PID with a short (1-byte) value padded to 4 bytes, then
        // PID_STATUS_INFO. The extractor must apply 4-byte padding after the
        // unknown PID to land on the next parameter header.
        let short = [0xAAu8]; // 1 byte, padded to 4 on the wire
        let status_value = [0x00u8, 0x00, 0x00, 0x01];
        for is_le in [true, false] {
            let qos = build_inline_qos_with_padded_value(
                0x4000, // arbitrary unknown PID, ignored by the helper
                &short,
                0x0071, // PID_STATUS_INFO
                &status_value,
                is_le,
            );
            let status = extract_status_info(&qos, is_le)
                .expect("status_info should be found after padded unknown PID");
            assert_eq!(status & 0x03, 0x01);
        }
    }

    #[test]
    fn extract_status_info_zero_length_unknown_pid_is_safe() {
        // PID with length=0 (empty value) must not desync the scanner. We
        // place an unknown PID with len=0 between PID_KEY_HASH and the
        // target PID_STATUS_INFO so the extractor steps by 4 (header only)
        // when the value is empty.
        let key_hash = [0xBBu8; 16];
        let status_value = [0x00u8, 0x00, 0x00, 0x02];
        for is_le in [true, false] {
            let mut qos = Vec::new();
            // PID_KEY_HASH (16-byte value, length already a multiple of 4)
            if is_le {
                qos.extend_from_slice(&0x0070u16.to_le_bytes());
                qos.extend_from_slice(&16u16.to_le_bytes());
            } else {
                qos.extend_from_slice(&0x0070u16.to_be_bytes());
                qos.extend_from_slice(&16u16.to_be_bytes());
            }
            qos.extend_from_slice(&key_hash);
            // Unknown PID with length=0
            if is_le {
                qos.extend_from_slice(&0x4001u16.to_le_bytes());
                qos.extend_from_slice(&0u16.to_le_bytes());
            } else {
                qos.extend_from_slice(&0x4001u16.to_be_bytes());
                qos.extend_from_slice(&0u16.to_be_bytes());
            }
            // PID_STATUS_INFO
            if is_le {
                qos.extend_from_slice(&0x0071u16.to_le_bytes());
                qos.extend_from_slice(&4u16.to_le_bytes());
            } else {
                qos.extend_from_slice(&0x0071u16.to_be_bytes());
                qos.extend_from_slice(&4u16.to_be_bytes());
            }
            qos.extend_from_slice(&status_value);
            // PID_SENTINEL
            if is_le {
                qos.extend_from_slice(&0x0001u16.to_le_bytes());
                qos.extend_from_slice(&0u16.to_le_bytes());
            } else {
                qos.extend_from_slice(&0x0001u16.to_be_bytes());
                qos.extend_from_slice(&0u16.to_be_bytes());
            }
            let status = extract_status_info(&qos, is_le)
                .expect("status_info should be found after zero-length unknown PID");
            assert_eq!(status & 0x03, 0x02);
        }
    }

    #[test]
    fn extract_status_info_truncated_without_sentinel_returns_none() {
        // ParameterList truncated mid-stream (no PID_SENTINEL, no further
        // bytes for the next PID header). The scanner must terminate
        // gracefully instead of running off the end.
        let key_hash = [0xCCu8; 16];
        for is_le in [true, false] {
            let mut qos = Vec::new();
            if is_le {
                qos.extend_from_slice(&0x0070u16.to_le_bytes());
                qos.extend_from_slice(&16u16.to_le_bytes());
            } else {
                qos.extend_from_slice(&0x0070u16.to_be_bytes());
                qos.extend_from_slice(&16u16.to_be_bytes());
            }
            qos.extend_from_slice(&key_hash);
            // No PID_SENTINEL, no further PIDs -> extractor must give up.
            assert!(
                extract_status_info(&qos, is_le).is_none(),
                "truncated list without PID_STATUS_INFO must yield None"
            );
        }
    }

    #[test]
    fn extract_status_info_pids_out_of_order_be() {
        // PIDs appearing in a non-canonical order: PID_GROUP_ENTITY_ID first,
        // PID_STATUS_INFO between PID_KEY_HASH and PID_COHERENT_SET, all in
        // big-endian wire form. PID ordering is unconstrained per the spec;
        // the scanner must find each by inspection not position.
        let entity_id = [0x01u8, 0x02, 0x03, 0xC1];
        let key_hash = [0xDDu8; 16];
        let status_value = [0x00u8, 0x00, 0x00, 0x03];
        let sn_value = encode_sn_t(0x0000_0009, 0x0000_000A, false);

        let inline_qos = build_inline_qos(
            &[
                (0x0053, &entity_id),    // PID_GROUP_ENTITY_ID
                (0x4000, &[0x55, 0x66]), // unknown PID with short padded value
                (0x0070, &key_hash),     // PID_KEY_HASH
                (0x0071, &status_value), // PID_STATUS_INFO
                (0x0056, &sn_value),     // PID_COHERENT_SET
            ],
            false,
        );

        assert_eq!(
            extract_status_info(&inline_qos, false).map(|v| v & 0x03),
            Some(0x03),
        );
        assert_eq!(extract_key_hash(&inline_qos, false), Some(key_hash));
        assert_eq!(extract_group_entity_id(&inline_qos, false), Some(entity_id));
        assert_eq!(
            extract_coherent_set(&inline_qos, false),
            Some((9u64 << 32) | 0xA),
        );
    }

    #[test]
    fn extract_inline_qos_e2e_be_pipeline() {
        // End-to-end big-endian DATA submessage: build a full RTPS packet
        // with E=0 + Q=1 inline QoS carrying PID_STATUS_INFO + PID_KEY_HASH,
        // pass it through `extract_inline_qos` to obtain the (slice, is_le)
        // pair, then route both helpers through the same flag. This is the
        // exact flow `engine/router.rs` and `sedp_handler.rs` rely on.
        let status_value = [0x00u8, 0x00, 0x00, 0x02];
        let key_hash = [0xEEu8; 16];
        let inline_qos = build_inline_qos(&[(0x0071, &status_value), (0x0070, &key_hash)], false);

        // flags = 0x02 (Q=1, E=0); writer SN encoded BE; inline QoS embedded.
        let writer_sn = encode_sn_t(0x0000_0000, 0x0000_002a, false);
        let packet = build_data_packet_with_flags(0x02, writer_sn, &inline_qos);

        let (qos_slice, is_le) =
            extract_inline_qos(&packet).expect("e2e BE inline QoS must decode");
        assert!(!is_le, "BE flag must be propagated to caller");
        let status =
            extract_status_info(qos_slice, is_le).expect("status decode through extracted slice");
        assert_eq!(status & 0x03, 0x02);
        let kh =
            extract_key_hash(qos_slice, is_le).expect("key_hash decode through extracted slice");
        assert_eq!(kh, key_hash);
    }

    // --- S2 sign-extend test: SEQUENCENUMBER_UNKNOWN must yield None ---

    #[test]
    fn extract_coherent_set_rejects_sequence_number_unknown() {
        // RTPS v2.5 sec. 9.3.2.4: SEQUENCENUMBER_UNKNOWN = {high=-1, low=0}.
        // The previous `(high as i64) << 32 | low as i64` composition turned
        // this into `0xFFFF_FFFF_0000_0000` (a u64 sentinel that aliases a
        // legitimate seq for downstream consumers). The S2 fix returns
        // `None` whenever `high < 0`.
        for is_le in [true, false] {
            let sn_unknown = encode_sn_t(-1i32, 0u32, is_le);
            let qos = build_inline_qos(&[(0x0056, &sn_unknown)], is_le);
            assert_eq!(
                extract_coherent_set(&qos, is_le),
                None,
                "SEQUENCENUMBER_UNKNOWN must map to None (is_le={})",
                is_le,
            );
        }
    }

    #[test]
    fn extract_coherent_set_accepts_zero_high_zero_low() {
        // Boundary case: SequenceNumber_t {0, 0} is a legitimate composed
        // u64 zero per RTPS v2.5 sec. 9.3.2.4 (only `{-1, 0}` is the sentinel).
        for is_le in [true, false] {
            let sn_zero = encode_sn_t(0i32, 0u32, is_le);
            let qos = build_inline_qos(&[(0x0056, &sn_zero)], is_le);
            assert_eq!(extract_coherent_set(&qos, is_le), Some(0u64));
        }
    }

    // --- Multi-preamble test: INFO_DST + INFO_TS + DATA in extract pipeline ---

    #[test]
    fn extract_inline_qos_through_info_preamble() {
        // Cross-check that `find_data_submsg_offset` correctly skips an
        // INFO_DST (0x0e) submessage preceding DATA so callers see the
        // inline QoS regardless of the wire preamble. Without this the
        // 7 callers in `engine/router.rs` would silently drop multicast
        // datagrams that lead with INFO_DST + DATA.
        let status_value = [0x00u8, 0x00, 0x00, 0x01];
        let inline_qos = build_inline_qos(&[(0x0071, &status_value)], true);
        let writer_sn = encode_sn_t(0x0000_0000, 0x0000_002a, true);

        // Build packet: RTPS header + INFO_DST + DATA(Q=1, E=1).
        let mut packet = Vec::new();
        packet.extend_from_slice(b"RTPS");
        packet.extend_from_slice(&[2, 3, 0x01, 0x1a]);
        packet.extend_from_slice(&[0u8; 12]);
        // INFO_DST submessage: id=0x0e, flags=0x01 (LE), octetsToNext=12,
        // body = 12-byte guidPrefix (zeroed for the test).
        packet.push(0x0e);
        packet.push(0x01);
        packet.extend_from_slice(&12u16.to_le_bytes());
        packet.extend_from_slice(&[0u8; 12]);

        // DATA submessage assembled inline (no RTPS header).
        let octets_to_next = (20 + inline_qos.len()) as u16;
        packet.push(0x15);
        packet.push(0x03); // Q=1, E=1
        packet.extend_from_slice(&octets_to_next.to_le_bytes());
        packet.extend_from_slice(&[0u8; 2]); // extraFlags
        packet.extend_from_slice(&16u16.to_le_bytes()); // octetsToInlineQos
        packet.extend_from_slice(&[0u8; 4]); // readerEntityId
        packet.extend_from_slice(&[0u8; 4]); // writerEntityId
        packet.extend_from_slice(&writer_sn);
        packet.extend_from_slice(&inline_qos);

        let (qos_slice, is_le) =
            extract_inline_qos(&packet).expect("INFO_DST preamble must be skipped");
        assert!(is_le, "DATA E flag must be honoured after preamble");
        assert_eq!(
            extract_status_info(qos_slice, is_le).map(|v| v & 0x03),
            Some(0x01),
        );
    }

    /// Collect every ParameterId that appears in a wire-format inline QoS
    /// ParameterList (LE), stopping at PID_SENTINEL. Local re-implementation
    /// of the PID/length walk the `extract_*` functions use internally, kept
    /// separate so the test does not rely on the very extraction logic it is
    /// verifying.
    fn collect_pids_le(inline_qos: &[u8]) -> Vec<u16> {
        let mut pids = Vec::new();
        let mut offset = 0usize;
        loop {
            if offset + 4 > inline_qos.len() {
                break;
            }
            let pid = u16::from_le_bytes([inline_qos[offset], inline_qos[offset + 1]]);
            let len = u16::from_le_bytes([inline_qos[offset + 2], inline_qos[offset + 3]]) as usize;
            if pid == 0x0001 {
                break; // PID_SENTINEL
            }
            pids.push(pid);
            offset += 4 + ((len + 3) & !3);
        }
        pids
    }

    /// Pins the HDDS-as-publisher GROUP access_scope contract: a
    /// GROUP-scope member DATA sample must carry the HDDS-private
    /// `PID_GROUP_COHERENT_SET_HDDS` (0x8030) and must NOT carry the
    /// standard OMG `PID_GROUP_COHERENT_SET` (0x0063). HDDS closes a set
    /// with a bare no-QoS DATA, never a vendor END marker, so a member
    /// tagged 0x0063 can leave a subscriber that implements the standard
    /// GROUP form waiting for a group end that HDDS never sends.
    #[test]
    fn group_member_data_carries_hdds_private_pid_not_standard_0x0063() {
        let coherent_sn: u64 = 5;
        let gsn: u64 = 42;
        let publisher_entity_id = [0x00, 0x00, 0x01, 0x08];

        let qos = crate::protocol::builder::helpers::build_inline_qos_with_topic_and_coherent(
            "GroupTopic",
            Some(coherent_sn),
            Some(gsn),
            Some(publisher_entity_id),
            None,
        );
        assert!(!qos.is_empty(), "inline QoS build must succeed");

        let pids = collect_pids_le(&qos);
        assert!(
            pids.contains(&0x8030),
            "member DATA must carry PID_GROUP_COHERENT_SET_HDDS (0x8030), got PIDs {pids:04x?}"
        );
        assert!(
            !pids.contains(&0x0063),
            "member DATA must NOT carry the standard PID_GROUP_COHERENT_SET (0x0063) \
             -- HDDS keeps its group-coherent marker in its own vendor PID, got PIDs {pids:04x?}"
        );

        // Reader-side round trip: the shared extractor (used by
        // `engine/router.rs` on every incoming DATA) must recover the same
        // GSN and coherent_sn the writer encoded.
        assert_eq!(extract_group_coherent_set(&qos, true), Some(gsn));
        assert_eq!(extract_coherent_set(&qos, true), Some(coherent_sn));
    }

    /// Round trip through the actual self-path recognition function
    /// (`extract_ecs_marker`, the one `engine/router.rs` calls to detect an
    /// HDDS-native End-of-Coherent-Set marker and flush the reader's
    /// per-(writer, gsn) `group_coherent_buffer` -- see
    /// `dds::reader::subscriber::stage_group_sample` /
    /// `close_group_set`). Builds the ECS marker inline QoS with the real
    /// production writer helper, wraps it in a full D=0 K=0 Q=1 DATA
    /// submessage, and asserts the marker is recognised with the same
    /// (coherent_sn, group_sn) pair carried entirely on the new private PID.
    #[test]
    fn group_ecs_marker_round_trips_through_bucket_extraction() {
        let coherent_sn: u64 = 5;
        let gsn: u64 = 42;
        let publisher_entity_id = [0x00, 0x00, 0x01, 0x08];

        let qos = crate::protocol::builder::helpers::build_inline_qos_for_ecs(
            "GroupTopic",
            coherent_sn,
            Some(gsn),
            Some(publisher_entity_id),
            3,
        );
        assert!(!qos.is_empty(), "ECS inline QoS build must succeed");
        assert!(
            !collect_pids_le(&qos).contains(&0x0063),
            "ECS marker must NOT carry the standard PID_GROUP_COHERENT_SET (0x0063)"
        );

        // D=0 K=0 Q=1, LE: flags = 0x03 (bit0 = LE, bit1 = InlineQoS).
        let writer_sn = encode_sn_t(0, 7, true);
        let packet = build_data_packet_with_flags(0x03, writer_sn, &qos);

        let (recovered_coherent_sn, recovered_group_sn) =
            extract_ecs_marker(&packet).expect("ECS marker must be recognised");
        assert_eq!(recovered_coherent_sn, coherent_sn);
        assert_eq!(recovered_group_sn, Some(gsn));
    }
}

/// An inline-QoS ParameterList is read inside its own DATA submessage
/// (RTPS v2.5 Sec.9.4.5.1.3 bounds the submessage, Sec.9.4.2.11 requires
/// the PID_SENTINEL), never on into the submessage that follows it.
#[cfg(test)]
mod inline_qos_bounded_by_its_submessage_tests {
    use super::{
        extract_data_payload, extract_inline_qos, extract_inline_qos_at, extract_key_hash,
        extract_status_info, is_key_only_data,
    };
    use crate::core::discovery::multicast::classifier::walk;
    use crate::engine::demux::TopicRegistry;
    use crate::engine::{route_data_packet, DisposeKind, RouteStatus, RouterMetrics, Subscriber};
    use std::sync::{Arc, Mutex};

    const PREFIX: [u8; 12] = [0x42; 12];
    const WRITER_ENTITY: [u8; 4] = [0x00, 0x00, 0x01, 0x02];
    const SEQ: u32 = 11;
    const FOREIGN_KEY: [u8; 16] = [0xC3; 16];

    fn u16_bytes(value: u16, le: bool) -> [u8; 2] {
        if le {
            value.to_le_bytes()
        } else {
            value.to_be_bytes()
        }
    }

    fn rtps_header() -> Vec<u8> {
        let mut header = b"RTPS".to_vec();
        header.extend_from_slice(&[0x02, 0x05, 0x01, 0x03]);
        header.extend_from_slice(&PREFIX);
        header
    }

    /// One submessage declaring exactly `body` (a multiple of 4 octets).
    fn submessage(id: u8, flags: u8, body: &[u8]) -> Vec<u8> {
        assert_eq!(body.len() % 4, 0, "fixture: bodies are 4-octet aligned");
        let le = flags & 0x01 != 0;
        let mut out = vec![id, flags];
        out.extend_from_slice(&u16_bytes(u16::try_from(body.len()).expect("small"), le));
        out.extend_from_slice(body);
        out
    }

    fn parameter(pid: u16, value: &[u8], le: bool) -> Vec<u8> {
        let mut out = u16_bytes(pid, le).to_vec();
        out.extend_from_slice(&u16_bytes(u16::try_from(value.len()).expect("small"), le));
        out.extend_from_slice(value);
        out
    }

    /// The fixed DATA fields (extraFlags .. writerSN, 20 octets) followed by
    /// `rest` (inline QoS, then any payload).
    fn data_body(seq_low: u32, rest: &[u8], le: bool) -> Vec<u8> {
        let mut body = vec![0x00, 0x00];
        body.extend_from_slice(&u16_bytes(16, le)); // octetsToInlineQos
        body.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // readerId UNKNOWN
        body.extend_from_slice(&WRITER_ENTITY);
        if le {
            body.extend_from_slice(&0i32.to_le_bytes());
            body.extend_from_slice(&seq_low.to_le_bytes());
        } else {
            body.extend_from_slice(&0i32.to_be_bytes());
            body.extend_from_slice(&seq_low.to_be_bytes());
        }
        body.extend_from_slice(rest);
        body
    }

    /// StatusInfo DISPOSED (flags in octet 3, Sec.9.6.4.9), a key hash and
    /// the sentinel: what a dispose's inline QoS carries.
    fn dispose_parameters(key: [u8; 16], le: bool) -> Vec<u8> {
        let mut list = parameter(0x0071, &[0, 0, 0, 0x01], le);
        list.extend_from_slice(&parameter(0x0070, &key, le));
        list.extend_from_slice(&parameter(0x0001, &[], le));
        list
    }

    /// A datagram whose first DATA (D=0, K=0, Q=1, writerSN 11) carries an
    /// inline QoS with NO sentinel: its one parameter declares 8 octets and
    /// the submessage ends 4 octets into it. A PAD follows whose body, read
    /// as a continuation of that list, is StatusInfo DISPOSED + KeyHash
    /// 0xC3.. + sentinel. Returns the datagram and the PAD body's offset.
    fn unterminated_data_then_pad(le: bool) -> (Vec<u8>, usize) {
        let e = u8::from(le);
        let mut overrun = u16_bytes(0x8000, le).to_vec();
        overrun.extend_from_slice(&u16_bytes(8, le));
        overrun.extend_from_slice(&[0xEE; 4]);
        let mut packet = rtps_header();
        packet.extend_from_slice(&submessage(0x15, 0x02 | e, &data_body(SEQ, &overrun, le)));
        let pad_body_at = packet.len() + 4;
        packet.extend_from_slice(&submessage(0x01, e, &dispose_parameters(FOREIGN_KEY, le)));

        // Fixture invariants: the walk sees DATA then PAD, each ending where
        // it declares, and the PAD body does read as a dispose.
        let mut chain = Vec::new();
        walk::for_each_submessage(&packet, |found| {
            chain.push((found.offset, found.id, found.body_end));
            walk::Step::Continue
        });
        assert_eq!(
            chain,
            vec![
                (20, 0x15, pad_body_at - 4),
                (pad_body_at - 4, 0x01, packet.len())
            ],
            "fixture: a DATA then a PAD, each bounded by its declared length"
        );
        let pad_body = &packet[pad_body_at..];
        assert_eq!(extract_status_info(pad_body, le), Some(0x01));
        assert_eq!(extract_key_hash(pad_body, le), Some(FOREIGN_KEY));
        (packet, pad_body_at)
    }

    #[test]
    fn an_unterminated_inline_qos_reads_nothing_from_the_next_submessage() {
        for le in [true, false] {
            let (packet, _) = unterminated_data_then_pad(le);
            assert_eq!(extract_inline_qos(&packet), None, "le={le}: no QoS");
            assert_eq!(extract_inline_qos_at(&packet, 20), None, "le={le}");
            assert!(!is_key_only_data(&packet), "le={le}: not a dispose");
            assert_eq!(
                extract_data_payload(&packet),
                None,
                "le={le}: the PAD's sentinel does not end this DATA's list"
            );
        }
    }

    #[test]
    fn an_unterminated_inline_qos_followed_by_a_heartbeat_is_no_qos() {
        // A plain list, no overrun: the HEARTBEAT header must not be read as
        // one more parameter, returning the whole rest of the datagram.
        let mut packet = rtps_header();
        let list = parameter(0x8000, &[0xEE; 4], true);
        packet.extend_from_slice(&submessage(0x15, 0x03, &data_body(SEQ, &list, true)));
        packet.extend_from_slice(&submessage(0x07, 0x01, &[0x45; 28]));
        assert_eq!(extract_inline_qos(&packet), None);
    }

    #[derive(Debug, PartialEq)]
    enum Delivered {
        Data(u64, Vec<u8>),
        Dispose(u64, [u8; 16], DisposeKind),
    }

    struct Probe {
        delivered: Mutex<Vec<Delivered>>,
    }

    impl Subscriber for Probe {
        fn on_data(&self, _topic: &str, seq: u64, data: &[u8]) {
            self.delivered
                .lock()
                .expect("probe lock")
                .push(Delivered::Data(seq, data.to_vec()));
        }

        fn on_dispose(&self, _topic: &str, seq: u64, key_hash: [u8; 16], kind: DisposeKind) {
            self.delivered
                .lock()
                .expect("probe lock")
                .push(Delivered::Dispose(seq, key_hash, kind));
        }

        fn topic_name(&self) -> &str {
            "T"
        }
    }

    fn route(packet: &[u8]) -> Vec<Delivered> {
        route_at(packet, None)
    }

    fn route_at(packet: &[u8], payload_offset: Option<usize>) -> Vec<Delivered> {
        let registry = TopicRegistry::new();
        let probe = Arc::new(Probe {
            delivered: Mutex::new(Vec::new()),
        });
        registry
            .register_subscriber(probe.clone())
            .expect("register subscriber");
        let mut writer = [0u8; 16];
        writer[..12].copy_from_slice(&PREFIX);
        writer[12..].copy_from_slice(&WRITER_ENTITY);
        registry.register_writer_guid(writer, "T".to_string());
        let metrics = RouterMetrics::new();
        let _: RouteStatus =
            route_data_packet(packet, packet.len(), payload_offset, &registry, &metrics);
        let mut delivered = probe.delivered.lock().expect("probe lock");
        std::mem::take(&mut *delivered)
    }

    /// The router delivers a sample the same with or without the payload
    /// offset the classifier computes: the serialized data, behind its
    /// encapsulation header (RTPS v2.5 Sec.10.2, the SerializedPayload
    /// starts with it), never the header itself, on the no-offset path too.
    #[test]
    fn a_sample_is_delivered_the_same_with_or_without_the_classifiers_offset() {
        for le in [true, false] {
            let serialized = [0x00, 0x01, 0x00, 0x00, 0x2A, 0x00, 0x00, 0x00];
            let mut packet = rtps_header();
            packet.extend_from_slice(&submessage(
                0x15,
                0x04 | u8::from(le),
                &data_body(SEQ, &serialized, le),
            ));
            let (_, offset, _, _) =
                crate::core::discovery::multicast::classifier::classify_rtps(&packet);
            assert_eq!(
                offset,
                Some(44),
                "fixture: the classifier's offset, le={le}"
            );
            let expected = vec![Delivered::Data(
                u64::from(SEQ),
                vec![0x2A, 0x00, 0x00, 0x00],
            )];
            assert_eq!(
                route_at(&packet, offset),
                expected,
                "with the offset, le={le}"
            );
            assert_eq!(route_at(&packet, None), expected, "without it, le={le}");
        }
    }

    /// At the router door: the PAD's octets dispose nothing.
    #[test]
    fn the_router_disposes_nothing_from_the_next_submessage() {
        for le in [true, false] {
            let (packet, _) = unterminated_data_then_pad(le);
            assert_eq!(route(&packet), vec![], "le={le}: nothing is delivered");
        }
    }

    /// The control: the same dispose carried INSIDE the DATA is delivered,
    /// so the test above fails for the bound and not for the plumbing.
    #[test]
    fn the_router_delivers_a_dispose_inside_its_own_data() {
        for le in [true, false] {
            let e = u8::from(le);
            let mut packet = rtps_header();
            let body = data_body(SEQ, &dispose_parameters(FOREIGN_KEY, le), le);
            packet.extend_from_slice(&submessage(0x15, 0x02 | e, &body));
            packet.extend_from_slice(&submessage(0x07, e, &[0x45; 28]));
            assert_eq!(
                route(&packet),
                vec![Delivered::Dispose(
                    u64::from(SEQ),
                    FOREIGN_KEY,
                    DisposeKind::Disposed
                )],
                "le={le}"
            );
        }
    }

    /// Two well-formed DATA: each reads its own list, exactly.
    #[test]
    fn each_data_reads_its_own_inline_qos() {
        let first_qos = dispose_parameters([0xA1; 16], true);
        let second_qos = dispose_parameters([0xB2; 16], true);
        let mut packet = rtps_header();
        packet.extend_from_slice(&submessage(0x15, 0x03, &data_body(1, &first_qos, true)));
        let second_at = packet.len();
        packet.extend_from_slice(&submessage(0x15, 0x03, &data_body(2, &second_qos, true)));
        assert_eq!(
            extract_inline_qos_at(&packet, 20),
            Some((first_qos.as_slice(), true))
        );
        assert_eq!(
            extract_inline_qos_at(&packet, second_at),
            Some((second_qos.as_slice(), true))
        );
    }

    /// Sec.9.4.5.1.3: octetsToNextHeader 0 on a DATA makes it the last
    /// submessage, running to the end of the message: its list and its
    /// payload are all there.
    #[test]
    fn a_last_data_of_length_zero_runs_to_the_end_of_the_message() {
        let qos = dispose_parameters([0xA1; 16], true);
        let mut rest = qos.clone();
        rest.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 0xAB, 0xCD, 0xEF, 0x01]);
        let mut packet = rtps_header();
        let mut data = submessage(0x15, 0x07, &data_body(1, &rest, true));
        data[2..4].copy_from_slice(&[0x00, 0x00]);
        packet.extend_from_slice(&data);
        assert_eq!(extract_inline_qos(&packet), Some((qos.as_slice(), true)));
    }

    /// A sentinel whose last octet is the submessage's last octet ends the
    /// list; the next submessage is not needed and not read.
    #[test]
    fn a_sentinel_at_the_very_end_of_its_submessage_ends_the_list() {
        for le in [true, false] {
            let e = u8::from(le);
            let qos = dispose_parameters([0xA1; 16], le);
            let mut packet = rtps_header();
            packet.extend_from_slice(&submessage(0x15, 0x02 | e, &data_body(1, &qos, le)));
            let data_end = packet.len();
            packet.extend_from_slice(&submessage(0x07, e, &[0x45; 28]));
            let (list, got_le) = extract_inline_qos(&packet).expect("a terminated list");
            assert_eq!((list, got_le), (qos.as_slice(), le), "le={le}");
            assert!(
                packet[..data_end].ends_with(&parameter(0x0001, &[], le)),
                "fixture: the sentinel is the DATA's last four octets"
            );
        }
    }

    /// `extract_data_payload` looks for the sentinel ending THIS DATA's list,
    /// not one in a later submessage: the overrunning parameter is the
    /// list's first; a HEARTBEAT behind the PAD is what was returned as the
    /// payload.
    #[test]
    fn a_payload_does_not_start_behind_the_next_submessages_sentinel() {
        let mut list = Vec::new();
        list.extend_from_slice(&0x8000u16.to_le_bytes());
        list.extend_from_slice(&8u16.to_le_bytes());
        list.extend_from_slice(&[0xEE; 4]);
        let mut packet = rtps_header();
        packet.extend_from_slice(&submessage(0x15, 0x07, &data_body(SEQ, &list, true)));
        packet.extend_from_slice(&submessage(
            0x01,
            0x01,
            &dispose_parameters(FOREIGN_KEY, true),
        ));
        let heartbeat = submessage(0x07, 0x01, &[0x45; 28]);
        packet.extend_from_slice(&heartbeat);
        assert_eq!(extract_data_payload(&packet), None);
    }

    /// The serializedPayload of a DATA carrying inline QoS, laid out as
    /// DDSI-RTPS 2.5 9.4.5.4 draws it: extraFlags, octetsToInlineQos,
    /// readerId, writerId, writerSN, then the inlineQos ParameterList at
    /// "the first octet immediately following" octetsToInlineQos plus its
    /// value, then the serializedPayload. The ParameterList (9.4.2.11) is
    /// parameters from its first octet: no encapsulation header in front.
    /// A foreign dispose (Cyclone DDS 0x0110, `fis1` capture, frame 734) has
    /// exactly this shape: PID_STATUS_INFO at writerSN + 8. Written here by
    /// hand, not by our encoder.
    #[test]
    fn the_payload_follows_an_inline_qos_laid_out_as_the_spec_draws_it() {
        let serialized = [0x00, 0x01, 0x00, 0x00, 0x2A, 0x00, 0x00, 0x00];
        for le in [true, false] {
            let mut rest = parameter(0x0071, &[0, 0, 0, 0x01], le);
            rest.extend_from_slice(&parameter(0x0070, &FOREIGN_KEY, le));
            rest.extend_from_slice(&parameter(0x0001, &[], le));
            rest.extend_from_slice(&serialized);
            let mut packet = rtps_header();
            // K=1 Q=1 (a key-only DATA with its inline QoS).
            packet.extend_from_slice(&submessage(
                0x15,
                0x0A | u8::from(le),
                &data_body(SEQ, &rest, le),
            ));
            // Fixture invariant: the list starts 16 octets after
            // octetsToInlineQos, i.e. right behind writerSN.
            assert_eq!(&packet[44..46], &u16_bytes(0x0071, le), "le={le}");
            assert_eq!(
                extract_data_payload(&packet),
                Some(serialized.as_slice()),
                "le={le}: the payload is what follows the sentinel"
            );
        }
    }

    /// A DATA header that is the last four octets of the datagram has no
    /// octetsToInlineQos to read: no payload, and no out-of-bounds read.
    #[test]
    fn a_data_cut_after_its_header_has_no_payload() {
        let mut packet = rtps_header();
        packet.extend_from_slice(&submessage(0x09, 0x01, &[0; 8])); // INFO_TS
        packet.extend_from_slice(&[0x15, 0x03, 0x00, 0x00]);
        assert_eq!(extract_data_payload(&packet), None);
    }
}

/// Read a participant status change, keyed by its participant GUID
/// (DDSI-RTPS v2.5 Sec.8.5.3, Sec.9.6.4.8, Sec.9.6.4.9).
/// The caller supplies the plain or secure builtin participant writer.
#[cfg(feature = "security")]
pub(crate) fn extract_participant_dispose_at(
    packet: &[u8],
    at: usize,
    writer: [u8; 4],
) -> Option<crate::core::discovery::GUID> {
    let layout = data_submessage_layout(packet, at)?;
    if packet[at] != 0x15 || packet.get(at + 12..at + 16)? != writer {
        return None;
    }
    let flags = packet[at + 1];
    if flags & 0x02 == 0 || flags & 0x04 != 0 {
        return None;
    }
    let (qos, le) = extract_inline_qos_at(packet, at)?;
    if extract_status_info(qos, le)? & 3 == 0 {
        return None;
    }
    let key = extract_key_hash(qos, le).or_else(|| {
        extract_serialized_key_at(packet, at).and_then(extract_participant_guid_from_serialized_key)
    })?;
    let prefix: [u8; 12] = packet.get(8..20)?.try_into().ok()?;
    let guid = crate::core::discovery::GUID::new(
        prefix,
        crate::core::rtps_constants::RTPS_ENTITYID_PARTICIPANT,
    );
    // The key must identify the sender's participant, never an endpoint
    // or another participant. A valid DATA sequence number is positive.
    let sn_high = read_u32(packet, at + 16, layout.is_le);
    let sn_low = read_u32(packet, at + 20, layout.is_le);
    (key == guid.as_bytes() && sn_high & 0x8000_0000 == 0 && (sn_high != 0 || sn_low != 0))
        .then_some(guid)
}
