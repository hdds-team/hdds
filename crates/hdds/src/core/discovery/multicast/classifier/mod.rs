// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! RTPS Packet Classifier - Main orchestration module.
//!
//!
//! This module coordinates RTPS packet classification by:
//! 1. Validating RTPS header (via header module)
//! 2. Scanning submessages (via submessage module)
//! 3. Accumulating RTPS context (INFO_DST, INFO_TS)
//! 4. Returning classification tuple

mod header;
mod submessage;
pub(crate) mod walk;

use super::{FragmentMetadata, PacketKind, RtpsContext};

pub(crate) use header::is_rtps_magic;
pub(crate) use submessage::{scan_all_addressed_data_frags_with_qos, FragInlineQos};
pub use submessage::{scan_all_data_frags, ScannedFrag};

/// The DATA submessage id (RTPS v2.5 Table 8.13).
const DATA_SUBMESSAGE_ID: u8 = 0x15;

/// Octets a DATA submessage must declare before its own fields are believed.
///
/// A DATA's fixed fields are extraFlags, octetsToInlineQos, readerEntityId,
/// writerEntityId and writerSN (RTPS v2.5 Sec.8.3.8.2): twenty octets of body,
/// which is also where the payload offset `offset + 24` starts counting from.
/// A DATA declaring less than that cannot hold what the classifier then reads
/// out of it, and the offset it would be given lands past its own end.
///
/// A well-formed DATA can never declare 1 to 19 octets, because its fixed
/// fields alone take 20; the only length below 20 a conforming sender
/// writes is 0, the sentinel below. A lower threshold (16, say) would admit a
/// DATA whose writerSN is half missing, so the threshold refuses only
/// malformed submessages.
///
/// `octetsToNextHeader == 0` is the "last submessage" sentinel (Sec.8.3.3.3),
/// which says nothing about the length, so it is admitted and the datagram
/// itself is the bound. It is not a corner case - real captures hold many
/// DATA submessages that declare themselves this way.
const MIN_DATA_BODY_OCTETS: u16 = 20;

/// Classify RTPS packet by scanning all submessages.
///
/// RTPS packet structure (DDS-RTPS v2.3 Sec.8.3):
/// ```text
/// Offset  | Field              | Size | Value
/// --------|--------------------|------|--------
/// 0-3     | Protocol           | 4    | "RTPS" (0x52 0x54 0x50 0x53)
/// 4-5     | Version            | 2    | 2.3 (0x02 0x03)
/// 6-7     | Vendor ID          | 2    | varies (RTI=0x0101, HDDS=0x011a)
/// 8-19    | GUID prefix        | 12   | participant GUID prefix (12 bytes per RTPS v2.3!)
/// 20+     | Submessages...     | var  | Multiple submessages (Sec.8.3.3)
/// ```
///
/// Submessage structure (Sec.8.3.3):
/// ```text
/// Offset  | Field              | Size | Value (RTPS v2.3 Table 8.13)
/// --------|--------------------|------|--------
/// 0       | Submessage ID      | 1    | 0x15=DATA, 0x16=DATA_FRAG, 0x06=HB, 0x09=INFO_TS, ...
/// 1       | Flags              | 1    | bit 0 = endianness (E)
/// 2-3     | octetsToNextHeader | 2    | length to next submessage (0=last)
/// 4+      | Submessage content | var  | submessage-specific data
/// ```
///
/// # Spec Compliance
/// Per RTPS v2.5 Sec.8.3.3, a single RTPS message can contain multiple submessages.
/// This scanner iterates through ALL submessages to classify the packet correctly.
///
/// # Arguments
/// * `buf` - Raw packet buffer
///
/// # Returns
/// Tuple of `(PacketKind, Option<payload_offset>, Option<FragmentMetadata>, RtpsContext)` where:
/// - payload_offset is the byte offset to the DATA submessage payload (after 4-byte submessage header).
///   None for non-DATA packets or standard offset (20+4=24 for simple DATA submessage).
/// - FragmentMetadata is present for PacketKind::DataFrag packets
/// - RtpsContext contains accumulated INFO_DST/INFO_TS state from scanning
///
/// # Examples
/// ```
/// use hdds::core::discovery::multicast::{classify_rtps, PacketKind};
///
/// let mut pkt = vec![0u8; 48];
/// // RTPS header
/// pkt[0..4].copy_from_slice(b"RTPS");  // Protocol ID
/// pkt[4] = 0x02; pkt[5] = 0x04;       // Version 2.4
/// pkt[6] = 0x01; pkt[7] = 0x1a;       // Vendor ID (HDDS)
/// // GUID prefix at [8..20] left as zeros
/// // DATA submessage at offset 20
/// pkt[20] = 0x15;                      // DATA submessage ID
/// pkt[21] = 0x05;                      // Flags: little-endian, D (data)
/// pkt[22] = 24; pkt[23] = 0;          // octetsToNextHeader
/// pkt[26] = 16;                        // octetsToInlineQos
/// pkt[40] = 1;                         // writerSN = 1 (must be positive)
///
/// let (kind, _offset, _meta, _ctx) = classify_rtps(&pkt);
/// assert_eq!(kind, PacketKind::Data);
/// ```
pub fn classify_rtps(
    buf: &[u8],
) -> (
    PacketKind,
    Option<usize>,
    Option<FragmentMetadata>,
    RtpsContext,
) {
    crate::trace_fn!("classify_rtps");
    // Step 1: Validate RTPS header and extract metadata
    let rtps_header = match header::validate_and_extract_header(buf) {
        Ok(header) => header,
        Err(error_tuple) => return error_tuple,
    };

    let vendor_id = rtps_header.vendor_id;
    let guid_prefix = rtps_header.guid_prefix;

    let mut found_kind = PacketKind::Unknown;
    let mut data_payload_offset: Option<usize> = None;
    let mut fragment_metadata: Option<FragmentMetadata> = None;

    // RTPS context accumulator.
    //
    // This keeps the context of the LAST submessage the walk reached: one
    // context for a whole datagram. That is wrong as soon as a datagram
    // carries several DATA each with its own INFO_TS, which is why the walk
    // hands out a per-submessage snapshot - see `for_each_data_submessage`.
    let mut rtps_context = RtpsContext::default();

    log::debug!(
        "[CLASSIFY] Starting submessage scan for vendor 0x{:04x}, packet length={}, starting offset=20",
        vendor_id,
        buf.len()
    );

    walk::for_each_submessage(buf, |found| {
        let offset = found.offset;
        let flags = found.flags;
        let octets_to_next = found.octets_to_next;
        rtps_context = found.context;

        log::debug!(
            "[RTPS-DEBUG] Submessage at offset {}: ID=0x{:02x} flags=0x{:02x} octets_to_next={}",
            offset,
            found.id,
            flags,
            octets_to_next
        );

        // Extra debug for vendor id 0x0101 packets
        if vendor_id == 0x0101 {
            log::debug!(
                "[CLASSIFY-RTI] Submsg ID=0x{:02x} at offset {} (octets_to_next={})",
                found.id,
                offset,
                octets_to_next
            );
        }

        // Whether the DATA_FRAG arm below produced metadata for THIS
        // submessage, `None` when this submessage is not a DATA_FRAG. The
        // admission rule must not ask `fragment_metadata.is_some()`, which is a
        // property of the DATAGRAM: a DATA_FRAG the reader refused - because
        // its declared body does not hold its own 32 fixed octets - would be
        // admitted on its predecessor's metadata and rewrite the payload
        // offset for itself, pairing one fragment's description with
        // another's bytes.
        let mut data_frag_yielded_metadata: Option<bool> = None;

        // Where a DATA or DATA_FRAG's payload lies, read ONCE per
        // submessage: admission, the DATA_FRAG arm and the published offset
        // all ask it. `None` for an invalid one (Sec.8.3.4.1) and for every
        // other submessage.
        let layout_payload = if matches!(found.id, DATA_SUBMESSAGE_ID | 0x16) {
            submessage::calculate_payload_offset(buf, offset)
        } else {
            None
        };

        // Step 3: Classify this submessage (RTPS v2.3 Table 8.13).
        //
        // INFO_TS (0x09) and INFO_DST (0x0e) only name their kind here: the
        // walk has already applied them to the context, because they are
        // receiver state for what follows rather than something to classify.
        let kind = match found.id {
            0x01 => PacketKind::Pad,                // PAD submessage (alignment padding)
            0x06 => submessage::classify_acknack(), // ACKNACK submessage
            0x07 => submessage::classify_heartbeat(), // HEARTBEAT submessage
            0x08 => submessage::classify_gap(),     // GAP submessage (missing sequence numbers)
            0x09 => PacketKind::InfoTs,
            0x12 => submessage::classify_nack_frag(), // NACK_FRAG submessage (RTPS v2.5 Sec.8.3.8.12)
            0x13 => submessage::classify_heartbeat_frag(), // HEARTBEAT_FRAG submessage (RTPS v2.5 Sec.8.3.8.7)
            0x0c => PacketKind::InfoSrc,                   // INFO_SRC (source GUID prefix)
            0x0d => PacketKind::InfoReply, // INFO_REPLY_IP4 (IPv4 unicast reply locator)
            0x0e => PacketKind::InfoDst,
            0x0f => PacketKind::InfoReply, // INFO_REPLY (unicast reply locator list)
            DATA_SUBMESSAGE_ID => submessage::classify_data(buf, offset, found.body_end),
            // An invalid DATA_FRAG (its layout refused, Sec.8.3.4.1) is
            // ignored before it can describe a fragment.
            0x16 if layout_payload.is_none() => {
                data_frag_yielded_metadata = Some(false);
                PacketKind::DataFrag
            }
            0x16 => {
                let (frag_kind, yielded_metadata) = submessage::classify_data_frag(
                    buf,
                    offset,
                    found.body_end,
                    flags,
                    guid_prefix,
                    &mut fragment_metadata,
                );
                data_frag_yielded_metadata = Some(yielded_metadata);
                frag_kind
            }

            // Ids reported in a hexdump of a Connext 6.1 peer's traffic during
            // early interop work. No Connext capture on disk (6.1, 7.3, 7.7)
            // carries them, and the result is the one `classify_unknown`
            // gives (RTPS 2.5 Sec.8.3.4.1 rule 3: ignore and continue).
            0x6e | 0x8f | 0x3f => submessage::classify_rti_proprietary(found.id, vendor_id),

            // eProsima FastDDS proprietary submessages (vendor_id 0x010F)
            0x80 => submessage::classify_eprosima_proprietary(found.id, vendor_id),

            _ => submessage::classify_unknown(found.id, vendor_id),
        };

        // Step 4: is this submessage allowed to speak for the datagram?
        //
        // The question is asked of the SUBMESSAGE, never of the kind it
        // produced. Asking the kind would miss exactly the case the rule
        // exists for: a DATA too short to hold a writer entity id is
        // classified by four octets belonging to its neighbour, and the kind
        // that comes back - SPDP, SEDP, a secure builtin - is not one the
        // rule would look at, so the misread would admit itself (a 76-octet
        // datagram whose DATA declares an 8-octet body would register a
        // participant).
        let is_valid_discovery_packet = if let Some(yielded) = data_frag_yielded_metadata {
            // A DATA_FRAG is admissible exactly when it described itself.
            // This also covers the DATA_FRAG of a builtin writer, which is
            // classified SPDP/SEDP/TypeLookup and so must not fall into a
            // branch that admits it whatever the reader made of its fields.
            // An invalid one (its layout refused, Sec.8.3.4.1) yielded none.
            yielded
        } else if found.id == DATA_SUBMESSAGE_ID {
            (octets_to_next >= MIN_DATA_BODY_OCTETS || octets_to_next == 0)
                && layout_payload.is_some()
        } else {
            true // Other packet types
        };

        // Set by the winner rule below when the scan has seen enough: it ends
        // the loop, and it is pinned by `a_data_over_100_octets_ends_the_scan`.
        let mut stop = false;

        if matches!(
            kind,
            PacketKind::Data
                | PacketKind::DataFrag
                | PacketKind::SEDP
                | PacketKind::SPDP
                | PacketKind::TypeLookup
                | PacketKind::SecureSPDP
                | PacketKind::SecureSEDP
                | PacketKind::SecureVolatile
                | PacketKind::Stateless
        ) && is_valid_discovery_packet
        {
            // For vendor ids 0x0101 and HDDS (0x011A), prefer DATA_FRAG over
            // small DATA submessages. The 0x0101 half is an interop rule for
            // Connext 6.1 peers. In the Connext captures examined (6.1, 7.3,
            // and the public 7.7 shape_main in OMG CoherentSets runs) a
            // datagram's DATA submessages all come from one writer and none
            // is a DATA_FRAG, so both rules below pick the same winner there.
            let should_update = if vendor_id == 0x0101 || vendor_id == 0x011A {
                // 0x0101/HDDS: prefer DATA_FRAG, or DATA with large payload
                matches!(kind, PacketKind::DataFrag)
                    || (matches!(kind, PacketKind::Data) && octets_to_next > 100)
            } else {
                // Other vendors: prefer DATA over DATA_FRAG
                matches!(kind, PacketKind::Data | PacketKind::TypeLookup)
                    || !matches!(found_kind, PacketKind::Data | PacketKind::TypeLookup)
            };

            // Always prioritize SEDP/SPDP classification over generic Data/DataFrag
            if matches!(kind, PacketKind::SEDP | PacketKind::SPDP) {
                found_kind = kind;
                // SEDP/SPDP are always DATA submessages, calculate payload offset
            } else if should_update || matches!(found_kind, PacketKind::Unknown) {
                found_kind = kind;
            }

            // Step 5: Calculate payload offset for any DATA/DataFrag/SEDP/SPDP packet we're using
            //
            // The four secure-builtin kinds MUST appear here even though the list
            // above already admits them into `found_kind`. Without them the offset
            // stays None and the listener falls back to
            // LEGACY_RTPS_DATA_PAYLOAD_OFFSET (44). That constant assumes a bare
            // "RTPS header + DATA" datagram, but every secure-builtin packet also
            // carries INFO_DST (16 bytes) and INFO_TS (12 bytes) ahead of the DATA,
            // so its payload starts at 72, not 44. Handing 44 to the handler makes
            // it parse the tail of the DATA header as a CDR DataHolder.
            if matches!(
                found_kind,
                PacketKind::Data
                    | PacketKind::DataFrag
                    | PacketKind::SEDP
                    | PacketKind::SPDP
                    | PacketKind::TypeLookup
                    | PacketKind::SecureSPDP
                    | PacketKind::SecureSEDP
                    | PacketKind::SecureVolatile
                    | PacketKind::Stateless
            ) && (kind == found_kind || matches!(kind, PacketKind::SEDP | PacketKind::SPDP))
            {
                // Admitted above only when its layout reads.
                let Some(payload_offset_value) = layout_payload else {
                    return walk::Step::Continue;
                };
                data_payload_offset = Some(payload_offset_value);
                log::debug!("[RTPS-DEBUG] Found {} submessage at offset {}, payload at offset {}, octets_to_next={}",
                          if matches!(kind, PacketKind::DataFrag) { "DATA_FRAG" } else { "DATA" },
                          offset, payload_offset_value, octets_to_next);

                // For a DATA_FRAG, continue scanning in case there are multiple fragments
                // For standard DATA/SEDP/SPDP with large payload, we can stop
                // SEDP/SPDP are in the stop condition so a following HEARTBEAT cannot
                // overwrite cdr_offset
                if matches!(
                    kind,
                    PacketKind::Data | PacketKind::SEDP | PacketKind::SPDP | PacketKind::TypeLookup
                ) && octets_to_next > 100
                {
                    stop = true;
                }
            }
        } else if is_valid_discovery_packet
            && matches!(found_kind, PacketKind::Unknown)
            && !matches!(kind, PacketKind::Unknown)
        {
            // Update found_kind if we haven't found anything yet
            // INFO_* submessages must not override found_kind - they're context, not
            // primary type. INFO_DST and INFO_TS are just context for subsequent
            // DATA submessages.
            //
            // `is_valid_discovery_packet` gates this branch too, and that is
            // the whole of its effect: every other kind reaches it with the
            // rule's `true`, so only a DATA or DATA_FRAG the rule refused
            // changes hands here. Without the gate a refused submessage would
            // still NAME the datagram, and being first it would name it for
            // good. Take three datagrams, each a malformed submessage
            // followed by a perfectly valid one: a HEARTBEAT behind a
            // truncated DATA must not come out `Data`, the same HEARTBEAT
            // behind a DATA_FRAG that declares no fragment must not come out
            // `DataFrag`, and an ACKNACK behind a truncated DATA must not come
            // out `Data`. The router hands `Data` to the sample path, which
            // drops it, so the heartbeat and the acknack a reliable writer is
            // waiting for would never be delivered. One malformed submessage
            // must not silence everything behind it in its datagram.
            //
            // PAD carries nothing either (RTPS 2.5 8.3.8.13, 9.4.5.13): a
            // datagram that opens with alignment padding, or in which a
            // submessage destined to another participant was padded out
            // (`walk::destined_to`), is named by what follows the PAD. Named
            // `Pad`, it would reach neither the ring nor the control channel's
            // ACKNACK branch, and every submessage behind the PAD would be lost.
            if !matches!(
                kind,
                PacketKind::InfoDst
                    | PacketKind::InfoTs
                    | PacketKind::InfoSrc
                    | PacketKind::InfoReply
                    | PacketKind::Pad
            ) {
                found_kind = kind;
            }
        }

        if stop {
            walk::Step::Stop
        } else {
            walk::Step::Continue
        }
    });

    log::debug!(
        "[RTPS-DEBUG] Final classification: {:?}, payload_offset: {:?}, fragment_metadata: {:?}, rtps_context: {:?}",
        found_kind, data_payload_offset, fragment_metadata, rtps_context
    );
    (
        found_kind,
        data_payload_offset,
        fragment_metadata,
        rtps_context,
    )
}

/// One DATA submessage of a datagram, as the discovery path needs it.
pub(crate) struct DataSubmessage {
    /// What its writer entity id makes it: SPDP, SEDP, TypeLookup, one of
    /// the DDS-Security builtin tunnels, or plain user Data.
    pub kind: PacketKind,
    /// Offset of the serialized payload in the datagram.
    pub payload_offset: usize,
    /// Offset of the submessage header itself, so a consumer handed a
    /// `payload_offset` can read the fields that describe THAT submessage
    /// (writerEntityId, writerSN) instead of re-walking to the first DATA,
    /// which would answer for the first announcement of every datagram,
    /// however many it carried.
    pub offset: usize,
}

/// One past the last octet of the submessage whose payload starts at
/// `payload_offset`.
///
/// The classifier publishes where a payload STARTS, never where its
/// submessage ends. Every consumer that then slices to the end of the
/// datagram reads whatever follows - a batched HEARTBEAT, or the next
/// fragment of the very same sample - and hands it on as sample bytes.
/// `Submessage::body_end` is the bound that stops this, and the fragment
/// payload read must use it rather than compute its own.
///
/// Answers with the walk that produced the offset rather than with a reader
/// of its own: a second traversal can disagree with the first. `None` when
/// no submessage claims the offset, which leaves the caller free to keep its
/// own bound.
pub(crate) fn submessage_end_for_payload(buf: &[u8], payload_offset: usize) -> Option<usize> {
    crate::trace_fn!("submessage_end_for_payload");
    if header::validate_and_extract_header(buf).is_err() {
        return None;
    }

    let mut end = None;
    walk::for_each_submessage(buf, |found| {
        if found.offset < payload_offset && payload_offset <= found.body_end {
            end = Some(found.body_end);
            walk::Step::Stop
        } else {
            walk::Step::Continue
        }
    });
    end
}

/// Visit every DATA submessage of an RTPS datagram, in wire order.
///
/// `classify_rtps` answers "what IS this datagram", and a single answer
/// forces it to elect one winner among the submessages and discard the
/// rest. This answers "what does this datagram CARRY", which is the
/// question the discovery path has been asking all along: a datagram that
/// bundles an SPDP and two SEDP announcements - RTPS v2.5 Sec.8.3.3 allows
/// any sender to - has three things to deliver, not one.
///
/// Only 0x15 is visited. DATA_FRAG reassembly has its own scan
/// (`scan_all_data_frags`), which handles fragments alone.
///
/// A DATA whose octetsToNextHeader is between 1 and 15 is skipped: it
/// cannot hold the twenty fixed fields a DATA submessage starts with, so
/// its writer entity id would be read out of the submessage behind it.
/// That is the filter `classify_rtps` applies too. Zero means "last
/// submessage", which says nothing about the length, and is admitted.
///
/// The per-submessage INFO_TS snapshot the walk maintains is deliberately
/// NOT carried out of here: no discovery handler takes a source timestamp
/// today, and a field written and never read is dead code. The snapshot is on
/// `walk::Submessage` for the day a handler wants it.
///
/// DDS-Security 1.1 Sec.7.3.7.6/.7 submessage ids: the one SEC_PREFIX and
/// SEC_POSTFIX pair a signed (AES256_GMAC) secure envelope leaves visible
/// around the real submessage it protects (Sec.9.5.3.3.4.5's
/// "authenticating only" column) -- the same shape `control_parser::
/// EnvelopeTracker` excludes ordinary ACKNACK/NACK_FRAG scanning from.
/// A SIGNED SecureSEDP/SecureSPDP/SecureVolatile DATA is visible plaintext
/// exactly the same way, and this walk must not visit it a SECOND time (the
/// listener's secure-prefix callback at the top of `dispatch_datagram`
/// already delivers it once, correctly decoded); a second delivery's
/// `payload_offset` would point INSIDE the envelope, not at its SEC_PREFIX, so
/// the discovery dispatch would try to read it as a CLEAR announcement and
/// count a decode failure on perfectly valid traffic.
const SEC_PREFIX_ID: u8 = 0x31;
const SEC_POSTFIX_ID: u8 = 0x32;

/// Allocates nothing.
pub(crate) fn for_each_data_submessage<F>(buf: &[u8], mut visit: F)
where
    F: FnMut(DataSubmessage),
{
    crate::trace_fn!("for_each_data_submessage");
    if header::validate_and_extract_header(buf).is_err() {
        return;
    }

    let mut inside_secure_envelope = false;
    walk::for_each_submessage(buf, |found| {
        match found.id {
            SEC_PREFIX_ID => {
                inside_secure_envelope = true;
                return walk::Step::Continue;
            }
            SEC_POSTFIX_ID => {
                inside_secure_envelope = false;
                return walk::Step::Continue;
            }
            _ => {}
        }
        if found.id == DATA_SUBMESSAGE_ID
            && !inside_secure_envelope
            && (found.octets_to_next == 0 || found.octets_to_next >= MIN_DATA_BODY_OCTETS)
        {
            // `found.body_end` rather than the datagram, and no fixture can
            // tell the two apart here: the filter above has already granted
            // that this submessage holds its fixed fields, so the bound is
            // never the tighter of the two. Kept because the filter and the
            // read are two different decisions, and neither must rely on the
            // other staying as it is.
            // An invalid DATA (its layout refused) is ignored, the rest of
            // the datagram still read (RTPS v2.5 Sec.8.3.4.1).
            if let Some(payload_offset) = submessage::calculate_payload_offset(buf, found.offset) {
                let kind = submessage::classify_data(buf, found.offset, found.body_end);
                visit(DataSubmessage {
                    kind,
                    payload_offset,
                    offset: found.offset,
                });
            }
        }
        walk::Step::Continue
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build the exact datagram shape every DDS-Security builtin tunnel emits:
    /// RTPS header, INFO_DST, INFO_TS, then one DATA carrying `payload`.
    ///
    /// Mirrors `security::stateless_writer::build_stateless_packet` by calling
    /// the same encoder, so the fixture follows the builder instead of freezing
    /// a hand-copied byte layout that could drift away from it.
    fn build_secure_builtin_packet(
        reader_entity: &[u8; 4],
        writer_entity: &[u8; 4],
        payload: &[u8],
    ) -> (Vec<u8>, usize) {
        use crate::core::rtps_constants::{RTPS_MAGIC, RTPS_VERSION_MAJOR, RTPS_VERSION_MINOR};
        use crate::protocol::dialect::{get_encoder, Dialect};

        let encoder = get_encoder(Dialect::Hybrid);
        let info_dst = encoder.build_info_dst(&[0xAB; 12]);
        let info_ts = encoder.build_info_ts(0x1234_5678, 0x9abc_def0);
        let data = encoder
            .build_data(reader_entity, writer_entity, 1, payload, None)
            .expect("DATA submessage must build");

        let mut packet = Vec::new();
        packet.extend_from_slice(RTPS_MAGIC);
        packet.push(RTPS_VERSION_MAJOR);
        packet.push(RTPS_VERSION_MINOR);
        packet.extend_from_slice(&[0x01, 0x1a]); // HDDS vendor id
        packet.extend_from_slice(&[0xCD; 12]); // source GUID prefix
        packet.extend_from_slice(&info_dst);
        packet.extend_from_slice(&info_ts);
        packet.extend_from_slice(&data);

        // The serialized payload starts 24 bytes into the DATA submessage
        // (4 submessage header + 20 fixed fields, no inline QoS).
        let expected_payload_offset = 20 + info_dst.len() + info_ts.len() + 24;
        (packet, expected_payload_offset)
    }

    /// The PKI-DH handshake tunnel must come out of the classifier with a
    /// payload offset, and that offset must land exactly on the DataHolder.
    ///
    /// The offset must be computed for this kind too, not only for
    /// Data/DataFrag/SEDP/SPDP/TypeLookup: with `None` the listener would
    /// substitute LEGACY_RTPS_DATA_PAYLOAD_OFFSET (44). 44 assumes a
    /// bare "RTPS header + DATA" datagram; here it lands inside the INFO_TS
    /// timestamp fraction, which is a fresh wall-clock value on every packet.
    /// The handshake would not fail cleanly, it would parse rotating garbage.
    #[test]
    fn stateless_packet_is_classified_with_a_payload_offset() {
        use crate::core::rtps_constants::{
            RTPS_ENTITYID_BUILTIN_PARTICIPANT_STATELESS_MESSAGE_READER,
            RTPS_ENTITYID_BUILTIN_PARTICIPANT_STATELESS_MESSAGE_WRITER,
        };

        // A CDR string length prefix, the first field of any DataHolder.
        let token_cdr: &[u8] = &[0x20, 0x00, 0x00, 0x00, b'D', b'D', b'S', b':'];
        let (packet, expected_offset) = build_secure_builtin_packet(
            &RTPS_ENTITYID_BUILTIN_PARTICIPANT_STATELESS_MESSAGE_READER,
            &RTPS_ENTITYID_BUILTIN_PARTICIPANT_STATELESS_MESSAGE_WRITER,
            token_cdr,
        );

        let (kind, offset, _frag, _ctx) = classify_rtps(&packet);
        assert_eq!(kind, PacketKind::Stateless);
        assert_eq!(
            offset,
            Some(expected_offset),
            "the handshake tunnel must carry a payload offset, not fall back to a guess"
        );

        let offset = offset.expect("checked above");
        assert_ne!(
            offset, 44,
            "44 is the legacy bare-DATA fallback; INFO_DST + INFO_TS push the real payload past it"
        );
        assert_eq!(
            &packet[offset..],
            token_cdr,
            "the offset must land on the first byte of the DataHolder CDR"
        );
    }

    /// A secure SEDP DATA with NONE protection uses the DATA payload offset.
    #[test]
    fn secure_sedp_packet_is_classified_with_a_payload_offset() {
        use crate::core::rtps_constants::{
            RTPS_ENTITYID_SEDP_PUBLICATIONS_SECURE_READER,
            RTPS_ENTITYID_SEDP_PUBLICATIONS_SECURE_WRITER,
        };

        let ciphertext: &[u8] = &[0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04];
        let (packet, expected_offset) = build_secure_builtin_packet(
            &RTPS_ENTITYID_SEDP_PUBLICATIONS_SECURE_READER,
            &RTPS_ENTITYID_SEDP_PUBLICATIONS_SECURE_WRITER,
            ciphertext,
        );

        let (kind, offset, _frag, _ctx) = classify_rtps(&packet);
        assert_eq!(kind, PacketKind::SecureSEDP);
        assert_eq!(offset, Some(expected_offset));
        assert_eq!(&packet[offset.expect("checked above")..], ciphertext);
    }

    /// A clear DATA of the volatile secure endpoints is named after them,
    /// with its payload offset, so the discovery dispatch can refuse it by
    /// name (the topic is submessage-protected: its real DATA arrives as a
    /// SEC_PREFIX and is never classified here).
    #[test]
    fn secure_volatile_packet_is_classified_with_a_payload_offset() {
        use crate::core::rtps_constants::{
            RTPS_ENTITYID_BUILTIN_PARTICIPANT_VOLATILE_MESSAGE_SECURE_READER,
            RTPS_ENTITYID_BUILTIN_PARTICIPANT_VOLATILE_MESSAGE_SECURE_WRITER,
        };

        // Opaque payload bytes: classification depends on the endpoint ids.
        let sealed: &[u8] = &[0x53, 0x45, 0x43, 0x56, 0x4F, 0x4C, 0x4B, 0x57, 0xAA, 0xBB];
        let (packet, expected_offset) = build_secure_builtin_packet(
            &RTPS_ENTITYID_BUILTIN_PARTICIPANT_VOLATILE_MESSAGE_SECURE_READER,
            &RTPS_ENTITYID_BUILTIN_PARTICIPANT_VOLATILE_MESSAGE_SECURE_WRITER,
            sealed,
        );

        let (kind, offset, _frag, _ctx) = classify_rtps(&packet);
        assert_eq!(kind, PacketKind::SecureVolatile);
        assert_eq!(offset, Some(expected_offset));
        assert_eq!(&packet[offset.expect("checked above")..], sealed);
    }

    #[test]
    fn test_classify_data() {
        // Create minimal valid DATA packet (44 bytes minimum: 20 header + 24 submessage)
        let mut buf = vec![0u8; 60]; // Increased to 60 for payload space
        buf[0..4].copy_from_slice(b"RTPS");
        // RTPS v2.5 sec. 8.3.6.3: receivers MUST ignore messages with mismatched
        // major version; the new header gate (validate_and_extract_header)
        // enforces this so test fixtures must set the matching version.
        buf[4] = 0x02;
        buf[5] = 0x04;
        buf[20] = 0x15; // DATA submessageId (RTPS v2.3 Table 8.13)
        buf[21] = 0x01; // flags: little-endian
        buf[22] = 32; // octetsToNextHeader (low byte)
        buf[23] = 0; // octetsToNextHeader (high byte)
                     // octetsToInlineQos at offset 26-27: set to 16 (no inline QoS)
        buf[26] = 16; // octetsToInlineQos = 16 (fixed fields size)
        buf[27] = 0;

        let (kind, offset, frag_meta, _ctx) = classify_rtps(&buf);
        assert_eq!(kind, PacketKind::Data);
        // DATA at offset 20, octetsToInlineQos=16
        // Payload offset = 20 + 16 + 8 = 44 (per RTPS v2.5 Sec.8.3.8.2)
        assert_eq!(offset, Some(44)); // 20 + 16 + 8
        assert!(frag_meta.is_none()); // DATA has no fragment metadata
    }

    #[test]
    fn test_classify_heartbeat() {
        let mut buf = vec![0u8; 24];
        buf[0..4].copy_from_slice(b"RTPS");
        // RTPS v2.5 sec. 8.3.6.3: receivers MUST ignore messages with mismatched
        // major version; the new header gate (validate_and_extract_header)
        // enforces this so test fixtures must set the matching version.
        buf[4] = 0x02;
        buf[5] = 0x04;
        buf[20] = 0x07; // HEARTBEAT (0x07 per RTPS v2.3 Table 8.13)
        let (kind, offset, frag_meta, _ctx) = classify_rtps(&buf);
        assert_eq!(kind, PacketKind::Heartbeat);
        assert_eq!(offset, None); // No DATA payload for non-DATA packets
        assert!(frag_meta.is_none());
    }

    #[test]
    fn test_classify_acknack() {
        let mut buf = vec![0u8; 24];
        buf[0..4].copy_from_slice(b"RTPS");
        // RTPS v2.5 sec. 8.3.6.3: receivers MUST ignore messages with mismatched
        // major version; the new header gate (validate_and_extract_header)
        // enforces this so test fixtures must set the matching version.
        buf[4] = 0x02;
        buf[5] = 0x04;
        buf[20] = 0x06; // ACKNACK (0x06 per RTPS v2.3 Table 8.13)
        let (kind, _offset, frag_meta, _ctx) = classify_rtps(&buf);
        assert_eq!(kind, PacketKind::AckNack);
        assert!(frag_meta.is_none());
    }

    /// A DATA_FRAG id alone does not name a datagram; the fields behind it do.
    ///
    /// Four octets carrying nothing - no writer, no sequence number, no
    /// fragment - are not named `DataFrag` on the strength of the submessage
    /// id alone: the rest of the stack acts on that name, so the router would
    /// go looking for a fragment, find none, and drop the datagram. Naming it
    /// `Unknown` says the same thing one step earlier and without the search.
    ///
    /// Both sides are here, because a rule that only ever refuses is
    /// indistinguishable from a rule that refuses everything.
    #[test]
    fn test_classify_datafrag() {
        let mut buf = vec![0u8; 24];
        buf[0..4].copy_from_slice(b"RTPS");
        // RTPS v2.5 sec. 8.3.6.3: receivers MUST ignore messages with mismatched
        // major version; the new header gate (validate_and_extract_header)
        // enforces this so test fixtures must set the matching version.
        buf[4] = 0x02;
        buf[5] = 0x04;
        buf[20] = 0x16; // DATA_FRAG (RTPS v2.3 Table 8.13)
        let (kind, _offset, frag_meta, _ctx) = classify_rtps(&buf);
        assert_eq!(
            kind,
            PacketKind::Unknown,
            "four octets that describe no fragment name no datagram"
        );
        assert!(frag_meta.is_none(), "and they describe no fragment");

        // The same id, this time with a body that holds what a DATA_FRAG
        // declares about itself.
        let complete = data_frag_submessage([0x00, 0x00, 0x01, 0x02], 8);
        let packet = datagram([0x01, 0x1A], &[complete]);
        let (kind, _offset, frag_meta, _ctx) = classify_rtps(&packet);
        assert_eq!(
            kind,
            PacketKind::DataFrag,
            "a DATA_FRAG that describes itself still names its datagram"
        );
        assert!(
            frag_meta.is_some(),
            "and the fragment it describes still comes out"
        );
    }

    #[test]
    fn test_classify_invalid_magic() {
        let buf = vec![0u8; 24];
        let (kind, offset, frag_meta, _ctx) = classify_rtps(&buf);
        assert_eq!(kind, PacketKind::Invalid);
        assert_eq!(offset, None);
        assert!(frag_meta.is_none());
    }

    #[test]
    fn test_classify_truncated() {
        let buf = vec![0u8; 10];
        let (kind, offset, frag_meta, _ctx) = classify_rtps(&buf);
        assert_eq!(kind, PacketKind::Invalid);
        assert_eq!(offset, None);
        assert!(frag_meta.is_none());
    }

    #[test]
    fn test_classify_unknown_submessage() {
        let mut buf = vec![0u8; 24];
        buf[0..4].copy_from_slice(b"RTPS");
        // RTPS v2.5 sec. 8.3.6.3: receivers MUST ignore messages with mismatched
        // major version; the new header gate (validate_and_extract_header)
        // enforces this so test fixtures must set the matching version.
        buf[4] = 0x02;
        buf[5] = 0x04;
        buf[20] = 0xFF; // Unknown submessage ID (now at offset 20, not 16!)
        let (kind, _offset, _frag_meta, _ctx) = classify_rtps(&buf);
        assert_eq!(kind, PacketKind::Unknown);
    }

    #[test]
    fn test_classify_nack_frag() {
        let mut buf = vec![0u8; 24];
        buf[0..4].copy_from_slice(b"RTPS");
        // RTPS v2.5 sec. 8.3.6.3: receivers MUST ignore messages with mismatched
        // major version; the new header gate (validate_and_extract_header)
        // enforces this so test fixtures must set the matching version.
        buf[4] = 0x02;
        buf[5] = 0x04;
        buf[20] = 0x12; // NACK_FRAG (0x12 per RTPS v2.5 Sec.8.3.8.12)
        let (kind, _offset, frag_meta, _ctx) = classify_rtps(&buf);
        assert_eq!(kind, PacketKind::NackFrag);
        assert!(frag_meta.is_none());
    }

    /// GAP-first compound: [INFO_DST, GAP, HEARTBEAT] bundled in ONE RTPS
    /// message (durable history replay shape). INFO_DST is context-only, so
    /// the first non-INFO submessage (GAP) wins the classification even
    /// though a HEARTBEAT follows. The listener's embedded-HEARTBEAT
    /// extraction in the Gap branch depends on this invariant.
    #[test]
    fn test_classify_gap_first_compound() {
        let mut buf = Vec::new();

        // RTPS header (20 bytes); major version must match our gate.
        buf.extend_from_slice(b"RTPS");
        buf.extend_from_slice(&[0x02, 0x05]); // Version 2.5
        buf.extend_from_slice(&[0x01, 0x1A]); // Vendor ID (HDDS)
        buf.extend_from_slice(&[0x0A; 12]); // GUID prefix

        // INFO_DST submessage (0x0e): 12-byte destination guidPrefix.
        buf.push(0x0e);
        buf.push(0x01); // Flags: little-endian
        buf.extend_from_slice(&12u16.to_le_bytes());
        buf.extend_from_slice(&[0x0B; 12]);

        // GAP submessage (0x08): gapStart=1, gapList.base=52, numBits=0.
        buf.push(0x08);
        buf.push(0x01); // Flags: little-endian
        buf.extend_from_slice(&28u16.to_le_bytes());
        buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // readerEntityId
        buf.extend_from_slice(&[0x00, 0x00, 0x01, 0x02]); // writerEntityId
        buf.extend_from_slice(&0i32.to_le_bytes()); // gapStart high
        buf.extend_from_slice(&1u32.to_le_bytes()); // gapStart low
        buf.extend_from_slice(&0i32.to_le_bytes()); // gapList.base high
        buf.extend_from_slice(&52u32.to_le_bytes()); // gapList.base low
        buf.extend_from_slice(&0u32.to_le_bytes()); // gapList.numBits

        // HEARTBEAT submessage (0x07): firstSN=52, lastSN=52, count=2.
        buf.push(0x07);
        buf.push(0x01); // Flags: little-endian only (not FINAL)
        buf.extend_from_slice(&28u16.to_le_bytes());
        buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // readerEntityId
        buf.extend_from_slice(&[0x00, 0x00, 0x01, 0x02]); // writerEntityId
        buf.extend_from_slice(&0i32.to_le_bytes()); // firstSeq high
        buf.extend_from_slice(&52u32.to_le_bytes()); // firstSeq low
        buf.extend_from_slice(&0i32.to_le_bytes()); // lastSeq high
        buf.extend_from_slice(&52u32.to_le_bytes()); // lastSeq low
        buf.extend_from_slice(&2u32.to_le_bytes()); // count

        let (kind, offset, frag_meta, _ctx) = classify_rtps(&buf);
        assert_eq!(
            kind,
            PacketKind::Gap,
            "first non-INFO submessage (GAP) must win over the trailing HEARTBEAT"
        );
        assert_eq!(offset, None); // GAP carries no DATA payload
        assert!(frag_meta.is_none());
    }

    #[test]
    fn test_classify_heartbeat_frag() {
        let mut buf = vec![0u8; 24];
        buf[0..4].copy_from_slice(b"RTPS");
        // RTPS v2.5 sec. 8.3.6.3: receivers MUST ignore messages with mismatched
        // major version; the new header gate (validate_and_extract_header)
        // enforces this so test fixtures must set the matching version.
        buf[4] = 0x02;
        buf[5] = 0x04;
        buf[20] = 0x13; // HEARTBEAT_FRAG (0x13 per RTPS v2.5 Sec.8.3.8.7)
        let (kind, _offset, frag_meta, _ctx) = classify_rtps(&buf);
        assert_eq!(kind, PacketKind::HeartbeatFrag);
        assert!(frag_meta.is_none());
    }

    // The fixtures below are hand-built, field by field, from the RTPS v2.5
    // layout: the message header (Sec.8.3.3.1), the submessage header
    // (Sec.8.3.3.3) and the DATA body (Sec.8.3.8.2). A hand-built fixture
    // only ratifies its author's reading of the layout, so whoever touches
    // this layout re-reads those sections, not this code.
    // ---------------------------------------------------------------
    // Pins for the two rules that steer the scan.
    //
    // Neither is an RTPS rule. Both are artefacts of an API that can
    // name only ONE kind and ONE payload offset per datagram, so the
    // scan has to elect a winner and stop. They are pinned here so that
    // a refactor which changes them has to change a test on purpose
    // rather than discover it in an interop run.
    // ---------------------------------------------------------------

    /// Assemble a datagram: RTPS header carrying `vendor_id`, then the
    /// submessages in wire order. Version 2.5, so the header gate admits it.
    fn datagram(vendor_id: [u8; 2], submessages: &[Vec<u8>]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"RTPS");
        buf.extend_from_slice(&[0x02, 0x05]);
        buf.extend_from_slice(&vendor_id);
        buf.extend_from_slice(&[0x0A; 12]);
        for submessage in submessages {
            // RTPS v2.5 Sec.9.4.1: every submessage header starts on a
            // 4-byte boundary. The scan realigns after each one, so a
            // fixture that ignores this makes the NEXT submessage land at
            // an offset the scanner will never look at - and a test can
            // then pass because its submessage was skipped rather than
            // because the rule under test fired.
            assert_eq!(
                submessage.len() % 4,
                0,
                "a fixture submessage must be 4-byte aligned like the wire"
            );
            buf.extend_from_slice(submessage);
        }
        buf
    }

    /// A DATA submessage (0x15) carrying `payload` past its 20 fixed
    /// fields, so octetsToNextHeader is exactly `20 + payload.len()` and a
    /// test can place it either side of the 100 threshold - or recognise
    /// its own bytes at the offset the classifier reports.
    fn data_submessage(writer_entity: [u8; 4], payload: &[u8]) -> Vec<u8> {
        let mut submessage = vec![0x15, 0x01];
        submessage.extend_from_slice(&((20 + payload.len()) as u16).to_le_bytes());
        submessage.extend_from_slice(&[0x00, 0x00]); // extraFlags
        submessage.extend_from_slice(&16u16.to_le_bytes()); // octetsToInlineQos
        submessage.extend_from_slice(&[0x00; 4]); // readerEntityId
        submessage.extend_from_slice(&writer_entity);
        submessage.extend_from_slice(&[0x00; 8]); // writerSN
        submessage.extend_from_slice(payload);
        submessage
    }

    /// A DATA_FRAG submessage (0x16) complete enough that
    /// `classify_data_frag` publishes fragment metadata, which is the
    /// condition that makes it eligible to win the classification.
    fn data_frag_submessage(writer_entity: [u8; 4], payload_len: usize) -> Vec<u8> {
        let mut submessage = vec![0x16, 0x01];
        submessage.extend_from_slice(&((32 + payload_len) as u16).to_le_bytes());
        submessage.extend_from_slice(&[0x00, 0x00]); // extraFlags
        submessage.extend_from_slice(&28u16.to_le_bytes()); // octetsToInlineQos
        submessage.extend_from_slice(&[0x00; 4]); // readerEntityId
        submessage.extend_from_slice(&writer_entity);
        submessage.extend_from_slice(&[0x00; 4]); // writerSN high
        submessage.extend_from_slice(&1u32.to_le_bytes()); // writerSN low
        submessage.extend_from_slice(&1u32.to_le_bytes()); // fragmentStartingNum
        submessage.extend_from_slice(&1u16.to_le_bytes()); // fragmentsInSubmessage
        submessage.extend_from_slice(&(payload_len as u16).to_le_bytes()); // fragmentSize
        submessage.extend_from_slice(&(payload_len as u32).to_le_bytes()); // dataSize
        submessage.extend_from_slice(&vec![0xBB; payload_len]);
        submessage
    }

    /// An INFO_TS submessage (0x09) carrying a timestamp a test can recognise.
    fn info_ts_submessage(seconds: i32, fraction: u32) -> Vec<u8> {
        let mut submessage = vec![0x09, 0x01];
        submessage.extend_from_slice(&8u16.to_le_bytes());
        submessage.extend_from_slice(&seconds.to_le_bytes());
        submessage.extend_from_slice(&fraction.to_le_bytes());
        submessage
    }

    /// A HEARTBEAT submessage (0x07) a reliable reader would answer.
    fn heartbeat_submessage() -> Vec<u8> {
        let mut submessage = vec![0x07, 0x01];
        submessage.extend_from_slice(&28u16.to_le_bytes());
        submessage.extend_from_slice(&[0x00, 0x00, 0x01, 0x07]); // readerEntityId
        submessage.extend_from_slice(&[0x00, 0x00, 0x01, 0x02]); // writerEntityId
        submessage.extend_from_slice(&0u32.to_le_bytes()); // firstSN high
        submessage.extend_from_slice(&1u32.to_le_bytes()); // firstSN low
        submessage.extend_from_slice(&0u32.to_le_bytes()); // lastSN high
        submessage.extend_from_slice(&9u32.to_le_bytes()); // lastSN low
        submessage.extend_from_slice(&3u32.to_le_bytes()); // count
        submessage
    }

    /// A DATA whose declared body stops short of its own writer entity id.
    ///
    /// `octetsToNextHeader = 8` puts the body at `[offset + 4, offset + 12)`,
    /// and the writer entity id is read at `[offset + 12, offset + 16)` -
    /// four octets this submessage does not own.
    fn a_data_that_stops_before_its_writer_id() -> Vec<u8> {
        let mut submessage = vec![0x15, 0x01];
        submessage.extend_from_slice(&8u16.to_le_bytes());
        submessage.extend_from_slice(&[0xAA; 8]);
        submessage
    }

    /// The writer entity id a DATA is named after has to be inside the DATA.
    ///
    /// Asked of `classify_data` directly. The datagram-level answer cannot
    /// separate the two outcomes - the admission rule refuses a runt DATA
    /// whatever its kind, so bounded and unbounded both come out `Unknown`
    /// up there - and a test that cannot tell bounded from unbounded code pins
    /// nothing.
    ///
    /// The four octets past the body spell the SPDP builtin participant
    /// writer on purpose: read against the datagram this answers SPDP, which
    /// is a participant announcement built from bytes belonging to the
    /// submessage next door.
    #[test]
    fn a_data_is_named_by_a_writer_id_inside_its_own_body() {
        const SPDP_WRITER: [u8; 4] = [0x00, 0x01, 0x00, 0xC2];
        const DATA_AT: usize = 20;

        let runt = a_data_that_stops_before_its_writer_id();
        let body_end = DATA_AT + runt.len();
        let packet = datagram([0x01, 0x1A], &[runt, SPDP_WRITER.to_vec()]);

        assert!(
            DATA_AT + 16 > body_end,
            "fixture: the writer entity id must lie past this submessage"
        );
        assert_eq!(
            &packet[DATA_AT + 12..DATA_AT + 16],
            &SPDP_WRITER,
            "fixture: and the octets there must name a builtin writer, or the \
             mutation this pins changes nothing"
        );

        assert_eq!(
            submessage::classify_data(&packet, DATA_AT, body_end),
            PacketKind::Data,
            "a DATA that carries no writer entity id is not an announcement \
             from whoever stands behind it"
        );

        // The same read, one octet of body further on: the id is its own
        // and the answer changes. Without this half the rule above is
        // indistinguishable from "always Data".
        let announcement = datagram([0x01, 0x1A], &[data_submessage(SPDP_WRITER, &[0x11; 32])]);
        assert_eq!(
            submessage::classify_data(&announcement, DATA_AT, announcement.len()),
            PacketKind::SPDP,
            "and a DATA that does carry one is still named by it"
        );
    }

    /// A DATA too short to hold its own fixed fields speaks for nothing.
    ///
    /// The admission rule asks the SUBMESSAGE - is this a 0x15 whose body can
    /// hold a DATA's fields - and not the kind the classification produced.
    /// Keyed on the kind, the rule would look only at `Data` and
    /// `TypeLookup`, so the one case it exists to catch would walk straight
    /// past it: a runt DATA whose writer id is read out of its neighbour comes
    /// back SPDP, and SPDP is not a kind such a rule would look at.
    ///
    /// This fixture needs no misread at all. Its writer entity id is really
    /// inside its twelve octets of body, so it is genuinely an SPDP writer's
    /// DATA - and still malformed, because a DATA's fixed fields run to
    /// twenty octets and its writerSN is missing. The payload offset computed
    /// for it, `offset + 24`, lands eight octets past its own end.
    #[test]
    fn a_data_that_cannot_hold_its_own_fields_names_nothing() {
        const SPDP_WRITER: [u8; 4] = [0x00, 0x01, 0x00, 0xC2];

        let mut short = vec![0x15, 0x01];
        short.extend_from_slice(&12u16.to_le_bytes());
        short.extend_from_slice(&[0x00, 0x00]); // extraFlags
        short.extend_from_slice(&16u16.to_le_bytes()); // octetsToInlineQos
        short.extend_from_slice(&[0x00; 4]); // readerEntityId
        short.extend_from_slice(&SPDP_WRITER); // and there it stops

        let packet = datagram([0x01, 0x1A], &[short, vec![0x11; 40]]);
        assert_eq!(
            submessage::classify_data(&packet, 20, 20 + 4 + 12),
            PacketKind::SPDP,
            "fixture: the writer id is genuinely inside this submessage, so \
             what refuses the datagram below is the admission rule and not \
             the bound on the read"
        );

        let (kind, payload_offset, _frag, _ctx) = classify_rtps(&packet);
        assert_eq!(
            kind,
            PacketKind::Unknown,
            "a DATA whose body cannot hold its fixed fields announces nothing"
        );
        assert!(
            payload_offset.is_none(),
            "and offers no offset to read a payload at"
        );

        // Four more octets of body and the same writer is believed.
        let whole = datagram([0x01, 0x1A], &[data_submessage(SPDP_WRITER, &[0x11; 32])]);
        let (kind, payload_offset, _frag, _ctx) = classify_rtps(&whole);
        assert_eq!(
            kind,
            PacketKind::SPDP,
            "the rule refuses runts, not announcements"
        );
        assert_eq!(payload_offset, Some(20 + 24));
    }

    /// A submessage the admission rule refused does not silence the ones
    /// behind it.
    ///
    /// The rule must decide more than the payload offset: a refused
    /// submessage must not NAME the datagram through the fallback branch,
    /// because being first it would name it for good, and everything behind
    /// it (a HEARTBEAT, an ACKNACK, whatever a reliable writer is waiting on)
    /// would be classified away.
    ///
    /// Each case is the same valid submessage twice: alone, and behind a
    /// malformed one. The pair is the point. A test that only checked the
    /// second half would pass on a classifier that answers `Heartbeat` for
    /// everything.
    #[test]
    fn what_stands_behind_a_refused_submessage_still_names_the_datagram() {
        let mut acknack = vec![0x06, 0x01];
        acknack.extend_from_slice(&24u16.to_le_bytes());
        acknack.extend_from_slice(&[0x11; 24]);

        let refused: [(&str, Vec<u8>); 2] = [
            (
                "a DATA that stops before its own writer id",
                a_data_that_stops_before_its_writer_id(),
            ),
            (
                "a DATA_FRAG that describes no fragment",
                a_data_frag_missing_its_fragment_fields([0x00, 0x00, 0x01, 0x02]),
            ),
        ];

        for (valid_name, valid, expected) in [
            ("a HEARTBEAT", heartbeat_submessage(), PacketKind::Heartbeat),
            ("an ACKNACK", acknack, PacketKind::AckNack),
        ] {
            let (alone, _, _, _) =
                classify_rtps(&datagram([0x01, 0x1A], std::slice::from_ref(&valid)));
            assert_eq!(
                alone, expected,
                "fixture: {valid_name} must name its own datagram"
            );

            for (refused_name, runt) in &refused {
                let packet = datagram([0x01, 0x1A], &[runt.clone(), valid.clone()]);
                let (kind, _offset, _frag, _ctx) = classify_rtps(&packet);
                assert_eq!(
                    kind, expected,
                    "{refused_name} must not answer for the datagram in place \
                     of {valid_name} standing behind it"
                );
            }
        }
    }

    /// The admission threshold, from both sides, and the sentinel that
    /// bypasses it.
    ///
    /// Raising the threshold to 20 and deleting `|| octets_to_next == 0` must
    /// each turn a test red. The second matters more: the sentinel is not a
    /// corner case but how many real DATA submessages declare their length.
    ///
    /// So the threshold is pinned at the two octet counts that straddle it,
    /// and the sentinel is pinned on its own. A threshold defended from one
    /// side only is a threshold anyone can move outward.
    ///
    /// The counts are written out as 16 and 20 rather than derived from
    /// `MIN_DATA_BODY_OCTETS`. A fixture computed from the constant moves
    /// with it and agrees with whatever it is set to, so a test written
    /// as `MIN_DATA_BODY_OCTETS - 4` could not catch a moved threshold.
    #[test]
    fn the_admission_threshold_holds_from_both_sides() {
        const SPDP_WRITER: [u8; 4] = [0x00, 0x01, 0x00, 0xC2];

        /// A DATA declaring `octets_to_next` octets of body, padded to that
        /// length, carrying the SPDP writer entity id where it belongs.
        fn a_data_declaring(octets_to_next: u16) -> Vec<u8> {
            let mut submessage = vec![0x15, 0x01];
            submessage.extend_from_slice(&octets_to_next.to_le_bytes());
            let mut body = vec![0x00, 0x00]; // extraFlags
            body.extend_from_slice(&16u16.to_le_bytes()); // octetsToInlineQos
            body.extend_from_slice(&[0x00; 4]); // readerEntityId
            body.extend_from_slice(&SPDP_WRITER);
            body.resize(octets_to_next as usize, 0x00);
            submessage.extend_from_slice(&body);
            submessage
        }

        assert_eq!(
            MIN_DATA_BODY_OCTETS, 20,
            "the fixed fields of a DATA are twenty octets of body \
             (RTPS v2.5 Sec.8.3.8.2), and the two fixtures below are written \
             for that number"
        );

        let (kind, _at, _frag, _ctx) = classify_rtps(&datagram(
            [0x01, 0x1A],
            &[a_data_declaring(16), vec![0x11; 40]],
        ));
        assert_eq!(
            kind,
            PacketKind::Unknown,
            "a DATA declaring 16 octets stops halfway through its writerSN"
        );

        let (kind, at, _frag, _ctx) = classify_rtps(&datagram(
            [0x01, 0x1A],
            &[a_data_declaring(20), vec![0x11; 40]],
        ));
        assert_eq!(
            kind,
            PacketKind::SPDP,
            "and one declaring 20 carries every field this reads out of it"
        );
        assert_eq!(at, Some(20 + 24));

        // RTPS v2.5 Sec.8.3.3.3: zero is "last submessage", not "empty". It
        // says nothing about the length, so the threshold does not apply and
        // the datagram itself is the bound.
        let mut last = vec![0x15, 0x01];
        last.extend_from_slice(&0u16.to_le_bytes());
        last.extend_from_slice(&[0x00, 0x00]);
        last.extend_from_slice(&16u16.to_le_bytes());
        last.extend_from_slice(&[0x00; 4]);
        last.extend_from_slice(&SPDP_WRITER);
        last.extend_from_slice(&[0x00; 8]); // writerSN
        last.extend_from_slice(&[0x11; 32]); // and the payload
        let (kind, at, _frag, _ctx) = classify_rtps(&datagram([0x01, 0x1A], &[last]));
        assert_eq!(
            kind,
            PacketKind::SPDP,
            "the last submessage of a datagram declares no length and is \
             still a DATA"
        );
        assert_eq!(at, Some(20 + 24));
    }

    /// PIN: under vendor id 0x0101 or HDDS (0x011A) a DATA_FRAG wins over a
    /// DATA sharing the datagram, whichever came first on the wire.
    ///
    /// It exists for SPDP carried in DATA_FRAG, and it is a
    /// tie-break, not a spec rule: only one kind can be returned, so one of
    /// the two submessages has to lose.
    #[test]
    fn for_rti_and_hdds_a_data_frag_beats_a_small_data() {
        let user_writer = [0x00, 0x00, 0x01, 0x02];
        for vendor in [[0x01, 0x01], [0x01, 0x1A]] {
            let packet = datagram(
                vendor,
                &[
                    data_submessage(user_writer, &[0xAA; 40]),
                    data_frag_submessage(user_writer, 40),
                ],
            );
            let (kind, _offset, frag, _ctx) = classify_rtps(&packet);
            assert_eq!(
                kind,
                PacketKind::DataFrag,
                "vendor {vendor:02x?} must prefer the fragment"
            );
            assert!(
                frag.is_some(),
                "vendor {vendor:02x?} must carry the fragment metadata out"
            );
        }
    }

    /// PIN: the mirror rule. Under any other vendor the DATA wins, again in
    /// either wire order - so the winner depends on the vendor id, never on
    /// the position in the datagram.
    #[test]
    fn for_every_other_vendor_a_data_beats_a_data_frag() {
        // 0x0105: any vendor id other than 0x0101 takes this rule.
        let user_writer = [0x00, 0x00, 0x01, 0x02];
        let data_first = datagram(
            [0x01, 0x05],
            &[
                data_submessage(user_writer, &[0xAA; 40]),
                data_frag_submessage(user_writer, 40),
            ],
        );
        let frag_first = datagram(
            [0x01, 0x05],
            &[
                data_frag_submessage(user_writer, 40),
                data_submessage(user_writer, &[0xAA; 40]),
            ],
        );

        assert_eq!(classify_rtps(&data_first).0, PacketKind::Data);
        assert_eq!(classify_rtps(&frag_first).0, PacketKind::Data);
    }

    /// PIN: a DATA whose octetsToNextHeader is over 100 ENDS the scan. What
    /// follows it in the datagram is never read - not even an INFO_TS, which
    /// RTPS v2.5 Sec.8.3.8.11 says applies to the submessages after it.
    ///
    /// 104 and 100 are the two 4-byte-aligned lengths straddling the
    /// threshold, so together these two tests pin it inside [101, 104]:
    /// moving it to 99 or to 105 fails one of them.
    #[test]
    fn a_data_over_100_octets_ends_the_scan() {
        let packet = datagram(
            [0x01, 0x05],
            &[
                data_submessage([0x00, 0x00, 0x01, 0x02], &[0xAA; 84]), // octetsToNextHeader = 104
                info_ts_submessage(0x1122_3344, 0x5566_7788),
            ],
        );
        let (kind, _offset, _frag, ctx) = classify_rtps(&packet);
        assert_eq!(kind, PacketKind::Data);
        assert_eq!(
            ctx.source_timestamp, None,
            "the scan stopped on the DATA, so the INFO_TS behind it was never read"
        );
    }

    /// PIN: the control case for the threshold above. One octet less and the
    /// scan carries on, so the same trailing INFO_TS does reach the context.
    #[test]
    fn a_data_of_exactly_100_octets_lets_the_scan_continue() {
        let packet = datagram(
            [0x01, 0x05],
            &[
                data_submessage([0x00, 0x00, 0x01, 0x02], &[0xAA; 80]), // octetsToNextHeader = 100
                info_ts_submessage(0x1122_3344, 0x5566_7788),
            ],
        );
        let (kind, _offset, _frag, ctx) = classify_rtps(&packet);
        assert_eq!(kind, PacketKind::Data);
        assert_eq!(
            ctx.source_timestamp,
            Some((0x1122_3344, 0x5566_7788)),
            "under the threshold the scan must still be running when the INFO_TS arrives"
        );
    }

    /// The datagram this walk exists for: one SPDP announcement
    /// and two SEDP announcements bundled into a single RTPS message, each
    /// behind its own INFO_TS. RTPS v2.5 Sec.8.3.3 allows any sender to
    /// bundle them this way, so the discovery path must deliver all three.
    ///
    /// Each DATA carries a payload only it could have, so the test proves
    /// the offsets land on the right submessage rather than merely counting
    /// three of something.
    #[test]
    fn every_data_submessage_of_a_compound_datagram_is_visited() {
        const SPDP_WRITER: [u8; 4] = [0x00, 0x01, 0x00, 0xC2];
        const SEDP_PUBLICATIONS_WRITER: [u8; 4] = [0x00, 0x00, 0x03, 0xC2];

        // The SPDP is the big one, as it is on the wire: its
        // octetsToNextHeader of 104 is over the threshold that ends
        // `classify_rtps`'s scan, so this datagram also proves the walk
        // does not inherit that stop.
        let first = [0x11u8; 84];
        let second = [0x22u8; 40];
        let third = [0x33u8; 40];

        let packet = datagram(
            [0x01, 0x05], // any vendor id other than 0x0101
            &[
                info_ts_submessage(1, 1),
                data_submessage(SPDP_WRITER, &first),
                info_ts_submessage(2, 2),
                data_submessage(SEDP_PUBLICATIONS_WRITER, &second),
                info_ts_submessage(3, 3),
                data_submessage(SEDP_PUBLICATIONS_WRITER, &third),
            ],
        );

        let mut visited = Vec::new();
        for_each_data_submessage(&packet, |data| {
            visited.push((data.kind, data.payload_offset));
        });

        assert_eq!(
            visited.iter().map(|(kind, _)| *kind).collect::<Vec<_>>(),
            vec![PacketKind::SPDP, PacketKind::SEDP, PacketKind::SEDP],
            "all three announcements must be visited, in wire order"
        );

        let payloads: [&[u8]; 3] = [&first, &second, &third];
        for ((_, offset), expected) in visited.iter().zip(payloads) {
            assert_eq!(
                &packet[*offset..*offset + expected.len()],
                expected,
                "the offset must land on that submessage's own payload"
            );
        }
    }

    /// The other half of the same fact, on the very same datagram: asked
    /// what it IS, `classify_rtps` answers with one kind and one offset,
    /// the SPDP, and the two SEDP behind it are invisible to it. That is
    /// all its signature can say, which is why the discovery path can no
    /// longer be fed from this function alone.
    ///
    /// Note which one it names, and why: the SPDP wins only because its
    /// length is over the threshold and ends the scan. Shorten it and the
    /// last SEDP takes the datagram's name instead. Either way, two of the
    /// three announcements are lost.
    #[test]
    fn classify_rtps_still_names_a_compound_datagram_with_one_kind() {
        const SPDP_WRITER: [u8; 4] = [0x00, 0x01, 0x00, 0xC2];
        const SEDP_PUBLICATIONS_WRITER: [u8; 4] = [0x00, 0x00, 0x03, 0xC2];

        let long_spdp = datagram(
            [0x01, 0x05],
            &[
                data_submessage(SPDP_WRITER, &[0x11; 84]), // octetsToNextHeader = 104
                data_submessage(SEDP_PUBLICATIONS_WRITER, &[0x22; 40]),
            ],
        );
        let (kind, offset, _frag, _ctx) = classify_rtps(&long_spdp);
        assert_eq!(kind, PacketKind::SPDP);
        assert_eq!(
            offset,
            Some(20 + 24),
            "the single offset it reports is the first DATA's"
        );

        let short_spdp = datagram(
            [0x01, 0x05],
            &[
                data_submessage(SPDP_WRITER, &[0x11; 40]), // octetsToNextHeader = 60
                data_submessage(SEDP_PUBLICATIONS_WRITER, &[0x22; 40]),
            ],
        );
        assert_eq!(
            classify_rtps(&short_spdp).0,
            PacketKind::SEDP,
            "under the threshold the scan runs on and the last one takes the name"
        );
    }

    /// A DATA whose octetsToNextHeader cannot hold its own twenty fixed
    /// fields is not a DATA to deliver: reading its writer entity id would
    /// mean reading bytes belonging to the submessage behind it. Skipped
    /// here, exactly as `classify_rtps` skips it.
    #[test]
    fn a_data_too_short_for_its_own_fixed_fields_is_not_visited() {
        const SPDP_WRITER: [u8; 4] = [0x00, 0x01, 0x00, 0xC2];

        // octetsToNextHeader = 8, then a well-formed SPDP behind it.
        let mut runt = vec![0x15, 0x01];
        runt.extend_from_slice(&8u16.to_le_bytes());
        runt.extend_from_slice(&[0x00; 8]);

        let packet = datagram(
            [0x01, 0x05],
            &[runt, data_submessage(SPDP_WRITER, &[0x11; 40])],
        );

        let mut visited = Vec::new();
        for_each_data_submessage(&packet, |data| visited.push(data.kind));
        assert_eq!(visited, vec![PacketKind::SPDP]);
    }

    /// A DATA_FRAG is named by the writer that sent it, not by its id.
    ///
    /// `classify_data_frag` reads the writerEntityId and answers SPDP or
    /// SEDP for the three builtin discovery writers, falling back to
    /// `DataFrag` only for a user writer. Every existing fixture in this
    /// module passes a user writer, so the builtin branch carried no test
    /// at all.
    ///
    /// It is load-bearing well outside this file: the discovery callback
    /// routes on the SHAPE of the submessage, so a fragment goes to
    /// reassembly whatever kind it carries, and the reassembled sample is
    /// then dispatched by this same writer id. An inventory entry
    /// that rests on an unpinned branch is a belief, not a fact.
    #[test]
    fn a_data_frag_is_named_by_its_writer_not_by_its_submessage_id() {
        const SPDP_WRITER: [u8; 4] = [0x00, 0x01, 0x00, 0xC2];
        const SEDP_PUBLICATIONS_WRITER: [u8; 4] = [0x00, 0x00, 0x03, 0xC2];
        const SEDP_SUBSCRIPTIONS_WRITER: [u8; 4] = [0x00, 0x00, 0x04, 0xC2];
        const USER_WRITER: [u8; 4] = [0x00, 0x00, 0x01, 0x02];

        for (writer, expected) in [
            (SPDP_WRITER, PacketKind::SPDP),
            (SEDP_PUBLICATIONS_WRITER, PacketKind::SEDP),
            (SEDP_SUBSCRIPTIONS_WRITER, PacketKind::SEDP),
            (USER_WRITER, PacketKind::DataFrag),
        ] {
            let packet = datagram([0x01, 0x05], &[data_frag_submessage(writer, 40)]);
            assert_eq!(
                classify_rtps(&packet).0,
                expected,
                "a DATA_FRAG from writer {writer:02x?} is classified by that writer"
            );
        }
    }
    /// The same writer names the same thing, DATA or DATA_FRAG.
    ///
    /// The entity id is what separates a discovery submessage from a user
    /// one, and it means the same thing in both. The map must exist once, not
    /// once per submessage handler: two copies drift, and a DATA_FRAG copy
    /// that knew only the three plaintext discovery writers would name a
    /// fragmented TypeLookup reply - and a large TypeObject is exactly what
    /// fragments - user data, while the very same reply sent whole is named
    /// TypeLookup. Same for the five secure builtin endpoints.
    ///
    /// The assertion is the EQUIVALENCE, not a list of expected kinds: a test
    /// that spells out what each id should give would keep passing on a copy
    /// that knew only three ids, because it would be written from that copy.
    #[test]
    fn a_builtin_writer_names_the_same_kind_whether_or_not_it_fragments() {
        // Wire values, spelled out rather than imported, so the test states
        // what goes past on the network. A wrong id would be simply a user
        // writer on BOTH sides and the equivalence would still hold. The
        // `is_builtin` column below is what makes a typo fail instead of
        // going quiet.
        const ENDPOINTS: [([u8; 4], bool); 13] = [
            ([0x00, 0x01, 0x00, 0xc2], true),  // SPDP writer
            ([0x00, 0x00, 0x03, 0xc2], true),  // SEDP publications writer
            ([0x00, 0x00, 0x04, 0xc2], true),  // SEDP subscriptions writer
            ([0x00, 0x03, 0x00, 0xc3], true),  // TypeLookup request writer
            ([0x00, 0x03, 0x01, 0xc3], true),  // TypeLookup reply writer
            ([0xff, 0x01, 0x01, 0xc2], true),  // SPDP secure writer
            ([0xff, 0x00, 0x03, 0xc2], true),  // SEDP publications secure writer
            ([0xff, 0x00, 0x04, 0xc2], true),  // SEDP subscriptions secure writer
            ([0xff, 0x02, 0x00, 0xc2], true),  // P2P participant message secure writer
            ([0xff, 0x02, 0x02, 0xc3], true),  // participant volatile message secure writer
            ([0x00, 0x02, 0x01, 0xc3], true),  // participant stateless message writer
            ([0x00, 0x00, 0x01, 0x02], false), // a user writer
            ([0x00, 0x00, 0x12, 0x03], false), // another user writer
        ];

        for (writer, is_builtin) in ENDPOINTS {
            let as_data = classify_rtps(&datagram(
                [0x01, 0x05],
                &[data_submessage(writer, &[0x00, 0x03, 0x00, 0x00])],
            ))
            .0;
            let as_frag =
                classify_rtps(&datagram([0x01, 0x05], &[data_frag_submessage(writer, 40)])).0;

            assert_eq!(
                as_data != PacketKind::Data,
                is_builtin,
                "writer {writer:02x?} was declared builtin={is_builtin} but reads as {as_data:?}"
            );

            // The one difference the two readers are ALLOWED to have: a
            // submessage no builtin endpoint owns is named after the
            // submessage that carried it.
            let expected = if is_builtin {
                as_data
            } else {
                PacketKind::DataFrag
            };
            assert_eq!(
                as_frag, expected,
                "writer {writer:02x?} is {as_data:?} as a DATA and {as_frag:?} as a DATA_FRAG"
            );
        }
    }

    // ---------------------------------------------------------------
    // A submessage is described by the octets it OWNS
    // ---------------------------------------------------------------

    /// A DATA_FRAG (0x16) whose octetsToNextHeader declares a 20-octet body:
    /// twelve short of the 32 fixed fields RTPS v2.5 Sec.8.3.8.3 gives it.
    /// Its fragmentStartingNum, fragmentsInSubmessage, fragmentSize and
    /// sampleSize are therefore NOT in it, and whatever follows holds the
    /// octets at those positions.
    fn a_data_frag_missing_its_fragment_fields(writer_entity: [u8; 4]) -> Vec<u8> {
        let mut submessage = vec![0x16, 0x01];
        submessage.extend_from_slice(&20u16.to_le_bytes());
        submessage.extend_from_slice(&[0x00, 0x00]); // extraFlags
        submessage.extend_from_slice(&28u16.to_le_bytes()); // octetsToInlineQos
        submessage.extend_from_slice(&[0x00; 4]); // readerEntityId
        submessage.extend_from_slice(&writer_entity);
        submessage.extend_from_slice(&[0x00; 4]); // writerSN high
        submessage.extend_from_slice(&5u32.to_le_bytes()); // writerSN low
        assert_eq!(
            submessage.len(),
            24,
            "fixture: 4 header octets and the 20 the body declares"
        );
        submessage
    }

    /// The same shape cut off by the end of the datagram instead: the first
    /// 24 octets of a DATA_FRAG, declared last (octetsToNextHeader 0) so the
    /// walk still visits it.
    fn a_data_frag_cut_off_by_the_datagram(writer_entity: [u8; 4]) -> Vec<u8> {
        let mut submessage = a_data_frag_missing_its_fragment_fields(writer_entity);
        submessage[2..4].copy_from_slice(&0u16.to_le_bytes());
        submessage
    }

    /// The submessage that supplies what the one before it left out.
    ///
    /// A PAD (0x01, RTPS v2.5 Sec.8.3.3) is four header octets and a body
    /// nobody reads. Read twelve octets early, its header is little-endian
    /// `01 00 00 00` = fragmentStartingNum 1, and its body then reads as
    /// fragmentsInSubmessage 1, fragmentSize 8 and sampleSize 16. Nothing
    /// here is chosen to be plausible: a PAD is the shortest submessage RTPS
    /// has, and 1 is the first fragment number a writer has.
    fn a_pad_whose_octets_describe_a_fragment() -> Vec<u8> {
        let mut submessage = vec![0x01, 0x00, 0x00, 0x00];
        submessage.extend_from_slice(&1u16.to_le_bytes());
        submessage.extend_from_slice(&8u16.to_le_bytes());
        submessage.extend_from_slice(&16u32.to_le_bytes());
        submessage.extend_from_slice(&[0xDE; 16]);
        submessage
    }

    /// A PAD whose header is what a runaway parameter scan takes for the end
    /// of a list: `01 00` little-endian is PID_SENTINEL, and `00 00` the
    /// length that follows it.
    fn a_pad_read_as_a_sentinel() -> Vec<u8> {
        let mut submessage = vec![0x01, 0x00, 0x00, 0x00];
        submessage.extend_from_slice(&[0xCC; 24]);
        submessage
    }

    /// A DATA_FRAG with the Q flag set whose inline-QoS list fills its body
    /// without ever reaching a sentinel: there is nothing inside the
    /// submessage for the scan to find.
    fn a_data_frag_whose_inline_qos_has_no_sentinel(writer_entity: [u8; 4]) -> Vec<u8> {
        let mut submessage = vec![0x16, 0x03]; // E and Q
        submessage.extend_from_slice(&(32u16 + 16).to_le_bytes());
        submessage.extend_from_slice(&[0x00, 0x00]); // extraFlags
        submessage.extend_from_slice(&28u16.to_le_bytes()); // octetsToInlineQos
        submessage.extend_from_slice(&[0x00; 4]); // readerEntityId
        submessage.extend_from_slice(&writer_entity);
        submessage.extend_from_slice(&[0x00; 4]); // writerSN high
        submessage.extend_from_slice(&1u32.to_le_bytes()); // writerSN low
        submessage.extend_from_slice(&1u32.to_le_bytes()); // fragmentStartingNum
        submessage.extend_from_slice(&1u16.to_le_bytes()); // fragmentsInSubmessage
        submessage.extend_from_slice(&8u16.to_le_bytes()); // fragmentSize
        submessage.extend_from_slice(&16u32.to_le_bytes()); // sampleSize
        submessage.extend_from_slice(&0x0050u16.to_le_bytes()); // a PID, not a sentinel
        submessage.extend_from_slice(&12u16.to_le_bytes());
        submessage.extend_from_slice(&[0x77; 12]);
        submessage
    }

    /// The same for a DATA (0x15): Q set, an inline-QoS list with no
    /// sentinel in it, sent by the SPDP writer so the classifier answers
    /// SPDP and the offset is handed to the participant-announcement parser.
    fn a_data_whose_inline_qos_has_no_sentinel(writer_entity: [u8; 4]) -> Vec<u8> {
        let mut submessage = vec![0x15, 0x03]; // E and Q
        submessage.extend_from_slice(&(20u16 + 16).to_le_bytes());
        submessage.extend_from_slice(&[0x00, 0x00]); // extraFlags
        submessage.extend_from_slice(&16u16.to_le_bytes()); // octetsToInlineQos
        submessage.extend_from_slice(&[0x00; 4]); // readerEntityId
        submessage.extend_from_slice(&writer_entity);
        submessage.extend_from_slice(&[0x00; 8]); // writerSN
        submessage.extend_from_slice(&0x0050u16.to_le_bytes()); // a PID, not a sentinel
        submessage.extend_from_slice(&12u16.to_le_bytes());
        submessage.extend_from_slice(&[0x77; 12]);
        submessage
    }

    /// A DATA_FRAG whose own submessage does not hold its 32 fixed octets
    /// describes NOTHING, because the octets that would describe it belong
    /// to the submessage beside it.
    ///
    /// On this datagram the classifier must not answer with writer
    /// 00.00.03.04, sequence 5, fragment 1 of 2 and a payload offset of 56,
    /// while the DATA_FRAG's body ends at 44: every one of those numbers would
    /// come from the PAD. `route_data_frag_packet` would then buffer sixteen
    /// of the PAD's octets as fragment 1 of that sample and go on asking the
    /// peer for fragment 2 - see
    /// `a_data_frag_shorter_than_its_own_header_buffers_nothing`.
    #[test]
    fn a_data_frag_shorter_than_its_own_header_describes_nothing() {
        const FRAG_AT: usize = 20;
        let short = a_data_frag_missing_its_fragment_fields([0x00, 0x00, 0x03, 0x04]);
        let body_end = FRAG_AT + short.len();
        let packet = datagram(
            [0x01, 0x1A],
            &[short, a_pad_whose_octets_describe_a_fragment()],
        );

        // The shape first. A test whose fixture stops posing the question
        // passes for the wrong reason, and a routing change is enough to do
        // that to it.
        assert!(
            FRAG_AT + 36 > body_end,
            "fixture: the DATA_FRAG's 32 fixed octets must NOT fit in its own body"
        );
        assert!(
            FRAG_AT + 36 <= packet.len(),
            "fixture: they must fit in the DATAGRAM, or a bound against the \
             datagram would refuse this for the right answer by accident"
        );

        let (_kind, payload_offset, fragment_metadata, _ctx) = classify_rtps(&packet);
        assert!(
            fragment_metadata.is_none(),
            "a DATA_FRAG that does not carry its own fragment fields describes \
             no fragment, and this one answered {fragment_metadata:?}"
        );
        assert_eq!(
            payload_offset, None,
            "and it names no payload either: the only offset available is \
             inside the PAD"
        );
        assert!(
            super::super::scan_all_data_frags(&packet).is_empty(),
            "the scan reads the same fields and must reach the same verdict"
        );
    }

    /// The writer a DATA_FRAG is named after must be inside it too.
    ///
    /// This one declares an 8-octet body, so its writerEntityId lies past its
    /// own end and the four octets at that position are the next
    /// submessage's header. Read against the datagram, they are
    /// `00 01 00 c2` - the SPDP writer - and the datagram is classified as a
    /// participant announcement on the strength of octets it does not own.
    #[test]
    fn a_data_frag_is_not_named_after_a_writer_outside_it() {
        const FRAG_AT: usize = 20;
        let mut short = vec![0x16u8, 0x01];
        short.extend_from_slice(&8u16.to_le_bytes());
        short.extend_from_slice(&[0x00, 0x00]); // extraFlags
        short.extend_from_slice(&28u16.to_le_bytes()); // octetsToInlineQos
        short.extend_from_slice(&[0x00; 4]); // readerEntityId
        let body_end = FRAG_AT + short.len();

        // Where the writerEntityId would be read: the octets of whatever
        // comes next, which here spell the SPDP builtin writer.
        let mut next = vec![0x00u8, 0x01, 0x00, 0xc2];
        next.extend_from_slice(&[0x00; 4]);

        let packet = datagram([0x01, 0x1A], &[short, next]);
        assert!(
            FRAG_AT + 16 > body_end,
            "fixture: the writerEntityId must lie past the submessage"
        );
        assert_eq!(
            &packet[FRAG_AT + 12..FRAG_AT + 16],
            &[0x00, 0x01, 0x00, 0xc2],
            "fixture: and the octets there must name a builtin writer, or the \
             mutation this pins changes nothing"
        );

        // Asked of the reader itself, because the datagram-level answer does
        // not separate the two outcomes: a DATA_FRAG that yields no
        // metadata is refused whatever its kind, so both the bounded read
        // and the unbounded one come out `Unknown` up there. Read against
        // the datagram this returns SPDP, and that unbounded read is what this
        // test pins against.
        let mut borrowed: Option<FragmentMetadata> = None;
        let (kind_of_the_submessage, yielded) = submessage::classify_data_frag(
            &packet,
            FRAG_AT,
            body_end,
            0x01,
            [0x0A; 12],
            &mut borrowed,
        );
        assert_eq!(
            kind_of_the_submessage,
            PacketKind::DataFrag,
            "a submessage too short to hold its own writerEntityId is not an \
             announcement from the writer standing behind it"
        );
        assert!(!yielded, "and it describes no fragment either");
        assert!(borrowed.is_none(), "so it publishes no metadata");

        let (kind, payload_offset, fragment_metadata, _ctx) = classify_rtps(&packet);
        assert_eq!(
            kind,
            PacketKind::Unknown,
            "and a submessage that describes nothing names nothing"
        );
        assert!(fragment_metadata.is_none());
        assert!(payload_offset.is_none());
    }

    /// A DATA_FRAG the reader refused does not get to answer for the datagram.
    ///
    /// `[DATA_FRAG complete, DATA_FRAG cut off by the end of the datagram]`.
    /// The admission rule must not ask whether fragment metadata existed at
    /// all, which is a property of the DATAGRAM, not of the submessage being
    /// judged: the truncated one would inherit the complete one's "yes" and
    /// rewrite the payload offset for itself, so this datagram would come out
    /// with the first fragment's metadata and an offset of 100 - past the
    /// end of its own 88 octets.
    #[test]
    fn a_refused_data_frag_does_not_move_the_payload_offset() {
        const COMPLETE_AT: usize = 20;
        let complete = data_frag_submessage([0x00, 0x00, 0x01, 0x02], 8);
        let truncated_at = COMPLETE_AT + complete.len();
        let packet = datagram(
            [0x01, 0x1A],
            &[
                complete,
                a_data_frag_cut_off_by_the_datagram([0x00, 0x00, 0x03, 0x04]),
            ],
        );

        assert!(
            truncated_at + 36 > packet.len(),
            "fixture: the second DATA_FRAG must be the one the datagram cuts short"
        );

        let (_kind, payload_offset, fragment_metadata, _ctx) = classify_rtps(&packet);
        assert_eq!(
            payload_offset,
            Some(COMPLETE_AT + 36),
            "the payload named must be the one submessage that described itself"
        );
        let meta = fragment_metadata.expect("the complete DATA_FRAG describes itself");
        assert_eq!(
            meta.writer_guid.entity_id,
            [0x00, 0x00, 0x01, 0x02],
            "and its metadata must belong to that same submessage"
        );
    }

    /// An inline-QoS list with no sentinel in it ends where its submessage
    /// does, not where the next submessage happens to hold `01 00`.
    ///
    /// Unbounded, the scan would walk out of the DATA_FRAG, read the PAD's
    /// header as PID_SENTINEL and answer 76 for a submessage whose body ends
    /// at 72.
    #[test]
    fn a_data_frag_inline_qos_scan_stops_at_its_own_submessage() {
        const FRAG_AT: usize = 20;
        let frag = a_data_frag_whose_inline_qos_has_no_sentinel([0x00, 0x00, 0x01, 0x02]);
        let body_end = FRAG_AT + frag.len();
        let packet = datagram([0x01, 0x1A], &[frag, a_pad_read_as_a_sentinel()]);

        assert_eq!(
            &packet[body_end..body_end + 2],
            &[0x01, 0x00],
            "fixture: the octets just past the submessage must read as PID_SENTINEL"
        );

        let (kind, payload_offset, meta, _ctx) = classify_rtps(&packet);
        // An inline QoS with no sentinel is an invalid inlineQos, which makes
        // the submessage invalid (RTPS v2.5 Sec.8.3.8.2 Validity), and an
        // invalid submessage is ignored (Sec.8.3.4.1): no payload offset, no
        // fragment, and it names nothing.
        assert_eq!(payload_offset, None, "an invalid DATA_FRAG has no payload");
        assert!(meta.is_none(), "nor a fragment");
        assert_eq!(kind, PacketKind::Unknown, "and names nothing");
    }

    /// The same rule on the DATA path, which is the one that carries
    /// participant announcements: the offset the classifier publishes for an
    /// SPDP DATA must be inside that DATA.
    ///
    /// Without the bound: body ending at 60, offset 64 - the announcement
    /// parser would be handed the PAD's body, as a peer would be registered
    /// out of the following HEARTBEAT's header.
    #[test]
    fn a_data_inline_qos_scan_stops_at_its_own_submessage() {
        const DATA_AT: usize = 20;
        let data = a_data_whose_inline_qos_has_no_sentinel([0x00, 0x01, 0x00, 0xc2]);
        let body_end = DATA_AT + data.len();
        let packet = datagram([0x01, 0x1A], &[data, a_pad_read_as_a_sentinel()]);

        assert_eq!(
            &packet[body_end..body_end + 2],
            &[0x01, 0x00],
            "fixture: the octets just past the submessage must read as PID_SENTINEL"
        );

        assert_eq!(
            submessage::classify_data(&packet, DATA_AT, body_end),
            PacketKind::SPDP,
            "fixture: this must reach the announcement parser to matter"
        );
        // Invalid (an inlineQos with no sentinel, RTPS v2.5 Sec.8.3.8.2),
        // so ignored (Sec.8.3.4.1): never handed to the announcement parser,
        // at an offset in this submessage or in the one next door.
        let (kind, payload_offset, _meta, _ctx) = classify_rtps(&packet);
        assert_eq!(payload_offset, None, "an invalid DATA has no payload");
        assert_eq!(kind, PacketKind::Unknown, "and names nothing");
        let mut visited = 0;
        for_each_data_submessage(&packet, |_| visited += 1);
        assert_eq!(visited, 0, "nor does the discovery walk visit it");
    }
}
