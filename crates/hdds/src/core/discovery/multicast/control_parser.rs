// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! RTPS control message parsers (HEARTBEAT, ACKNACK).
//!

use super::control_types::{AckNackInfo, HeartbeatInfo, NackFragInfo};

/// Parse HEARTBEAT submessage from RTPS packet
///
/// Returns parsed HeartbeatInfo if successful
pub fn parse_heartbeat_submessage(packet: &[u8]) -> Option<HeartbeatInfo> {
    // Need at least RTPS header (20) + submessage header (4) + HEARTBEAT body (28)
    if packet.len() < 52 {
        log::trace!("[PARSE-HB] v189: Packet too small: {} < 52", packet.len());
        return None;
    }

    // Verify RTPS magic
    if &packet[0..4] != b"RTPS" {
        log::trace!("[PARSE-HB] v189: Invalid RTPS magic");
        return None;
    }

    // Find HEARTBEAT submessage (ID = 0x07)
    let mut offset = 20; // Start after RTPS header

    while offset + 4 <= packet.len() {
        let submsg_id = packet[offset];
        let flags = packet[offset + 1];
        let is_le = flags & 0x01 != 0;

        let octets_to_next = if is_le {
            u16::from_le_bytes([packet[offset + 2], packet[offset + 3]]) as usize
        } else {
            u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]) as usize
        };

        if submsg_id == 0x07 {
            // HEARTBEAT found
            let hb_offset = offset + 4;

            if hb_offset + 28 > packet.len() {
                return None;
            }

            // writerEntityId: 4 bytes at +4 (after readerEntityId)
            let writer_entity_id: [u8; 4] = packet[hb_offset + 4..hb_offset + 8].try_into().ok()?;

            // firstSeq: SequenceNumber_t {high: i32, low: u32} at +8
            let first_seq = if is_le {
                let high =
                    i32::from_le_bytes(packet[hb_offset + 8..hb_offset + 12].try_into().ok()?);
                let low =
                    u32::from_le_bytes(packet[hb_offset + 12..hb_offset + 16].try_into().ok()?);
                (high as i64) * (1i64 << 32) + (low as i64)
            } else {
                let high =
                    i32::from_be_bytes(packet[hb_offset + 8..hb_offset + 12].try_into().ok()?);
                let low =
                    u32::from_be_bytes(packet[hb_offset + 12..hb_offset + 16].try_into().ok()?);
                (high as i64) * (1i64 << 32) + (low as i64)
            };

            // lastSeq: SequenceNumber_t at +16
            let last_seq = if is_le {
                let high =
                    i32::from_le_bytes(packet[hb_offset + 16..hb_offset + 20].try_into().ok()?);
                let low =
                    u32::from_le_bytes(packet[hb_offset + 20..hb_offset + 24].try_into().ok()?);
                (high as i64) * (1i64 << 32) + (low as i64)
            } else {
                let high =
                    i32::from_be_bytes(packet[hb_offset + 16..hb_offset + 20].try_into().ok()?);
                let low =
                    u32::from_be_bytes(packet[hb_offset + 20..hb_offset + 24].try_into().ok()?);
                (high as i64) * (1i64 << 32) + (low as i64)
            };

            // count: u32 at +24
            let count = if is_le {
                u32::from_le_bytes(packet[hb_offset + 24..hb_offset + 28].try_into().ok()?)
            } else {
                u32::from_be_bytes(packet[hb_offset + 24..hb_offset + 28].try_into().ok()?)
            };

            // Flags: bit 1 = FinalFlag, bit 2 = LivelinessFlag
            let final_flag = flags & 0x02 != 0;
            let liveliness_flag = flags & 0x04 != 0;

            return Some(HeartbeatInfo {
                writer_entity_id,
                first_seq,
                last_seq,
                count,
                final_flag,
                liveliness_flag,
            });
        }

        // Move to next submessage
        if octets_to_next == 0 {
            break;
        }
        offset += 4 + octets_to_next;
    }

    None
}

/// v210: Parse ALL HEARTBEAT submessages from a multi-submessage RTPS packet.
///
/// FastDDS bundles HBs for multiple writers (03C2, 04C2, 0200C2) in one packet.
/// Previous `parse_heartbeat_submessage()` only extracted the first one,
/// causing the other SEDP writers' HBs to be silently dropped.
pub fn parse_all_heartbeat_submessages(packet: &[u8]) -> Vec<HeartbeatInfo> {
    let mut results = Vec::new();

    if packet.len() < 52 || &packet[0..4] != b"RTPS" {
        return results;
    }

    let mut offset = 20; // Start after RTPS header

    while offset + 4 <= packet.len() {
        let submsg_id = packet[offset];
        let flags = packet[offset + 1];
        let is_le = flags & 0x01 != 0;

        let octets_to_next = if is_le {
            u16::from_le_bytes([packet[offset + 2], packet[offset + 3]]) as usize
        } else {
            u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]) as usize
        };

        if submsg_id == 0x07 {
            // HEARTBEAT found
            let hb_offset = offset + 4;

            if hb_offset + 28 <= packet.len() {
                if let Ok(writer_entity_id) = packet[hb_offset + 4..hb_offset + 8].try_into() {
                    let writer_entity_id: [u8; 4] = writer_entity_id;

                    let first_seq = if is_le {
                        let high = i32::from_le_bytes(
                            packet[hb_offset + 8..hb_offset + 12]
                                .try_into()
                                .unwrap_or([0; 4]),
                        );
                        let low = u32::from_le_bytes(
                            packet[hb_offset + 12..hb_offset + 16]
                                .try_into()
                                .unwrap_or([0; 4]),
                        );
                        (high as i64) * (1i64 << 32) + (low as i64)
                    } else {
                        let high = i32::from_be_bytes(
                            packet[hb_offset + 8..hb_offset + 12]
                                .try_into()
                                .unwrap_or([0; 4]),
                        );
                        let low = u32::from_be_bytes(
                            packet[hb_offset + 12..hb_offset + 16]
                                .try_into()
                                .unwrap_or([0; 4]),
                        );
                        (high as i64) * (1i64 << 32) + (low as i64)
                    };

                    let last_seq = if is_le {
                        let high = i32::from_le_bytes(
                            packet[hb_offset + 16..hb_offset + 20]
                                .try_into()
                                .unwrap_or([0; 4]),
                        );
                        let low = u32::from_le_bytes(
                            packet[hb_offset + 20..hb_offset + 24]
                                .try_into()
                                .unwrap_or([0; 4]),
                        );
                        (high as i64) * (1i64 << 32) + (low as i64)
                    } else {
                        let high = i32::from_be_bytes(
                            packet[hb_offset + 16..hb_offset + 20]
                                .try_into()
                                .unwrap_or([0; 4]),
                        );
                        let low = u32::from_be_bytes(
                            packet[hb_offset + 20..hb_offset + 24]
                                .try_into()
                                .unwrap_or([0; 4]),
                        );
                        (high as i64) * (1i64 << 32) + (low as i64)
                    };

                    let count = if is_le {
                        u32::from_le_bytes(
                            packet[hb_offset + 24..hb_offset + 28]
                                .try_into()
                                .unwrap_or([0; 4]),
                        )
                    } else {
                        u32::from_be_bytes(
                            packet[hb_offset + 24..hb_offset + 28]
                                .try_into()
                                .unwrap_or([0; 4]),
                        )
                    };

                    let final_flag = flags & 0x02 != 0;
                    let liveliness_flag = flags & 0x04 != 0;

                    results.push(HeartbeatInfo {
                        writer_entity_id,
                        first_seq,
                        last_seq,
                        count,
                        final_flag,
                        liveliness_flag,
                    });
                }
            }
        }

        // Move to next submessage
        if octets_to_next == 0 {
            break;
        }
        offset += 4 + octets_to_next;
    }

    results
}

/// Parse ACKNACK submessage from RTPS packet (v137, v202)
///
/// Returns parsed AckNackInfo if successful.
/// ACKNACK structure (RTPS 2.5 Sec.8.3.7.4):
/// - readerEntityId: 4 bytes
/// - writerEntityId: 4 bytes
/// - readerSNState: SequenceNumberSet (bitmapBase:8 + numBits:4 + bitmap:variable)
/// - count: 4 bytes
///
/// v202: Now also extracts missing_ranges from the RTPS bitmap for retransmission.
/// The bitmap encodes which sequences are MISSING (bit=1) vs received (bit=0).
pub fn parse_acknack_submessage(packet: &[u8]) -> Option<AckNackInfo> {
    // Need at least RTPS header (20) + submessage header (4) + ACKNACK body (minimum 20)
    // ACKNACK body: readerEntityId(4) + writerEntityId(4) + bitmapBase(8) + numBits(4) = 20 min
    if packet.len() < 44 {
        return None;
    }

    // Verify RTPS magic
    if &packet[0..4] != b"RTPS" {
        return None;
    }

    // Find ACKNACK submessage (ID = 0x06)
    let mut offset = 20; // Start after RTPS header

    while offset + 4 <= packet.len() {
        let submsg_id = packet[offset];
        let flags = packet[offset + 1];
        let is_le = flags & 0x01 != 0;

        let octets_to_next = if is_le {
            u16::from_le_bytes([packet[offset + 2], packet[offset + 3]]) as usize
        } else {
            u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]) as usize
        };

        if submsg_id == 0x06 {
            // ACKNACK found
            let an_offset = offset + 4;

            if an_offset + 20 > packet.len() {
                return None;
            }

            // readerEntityId: 4 bytes at +0
            let reader_entity_id: [u8; 4] = packet[an_offset..an_offset + 4].try_into().ok()?;

            // writerEntityId: 4 bytes at +4
            let writer_entity_id: [u8; 4] = packet[an_offset + 4..an_offset + 8].try_into().ok()?;

            // v202: Extract readerSNState (SequenceNumberSet) for retransmission
            // bitmapBase: 8 bytes at +8 (SequenceNumber_t = high:i32 + low:u32)
            // numBits: 4 bytes at +16 (u32)
            // bitmap: variable, (numBits + 31) / 32 * 4 bytes
            //
            // v211: RTPS SequenceNumber_t is NOT a single i64, it's two words:
            //   - First 4 bytes: high word (signed i32)
            //   - Next 4 bytes: low word (unsigned u32)
            // The endianness flag affects each word individually, NOT the combined layout.
            // Combined value = (high << 32) | low
            let (sn_high, sn_low) = if is_le {
                let high =
                    i32::from_le_bytes(packet[an_offset + 8..an_offset + 12].try_into().ok()?);
                let low =
                    u32::from_le_bytes(packet[an_offset + 12..an_offset + 16].try_into().ok()?);
                (high, low)
            } else {
                let high =
                    i32::from_be_bytes(packet[an_offset + 8..an_offset + 12].try_into().ok()?);
                let low =
                    u32::from_be_bytes(packet[an_offset + 12..an_offset + 16].try_into().ok()?);
                (high, low)
            };
            // Combine into 64-bit sequence number (high can be negative for special values)
            let bitmap_base = ((sn_high as i64) << 32) | (sn_low as i64);

            let num_bits = if is_le {
                u32::from_le_bytes(packet[an_offset + 16..an_offset + 20].try_into().ok()?)
            } else {
                u32::from_be_bytes(packet[an_offset + 16..an_offset + 20].try_into().ok()?)
            };

            // Convert RTPS bitmap to missing_ranges
            let missing_ranges = parse_rtps_bitmap_to_ranges(
                &packet[an_offset + 20..],
                bitmap_base as u64,
                num_bits,
                is_le,
            );

            return Some(AckNackInfo {
                reader_entity_id,
                writer_entity_id,
                missing_ranges,
            });
        }

        // Move to next submessage
        if octets_to_next == 0 {
            break;
        }
        offset += 4 + octets_to_next;
    }

    None
}

/// v202/v205: Convert RTPS SequenceNumberSet bitmap to missing sequence ranges.
///
/// HDDS ACKNACK bitmap semantics (matching our builder in acknack.rs):
/// - bitmapBase is the first sequence number in the set
/// - Bit N corresponds to sequence (bitmapBase + N)
/// - Bit value 1 = sequence is MISSING (reader doesn't have it, needs retransmit)
/// - Bit value 0 = sequence is RECEIVED (reader already has it)
///
/// NOTE: This follows HDDS's internal convention where bit=1 means MISSING.
/// The builder (build_acknack_packet_with_final) sets bits for missing sequences,
/// so the parser must interpret them the same way for HDDS-to-HDDS interop.
///
/// This function extracts contiguous ranges of missing sequences.
fn parse_rtps_bitmap_to_ranges(
    bitmap_bytes: &[u8],
    bitmap_base: u64,
    num_bits: u32,
    is_le: bool,
) -> Vec<std::ops::Range<u64>> {
    let mut ranges = Vec::new();

    if num_bits == 0 {
        return ranges;
    }

    // Limit num_bits to reasonable value (256 per RTPS spec)
    let num_bits = num_bits.min(256) as usize;
    let word_count = num_bits.div_ceil(32);

    if bitmap_bytes.len() < word_count * 4 {
        return ranges;
    }

    let mut range_start: Option<u64> = None;

    for bit_idx in 0..num_bits {
        let word_idx = bit_idx / 32;
        let bit_in_word = bit_idx % 32;

        let word_offset = word_idx * 4;
        let word = if is_le {
            u32::from_le_bytes(
                bitmap_bytes[word_offset..word_offset + 4]
                    .try_into()
                    .unwrap_or([0; 4]),
            )
        } else {
            u32::from_be_bytes(
                bitmap_bytes[word_offset..word_offset + 4]
                    .try_into()
                    .unwrap_or([0; 4]),
            )
        };

        // v205: RTPS bitmap bit ordering - bit 0 is MSB (bit 31 of first word)
        // HDDS convention: bit=1 means MISSING (matches our builder)
        let bit_mask = 1u32 << (31 - bit_in_word);
        let is_missing = (word & bit_mask) != 0; // v205: bit=1 -> MISSING
                                                 // v232: Use saturating_add to prevent overflow panic on malformed packets
        let seq = bitmap_base.saturating_add(bit_idx as u64);

        if is_missing {
            if range_start.is_none() {
                range_start = Some(seq);
            }
        } else if let Some(start) = range_start {
            ranges.push(start..seq);
            range_start = None;
        }
    }

    // Close any open range at the end
    if let Some(start) = range_start {
        // v232: Use saturating_add to prevent overflow panic
        ranges.push(start..bitmap_base.saturating_add(num_bits as u64));
    }

    ranges
}

/// Parse NACK_FRAG submessage from RTPS packet (RTPS v2.3 Sec.8.3.7.5)
///
/// Returns parsed NackFragInfo if successful.
/// NACK_FRAG structure:
/// - readerEntityId: 4 bytes
/// - writerEntityId: 4 bytes
/// - writerSN: 8 bytes (SequenceNumber_t = high:i32 + low:u32)
/// - fragmentNumberState: bitmapBase(4) + numBits(4) + bitmap(variable)
/// - count: 4 bytes
pub fn parse_nack_frag_submessage(packet: &[u8]) -> Option<NackFragInfo> {
    // Need at least RTPS header (20) + submessage header (4) + NACK_FRAG body (minimum 24)
    // NACK_FRAG body: readerEntityId(4) + writerEntityId(4) + writerSN(8) + bitmapBase(4) + numBits(4) = 24 min
    if packet.len() < 48 {
        return None;
    }

    // Verify RTPS magic
    if &packet[0..4] != b"RTPS" {
        return None;
    }

    // Find NACK_FRAG submessage (ID = 0x12)
    let mut offset = 20; // Start after RTPS header

    while offset + 4 <= packet.len() {
        let submsg_id = packet[offset];
        let flags = packet[offset + 1];
        let is_le = flags & 0x01 != 0;

        let octets_to_next = if is_le {
            u16::from_le_bytes([packet[offset + 2], packet[offset + 3]]) as usize
        } else {
            u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]) as usize
        };

        if submsg_id == 0x12 {
            // NACK_FRAG found
            let nf_offset = offset + 4;

            if nf_offset + 24 > packet.len() {
                return None;
            }

            // readerEntityId: 4 bytes at +0
            let reader_entity_id: [u8; 4] = packet[nf_offset..nf_offset + 4].try_into().ok()?;

            // writerEntityId: 4 bytes at +4
            let writer_entity_id: [u8; 4] = packet[nf_offset + 4..nf_offset + 8].try_into().ok()?;

            // writerSN: 8 bytes at +8 (SequenceNumber_t = high:i32 + low:u32)
            let (sn_high, sn_low) = if is_le {
                let high =
                    i32::from_le_bytes(packet[nf_offset + 8..nf_offset + 12].try_into().ok()?);
                let low =
                    u32::from_le_bytes(packet[nf_offset + 12..nf_offset + 16].try_into().ok()?);
                (high, low)
            } else {
                let high =
                    i32::from_be_bytes(packet[nf_offset + 8..nf_offset + 12].try_into().ok()?);
                let low =
                    u32::from_be_bytes(packet[nf_offset + 12..nf_offset + 16].try_into().ok()?);
                (high, low)
            };
            let writer_sn = ((sn_high as i64) << 32) | (sn_low as i64);

            // fragmentNumberState.bitmapBase: 4 bytes at +16 (first fragment number, u32)
            let bitmap_base = if is_le {
                u32::from_le_bytes(packet[nf_offset + 16..nf_offset + 20].try_into().ok()?)
            } else {
                u32::from_be_bytes(packet[nf_offset + 16..nf_offset + 20].try_into().ok()?)
            };

            // fragmentNumberState.numBits: 4 bytes at +20
            let num_bits = if is_le {
                u32::from_le_bytes(packet[nf_offset + 20..nf_offset + 24].try_into().ok()?)
            } else {
                u32::from_be_bytes(packet[nf_offset + 20..nf_offset + 24].try_into().ok()?)
            };

            // Parse bitmap to get missing fragment numbers
            let bitmap_offset = nf_offset + 24;
            let missing_fragments =
                parse_fragment_bitmap(&packet[bitmap_offset..], bitmap_base, num_bits, is_le);

            // count: after bitmap
            let bitmap_words = num_bits.div_ceil(32) as usize;
            let count_offset = bitmap_offset + bitmap_words * 4;
            let count = if count_offset + 4 <= packet.len() {
                if is_le {
                    u32::from_le_bytes(packet[count_offset..count_offset + 4].try_into().ok()?)
                } else {
                    u32::from_be_bytes(packet[count_offset..count_offset + 4].try_into().ok()?)
                }
            } else {
                0
            };

            return Some(NackFragInfo {
                reader_entity_id,
                writer_entity_id,
                writer_sn: writer_sn as u64,
                missing_fragments,
                count,
            });
        }

        // Move to next submessage
        if octets_to_next == 0 {
            break;
        }
        offset += 4 + octets_to_next;
    }

    None
}

/// Parse fragment bitmap to get list of missing fragment numbers.
///
/// NACK_FRAG uses fragmentNumberState (similar to SequenceNumberSet but for fragments).
/// - bitmapBase is the first fragment number (1-based per RTPS spec)
/// - Bit N corresponds to fragment (bitmapBase + N)
/// - Bit value 1 = fragment is MISSING
/// - Bit value 0 = fragment is received
fn parse_fragment_bitmap(
    bitmap_bytes: &[u8],
    bitmap_base: u32,
    num_bits: u32,
    is_le: bool,
) -> Vec<u32> {
    let mut missing = Vec::new();

    if num_bits == 0 {
        return missing;
    }

    // Limit num_bits to reasonable value (256 per RTPS spec)
    // Keep native u32 type for consistency with bitmap_base
    let num_bits = num_bits.min(256);
    let word_count = num_bits.div_ceil(32) as usize;

    if bitmap_bytes.len() < word_count * 4 {
        return missing;
    }

    for bit_idx in 0..num_bits {
        let word_idx = (bit_idx / 32) as usize;
        let bit_in_word = bit_idx % 32;

        let word_offset = word_idx * 4;
        let word = if is_le {
            u32::from_le_bytes(
                bitmap_bytes[word_offset..word_offset + 4]
                    .try_into()
                    .unwrap_or([0; 4]),
            )
        } else {
            u32::from_be_bytes(
                bitmap_bytes[word_offset..word_offset + 4]
                    .try_into()
                    .unwrap_or([0; 4]),
            )
        };

        // RTPS bitmap bit ordering - bit 0 is MSB (bit 31 of first word)
        let bit_mask = 1u32 << (31 - bit_in_word);
        let is_missing = (word & bit_mask) != 0;

        if is_missing {
            // v232: Use saturating_add to prevent overflow panic on malformed packets
            missing.push(bitmap_base.saturating_add(bit_idx));
        }
    }

    missing
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_heartbeat() {
        // Build minimal HEARTBEAT packet
        let mut packet = Vec::new();

        // RTPS Header (20 bytes)
        packet.extend_from_slice(b"RTPS");
        packet.extend_from_slice(&[2, 4]); // Version
        packet.extend_from_slice(&[0x01, 0x0f]); // FastDDS vendor
        packet.extend_from_slice(&[0x01; 12]); // GUID prefix

        // HEARTBEAT submessage
        packet.push(0x07); // ID
        packet.push(0x03); // Flags: little-endian + FinalFlag
        packet.extend_from_slice(&28u16.to_le_bytes()); // Length

        // readerEntityId
        packet.extend_from_slice(&[0x00, 0x00, 0x01, 0x04]);
        // writerEntityId
        packet.extend_from_slice(&[0x00, 0x00, 0x01, 0x03]);
        // firstSeq: {high=0, low=1}
        packet.extend_from_slice(&0i32.to_le_bytes());
        packet.extend_from_slice(&1u32.to_le_bytes());
        // lastSeq: {high=0, low=5}
        packet.extend_from_slice(&0i32.to_le_bytes());
        packet.extend_from_slice(&5u32.to_le_bytes());
        // count
        packet.extend_from_slice(&42u32.to_le_bytes());

        let hb = parse_heartbeat_submessage(&packet).expect("Should parse");
        assert_eq!(hb.writer_entity_id, [0x00, 0x00, 0x01, 0x03]);
        assert_eq!(hb.first_seq, 1);
        assert_eq!(hb.last_seq, 5);
        assert_eq!(hb.count, 42);
        assert!(hb.final_flag);
        assert!(!hb.liveliness_flag);
    }

    #[test]
    fn test_parse_bitmap_to_ranges_empty() {
        let ranges = parse_rtps_bitmap_to_ranges(&[], 1, 0, true);
        assert!(ranges.is_empty());
    }

    #[test]
    fn test_parse_bitmap_to_ranges_single_missing() {
        // Bitmap with bit 0 set (MSB) = sequence 1 missing
        // When is_le=false, [0x80, 0x00, 0x00, 0x00] is read as 0x80_00_00_00 (BE)
        // Bit 0 (MSB = bit 31) is then correctly detected as set
        let bitmap = [0x80, 0x00, 0x00, 0x00]; // bit 0 set in MSB
        let ranges = parse_rtps_bitmap_to_ranges(&bitmap, 1, 1, false);
        assert_eq!(ranges, vec![1..2]);
    }

    #[test]
    fn test_parse_bitmap_to_ranges_single_missing_le() {
        // For little-endian encoded packets, [0x00, 0x00, 0x00, 0x80] is read as 0x80_00_00_00
        // which has bit 31 (= bitmap bit 0) set
        let bitmap = [0x00, 0x00, 0x00, 0x80]; // bit 0 set when read as LE
        let ranges = parse_rtps_bitmap_to_ranges(&bitmap, 1, 1, true);
        assert_eq!(ranges, vec![1..2]);
    }

    #[test]
    fn test_parse_nack_frag() {
        // Build minimal NACK_FRAG packet requesting fragments 2 and 4
        let mut packet = Vec::new();

        // RTPS Header (20 bytes)
        packet.extend_from_slice(b"RTPS");
        packet.extend_from_slice(&[2, 4]); // Version
        packet.extend_from_slice(&[0x01, 0xAA]); // HDDS vendor
        packet.extend_from_slice(&[0x01; 12]); // GUID prefix

        // NACK_FRAG submessage
        packet.push(0x12); // ID = NACK_FRAG
        packet.push(0x01); // Flags: little-endian
                           // octetsToNextHeader = 4 + 4 + 8 + 4 + 4 + 4 + 4 = 32
        packet.extend_from_slice(&32u16.to_le_bytes());

        // readerEntityId
        packet.extend_from_slice(&[0x00, 0x00, 0x01, 0x04]);
        // writerEntityId
        packet.extend_from_slice(&[0x00, 0x00, 0x01, 0x03]);
        // writerSN: {high=0, low=42}
        packet.extend_from_slice(&0i32.to_le_bytes());
        packet.extend_from_slice(&42u32.to_le_bytes());
        // fragmentNumberState.bitmapBase = 2
        packet.extend_from_slice(&2u32.to_le_bytes());
        // fragmentNumberState.numBits = 4 (covers fragments 2, 3, 4, 5)
        packet.extend_from_slice(&4u32.to_le_bytes());
        // bitmap: bits for fragments 2 and 4 set (bit 0 and bit 2 set)
        // MSB-first: bit 0 = fragment 2, bit 2 = fragment 4
        // Binary: 1010_0000_... = 0xA0000000 in LE = [0x00, 0x00, 0x00, 0xA0]
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0xA0]);
        // count
        packet.extend_from_slice(&5u32.to_le_bytes());

        let nf = parse_nack_frag_submessage(&packet).expect("Should parse");
        assert_eq!(nf.reader_entity_id, [0x00, 0x00, 0x01, 0x04]);
        assert_eq!(nf.writer_entity_id, [0x00, 0x00, 0x01, 0x03]);
        assert_eq!(nf.writer_sn, 42);
        assert_eq!(nf.missing_fragments, vec![2, 4]);
        assert_eq!(nf.count, 5);
    }

    #[test]
    fn test_parse_fragment_bitmap_empty() {
        let missing = parse_fragment_bitmap(&[], 1, 0, true);
        assert!(missing.is_empty());
    }

    #[test]
    fn test_parse_fragment_bitmap_single() {
        // Bitmap with bit 0 set = fragment 1 missing
        let bitmap = [0x00, 0x00, 0x00, 0x80]; // bit 0 set when read as LE
        let missing = parse_fragment_bitmap(&bitmap, 1, 1, true);
        assert_eq!(missing, vec![1]);
    }
}
