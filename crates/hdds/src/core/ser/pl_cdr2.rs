// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Helpers for PL_CDR2 (Parameter List CDR2) mutable structs.
//!
//!
//! These helpers centralize the XTypes v1.3 encoding pattern:
//! - DHEADER (u32) delimiter for the struct payload
//! - MemberId (u32) before each member
//! - Optional members omitted entirely
//! - Alignment applied before each member payload
//!
//! They are intended for use by `hdds_gen` and manual sandbox types until the
//! code generator emits PL_CDR2 directly.

use super::traits::CdrError;

/// Length code for EMHEADER1 (OMG DDS-XTypes v1.3 sec. 7.4.3.4.2, "Member
/// Header (EMHEADER), Length Code (LC) and NEXTINT"). The 3-bit `LC`
/// field at the top of the EMHEADER1 word tells the reader how to
/// determine the member length -- the full table, all 8 values:
///   - `LC=0..3` (Lc1/Lc2/Lc4/Lc8): the header is 4 bytes (no NEXTINT);
///     the member is exactly 1/2/4/8 bytes, length is implicit in `LC`.
///   - `LC=4` (NextInt): the header is 8 bytes; the NEXTINT that follows
///     EMHEADER1 is the member's byte length, and is NOT itself part of
///     the member (the value starts right after it).
///   - `LC=5/6/7`: the header is 8 bytes too, but NEXTINT is ALSO reused
///     as the member's own leading word (the spec: "this is useful
///     because the serialization of certain members also starts with an
///     integer length, which would take exactly the same value as
///     NEXTINT"). The member's length, counted from NEXTINT's own
///     position (never skipped as pure header), is `4 + NEXTINT * 1` for
///     `LC=5`, `* 4` for `LC=6`, `* 8` for `LC=7`.
///
/// `LC=5/6/7` are NOT reserved: RTI Connext and other vendors emit them
/// routinely, e.g. for a `sequence<T>` or `string` member whose own
/// leading length word doubles as NEXTINT, so [`decode_pl_cdr2_struct`]
/// accepts them.
///
/// HDDS's OWN encoder (`encode_pl_cdr2_struct`) always chooses `LC=4`
/// (NextInt) for every member: a uniform layout regardless of whether
/// the member type happens to emit a leading length word of its own, at
/// the cost of 4 bytes per member when it could reuse one. That is a
/// capacity choice, not a decode limitation: see
/// [`emheader_member_extent`] for the full 0-7 decode this module and
/// `dynamic::cdr_dynamic::CdrDecoder::read_emheader_member` share.
#[derive(Copy, Clone, Debug)]
#[allow(dead_code)] // Part of XTypes PL_CDR2 spec, variants used based on member sizes
enum LengthCode {
    Lc1 = 0,
    Lc2 = 1,
    Lc4 = 2,
    Lc8 = 3,
    NextInt = 4,
}

impl LengthCode {
    fn as_u32(self) -> u32 {
        self as u32
    }
}

/// Decode one EMHEADER1 length code (`lc`, 0-7) into the member's byte
/// extent, per DDS-XTypes v1.3 sec. 7.4.3.4.2 (see [`LengthCode`] for the
/// full table). `header_end` is the absolute offset right after
/// EMHEADER1's own 4 bytes (where NEXTINT would start, for `LC>=4`).
/// `read_u32_le(offset)` reads a little-endian `u32` at an absolute
/// offset; the caller must have already bounds-checked that read (this
/// function performs none, so it never panics or errors on its own).
///
/// Returns `(member_start, member_len)`: where the member's VALUE begins
/// (NOT including NEXTINT for `LC=4`, including it for `LC=5/6/7` since
/// the spec has it double as the member's own leading word, and equal to
/// `header_end` for `LC=0..=3`, which has no NEXTINT at all) and its
/// byte length. The caller forms `member_end = member_start + member_len`
/// and bounds-checks THAT against its buffer -- this function's own
/// arithmetic saturates so it cannot panic, but an unchecked `member_end`
/// can still exceed the buffer, same as a NEXTINT a peer announced wrong.
///
/// Shared by [`decode_pl_cdr2_struct`] and
/// `dynamic::cdr_dynamic::CdrDecoder::read_emheader_member`, which calls
/// this function too: one copy of the Table rule for these two LE-only,
/// "start+len" readers. `core::key_hash::KeyPayloadReader::read_emheader`
/// keeps its OWN, genuinely independent copy (it also reads big-endian,
/// and tracks "exact vs NEXTINT-only" for `close_member`, a contract this
/// function does not need) -- `emheader_extent_matches_key_payload_reader_per_lc`
/// below runs identical spec-built bytes through both and checks they
/// agree on the member's end, the one cross-check two independent copies
/// of the same table rule can still give.
pub(crate) fn emheader_member_extent(
    lc: u32,
    header_end: usize,
    read_u32_le: impl FnOnce(usize) -> u32,
) -> (usize, usize) {
    match lc {
        0..=3 => (header_end, 1usize << lc),
        4 => {
            let byte_count = read_u32_le(header_end) as usize;
            (header_end.saturating_add(4), byte_count)
        }
        _ => {
            // LC 5, 6, 7: NEXTINT is read but NOT skipped -- it is the
            // member's own first word, so the extent starts AT it.
            let count = read_u32_le(header_end) as usize;
            let scale: usize = match lc {
                5 => 1,
                6 => 4,
                _ => 8, // lc == 7 (and any other value: last resort, never emitted)
            };
            (
                header_end,
                4usize.saturating_add(count.saturating_mul(scale)),
            )
        }
    }
}

/// Align an absolute offset to the given power-of-two boundary.
#[inline]
pub const fn align_offset(offset: usize, alignment: usize) -> usize {
    if alignment == 0 {
        offset
    } else {
        (offset + alignment - 1) & !(alignment - 1)
    }
}

/// Compute padding needed to reach the given alignment.
#[inline]
pub const fn padding_for_alignment(offset: usize, alignment: usize) -> usize {
    align_offset(offset, alignment) - offset
}

/// Encoder descriptor for a PL_CDR2 member.
#[allow(clippy::type_complexity)] // FnMut closure type for CDR encoding
pub struct PlMemberEncoder<'a> {
    pub member_id: u32,
    /// Alignment to apply before invoking `encode`.
    pub align: usize,
    /// Encode the member payload at the given absolute offset.
    ///
    /// The closure must return the number of bytes written.
    pub encode: &'a mut dyn FnMut(&mut [u8], usize) -> Result<usize, CdrError>,
}

/// Encode a mutable struct in PL_CDR2.
///
/// Layout: `[DHEADER:u32][MemberId][member payload]...`
pub fn encode_pl_cdr2_struct(
    dst: &mut [u8],
    members: &mut [PlMemberEncoder<'_>],
) -> Result<usize, CdrError> {
    let mut offset: usize = 0;

    if dst.len() < 4 {
        return Err(CdrError::BufferTooSmall);
    }

    // Reserve space for DHEADER (payload length)
    offset += 4;

    for m in members.iter_mut() {
        // EMHEADER1: LC=NEXTINT (reuse NEXTINT as member length), M_FLAG=0
        if dst.len() < offset + 4 {
            return Err(CdrError::BufferTooSmall);
        }
        let em = (LengthCode::NextInt.as_u32() << 28) | (m.member_id & 0x0fff_ffff);
        dst[offset..offset + 4].copy_from_slice(&em.to_le_bytes());
        offset += 4;

        // Placeholder for NEXTINT (member length)
        if dst.len() < offset + 4 {
            return Err(CdrError::BufferTooSmall);
        }
        let nextint_pos = offset;
        offset += 4;

        let member_start = offset;

        // Align member payload
        let aligned = align_offset(offset, m.align.max(1));
        if aligned > offset {
            if dst.len() < aligned {
                return Err(CdrError::BufferTooSmall);
            }
            dst[offset..aligned].fill(0);
            offset = aligned;
        }

        let used = (m.encode)(&mut dst[offset..], offset)?;
        offset += used;

        // Fill NEXTINT with member length (including any per-element DHEADERs written by encoder)
        let member_len = offset - member_start;
        let member_len_u32 = u32::try_from(member_len).map_err(|_| CdrError::InvalidEncoding)?;
        dst[nextint_pos..nextint_pos + 4].copy_from_slice(&member_len_u32.to_le_bytes());
    }

    let payload_len = u32::try_from(offset - 4).map_err(|_| CdrError::InvalidEncoding)?;
    dst[..4].copy_from_slice(&payload_len.to_le_bytes());
    Ok(offset)
}

/// Decode a mutable struct in PL_CDR2.
///
/// Calls `visitor` for each member encountered. The visitor receives the
/// `member_id`, the full source buffer, a mutable offset (pointing at the
/// member's value -- for `LC=5/6/7` that is AT the reused NEXTINT word,
/// which the visitor's own decode is expected to read again as the
/// member's leading length, per [`emheader_member_extent`]), and the end
/// offset of the member (not of the whole struct payload: a member the
/// visitor does not recognize is skipped to exactly this offset by the
/// caller of `decode_pl_cdr2_struct`, same as every other LC).
///
/// Accepts every length code 0-7 ([`emheader_member_extent`]). Treating
/// every LC other than `4` (NextInt) as "the member runs to the end of the
/// struct payload" would be correct only for a struct's LAST member under
/// `LC=0..=3` (there is nothing after it to overrun into) and wrong
/// everywhere else -- a peer's EARLIER member at `LC=0..=3`, or ANY member
/// at `LC=5/6/7`, would get a length computed as "everything up to the
/// DHEADER boundary", so decoding would walk a dynamic-type-sized slice
/// through what is a `u16` or an enum tag.
pub fn decode_pl_cdr2_struct<F>(src: &[u8], mut visitor: F) -> Result<(), CdrError>
where
    F: FnMut(u32, &[u8], &mut usize, usize) -> Result<(), CdrError>,
{
    if src.len() < 4 {
        return Err(CdrError::UnexpectedEof);
    }
    let payload_len = {
        let mut tmp = [0u8; 4];
        tmp.copy_from_slice(&src[..4]);
        u32::from_le_bytes(tmp) as usize
    };

    let end = 4 + payload_len;
    if end > src.len() {
        return Err(CdrError::UnexpectedEof);
    }

    let mut offset = 4;
    while offset < end {
        if src.len() < offset + 4 {
            return Err(CdrError::UnexpectedEof);
        }
        #[allow(clippy::expect_used)] // bounds validated just above: src.len() >= offset + 4
        let em = u32::from_le_bytes(
            src[offset..offset + 4]
                .try_into()
                .expect("em bytes checked"),
        );
        let header_end = offset + 4;
        let lc = (em >> 28) & 0x7;
        let member_id = em & 0x0fff_ffff;

        // LC 0..=3 have no NEXTINT (4-byte header, already read above);
        // LC 4..=7 need 4 more bytes before `emheader_member_extent` may
        // read them.
        if lc >= 4 && src.len() < header_end + 4 {
            return Err(CdrError::UnexpectedEof);
        }
        let (member_start, member_len) = emheader_member_extent(lc, header_end, |at| {
            #[allow(clippy::expect_used)]
            // bounds validated just above: src.len() >= header_end + 4
            u32::from_le_bytes(src[at..at + 4].try_into().expect("nextint bytes checked"))
        });
        let member_end = member_start.saturating_add(member_len);
        if member_end > end {
            return Err(CdrError::UnexpectedEof);
        }
        offset = member_start;

        visitor(member_id, src, &mut offset, member_end)?;
        // Snap forward to the member's own extent even when the visitor
        // left `offset` short of it (an unrecognized member id, or one
        // whose value decode stopped early on padding alone): the LOOP
        // must never re-read bytes this member already claimed, matching
        // `CdrDecoder::collect_emheader_member_entries`'s
        // `self.offset = entry.end`.
        if offset < member_end {
            offset = member_end;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------
    // emheader_member_extent: the LC 0-7 table in isolation.
    // ------------------------------------------------------------------

    #[test]
    fn extent_lc_0_to_3_is_implicit_and_needs_no_nextint() {
        for (lc, expected_len) in [(0u32, 1usize), (1, 2), (2, 4), (3, 8)] {
            // A `read_u32_le` that panics if called: LC 0-3 must never
            // read NEXTINT at all.
            let (start, len) = emheader_member_extent(lc, 100, |_| panic!("no NEXTINT for LC<4"));
            assert_eq!((start, len), (100, expected_len), "lc={lc}");
        }
    }

    #[test]
    fn extent_lc_4_is_an_explicit_byte_count_not_part_of_the_member() {
        let (start, len) = emheader_member_extent(4, 100, |at| {
            assert_eq!(at, 100, "NEXTINT is read right after EMHEADER1");
            42
        });
        // member starts AFTER the 4-byte NEXTINT, which is not counted
        // in its own length.
        assert_eq!((start, len), (104, 42));
    }

    #[test]
    fn extent_lc_5_6_7_reuse_nextint_as_the_members_own_leading_word() {
        for (lc, scale) in [(5u32, 1usize), (6, 4), (7, 8)] {
            let count = 3usize;
            let (start, len) = emheader_member_extent(lc, 100, |at| {
                assert_eq!(at, 100);
                count as u32
            });
            // member starts AT NEXTINT (never skipped), length = 4 + count*scale.
            assert_eq!((start, len), (100, 4 + count * scale), "lc={lc}");
        }
    }

    #[test]
    fn extent_saturates_instead_of_overflowing_on_a_hostile_nextint() {
        // A peer's NEXTINT of u32::MAX must not panic the multiply/add.
        let (_, len) = emheader_member_extent(7, 0, |_| u32::MAX);
        assert_eq!(
            len,
            usize::MAX.min(4usize.saturating_add((u32::MAX as usize).saturating_mul(8)))
        );
    }

    // ------------------------------------------------------------------
    // decode_pl_cdr2_struct: full struct decode per LC value, from bytes
    // built straight from DDS-XTypes v1.3 Sec.7.4.3.4.2's own rule, never
    // from this crate's encoder (which only ever emits LC=4).
    // ------------------------------------------------------------------

    /// One EMHEADER1 (+ NEXTINT if `lc>=4`), little-endian, M_FLAG clear.
    fn emheader_bytes(lc: u32, member_id: u32, nextint: Option<u32>) -> Vec<u8> {
        let em = (lc << 28) | (member_id & 0x0fff_ffff);
        let mut out = em.to_le_bytes().to_vec();
        if let Some(n) = nextint {
            out.extend_from_slice(&n.to_le_bytes());
        }
        out
    }

    /// A DHEADER-delimited PL_CDR2 struct payload (`[u32 payload_len][members...]`).
    fn struct_bytes(members: &[u8]) -> Vec<u8> {
        let mut out = (members.len() as u32).to_le_bytes().to_vec();
        out.extend_from_slice(members);
        out
    }

    #[test]
    fn decode_accepts_lc_0_to_3_without_overrunning_into_the_next_member() {
        // Member 0 at LC=1 (2 implicit bytes: 0xAA 0xBB), member 1 at
        // LC=0 (1 implicit byte: 0xCC). The LC=1 member (not LC=4) must
        // not fall into a "rest of buffer" branch and swallow member 1 too.
        let mut members = emheader_bytes(1, 0, None);
        members.extend_from_slice(&[0xAA, 0xBB]);
        members.extend_from_slice(&emheader_bytes(0, 1, None));
        members.push(0xCC);
        let src = struct_bytes(&members);

        let mut seen = Vec::new();
        decode_pl_cdr2_struct(&src, |id, buf, offset, end| {
            seen.push((id, buf[*offset..end].to_vec()));
            *offset = end;
            Ok(())
        })
        .unwrap();

        assert_eq!(seen, vec![(0, vec![0xAA, 0xBB]), (1, vec![0xCC]),]);
    }

    #[test]
    fn decode_accepts_lc_4_nextint_explicit_length() {
        let mut members = emheader_bytes(4, 7, Some(3));
        members.extend_from_slice(&[1, 2, 3]);
        let src = struct_bytes(&members);

        let mut seen = Vec::new();
        decode_pl_cdr2_struct(&src, |id, buf, offset, end| {
            seen.push((id, buf[*offset..end].to_vec()));
            *offset = end;
            Ok(())
        })
        .unwrap();

        assert_eq!(seen, vec![(7, vec![1, 2, 3])]);
    }

    /// LC=6: a `sequence<u32>` member (NEXTINT = element count, reused as
    /// the sequence's own leading count word), followed by a second
    /// member, exactly the shape of the measured Connext `seq<enum>`
    /// mutable case. LC=6 must not take a "rest of buffer" branch: the
    /// second member must be reached, not read as part of the first.
    #[test]
    fn decode_accepts_lc_6_sequence_reuse_and_reaches_the_next_member() {
        let count: u32 = 2;
        let mut members = emheader_bytes(6, 0, Some(count));
        // The sequence's own content: count (reused NEXTINT, already in
        // the header) + `count` 4-byte elements.
        members.extend_from_slice(&11u32.to_le_bytes());
        members.extend_from_slice(&22u32.to_le_bytes());
        members.extend_from_slice(&emheader_bytes(0, 1, None));
        members.push(0x42);
        let src = struct_bytes(&members);

        let mut seen = Vec::new();
        decode_pl_cdr2_struct(&src, |id, buf, offset, end| {
            if id == 0 {
                // The visitor reads the reused NEXTINT itself, as the
                // sequence's own count, per the spec rationale.
                assert_eq!(end - *offset, 4 + (count as usize) * 4);
                let seq_count = u32::from_le_bytes(buf[*offset..*offset + 4].try_into().unwrap());
                assert_eq!(seq_count, count);
            } else {
                assert_eq!(buf[*offset..end], [0x42]);
            }
            seen.push(id);
            *offset = end;
            Ok(())
        })
        .unwrap();

        assert_eq!(seen, vec![0, 1]);
    }

    #[test]
    fn decode_accepts_lc_5_and_lc_7_reuse_too() {
        for (lc, scale) in [(5u32, 1usize), (7, 8)] {
            let count: u32 = 1;
            let mut members = emheader_bytes(lc, 0, Some(count));
            members.extend(std::iter::repeat_n(0u8, scale)); // the reused element(s)
            let src = struct_bytes(&members);

            let mut lens = Vec::new();
            decode_pl_cdr2_struct(&src, |_id, _buf, offset, end| {
                lens.push(end - *offset);
                *offset = end;
                Ok(())
            })
            .unwrap();
            assert_eq!(lens, vec![4 + scale], "lc={lc}");
        }
    }

    /// An unrecognized member id is skipped to its own extent, never
    /// reprocessed as a fresh EMHEADER (the loop's forward-snap).
    #[test]
    fn decode_skips_an_unrecognized_member_the_visitor_does_not_advance() {
        let mut members = emheader_bytes(2, 99, None); // LC=2, 4 implicit bytes
        members.extend_from_slice(&[0, 0, 0, 0]);
        members.extend_from_slice(&emheader_bytes(0, 1, None));
        members.push(0x7A);
        let src = struct_bytes(&members);

        let mut seen = Vec::new();
        decode_pl_cdr2_struct(&src, |id, _buf, _offset, _end| {
            // Deliberately does not advance `*offset` for the unknown id.
            seen.push(id);
            Ok(())
        })
        .unwrap();

        assert_eq!(seen, vec![99, 1]);
    }

    #[test]
    fn decode_refuses_a_nextint_that_runs_past_the_dheader() {
        let members = emheader_bytes(4, 0, Some(1000)); // claims 1000 bytes, none present
        let src = struct_bytes(&members);
        assert!(matches!(
            decode_pl_cdr2_struct(&src, |_, _, _, _| Ok(())),
            Err(CdrError::UnexpectedEof)
        ));
    }

    #[test]
    fn roundtrip_through_this_modules_own_encoder_still_decodes() {
        // encode_pl_cdr2_struct always chooses LC=4; decode must still
        // read its own output correctly.
        let mut buf = [0u8; 64];
        let payload = [9u8, 8, 7, 6];
        let mut encode_fn = |dst: &mut [u8], _offset: usize| {
            dst[..4].copy_from_slice(&payload);
            Ok(4)
        };
        let mut members = [PlMemberEncoder {
            member_id: 5,
            align: 1,
            encode: &mut encode_fn,
        }];
        let written = encode_pl_cdr2_struct(&mut buf, &mut members).unwrap();

        let mut seen = Vec::new();
        decode_pl_cdr2_struct(&buf[..written], |id, src, offset, end| {
            seen.push((id, src[*offset..end].to_vec()));
            *offset = end;
            Ok(())
        })
        .unwrap();
        assert_eq!(seen, vec![(5, payload.to_vec())]);
    }

    // ------------------------------------------------------------------
    // Cross-check against the genuinely independent second LC reader.
    // ------------------------------------------------------------------

    /// `core::key_hash::KeyPayloadReader::read_emheader` has its
    /// own copy of the Table rule (big-endian capable, different struct).
    /// For identical spec-built EMHEADER(+NEXTINT) bytes, it must agree
    /// with `emheader_member_extent` on where the member ends.
    #[test]
    fn emheader_extent_matches_key_payload_reader_per_lc() {
        use crate::core::key_hash::KeyPayloadReader;

        for lc in 0u32..=7 {
            let nextint = if lc >= 4 { Some(5u32) } else { None };
            let header = emheader_bytes(lc, 3, nextint);

            // emheader_member_extent's own answer, in the SAME coordinate
            // system KeyPayloadReader uses below (position 0 = EMHEADER1's
            // first byte, so `header_end` -- right after EMHEADER1's own
            // 4 bytes -- is always 4, whatever `lc` is).
            let (member_start, member_len) =
                emheader_member_extent(lc, 4, |_| nextint.unwrap_or(0));
            let expected_end = member_start + member_len;

            // KeyPayloadReader's independent answer: a minimal PL_CDR2_LE
            // payload (encapsulation 0x0007) carrying just this header,
            // padded with enough trailing bytes for the largest LC to
            // stay in bounds.
            let mut payload = vec![0x00, 0x07, 0x00, 0x00];
            payload.extend_from_slice(&header);
            payload.extend(std::iter::repeat_n(0u8, 64));
            let mut reader = KeyPayloadReader::new(&payload).expect("valid PL_CDR2_LE header");
            let (id, member) = reader.read_emheader().expect("in bounds");
            assert_eq!(id, 3, "lc={lc}");
            assert_eq!(
                member.end_for_test(),
                expected_end,
                "lc={lc}: the two readers disagree"
            );
        }
    }
}
