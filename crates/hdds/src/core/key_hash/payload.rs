// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Reader of a key-only payload: the serializedPayload of a DATA whose K
//! flag is set (DDSI-RTPS 2.5 9.4.5.3: "D=0 and K=1 means that the
//! serializedPayload SubmessageElement contains the serialized Key").
//!
//! A DataReader that receives that key reads it back into the type's key
//! members, then computes the KeyHash with [`KeyHolderWriter`] exactly as
//! the type's `compute_key` does for a sample. The PID_KEY_HASH that may
//! travel beside the payload is only "a hint for the key" (8.7.10): the
//! serialized key, when the reader can read it, names the instance.
//!
//! The reader mirrors the key-only payload writer of the generated code
//! (`encode_key`), in either byte order the encapsulation identifier names
//! (`encode_key` writes little endian, other vendors may write big endian):
//! alignment relative to the start of the
//! payload body (capped at 4 under XCDR2, 8 under XCDR1), the framing the
//! type's extensibility selects (none for FINAL, DHEADER for APPENDABLE and
//! MUTABLE under XCDR2, EMHEADER1 per MUTABLE member under XCDR2, a
//! parameter list closed by PID_LIST_END for MUTABLE under XCDR1; DDS-XTypes
//! 1.3 7.4.3.4 and 7.4.3.5.3). Every method returns `None` on anything it
//! cannot read with certainty: an encapsulation that is not CDR, a
//! truncated value, a string beyond its bound or not valid text, a bool other
//! than 0 or 1, trailing bytes. `None` means "this reader does not know the
//! key", and the caller falls back to the PID_KEY_HASH, never to a guess.
//!
//! [`KeyHolderWriter`]: super::KeyHolderWriter

use crate::dds::CdrVersion;

/// `PID_EXTENDED` (DDS-XTypes 1.3 Table 34), without its flag bits.
const PID_EXTENDED: u16 = 0x3f01;
/// `PID_LIST_END` (DDS-XTypes 1.3 Table 34), without its flag bits.
const PID_LIST_END: u16 = 0x3f02;
/// `PID_IGNORE` (DDS-XTypes 1.3 Table 34), without its flag bits.
const PID_IGNORE: u16 = 0x3f03;
/// The parameter id bits of an XCDR1 parameter header (the two upper bits
/// are the must-understand and implementation-specific flags).
const PID_MASK: u16 = 0x3fff;
/// The member id bits of an XCDR2 EMHEADER1 or an XCDR1 extended header.
const MEMBER_ID_MASK: u32 = 0x0fff_ffff;

/// Reads the key members of a key-only payload, in the order and framing the
/// writer serialized them. See the module documentation.
#[derive(Debug, Clone)]
pub struct KeyPayloadReader<'a> {
    /// The payload body, after the 4-byte encapsulation header.
    buf: &'a [u8],
    /// Next byte to read in `buf`.
    pos: usize,
    /// The offset alignment is relative to: 0, or the start of the XCDR1
    /// parameter whose member is being read.
    origin: usize,
    xcdr2: bool,
    /// The encapsulation is little endian.
    le: bool,
}

/// A MUTABLE member being read under XCDR2: where its EMHEADER1 says it
/// ends, and whether its length code fixes that end exactly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyPayloadMember {
    end: usize,
    exact: bool,
}

#[cfg(test)]
impl KeyPayloadMember {
    /// Test-only: the extent `read_emheader` computed for this member,
    /// for a cross-check in another module against the genuinely
    /// independent second copy of the LC-table rule
    /// (`core::ser::pl_cdr2::emheader_member_extent`). Not used by
    /// production code, which only ever reaches `end` through
    /// `close_member`.
    pub(crate) fn end_for_test(&self) -> usize {
        self.end
    }
}

/// An XCDR1 parameter being read: where it ends, and the alignment origin
/// to restore after it.
#[derive(Debug, Clone, Copy)]
pub struct KeyPayloadParameter {
    end: usize,
    origin: usize,
}

impl<'a> KeyPayloadReader<'a> {
    /// A reader of `payload`, the whole serializedPayload: the 4-byte
    /// encapsulation header, then the key.
    ///
    /// The CDR encapsulations are read, in both byte orders (CDR, PL_CDR,
    /// CDR2, D_CDR2, PL_CDR2, BE and LE; DDS-XTypes 1.3 7.6.3.1.2): `None`
    /// for any other identifier, or a payload with no key after its header.
    #[must_use]
    pub fn new(payload: &'a [u8]) -> Option<Self> {
        let header = payload.get(..4)?;
        let kind = u16::from_be_bytes([header[0], header[1]]);
        let xcdr2 = match kind {
            0x0000..=0x0003 => false,
            0x0006..=0x000b => true,
            _ => return None,
        };
        let buf = &payload[4..];
        if buf.is_empty() {
            return None;
        }
        Some(Self {
            buf,
            pos: 0,
            origin: 0,
            xcdr2,
            le: kind & 1 == 1,
        })
    }

    /// The payload is XCDR2 (encoding version 2).
    #[must_use]
    pub const fn is_xcdr2(&self) -> bool {
        self.xcdr2
    }

    /// The encoding version of the payload.
    #[must_use]
    pub const fn version(&self) -> CdrVersion {
        if self.xcdr2 {
            CdrVersion::Xcdr2
        } else {
            CdrVersion::Xcdr1
        }
    }

    fn align(&mut self, size: usize) -> Option<()> {
        let max = if self.xcdr2 { 4 } else { 8 };
        let align = size.min(max);
        if align > 1 {
            let rel = self.pos.checked_sub(self.origin)?;
            let pad = (align - rel % align) % align;
            let to = self.pos.checked_add(pad)?;
            if to > self.buf.len() {
                return None;
            }
            self.pos = to;
        }
        Some(())
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let bytes = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(bytes)
    }

    fn fixed<const N: usize>(&mut self) -> Option<[u8; N]> {
        self.align(N)?;
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N)?);
        Some(out)
    }

    /// `boolean`: one byte, 0 or 1.
    pub fn read_bool(&mut self) -> Option<bool> {
        match self.take(1)?[0] {
            0 => Some(false),
            1 => Some(true),
            _ => None,
        }
    }

    /// `octet`, `uint8`, `char`.
    pub fn read_u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }

    /// `int8`, or an enum of `@bit_bound` at most 8.
    pub fn read_i8(&mut self) -> Option<i8> {
        let b = self.fixed()?;
        Some(if self.le {
            i8::from_le_bytes(b)
        } else {
            i8::from_be_bytes(b)
        })
    }

    /// `unsigned short`, `wchar`.
    pub fn read_u16(&mut self) -> Option<u16> {
        let b = self.fixed()?;
        Some(if self.le {
            u16::from_le_bytes(b)
        } else {
            u16::from_be_bytes(b)
        })
    }

    /// `short`.
    pub fn read_i16(&mut self) -> Option<i16> {
        let b = self.fixed()?;
        Some(if self.le {
            i16::from_le_bytes(b)
        } else {
            i16::from_be_bytes(b)
        })
    }

    /// `unsigned long`.
    pub fn read_u32(&mut self) -> Option<u32> {
        let b = self.fixed()?;
        Some(if self.le {
            u32::from_le_bytes(b)
        } else {
            u32::from_be_bytes(b)
        })
    }

    /// `long`.
    pub fn read_i32(&mut self) -> Option<i32> {
        let b = self.fixed()?;
        Some(if self.le {
            i32::from_le_bytes(b)
        } else {
            i32::from_be_bytes(b)
        })
    }

    /// `unsigned long long`.
    pub fn read_u64(&mut self) -> Option<u64> {
        let b = self.fixed()?;
        Some(if self.le {
            u64::from_le_bytes(b)
        } else {
            u64::from_be_bytes(b)
        })
    }

    /// `long long`.
    pub fn read_i64(&mut self) -> Option<i64> {
        let b = self.fixed()?;
        Some(if self.le {
            i64::from_le_bytes(b)
        } else {
            i64::from_be_bytes(b)
        })
    }

    /// `float`.
    pub fn read_f32(&mut self) -> Option<f32> {
        let b = self.fixed()?;
        Some(if self.le {
            f32::from_le_bytes(b)
        } else {
            f32::from_be_bytes(b)
        })
    }

    /// `double`.
    pub fn read_f64(&mut self) -> Option<f64> {
        let b = self.fixed()?;
        Some(if self.le {
            f64::from_le_bytes(b)
        } else {
            f64::from_be_bytes(b)
        })
    }

    /// `string` or `string<bound>`: the length counting the NUL, the bytes,
    /// the NUL (DDS-XTypes 1.3 7.4.3.5.3 rule 3). `None` beyond `bound`, for
    /// a missing NUL, an inner NUL, or bytes that are not UTF-8.
    pub fn read_string(&mut self, bound: Option<u32>) -> Option<String> {
        let len = usize::try_from(self.read_u32()?).ok()?;
        let chars = len.checked_sub(1)?;
        if let Some(bound) = bound {
            if chars > usize::try_from(bound).ok()? {
                return None;
            }
        }
        let bytes = self.take(len)?;
        let (text, nul) = bytes.split_at(chars);
        if nul != [0] || text.contains(&0) {
            return None;
        }
        String::from_utf8(text.to_vec()).ok()
    }

    /// `wstring` or `wstring<bound>`: the length in bytes, then UTF-16 code
    /// units, no NUL (DDS-XTypes 1.3 7.4.3.5.3 rule 4). `None` beyond `bound`
    /// characters or for code units that are not valid UTF-16.
    pub fn read_wstring(&mut self, bound: Option<u32>) -> Option<String> {
        let len = usize::try_from(self.read_u32()?).ok()?;
        if len % 2 != 0 {
            return None;
        }
        let units = len / 2;
        if let Some(bound) = bound {
            if units > usize::try_from(bound).ok()? {
                return None;
            }
        }
        let bytes = self.take(len)?;
        let units: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|c| {
                if self.le {
                    u16::from_le_bytes([c[0], c[1]])
                } else {
                    u16::from_be_bytes([c[0], c[1]])
                }
            })
            .collect();
        String::from_utf16(&units).ok()
    }

    /// The length of a sequence whose elements are `elem_size` bytes each:
    /// `None` beyond `bound`, or when that many elements cannot fit in what
    /// is left of the payload.
    pub fn read_len(&mut self, bound: Option<u32>, elem_size: usize) -> Option<usize> {
        let n = self.read_u32()?;
        if let Some(bound) = bound {
            if n > bound {
                return None;
            }
        }
        let n = usize::try_from(n).ok()?;
        if n.checked_mul(elem_size.max(1))? > self.buf.len() - self.pos {
            return None;
        }
        Some(n)
    }

    /// `n` octets, no alignment.
    pub fn read_octets(&mut self, n: usize) -> Option<&'a [u8]> {
        self.take(n)
    }

    /// A DHEADER (or NEXTINT): the 4-byte length of what follows, returned
    /// as the position where it ends.
    pub fn read_dheader(&mut self) -> Option<usize> {
        let n = usize::try_from(self.read_u32()?).ok()?;
        let end = self.pos.checked_add(n)?;
        if end > self.buf.len() {
            return None;
        }
        Some(end)
    }

    /// Whether the reader is still before `end` (a DHEADER's end).
    #[must_use]
    pub const fn before(&self, end: usize) -> bool {
        self.pos < end
    }

    /// Close what a DHEADER or NEXTINT opened: nothing was read past `end`,
    /// and what remains before it (members an APPENDABLE type appended, the
    /// padding a NEXTINT counts) is skipped. `None` for an `end` past the
    /// payload.
    pub fn close(&mut self, end: usize) -> Option<()> {
        if self.pos > end || end > self.buf.len() {
            return None;
        }
        self.pos = end;
        Some(())
    }

    /// An XCDR2 EMHEADER1 (DDS-XTypes 1.3 7.4.3.4.8): the member id, and the
    /// extent its length code gives the member, to
    /// [`close_member`](Self::close_member) after reading it. Length codes 0
    /// to 3 give the member 1, 2, 4 or 8 bytes; 4 reads the NEXTINT that
    /// follows, the member's length; 5, 6 and 7 take the member's own first
    /// word as NEXTINT, its length being 4 plus 1, 4 or 8 times it. `None`
    /// when that extent runs past the payload.
    pub fn read_emheader(&mut self) -> Option<(u32, KeyPayloadMember)> {
        let word = self.read_u32()?;
        let lc = (word >> 28) & 0x7;
        let id = word & MEMBER_ID_MASK;
        let (end, exact) = match lc {
            0..=3 => (self.pos.checked_add(1usize << lc)?, true),
            4 => (self.read_dheader()?, false),
            _ => {
                let next = self.buf.get(self.pos..self.pos.checked_add(4)?)?;
                let next: [u8; 4] = next.try_into().ok()?;
                let n = if self.le {
                    u32::from_le_bytes(next)
                } else {
                    u32::from_be_bytes(next)
                };
                let n = usize::try_from(n).ok()?;
                let unit = match lc {
                    5 => 1,
                    6 => 4,
                    _ => 8,
                };
                (
                    self.pos.checked_add(4)?.checked_add(n.checked_mul(unit)?)?,
                    true,
                )
            }
        };
        if end > self.buf.len() {
            return None;
        }
        Some((id, KeyPayloadMember { end, exact }))
    }

    /// Close a MUTABLE member: under length codes 0 to 3 and 5 to 7 the
    /// member filled exactly the extent its EMHEADER1 gave it, as the sample
    /// decoder reads it (a value that does not fill it is not the member the
    /// header announces); under a NEXTINT (length code 4), nothing was read
    /// past it and the rest is skipped.
    pub fn close_member(&mut self, member: KeyPayloadMember) -> Option<()> {
        if member.exact && self.pos != member.end {
            return None;
        }
        self.close(member.end)
    }

    /// The next XCDR1 parameter header of a MUTABLE type's parameter list
    /// (DDS-XTypes 1.3 7.4.1.2.2): `Some(None)` at PID_LIST_END, else the
    /// member id and the parameter, to [`leave`](Self::leave) after the
    /// member. PID_IGNORE parameters are skipped. Alignment inside the
    /// parameter restarts at its first byte, as the writer aligns it.
    pub fn read_parameter(&mut self) -> Option<Option<(u32, KeyPayloadParameter)>> {
        loop {
            self.align(4)?;
            let pid = self.read_u16()?;
            let len = usize::from(self.read_u16()?);
            let (id, len) = match pid & PID_MASK {
                PID_LIST_END => return Some(None),
                PID_IGNORE => {
                    self.take(len)?;
                    continue;
                }
                PID_EXTENDED => {
                    if len != 8 {
                        return None;
                    }
                    let header = self.read_u32()?;
                    let len = self.read_u32()?;
                    (header & MEMBER_ID_MASK, usize::try_from(len).ok()?)
                }
                short => (u32::from(short), len),
            };
            let end = self.pos.checked_add(len)?;
            if end > self.buf.len() {
                return None;
            }
            let param = KeyPayloadParameter {
                end,
                origin: self.origin,
            };
            self.origin = self.pos;
            return Some(Some((id, param)));
        }
    }

    /// Close an XCDR1 parameter: nothing was read past its end, and the
    /// alignment origin of the enclosing list comes back.
    pub fn leave(&mut self, param: KeyPayloadParameter) -> Option<()> {
        self.origin = param.origin;
        self.close(param.end)
    }

    /// The end of the payload: what is left is at most the 3 zero bytes that
    /// pad a serializedPayload to a multiple of 4 (DDSI-RTPS 2.5 9.4.5.1).
    pub fn finish(&self) -> Option<()> {
        let rest = self.buf.get(self.pos..)?;
        (rest.len() <= 3 && rest.iter().all(|b| *b == 0)).then_some(())
    }
}

#[cfg(test)]
mod tests {
    use super::KeyPayloadReader;

    #[test]
    fn reads_the_cdr_encapsulations_in_both_byte_orders() {
        for kind in [0x0001u16, 0x0003, 0x0007, 0x0009, 0x000b] {
            let mut p = kind.to_be_bytes().to_vec();
            p.extend_from_slice(&[0, 0, 7, 0, 0, 0]);
            let mut r = KeyPayloadReader::new(&p).expect("a little-endian kind");
            assert_eq!(r.is_xcdr2(), kind >= 0x0007, "kind {kind:#06x}");
            assert_eq!(r.read_i32(), Some(7));
            assert_eq!(r.finish(), Some(()));
        }
        for kind in [0x0000u16, 0x0002, 0x0006, 0x0008, 0x000a] {
            let mut p = kind.to_be_bytes().to_vec();
            p.extend_from_slice(&[
                0, 0, 0, 0, 0, 7, 0, 3, 0, 0, 0, 0, 0, 5, b'B', b'L', b'U', b'E', 0,
            ]);
            let mut r = KeyPayloadReader::new(&p).expect("a big-endian kind");
            assert_eq!(r.is_xcdr2(), kind >= 0x0006, "kind {kind:#06x}");
            assert_eq!(r.read_i32(), Some(7));
            assert_eq!(r.read_u16(), Some(3));
            assert_eq!(r.read_string(None).as_deref(), Some("BLUE"));
            assert_eq!(r.finish(), Some(()));
        }
        for kind in [0x0004u16, 0x0005, 0x000c, 0xc000] {
            let mut p = kind.to_be_bytes().to_vec();
            p.extend_from_slice(&[0, 0, 7, 0, 0, 0]);
            assert!(KeyPayloadReader::new(&p).is_none(), "kind {kind:#06x}");
        }
    }

    /// A big-endian MUTABLE member: its EMHEADER1 and its value, both big
    /// endian, and a big-endian XCDR1 parameter header.
    #[test]
    fn a_big_endian_mutable_member_is_read() {
        let mut p = vec![0x00, 0x0a, 0x00, 0x00];
        p.extend_from_slice(&8u32.to_be_bytes());
        p.extend_from_slice(&((2u32 << 28) | 7).to_be_bytes());
        p.extend_from_slice(&5i32.to_be_bytes());
        let mut r = KeyPayloadReader::new(&p).expect("payload");
        let end = r.read_dheader().expect("dheader");
        let (id, m) = r.read_emheader().expect("emheader");
        assert_eq!(id, 7);
        assert_eq!(r.read_i32(), Some(5));
        assert_eq!(r.close_member(m), Some(()));
        assert_eq!(r.close(end), Some(()));
        let mut p = vec![0x00, 0x02, 0x00, 0x00];
        p.extend_from_slice(&0x7f01u16.to_be_bytes());
        p.extend_from_slice(&8u16.to_be_bytes());
        p.extend_from_slice(&30u32.to_be_bytes());
        p.extend_from_slice(&4u32.to_be_bytes());
        p.extend_from_slice(&6i32.to_be_bytes());
        p.extend_from_slice(&0x7f02u16.to_be_bytes());
        p.extend_from_slice(&0u16.to_be_bytes());
        let mut r = KeyPayloadReader::new(&p).expect("payload");
        let (id, param) = r.read_parameter().expect("header").expect("member");
        assert_eq!(id, 30);
        assert_eq!(r.read_i32(), Some(6));
        assert_eq!(r.leave(param), Some(()));
        assert!(matches!(r.read_parameter(), Some(None)));
    }

    #[test]
    fn an_empty_key_is_not_a_key() {
        // What a 1.4.x writer of a generated type sends: the header alone.
        assert!(KeyPayloadReader::new(&[0x00, 0x09, 0x00, 0x00]).is_none());
        assert!(KeyPayloadReader::new(&[0x00, 0x09]).is_none());
    }

    #[test]
    fn an_eight_byte_value_aligns_at_four_in_xcdr2_and_eight_in_xcdr1() {
        let body = [1u8, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0];
        let mut v2 = vec![0x00, 0x07, 0x00, 0x00, 9];
        v2.extend_from_slice(&[0, 0, 0]);
        v2.extend_from_slice(&body[..8]);
        let mut r = KeyPayloadReader::new(&v2).expect("xcdr2");
        assert_eq!(r.read_u8(), Some(9));
        assert_eq!(r.read_i64(), Some(0x0000_0002_0000_0001));
        assert_eq!(r.finish(), Some(()));

        let mut v1 = vec![0x00, 0x01, 0x00, 0x00, 9];
        v1.extend_from_slice(&[0; 7]);
        v1.extend_from_slice(&body[..8]);
        let mut r = KeyPayloadReader::new(&v1).expect("xcdr1");
        assert_eq!(r.read_u8(), Some(9));
        assert_eq!(r.read_i64(), Some(0x0000_0002_0000_0001));
        assert_eq!(r.finish(), Some(()));
    }

    #[test]
    fn a_string_is_refused_beyond_its_bound_and_without_its_nul() {
        let blue = [
            0x00, 0x07, 0x00, 0x00, 5, 0, 0, 0, b'B', b'L', b'U', b'E', 0,
        ];
        let mut r = KeyPayloadReader::new(&blue).expect("payload");
        assert_eq!(r.read_string(Some(4)).as_deref(), Some("BLUE"));
        let mut r = KeyPayloadReader::new(&blue).expect("payload");
        assert_eq!(r.read_string(Some(3)), None);
        let mut no_nul = blue;
        no_nul[12] = b'!';
        let mut r = KeyPayloadReader::new(&no_nul).expect("payload");
        assert_eq!(r.read_string(None), None);
        let mut inner_nul = blue;
        inner_nul[9] = 0;
        let mut r = KeyPayloadReader::new(&inner_nul).expect("payload");
        assert_eq!(r.read_string(None), None);
    }

    /// `close` and `leave` refuse an end past the payload: nothing is read
    /// beyond it, and `finish` still answers.
    #[test]
    fn an_end_past_the_payload_is_refused() {
        let p = [0x00, 0x07, 0x00, 0x00, 1, 0, 0, 0];
        let mut r = KeyPayloadReader::new(&p).expect("payload");
        assert_eq!(r.close(5), None);
        assert_eq!(r.close(4), Some(()));
        assert_eq!(r.finish(), Some(()));
        let mut r = KeyPayloadReader::new(&p).expect("payload");
        assert_eq!(r.close(1000), None);
        assert_eq!(r.read_u32(), Some(1));
        assert_eq!(r.finish(), Some(()));
    }

    #[test]
    fn a_bool_is_zero_or_one() {
        for (byte, value) in [(0u8, Some(false)), (1, Some(true)), (2, None)] {
            let p = [0x00, 0x07, 0x00, 0x00, byte];
            let mut r = KeyPayloadReader::new(&p).expect("payload");
            assert_eq!(r.read_bool(), value);
        }
    }

    #[test]
    fn trailing_bytes_other_than_zero_padding_refuse_the_payload() {
        let p = [0x00, 0x07, 0x00, 0x00, 7, 0, 0, 0, 0, 0, 0];
        let mut r = KeyPayloadReader::new(&p).expect("payload");
        assert_eq!(r.read_i32(), Some(7));
        assert_eq!(r.finish(), Some(()), "three zero bytes are padding");
        let p = [0x00, 0x07, 0x00, 0x00, 7, 0, 0, 0, 0, 1, 0];
        let mut r = KeyPayloadReader::new(&p).expect("payload");
        assert_eq!(r.read_i32(), Some(7));
        assert_eq!(r.finish(), None, "a non-zero byte is not padding");
        let p = [0x00, 0x07, 0x00, 0x00, 7, 0, 0, 0, 0, 0, 0, 0];
        let mut r = KeyPayloadReader::new(&p).expect("payload");
        assert_eq!(r.read_i32(), Some(7));
        assert_eq!(r.finish(), None, "four bytes are a value, not padding");
    }

    #[test]
    fn a_sequence_length_beyond_the_payload_or_its_bound_is_refused() {
        let p = [0x00, 0x07, 0x00, 0x00, 3, 0, 0, 0, 1, 2, 3];
        let mut r = KeyPayloadReader::new(&p).expect("payload");
        assert_eq!(r.read_len(Some(3), 1), Some(3));
        let mut r = KeyPayloadReader::new(&p).expect("payload");
        assert_eq!(r.read_len(Some(2), 1), None);
        let mut r = KeyPayloadReader::new(&p).expect("payload");
        assert_eq!(
            r.read_len(None, 2),
            None,
            "3 two-byte elements need 6 bytes"
        );
    }

    #[test]
    fn a_mutable_xcdr2_member_is_named_by_its_emheader() {
        // DHEADER 12; EMHEADER1 LC=2 id 7; the long; EMHEADER1 LC=4 id 9,
        // NEXTINT 1, one octet.
        let mut p = vec![0x00, 0x0b, 0x00, 0x00];
        p.extend_from_slice(&17u32.to_le_bytes());
        p.extend_from_slice(&((2u32 << 28) | 7).to_le_bytes());
        p.extend_from_slice(&5i32.to_le_bytes());
        p.extend_from_slice(&((4u32 << 28) | 9).to_le_bytes());
        p.extend_from_slice(&1u32.to_le_bytes());
        p.push(0xaa);
        let mut r = KeyPayloadReader::new(&p).expect("payload");
        let end = r.read_dheader().expect("dheader");
        let (id, m) = r.read_emheader().expect("emheader");
        assert_eq!(id, 7);
        assert_eq!(r.read_i32(), Some(5));
        assert_eq!(r.close_member(m), Some(()));
        let (id, m) = r.read_emheader().expect("emheader");
        assert_eq!(id, 9);
        assert_eq!(r.read_u8(), Some(0xaa));
        assert_eq!(r.close_member(m), Some(()));
        assert!(!r.before(end));
        assert_eq!(r.close(end), Some(()));
        assert_eq!(r.finish(), Some(()));
    }

    /// The length code is the member's size: a `long` under LC 3 (8 bytes)
    /// or LC 1 (2 bytes) is refused, under LC 2 read; LC 5 counts the
    /// member's own length word, so a string fills `4 + n`.
    #[test]
    fn a_member_must_fill_what_its_length_code_says() {
        let member = |lc: u32, value: &[u8]| {
            let mut p = vec![0x00, 0x0b, 0x00, 0x00];
            p.extend_from_slice(&((lc << 28) | 7).to_le_bytes());
            p.extend_from_slice(value);
            p
        };
        for (lc, value, ok) in [
            (2u32, &[5u8, 0, 0, 0][..], true),
            (3, &[5, 0, 0, 0, 0, 0, 0, 0][..], false),
            (1, &[5, 0, 0, 0][..], false),
        ] {
            let p = member(lc, value);
            let mut r = KeyPayloadReader::new(&p).expect("payload");
            let (_, m) = r.read_emheader().expect("emheader");
            assert_eq!(r.read_i32(), Some(5));
            assert_eq!(r.close_member(m).is_some(), ok, "lc {lc}");
        }
        let p = member(5, &[5, 0, 0, 0, b'B', b'L', b'U', b'E', 0]);
        let mut r = KeyPayloadReader::new(&p).expect("payload");
        let (_, m) = r.read_emheader().expect("emheader");
        assert_eq!(r.read_string(None).as_deref(), Some("BLUE"));
        assert_eq!(r.close_member(m), Some(()));
        // LC 6 says 4 + 4 * 5 bytes: more than the payload holds.
        let p = member(6, &[5, 0, 0, 0, b'B', b'L', b'U', b'E', 0]);
        let mut r = KeyPayloadReader::new(&p).expect("payload");
        assert_eq!(r.read_emheader(), None);
    }

    #[test]
    fn a_mutable_xcdr1_parameter_list_ends_at_pid_list_end() {
        let mut p = vec![0x00, 0x03, 0x00, 0x00];
        // PID_EXTENDED | M, length 8, member id 30, value length 4.
        p.extend_from_slice(&0x7f01u16.to_le_bytes());
        p.extend_from_slice(&8u16.to_le_bytes());
        p.extend_from_slice(&30u32.to_le_bytes());
        p.extend_from_slice(&4u32.to_le_bytes());
        p.extend_from_slice(&6i32.to_le_bytes());
        // PID_IGNORE, skipped.
        p.extend_from_slice(&0x3f03u16.to_le_bytes());
        p.extend_from_slice(&4u16.to_le_bytes());
        p.extend_from_slice(&[9; 4]);
        // A short parameter header: id 2, length 4.
        p.extend_from_slice(&2u16.to_le_bytes());
        p.extend_from_slice(&4u16.to_le_bytes());
        p.extend_from_slice(&8i32.to_le_bytes());
        p.extend_from_slice(&0x7f02u16.to_le_bytes());
        p.extend_from_slice(&0u16.to_le_bytes());
        let mut r = KeyPayloadReader::new(&p).expect("payload");
        let (id, param) = r.read_parameter().expect("header").expect("member");
        assert_eq!(id, 30);
        assert_eq!(r.read_i32(), Some(6));
        assert_eq!(r.leave(param), Some(()));
        let (id, param) = r.read_parameter().expect("header").expect("member");
        assert_eq!(id, 2);
        assert_eq!(r.read_i32(), Some(8));
        assert_eq!(r.leave(param), Some(()));
        assert!(matches!(r.read_parameter(), Some(None)));
        assert_eq!(r.finish(), Some(()));
    }
}
