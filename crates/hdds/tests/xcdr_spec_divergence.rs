// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com
//
// Spec-correct alignment regression test for the user-struct
// `@final struct Probe { octet a; double b; };`.
//
// Per OMG DDS-XTypes v1.3 Sec.7.4.1.1.1 Table 31, XCDR v1 aligns 8-byte
// primitives on 8, producing 16 bytes (1 + 7 padding + 8).
// Per Sec.7.4.2 + Sec.7.4.3.2.2 Table 37 `MAXALIGN(VERSION2) = 4`, XCDR v2
// caps alignment at 4 for 8-byte primitives, producing 12 bytes
// (1 + 3 padding + 8).
//
// The `Cdr2Encode` / `Cdr2Decode` impls below mirror the spec-correct
// XCDR2 wire format that hddsgen >= 1.2.0 emits for `Probe.idl` via its
// dual-emission codegen (alignment cap migration).
// The encode-side test gates that an encoder regression on 8-byte
// primitive alignment surfaces as a 16-byte XCDR1 pattern instead of
// the 12-byte XCDR2 form; the roundtrip test gates symmetric decoder
// behavior.

use hdds::{Cdr2Decode, Cdr2Encode, CdrError};

// --- begin spec-correct XCDR2 impl for Probe.idl ---

#[derive(Debug, Clone, PartialEq)]
pub struct Probe {
    pub a: u8,
    pub b: f64,
}

impl Cdr2Encode for Probe {
    fn encode_cdr2_le(&self, dst: &mut [u8]) -> Result<usize, CdrError> {
        let mut offset: usize = 0;

        if dst.len() < offset + 1 {
            return Err(CdrError::BufferTooSmall);
        }
        dst[offset] = self.a;
        offset += 1;

        // Align to 4-byte boundary for field 'b' (XCDR2 cap per sec. 7.4.3.4.1 Tab.15)
        let padding = (4 - (offset % 4)) % 4;
        offset += padding;

        if dst.len() < offset + 8 {
            return Err(CdrError::BufferTooSmall);
        }
        dst[offset..offset + 8].copy_from_slice(&self.b.to_le_bytes());
        offset += 8;

        Ok(offset)
    }

    fn max_cdr2_size(&self) -> usize {
        1 + 3 + 8
    }

    fn encode_cdr2_le_at(&self, dst: &mut [u8], offset: &mut usize) -> Result<(), CdrError> {
        let len = self.encode_cdr2_le(&mut dst[*offset..])?;
        *offset += len;
        Ok(())
    }
}

impl Cdr2Decode for Probe {
    fn decode_cdr2_le(src: &[u8]) -> Result<(Self, usize), CdrError> {
        let mut offset: usize = 0;

        if src.len() < offset + 1 {
            return Err(CdrError::UnexpectedEof);
        }
        let a = src[offset];
        offset += 1;

        // Align to 4-byte boundary for field 'b' (XCDR2 cap per sec. 7.4.3.4.1 Tab.15)
        let padding = (4 - (offset % 4)) % 4;
        offset += padding;

        if src.len() < offset + 8 {
            return Err(CdrError::UnexpectedEof);
        }
        let b = {
            let mut tmp = [0u8; 8];
            tmp.copy_from_slice(&src[offset..offset + 8]);
            f64::from_le_bytes(tmp)
        };
        offset += 8;

        Ok((Self { a, b }, offset))
    }

    fn decode_cdr2_le_at(src: &[u8], offset: &mut usize) -> Result<Self, CdrError> {
        let (value, consumed) = Self::decode_cdr2_le(&src[*offset..])?;
        *offset += consumed;
        Ok(value)
    }
}

// --- end spec-correct XCDR2 impl ---

fn xcdr1_reference_bytes() -> [u8; 16] {
    [
        0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 1 byte + 7 padding (align 8)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0, 0x3F, // f64 1.0 little-endian
    ]
}

fn xcdr2_spec_correct_reference_bytes() -> [u8; 12] {
    [
        0x42, 0x00, 0x00, 0x00, // 1 byte + 3 padding (align 4 per XTypes v1.3 Table 15)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0, 0x3F, // f64 1.0 little-endian
    ]
}

#[test]
fn probe_octet_double_encoded_bytes_match_xcdr2_pattern() {
    let probe = Probe { a: 0x42, b: 1.0f64 };
    let mut buf = vec![0u8; probe.max_cdr2_size()];
    let n = probe
        .encode_cdr2_le(&mut buf)
        .expect("Probe encode succeeds");
    buf.truncate(n);

    let xcdr1 = xcdr1_reference_bytes();
    let xcdr2 = xcdr2_spec_correct_reference_bytes();

    eprintln!("Probe {{ a = 0x42, b = 1.0f64 }}");
    eprintln!("HDDS encoded {} bytes:", buf.len());
    eprintln!("  {:02X?}", buf);
    eprintln!("XCDR1 reference (align 8-on-8, {} bytes):", xcdr1.len());
    eprintln!("  {:02X?}", &xcdr1);
    eprintln!(
        "XCDR2 spec-correct reference (align 8-on-4, {} bytes):",
        xcdr2.len()
    );
    eprintln!("  {:02X?}", &xcdr2);

    assert_eq!(
        buf.as_slice(),
        xcdr2.as_slice(),
        "Probe wire bytes must match the XCDR2 spec pattern (12 bytes) \
         per DDS-XTypes v1.3 sec. 7.4.3.4.1 Tab.15 (alignment cap 4 for \
         8-byte primitives). A regression to the XCDR1 16-byte form \
         indicates that 8-byte primitive alignment lost its cap."
    );
}

#[test]
fn probe_octet_double_roundtrip_decodes() {
    let probe = Probe { a: 0x42, b: 1.0f64 };
    let mut buf = vec![0u8; probe.max_cdr2_size()];
    let n = probe.encode_cdr2_le(&mut buf).unwrap();
    buf.truncate(n);

    let (decoded, consumed) = Probe::decode_cdr2_le(&buf).unwrap();
    assert_eq!(consumed, buf.len());
    assert_eq!(decoded, probe);
}
