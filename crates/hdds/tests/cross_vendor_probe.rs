// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Alignment of an 8-byte member after an octet, under XCDR2 and XCDR1.
//!
//! `@final struct Probe { octet a; double b; }`. DDS-XTypes 1.3 7.4.3.2.2,
//! Table 37: `MAXALIGN(VERSION2) = 4`, `MAXALIGN(VERSION1) = 8`, and
//! `ALIGN(N)` aligns to `MIN(N, MAXALIGN)`. So under XCDR2 (PLAIN_CDR2,
//! no DHEADER for a @final type) `b` starts at offset 4 after three
//! padding octets, and under XCDR1 (PLAIN_CDR) at offset 8 after seven.
//! The expected bodies are written out from that rule, little endian, with
//! zero padding; the double's bits are IEEE 754 binary64 (1.0, a quiet NaN
//! and -0.0 keep their exact bit patterns). Through `Cdr2Encode` the
//! XCDR2 path exercises the primitive impls in `core::ser::traits`, so a
//! regression in `impl_cdr2_primitive!`'s alignment fails here.

use hdds::{Cdr2Encode, CdrError};

#[derive(Debug, Clone, PartialEq)]
struct Probe {
    a: u8,
    b: f64,
}

impl Cdr2Encode for Probe {
    fn max_cdr2_size(&self) -> usize {
        1 + 3 + 8
    }

    fn encode_cdr2_le_at(&self, dst: &mut [u8], offset: &mut usize) -> Result<(), CdrError> {
        self.a.encode_cdr2_le_at(dst, offset)?;
        self.b.encode_cdr2_le_at(dst, offset)?;
        Ok(())
    }

    fn encode_xcdr1_le_at(&self, dst: &mut [u8], offset: &mut usize) -> Result<(), CdrError> {
        if *offset + 1 > dst.len() {
            return Err(CdrError::BufferTooSmall);
        }
        dst[*offset] = self.a;
        *offset += 1;

        let pad = (8 - (*offset % 8)) % 8;
        if *offset + pad + 8 > dst.len() {
            return Err(CdrError::BufferTooSmall);
        }
        dst[*offset..*offset + pad].fill(0);
        *offset += pad;

        dst[*offset..*offset + 8].copy_from_slice(&self.b.to_le_bytes());
        *offset += 8;
        Ok(())
    }
}

/// Common assert helper: encode `probe` via the requested CDR variant
/// and compare against the expected bytes.
fn assert_probe_matches_golden(probe: Probe, golden: &[u8], cdr_v2: bool) {
    let mut buf = vec![0u8; 64];
    let mut offset = 0;
    if cdr_v2 {
        probe
            .encode_xcdr2_le_at(&mut buf, &mut offset)
            .expect("encode XCDR2");
    } else {
        probe
            .encode_xcdr1_le_at(&mut buf, &mut offset)
            .expect("encode XCDR1");
    }
    assert_eq!(
        &buf[..offset],
        golden,
        "wire bytes diverge from the Table 37 layout\nexpected: {:02x?}\nactual:   {:02x?}",
        golden,
        &buf[..offset]
    );
}

/// Expected body: `a`, padding to `b`'s offset (4 under XCDR2, 8 under
/// XCDR1, Table 37), then `b` little endian.
fn expected(a: u8, b_bits: u64, cdr_v2: bool) -> Vec<u8> {
    let b_at = if cdr_v2 { 4 } else { 8 };
    let mut v = vec![a];
    v.resize(b_at, 0);
    v.extend(b_bits.to_le_bytes());
    v
}

#[test]
fn xcdr2_double_after_an_octet_is_aligned_at_4() {
    for (b, bits) in [
        (2.5f64, 0x4004_0000_0000_0000u64),
        (f64::NAN, f64::NAN.to_bits()),
        (-0.0, 0x8000_0000_0000_0000),
    ] {
        let exp = expected(0x5a, bits, true);
        assert_eq!(exp.len(), 12);
        assert_probe_matches_golden(Probe { a: 0x5a, b }, &exp, true);
    }
}

#[test]
fn xcdr1_double_after_an_octet_is_aligned_at_8() {
    for (b, bits) in [
        (2.5f64, 0x4004_0000_0000_0000u64),
        (f64::NAN, f64::NAN.to_bits()),
        (-0.0, 0x8000_0000_0000_0000),
    ] {
        let exp = expected(0x5a, bits, false);
        assert_eq!(exp.len(), 16);
        assert_probe_matches_golden(Probe { a: 0x5a, b }, &exp, false);
    }
}
