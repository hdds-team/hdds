// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! RSASSA-PSS verification with SHA-256 and MGF1-SHA-256, whatever the salt
//! length (RFC 8017 Sec.8.1.2 and Sec.9.1.2).
//!
//! DDS Security v1.1 Sec.9.3.2.5.2 names "RSASSA-PSS-SHA256" and fixes the
//! hash and the mask generation function, not the salt length. Each signer
//! picks its own: ring uses the digest length (32), and so does OpenSSL >= 3.1
//! by default (the largest salt up to the digest length); OpenSSL 1.1.1 and
//! 3.0 sign with the MAXIMUM salt by default. Cyclone DDS sets no salt length
//! (master, `auth_utils.c`), so built on OpenSSL 1.1.1 or 3.0 it sends the
//! maximum; Fast DDS signs with the digest length (`RSA_PSS_SALTLEN_DIGEST`,
//! master `PKIDH.cpp`). ring's verifier accepts only the digest length, so a
//! conformant peer signing with another salt was refused. Fast DDS verifies
//! with `RSA_PSS_SALTLEN_AUTO`: the salt length is read from the encoded
//! message, as here.
//!
//! What stays refused: any other padding (PKCS #1 v1.5 has no 0xbc trailer
//! and no 0x01 separator), another hash, another mask generation function
//! (MGF1-SHA1 unmasks to bytes that are not a zero run followed by 0x01, or
//! to a salt whose hash does not match), a key outside 2048..=8192 bits or
//! with a public exponent ring would refuse, and a signature whose length is
//! not the modulus length.
//!
//! Every input here is public (the peer's certificate, its signature, the
//! signed bytes), so the arithmetic need not be constant-time; the private
//! side stays with ring (`sign_bytes`).

use num_bigint::BigUint;
use ring::digest::{digest, Context, SHA256, SHA256_OUTPUT_LEN};

/// Smallest modulus accepted, in bits: ring's `RSA_PSS_2048_8192_SHA256`.
const MIN_MODULUS_BITS: usize = 2048;
/// Largest modulus accepted, in bits: ring's `RSA_PSS_2048_8192_SHA256`.
const MAX_MODULUS_BITS: usize = 8192;
/// Largest public exponent accepted, in bits, as ring (RFC 8017 allows any;
/// a 33-bit bound is what ring and the Web PKI apply).
const MAX_EXPONENT_BITS: u64 = 33;

/// Whether `signature` is an RSASSA-PSS signature, SHA-256 and MGF1-SHA-256,
/// of `message` under the RSA public key (`modulus`, `exponent`), both
/// big-endian unsigned integers as an RSAPublicKey carries them, for any salt
/// length the encoded message holds.
pub(super) fn verify_pss_sha256_any_salt(
    modulus: &[u8],
    exponent: &[u8],
    message: &[u8],
    signature: &[u8],
) -> bool {
    let n = BigUint::from_bytes_be(modulus);
    let e = BigUint::from_bytes_be(exponent);
    let Ok(mod_bits) = usize::try_from(n.bits()) else {
        return false;
    };
    if !(MIN_MODULUS_BITS..=MAX_MODULUS_BITS).contains(&mod_bits) {
        return false;
    }
    // ring: odd, at least 3, at most 33 bits.
    if e.bits() > MAX_EXPONENT_BITS || e < BigUint::from(3u8) || !e.bit(0) {
        return false;
    }
    // RFC 8017 Sec.8.1.2 step 1: the signature is exactly k octets.
    let k = mod_bits.div_ceil(8);
    if signature.len() != k {
        return false;
    }
    // Step 2: RSAVP1, s < n.
    let s = BigUint::from_bytes_be(signature);
    if s >= n {
        return false;
    }
    let m = s.modpow(&e, &n);
    // EM = I2OSP(m, emLen), emBits = modBits - 1.
    let em_bits = mod_bits - 1;
    let em_len = em_bits.div_ceil(8);
    let m_bytes = m.to_bytes_be();
    if m_bytes.len() > em_len {
        return false;
    }
    let mut em = vec![0u8; em_len];
    em[em_len - m_bytes.len()..].copy_from_slice(&m_bytes);
    emsa_pss_verify_any_salt(message, &em, em_bits)
}

/// EMSA-PSS-VERIFY (RFC 8017 Sec.9.1.2) with SHA-256 and MGF1-SHA-256, the
/// salt length taken from the encoded message (OpenSSL's
/// `RSA_PSS_SALTLEN_AUTO`).
fn emsa_pss_verify_any_salt(message: &[u8], em: &[u8], em_bits: usize) -> bool {
    const H_LEN: usize = SHA256_OUTPUT_LEN;
    let em_len = em.len();
    // Step 3 for the shortest salt, 0. Unreachable behind MIN_MODULUS_BITS
    // (emLen >= 255; mutation-verified as such), kept so this step does
    // not rest on a bound checked elsewhere.
    if em_len < H_LEN + 2 {
        return false;
    }
    // Step 4.
    if em[em_len - 1] != 0xbc {
        return false;
    }
    // Step 5.
    let db_len = em_len - H_LEN - 1;
    let (masked_db, rest) = em.split_at(db_len);
    let h = &rest[..H_LEN];
    // Step 6: the leftmost 8 * emLen - emBits bits of maskedDB are zero.
    // 0 to 7: emLen is emBits rounded up to whole octets.
    let unused_bits = 8 * em_len - em_bits;
    let top_mask: u8 = 0xffu8 >> unused_bits;
    if masked_db[0] & !top_mask != 0 {
        return false;
    }
    // Steps 7 to 9.
    let mut db = mgf1_sha256(h, db_len);
    for (byte, masked) in db.iter_mut().zip(masked_db) {
        *byte ^= masked;
    }
    db[0] &= top_mask;
    // Step 10, the salt length read from DB: a run of zero octets, then
    // 0x01, then the salt.
    let Some(separator) = db.iter().position(|&byte| byte != 0) else {
        return false;
    };
    if db[separator] != 0x01 {
        return false;
    }
    let salt = &db[separator + 1..];
    // Steps 2 and 12 to 14: H' = Hash(0x00 * 8 || mHash || salt).
    let m_hash = digest(&SHA256, message);
    let mut ctx = Context::new(&SHA256);
    ctx.update(&[0u8; 8]);
    ctx.update(m_hash.as_ref());
    ctx.update(salt);
    ctx.finish().as_ref() == h
}

/// MGF1 with SHA-256 (RFC 8017 Appendix B.2.1), `len` octets of mask.
fn mgf1_sha256(seed: &[u8], len: usize) -> Vec<u8> {
    let mut mask = Vec::with_capacity(len + SHA256_OUTPUT_LEN);
    let mut counter: u32 = 0;
    while mask.len() < len {
        let mut ctx = Context::new(&SHA256);
        ctx.update(seed);
        ctx.update(&counter.to_be_bytes());
        mask.extend_from_slice(ctx.finish().as_ref());
        counter += 1;
    }
    mask.truncate(len);
    mask
}

/// Differential vectors against OpenSSL (`fixtures/pss/differential.txt`,
/// made by `scripts/security/gen-pss-differential.py`, which the test never
/// runs): keys of odd sizes and both exponents, every salt length, one
/// defect at most per case, each verdict as OpenSSL gives it with
/// `PSS.AUTO`, and a refusal for a key outside 2048..=8192 bits.
#[cfg(test)]
mod differential {
    use super::verify_pss_sha256_any_salt;

    const VECTORS: &str = include_str!("../fixtures/pss/differential.txt");

    fn from_hex(text: &str) -> Vec<u8> {
        if text == "-" {
            return Vec::new();
        }
        (0..text.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&text[at..at + 2], 16).expect("hex"))
            .collect()
    }

    #[test]
    fn every_verdict_matches_openssl() {
        let mut key: Option<(Vec<u8>, Vec<u8>)> = None;
        let (mut cases, mut accepted) = (0usize, 0usize);
        let mut mismatches = Vec::new();
        for (line_no, line) in VECTORS.lines().enumerate() {
            let fields: Vec<&str> = line.split(' ').collect();
            match fields.as_slice() {
                ["K", modulus, exponent] => key = Some((from_hex(modulus), from_hex(exponent))),
                ["C", expected, defect, message, signature] => {
                    let (modulus, exponent) = key.as_ref().expect("a key before its cases");
                    let got = verify_pss_sha256_any_salt(
                        modulus,
                        exponent,
                        &from_hex(message),
                        &from_hex(signature),
                    );
                    let want = *expected == "1";
                    cases += 1;
                    accepted += usize::from(got);
                    if got != want {
                        mismatches.push(format!(
                            "line {}: {} expected {} got {}",
                            line_no + 1,
                            defect,
                            want,
                            got
                        ));
                    }
                }
                _ => panic!("line {}: not a vector: {:.40}", line_no + 1, line),
            }
        }
        assert!(mismatches.is_empty(), "{:#?}", mismatches);
        // The file is what it says: hundreds of cases, both verdicts.
        assert!(cases >= 300, "{} cases", cases);
        assert!(
            accepted >= 40 && cases - accepted >= 200,
            "{} of {}",
            accepted,
            cases
        );
    }
}
