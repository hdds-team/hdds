// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! SHA-256 and HMAC-SHA-256 for the cloud backends' request signing
//! (AWS SigV4, Azure Shared Key), delegated to `ring`.
//!
//! `ring` is already linked under `cloud-discovery` through
//! `reqwest -> rustls`, so this adds no crate. This module is the one
//! audited primitive for both the AWS and Azure backends, instead of private
//! hand-rolled FIPS 180-4 copies.

//! Internal to the crate: its consumer is `aws_sigv4.rs` (module-declared
//! since the AWS Cloud Map backend landed), and the Azure Shared Key
//! signer will be the second. `pub(crate)` rather than `pub` because
//! nothing outside this crate should reach for a primitive; the
//! `dead_code` allowance covers the helpers no signer uses yet in a build
//! where only one of them is compiled.
#![cfg_attr(not(test), allow(dead_code))]

use ring::{digest, hmac};

/// SHA-256 digest of `data`.
pub(crate) fn hash(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(digest::digest(&digest::SHA256, data).as_ref());
    out
}

/// HMAC-SHA-256 of `data` under `key`.
pub(crate) fn hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
    let key = hmac::Key::new(hmac::HMAC_SHA256, key);
    let mut out = [0u8; 32];
    out.copy_from_slice(hmac::sign(&key, data).as_ref());
    out
}

/// Lowercase hexadecimal rendering, as every signing scheme wants it.
pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // FIPS 180-4 / NIST CAVP known answers.
    #[test]
    fn sha256_known_answers() {
        assert_eq!(
            hex(&hash(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex(&hash(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex(&hash(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    // RFC 4231 test cases 1 and 2.
    #[test]
    fn hmac_sha256_rfc4231_vectors() {
        assert_eq!(
            hex(&hmac(&[0x0b; 20], b"Hi There")),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
        assert_eq!(
            hex(&hmac(b"Jefe", b"what do ya want for nothing?")),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }
}
