// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Key material for the `BuiltinParticipantVolatileMessageSecureWriter` and
//! `BuiltinParticipantVolatileMessageSecureReader` (DDS Security v1.1
//! Sec.9.5.2.1.2, Table 67; cookies Table 68).
//!
//! This is the one channel whose key material needs no CryptoToken
//! exchange: both participants derive it independently and identically
//! from values each already holds once authentication completes.
//!
//! # Inputs, precisely
//!
//! - `shared_secret`: the authentication protocol's `SharedSecret` (Table
//!   53), defined as `SHA256(DHSharedSecret)` -- the SHA256 of the RAW ECDH
//!   output. This is NOT `HandshakeState::Complete::shared_secret`, which
//!   HDDS calls the MasterSharedSecret: an extra HKDF step over
//!   `challenge1 || challenge2` that Sec.9.3.2.5.3's SharedSecret (Table
//!   53) does not call for. Passing the wrong one still lets two HDDS
//!   builds of this version agree with each other (both derive the SAME
//!   non-spec value), but it is not what Table 67 asks for, and that is
//!   what a certifier reads.
//! - `challenge1`: the INITIATOR's 32-byte authentication nonce.
//! - `challenge2`: the RESPONDER's 32-byte authentication nonce.
//!
//!   Both roles of the SAME handshake must pass the SAME two values, in
//!   this same assignment (challenge1 = initiator's, challenge2 =
//!   responder's) -- not "mine" and "theirs" -- or the two sides derive
//!   different key material and the channel goes silently one-way.
//!
//! # Formula (Table 67, HMAC per Table 68)
//!
//! Table 68 defines the term `HMACsha256(key, data)` with the KEY as the
//! first argument and the DATA being MAC'd as the second. Table 67 then
//! writes:
//!
//! ```text
//! master_salt        = HMACsha256( SHA256(Challenge1 | KxSaltCookie | Challenge2) , SharedSecret )
//! master_sender_key  = HMACsha256( SHA256(Challenge2 | KxKeyCookie  | Challenge1) , SharedSecret )
//! ```
//!
//! so the KEY is the SHA256 of the challenges-and-cookie, and SharedSecret
//! is the DATA being authenticated -- NOT the other way around. (This
//! matches Cyclone DDS's builtin crypto plugin's own reading of the same
//! table, confirming it as public wire behaviour; no code from there is
//! used here.)
//!
//! ```text
//! sender_key_id             = 0
//! receiver_specific_key_id  = 0   (zero-length master_receiver_specific_key)
//! transformation_kind       = CRYPTO_TRANSFORMATION_KIND_AES256_GCM
//! ```
//!
//! The two cookie strings are not interchangeable, the challenge order is
//! swapped between the two formulas, and the key/data assignment above is
//! easy to read backwards (an earlier version of this module did): this is
//! the one place in this module where a byte-for-byte spec reading, not
//! "a reasonable HMAC", is the rule. See the `tests` module for a
//! known-answer vector computed independently of this file.

use crate::security::crypto::secure_submessage::WriterKeyMaterial;
use ring::{digest, hmac};

/// `KxSaltCookie` (Table 68): "the 16 bytes in the string 'keyexchange salt'".
const KX_SALT_COOKIE: &[u8; 16] = b"keyexchange salt";
/// `KxKeyCookie` (Table 68): "the 16 bytes in the string 'key exchange key'".
const KX_KEY_COOKIE: &[u8; 16] = b"key exchange key";

/// `sender_key_id` and `receiver_specific_key_id` of Table 67: both zero
/// (no receiver-specific authentication tag on this channel).
const ZERO_KEY_ID: [u8; 4] = [0, 0, 0, 0];

/// Derive the Table 67 KxKeys as a [`WriterKeyMaterial`], ready for
/// `secure_submessage::encode_datawriter_submessage` /
/// `decode_datawriter_submessage`.
///
/// See the module docs for exactly what `shared_secret`, `challenge1` and
/// `challenge2` must be, and for which operand of the HMAC is the key.
pub(crate) fn derive(
    shared_secret: &[u8; 32],
    challenge1: &[u8; 32],
    challenge2: &[u8; 32],
) -> WriterKeyMaterial {
    let master_salt = hmac_keyed_by_digest(challenge1, KX_SALT_COOKIE, challenge2, shared_secret);
    let master_sender_key =
        hmac_keyed_by_digest(challenge2, KX_KEY_COOKIE, challenge1, shared_secret);

    WriterKeyMaterial::new(*master_sender_key, *master_salt, ZERO_KEY_ID)
}

/// `HMAC-SHA256(key = SHA256(a | cookie | b), data = shared_secret)` --
/// the shape both Table 67 rows share. The key is the digest, NOT
/// `shared_secret`: Table 68's `HMACsha256(key, data)` names the FIRST
/// argument of Table 67's formula as the key, and Table 67 always writes
/// the digest first and `SharedSecret` second.
fn hmac_keyed_by_digest(
    a: &[u8; 32],
    cookie: &[u8; 16],
    b: &[u8; 32],
    shared_secret: &[u8; 32],
) -> zeroize::Zeroizing<[u8; 32]> {
    let mut input = Vec::with_capacity(32 + 16 + 32);
    input.extend_from_slice(a);
    input.extend_from_slice(cookie);
    input.extend_from_slice(b);
    let hashed = digest::digest(&digest::SHA256, &input);

    let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, hashed.as_ref());
    let tag = hmac::sign(&hmac_key, shared_secret);
    let mut out = zeroize::Zeroizing::new([0u8; 32]);
    out.copy_from_slice(tag.as_ref());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::crypto::secure_submessage::{
        decode_datawriter_submessage, encode_datawriter_submessage, Transformation,
    };

    /// A single PAD submessage (id 0x01, E flag, 4-byte body): the minimal
    /// fixture `decode_datawriter_submessage` accepts (one submessage,
    /// header included, whose length covers exactly what follows it).
    fn fake_submessage() -> Vec<u8> {
        vec![0x01, 0x01, 4, 0, 0, 0, 0, 0]
    }

    fn datagram_around(protected: &[u8]) -> Vec<u8> {
        let mut d = b"RTPS".to_vec();
        d.extend_from_slice(&[2, 5, 0x01, 0x1a]);
        d.extend_from_slice(&[0x22; 12]);
        d.extend_from_slice(protected);
        d
    }

    /// Known-answer test. `master_salt` and `master_sender_key` below were
    /// computed OUTSIDE this codebase, straight from Table 67/68's text,
    /// with this Python one-liner (shared_secret = 0xAB*32, challenge1 =
    /// 0xCD*32, challenge2 = 0xEF*32):
    ///
    /// ```text
    /// python3 -c "
    /// import hashlib, hmac
    /// shared_secret = bytes([0xAB]*32)
    /// challenge1 = bytes([0xCD]*32)
    /// challenge2 = bytes([0xEF]*32)
    /// salt_key = hashlib.sha256(challenge1 + b'keyexchange salt' + challenge2).digest()
    /// master_salt = hmac.new(salt_key, shared_secret, hashlib.sha256).digest()
    /// key_key = hashlib.sha256(challenge2 + b'key exchange key' + challenge1).digest()
    /// master_sender_key = hmac.new(key_key, shared_secret, hashlib.sha256).digest()
    /// print(master_salt.hex(), master_sender_key.hex())
    /// "
    /// ```
    ///
    /// `WriterKeyMaterial` exposes no raw-byte getter by design, so the
    /// vector is checked behaviorally: a `WriterKeyMaterial` built directly
    /// from these literal bytes (no formula computed in Rust at all) must
    /// decode what `derive` encodes, and vice versa. Two different 32-byte
    /// keys interoperating under AES-256-GCM is not a realistic accident,
    /// so this is as strong a pin as a direct byte comparison would be.
    #[test]
    fn derive_matches_a_known_answer_vector_computed_outside_this_codebase() {
        let shared_secret = [0xABu8; 32];
        let challenge1 = [0xCDu8; 32];
        let challenge2 = [0xEFu8; 32];

        #[rustfmt::skip]
        let known_master_salt: [u8; 32] = [
            0x49, 0xc3, 0xa8, 0x33, 0x2b, 0x6a, 0x30, 0x51, 0x6d, 0xeb, 0xcb, 0x37, 0x99, 0xf4,
            0xc3, 0x04, 0x90, 0xc7, 0x44, 0x35, 0x9f, 0xf8, 0xc6, 0xc6, 0xe9, 0xed, 0xe8, 0x9f,
            0xa8, 0xe8, 0x7d, 0x27,
        ];
        #[rustfmt::skip]
        let known_master_sender_key: [u8; 32] = [
            0x44, 0xed, 0x39, 0x60, 0x41, 0x5d, 0xf7, 0x8e, 0xa6, 0xd7, 0x2f, 0xde, 0x47, 0xe4,
            0x1a, 0x86, 0x41, 0x62, 0x30, 0x4a, 0x0b, 0x94, 0x34, 0x58, 0x2b, 0xcc, 0x50, 0x2e,
            0x48, 0x3c, 0x06, 0xc6,
        ];

        let produced = derive(&shared_secret, &challenge1, &challenge2);
        let from_known_answer =
            WriterKeyMaterial::new(known_master_sender_key, known_master_salt, ZERO_KEY_ID);

        let submessage = fake_submessage();
        let protected = encode_datawriter_submessage(&produced, &submessage).unwrap();
        let datagram = datagram_around(&protected);
        let decoded = decode_datawriter_submessage(&from_known_answer, &datagram, 20)
            .expect("derive() must produce exactly the known-answer bytes");
        assert_eq!(decoded.submessage, submessage);

        // And the reverse direction, so a one-sided coincidence cannot pass.
        let protected2 = encode_datawriter_submessage(&from_known_answer, &submessage).unwrap();
        let decoded2 = decode_datawriter_submessage(&produced, &datagram_around(&protected2), 20)
            .expect("derive() must produce exactly the known-answer bytes (reverse direction)");
        assert_eq!(decoded2.submessage, submessage);
    }

    /// Both roles of one handshake pass the SAME (challenge1, challenge2)
    /// assignment, so `derive` called twice with identical arguments (as
    /// each role independently would) agrees with itself: one encodes,
    /// the other decodes.
    #[test]
    fn both_handshake_roles_derive_byte_identical_material() {
        let shared_secret = [0x5Au8; 32];
        let challenge1 = [0x11u8; 32];
        let challenge2 = [0x22u8; 32];

        let initiator_side = derive(&shared_secret, &challenge1, &challenge2);
        let responder_side = derive(&shared_secret, &challenge1, &challenge2);

        let submessage = fake_submessage();
        let protected = encode_datawriter_submessage(&initiator_side, &submessage).unwrap();
        let decoded =
            decode_datawriter_submessage(&responder_side, &datagram_around(&protected), 20)
                .unwrap();
        assert_eq!(decoded.submessage, submessage);
    }

    /// Mutant: swap the key and data of the HMAC (the exact mistake an
    /// earlier version of `derive` made) -- use `shared_secret` as the
    /// HMAC key and the digest as the data, instead of Table 68's
    /// `HMACsha256(key = digest, data = shared_secret)`. The known-answer
    /// test above already fails this way, but this test names the mutant
    /// explicitly and is cheaper to read as a regression pin.
    #[test]
    fn swapping_the_hmac_key_and_data_breaks_interop() {
        let shared_secret = [0x33u8; 32];
        let challenge1 = [0x44u8; 32];
        let challenge2 = [0x55u8; 32];

        let correct = derive(&shared_secret, &challenge1, &challenge2);

        let mut salt_input = Vec::new();
        salt_input.extend_from_slice(&challenge1);
        salt_input.extend_from_slice(KX_SALT_COOKIE);
        salt_input.extend_from_slice(&challenge2);
        let salt_digest = digest::digest(&digest::SHA256, &salt_input);
        let mut correct_salt = [0u8; 32];
        correct_salt.copy_from_slice(salt_digest.as_ref());

        let mut key_input = Vec::new();
        key_input.extend_from_slice(&challenge2);
        key_input.extend_from_slice(KX_KEY_COOKIE);
        key_input.extend_from_slice(&challenge1);
        let key_digest = digest::digest(&digest::SHA256, &key_input);

        // Mutant: shared_secret as the HMAC key, the digest as the data.
        let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, &shared_secret);
        let tag = hmac::sign(&hmac_key, key_digest.as_ref());
        let mut mutant_sender_key = [0u8; 32];
        mutant_sender_key.copy_from_slice(tag.as_ref());

        let mutant = WriterKeyMaterial::new(mutant_sender_key, correct_salt, ZERO_KEY_ID);

        let submessage = fake_submessage();
        let protected = encode_datawriter_submessage(&correct, &submessage).unwrap();
        assert!(
            decode_datawriter_submessage(&mutant, &datagram_around(&protected), 20).is_err(),
            "swapping the HMAC key and data must break decoding"
        );
    }

    /// Mutant: swap the two cookie strings between the two formulas.
    #[test]
    fn swapping_the_cookies_breaks_interop() {
        let shared_secret = [0x66u8; 32];
        let challenge1 = [0x77u8; 32];
        let challenge2 = [0x88u8; 32];

        let correct = derive(&shared_secret, &challenge1, &challenge2);

        // Mutant: master_sender_key built with KX_SALT_COOKIE instead of
        // KX_KEY_COOKIE.
        let mutant_sender_key =
            hmac_keyed_by_digest(&challenge2, KX_SALT_COOKIE, &challenge1, &shared_secret);
        let correct_salt =
            hmac_keyed_by_digest(&challenge1, KX_SALT_COOKIE, &challenge2, &shared_secret);
        let mutant = WriterKeyMaterial::new(*mutant_sender_key, *correct_salt, ZERO_KEY_ID);

        let submessage = fake_submessage();
        let protected = encode_datawriter_submessage(&correct, &submessage).unwrap();
        assert!(
            decode_datawriter_submessage(&mutant, &datagram_around(&protected), 20).is_err(),
            "swapping the two cookies between the formulas must break decoding"
        );
    }

    /// Table 67: `sender_key_id` is 0 and the transformation is
    /// `CRYPTO_TRANSFORMATION_KIND_AES256_GCM`.
    #[test]
    fn sender_key_id_is_zero_and_transformation_is_aes256_gcm() {
        let material = derive(&[0x99u8; 32], &[0xAAu8; 32], &[0xBBu8; 32]);
        assert_eq!(material.key_id(), ZERO_KEY_ID);
        assert_eq!(material.transformation(), Transformation::Aes256Gcm);
    }

    /// A different shared secret (a different peer) must not land on the
    /// same key material.
    #[test]
    fn different_shared_secrets_yield_different_material() {
        let challenge1 = [0x01u8; 32];
        let challenge2 = [0x02u8; 32];
        let one = derive(&[0x10u8; 32], &challenge1, &challenge2);
        let two = derive(&[0x20u8; 32], &challenge1, &challenge2);

        let submessage = fake_submessage();
        let protected = encode_datawriter_submessage(&one, &submessage).unwrap();
        assert!(
            decode_datawriter_submessage(&two, &datagram_around(&protected), 20).is_err(),
            "two different shared secrets produced interoperable key material"
        );
    }
}
