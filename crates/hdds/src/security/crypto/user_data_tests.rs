// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use super::*;
use crate::security::crypto::peer_keys::SecretKey;

// Independent Python cryptography AESGCM vectors, calculated directly from
// Sec.9.5.3.3.3-4: HMAC-SHA256(11*32, "SessionKey" | 22*32 | deadbeef),
// IV deadbeef0102030405060708, empty AAD for GCM, payload as AAD for GMAC.
const GCM: &str = "0000000400000a0bdeadbeef01020304050607080000000c21f14919de808052ed538dbbebbdd5755fd2881d8283e7b95d41e51c00000000";
const GMAC: &str = "0000000300000a0bdeadbeef01020304050607080007000301020304050000002484e564a515b14a3bf17d4bb92e4c4200000000";
const PLAIN: [u8; 12] = [0, 7, 0, 3, 1, 2, 3, 4, 5, 0, 0, 0];
const ID: u64 = 0x0a0b;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
fn material(transformation: Transformation) -> WriterKey {
    WriterKey::new(
        SecretKey::from_bytes([0x11; 32]),
        SecretKey::from_bytes([0x22; 32]),
    )
    .with_transformation(transformation)
}

#[test]
fn independent_crypto_elements_include_the_encapsulation_and_empty_gcm_aad() {
    for (kind, vector) in [
        (Transformation::Aes256Gcm, GCM),
        (Transformation::Aes256Gmac, GMAC),
    ] {
        let expected = unhex(vector);
        let m = material(kind);
        assert_eq!(secured_payload_key_id(&expected).unwrap(), ID);
        assert_eq!(decode_serialized_payload(ID, &m, &expected).unwrap(), PLAIN);
        let encoded = encode_with_iv(
            ID,
            &m,
            &PLAIN,
            [0xde, 0xad, 0xbe, 0xef],
            [1, 2, 3, 4, 5, 6, 7, 8],
        )
        .unwrap();
        assert_eq!(encoded, expected);
        assert_eq!(&encoded[..4], &kind.kind());
        if kind == Transformation::Aes256Gcm {
            assert_eq!(&encoded[20..24], &[0, 0, 0, 12]);
            assert_ne!(&encoded[24..28], &PLAIN[..4]);
        }
        assert_eq!(
            serialized_body(&PLAIN).unwrap(),
            (vec![1, 2, 3, 4, 5], crate::dds::CdrVersion::Xcdr2)
        );
    }
}

#[test]
fn altered_header_content_footer_or_announced_material_is_refused() {
    for (kind, vector) in [
        (Transformation::Aes256Gcm, GCM),
        (Transformation::Aes256Gmac, GMAC),
    ] {
        let bytes = unhex(vector);
        let m = material(kind);
        for i in 0..bytes.len() {
            let mut changed = bytes.clone();
            changed[i] ^= 1;
            assert!(
                decode_serialized_payload(ID, &m, &changed).is_err(),
                "accepted changed octet {i} of {kind:?}"
            );
        }
        for n in 0..bytes.len() {
            assert!(decode_serialized_payload(ID, &m, &bytes[..n]).is_err());
        }
        assert!(decode_serialized_payload(ID + 1, &m, &bytes).is_err());
        let wrong_salt = WriterKey::new(
            SecretKey::from_bytes([0x11; 32]),
            SecretKey::from_bytes([0x23; 32]),
        )
        .with_transformation(kind);
        assert!(decode_serialized_payload(ID, &wrong_salt, &bytes).is_err());
        let wrong_key = WriterKey::new(
            SecretKey::from_bytes([0x12; 32]),
            SecretKey::from_bytes([0x22; 32]),
        )
        .with_transformation(kind);
        assert!(decode_serialized_payload(ID, &wrong_key, &bytes).is_err());
    }
}

#[test]
fn fresh_ivs_and_representation_padding_preserve_exact_sample_bytes() {
    for repr in [0x0001, 0x0007, 0x0009, 0x000b] {
        for len in 1..=16 {
            let body = vec![0x51; len];
            let plain =
                crate::protocol::builder::encapsulate_serialized_payload(repr, &body, false);
            let m = material(Transformation::Aes256Gcm);
            let a = encode_serialized_payload(ID, &m, &plain).unwrap();
            let b = encode_serialized_payload(ID, &m, &plain).unwrap();
            assert_ne!(&a[8..20], &b[8..20]);
            assert_eq!(a.len() % 4, 0);
            let decoded = decode_serialized_payload(ID, &m, &a).unwrap();
            assert_eq!(decoded, plain);
            assert_eq!(serialized_body(&decoded).unwrap().0, body);
        }
    }
}

/// CryptoFooter's MAC is an octet array; the u32 count alone is aligned.
/// The independent AESGCM vector has five encrypted octets and a full-width id.
#[test]
fn unaligned_crypto_content_places_mac_before_count_alignment() {
    let expected = unhex("0000000401020a0bdeadbeef01020304050607080000000521f1491a9df2dfcdc93d8e43e68b643144fbacda6300000000000000");
    let id = 0x0102_0a0b;
    let plain = [0, 7, 0, 0, 0x42];
    let m = material(Transformation::Aes256Gcm);
    assert_eq!(secured_payload_key_id(&expected).unwrap(), id);
    assert_eq!(&expected[20..24], &[0, 0, 0, 5]);
    assert_eq!(&expected[29..45], unhex("f2dfcdc93d8e43e68b643144fbacda63"));
    assert_eq!(&expected[45..48], &[0; 3]);
    assert_eq!(&expected[48..], &[0; 4]);
    assert_eq!(decode_serialized_payload(id, &m, &expected).unwrap(), plain);
    let encoded = encode_with_iv(
        id,
        &m,
        &plain,
        [0xde, 0xad, 0xbe, 0xef],
        [1, 2, 3, 4, 5, 6, 7, 8],
    )
    .unwrap();
    assert_eq!(encoded, expected);
    assert!(
        encode_serialized_payload(id, &material(Transformation::Aes256Gmac), &plain).is_err(),
        "SIGN requires the caller's declared CDR padding to be present"
    );
}
