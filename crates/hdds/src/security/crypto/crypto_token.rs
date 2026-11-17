// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! The builtin `DDS:Crypto:AES_GCM_GMAC` `CryptoToken` (DDS Security v1.1
//! Sec.9.5.2.1, Table 66) and its `KeyMaterial_AES_GCM_GMAC` payload
//! (Sec.9.5.2.1.1).
//!
//! A `CryptoToken` is a `Token`, which Sec.7.2.4.2 defines as `typedef
//! DataHolder Token;` -- the same `DataHolder` shape the handshake tokens
//! and `crypto::volatile::WriterKeyAnnouncement` already ride in. Table 66
//! fixes it to exactly one binary property:
//!
//! ```text
//! CryptoToken (a DataHolder) {
//!     class_id          = "DDS:Crypto:AES_GCM_GMAC"
//!     binary_properties = [ ("dds.cryp.keymat", <bytes below>) ]
//! }
//! ```
//!
//! where `<bytes>` is "the Big Endian CDR Serialization of the
//! KeyMaterial_AES_GCM_GMAC structure" (Table 66) -- big endian
//! REGARDLESS of the DataHolder's own framing, which here is HDDS's
//! established little-endian `DataHolder` codec (`protocol::discovery::
//! spdp::data_holder`), the same one every other DataHolder-shaped token
//! in this tree uses. Two different endiannesses in one envelope is not a
//! contradiction: the outer `DataHolder` framing is HDDS's own choice (G4,
//! already not interoperable with other vendors' secure builtins), the
//! inner struct's byte layout is the one place Table 66 pins a literal,
//! auditable answer.
//!
//! Sec.9.5.2.1.1's struct, `@extensibility(FINAL)`:
//!
//! ```text
//! struct KeyMaterial_AES_GCM_GMAC {
//!     CryptoTransformKind   transformation_kind;          // octet[4], Sec.9.5.1.1 (no length prefix)
//!     sequence<octet, 32>   master_salt;                  // u32 BE length + up to 32 octets
//!     CryptoTransformKeyId  sender_key_id;                // octet[4]
//!     sequence<octet, 32>   master_sender_key;             // u32 BE length + up to 32 octets
//!     CryptoTransformKeyId  receiver_specific_key_id;      // octet[4]
//!     sequence<octet, 32>   master_receiver_specific_key;  // u32 BE length + up to 32 octets
//! };
//! ```
//!
//! "A zero value for receiver_specific_key_id indicates there is no
//! receiver-specific authentication tags and shall occur if and only if
//! the length of the master_receiver_specific_key is also zero" (Sec.
//! 9.5.2.1.1): `encode` and `decode` enforce that pairing.

use crate::protocol::discovery::spdp::data_holder::{parse_data_holder, serialize_data_holder};
use crate::security::SecurityError;

/// `class_id` of Table 66's `CryptoToken`.
pub(crate) const CRYPTO_TOKEN_CLASS_ID: &str = "DDS:Crypto:AES_GCM_GMAC";
/// The one binary property name Table 66 fixes.
pub(crate) const PROP_KEYMAT: &str = "dds.cryp.keymat";

/// `CRYPTO_TRANSFORMATION_KIND_AES256_GCM` (Sec.9.5.2.1.1, `{0,0,0,4}`).
pub(crate) const TRANSFORMATION_KIND_AES256_GCM: [u8; 4] = [0, 0, 0, 4];

const MAX_FIELD_LEN: usize = 32;

fn malformed(why: &str) -> SecurityError {
    SecurityError::CryptoError(format!("KeyMaterial_AES_GCM_GMAC: {}", why))
}

/// `KeyMaterial_AES_GCM_GMAC` (DDS Security v1.1 Sec.9.5.2.1.1, Table 66).
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct KeyMaterialAesGcmGmac {
    pub transformation_kind: [u8; 4],
    /// `sequence<octet, 32>`: at most 32 octets.
    pub master_salt: Vec<u8>,
    pub sender_key_id: [u8; 4],
    /// `sequence<octet, 32>`: at most 32 octets.
    pub master_sender_key: Vec<u8>,
    pub receiver_specific_key_id: [u8; 4],
    /// `sequence<octet, 32>`: at most 32 octets. Non-empty iff
    /// `receiver_specific_key_id != [0,0,0,0]` (Sec.9.5.2.1.1).
    pub master_receiver_specific_key: Vec<u8>,
}

/// Every copy of the key material is wiped when it drops (`Clone` makes copies
/// of the same kind, and each is wiped too). The three key fields are the
/// `master_*` values of Sec.9.5.2.1.1 and nothing else.
impl Drop for KeyMaterialAesGcmGmac {
    fn drop(&mut self) {
        self.wipe();
    }
}

impl KeyMaterialAesGcmGmac {
    /// Clear the three key fields, in place. `Drop` is the only caller in
    /// production; the test calls it on a live value.
    fn wipe(&mut self) {
        use zeroize::Zeroize;
        self.master_salt.zeroize();
        self.master_sender_key.zeroize();
        self.master_receiver_specific_key.zeroize();
    }
}

/// Redacted: the key fields print their lengths, never their bytes, so a
/// `{:?}` on a log line or a panic message cannot carry the key.
impl std::fmt::Debug for KeyMaterialAesGcmGmac {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyMaterialAesGcmGmac")
            .field("transformation_kind", &self.transformation_kind)
            .field(
                "master_salt",
                &format_args!("<redacted {} bytes>", self.master_salt.len()),
            )
            .field("sender_key_id", &self.sender_key_id)
            .field(
                "master_sender_key",
                &format_args!("<redacted {} bytes>", self.master_sender_key.len()),
            )
            .field("receiver_specific_key_id", &self.receiver_specific_key_id)
            .field(
                "master_receiver_specific_key",
                &format_args!(
                    "<redacted {} bytes>",
                    self.master_receiver_specific_key.len()
                ),
            )
            .finish()
    }
}

impl KeyMaterialAesGcmGmac {
    /// Big Endian CDR serialization of the struct (Table 66), exactly as
    /// specified: no encapsulation header, the four-octet arrays with no
    /// length prefix, the three sequences each a u32 BE length followed by
    /// its octets.
    pub(crate) fn encode(&self) -> Result<zeroize::Zeroizing<Vec<u8>>, SecurityError> {
        for (name, field) in [
            ("master_salt", &self.master_salt),
            ("master_sender_key", &self.master_sender_key),
            (
                "master_receiver_specific_key",
                &self.master_receiver_specific_key,
            ),
        ] {
            if field.len() > MAX_FIELD_LEN {
                return Err(malformed(&format!(
                    "{} is {} octets, the bound is {}",
                    name,
                    field.len(),
                    MAX_FIELD_LEN
                )));
            }
        }
        let no_receiver_key = self.receiver_specific_key_id == [0, 0, 0, 0];
        if no_receiver_key != self.master_receiver_specific_key.is_empty() {
            return Err(malformed(
                "receiver_specific_key_id is zero iff master_receiver_specific_key is empty",
            ));
        }

        let mut out = Vec::with_capacity(4 + 4 + 32 + 4 + 4 + 32 + 4 + 4 + 32);
        out.extend_from_slice(&self.transformation_kind);
        write_be_sequence(&mut out, &self.master_salt)?;
        out.extend_from_slice(&self.sender_key_id);
        write_be_sequence(&mut out, &self.master_sender_key)?;
        out.extend_from_slice(&self.receiver_specific_key_id);
        write_be_sequence(&mut out, &self.master_receiver_specific_key)?;
        Ok(zeroize::Zeroizing::new(out))
    }

    /// Inverse of [`Self::encode`].
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, SecurityError> {
        let mut at = 0usize;
        let transformation_kind = read_fixed4(bytes, &mut at)?;
        let master_salt = read_be_sequence(bytes, &mut at)?;
        let sender_key_id = read_fixed4(bytes, &mut at)?;
        let master_sender_key = read_be_sequence(bytes, &mut at)?;
        let receiver_specific_key_id = read_fixed4(bytes, &mut at)?;
        let master_receiver_specific_key = read_be_sequence(bytes, &mut at)?;

        let no_receiver_key = receiver_specific_key_id == [0, 0, 0, 0];
        if no_receiver_key != master_receiver_specific_key.is_empty() {
            return Err(malformed(
                "receiver_specific_key_id is zero iff master_receiver_specific_key is empty",
            ));
        }

        Ok(Self {
            transformation_kind,
            master_salt,
            sender_key_id,
            master_sender_key,
            receiver_specific_key_id,
            master_receiver_specific_key,
        })
    }

    /// Wrap as the `CryptoToken` DataHolder (Table 66), in HDDS's own
    /// little-endian `DataHolder` framing (the outer envelope, not this
    /// struct's own big-endian bytes).
    pub(crate) fn to_crypto_token(&self) -> Result<Vec<u8>, SecurityError> {
        // The keymat moves into the data holder, which is the wire blob itself:
        // taken, not copied, so no second unwiped copy is made here.
        let mut keymat = self.encode()?;
        let keymat_bytes = std::mem::take(&mut *keymat);
        serialize_data_holder(
            CRYPTO_TOKEN_CLASS_ID,
            &[],
            &[(PROP_KEYMAT.to_string(), keymat_bytes, true)],
        )
        .map_err(|e| malformed(&format!("does not fit its CDR length fields: {:?}", e)))
    }

    /// Inverse of [`Self::to_crypto_token`].
    pub(crate) fn from_crypto_token(holder_bytes: &[u8]) -> Result<Self, SecurityError> {
        let holder = parse_data_holder(holder_bytes)
            .ok_or_else(|| malformed("not a well-formed DataHolder"))?;
        if holder.class_id != CRYPTO_TOKEN_CLASS_ID {
            return Err(malformed(&format!(
                "unexpected class id '{}'",
                holder.class_id
            )));
        }
        let keymat = holder
            .binary_properties
            .iter()
            .find(|(name, _, _)| name == PROP_KEYMAT)
            .map(|(_, v, _)| v.as_slice())
            .ok_or_else(|| malformed(&format!("missing property '{}'", PROP_KEYMAT)))?;
        Self::decode(keymat)
    }
}

fn write_be_sequence(out: &mut Vec<u8>, field: &[u8]) -> Result<(), SecurityError> {
    // The wire prefix is 32 bits: a longer field must be refused, never
    // written with a wrapped length.
    debug_assert!(
        u32::try_from(field.len()).is_ok(),
        "encode bounds every field to MAX_FIELD_LEN"
    );
    let len = u32::try_from(field.len()).map_err(|_| {
        log::error!("token field refused: its length does not fit the 32-bit prefix");
        malformed("field length does not fit the 32-bit prefix")
    })?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(field);
    Ok(())
}

fn read_fixed4(bytes: &[u8], at: &mut usize) -> Result<[u8; 4], SecurityError> {
    let slice = bytes
        .get(*at..*at + 4)
        .ok_or_else(|| malformed("truncated 4-octet field"))?;
    *at += 4;
    debug_assert!(slice.len() == 4, "a four-octet get yields four octets");
    <[u8; 4]>::try_from(slice).map_err(|_| {
        log::error!("truncated 4-octet field after a length check");
        malformed("truncated 4-octet field")
    })
}

fn read_be_sequence(bytes: &[u8], at: &mut usize) -> Result<Vec<u8>, SecurityError> {
    let len_bytes = bytes
        .get(*at..*at + 4)
        .ok_or_else(|| malformed("truncated sequence length"))?;
    debug_assert!(len_bytes.len() == 4, "a four-octet get yields four octets");
    let len_octets = <[u8; 4]>::try_from(len_bytes).map_err(|_| {
        log::error!("truncated sequence length after a length check");
        malformed("truncated sequence length")
    })?;
    let len = u32::from_be_bytes(len_octets) as usize;
    *at += 4;
    if len > MAX_FIELD_LEN {
        return Err(malformed(&format!(
            "sequence length {} exceeds the bound of {}",
            len, MAX_FIELD_LEN
        )));
    }
    let data = bytes
        .get(*at..*at + len)
        .ok_or_else(|| malformed("sequence runs past the end"))?
        .to_vec();
    *at += len;
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Known-answer test. The expected bytes below were derived by hand,
    /// field by field, straight from Table 66's layout (no Rust code ran
    /// to produce them):
    ///
    /// ```text
    /// transformation_kind            00 00 00 04                     (4 bytes)
    /// master_salt   len=32 (0x20)     00 00 00 20                     (4 bytes)
    ///               data              0x11 * 32                       (32 bytes)
    /// sender_key_id                   DE AD BE EF                     (4 bytes)
    /// master_sender_key len=32        00 00 00 20                     (4 bytes)
    ///                   data         0x22 * 32                       (32 bytes)
    /// receiver_specific_key_id        00 00 00 00                     (4 bytes)
    /// master_receiver_specific_key    00 00 00 00                     (4 bytes, len=0)
    ///                                 (no data)
    /// -----------------------------------------------------------------
    /// total                           4+4+32+4+4+32+4+4 = 88 bytes
    /// ```
    /// Key bytes must not reach a `{:?}`: the fields print their lengths.
    #[test]
    fn debug_prints_the_key_lengths_and_never_the_key_bytes() {
        let material = KeyMaterialAesGcmGmac {
            transformation_kind: [0, 0, 0, 4],
            master_salt: vec![0xA5; 32],
            sender_key_id: [0, 0, 0, 1],
            master_sender_key: vec![0x5A; 32],
            receiver_specific_key_id: [0, 0, 0, 0],
            master_receiver_specific_key: vec![],
        };
        let shown = format!("{:?}", material);
        assert!(shown.contains("<redacted 32 bytes>"), "got: {}", shown);
        assert!(
            !shown.contains("165") && !shown.contains("90"),
            "0xA5 (165) and 0x5A (90) must not print: {}",
            shown
        );
    }

    /// The key fields are cleared in place: the wipe `Drop` runs leaves no
    /// key bytes behind in the value it drops.
    #[test]
    fn wipe_clears_every_key_field() {
        let mut material = KeyMaterialAesGcmGmac {
            transformation_kind: [0, 0, 0, 4],
            master_salt: vec![0xA5; 32],
            sender_key_id: [0, 0, 0, 1],
            master_sender_key: vec![0x5A; 32],
            receiver_specific_key_id: [0, 0, 0, 2],
            master_receiver_specific_key: vec![0x3C; 32],
        };
        material.wipe();
        assert!(material.master_salt.is_empty());
        assert!(material.master_sender_key.is_empty());
        assert!(material.master_receiver_specific_key.is_empty());
    }

    #[test]
    fn encode_matches_a_known_answer_vector() {
        let material = KeyMaterialAesGcmGmac {
            transformation_kind: TRANSFORMATION_KIND_AES256_GCM,
            master_salt: vec![0x11; 32],
            sender_key_id: [0xDE, 0xAD, 0xBE, 0xEF],
            master_sender_key: vec![0x22; 32],
            receiver_specific_key_id: [0, 0, 0, 0],
            master_receiver_specific_key: vec![],
        };

        let mut expected = Vec::with_capacity(88);
        expected.extend_from_slice(&[0x00, 0x00, 0x00, 0x04]);
        expected.extend_from_slice(&[0x00, 0x00, 0x00, 0x20]);
        expected.extend_from_slice(&[0x11; 32]);
        expected.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        expected.extend_from_slice(&[0x00, 0x00, 0x00, 0x20]);
        expected.extend_from_slice(&[0x22; 32]);
        expected.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        expected.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        assert_eq!(expected.len(), 88);

        let encoded = material.encode().expect("encode");
        assert_eq!(*encoded, expected);

        let decoded = KeyMaterialAesGcmGmac::decode(&encoded).expect("decode");
        assert_eq!(decoded, material);
    }

    /// Mutant: encode `master_salt`'s length as little-endian instead of
    /// Table 66's big endian. Must diverge from the known-answer vector.
    #[test]
    fn a_little_endian_length_mutant_does_not_match_the_known_answer() {
        let material = KeyMaterialAesGcmGmac {
            transformation_kind: TRANSFORMATION_KIND_AES256_GCM,
            master_salt: vec![0x11; 32],
            sender_key_id: [0xDE, 0xAD, 0xBE, 0xEF],
            master_sender_key: vec![0x22; 32],
            receiver_specific_key_id: [0, 0, 0, 0],
            master_receiver_specific_key: vec![],
        };
        let mut mutant = material.encode().expect("encode");
        // The master_salt length field is at offset 4..8; corrupt it to a
        // little-endian-looking encoding of the same logical value (32)
        // read as 0x20000000 big endian -- wildly different bytes.
        mutant[4..8].copy_from_slice(&32u32.to_le_bytes());
        assert!(
            KeyMaterialAesGcmGmac::decode(&mutant).is_err(),
            "a little-endian length must not decode as a valid sequence length"
        );
    }

    /// Sec.9.5.2.1.1: receiver_specific_key_id is zero if and only if
    /// master_receiver_specific_key is empty.
    #[test]
    fn receiver_key_id_and_key_length_must_agree() {
        let mismatched = KeyMaterialAesGcmGmac {
            transformation_kind: TRANSFORMATION_KIND_AES256_GCM,
            master_salt: vec![0x01; 32],
            sender_key_id: [1, 0, 0, 0],
            master_sender_key: vec![0x02; 32],
            receiver_specific_key_id: [0, 0, 0, 0],
            master_receiver_specific_key: vec![0x03; 16], // non-empty, but id is zero
        };
        assert!(mismatched.encode().is_err());
    }

    /// `encode()` refusing a mismatched pairing proves nothing about
    /// `decode()`: bytes `decode()` receives did not necessarily pass
    /// through this crate's own `encode()` at all (a hostile or buggy
    /// peer hand-builds its own). Built by hand here, byte for byte,
    /// never touched by `encode`, so the pairing rule is pinned on
    /// `decode()`'s OWN enforcement, not borrowed from the test above.
    #[test]
    fn decode_rejects_a_hand_built_mismatched_pairing_never_touched_by_encode() {
        // receiver_specific_key_id != 0, master_receiver_specific_key empty.
        let mut nonzero_id_empty_key = Vec::new();
        nonzero_id_empty_key.extend_from_slice(&TRANSFORMATION_KIND_AES256_GCM);
        nonzero_id_empty_key.extend_from_slice(&0u32.to_be_bytes()); // master_salt: len 0
        nonzero_id_empty_key.extend_from_slice(&[0, 0, 0, 1]); // sender_key_id
        nonzero_id_empty_key.extend_from_slice(&0u32.to_be_bytes()); // master_sender_key: len 0
        nonzero_id_empty_key.extend_from_slice(&[0, 0, 0, 7]); // receiver_specific_key_id != 0
        nonzero_id_empty_key.extend_from_slice(&0u32.to_be_bytes()); // master_receiver_specific_key: len 0 (EMPTY)
        assert!(
            KeyMaterialAesGcmGmac::decode(&nonzero_id_empty_key).is_err(),
            "receiver_specific_key_id != 0 with an empty master_receiver_specific_key must be \
             refused by decode() itself"
        );

        // receiver_specific_key_id == 0, master_receiver_specific_key non-empty.
        let mut zero_id_nonempty_key = Vec::new();
        zero_id_nonempty_key.extend_from_slice(&TRANSFORMATION_KIND_AES256_GCM);
        zero_id_nonempty_key.extend_from_slice(&0u32.to_be_bytes());
        zero_id_nonempty_key.extend_from_slice(&[0, 0, 0, 1]);
        zero_id_nonempty_key.extend_from_slice(&0u32.to_be_bytes());
        zero_id_nonempty_key.extend_from_slice(&[0, 0, 0, 0]); // receiver_specific_key_id == 0
        zero_id_nonempty_key.extend_from_slice(&16u32.to_be_bytes()); // len 16 (NON-EMPTY)
        zero_id_nonempty_key.extend_from_slice(&[0xCC; 16]);
        assert!(
            KeyMaterialAesGcmGmac::decode(&zero_id_nonempty_key).is_err(),
            "receiver_specific_key_id == 0 with a non-empty master_receiver_specific_key must \
             be refused by decode() itself"
        );
    }

    /// A struct with a non-zero receiver key id and matching key material
    /// round-trips through `encode`/`decode`.
    #[test]
    fn a_receiver_specific_key_round_trips() {
        let material = KeyMaterialAesGcmGmac {
            transformation_kind: TRANSFORMATION_KIND_AES256_GCM,
            master_salt: vec![0x05; 32],
            sender_key_id: [9, 9, 9, 9],
            master_sender_key: vec![0x06; 32],
            receiver_specific_key_id: [7, 7, 7, 7],
            master_receiver_specific_key: vec![0x08; 32],
        };
        let encoded = material.encode().expect("encode");
        let decoded = KeyMaterialAesGcmGmac::decode(&encoded).expect("decode");
        assert_eq!(decoded, material);
    }

    /// A length beyond the `sequence<octet, 32>` bound is refused.
    #[test]
    fn a_field_over_the_32_octet_bound_is_refused() {
        let over = KeyMaterialAesGcmGmac {
            transformation_kind: TRANSFORMATION_KIND_AES256_GCM,
            master_salt: vec![0x01; 33],
            sender_key_id: [0, 0, 0, 1],
            master_sender_key: vec![0x02; 32],
            receiver_specific_key_id: [0, 0, 0, 0],
            master_receiver_specific_key: vec![],
        };
        assert!(over.encode().is_err());
    }

    /// `to_crypto_token` / `from_crypto_token`: the full Table 66 DataHolder
    /// wrapping, class id and property name included.
    #[test]
    fn crypto_token_round_trips_through_the_data_holder() {
        let material = KeyMaterialAesGcmGmac {
            transformation_kind: TRANSFORMATION_KIND_AES256_GCM,
            master_salt: vec![0xAA; 32],
            sender_key_id: [1, 2, 3, 4],
            master_sender_key: vec![0xBB; 32],
            receiver_specific_key_id: [0, 0, 0, 0],
            master_receiver_specific_key: vec![],
        };
        let token = material.to_crypto_token().expect("to_crypto_token");
        let holder = parse_data_holder(&token).expect("parse");
        assert_eq!(holder.class_id, CRYPTO_TOKEN_CLASS_ID);
        assert_eq!(holder.binary_properties.len(), 1);
        assert_eq!(holder.binary_properties[0].0, PROP_KEYMAT);

        let decoded = KeyMaterialAesGcmGmac::from_crypto_token(&token).expect("from_crypto_token");
        assert_eq!(decoded, material);
    }

    /// A DataHolder of the wrong class id is refused, not misread as a
    /// CryptoToken.
    #[test]
    fn a_wrong_class_id_is_refused() {
        let token = serialize_data_holder("DDS:Crypto:SOMETHING_ELSE", &[], &[]).expect("encode");
        assert!(KeyMaterialAesGcmGmac::from_crypto_token(&token).is_err());
    }

    /// A CryptoToken missing its one property is refused.
    #[test]
    fn a_crypto_token_without_the_keymat_property_is_refused() {
        let token = serialize_data_holder(CRYPTO_TOKEN_CLASS_ID, &[], &[]).expect("encode");
        assert!(KeyMaterialAesGcmGmac::from_crypto_token(&token).is_err());
    }
}
