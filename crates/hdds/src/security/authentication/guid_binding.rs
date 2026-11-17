// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! The participant GUID prefix of an authenticated participant, bound to its
//! identity certificate (DDS-Security 1.1 Sec.9.3.3, Table 52).
//!
//! `validate_local_identity` returns the `adjusted_participant_guid`: the
//! candidate GUID's entity id, and a GuidPrefix_t whose
//!
//! - bit 0 is 1;
//! - bits 1 to 47 are the first 47 bits of the SHA-256 hash of the ASN.1 DER
//!   encoding of the SubjectName of the identity certificate;
//! - bits 48 to 95 are the first 48 bits of the SHA-256 hash of the
//!   candidate participant GUID.
//!
//! `begin_handshake_reply` checks the first two of these on the participant
//! GUID the initiator presents, and fails the handshake when they do not
//! hold. So a certificate authenticates the prefixes of one subject only: a
//! participant holding a valid certificate cannot take the prefix of a
//! participant of another subject.
//!
//! Bits are numbered from the most significant bit of octet 0, as the
//! GuidPrefix_t is an octet array (DDSI-RTPS v2.5 Sec.9.3.1.5).
//!
//! # The prefixes of HDDS before this binding
//!
//! An HDDS participant used to take its prefix from its vendor id
//! (`01 1a`, bit 0 is 0) whatever its certificate. [`binding_of`] names
//! that shape [`PrefixBinding::HddsUnbound`]: a prefix that begins with the
//! HDDS vendor id is never an adjusted prefix, so a peer cannot claim the
//! exemption for a prefix this module derives, only for a prefix of the
//! old shape - which is what an HDDS release before the binding uses, and
//! all that a certificate holder could take before it.

/// The prefix of the participant whose identity certificate has the
/// SubjectName `subject_name_der`, from the `candidate` GUID (prefix and
/// entity id, 16 octets) it would have without security: the
/// `adjusted_participant_guid` prefix of DDS-Security 1.1 Sec.9.3.3,
/// Table 52, `validate_local_identity` (module docs).
#[must_use]
pub fn adjusted_participant_prefix(subject_name_der: &[u8], candidate: &[u8; 16]) -> [u8; 12] {
    let subject = sha256(subject_name_der);
    let candidate = sha256(candidate);
    let mut prefix = [0u8; 12];
    prefix[..6].copy_from_slice(&subject_bits(&subject));
    prefix[6..].copy_from_slice(&candidate[..6]);
    prefix
}

/// Bits 0 to 47 of a prefix bound to the subject whose SubjectName hashes
/// to `subject_hash`: a 1, then the first 47 bits of the hash.
fn subject_bits(subject_hash: &[u8; 32]) -> [u8; 6] {
    let mut first48 = [0u8; 8];
    first48[2..].copy_from_slice(&subject_hash[..6]);
    let value = (u64::from_be_bytes(first48) >> 1) | (1 << 47);
    let [_, _, b0, b1, b2, b3, b4, b5] = value.to_be_bytes();
    [b0, b1, b2, b3, b4, b5]
}

/// How a participant prefix stands toward the certificate it authenticated
/// with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrefixBinding {
    /// Bit 0 set and bits 1 to 47 those of the certificate's SubjectName
    /// (Sec.9.3.3, Table 52, `begin_handshake_reply`).
    Bound,
    /// The prefix of an HDDS release before the binding (module docs):
    /// accepted unbound, as those releases are.
    HddsUnbound,
    /// Neither: the handshake fails.
    Unbound,
}

/// How `prefix` stands toward the certificate whose SubjectName is
/// `subject_name_der`.
#[must_use]
pub fn binding_of(prefix: &[u8; 12], subject_name_der: &[u8]) -> PrefixBinding {
    if prefix[..6] == subject_bits(&sha256(subject_name_der)) {
        PrefixBinding::Bound
    } else if prefix[..2] == crate::core::rtps_constants::HDDS_VENDOR_ID {
        PrefixBinding::HddsUnbound
    } else {
        PrefixBinding::Unbound
    }
}

#[cfg(feature = "security")]
fn sha256(bytes: &[u8]) -> [u8; 32] {
    let digest = ring::digest::digest(&ring::digest::SHA256, bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_ref());
    out
}

/// The DER SubjectName of the certificate `cert_pem` (PEM, or DER).
#[cfg(feature = "security")]
pub(crate) fn subject_name_der(cert: &[u8]) -> Result<Vec<u8>, crate::security::SecurityError> {
    use crate::security::SecurityError;
    use x509_parser::prelude::FromDer;
    let der = match x509_parser::pem::parse_x509_pem(cert) {
        Ok((_, pem)) => pem.contents,
        Err(_) => cert.to_vec(),
    };
    let (_, parsed) = x509_parser::certificate::X509Certificate::from_der(&der).map_err(|e| {
        SecurityError::CertificateInvalid(format!("failed to parse X.509 certificate: {:?}", e))
    })?;
    Ok(parsed.subject().as_raw().to_vec())
}

#[cfg(all(test, feature = "security"))]
mod tests {
    use super::*;

    /// The layout of Table 52 read bit by bit, independently of
    /// `subject_bits`: bit i of the prefix against bit i-1 of the hash.
    #[test]
    fn the_adjusted_prefix_is_a_one_then_47_subject_bits_then_48_candidate_bits() {
        let subject = b"0\x161\x140\x12\x06\x03U\x04\x03\x0c\x0bparticipant";
        let candidate = [0x01, 0x1a, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0, 0, 1, 0xc1];
        let prefix = adjusted_participant_prefix(subject, &candidate);
        let bit = |bytes: &[u8], i: usize| (bytes[i / 8] >> (7 - i % 8)) & 1;
        let hs = sha256(subject);
        let hc = sha256(&candidate);
        assert_eq!(bit(&prefix, 0), 1, "bit 0");
        for i in 1..48 {
            assert_eq!(bit(&prefix, i), bit(&hs, i - 1), "bit {}", i);
        }
        for i in 48..96 {
            assert_eq!(bit(&prefix, i), bit(&hc, i - 48), "bit {}", i);
        }
        assert_eq!(binding_of(&prefix, subject), PrefixBinding::Bound);
    }

    #[test]
    fn a_prefix_is_bound_to_one_subject() {
        let candidate = [7u8; 16];
        let alice = adjusted_participant_prefix(b"alice", &candidate);
        assert_eq!(binding_of(&alice, b"alice"), PrefixBinding::Bound);
        assert_eq!(binding_of(&alice, b"bob"), PrefixBinding::Unbound);
        // Bits 48 and up are the candidate's: any value is bound.
        let mut other_instance = alice;
        other_instance[6..].copy_from_slice(&[0xEE; 6]);
        assert_eq!(binding_of(&other_instance, b"alice"), PrefixBinding::Bound);
        // Bit 0 cleared, the subject bits kept: not an adjusted prefix.
        let mut low = alice;
        low[0] &= 0x7f;
        assert_eq!(binding_of(&low, b"alice"), PrefixBinding::Unbound);
        // Each of bits 1 to 47 is checked.
        for i in 1..48 {
            let mut flipped = alice;
            flipped[i / 8] ^= 0x80 >> (i % 8);
            assert_eq!(
                binding_of(&flipped, b"alice"),
                PrefixBinding::Unbound,
                "bit {}",
                i
            );
        }
    }

    /// The old HDDS shape is never an adjusted prefix (its bit 0 is 0), so
    /// its exemption cannot be claimed for a prefix that is.
    #[test]
    fn the_hdds_unbound_shape_is_its_vendor_prefix_only() {
        let legacy = [0x01, 0x1a, 0x7f, 0, 0, 1, 0xe2, 0xe2, 0xe2, 0xe2, 0, 4];
        assert_eq!(binding_of(&legacy, b"alice"), PrefixBinding::HddsUnbound);
        let mut foreign = legacy;
        foreign[1] = 0x0f;
        assert_eq!(binding_of(&foreign, b"alice"), PrefixBinding::Unbound);
        for seed in 0..64u8 {
            let p = adjusted_participant_prefix(&[seed], &[seed; 16]);
            assert_ne!(p[..2], crate::core::rtps_constants::HDDS_VENDOR_ID);
        }
    }
}
