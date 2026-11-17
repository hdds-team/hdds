// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Per-peer key inputs retained with the completed handshake.
//!
//! The volatile channel uses the authentication SharedSecret and both
//! challenges (DDS Security v1.1 Tables 67/68), retained here so both
//! handshake roles have them and session teardown drops them together.
//!
use crate::security::crypto::secure_submessage::WriterKeyMaterial;
use zeroize::Zeroize;

/// 32 bytes of AES-256 key material that clears itself on drop.
///
/// No `Clone`, no `Copy`, no `Deref`: duplication happens only inside this
/// module, through [`SecretKey::duplicate`], so every copy in existence is one
/// this module handed out and every one of them zeroizes. `Debug` is redacted so
/// a key cannot escape through a `{:?}` on an enclosing struct.
///
/// Contrast the retired `SessionKeyManager` registry, whose `get_session_key`
/// returned `[u8; 32]` by value: every lookup left an unzeroized copy on the
/// caller's stack.
pub struct SecretKey {
    bytes: [u8; 32],
}

impl SecretKey {
    /// Wrap raw key material.
    pub(crate) fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    /// Borrow the key for a cipher call.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    /// Hand out an owned copy that also zeroizes.
    fn duplicate(&self) -> Self {
        Self { bytes: self.bytes }
    }

    /// Crate-internal duplication for stores that hand out owned copies
    /// (`DataKeyStore`). Same contract as [`SecretKey::duplicate`]: every copy
    /// in existence came from this module's code paths and zeroizes on drop.
    /// Deliberately NOT `Clone`: an explicit name keeps duplication greppable.
    pub(crate) fn duplicate_for_store(&self) -> Self {
        self.duplicate()
    }

    /// Compare key material without making another owned copy.
    ///
    /// Constant time over the 32 bytes: the only caller compares an announced
    /// key against the one already installed, and an early-exit `==` on key
    /// material is a habit worth not having in a security plugin. Folded by
    /// hand rather than through `subtle` or ring's deprecated
    /// `verify_slices_are_equal`, so no dependency is added; `black_box`
    /// keeps the fold from being turned back into an early exit.
    pub(crate) fn same_material(&self, other: &Self) -> bool {
        let mut diff = 0u8;
        for (a, b) in self.bytes.iter().zip(other.bytes.iter()) {
            diff |= a ^ b;
        }
        std::hint::black_box(diff) == 0
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretKey(<redacted 32 bytes>)")
    }
}

/// Volatile-channel key inputs for one authenticated participant.
/// Owned by `HandshakeState::Complete` for exactly that session's lifetime.
pub struct PeerKeys {
    /// The authentication `SharedSecret` (Table 53: `SHA256(DHSharedSecret)`),
    /// Retained only to feed `crypto::kx_keys::derive` on demand. As sensitive
    /// as the MasterSharedSecret itself: zeroized on drop and redacted
    /// on `{:?}`.
    kx_shared_secret: SecretKey,
    /// Challenge1 (the initiator's nonce) of the completed handshake.
    challenge1: [u8; 32],
    /// Challenge2 (the responder's nonce) of the completed handshake.
    challenge2: [u8; 32],
}

impl std::fmt::Debug for PeerKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerKeys")
            .field("kx_shared_secret", &self.kx_shared_secret)
            .field("challenge1", &self.challenge1)
            .field("challenge2", &self.challenge2)
            .finish()
    }
}

impl PeerKeys {
    /// Retain the Table 67/68 inputs at handshake completion, in both roles.
    /// Challenge1 is the initiator's nonce; challenge2 is the responder's.
    pub(crate) fn new(
        kx_shared_secret: &[u8; 32],
        challenge1: &[u8; 32],
        challenge2: &[u8; 32],
    ) -> Self {
        Self {
            kx_shared_secret: SecretKey::from_bytes(*kx_shared_secret),
            challenge1: *challenge1,
            challenge2: *challenge2,
        }
    }

    /// The Table 67 KxKeys for this peer's volatile channel, re-derived on
    /// every call (the alternative to caching a `WriterKeyMaterial`, which
    /// exposes no raw bytes to duplicate by design).
    pub(crate) fn volatile_key_material(&self) -> WriterKeyMaterial {
        crate::security::crypto::kx_keys::derive(
            self.kx_shared_secret.as_bytes(),
            &self.challenge1,
            &self.challenge2,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Three distinct inputs for the kx-related arguments, so a test that
    /// mixes up which one goes where (e.g. passes challenge1 as
    /// kx_shared_secret) fails loudly instead of accidentally matching.
    fn kx_inputs() -> ([u8; 32], [u8; 32], [u8; 32]) {
        ([0x5Au8; 32], [0x11u8; 32], [0x22u8; 32])
    }

    /// `PeerKeys::volatile_key_material` must be the SAME call as
    /// `crypto::kx_keys::derive` with the inputs `PeerKeys::new` was
    /// given -- the wiring pin, not a re-test of the formula itself (that
    /// lives in `crypto::kx_keys`'s own tests).
    #[test]
    fn peer_keys_volatile_key_material_matches_kx_keys_derive() {
        let (kx_secret, c1, c2) = kx_inputs();
        let keys = PeerKeys::new(&kx_secret, &c1, &c2);

        let from_peer_keys = keys.volatile_key_material();
        let direct = crate::security::crypto::kx_keys::derive(&kx_secret, &c1, &c2);

        assert_eq!(from_peer_keys.key_id(), direct.key_id());
        assert_eq!(from_peer_keys.transformation(), direct.transformation());
        // Behavioral cross-check since `WriterKeyMaterial` exposes no raw
        // bytes: one encodes, the other must decode it.
        let submessage = vec![0x01, 0x01, 4, 0, 0, 0, 0, 0];
        let protected = crate::security::crypto::secure_submessage::encode_datawriter_submessage(
            &from_peer_keys,
            &submessage,
        )
        .expect("encode");
        let mut datagram = b"RTPS".to_vec();
        datagram.extend_from_slice(&[2, 5, 0x01, 0x1a]);
        datagram.extend_from_slice(&[0x33; 12]);
        datagram.extend_from_slice(&protected);
        let decoded = crate::security::crypto::secure_submessage::decode_datawriter_submessage(
            &direct, &datagram, 20,
        )
        .expect("decode with the independently-derived material");
        assert_eq!(decoded.submessage, submessage);
    }

    /// A duplicate is a real copy, not a view, and both zeroize independently.
    #[test]
    fn duplicated_secret_keys_carry_the_same_bytes() {
        let a = SecretKey::from_bytes([0x11; 32]);
        let b = a.duplicate_for_store();

        assert_eq!(a.as_bytes(), b.as_bytes());
        assert_ne!(
            a.as_bytes(),
            &[0u8; 32],
            "the duplicate preserves the secret"
        );
    }

    /// A key must not reach a log line through `{:?}` on the enclosing struct.
    #[test]
    fn debug_redacts_the_key_material() {
        let (kx_secret, c1, c2) = kx_inputs();
        let keys = PeerKeys::new(&kx_secret, &c1, &c2);

        let rendered = format!("{:?}", keys);
        assert!(
            rendered.contains("redacted"),
            "PeerKeys Debug rendered as {rendered}, which is how key material reaches a log file"
        );
        assert!(
            !rendered.contains("7e") && !rendered.contains("126"),
            "PeerKeys Debug leaked key bytes: {rendered}"
        );
        assert!(
            !rendered.contains("5a, 5a") && !rendered.contains("90, 90"),
            "PeerKeys Debug leaked the kx_shared_secret bytes: {rendered}"
        );
    }
}
