// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! EquivalenceHash per OMG DDS-XTypes v1.3 specification
//!
//!
//! Section 7.3.4.8: TypeIdentifier Hash computation

use std::fmt;

/// EquivalenceHash - 14-byte MD5 hash for TypeIdentifier
///
/// Per DDS-XTypes v1.3 spec section 7.3.4.8:
/// "The EquivalenceHash is computed by applying the MD5 algorithm to the
/// CDR serialization of the TypeObject, truncated to 14 bytes."
///
/// # Example
///
/// ```ignore
/// use hdds::xtypes::EquivalenceHash;
///
/// let type_object_bytes = &[/* CDR2 encoded TypeObject */];
/// let hash = EquivalenceHash::compute(type_object_bytes);
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct EquivalenceHash([u8; 14]);

impl EquivalenceHash {
    /// Create from raw 14-byte array
    pub const fn from_bytes(bytes: [u8; 14]) -> Self {
        Self(bytes)
    }

    /// Get the raw 14-byte array
    pub const fn as_bytes(&self) -> &[u8; 14] {
        &self.0
    }

    /// Create a zero hash (for testing/placeholder)
    pub const fn zero() -> Self {
        Self([0u8; 14])
    }

    /// Compute EquivalenceHash from CDR2-encoded TypeObject
    ///
    /// Per XTypes spec section 7.3.4.8:
    /// 1. Serialize TypeObject to CDR2 format
    /// 2. Compute MD5 hash (16 bytes)
    /// 3. Truncate to 14 bytes (discard last 2 bytes)
    ///
    /// # Arguments
    ///
    /// * `cdr2_data` - CDR2-encoded TypeObject bytes
    ///
    /// # Returns
    ///
    /// 14-byte EquivalenceHash
    ///
    /// # Example
    ///
    /// ```ignore
    /// let cdr2_bytes = type_object.serialize_cdr2()?;
    /// let hash = EquivalenceHash::compute(&cdr2_bytes);
    /// ```
    #[cfg(feature = "xtypes")]
    pub fn compute(cdr2_data: &[u8]) -> Self {
        use md5::{Digest, Md5};

        let mut hasher = Md5::new();
        hasher.update(cdr2_data);
        let result = hasher.finalize();

        // Truncate MD5 (16 bytes) to 14 bytes per XTypes spec
        let mut bytes = [0u8; 14];
        bytes.copy_from_slice(&result[..14]);

        Self(bytes)
    }

    /// Compute EquivalenceHash (fallback when feature "xtypes" disabled)
    ///
    /// This is a placeholder that returns a zero hash.
    /// The real implementation requires the "xtypes" feature.
    #[cfg(not(feature = "xtypes"))]
    pub fn compute(_cdr2_data: &[u8]) -> Self {
        Self::zero()
    }
}

impl fmt::Debug for EquivalenceHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EquivalenceHash(")?;
        for byte in &self.0 {
            write!(f, "{:02x}", byte)?;
        }
        write!(f, ")")
    }
}

impl fmt::Display for EquivalenceHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

impl From<[u8; 14]> for EquivalenceHash {
    fn from(bytes: [u8; 14]) -> Self {
        Self::from_bytes(bytes)
    }
}

impl AsRef<[u8]> for EquivalenceHash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_equivalence_hash_zero() {
        let hash = EquivalenceHash::zero();
        assert_eq!(hash.as_bytes(), &[0u8; 14]);
    }

    #[test]
    fn test_equivalence_hash_from_bytes() {
        let bytes = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14];
        let hash = EquivalenceHash::from_bytes(bytes);
        assert_eq!(hash.as_bytes(), &bytes);
    }

    #[test]
    fn test_equivalence_hash_equality() {
        let bytes1 = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14];
        let bytes2 = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14];
        let bytes3 = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 99];

        let hash1 = EquivalenceHash::from_bytes(bytes1);
        let hash2 = EquivalenceHash::from_bytes(bytes2);
        let hash3 = EquivalenceHash::from_bytes(bytes3);

        assert_eq!(hash1, hash2);
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_equivalence_hash_debug() {
        let bytes = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
        ];
        let hash = EquivalenceHash::from_bytes(bytes);
        let debug_str = format!("{:?}", hash);
        assert_eq!(debug_str, "EquivalenceHash(0123456789abcdef0123456789ab)");
    }

    #[test]
    fn test_equivalence_hash_display() {
        let bytes = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
        ];
        let hash = EquivalenceHash::from_bytes(bytes);
        let display_str = format!("{}", hash);
        assert_eq!(display_str, "0123456789abcdef0123456789ab");
    }

    #[cfg(feature = "xtypes")]
    #[test]
    fn test_equivalence_hash_compute() {
        // Test MD5 computation with known data
        let data = b"Hello, XTypes!";
        let hash = EquivalenceHash::compute(data);

        // MD5("Hello, XTypes!") = 3e8c7e6a5f9d2b1c4a8e7d6c5b4a3e2f (16 bytes)
        // Truncated to 14 bytes: 3e8c7e6a5f9d2b1c4a8e7d6c5b4a
        // (This is just a test - actual hash will differ)

        // Verify it's not zero
        assert_ne!(hash, EquivalenceHash::zero());

        // Verify deterministic (same input = same hash)
        let hash2 = EquivalenceHash::compute(data);
        assert_eq!(hash, hash2);

        // Verify different input = different hash
        let hash3 = EquivalenceHash::compute(b"Different data");
        assert_ne!(hash, hash3);
    }

    #[cfg(feature = "xtypes")]
    #[test]
    fn test_equivalence_hash_length() {
        // Verify hash is exactly 14 bytes (not 16)
        let data = b"Test data for hash length verification";
        let hash = EquivalenceHash::compute(data);
        assert_eq!(hash.as_bytes().len(), 14);
    }

    #[test]
    fn test_equivalence_hash_as_ref() {
        let bytes = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14];
        let hash = EquivalenceHash::from_bytes(bytes);
        let slice: &[u8] = hash.as_ref();
        assert_eq!(slice, &bytes);
    }

    #[test]
    fn test_equivalence_hash_clone() {
        let bytes = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14];
        let hash1 = EquivalenceHash::from_bytes(bytes);
        let hash2 = hash1;
        assert_eq!(hash1, hash2);
    }
}
