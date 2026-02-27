// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/// Compute 32-bit FNV-1a hash for fully qualified type names.
///
/// This matches the algorithm used in RTPS/XTypes for deterministic type IDs.
#[must_use]
pub fn compute_type_id(fqn: &str) -> u32 {
    const FNV_PRIME: u32 = 16_777_619;
    const FNV_OFFSET: u32 = 2_166_136_261;

    let mut hash = FNV_OFFSET;
    for byte in fqn.as_bytes() {
        hash ^= u32::from(*byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::compute_type_id;

    #[test]
    fn test_fnv_reproducible() {
        let name = "sensor::Temperature";
        let id1 = compute_type_id(name);
        let id2 = compute_type_id(name);
        assert_eq!(id1, id2);
    }
}
