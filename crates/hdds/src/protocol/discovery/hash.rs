// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use super::constants::{FNV1A_OFFSET_BASIS_64, FNV1A_PRIME_64};

pub(super) fn simple_hash(s: &str) -> u64 {
    let mut hash = FNV1A_OFFSET_BASIS_64;
    for &byte in s.as_bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(FNV1A_PRIME_64);
    }
    hash
}
