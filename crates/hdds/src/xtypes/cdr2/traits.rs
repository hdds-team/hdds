// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! CDR2 serialization traits
//!
//!
//! Defines the encoding/decoding contract for XTypes v1.3 type system.
//!
//! # References
//! - XTypes v1.3 Spec: Section 7.3 (CDR2 Encoding)
//! - DDS-XTYPES formal/2020-06-01

use crate::dds::Result;

/// CDR2 encoding trait
///
/// Types implementing this trait can be serialized to CDR2 little-endian format.
#[allow(dead_code)] // Used via trait implementations throughout cdr2 module
pub trait Cdr2Encode {
    /// Encode this value to CDR2 format
    ///
    /// # Arguments
    /// * `buf` - Output buffer (must have sufficient capacity)
    ///
    /// # Returns
    /// Number of bytes written
    fn encode_cdr2(&self, buf: &mut [u8]) -> Result<usize>;
}

/// CDR2 decoding trait
///
/// Types implementing this trait can be deserialized from CDR2 little-endian format.
#[allow(dead_code)] // Used via trait implementations throughout cdr2 module
pub trait Cdr2Decode: Sized {
    /// Decode a value from CDR2 format
    ///
    /// # Arguments
    /// * `buf` - Input buffer containing CDR2-encoded data
    ///
    /// # Returns
    /// Tuple of (decoded value, bytes consumed)
    fn decode_cdr2(buf: &[u8]) -> Result<(Self, usize)>;
}
