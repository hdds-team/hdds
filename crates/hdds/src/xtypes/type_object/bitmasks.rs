// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Bitmask type definitions per OMG DDS-XTypes v1.3.
//!
//!
//! Complete and Minimal representations for named bit flags.

use crate::xtypes::{
    BitflagFlag, CompleteMemberDetail, CompleteTypeDetail, MinimalMemberDetail, MinimalTypeDetail,
};

// ============================================================================
// Bitmask Types
// ============================================================================

/// CompleteBitmaskType - Complete representation of a bitmask
#[derive(Debug, Clone, PartialEq)]
pub struct CompleteBitmaskType {
    /// Bitmask header (bit bound, detail)
    pub header: CompleteBitmaskHeader,

    /// Bitmask flags (bit positions)
    pub flag_seq: Vec<CompleteBitflag>,
}

/// MinimalBitmaskType - Minimal representation of a bitmask
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MinimalBitmaskType {
    /// Bitmask header (bit bound, detail)
    pub header: MinimalBitmaskHeader,

    /// Bitmask flags (bit positions)
    pub flag_seq: Vec<MinimalBitflag>,
}

/// CompleteBitmaskHeader - Complete bitmask metadata
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompleteBitmaskHeader {
    /// Bit bound (8, 16, 32, or 64 bits)
    pub bit_bound: i16,

    /// Complete detail (name, annotations)
    pub detail: CompleteTypeDetail,
}

/// MinimalBitmaskHeader - Minimal bitmask metadata
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MinimalBitmaskHeader {
    /// Bit bound (8, 16, 32, or 64 bits)
    pub bit_bound: i16,

    /// Minimal detail
    pub detail: MinimalTypeDetail,
}

/// CompleteBitflag - Complete representation of a bit flag
#[derive(Debug, Clone, PartialEq)]
pub struct CompleteBitflag {
    /// Common bitflag info
    pub common: CommonBitflag,

    /// Complete detail (name, annotations)
    pub detail: CompleteMemberDetail,
}

/// MinimalBitflag - Minimal representation of a bit flag
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MinimalBitflag {
    /// Common bitflag info
    pub common: CommonBitflag,

    /// Minimal detail (hash only)
    pub detail: MinimalMemberDetail,
}

/// CommonBitflag - Info shared between Complete and Minimal
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommonBitflag {
    /// Bit position (0-based)
    pub position: u16,

    /// Bitflag flags (currently unused)
    pub flags: BitflagFlag,
}
