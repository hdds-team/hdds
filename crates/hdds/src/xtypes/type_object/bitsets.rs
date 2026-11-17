// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Bitset type definitions per OMG DDS-XTypes v1.3 and IDL 4.2.
//!
//!
//! Complete and Minimal representations for fixed-size bit containers.

use super::TypeIdentifier;
use crate::xtypes::{
    BitfieldFlag, BitsetTypeFlag, CompleteMemberDetail, CompleteTypeDetail, MinimalMemberDetail,
    MinimalTypeDetail,
};

// ============================================================================
// Bitset Types (IDL 4.2)
// ============================================================================

/// CompleteBitsetType - Complete representation of a bitset
#[derive(Debug, Clone, PartialEq)]
pub struct CompleteBitsetType {
    /// Bitset flags
    pub bitset_flags: BitsetTypeFlag,

    /// Bitset header (detail)
    pub header: CompleteBitsetHeader,

    /// Bitset fields
    pub field_seq: Vec<CompleteBitfield>,
}

/// MinimalBitsetType - Minimal representation of a bitset
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MinimalBitsetType {
    /// Bitset flags
    pub bitset_flags: BitsetTypeFlag,

    /// Bitset header (empty)
    pub header: MinimalBitsetHeader,

    /// Bitset fields
    pub field_seq: Vec<MinimalBitfield>,
}

/// CompleteBitsetHeader - Complete bitset metadata
///
/// DDS-XTypes 1.3 Annex B: `@appendable struct CompleteBitsetHeader {
/// CompleteTypeDetail detail; }`. A bitset has no base type in 1.3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompleteBitsetHeader {
    /// Complete detail (name, annotations)
    pub detail: CompleteTypeDetail,
}

/// MinimalBitsetHeader - Minimal bitset metadata
///
/// DDS-XTypes 1.3 Annex B: an empty `@appendable` struct; `detail` is the
/// empty `MinimalTypeDetail` and serializes nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MinimalBitsetHeader {
    /// Minimal detail
    pub detail: MinimalTypeDetail,
}

/// CompleteBitfield - Complete representation of a bitfield
#[derive(Debug, Clone, PartialEq)]
pub struct CompleteBitfield {
    /// Common bitfield info
    pub common: CommonBitfield,

    /// Complete detail (name, annotations)
    pub detail: CompleteMemberDetail,
}

/// MinimalBitfield - Minimal representation of a bitfield
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MinimalBitfield {
    /// Common bitfield info
    pub common: CommonBitfield,

    /// Minimal detail (hash only)
    pub detail: MinimalMemberDetail,
}

/// CommonBitfield - Info shared between Complete and Minimal
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommonBitfield {
    /// Bit position (offset in bits)
    pub position: u16,

    /// Bitfield flags
    pub flags: BitfieldFlag,

    /// Bit count (width in bits)
    pub bit_count: u8,

    /// Holder type (TK_BOOLEAN, TK_BYTE, TK_INT8, etc.)
    pub holder_type: TypeIdentifier,
}
