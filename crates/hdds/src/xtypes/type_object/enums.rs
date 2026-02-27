// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Enumerated type definitions per OMG DDS-XTypes v1.3.
//!
//!
//! Complete and Minimal representations of enum types and literals.

use crate::xtypes::{
    CompleteMemberDetail, CompleteTypeDetail, EnumeratedLiteralFlag, MinimalMemberDetail,
    MinimalTypeDetail,
};

// ============================================================================
// Enumeration Types
// ============================================================================

/// CompleteEnumeratedType - Complete representation of an enum
#[derive(Debug, Clone, PartialEq)]
pub struct CompleteEnumeratedType {
    /// Enum header (bit bound, detail)
    pub header: CompleteEnumeratedHeader,

    /// Enum literals (values)
    pub literal_seq: Vec<CompleteEnumeratedLiteral>,
}

/// MinimalEnumeratedType - Minimal representation of an enum
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MinimalEnumeratedType {
    /// Enum header (bit bound, detail)
    pub header: MinimalEnumeratedHeader,

    /// Enum literals (values)
    pub literal_seq: Vec<MinimalEnumeratedLiteral>,
}

/// CompleteEnumeratedHeader - Complete enum metadata
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompleteEnumeratedHeader {
    /// Bit bound (8, 16, or 32 bits)
    pub bit_bound: i16,

    /// Complete detail (name, annotations)
    pub detail: CompleteTypeDetail,
}

/// MinimalEnumeratedHeader - Minimal enum metadata
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MinimalEnumeratedHeader {
    /// Bit bound (8, 16, or 32 bits)
    pub bit_bound: i16,

    /// Minimal detail (no names)
    pub detail: MinimalTypeDetail,
}

/// CompleteEnumeratedLiteral - Complete representation of an enum value
#[derive(Debug, Clone, PartialEq)]
pub struct CompleteEnumeratedLiteral {
    /// Common literal info
    pub common: CommonEnumeratedLiteral,

    /// Complete detail (name, annotations)
    pub detail: CompleteMemberDetail,
}

/// MinimalEnumeratedLiteral - Minimal representation of an enum value
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MinimalEnumeratedLiteral {
    /// Common literal info
    pub common: CommonEnumeratedLiteral,

    /// Minimal detail (hash only)
    pub detail: MinimalMemberDetail,
}

/// CommonEnumeratedLiteral - Info shared between Complete and Minimal
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommonEnumeratedLiteral {
    /// Literal value (e.g., RED = 0, GREEN = 1, BLUE = 2)
    pub value: i32,

    /// Literal flags (currently unused, reserved for future)
    pub flags: EnumeratedLiteralFlag,
}
