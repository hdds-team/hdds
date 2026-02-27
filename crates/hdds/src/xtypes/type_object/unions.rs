// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Union type definitions per OMG DDS-XTypes v1.3.
//!
//!
//! Complete and Minimal representations of discriminated union types.

use super::TypeIdentifier;
use crate::xtypes::{
    CompleteMemberDetail, CompleteTypeDetail, MemberFlag, MinimalMemberDetail, MinimalTypeDetail,
    UnionTypeFlag,
};

// ============================================================================
// Union Types
// ============================================================================

/// CompleteUnionType - Complete representation of a union
#[derive(Debug, Clone, PartialEq)]
pub struct CompleteUnionType {
    /// Union flags (extensibility)
    pub union_flags: UnionTypeFlag,

    /// Union header (discriminator type, detail)
    pub header: CompleteUnionHeader,

    /// Union members (cases)
    pub member_seq: Vec<CompleteUnionMember>,
}

/// MinimalUnionType - Minimal representation of a union
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MinimalUnionType {
    /// Union flags (extensibility)
    pub union_flags: UnionTypeFlag,

    /// Union header (discriminator type, detail)
    pub header: MinimalUnionHeader,

    /// Union members (cases)
    pub member_seq: Vec<MinimalUnionMember>,
}

/// CompleteUnionHeader - Complete union metadata
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompleteUnionHeader {
    /// Discriminator type (e.g., TK_INT32, TK_ENUM)
    pub discriminator: TypeIdentifier,

    /// Complete detail (name, annotations)
    pub detail: CompleteTypeDetail,
}

/// MinimalUnionHeader - Minimal union metadata
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MinimalUnionHeader {
    /// Discriminator type
    pub discriminator: TypeIdentifier,

    /// Minimal detail
    pub detail: MinimalTypeDetail,
}

/// CompleteUnionMember - Complete representation of a union member
#[derive(Debug, Clone, PartialEq)]
pub struct CompleteUnionMember {
    /// Common member info
    pub common: CommonUnionMember,

    /// Complete detail (name, annotations)
    pub detail: CompleteMemberDetail,
}

/// MinimalUnionMember - Minimal representation of a union member
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MinimalUnionMember {
    /// Common member info
    pub common: CommonUnionMember,

    /// Minimal detail (hash only)
    pub detail: MinimalMemberDetail,
}

/// CommonUnionMember - Info shared between Complete and Minimal
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommonUnionMember {
    /// Member ID (unique within union)
    pub member_id: u32,

    /// Member flags (@default, etc.)
    pub member_flags: MemberFlag,

    /// Type of this member
    pub member_type_id: TypeIdentifier,

    /// Case labels (discriminator values)
    ///
    /// Example:
    /// ```idl
    /// union MyUnion switch(long) {
    ///   case 0:
    ///   case 1: long x;  // label_seq = [0, 1]
    ///   case 2: float y; // label_seq = [2]
    /// };
    /// ```
    pub label_seq: Vec<i32>,
}
