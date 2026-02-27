// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Struct type definitions per OMG DDS-XTypes v1.3.
//!
//!
//! Complete and Minimal representations of struct types, including
//! headers, members, and extensibility annotations.

use super::TypeIdentifier;
use crate::xtypes::{
    CompleteMemberDetail, CompleteTypeDetail, MemberFlag, MinimalMemberDetail, MinimalTypeDetail,
    StructTypeFlag,
};

// ============================================================================
// Struct Types
// ============================================================================

/// CompleteStructType - Complete representation of a struct
///
/// Per XTypes spec section 7.3.4.4.4:
/// A struct has:
/// - Extensibility flags (@final, @appendable, @mutable)
/// - Optional base type (inheritance)
/// - Member sequence (fields)
#[derive(Debug, Clone, PartialEq)]
pub struct CompleteStructType {
    /// Struct extensibility flags
    pub struct_flags: StructTypeFlag,

    /// Struct header (base type, detail)
    pub header: CompleteStructHeader,

    /// Struct members (fields)
    pub member_seq: Vec<CompleteStructMember>,
}

/// MinimalStructType - Minimal representation of a struct
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MinimalStructType {
    /// Struct extensibility flags
    pub struct_flags: StructTypeFlag,

    /// Struct header (base type hash only)
    pub header: MinimalStructHeader,

    /// Struct members (fields)
    pub member_seq: Vec<MinimalStructMember>,
}

/// CompleteStructHeader - Complete struct metadata
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompleteStructHeader {
    /// Base type (for inheritance), None if no base
    pub base_type: Option<TypeIdentifier>,

    /// Complete detail (name, annotations)
    pub detail: CompleteTypeDetail,
}

/// MinimalStructHeader - Minimal struct metadata
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MinimalStructHeader {
    /// Base type (for inheritance), None if no base
    pub base_type: Option<TypeIdentifier>,

    /// Minimal detail (no names)
    pub detail: MinimalTypeDetail,
}

/// CompleteStructMember - Complete representation of a struct member
#[derive(Debug, Clone, PartialEq)]
pub struct CompleteStructMember {
    /// Common member info (shared between Complete/Minimal)
    pub common: CommonStructMember,

    /// Complete detail (name, annotations)
    pub detail: CompleteMemberDetail,
}

/// MinimalStructMember - Minimal representation of a struct member
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MinimalStructMember {
    /// Common member info (shared between Complete/Minimal)
    pub common: CommonStructMember,

    /// Minimal detail (hash only)
    pub detail: MinimalMemberDetail,
}

/// CommonStructMember - Info shared between Complete and Minimal
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommonStructMember {
    /// Member ID (unique within struct)
    ///
    /// Per XTypes spec section 7.3.1.2:
    /// - Auto-assigned sequentially (0, 1, 2, ...) for @appendable/@final
    /// - Hash-based for @mutable (from member name)
    pub member_id: u32,

    /// Member flags (@key, @optional, @must_understand, etc.)
    pub member_flags: MemberFlag,

    /// Type of this member
    pub member_type_id: TypeIdentifier,
}
