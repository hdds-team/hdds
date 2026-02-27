// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Alias (typedef) type definitions per OMG DDS-XTypes v1.3.
//!
//!
//! Complete and Minimal representations of type aliases.

use super::TypeIdentifier;
use crate::xtypes::{AliasTypeFlag, CompleteTypeDetail, MinimalTypeDetail, TypeRelationFlag};

// ============================================================================
// Alias Types (typedef)
// ============================================================================

/// CompleteAliasType - Complete representation of a type alias
///
/// Corresponds to IDL: `typedef T MyAlias;`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompleteAliasType {
    /// Alias flags
    pub alias_flags: AliasTypeFlag,

    /// Alias header (detail)
    pub header: CompleteAliasHeader,

    /// Aliased type
    pub body: CompleteAliasBody,
}

/// MinimalAliasType - Minimal representation of a type alias
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MinimalAliasType {
    /// Alias flags
    pub alias_flags: AliasTypeFlag,

    /// Alias header (detail)
    pub header: MinimalAliasHeader,

    /// Aliased type
    pub body: MinimalAliasBody,
}

/// CompleteAliasHeader - Complete alias metadata
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompleteAliasHeader {
    /// Complete detail (name, annotations)
    pub detail: CompleteTypeDetail,
}

/// MinimalAliasHeader - Minimal alias metadata
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MinimalAliasHeader {
    /// Minimal detail
    pub detail: MinimalTypeDetail,
}

/// CompleteAliasBody - Complete alias body (related type)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompleteAliasBody {
    /// Common alias info
    pub common: CommonAliasBody,

    /// Complete detail (annotations)
    pub detail: CompleteTypeDetail,
}

/// MinimalAliasBody - Minimal alias body (related type)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MinimalAliasBody {
    /// Common alias info
    pub common: CommonAliasBody,
}

/// CommonAliasBody - Info shared between Complete and Minimal
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommonAliasBody {
    /// Related flags
    pub related_flags: TypeRelationFlag,

    /// Related type (the aliased type)
    pub related_type: TypeIdentifier,
}
