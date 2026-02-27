// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Collection type definitions per OMG DDS-XTypes v1.3.
//!
//!
//! Sequence, array, map, and string types with bounds metadata.

use super::TypeIdentifier;
use crate::xtypes::{CollectionElementFlag, CompleteTypeDetail};

// ============================================================================
// Sequence Types
// ============================================================================

/// CompleteSequenceType - Complete representation of a sequence
///
/// Corresponds to IDL: `sequence<T>` or `sequence<T, N>`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompleteSequenceType {
    /// Collection header (bound)
    pub header: CompleteCollectionHeader,

    /// Element type
    pub element: CompleteCollectionElement,
}

/// MinimalSequenceType - Minimal representation of a sequence
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MinimalSequenceType {
    /// Collection header (bound)
    pub header: MinimalCollectionHeader,

    /// Element type
    pub element: MinimalCollectionElement,
}

// ============================================================================
// Array Types
// ============================================================================

/// CompleteArrayType - Complete representation of an array
///
/// Corresponds to IDL: `T array[N]` or `T array[N][M]`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompleteArrayType {
    /// Collection header
    pub header: CompleteCollectionHeader,

    /// Element type
    pub element: CompleteCollectionElement,

    /// Bound sequence (dimensions)
    ///
    /// Example: `long matrix[3][4]` -> bounds = [3, 4]
    pub bound_seq: Vec<u32>,
}

/// MinimalArrayType - Minimal representation of an array
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MinimalArrayType {
    /// Collection header
    pub header: MinimalCollectionHeader,

    /// Element type
    pub element: MinimalCollectionElement,

    /// Bound sequence (dimensions)
    pub bound_seq: Vec<u32>,
}

// ============================================================================
// Map Types
// ============================================================================

/// CompleteMapType - Complete representation of a map
///
/// Corresponds to IDL: `map<K, V>` or `map<K, V, N>`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompleteMapType {
    /// Collection header (bound)
    pub header: CompleteCollectionHeader,

    /// Key type
    pub key: CompleteCollectionElement,

    /// Value type (element)
    pub element: CompleteCollectionElement,
}

/// MinimalMapType - Minimal representation of a map
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MinimalMapType {
    /// Collection header (bound)
    pub header: MinimalCollectionHeader,

    /// Key type
    pub key: MinimalCollectionElement,

    /// Value type (element)
    pub element: MinimalCollectionElement,
}

// ============================================================================
// Collection Headers and Elements
// ============================================================================

/// CompleteCollectionHeader - Complete collection metadata
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompleteCollectionHeader {
    /// Bound (0 = unbounded)
    pub bound: u32,

    /// Complete detail (annotations)
    pub detail: CompleteTypeDetail,
}

/// MinimalCollectionHeader - Minimal collection metadata
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MinimalCollectionHeader {
    /// Bound (0 = unbounded)
    pub bound: u32,
}

/// CompleteCollectionElement - Complete element type info
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompleteCollectionElement {
    /// Element flags (currently unused)
    pub flags: CollectionElementFlag,

    /// Element type
    pub type_id: TypeIdentifier,
}

/// MinimalCollectionElement - Minimal element type info
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MinimalCollectionElement {
    /// Element flags (currently unused)
    pub flags: CollectionElementFlag,

    /// Element type
    pub type_id: TypeIdentifier,
}
