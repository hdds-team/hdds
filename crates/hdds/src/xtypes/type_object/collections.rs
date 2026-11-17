// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Collection type definitions per OMG DDS-XTypes v1.3.
//!
//!
//! Sequence, array, map, and string types with bounds metadata.

use super::TypeIdentifier;
use crate::xtypes::{
    AppliedAnnotation, AppliedBuiltinMemberAnnotations, CollectionElementFlag, CollectionTypeFlag,
    CompleteTypeDetail,
};

// ============================================================================
// Sequence Types
// ============================================================================

/// CompleteSequenceType - Complete representation of a sequence
///
/// Corresponds to IDL: `sequence<T>` or `sequence<T, N>`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompleteSequenceType {
    /// Collection flags (unused, Annex B)
    pub collection_flag: CollectionTypeFlag,

    /// Collection header (bound)
    pub header: CompleteCollectionHeader,

    /// Element type
    pub element: CompleteCollectionElement,
}

/// MinimalSequenceType - Minimal representation of a sequence
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MinimalSequenceType {
    /// Collection flags (unused, Annex B)
    pub collection_flag: CollectionTypeFlag,

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
    /// Collection flags (unused, Annex B)
    pub collection_flag: CollectionTypeFlag,

    /// Array header (dimensions, detail)
    pub header: CompleteArrayHeader,

    /// Element type
    pub element: CompleteCollectionElement,
}

/// CompleteArrayHeader - Complete array metadata
///
/// DDS-XTypes 1.3 Annex B: `@appendable struct CompleteArrayHeader {
/// CommonArrayHeader common; CompleteTypeDetail detail; }`, the common part
/// being the dimensions alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompleteArrayHeader {
    /// Bound sequence (dimensions)
    ///
    /// Example: `long matrix[3][4]` -> bounds = [3, 4]
    pub bound_seq: Vec<u32>,

    /// Complete detail (name, annotations)
    pub detail: CompleteTypeDetail,
}

/// MinimalArrayType - Minimal representation of an array
///
/// NOT the Annex B layout (`collection_flag`, then a MinimalArrayHeader
/// holding the dimensions, then the element): the ROS 2 type builder hashes
/// this object into the identifiers it announces, so its layout moves with
/// that builder's own fix (plain collection identifiers), not before.
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
    /// Collection flags (unused, Annex B)
    pub collection_flag: CollectionTypeFlag,

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
    /// Collection flags (unused, Annex B)
    pub collection_flag: CollectionTypeFlag,

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

    /// Complete detail (name, annotations); Annex B: @optional
    pub detail: Option<CompleteTypeDetail>,
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

    /// The element's annotations
    pub detail: CompleteElementDetail,
}

/// CompleteElementDetail - annotations applied to a collection element
///
/// DDS-XTypes 1.3 Annex B: `@final struct CompleteElementDetail {
/// @optional AppliedBuiltinMemberAnnotations ann_builtin; @optional
/// AppliedAnnotationSeq ann_custom; }`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CompleteElementDetail {
    /// Builtin annotations (boxed: rare, and large inline in every
    /// collection element of a `CompleteTypeObject`)
    pub ann_builtin: Option<Box<AppliedBuiltinMemberAnnotations>>,

    /// Custom annotations
    pub ann_custom: Option<Vec<AppliedAnnotation>>,
}

/// MinimalCollectionElement - Minimal element type info
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MinimalCollectionElement {
    /// Element flags (currently unused)
    pub flags: CollectionElementFlag,

    /// Element type
    pub type_id: TypeIdentifier,
}
