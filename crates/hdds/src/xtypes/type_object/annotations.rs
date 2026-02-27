// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Annotation type definitions per OMG DDS-XTypes v1.3 and IDL 4.2.
//!
//!
//! Runtime representations for built-in and custom annotations.

use crate::xtypes::{
    CompleteAnnotationParameter, CompleteTypeDetail, MinimalAnnotationParameter, MinimalTypeDetail,
};

// ============================================================================
// Annotation Types (IDL 4.2)
// ============================================================================

/// CompleteAnnotationType - Complete representation of an annotation
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompleteAnnotationType {
    /// Annotation header (detail)
    pub header: CompleteAnnotationHeader,

    /// Annotation parameters
    pub member_seq: Vec<CompleteAnnotationParameter>,
}

/// MinimalAnnotationType - Minimal representation of an annotation
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MinimalAnnotationType {
    /// Annotation header (detail)
    pub header: MinimalAnnotationHeader,

    /// Annotation parameters
    pub member_seq: Vec<MinimalAnnotationParameter>,
}

/// CompleteAnnotationHeader - Complete annotation metadata
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompleteAnnotationHeader {
    /// Complete detail (name)
    pub detail: CompleteTypeDetail,
}

/// MinimalAnnotationHeader - Minimal annotation metadata
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MinimalAnnotationHeader {
    /// Minimal detail
    pub detail: MinimalTypeDetail,
}
