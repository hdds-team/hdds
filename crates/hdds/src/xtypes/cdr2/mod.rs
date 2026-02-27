// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! CDR2 serialization for XTypes v1.3
//!
//!
//! This module provides CDR2 (Common Data Representation v2) encoding/decoding
//! for the DDS XTypes v1.3 type system.
//!
//! # Module Organization
//!
//! The original 4194-line `cdr2_serde.rs` has been split into logical modules:
//!
//! - [`traits`] - Core `Cdr2Encode`/`Cdr2Decode` traits
//! - [`primitives`] - Low-level encode/decode helpers (NOT auto-exported)
//! - [`type_identifier`] - Type identification (TypeIdentifier, EquivalenceHash)
//! - [`flags`] - Type and member flags
//! - [`details`] - Type and member metadata (TypeDetail, MemberDetail)
//! - [`members`] - Common member definitions (struct/union/enum/bitset)
//! - [`structs`] - Struct type definitions
//! - [`unions`] - Union type definitions
//! - [`enums`] - Enumerated type definitions
//! - [`bitsets`] - Bitset/bitmask/bitfield definitions
//! - [`collections`] - Sequence/array/map/string definitions
//! - [`aliases`] - Alias (typedef) definitions
//! - [`annotations`] - Annotation type definitions
//! - [`type_objects`] - Top-level TypeObject containers
//!
//! # Usage
//!
//! ```ignore
//! use crate::xtypes::cdr2::{Cdr2Encode, Cdr2Decode, CompleteTypeObject};
//!
//! // Encode a type object
//! let type_obj = CompleteTypeObject::Struct(...);
//! let mut buf = vec![0u8; 1024];
//! let size = type_obj.encode_cdr2(&mut buf)?;
//!
//! // Decode a type object
//! let decoded = CompleteTypeObject::decode_cdr2(&buf[..size])?;
//! ```
//!
//! # References
//!
//! - **XTypes v1.3 Specification:** OMG formal/2020-06-01
//! - **CDR2 Encoding:** Section 7.3 (OMG XTypes spec)
//! - **Type System:** Section 7.2 (OMG XTypes spec)
//!
//! # Design Decisions
//!
//! ## Selective Exports
//!
//! Public API types are re-exported for convenience, but internal helpers
//! (like `primitives`) require explicit imports:
//!
//! ```ignore
//! // [OK] Public API - auto-exported
//! use crate::xtypes::cdr2::CompleteStructType;
//!
//! // [OK] Internal helpers - explicit import
//! use crate::xtypes::cdr2::primitives::encode_u32_le;
//! ```
//!
//! **Rationale:** Forces explicit dependencies for ANSSI/IGI-1300 auditability.
//!
//! ## Test Distribution
//!
//! Tests are inline in each module for proximity to implementation.
//! Integration tests (cross-module behavior) live in [`type_objects`].
//!
//! # Migration Status
//!
//! **Phase 1:** [OK] Structure created (2025-01-27)
//! **Phase 2-7:** [*] In progress

// Foundation
mod helpers;
mod primitives;
mod traits; // Shared helpers for encoding/decoding

// Core types
mod details;
mod flags;
mod members;
mod type_identifier;

// Composite types
mod aliases;
mod annotations;
mod bitsets;
mod collections;
mod enums;
mod structs;
mod unions;

// Top-level
mod type_objects;

// ==========================================
//   PUBLIC API - Selective Re-exports
// ==========================================

// Traits ONLY (foundation)
// The CDR2 module provides serialization traits for TypeObject types.
// TypeObject types themselves are defined and exported from `crate::xtypes::type_object`.
#[allow(unused_imports)] // Re-exported for public API
pub use traits::{Cdr2Decode, Cdr2Encode};

// NOTE: `primitives`, `flags`, `details`, etc. are NOT re-exported
// They are internal implementation modules that provide `Cdr2Encode`/`Cdr2Decode`
// trait implementations for types defined in `crate::xtypes::type_object`.
//
// TypeObject types are accessed via:
//   use crate::xtypes::{CompleteTypeObject, MinimalTypeObject, ...};
//
// For low-level helpers, use explicit imports:
//   use crate::xtypes::cdr2::primitives::encode_u32_le;
