// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Error types for TypeObject builder and ROS 2 introspection.
//!
//!
//! Defines `BuilderError` and `RosidlError` for failures during
//! TypeObject construction from safe descriptors or rosidl metadata.

use crate::core::ser::traits::CdrError;
use std::str;

/// Builder failure modes.
#[derive(Debug)]
pub enum BuilderError {
    /// The rosidl metadata did not expose a hash (RIHS) for the type.
    MissingHash,
    /// A size/bound exceeded `u32` or was otherwise invalid.
    InvalidBound {
        /// Context for the failing bound (e.g. "array bound").
        context: &'static str,
    },
    /// Recursive type detected (currently unsupported).
    RecursiveType {
        /// Fully-qualified name that triggered the recursion.
        fqn: String,
    },
    /// The builder attempted to handle a field type that is not yet supported.
    UnsupportedType(u8),
    /// Failed to compute an XTypes equivalence hash.
    HashFailure(CdrError),
}

impl From<CdrError> for BuilderError {
    fn from(value: CdrError) -> Self {
        Self::HashFailure(value)
    }
}

/// Errors while converting `rosidl` introspection data into XTypes descriptors.
#[derive(Debug)]
pub enum RosidlError {
    /// Provided type support pointer was null.
    NullTypeSupport,
    /// Introspection metadata for the message was missing.
    NullMembers,
    /// Hash retrieval function was missing or returned null.
    MissingHash,
    /// Failed to decode a C string to UTF-8.
    InvalidUtf8(str::Utf8Error),
    /// Encountered an array/sequence bound that exceeds `u32::MAX`.
    BoundOverflow {
        /// Additional error context.
        context: &'static str,
        /// Offending value.
        value: usize,
    },
    /// Unsupported rosidl field type.
    UnsupportedType(u8),
    /// Underlying builder error.
    Builder(BuilderError),
}

impl From<BuilderError> for RosidlError {
    fn from(value: BuilderError) -> Self {
        Self::Builder(value)
    }
}

impl From<str::Utf8Error> for RosidlError {
    fn from(value: str::Utf8Error) -> Self {
        Self::InvalidUtf8(value)
    }
}

impl From<CdrError> for RosidlError {
    fn from(value: CdrError) -> Self {
        Self::Builder(BuilderError::from(value))
    }
}
