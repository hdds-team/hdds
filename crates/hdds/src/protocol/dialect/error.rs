// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Dialect encoder error types

/// Errors that can occur during dialect-specific encoding
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncodeError {
    /// Buffer provided is too small for the encoded data
    BufferTooSmall,
    /// Invalid parameter value
    InvalidParameter(String),
    /// Encoding operation failed
    EncodingFailed(String),
    /// Dialect not supported in this build
    UnsupportedDialect(&'static str),
    /// Feature unavailable for this dialect
    NotImplemented(&'static str),
}

impl std::fmt::Display for EncodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BufferTooSmall => write!(f, "Buffer too small"),
            Self::InvalidParameter(msg) => write!(f, "Invalid parameter: {}", msg),
            Self::EncodingFailed(msg) => write!(f, "Encoding failed: {}", msg),
            Self::UnsupportedDialect(dialect) => write!(f, "Dialect unsupported: {}", dialect),
            Self::NotImplemented(feature) => write!(f, "Not implemented: {}", feature),
        }
    }
}

impl std::error::Error for EncodeError {}

/// Result type for dialect encoding operations
pub type EncodeResult<T> = Result<T, EncodeError>;
