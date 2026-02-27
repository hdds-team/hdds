// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Error types for HDDS Micro

use core::fmt;

/// Result type for HDDS Micro operations
pub type Result<T> = core::result::Result<T, Error>;

/// Error type for HDDS Micro
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Buffer too small for operation
    BufferTooSmall,

    /// Invalid RTPS header
    InvalidHeader,

    /// Invalid submessage
    InvalidSubmessage,

    /// CDR encoding error
    EncodingError,

    /// CDR decoding error
    DecodingError,

    /// Transport error
    TransportError,

    /// Participant not initialized
    NotInitialized,

    /// Entity not found
    EntityNotFound,

    /// Invalid parameter
    InvalidParameter,

    /// Resource exhausted (history full, etc.)
    ResourceExhausted,

    /// Operation timed out
    Timeout,

    /// Invalid or corrupted data
    InvalidData,

    /// Invalid encoding (e.g., unknown enum discriminator)
    InvalidEncoding,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::BufferTooSmall => write!(f, "Buffer too small"),
            Error::InvalidHeader => write!(f, "Invalid RTPS header"),
            Error::InvalidSubmessage => write!(f, "Invalid submessage"),
            Error::EncodingError => write!(f, "CDR encoding error"),
            Error::DecodingError => write!(f, "CDR decoding error"),
            Error::TransportError => write!(f, "Transport error"),
            Error::NotInitialized => write!(f, "Participant not initialized"),
            Error::EntityNotFound => write!(f, "Entity not found"),
            Error::InvalidParameter => write!(f, "Invalid parameter"),
            Error::ResourceExhausted => write!(f, "Resource exhausted"),
            Error::Timeout => write!(f, "Operation timed out"),
            Error::InvalidData => write!(f, "Invalid or corrupted data"),
            Error::InvalidEncoding => write!(f, "Invalid encoding"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}
