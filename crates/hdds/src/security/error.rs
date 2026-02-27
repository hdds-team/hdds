// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Security error types

use std::fmt;

/// Security-related errors
#[derive(Debug, Clone)]
pub enum SecurityError {
    /// Authentication failed (invalid certificate, expired, etc.)
    AuthenticationFailed(String),

    /// Access denied by permissions policy
    AccessDenied(String),

    /// Cryptographic operation failed (encryption, decryption, MAC verification)
    CryptographicError(String),

    /// Logging operation failed
    LoggingError(String),

    /// Configuration error (missing cert, invalid XML, etc.)
    ConfigurationError(String),

    /// Invalid security token or wire format
    InvalidToken(String),
}

impl fmt::Display for SecurityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AuthenticationFailed(msg) => write!(f, "Authentication failed: {}", msg),
            Self::AccessDenied(msg) => write!(f, "Access denied: {}", msg),
            Self::CryptographicError(msg) => write!(f, "Cryptographic error: {}", msg),
            Self::LoggingError(msg) => write!(f, "Logging error: {}", msg),
            Self::ConfigurationError(msg) => write!(f, "Configuration error: {}", msg),
            Self::InvalidToken(msg) => write!(f, "Invalid token: {}", msg),
        }
    }
}

impl std::error::Error for SecurityError {}
