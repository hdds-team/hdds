// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Error types for DDS-RPC operations.

use crate::rpc::RemoteExceptionCode;
use std::fmt;

/// Result type for RPC operations
pub type RpcResult<T> = Result<T, RpcError>;

/// Errors that can occur during RPC operations
#[derive(Debug)]
pub enum RpcError {
    /// Failed to send request
    SendFailed(String),

    /// Request timed out waiting for reply
    Timeout,

    /// Remote service returned an exception
    RemoteException {
        code: RemoteExceptionCode,
        message: Option<String>,
    },

    /// Failed to serialize request
    SerializationError(String),

    /// Failed to deserialize reply
    DeserializationError(String),

    /// Service not found
    ServiceNotFound(String),

    /// Method not found
    MethodNotFound(String),

    /// Client was shut down
    Shutdown,

    /// DDS transport error
    DdsError(crate::dds::Error),

    /// Internal error
    Internal(String),
}

impl RpcError {
    /// Create a remote exception error
    pub fn remote(code: RemoteExceptionCode) -> Self {
        Self::RemoteException {
            code,
            message: None,
        }
    }

    /// Create a remote exception with message
    pub fn remote_with_message(code: RemoteExceptionCode, message: impl Into<String>) -> Self {
        Self::RemoteException {
            code,
            message: Some(message.into()),
        }
    }

    /// Create from RemoteExceptionCode
    pub fn from_code(code: RemoteExceptionCode) -> Self {
        match code {
            RemoteExceptionCode::Ok => Self::Internal("from_code called with Ok".to_string()),
            RemoteExceptionCode::Timeout => Self::Timeout,
            _ => Self::RemoteException {
                code,
                message: None,
            },
        }
    }
}

impl fmt::Display for RpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SendFailed(msg) => write!(f, "RPC send failed: {}", msg),
            Self::Timeout => write!(f, "RPC request timed out"),
            Self::RemoteException { code, message } => {
                write!(f, "Remote exception: {:?}", code)?;
                if let Some(msg) = message {
                    write!(f, " - {}", msg)?;
                }
                Ok(())
            }
            Self::SerializationError(msg) => write!(f, "RPC serialization error: {}", msg),
            Self::DeserializationError(msg) => write!(f, "RPC deserialization error: {}", msg),
            Self::ServiceNotFound(name) => write!(f, "Service not found: {}", name),
            Self::MethodNotFound(name) => write!(f, "Method not found: {}", name),
            Self::Shutdown => write!(f, "RPC client shut down"),
            Self::DdsError(e) => write!(f, "DDS error: {}", e),
            Self::Internal(msg) => write!(f, "Internal RPC error: {}", msg),
        }
    }
}

impl std::error::Error for RpcError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::DdsError(e) => Some(e),
            _ => None,
        }
    }
}

impl From<crate::dds::Error> for RpcError {
    fn from(e: crate::dds::Error) -> Self {
        Self::DdsError(e)
    }
}

impl From<RemoteExceptionCode> for RpcError {
    fn from(code: RemoteExceptionCode) -> Self {
        Self::from_code(code)
    }
}
