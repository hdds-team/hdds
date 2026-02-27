// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! CDR2 serialization helpers for RTPS message encoding/decoding.

pub mod cursor;
pub mod pl_cdr2;
pub mod traits;

// Re-export from protocol module for backwards compatibility
pub use crate::protocol::cdr::{DecoderLE, EncoderLE};
pub use cursor::{Cursor, CursorMut};

// Re-export CDR2 traits for public API (hdds_gen integration)
pub use pl_cdr2::{
    align_offset as pl_align_offset, decode_pl_cdr2_struct, encode_pl_cdr2_struct,
    padding_for_alignment as pl_padding_for_alignment, PlMemberEncoder,
};
pub use traits::{Cdr2Decode, Cdr2Encode, CdrError};

// encode_message/decode_message stubs removed in v0.3.0 cleanup.
// v0.3.0 uses #[derive(hdds::DDS)] for automatic serialization.
// Manual encoding/decoding via EncoderLE/DecoderLE directly if needed.

use std::fmt;

/// Serialization error used within core::ser.
#[derive(Debug, Clone)]
pub enum SerError {
    EncoderFailed { reason: String },
    DecoderFailed { reason: String },
    WriteFailed { offset: usize, reason: String },
    ReadFailed { offset: usize, reason: String },
    InvalidData { reason: String },
}

impl fmt::Display for SerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SerError::EncoderFailed { reason } => write!(f, "encoder failed: {}", reason),
            SerError::DecoderFailed { reason } => write!(f, "decoder failed: {}", reason),
            SerError::WriteFailed { offset, reason } => {
                write!(f, "write failed at offset {}: {}", offset, reason)
            }
            SerError::ReadFailed { offset, reason } => {
                write!(f, "read failed at offset {}: {}", offset, reason)
            }
            SerError::InvalidData { reason } => write!(f, "invalid data: {}", reason),
        }
    }
}

impl std::error::Error for SerError {}

impl From<SerError> for crate::dds::Error {
    fn from(_: SerError) -> Self {
        crate::dds::Error::SerializationError
    }
}

pub type SerResult<T> = core::result::Result<T, SerError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ser_error_display_variants() {
        let err = SerError::WriteFailed {
            offset: 12,
            reason: "buffer too small".into(),
        };
        assert_eq!(
            crate::core::string_utils::format_string(format_args!("{}", err)),
            "write failed at offset 12: buffer too small"
        );

        let err = SerError::ReadFailed {
            offset: 4,
            reason: "unexpected end of buffer".into(),
        };
        assert_eq!(
            crate::core::string_utils::format_string(format_args!("{}", err)),
            "read failed at offset 4: unexpected end of buffer"
        );

        let err = SerError::EncoderFailed {
            reason: "cannot create encoder".into(),
        };
        assert_eq!(
            crate::core::string_utils::format_string(format_args!("{}", err)),
            "encoder failed: cannot create encoder"
        );

        let err = SerError::DecoderFailed {
            reason: "invalid header".into(),
        };
        assert_eq!(
            crate::core::string_utils::format_string(format_args!("{}", err)),
            "decoder failed: invalid header"
        );
    }

    #[test]
    fn test_ser_error_into_api_error() {
        let api_err: crate::dds::Error = SerError::InvalidData {
            reason: "bad payload".into(),
        }
        .into();
        match api_err {
            crate::dds::Error::SerializationError => {}
            other => std::panic::panic_any(crate::core::string_utils::format_string(format_args!(
                "unexpected api error {:?}",
                other
            ))),
        }
    }
}
