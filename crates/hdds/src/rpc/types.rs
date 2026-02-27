// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Core types for DDS-RPC protocol.
//!
//! These types follow the OMG DDS-RPC specification for request/reply correlation.

use crate::core::discovery::GUID;
use crate::core::ser::{Cdr2Decode, Cdr2Encode, CdrError};
use std::hash::{Hash, Hasher};

/// Unique identifier for a sample, used for request/reply correlation.
///
/// Combines the writer's GUID with a sequence number to create a globally
/// unique identifier for each request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SampleIdentity {
    /// GUID of the DataWriter that sent the sample
    pub writer_guid: GUID,
    /// Sequence number assigned by the writer
    pub sequence_number: i64,
}

impl SampleIdentity {
    /// Create a new SampleIdentity
    pub fn new(writer_guid: GUID, sequence_number: i64) -> Self {
        Self {
            writer_guid,
            sequence_number,
        }
    }

    /// Create a zero/null identity
    pub fn zero() -> Self {
        Self {
            writer_guid: GUID::zero(),
            sequence_number: 0,
        }
    }
}

impl Hash for SampleIdentity {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.writer_guid.prefix.hash(state);
        self.writer_guid.entity_id.hash(state);
        self.sequence_number.hash(state);
    }
}

impl Default for SampleIdentity {
    fn default() -> Self {
        Self::zero()
    }
}

/// Header prepended to request messages.
///
/// Contains the identity for correlation and optional instance tracking.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RequestHeader {
    /// Identity of this request (for reply correlation)
    pub request_id: SampleIdentity,
    /// Optional instance handle for keyed services
    pub instance_id: SampleIdentity,
}

impl RequestHeader {
    /// Create a new RequestHeader with the given request ID
    pub fn new(request_id: SampleIdentity) -> Self {
        Self {
            request_id,
            instance_id: SampleIdentity::zero(),
        }
    }

    /// Create a RequestHeader with both request and instance IDs
    pub fn with_instance(request_id: SampleIdentity, instance_id: SampleIdentity) -> Self {
        Self {
            request_id,
            instance_id,
        }
    }
}

/// Header prepended to reply messages.
///
/// Contains correlation info and status of the request processing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplyHeader {
    /// Identity of the original request (for correlation)
    pub related_request_id: SampleIdentity,
    /// Remote exception code (0 = success)
    pub remote_exception_code: RemoteExceptionCode,
}

impl ReplyHeader {
    /// Create a successful reply header
    pub fn success(related_request_id: SampleIdentity) -> Self {
        Self {
            related_request_id,
            remote_exception_code: RemoteExceptionCode::Ok,
        }
    }

    /// Create an error reply header
    pub fn error(related_request_id: SampleIdentity, code: RemoteExceptionCode) -> Self {
        Self {
            related_request_id,
            remote_exception_code: code,
        }
    }

    /// Check if this reply indicates success
    pub fn is_success(&self) -> bool {
        self.remote_exception_code == RemoteExceptionCode::Ok
    }
}

impl Default for ReplyHeader {
    fn default() -> Self {
        Self {
            related_request_id: SampleIdentity::zero(),
            remote_exception_code: RemoteExceptionCode::Ok,
        }
    }
}

/// Remote exception codes as defined by DDS-RPC spec.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(i32)]
pub enum RemoteExceptionCode {
    /// No error, request processed successfully
    #[default]
    Ok = 0,
    /// Service not found
    UnsupportedService = 1,
    /// Method not found in service
    UnsupportedMethod = 2,
    /// Invalid arguments
    InvalidArgument = 3,
    /// Service is unavailable
    ServiceUnavailable = 4,
    /// Request timed out
    Timeout = 5,
    /// Internal error in service
    InternalError = 6,
    /// Unknown/custom error
    Unknown = -1,
}

impl RemoteExceptionCode {
    /// Convert from i32
    pub fn from_i32(value: i32) -> Self {
        match value {
            0 => Self::Ok,
            1 => Self::UnsupportedService,
            2 => Self::UnsupportedMethod,
            3 => Self::InvalidArgument,
            4 => Self::ServiceUnavailable,
            5 => Self::Timeout,
            6 => Self::InternalError,
            _ => Self::Unknown,
        }
    }

    /// Convert to i32 (safe: #[repr(i32)] guarantees exact representation)
    pub fn as_i32(self) -> i32 {
        // Enum values: Ok=0, UnsupportedService=1, ..., InternalError=6, Unknown=-1
        self as i32 // SAFETY: #[repr(i32)] on enum declaration ensures all variants fit in i32
    }
}

// CDR encoding for SampleIdentity
impl Cdr2Encode for SampleIdentity {
    fn encode_cdr2_le(&self, buf: &mut [u8]) -> Result<usize, CdrError> {
        if buf.len() < Self::CDR_SIZE {
            return Err(CdrError::BufferTooSmall);
        }

        let mut offset = 0;

        // GUID prefix (12 bytes)
        buf[offset..offset + 12].copy_from_slice(&self.writer_guid.prefix);
        offset += 12;

        // Entity ID (4 bytes)
        buf[offset..offset + 4].copy_from_slice(&self.writer_guid.entity_id);
        offset += 4;

        // Sequence number (8 bytes, i64 LE)
        buf[offset..offset + 8].copy_from_slice(&self.sequence_number.to_le_bytes());
        offset += 8;

        Ok(offset)
    }

    fn max_cdr2_size(&self) -> usize {
        Self::CDR_SIZE
    }
}

impl SampleIdentity {
    /// Size in CDR encoding: 12 (prefix) + 4 (entity) + 8 (seq) = 24 bytes
    const CDR_SIZE: usize = 24;
}

impl Cdr2Decode for SampleIdentity {
    fn decode_cdr2_le(src: &[u8]) -> Result<(Self, usize), CdrError> {
        if src.len() < Self::CDR_SIZE {
            return Err(CdrError::UnexpectedEof);
        }

        let mut prefix = [0u8; 12];
        prefix.copy_from_slice(&src[0..12]);

        let mut entity_id = [0u8; 4];
        entity_id.copy_from_slice(&src[12..16]);

        let sequence_number = i64::from_le_bytes([
            src[16], src[17], src[18], src[19], src[20], src[21], src[22], src[23],
        ]);

        Ok((
            Self {
                writer_guid: GUID { prefix, entity_id },
                sequence_number,
            },
            Self::CDR_SIZE,
        ))
    }
}

// CDR encoding for RequestHeader
impl Cdr2Encode for RequestHeader {
    fn encode_cdr2_le(&self, buf: &mut [u8]) -> Result<usize, CdrError> {
        if buf.len() < Self::CDR_SIZE {
            return Err(CdrError::BufferTooSmall);
        }

        let mut offset = self.request_id.encode_cdr2_le(buf)?;
        offset += self.instance_id.encode_cdr2_le(&mut buf[offset..])?;

        Ok(offset)
    }

    fn max_cdr2_size(&self) -> usize {
        Self::CDR_SIZE
    }
}

impl RequestHeader {
    /// Size: 2 * SampleIdentity = 48 bytes
    const CDR_SIZE: usize = 48;
}

impl Cdr2Decode for RequestHeader {
    fn decode_cdr2_le(src: &[u8]) -> Result<(Self, usize), CdrError> {
        if src.len() < Self::CDR_SIZE {
            return Err(CdrError::UnexpectedEof);
        }

        let (request_id, offset1) = SampleIdentity::decode_cdr2_le(src)?;
        let (instance_id, offset2) = SampleIdentity::decode_cdr2_le(&src[offset1..])?;

        Ok((
            Self {
                request_id,
                instance_id,
            },
            offset1 + offset2,
        ))
    }
}

// CDR encoding for ReplyHeader
impl Cdr2Encode for ReplyHeader {
    fn encode_cdr2_le(&self, buf: &mut [u8]) -> Result<usize, CdrError> {
        if buf.len() < Self::CDR_SIZE {
            return Err(CdrError::BufferTooSmall);
        }

        let mut offset = self.related_request_id.encode_cdr2_le(buf)?;

        buf[offset..offset + 4].copy_from_slice(&self.remote_exception_code.as_i32().to_le_bytes());
        offset += 4;

        Ok(offset)
    }

    fn max_cdr2_size(&self) -> usize {
        Self::CDR_SIZE
    }
}

impl ReplyHeader {
    /// Size: SampleIdentity (24) + i32 (4) = 28 bytes
    const CDR_SIZE: usize = 28;
}

impl Cdr2Decode for ReplyHeader {
    fn decode_cdr2_le(src: &[u8]) -> Result<(Self, usize), CdrError> {
        if src.len() < Self::CDR_SIZE {
            return Err(CdrError::UnexpectedEof);
        }

        let (related_request_id, offset1) = SampleIdentity::decode_cdr2_le(src)?;

        let code_bytes = [
            src[offset1],
            src[offset1 + 1],
            src[offset1 + 2],
            src[offset1 + 3],
        ];
        let code = i32::from_le_bytes(code_bytes);
        let remote_exception_code = RemoteExceptionCode::from_i32(code);

        Ok((
            Self {
                related_request_id,
                remote_exception_code,
            },
            Self::CDR_SIZE,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sample_identity_roundtrip() {
        let identity = SampleIdentity {
            writer_guid: GUID {
                prefix: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
                entity_id: [0x00, 0x00, 0x01, 0x02],
            },
            sequence_number: 12345678,
        };

        let mut buf = [0u8; 64];
        let written = identity.encode_cdr2_le(&mut buf).unwrap();
        assert_eq!(written, 24);

        let (decoded, read) = SampleIdentity::decode_cdr2_le(&buf).unwrap();
        assert_eq!(read, 24);
        assert_eq!(decoded, identity);
    }

    #[test]
    fn request_header_roundtrip() {
        let header = RequestHeader {
            request_id: SampleIdentity::new(GUID::zero(), 42),
            instance_id: SampleIdentity::zero(),
        };

        let mut buf = [0u8; 64];
        let written = header.encode_cdr2_le(&mut buf).unwrap();
        assert_eq!(written, 48);

        let (decoded, read) = RequestHeader::decode_cdr2_le(&buf).unwrap();
        assert_eq!(read, 48);
        assert_eq!(decoded, header);
    }

    #[test]
    fn reply_header_roundtrip() {
        let header = ReplyHeader {
            related_request_id: SampleIdentity::new(GUID::zero(), 42),
            remote_exception_code: RemoteExceptionCode::InvalidArgument,
        };

        let mut buf = [0u8; 64];
        let written = header.encode_cdr2_le(&mut buf).unwrap();
        assert_eq!(written, 28);

        let (decoded, read) = ReplyHeader::decode_cdr2_le(&buf).unwrap();
        assert_eq!(read, 28);
        assert_eq!(decoded, header);
    }

    #[test]
    fn exception_code_conversion() {
        assert_eq!(RemoteExceptionCode::from_i32(0), RemoteExceptionCode::Ok);
        assert_eq!(
            RemoteExceptionCode::from_i32(3),
            RemoteExceptionCode::InvalidArgument
        );
        assert_eq!(
            RemoteExceptionCode::from_i32(999),
            RemoteExceptionCode::Unknown
        );
    }
}
