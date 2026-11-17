// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Core types for the DDS-RPC Basic Service Mapping.
//!
//! The wire layout of every type in this file is the one the OMG DDS-RPC 1.0
//! specification (formal/17-04-01) defines in clause 7.5.1.1.1 "Common
//! Types", serialized as plain CDR in declaration order:
//!
//! ```text
//! struct SequenceNumber_t   { long high; unsigned long low; };        // RTPS 9.3.2
//! struct SampleIdentity     { GUID_t writer_guid; SequenceNumber_t sequence_number; };
//! typedef string<255> InstanceName;
//! struct RequestHeader      { SampleIdentity requestId; InstanceName instanceName; };
//! struct ReplyHeader        { SampleIdentity relatedRequestId; RemoteExceptionCode_t remoteEx; };
//! ```
//!
//! The unit tests pin these layouts against byte vectors produced by an
//! independent toolchain (fastddsgen 4.0.4 + Fast-CDR 2.3.3) from the
//! specification's own IDL, so a change that keeps encoder and decoder
//! self-consistent but drifts from the specification fails here.

use crate::core::discovery::GUID;
use crate::core::ser::{Cdr2Decode, Cdr2Encode, CdrError};
use std::hash::{Hash, Hasher};

/// Round `offset` up to the next multiple of 4, the alignment of the `long`
/// discriminator a Basic-mapping `_Call`/`_Return` union starts with.
fn pad_to_4(offset: usize) -> usize {
    (4 - (offset % 4)) % 4
}

/// Unique identifier for a sample, used for request/reply correlation.
///
/// Combines the writer's GUID with a sequence number to create a globally
/// unique identifier for each request.
///
/// # Wire layout (24 bytes)
///
/// `writer_guid` is the 16-byte RTPS GUID (12-byte prefix + 4-byte entity id).
/// `sequence_number` is an RTPS `SequenceNumber_t`, which is NOT a 64-bit
/// integer on the wire: it is `long high` followed by `unsigned long low`,
/// value = `(high << 32) + low` (RTPS 9.3.2, DDS-RPC 7.5.1.1.1). For sequence
/// number 42 the eight bytes are `00 00 00 00 2a 00 00 00`, not the
/// little-endian `i64` `2a 00 00 00 00 00 00 00`. RTPS defines
/// `SEQUENCENUMBER_UNKNOWN` as `{high: -1, low: 0}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SampleIdentity {
    /// GUID of the DataWriter that sent the sample
    pub writer_guid: GUID,
    /// Sequence number assigned by the writer, `(high << 32) + low`
    pub sequence_number: i64,
}

impl SampleIdentity {
    /// Size in CDR encoding: 12 (prefix) + 4 (entity) + 4 (high) + 4 (low) = 24 bytes
    pub const CDR_SIZE: usize = 24;

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

/// Header prepended to request messages (`dds::rpc::RequestHeader`).
///
/// # Wire layout
///
/// `request_id` (24 bytes) followed by `instance_name` as a CDR
/// `string<255>`: 4-byte length including the terminating NUL, the bytes,
/// the NUL. The encoder then pads to a 4-byte boundary and the decoder skips
/// that padding, because in the Basic Service Mapping the header is always
/// followed by the `_Call` union whose `long` discriminator is 4-aligned
/// (DDS-RPC 7.5.1.1.6). An empty instance name therefore occupies 32 bytes
/// on the wire (24 + 4 + 1 + 3 padding); the payload starts at offset 32.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RequestHeader {
    /// Identity of this request (for reply correlation)
    pub request_id: SampleIdentity,
    /// `InstanceName instanceName`: names the service instance addressed by
    /// the request. Empty unless the caller sets one. Bounded to
    /// [`RequestHeader::INSTANCE_NAME_MAX_LEN`] bytes on the wire.
    pub instance_name: String,
}

impl RequestHeader {
    /// `typedef string<255> InstanceName` (DDS-RPC 7.5.1.1.1): the bound is
    /// on the string bytes, excluding the NUL terminator.
    pub const INSTANCE_NAME_MAX_LEN: usize = 255;

    /// Create a new RequestHeader with the given request ID and no instance name
    pub fn new(request_id: SampleIdentity) -> Self {
        Self {
            request_id,
            instance_name: String::new(),
        }
    }

    /// Create a RequestHeader that names a service instance
    pub fn with_instance_name(
        request_id: SampleIdentity,
        instance_name: impl Into<String>,
    ) -> Self {
        Self {
            request_id,
            instance_name: instance_name.into(),
        }
    }
}

/// Header prepended to reply messages (`dds::rpc::ReplyHeader`).
///
/// # Wire layout (28 bytes)
///
/// `related_request_id` (24 bytes) followed by `remote_exception_code` as a
/// 4-byte CDR enum.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplyHeader {
    /// Identity of the original request (for correlation)
    pub related_request_id: SampleIdentity,
    /// Remote exception code (`RemoteExceptionCode::Ok` = success)
    pub remote_exception_code: RemoteExceptionCode,
}

impl ReplyHeader {
    /// Size: SampleIdentity (24) + RemoteExceptionCode_t (4) = 28 bytes
    pub const CDR_SIZE: usize = 28;

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

/// `dds::rpc::RemoteExceptionCode_t` (DDS-RPC 7.5.1.1.1 and 7.5.2).
///
/// The discriminant IS the wire value; these are the only six values the
/// specification defines, so a reply carrying anything else is malformed and
/// [`ReplyHeader`] refuses to decode it. The specification has no code for a
/// service-side timeout: a handler that exceeds the server's request timeout
/// is reported as [`RemoteExceptionCode::UnknownException`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(i32)]
pub enum RemoteExceptionCode {
    /// `REMOTE_EX_OK`: the request was executed successfully
    #[default]
    Ok = 0,
    /// `REMOTE_EX_UNSUPPORTED`: the operation is valid but not implemented
    Unsupported = 1,
    /// `REMOTE_EX_INVALID_ARGUMENT`: a parameter has an illegal value
    InvalidArgument = 2,
    /// `REMOTE_EX_OUT_OF_RESOURCES`: the service ran out of resources while
    /// processing the request
    OutOfResources = 3,
    /// `REMOTE_EX_UNKNOWN_OPERATION`: the operation called is unknown
    UnknownOperation = 4,
    /// `REMOTE_EX_UNKNOWN_EXCEPTION`: a generic, unspecified exception was
    /// raised by the service implementation
    UnknownException = 5,
}

impl RemoteExceptionCode {
    /// Interpret a wire value; `None` for anything outside the specification's enum
    pub fn from_wire(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::Ok),
            1 => Some(Self::Unsupported),
            2 => Some(Self::InvalidArgument),
            3 => Some(Self::OutOfResources),
            4 => Some(Self::UnknownOperation),
            5 => Some(Self::UnknownException),
            _ => None,
        }
    }

    /// The wire value (`#[repr(i32)]` makes the cast exact)
    pub fn as_i32(self) -> i32 {
        self as i32 // @audit-ok: repr(i32) enum, explicit discriminants 0..=5, the cast reads the discriminant
    }
}

// CDR encoding for SampleIdentity
impl Cdr2Encode for SampleIdentity {
    fn max_cdr2_size(&self) -> usize {
        Self::CDR_SIZE
    }

    fn encode_cdr2_le_at(&self, buf: &mut [u8], offset: &mut usize) -> Result<(), CdrError> {
        if *offset + Self::CDR_SIZE > buf.len() {
            return Err(CdrError::BufferTooSmall);
        }
        buf[*offset..*offset + 12].copy_from_slice(&self.writer_guid.prefix);
        *offset += 12;
        buf[*offset..*offset + 4].copy_from_slice(&self.writer_guid.entity_id);
        *offset += 4;
        // SequenceNumber_t: high word first, then low word (RTPS 9.3.2).
        let high = (self.sequence_number >> 32) as i32;
        let low = self.sequence_number as u32; // @audit-ok: the truncation IS the split, this is the low word
        buf[*offset..*offset + 4].copy_from_slice(&high.to_le_bytes());
        *offset += 4;
        buf[*offset..*offset + 4].copy_from_slice(&low.to_le_bytes());
        *offset += 4;
        Ok(())
    }
}

impl Cdr2Decode for SampleIdentity {
    fn decode_cdr2_le_at(src: &[u8], offset: &mut usize) -> Result<Self, CdrError> {
        if *offset + Self::CDR_SIZE > src.len() {
            return Err(CdrError::UnexpectedEof);
        }

        let base = *offset;
        let mut prefix = [0u8; 12];
        prefix.copy_from_slice(&src[base..base + 12]);

        let mut entity_id = [0u8; 4];
        entity_id.copy_from_slice(&src[base + 12..base + 16]);

        let mut word = [0u8; 4];
        word.copy_from_slice(&src[base + 16..base + 20]);
        let high = i32::from_le_bytes(word);
        word.copy_from_slice(&src[base + 20..base + 24]);
        let low = u32::from_le_bytes(word);
        let sequence_number = (i64::from(high) << 32) | i64::from(low);

        *offset += Self::CDR_SIZE;

        Ok(Self {
            writer_guid: GUID { prefix, entity_id },
            sequence_number,
        })
    }
}

// CDR encoding for RequestHeader
impl Cdr2Encode for RequestHeader {
    fn max_cdr2_size(&self) -> usize {
        let unpadded = SampleIdentity::CDR_SIZE + self.instance_name.max_cdr2_size();
        unpadded + pad_to_4(unpadded)
    }

    fn encode_cdr2_le_at(&self, buf: &mut [u8], offset: &mut usize) -> Result<(), CdrError> {
        if self.instance_name.len() > Self::INSTANCE_NAME_MAX_LEN {
            return Err(CdrError::Other(format!(
                "RequestHeader.instanceName is {} bytes, the bound is string<{}>",
                self.instance_name.len(),
                Self::INSTANCE_NAME_MAX_LEN
            )));
        }
        self.request_id.encode_cdr2_le_at(buf, offset)?;
        self.instance_name.encode_cdr2_le_at(buf, offset)?;
        let pad = pad_to_4(*offset);
        if *offset + pad > buf.len() {
            return Err(CdrError::BufferTooSmall);
        }
        buf[*offset..*offset + pad].fill(0);
        *offset += pad;
        Ok(())
    }
}

impl Cdr2Decode for RequestHeader {
    fn decode_cdr2_le_at(src: &[u8], offset: &mut usize) -> Result<Self, CdrError> {
        let request_id = SampleIdentity::decode_cdr2_le_at(src, offset)?;

        // Check the string against its IDL bound before the generic string
        // decoder allocates for it: the CDR length counts the NUL, so a legal
        // InstanceName has a length in 1..=256 and ends with a zero byte.
        let len_at = *offset;
        if len_at + 4 > src.len() {
            return Err(CdrError::UnexpectedEof);
        }
        let mut word = [0u8; 4];
        word.copy_from_slice(&src[len_at..len_at + 4]);
        let cdr_len = u32::from_le_bytes(word) as usize;
        if cdr_len == 0 || cdr_len > Self::INSTANCE_NAME_MAX_LEN + 1 {
            return Err(CdrError::Other(format!(
                "RequestHeader.instanceName CDR length {cdr_len} is outside 1..=256"
            )));
        }
        if len_at + 4 + cdr_len > src.len() {
            return Err(CdrError::UnexpectedEof);
        }
        if src[len_at + 4 + cdr_len - 1] != 0 {
            return Err(CdrError::InvalidEncoding);
        }
        let instance_name = String::decode_cdr2_le_at(src, offset)?;

        let pad = pad_to_4(*offset);
        if *offset + pad > src.len() {
            return Err(CdrError::UnexpectedEof);
        }
        *offset += pad;

        Ok(Self {
            request_id,
            instance_name,
        })
    }
}

// CDR encoding for ReplyHeader
impl Cdr2Encode for ReplyHeader {
    fn max_cdr2_size(&self) -> usize {
        Self::CDR_SIZE
    }

    fn encode_cdr2_le_at(&self, buf: &mut [u8], offset: &mut usize) -> Result<(), CdrError> {
        if *offset + Self::CDR_SIZE > buf.len() {
            return Err(CdrError::BufferTooSmall);
        }
        self.related_request_id.encode_cdr2_le_at(buf, offset)?;
        buf[*offset..*offset + 4]
            .copy_from_slice(&self.remote_exception_code.as_i32().to_le_bytes());
        *offset += 4;
        Ok(())
    }
}

impl Cdr2Decode for ReplyHeader {
    fn decode_cdr2_le_at(src: &[u8], offset: &mut usize) -> Result<Self, CdrError> {
        if *offset + Self::CDR_SIZE > src.len() {
            return Err(CdrError::UnexpectedEof);
        }

        let related_request_id = SampleIdentity::decode_cdr2_le_at(src, offset)?;

        let mut word = [0u8; 4];
        word.copy_from_slice(&src[*offset..*offset + 4]);
        let code = i32::from_le_bytes(word);
        let remote_exception_code = RemoteExceptionCode::from_wire(code).ok_or_else(|| {
            CdrError::Other(format!(
                "ReplyHeader.remoteEx {code} is not a RemoteExceptionCode_t value (0..=5)"
            ))
        })?;
        *offset += 4;

        Ok(Self {
            related_request_id,
            remote_exception_code,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Byte vectors produced by fastddsgen 4.0.4 + Fast-CDR
    // 2.3.3 (XCDRv1, little-endian) from the IDL of DDS-RPC 1.0 clause
    // 7.5.1.1.1, with the GUID below and sequence number 42. Nothing in HDDS
    // generated these bytes; they are an independent toolchain's encoding.
    const VENDOR_GUID: GUID = GUID {
        prefix: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
        entity_id: [0x00, 0x00, 0x01, 0x02],
    };
    const VENDOR_SAMPLE_IDENTITY_42: [u8; 24] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, // guidPrefix
        0x00, 0x00, 0x01, 0x02, // entityId
        0x00, 0x00, 0x00, 0x00, // sequence_number.high
        0x2a, 0x00, 0x00, 0x00, // sequence_number.low = 42
    ];
    // sequence number (1 << 32) + 42
    const VENDOR_SAMPLE_IDENTITY_HIGH_1_LOW_42: [u8; 24] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, //
        0x00, 0x00, 0x01, 0x02, //
        0x01, 0x00, 0x00, 0x00, // high = 1
        0x2a, 0x00, 0x00, 0x00, // low = 42
    ];
    // RTPS SEQUENCENUMBER_UNKNOWN = {high: -1, low: 0}
    const VENDOR_SAMPLE_IDENTITY_UNKNOWN: [u8; 24] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, //
        0x00, 0x00, 0x01, 0x02, //
        0xff, 0xff, 0xff, 0xff, // high = -1
        0x00, 0x00, 0x00, 0x00, // low = 0
    ];
    // RequestHeader { requestId, instanceName: "" }: the vendor emits 29
    // bytes when the header stands alone; the three padding bytes that
    // precede a following `_Call` union are appended in the tests.
    const VENDOR_REQUEST_HEADER_EMPTY_NAME: [u8; 29] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, //
        0x00, 0x00, 0x01, 0x02, //
        0x00, 0x00, 0x00, 0x00, 0x2a, 0x00, 0x00, 0x00, //
        0x01, 0x00, 0x00, 0x00, // instanceName length, NUL included
        0x00, // instanceName = ""
    ];
    // RequestHeader { requestId, instanceName: "svc" }
    const VENDOR_REQUEST_HEADER_SVC: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, //
        0x00, 0x00, 0x01, 0x02, //
        0x00, 0x00, 0x00, 0x00, 0x2a, 0x00, 0x00, 0x00, //
        0x04, 0x00, 0x00, 0x00, // instanceName length, NUL included
        0x73, 0x76, 0x63, 0x00, // "svc\0"
    ];
    // ReplyHeader { relatedRequestId, remoteEx: REMOTE_EX_INVALID_ARGUMENT }
    const VENDOR_REPLY_HEADER_INVALID_ARGUMENT: [u8; 28] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, //
        0x00, 0x00, 0x01, 0x02, //
        0x00, 0x00, 0x00, 0x00, 0x2a, 0x00, 0x00, 0x00, //
        0x02, 0x00, 0x00, 0x00, // REMOTE_EX_INVALID_ARGUMENT = 2
    ];
    // A complete Basic-mapping request sample for
    //   union Echo_Call switch (long) { case 1: Echo_ping_In ping; };
    //   struct Echo_Request { dds::rpc::RequestHeader header; Echo_Call data; };
    // with instanceName "" and ping.value = 7. The vendor left the three
    // padding bytes after the NUL untouched (0xee is the buffer poison), which
    // is why the decoder must skip them without reading them.
    const VENDOR_ECHO_REQUEST: [u8; 40] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, //
        0x00, 0x00, 0x01, 0x02, //
        0x00, 0x00, 0x00, 0x00, 0x2a, 0x00, 0x00, 0x00, //
        0x01, 0x00, 0x00, 0x00, // instanceName length
        0x00, 0xee, 0xee, 0xee, // "" + 3 bytes of padding
        0x01, 0x00, 0x00, 0x00, // Echo_Call discriminator = 1 (ping)
        0x07, 0x00, 0x00, 0x00, // Echo_ping_In.value = 7
    ];

    fn encode<T: Cdr2Encode>(value: &T) -> Vec<u8> {
        let mut buf = vec![0u8; value.max_cdr2_size()];
        let written = value.encode_cdr2_le(&mut buf).unwrap();
        buf.truncate(written);
        buf
    }

    #[test]
    fn sample_identity_matches_the_vendor_bytes() {
        let cases: [(i64, &[u8; 24]); 3] = [
            (42, &VENDOR_SAMPLE_IDENTITY_42),
            ((1 << 32) + 42, &VENDOR_SAMPLE_IDENTITY_HIGH_1_LOW_42),
            (-1 << 32, &VENDOR_SAMPLE_IDENTITY_UNKNOWN),
        ];
        for (sequence_number, vector) in cases {
            let identity = SampleIdentity::new(VENDOR_GUID, sequence_number);
            assert_eq!(
                encode(&identity),
                vector.as_slice(),
                "seq {sequence_number}"
            );
            let (decoded, read) = SampleIdentity::decode_cdr2_le(vector.as_slice()).unwrap();
            assert_eq!(read, 24);
            assert_eq!(decoded, identity);
        }
    }

    #[test]
    fn sample_identity_high_word_comes_first_on_the_wire() {
        // A little-endian i64 would put 0x2a in byte 16; RTPS puts it in byte 20.
        let bytes = encode(&SampleIdentity::new(VENDOR_GUID, 42));
        assert_eq!(&bytes[16..20], &[0, 0, 0, 0]);
        assert_eq!(&bytes[20..24], &[0x2a, 0, 0, 0]);
    }

    #[test]
    fn request_header_matches_the_vendor_bytes() {
        let empty = RequestHeader::new(SampleIdentity::new(VENDOR_GUID, 42));
        let mut expected = VENDOR_REQUEST_HEADER_EMPTY_NAME.to_vec();
        expected.extend_from_slice(&[0, 0, 0]); // padding before the _Call union
        assert_eq!(encode(&empty), expected);
        assert_eq!(empty.max_cdr2_size(), 32);

        let named = RequestHeader::with_instance_name(SampleIdentity::new(VENDOR_GUID, 42), "svc");
        assert_eq!(encode(&named), VENDOR_REQUEST_HEADER_SVC.as_slice());

        let (decoded, read) = RequestHeader::decode_cdr2_le(&expected).unwrap();
        assert_eq!(read, 32);
        assert_eq!(decoded, empty);
        let (decoded, read) = RequestHeader::decode_cdr2_le(&VENDOR_REQUEST_HEADER_SVC).unwrap();
        assert_eq!(read, 32);
        assert_eq!(decoded, named);
    }

    #[test]
    fn request_header_payload_starts_after_the_padded_header() {
        let (header, consumed) = RequestHeader::decode_cdr2_le(&VENDOR_ECHO_REQUEST).unwrap();
        assert_eq!(header.request_id, SampleIdentity::new(VENDOR_GUID, 42));
        assert_eq!(header.instance_name, "");
        assert_eq!(consumed, 32);
        assert_eq!(
            &VENDOR_ECHO_REQUEST[consumed..],
            &[0x01, 0, 0, 0, 0x07, 0, 0, 0],
            "the _Call union must start at the 4-aligned offset"
        );
    }

    #[test]
    fn request_header_string_bound_is_enforced_both_ways() {
        let too_long = RequestHeader::with_instance_name(SampleIdentity::zero(), "x".repeat(256));
        let mut buf = vec![0u8; 512];
        assert!(too_long.encode_cdr2_le(&mut buf).is_err());

        let at_bound = RequestHeader::with_instance_name(SampleIdentity::zero(), "x".repeat(255));
        let bytes = encode(&at_bound);
        assert_eq!(bytes.len(), 24 + 4 + 255 + 1); // 284, already 4-aligned
        let (decoded, read) = RequestHeader::decode_cdr2_le(&bytes).unwrap();
        assert_eq!(read, 284);
        assert_eq!(decoded, at_bound);

        let mut oversized = bytes.clone();
        oversized[24..28].copy_from_slice(&257u32.to_le_bytes());
        oversized.push(0);
        assert!(RequestHeader::decode_cdr2_le(&oversized).is_err());
    }

    #[test]
    fn request_header_rejects_malformed_strings() {
        let mut zero_length = VENDOR_REQUEST_HEADER_SVC;
        zero_length[24..28].copy_from_slice(&0u32.to_le_bytes());
        assert!(RequestHeader::decode_cdr2_le(&zero_length).is_err());

        let mut missing_nul = VENDOR_REQUEST_HEADER_SVC;
        missing_nul[31] = b'!';
        assert!(matches!(
            RequestHeader::decode_cdr2_le(&missing_nul),
            Err(CdrError::InvalidEncoding)
        ));

        let mut not_utf8 = VENDOR_REQUEST_HEADER_SVC;
        not_utf8[28] = 0xff;
        assert!(matches!(
            RequestHeader::decode_cdr2_le(&not_utf8),
            Err(CdrError::InvalidEncoding)
        ));

        // Every truncation of a header that needs 32 bytes is an error, and
        // the string bytes announced by the length must be present.
        for len in 0..32 {
            assert!(
                RequestHeader::decode_cdr2_le(&VENDOR_REQUEST_HEADER_SVC[..len]).is_err(),
                "truncated at {len}"
            );
        }
        for len in 0..29 {
            assert!(
                RequestHeader::decode_cdr2_le(&VENDOR_REQUEST_HEADER_EMPTY_NAME[..len]).is_err(),
                "truncated at {len}"
            );
        }
        // 29 bytes: the string is complete but the padding is not.
        assert!(matches!(
            RequestHeader::decode_cdr2_le(&VENDOR_REQUEST_HEADER_EMPTY_NAME),
            Err(CdrError::UnexpectedEof)
        ));
    }

    #[test]
    fn reply_header_matches_the_vendor_bytes() {
        let header = ReplyHeader::error(
            SampleIdentity::new(VENDOR_GUID, 42),
            RemoteExceptionCode::InvalidArgument,
        );
        assert_eq!(
            encode(&header),
            VENDOR_REPLY_HEADER_INVALID_ARGUMENT.as_slice()
        );
        let (decoded, read) =
            ReplyHeader::decode_cdr2_le(&VENDOR_REPLY_HEADER_INVALID_ARGUMENT).unwrap();
        assert_eq!(read, 28);
        assert_eq!(decoded, header);
        for len in 0..28 {
            assert!(
                ReplyHeader::decode_cdr2_le(&VENDOR_REPLY_HEADER_INVALID_ARGUMENT[..len]).is_err(),
                "truncated at {len}"
            );
        }
    }

    #[test]
    fn reply_header_rejects_codes_outside_the_spec_enum() {
        for bad in [6i32, 7, -1, i32::MAX] {
            let mut bytes = VENDOR_REPLY_HEADER_INVALID_ARGUMENT;
            bytes[24..28].copy_from_slice(&bad.to_le_bytes());
            assert!(ReplyHeader::decode_cdr2_le(&bytes).is_err(), "code {bad}");
        }
        for good in 0..=5i32 {
            let mut bytes = VENDOR_REPLY_HEADER_INVALID_ARGUMENT;
            bytes[24..28].copy_from_slice(&good.to_le_bytes());
            let (header, _) = ReplyHeader::decode_cdr2_le(&bytes).unwrap();
            assert_eq!(header.remote_exception_code.as_i32(), good);
        }
    }

    #[test]
    fn exception_codes_are_the_spec_values() {
        assert_eq!(RemoteExceptionCode::Ok.as_i32(), 0);
        assert_eq!(RemoteExceptionCode::Unsupported.as_i32(), 1);
        assert_eq!(RemoteExceptionCode::InvalidArgument.as_i32(), 2);
        assert_eq!(RemoteExceptionCode::OutOfResources.as_i32(), 3);
        assert_eq!(RemoteExceptionCode::UnknownOperation.as_i32(), 4);
        assert_eq!(RemoteExceptionCode::UnknownException.as_i32(), 5);
        for value in 0..=5 {
            assert_eq!(
                RemoteExceptionCode::from_wire(value).unwrap().as_i32(),
                value
            );
        }
        assert_eq!(RemoteExceptionCode::from_wire(6), None);
        assert_eq!(RemoteExceptionCode::from_wire(-1), None);
    }

    #[test]
    fn request_header_roundtrips_through_a_tight_buffer() {
        let header = RequestHeader::with_instance_name(SampleIdentity::new(VENDOR_GUID, 7), "ab");
        // 24 + 4 + 3 = 31, padded to 32
        assert_eq!(header.max_cdr2_size(), 32);
        let mut buf = [0u8; 32];
        assert_eq!(header.encode_cdr2_le(&mut buf).unwrap(), 32);
        let mut short = [0u8; 31];
        assert!(matches!(
            header.encode_cdr2_le(&mut short),
            Err(CdrError::BufferTooSmall)
        ));
        let (decoded, read) = RequestHeader::decode_cdr2_le(&buf).unwrap();
        assert_eq!(read, 32);
        assert_eq!(decoded, header);
    }
}
