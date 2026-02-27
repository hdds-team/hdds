// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Annotation type definitions
//!
//!
//! Complete and Minimal annotation types, headers, and parameters.
//!
//! # References
//! - XTypes v1.3 Spec: Section 7.3.4.8.10 (Annotation Types)

use super::helpers::{checked_usize, encode_fields_sequential};
use super::primitives::{
    align_offset, decode_bool, decode_i32, decode_option, decode_string, decode_u16, decode_u32,
    decode_u8, encode_bool, encode_i32, encode_option, encode_string, encode_u16, encode_u32,
    encode_u8, encode_vec,
};
use crate::core::ser::traits::{Cdr2Decode, Cdr2Encode, CdrError};
use crate::xtypes::TypeIdentifier;

#[allow(clippy::wildcard_imports)]
use crate::xtypes::type_object::*;

// ============================================================================
// CompleteAnnotationType / MinimalAnnotationType CDR2 (0x0A)
// ============================================================================

// AnnotationParameterFlag
impl Cdr2Encode for AnnotationParameterFlag {
    fn encode_cdr2_le(&self, dst: &mut [u8]) -> Result<usize, CdrError> {
        let mut offset = 0;
        encode_u16(self.0, dst, &mut offset)?;
        Ok(offset)
    }

    fn max_cdr2_size(&self) -> usize {
        4 // 2 bytes + alignment
    }
}

impl Cdr2Decode for AnnotationParameterFlag {
    fn decode_cdr2_le(src: &[u8]) -> Result<(Self, usize), CdrError> {
        let mut offset = 0;
        let flags = decode_u16(src, &mut offset)?;
        Ok((AnnotationParameterFlag(flags), offset))
    }
}

// AnnotationParameterValue (discriminated union enum)
impl Cdr2Encode for AnnotationParameterValue {
    // @audit-ok: Simple pattern matching (cyclo 13, cogni 1) - union variant encoder with discriminant
    fn encode_cdr2_le(&self, dst: &mut [u8]) -> Result<usize, CdrError> {
        let mut offset = 0;

        match self {
            AnnotationParameterValue::Boolean(b) => {
                encode_u8(0x00, dst, &mut offset)?; // discriminator
                encode_bool(*b, dst, &mut offset)?;
            }
            AnnotationParameterValue::Int32(i) => {
                encode_u8(0x01, dst, &mut offset)?; // discriminator
                encode_i32(*i, dst, &mut offset)?;
            }
            AnnotationParameterValue::String(s) => {
                encode_u8(0x02, dst, &mut offset)?; // discriminator
                encode_string(s, dst, &mut offset)?;
            }
            AnnotationParameterValue::Enumerated(e) => {
                encode_u8(0x03, dst, &mut offset)?; // discriminator
                encode_i32(*e, dst, &mut offset)?;
            }
        }

        Ok(offset)
    }

    fn max_cdr2_size(&self) -> usize {
        // Conservative: discriminator + max variant size
        match self {
            AnnotationParameterValue::Boolean(_) => 4 + 4, // disc + bool aligned
            AnnotationParameterValue::Int32(_) => 4 + 4,
            AnnotationParameterValue::String(s) => 4 + 4 + s.len() + 1, // disc + len + str + null
            AnnotationParameterValue::Enumerated(_) => 4 + 4,
        }
    }
}

impl Cdr2Decode for AnnotationParameterValue {
    // @audit-ok: Simple pattern matching (cyclo 11, cogni 1) - discriminator dispatch to union variants
    fn decode_cdr2_le(src: &[u8]) -> Result<(Self, usize), CdrError> {
        let mut offset = 0;

        let discriminator = decode_u8(src, &mut offset)?;

        match discriminator {
            0x00 => {
                let b = decode_bool(src, &mut offset)?;
                Ok((AnnotationParameterValue::Boolean(b), offset))
            }
            0x01 => {
                let i = decode_i32(src, &mut offset)?;
                Ok((AnnotationParameterValue::Int32(i), offset))
            }
            0x02 => {
                let s = decode_string(src, &mut offset)?;
                Ok((AnnotationParameterValue::String(s), offset))
            }
            0x03 => {
                let e = decode_i32(src, &mut offset)?;
                Ok((AnnotationParameterValue::Enumerated(e), offset))
            }
            _ => Err(CdrError::InvalidEncoding),
        }
    }
}

// Annotation Headers
impl Cdr2Encode for CompleteAnnotationHeader {
    fn encode_cdr2_le(&self, dst: &mut [u8]) -> Result<usize, CdrError> {
        self.detail.encode_cdr2_le(dst)
    }

    fn max_cdr2_size(&self) -> usize {
        self.detail.max_cdr2_size()
    }
}

impl Cdr2Decode for CompleteAnnotationHeader {
    fn decode_cdr2_le(src: &[u8]) -> Result<(Self, usize), CdrError> {
        let (detail, used) = CompleteTypeDetail::decode_cdr2_le(src)?;
        Ok((CompleteAnnotationHeader { detail }, used))
    }
}

impl Cdr2Encode for MinimalAnnotationHeader {
    fn encode_cdr2_le(&self, dst: &mut [u8]) -> Result<usize, CdrError> {
        self.detail.encode_cdr2_le(dst)
    }

    fn max_cdr2_size(&self) -> usize {
        self.detail.max_cdr2_size()
    }
}

impl Cdr2Decode for MinimalAnnotationHeader {
    fn decode_cdr2_le(src: &[u8]) -> Result<(Self, usize), CdrError> {
        let (detail, used) = MinimalTypeDetail::decode_cdr2_le(src)?;
        Ok((MinimalAnnotationHeader { detail }, used))
    }
}

// CommonAnnotationParameter
impl Cdr2Encode for CommonAnnotationParameter {
    fn encode_cdr2_le(&self, dst: &mut [u8]) -> Result<usize, CdrError> {
        let mut encode_flags = |buf: &mut [u8]| self.member_flags.encode_cdr2_le(buf);
        let mut encode_type = |buf: &mut [u8]| self.member_type_id.encode_cdr2_le(buf);

        encode_fields_sequential(dst, &mut [&mut encode_flags, &mut encode_type])
    }

    fn max_cdr2_size(&self) -> usize {
        self.member_flags.max_cdr2_size() + self.member_type_id.max_cdr2_size()
    }
}

impl Cdr2Decode for CommonAnnotationParameter {
    fn decode_cdr2_le(src: &[u8]) -> Result<(Self, usize), CdrError> {
        let mut offset = 0;

        let (member_flags, used) = AnnotationParameterFlag::decode_cdr2_le(&src[offset..])?;
        offset += used;

        let (member_type_id, used) = TypeIdentifier::decode_cdr2_le(&src[offset..])?;
        offset += used;

        Ok((
            CommonAnnotationParameter {
                member_flags,
                member_type_id,
            },
            offset,
        ))
    }
}

// CompleteAnnotationParameter
impl Cdr2Encode for CompleteAnnotationParameter {
    fn encode_cdr2_le(&self, dst: &mut [u8]) -> Result<usize, CdrError> {
        let mut encode_common = |buf: &mut [u8]| self.common.encode_cdr2_le(buf);
        let mut encode_name = |buf: &mut [u8]| -> Result<usize, CdrError> {
            let mut local = 0;
            encode_string(&self.name, buf, &mut local)?;
            Ok(local)
        };
        let mut encode_default = |buf: &mut [u8]| -> Result<usize, CdrError> {
            let mut local = 0;
            encode_option(
                &self.default_value,
                buf,
                &mut local,
                |value, buf, offset| {
                    let len = value.encode_cdr2_le(&mut buf[*offset..])?;
                    *offset += len;
                    Ok(())
                },
            )?;
            Ok(local)
        };

        encode_fields_sequential(
            dst,
            &mut [&mut encode_common, &mut encode_name, &mut encode_default],
        )
    }

    fn max_cdr2_size(&self) -> usize {
        let default_value_size = match &self.default_value {
            None => 4, // bool flag
            Some(v) => 4 + v.max_cdr2_size(),
        };
        self.common.max_cdr2_size() + 4 + self.name.len() + 1 + default_value_size
    }
}

impl Cdr2Decode for CompleteAnnotationParameter {
    fn decode_cdr2_le(src: &[u8]) -> Result<(Self, usize), CdrError> {
        let mut offset = 0;

        let (common, used) = CommonAnnotationParameter::decode_cdr2_le(&src[offset..])?;
        offset += used;

        let name = decode_string(src, &mut offset)?;

        let default_value = decode_option(src, &mut offset, |src, offset| {
            let (v, used) = AnnotationParameterValue::decode_cdr2_le(&src[*offset..])?;
            *offset += used;
            Ok(v)
        })?;

        Ok((
            CompleteAnnotationParameter {
                common,
                name,
                default_value,
            },
            offset,
        ))
    }
}

// MinimalAnnotationParameter
impl Cdr2Encode for MinimalAnnotationParameter {
    fn encode_cdr2_le(&self, dst: &mut [u8]) -> Result<usize, CdrError> {
        let mut encode_common = |buf: &mut [u8]| self.common.encode_cdr2_le(buf);
        let mut encode_name_hash = |buf: &mut [u8]| -> Result<usize, CdrError> {
            let mut local = 0;
            encode_u32(self.name_hash, buf, &mut local)?;
            Ok(local)
        };
        let mut encode_default = |buf: &mut [u8]| -> Result<usize, CdrError> {
            let mut local = 0;
            encode_option(
                &self.default_value,
                buf,
                &mut local,
                |value, buf, offset| {
                    let len = value.encode_cdr2_le(&mut buf[*offset..])?;
                    *offset += len;
                    Ok(())
                },
            )?;
            Ok(local)
        };

        encode_fields_sequential(
            dst,
            &mut [
                &mut encode_common,
                &mut encode_name_hash,
                &mut encode_default,
            ],
        )
    }

    fn max_cdr2_size(&self) -> usize {
        let default_value_size = match &self.default_value {
            None => 4, // bool flag
            Some(v) => 4 + v.max_cdr2_size(),
        };
        self.common.max_cdr2_size() + 4 + default_value_size
    }
}

impl Cdr2Decode for MinimalAnnotationParameter {
    fn decode_cdr2_le(src: &[u8]) -> Result<(Self, usize), CdrError> {
        let mut offset = 0;

        let (common, used) = CommonAnnotationParameter::decode_cdr2_le(&src[offset..])?;
        offset += used;

        let name_hash = decode_u32(src, &mut offset)?;

        let default_value = decode_option(src, &mut offset, |src, offset| {
            let (v, used) = AnnotationParameterValue::decode_cdr2_le(&src[*offset..])?;
            *offset += used;
            Ok(v)
        })?;

        Ok((
            MinimalAnnotationParameter {
                common,
                name_hash,
                default_value,
            },
            offset,
        ))
    }
}

// Complete/Minimal AnnotationType
impl Cdr2Encode for CompleteAnnotationType {
    fn encode_cdr2_le(&self, dst: &mut [u8]) -> Result<usize, CdrError> {
        let mut encode_header = |buf: &mut [u8]| self.header.encode_cdr2_le(buf);
        let mut encode_params = |buf: &mut [u8]| -> Result<usize, CdrError> {
            let mut local = 0;
            encode_vec(
                &self.member_seq,
                buf,
                &mut local,
                |param: &CompleteAnnotationParameter, buf, offset| {
                    let len = param.encode_cdr2_le(&mut buf[*offset..])?;
                    *offset += len;
                    Ok(())
                },
            )?;
            Ok(local)
        };

        encode_fields_sequential(dst, &mut [&mut encode_header, &mut encode_params])
    }

    fn max_cdr2_size(&self) -> usize {
        self.header.max_cdr2_size()
            + 4
            + self
                .member_seq
                .iter()
                .map(|p| p.max_cdr2_size())
                .sum::<usize>()
    }
}

impl Cdr2Decode for CompleteAnnotationType {
    fn decode_cdr2_le(src: &[u8]) -> Result<(Self, usize), CdrError> {
        let mut offset = 0;

        let (header, used) = CompleteAnnotationHeader::decode_cdr2_le(&src[offset..])?;
        offset += used;

        // Decode member_seq (Vec<CompleteAnnotationParameter>)
        let param_len = decode_u32(src, &mut offset)?;
        let capacity = checked_usize(param_len, "annotation parameter sequence length")?;
        let mut member_seq = Vec::with_capacity(capacity);
        for _ in 0..capacity {
            // Align each element to 4 bytes (CDR2 struct alignment in sequences)
            offset = align_offset(offset, 4);
            // v232: Bounds check after alignment to prevent panic on malformed data
            if offset > src.len() {
                return Err(CdrError::UnexpectedEof);
            }
            let (param, used) = CompleteAnnotationParameter::decode_cdr2_le(&src[offset..])?;
            offset += used;
            member_seq.push(param);
        }

        Ok((CompleteAnnotationType { header, member_seq }, offset))
    }
}

impl Cdr2Encode for MinimalAnnotationType {
    fn encode_cdr2_le(&self, dst: &mut [u8]) -> Result<usize, CdrError> {
        let mut encode_header = |buf: &mut [u8]| self.header.encode_cdr2_le(buf);
        let mut encode_params = |buf: &mut [u8]| -> Result<usize, CdrError> {
            let mut local = 0;
            encode_vec(
                &self.member_seq,
                buf,
                &mut local,
                |param: &MinimalAnnotationParameter, buf, offset| {
                    let len = param.encode_cdr2_le(&mut buf[*offset..])?;
                    *offset += len;
                    Ok(())
                },
            )?;
            Ok(local)
        };

        encode_fields_sequential(dst, &mut [&mut encode_header, &mut encode_params])
    }

    fn max_cdr2_size(&self) -> usize {
        self.header.max_cdr2_size()
            + 4
            + self
                .member_seq
                .iter()
                .map(|p| p.max_cdr2_size())
                .sum::<usize>()
    }
}

impl Cdr2Decode for MinimalAnnotationType {
    fn decode_cdr2_le(src: &[u8]) -> Result<(Self, usize), CdrError> {
        let mut offset = 0;

        let (header, used) = MinimalAnnotationHeader::decode_cdr2_le(&src[offset..])?;
        offset += used;

        // Decode member_seq (Vec<MinimalAnnotationParameter>)
        let param_len = decode_u32(src, &mut offset)?;
        let capacity = checked_usize(param_len, "minimal annotation parameter sequence length")?;
        let mut member_seq = Vec::with_capacity(capacity);
        for _ in 0..capacity {
            // Align each element to 4 bytes (CDR2 struct alignment in sequences)
            offset = align_offset(offset, 4);
            let (param, used) = MinimalAnnotationParameter::decode_cdr2_le(&src[offset..])?;
            offset += used;
            member_seq.push(param);
        }

        Ok((MinimalAnnotationType { header, member_seq }, offset))
    }
}
