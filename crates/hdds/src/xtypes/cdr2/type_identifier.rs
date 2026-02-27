// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! TypeIdentifier - Core type identification for XTypes
//!
//!
//! TypeIdentifier uniquely identifies a type in the DDS type system.
//!
//! # References
//! - XTypes v1.3 Spec: Section 7.3.4.4 (TypeIdentifier)

use super::primitives::{decode_i32, decode_u32, decode_u8, encode_i32, encode_u32, encode_u8};
use crate::core::ser::traits::{Cdr2Decode, Cdr2Encode, CdrError};
use crate::xtypes::{CompleteTypeObject, TypeIdentifier, TypeKind};

// ============================================================================
// TypeIdentifier CDR2 Encoding/Decoding
// ============================================================================

impl Cdr2Encode for TypeIdentifier {
    fn encode_cdr2_le(&self, dst: &mut [u8]) -> Result<usize, CdrError> {
        let mut offset = 0;

        // Discriminator (u8)
        let discriminator = match self {
            TypeIdentifier::Primitive(_) => 0x01,
            TypeIdentifier::StringSmall { .. } => 0x02,
            TypeIdentifier::StringLarge { .. } => 0x03,
            TypeIdentifier::WStringSmall { .. } => 0x04,
            TypeIdentifier::WStringLarge { .. } => 0x05,
            TypeIdentifier::Minimal(_) => 0x06,
            TypeIdentifier::Complete(_) => 0x07,
            TypeIdentifier::StronglyConnected(_) => 0x08,
            // Inline is an hdds extension: inline CompleteTypeObject in the stream.
            TypeIdentifier::Inline(_) => 0x09,
        };
        encode_u8(discriminator, dst, &mut offset)?;

        // Variant data
        match self {
            TypeIdentifier::Primitive(kind) => {
                encode_u8(kind.to_u8(), dst, &mut offset)?;
            }
            TypeIdentifier::StringSmall { bound } => {
                encode_u8(*bound, dst, &mut offset)?;
            }
            TypeIdentifier::StringLarge { bound } => {
                encode_u32(*bound, dst, &mut offset)?;
            }
            TypeIdentifier::WStringSmall { bound } => {
                encode_u8(*bound, dst, &mut offset)?;
            }
            TypeIdentifier::WStringLarge { bound } => {
                encode_u32(*bound, dst, &mut offset)?;
            }
            TypeIdentifier::Minimal(hash) | TypeIdentifier::Complete(hash) => {
                // Write 14-byte hash
                if offset + 14 > dst.len() {
                    return Err(CdrError::BufferTooSmall);
                }
                dst[offset..offset + 14].copy_from_slice(hash.as_bytes());
                offset += 14;
            }
            TypeIdentifier::StronglyConnected(sc) => {
                // Write hash (14 bytes)
                if offset + 14 > dst.len() {
                    return Err(CdrError::BufferTooSmall);
                }
                dst[offset..offset + 14].copy_from_slice(sc.sc_component_id.as_bytes());
                offset += 14;

                // Write scc_length and scc_index (i32 each)
                encode_i32(sc.scc_length, dst, &mut offset)?;
                encode_i32(sc.scc_index, dst, &mut offset)?;
            }
            TypeIdentifier::Inline(ref type_obj) => {
                // Encode the complete inline TypeObject after the discriminator.
                let obj_written = type_obj.encode_cdr2_le(&mut dst[offset..])?;
                offset += obj_written;
            }
        }

        Ok(offset)
    }

    fn max_cdr2_size(&self) -> usize {
        match self {
            TypeIdentifier::Inline(type_obj) => 1 + type_obj.max_cdr2_size(),
            // Discriminator (1) + worst case (StronglyConnected: 14 + 4 + 4 + padding)
            _ => 32,
        }
    }
}

impl Cdr2Decode for TypeIdentifier {
    fn decode_cdr2_le(src: &[u8]) -> Result<(Self, usize), CdrError> {
        let mut offset = 0;
        let result = decode_type_identifier_internal(src, &mut offset)?;
        Ok((result, offset))
    }
}

/// Internal helper that tracks offset
pub(super) fn decode_type_identifier_internal(
    src: &[u8],
    offset: &mut usize,
) -> Result<TypeIdentifier, CdrError> {
    let discriminator = decode_u8(src, offset)?;

    match discriminator {
        0x01 => {
            let kind_byte = decode_u8(src, offset)?;
            let kind = TypeKind::from_u8(kind_byte)
                .ok_or_else(|| CdrError::Other(format!("Invalid TypeKind: {}", kind_byte)))?;
            Ok(TypeIdentifier::Primitive(kind))
        }
        0x02 => {
            let bound = decode_u8(src, offset)?;
            Ok(TypeIdentifier::StringSmall { bound })
        }
        0x03 => {
            let bound = decode_u32(src, offset)?;
            Ok(TypeIdentifier::StringLarge { bound })
        }
        0x04 => {
            let bound = decode_u8(src, offset)?;
            Ok(TypeIdentifier::WStringSmall { bound })
        }
        0x05 => {
            let bound = decode_u32(src, offset)?;
            Ok(TypeIdentifier::WStringLarge { bound })
        }
        0x06 => {
            // Minimal hash
            if *offset + 14 > src.len() {
                return Err(CdrError::UnexpectedEof);
            }
            let hash_bytes: [u8; 14] = src[*offset..*offset + 14]
                .try_into()
                .map_err(|_| CdrError::UnexpectedEof)?;
            *offset += 14;
            Ok(TypeIdentifier::Minimal(hash_bytes.into()))
        }
        0x07 => {
            // Complete hash
            if *offset + 14 > src.len() {
                return Err(CdrError::UnexpectedEof);
            }
            let hash_bytes: [u8; 14] = src[*offset..*offset + 14]
                .try_into()
                .map_err(|_| CdrError::UnexpectedEof)?;
            *offset += 14;
            Ok(TypeIdentifier::Complete(hash_bytes.into()))
        }
        0x08 => {
            // StronglyConnected
            if *offset + 14 > src.len() {
                return Err(CdrError::UnexpectedEof);
            }
            let hash_bytes: [u8; 14] = src[*offset..*offset + 14]
                .try_into()
                .map_err(|_| CdrError::UnexpectedEof)?;
            *offset += 14;

            let scc_length = decode_i32(src, offset)?;
            let scc_index = decode_i32(src, offset)?;

            Ok(TypeIdentifier::StronglyConnected(
                crate::xtypes::type_id::StronglyConnectedComponentId {
                    sc_component_id: hash_bytes.into(),
                    scc_length,
                    scc_index,
                },
            ))
        }
        0x09 => {
            // Inline CompleteTypeObject (hdds extension)
            let (type_obj, consumed) = CompleteTypeObject::decode_cdr2_le(&src[*offset..])?;
            *offset += consumed;
            Ok(TypeIdentifier::Inline(Box::new(type_obj)))
        }
        _ => Err(CdrError::Other(format!(
            "Invalid TypeIdentifier discriminator: {}",
            discriminator
        ))),
    }
}
