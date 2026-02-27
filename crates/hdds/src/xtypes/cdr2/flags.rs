// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! XTypes flag types
//!
//! Type flags, extensibility kinds, and member flags per XTypes v1.3.
//!
//! # References
//! - XTypes v1.3 Spec: Section 7.3.1.2 (Type Flags)

use super::primitives::{decode_u16, encode_u16};
use crate::core::ser::traits::{Cdr2Decode, Cdr2Encode, CdrError};

#[allow(clippy::wildcard_imports)]
use crate::xtypes::type_object::*;

// ============================================================================
// Flag Types CDR2 Encoding/Decoding
// ============================================================================

impl Cdr2Encode for StructTypeFlag {
    fn encode_cdr2_le(&self, dst: &mut [u8]) -> Result<usize, CdrError> {
        let mut offset = 0;
        encode_u16(self.0, dst, &mut offset)?;
        Ok(offset)
    }

    fn max_cdr2_size(&self) -> usize {
        4 // 2 bytes + alignment
    }
}

impl Cdr2Decode for StructTypeFlag {
    fn decode_cdr2_le(src: &[u8]) -> Result<(Self, usize), CdrError> {
        let mut offset = 0;
        let flags = decode_u16(src, &mut offset)?;
        Ok((StructTypeFlag(flags), offset))
    }
}

impl Cdr2Encode for MemberFlag {
    fn encode_cdr2_le(&self, dst: &mut [u8]) -> Result<usize, CdrError> {
        let mut offset = 0;
        encode_u16(self.0, dst, &mut offset)?;
        Ok(offset)
    }

    fn max_cdr2_size(&self) -> usize {
        4
    }
}

impl Cdr2Decode for MemberFlag {
    fn decode_cdr2_le(src: &[u8]) -> Result<(Self, usize), CdrError> {
        let mut offset = 0;
        let flags = decode_u16(src, &mut offset)?;
        Ok((MemberFlag(flags), offset))
    }
}

impl Cdr2Encode for UnionTypeFlag {
    fn encode_cdr2_le(&self, dst: &mut [u8]) -> Result<usize, CdrError> {
        let mut offset = 0;
        encode_u16(self.0, dst, &mut offset)?;
        Ok(offset)
    }

    fn max_cdr2_size(&self) -> usize {
        4 // 2 bytes + alignment
    }
}

impl Cdr2Decode for UnionTypeFlag {
    fn decode_cdr2_le(src: &[u8]) -> Result<(Self, usize), CdrError> {
        let mut offset = 0;
        let flags = decode_u16(src, &mut offset)?;
        Ok((UnionTypeFlag(flags), offset))
    }
}

impl Cdr2Encode for BitflagFlag {
    fn encode_cdr2_le(&self, dst: &mut [u8]) -> Result<usize, CdrError> {
        let mut offset = 0;
        encode_u16(self.0, dst, &mut offset)?;
        Ok(offset)
    }

    fn max_cdr2_size(&self) -> usize {
        4 // 2 bytes + alignment
    }
}

impl Cdr2Decode for BitflagFlag {
    fn decode_cdr2_le(src: &[u8]) -> Result<(Self, usize), CdrError> {
        let mut offset = 0;
        let flags = decode_u16(src, &mut offset)?;
        Ok((BitflagFlag(flags), offset))
    }
}

impl Cdr2Encode for BitsetTypeFlag {
    fn encode_cdr2_le(&self, dst: &mut [u8]) -> Result<usize, CdrError> {
        let mut offset = 0;
        encode_u16(self.0, dst, &mut offset)?;
        Ok(offset)
    }

    fn max_cdr2_size(&self) -> usize {
        4 // 2 bytes + alignment
    }
}

impl Cdr2Decode for BitsetTypeFlag {
    fn decode_cdr2_le(src: &[u8]) -> Result<(Self, usize), CdrError> {
        let mut offset = 0;
        let flags = decode_u16(src, &mut offset)?;
        Ok((BitsetTypeFlag(flags), offset))
    }
}

impl Cdr2Encode for BitfieldFlag {
    fn encode_cdr2_le(&self, dst: &mut [u8]) -> Result<usize, CdrError> {
        let mut offset = 0;
        encode_u16(self.0, dst, &mut offset)?;
        Ok(offset)
    }

    fn max_cdr2_size(&self) -> usize {
        4 // 2 bytes + alignment
    }
}

impl Cdr2Decode for BitfieldFlag {
    fn decode_cdr2_le(src: &[u8]) -> Result<(Self, usize), CdrError> {
        let mut offset = 0;
        let flags = decode_u16(src, &mut offset)?;
        Ok((BitfieldFlag(flags), offset))
    }
}

impl Cdr2Encode for AliasTypeFlag {
    fn encode_cdr2_le(&self, dst: &mut [u8]) -> Result<usize, CdrError> {
        let mut offset = 0;
        encode_u16(self.0, dst, &mut offset)?;
        Ok(offset)
    }

    fn max_cdr2_size(&self) -> usize {
        4 // 2 bytes + alignment
    }
}

impl Cdr2Decode for AliasTypeFlag {
    fn decode_cdr2_le(src: &[u8]) -> Result<(Self, usize), CdrError> {
        let mut offset = 0;
        let flags = decode_u16(src, &mut offset)?;
        Ok((AliasTypeFlag(flags), offset))
    }
}

impl Cdr2Encode for TypeRelationFlag {
    fn encode_cdr2_le(&self, dst: &mut [u8]) -> Result<usize, CdrError> {
        let mut offset = 0;
        encode_u16(self.0, dst, &mut offset)?;
        Ok(offset)
    }

    fn max_cdr2_size(&self) -> usize {
        4 // 2 bytes + alignment
    }
}

impl Cdr2Decode for TypeRelationFlag {
    fn decode_cdr2_le(src: &[u8]) -> Result<(Self, usize), CdrError> {
        let mut offset = 0;
        let flags = decode_u16(src, &mut offset)?;
        Ok((TypeRelationFlag(flags), offset))
    }
}
