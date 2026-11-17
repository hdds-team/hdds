// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! TypeIdentifier - Core type identification for XTypes
//!
//!
//! TypeIdentifier uniquely identifies a type in the DDS type system.
//!
//! # References
//! - XTypes v1.3 Spec: Section 7.3.4.4 (TypeIdentifier)

use super::dheader::{decode_dheader_at, encode_dheader_at};
use super::primitives::{
    decode_i32, decode_u16, decode_u32, decode_u8, encode_i32, encode_u16, encode_u32, encode_u8,
};
use crate::core::ser::traits::{Cdr2Decode, Cdr2Encode, CdrError};
use crate::xtypes::discriminators::{
    EK_BOTH, EK_COMPLETE, EK_MINIMAL, TI_PLAIN_ARRAY_LARGE, TI_PLAIN_ARRAY_SMALL,
    TI_PLAIN_MAP_LARGE, TI_PLAIN_MAP_SMALL, TI_PLAIN_SEQUENCE_LARGE, TI_PLAIN_SEQUENCE_SMALL,
    TI_STRING16_LARGE, TI_STRING16_SMALL, TI_STRING8_LARGE, TI_STRING8_SMALL,
    TI_STRONGLY_CONNECTED_COMPONENT,
};
use crate::xtypes::type_id::{
    PlainArrayLElemDefn, PlainArraySElemDefn, PlainCollectionHeader, PlainMapLTypeDefn,
    PlainMapSTypeDefn, PlainSequenceLElemDefn, PlainSequenceSElemDefn,
};
use crate::xtypes::type_object::CollectionElementFlag;
use crate::xtypes::{EquivalenceKind, TypeIdentifier, TypeKind};

/// Encode a `PlainCollectionHeader` (XTypes v1.3 sec. 7.3.4.4 IDL):
///   `equiv_kind: octet` followed by `element_flags: CollectionElementFlag (u16)`.
///
/// `equiv_kind` is a `typedef octet EquivalenceKind;` (spec line 12181) whose
/// valid wire values are the `EK_MINIMAL = 0xF1` / `EK_COMPLETE = 0xF2`
/// constants. HDDS's internal `EquivalenceKind` enum uses 0x10 / 0x20 in
/// memory for back-compat with the type system, but the wire bytes are
/// always the spec EK_* constants.
fn encode_plain_collection_header(
    header: &PlainCollectionHeader,
    dst: &mut [u8],
    offset: &mut usize,
) -> Result<(), CdrError> {
    let equiv_byte = match header.equiv_kind {
        EquivalenceKind::Minimal => EK_MINIMAL,
        EquivalenceKind::Complete => EK_COMPLETE,
        EquivalenceKind::Both => EK_BOTH,
    };
    encode_u8(equiv_byte, dst, offset)?;
    encode_u16(header.element_flags.0, dst, offset)?;
    Ok(())
}

/// Decode a `PlainCollectionHeader`. Symmetric with
/// [`encode_plain_collection_header`]: accepts only the spec `EK_MINIMAL`
/// (0xF1) / `EK_COMPLETE` (0xF2) wire bytes for `equiv_kind`.
fn decode_plain_collection_header(
    src: &[u8],
    offset: &mut usize,
) -> Result<PlainCollectionHeader, CdrError> {
    let equiv_byte = decode_u8(src, offset)?;
    let equiv_kind = match equiv_byte {
        EK_MINIMAL => EquivalenceKind::Minimal,
        EK_COMPLETE => EquivalenceKind::Complete,
        EK_BOTH => EquivalenceKind::Both,
        other => {
            return Err(CdrError::Other(format!(
                "PlainCollectionHeader.equiv_kind must be EK_MINIMAL (0xF1), \
                 EK_COMPLETE (0xF2) or EK_BOTH (0xF3) per XTypes v1.3 sec. 7.3.4.4 IDL, got 0x{:02X}",
                other
            )));
        }
    };
    let element_flags = CollectionElementFlag(decode_u16(src, offset)?);
    Ok(PlainCollectionHeader {
        equiv_kind,
        element_flags,
    })
}

/// Encode a `sequence<u8>` (`SBoundSeq`) per OMG CDR2: u32 length + raw bytes.
fn encode_sbound_seq(seq: &[u8], dst: &mut [u8], offset: &mut usize) -> Result<(), CdrError> {
    let len = u32::try_from(seq.len())
        .map_err(|_| CdrError::Other("SBoundSeq length exceeds u32::MAX".into()))?;
    encode_u32(len, dst, offset)?;
    if *offset + seq.len() > dst.len() {
        return Err(CdrError::BufferTooSmall);
    }
    dst[*offset..*offset + seq.len()].copy_from_slice(seq);
    *offset += seq.len();
    Ok(())
}

/// Decode a `sequence<u8>` (`SBoundSeq`).
fn decode_sbound_seq(src: &[u8], offset: &mut usize) -> Result<Vec<u8>, CdrError> {
    let len = decode_u32(src, offset)? as usize;
    if *offset + len > src.len() {
        return Err(CdrError::UnexpectedEof);
    }
    let out = src[*offset..*offset + len].to_vec();
    *offset += len;
    Ok(out)
}

/// Encode a `sequence<u32>` (`LBoundSeq`) per OMG CDR2: u32 length + u32 elements.
fn encode_lbound_seq(seq: &[u32], dst: &mut [u8], offset: &mut usize) -> Result<(), CdrError> {
    let len = u32::try_from(seq.len())
        .map_err(|_| CdrError::Other("LBoundSeq length exceeds u32::MAX".into()))?;
    encode_u32(len, dst, offset)?;
    for v in seq {
        encode_u32(*v, dst, offset)?;
    }
    Ok(())
}

/// Decode a `sequence<u32>` (`LBoundSeq`). The length is sanity-checked
/// against the remaining input so a crafted `len = u32::MAX` cannot
/// pre-allocate a multi-GB `Vec`.
fn decode_lbound_seq(src: &[u8], offset: &mut usize) -> Result<Vec<u32>, CdrError> {
    let len = decode_u32(src, offset)? as usize;
    let remaining = src.len().saturating_sub(*offset);
    // Each element is at least 4 bytes (aligned u32). Reject up front when
    // the declared length cannot fit in the remaining buffer.
    if len > remaining / 4 {
        return Err(CdrError::UnexpectedEof);
    }
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        out.push(decode_u32(src, offset)?);
    }
    Ok(out)
}

// ============================================================================
// TypeIdentifier CDR2 Encoding/Decoding
// ============================================================================

impl Cdr2Encode for TypeIdentifier {
    fn max_cdr2_size(&self) -> usize {
        // Conservative upper bound covering all variants:
        //   - Primitive / String*: 1..8 bytes
        //   - Minimal / Complete: 1 + 14 = 15 bytes
        //   - StronglyConnected: 32 bytes (see test at line locked below)
        //   - PlainSequence*: 1 + header(4) + bound(1..4) + nested TypeId
        //   - PlainArray*: 1 + header(4) + bound_seq(4 + N*1..4) + nested TypeId
        //   - PlainMap*: 1 + header(4) + bound(1..4) + nested + key_flags(2)
        //                + nested key TypeId
        //
        // Plain-collection variants are recursive; this constant covers
        // up to ~8 levels of nesting with primitive leaves. Callers
        // serializing deeply nested types should size their buffer with
        // `encode_cdr2_le_at` failure as the signal to retry larger.
        256
    }

    /// Wire encoding per OMG DDS-XTypes v1.3 sec. 7.3.4.4.
    ///
    /// Each variant produces the discriminator octet defined in the IDL
    /// `union TypeIdentifier switch (octet)` declaration, followed by the
    /// variant payload. Primitive types use the `TypeKind` octet directly
    /// as the discriminator and carry no payload.
    fn encode_cdr2_le_at(&self, dst: &mut [u8], offset: &mut usize) -> Result<(), CdrError> {
        match self {
            TypeIdentifier::Primitive(kind) => {
                encode_u8(kind.to_u8(), dst, offset)?;
            }
            TypeIdentifier::StringSmall { bound } => {
                encode_u8(TI_STRING8_SMALL, dst, offset)?;
                encode_u8(*bound, dst, offset)?;
            }
            TypeIdentifier::StringLarge { bound } => {
                encode_u8(TI_STRING8_LARGE, dst, offset)?;
                encode_u32(*bound, dst, offset)?;
            }
            TypeIdentifier::WStringSmall { bound } => {
                encode_u8(TI_STRING16_SMALL, dst, offset)?;
                encode_u8(*bound, dst, offset)?;
            }
            TypeIdentifier::WStringLarge { bound } => {
                encode_u8(TI_STRING16_LARGE, dst, offset)?;
                encode_u32(*bound, dst, offset)?;
            }
            TypeIdentifier::Minimal(hash) => {
                encode_u8(EK_MINIMAL, dst, offset)?;
                if *offset + 14 > dst.len() {
                    return Err(CdrError::BufferTooSmall);
                }
                dst[*offset..*offset + 14].copy_from_slice(hash.as_bytes());
                *offset += 14;
            }
            TypeIdentifier::Complete(hash) => {
                encode_u8(EK_COMPLETE, dst, offset)?;
                if *offset + 14 > dst.len() {
                    return Err(CdrError::BufferTooSmall);
                }
                dst[*offset..*offset + 14].copy_from_slice(hash.as_bytes());
                *offset += 14;
            }
            TypeIdentifier::PlainSequenceSmall(sd) => {
                encode_u8(TI_PLAIN_SEQUENCE_SMALL, dst, offset)?;
                encode_plain_collection_header(&sd.header, dst, offset)?;
                encode_u8(sd.bound, dst, offset)?;
                sd.element_identifier.encode_cdr2_le_at(dst, offset)?;
            }
            TypeIdentifier::PlainSequenceLarge(ld) => {
                encode_u8(TI_PLAIN_SEQUENCE_LARGE, dst, offset)?;
                encode_plain_collection_header(&ld.header, dst, offset)?;
                encode_u32(ld.bound, dst, offset)?;
                ld.element_identifier.encode_cdr2_le_at(dst, offset)?;
            }
            TypeIdentifier::PlainArraySmall(sd) => {
                encode_u8(TI_PLAIN_ARRAY_SMALL, dst, offset)?;
                encode_plain_collection_header(&sd.header, dst, offset)?;
                encode_sbound_seq(&sd.array_bound_seq, dst, offset)?;
                sd.element_identifier.encode_cdr2_le_at(dst, offset)?;
            }
            TypeIdentifier::PlainArrayLarge(ld) => {
                encode_u8(TI_PLAIN_ARRAY_LARGE, dst, offset)?;
                encode_plain_collection_header(&ld.header, dst, offset)?;
                encode_lbound_seq(&ld.array_bound_seq, dst, offset)?;
                ld.element_identifier.encode_cdr2_le_at(dst, offset)?;
            }
            TypeIdentifier::PlainMapSmall(sd) => {
                encode_u8(TI_PLAIN_MAP_SMALL, dst, offset)?;
                encode_plain_collection_header(&sd.header, dst, offset)?;
                encode_u8(sd.bound, dst, offset)?;
                sd.element_identifier.encode_cdr2_le_at(dst, offset)?;
                encode_u16(sd.key_flags.0, dst, offset)?;
                sd.key_identifier.encode_cdr2_le_at(dst, offset)?;
            }
            TypeIdentifier::PlainMapLarge(ld) => {
                encode_u8(TI_PLAIN_MAP_LARGE, dst, offset)?;
                encode_plain_collection_header(&ld.header, dst, offset)?;
                encode_u32(ld.bound, dst, offset)?;
                ld.element_identifier.encode_cdr2_le_at(dst, offset)?;
                encode_u16(ld.key_flags.0, dst, offset)?;
                ld.key_identifier.encode_cdr2_le_at(dst, offset)?;
            }
            TypeIdentifier::StronglyConnected(sc) => {
                encode_u8(TI_STRONGLY_CONNECTED_COMPONENT, dst, offset)?;
                // `StronglyConnectedComponentId` is `@extensibility(APPENDABLE) @nested`
                // per XTypes v1.3 spec line 12466 -> rule (30) requires DHEADER.
                // Inside the DHEADER body the `sc_component_id` field is a
                // `TypeObjectHashId` union (XTypes v1.3 sec. 7.3.4.6.5 /
                // sec. 7.3.4.6.6 + IDL annex): 1-byte octet discriminator
                // (EK_MINIMAL = 0xF1, EK_COMPLETE = 0xF2) followed by the
                // 14-byte EquivalenceHash.
                encode_dheader_at(dst, offset, |dst, offset| {
                    let inner_disc = match sc.kind {
                        crate::xtypes::EquivalenceKind::Minimal => EK_MINIMAL,
                        // A TypeObjectHashId union (XTypes v1.3 sec. 7.3.4.6.5/.6)
                        // only admits EK_MINIMAL / EK_COMPLETE; EK_BOTH is a
                        // PlainCollectionHeader-only value and never reaches an
                        // SCC hash id, so it falls back to EK_COMPLETE here.
                        crate::xtypes::EquivalenceKind::Complete
                        | crate::xtypes::EquivalenceKind::Both => EK_COMPLETE,
                    };
                    encode_u8(inner_disc, dst, offset)?;
                    if *offset + 14 > dst.len() {
                        return Err(CdrError::BufferTooSmall);
                    }
                    dst[*offset..*offset + 14].copy_from_slice(sc.sc_component_id.as_bytes());
                    *offset += 14;
                    encode_i32(sc.scc_length, dst, offset)?;
                    encode_i32(sc.scc_index, dst, offset)?;
                    Ok(())
                })?;
            }
        }
        Ok(())
    }
}

impl Cdr2Decode for TypeIdentifier {
    fn decode_cdr2_le_at(src: &[u8], offset: &mut usize) -> Result<Self, CdrError> {
        decode_type_identifier_internal(src, offset)
    }
}

/// Maximum nesting depth accepted by [`decode_type_identifier_internal`].
///
/// Plain-collection TypeIdentifiers carry recursive `Box<TypeIdentifier>`
/// payloads. A crafted peer message could otherwise nest thousands of
/// `PlainSequence<PlainSequence<...>>` layers and blow the parser stack.
/// 32 levels is comfortably above any legitimate IDL -- practical nested
/// types stay in the single-digit range -- and well inside the default
/// Rust stack budget.
const MAX_TYPE_IDENTIFIER_DEPTH: usize = 32;

/// Wire decoding of a `TypeIdentifier` per OMG DDS-XTypes v1.3 sec. 7.3.4.4.
///
/// Symmetric with [`Cdr2Encode::encode_cdr2_le`]: the discriminator octet
/// dispatches to the matching variant per the IDL `union TypeIdentifier
/// switch (octet)` declaration. Primitive `TypeIdentifier`s are decoded
/// directly from the `TypeKind` octet (TK_NONE..TK_CHAR16, 0x00..0x11)
/// with no payload.
///
/// Bytes outside the spec discriminator set surface as `CdrError::Other`.
/// In particular, `EK_BOTH` (0xF3) is not currently emitted by HDDS and is
/// rejected here rather than silently aliased to `Minimal` or `Complete`.
///
/// Recursive plain-collection TypeIdentifiers are bounded by
/// [`MAX_TYPE_IDENTIFIER_DEPTH`] to prevent stack-overflow attacks.
pub(super) fn decode_type_identifier_internal(
    src: &[u8],
    offset: &mut usize,
) -> Result<TypeIdentifier, CdrError> {
    decode_type_identifier_with_depth(src, offset, 0)
}

fn decode_type_identifier_with_depth(
    src: &[u8],
    offset: &mut usize,
    depth: usize,
) -> Result<TypeIdentifier, CdrError> {
    if depth >= MAX_TYPE_IDENTIFIER_DEPTH {
        return Err(CdrError::Other(format!(
            "TypeIdentifier nesting depth exceeds MAX_TYPE_IDENTIFIER_DEPTH ({})",
            MAX_TYPE_IDENTIFIER_DEPTH
        )));
    }
    let discriminator = decode_u8(src, offset)?;

    match discriminator {
        // sec. 7.3.4.4: when a `TypeIdentifier` carries a primitive type, the
        // discriminator octet IS the `TypeKind` value (TK_NONE..TK_CHAR16,
        // 0x00..0x11) and there is no payload following.
        0x00..=0x11 => {
            let kind = TypeKind::from_u8(discriminator).ok_or_else(|| {
                CdrError::Other(format!(
                    "TypeIdentifier primitive discriminator 0x{:02X} is not a known TypeKind",
                    discriminator
                ))
            })?;
            Ok(TypeIdentifier::Primitive(kind))
        }
        // sec. 7.3.4.4: `case TI_STRING8_SMALL: StringSTypeDefn { SBound bound; };`
        TI_STRING8_SMALL => {
            let bound = decode_u8(src, offset)?;
            Ok(TypeIdentifier::StringSmall { bound })
        }
        // sec. 7.3.4.4: `case TI_STRING8_LARGE: StringLTypeDefn { LBound bound; };`
        TI_STRING8_LARGE => {
            let bound = decode_u32(src, offset)?;
            Ok(TypeIdentifier::StringLarge { bound })
        }
        // sec. 7.3.4.4: `case TI_STRING16_SMALL: StringSTypeDefn { SBound bound; };`
        TI_STRING16_SMALL => {
            let bound = decode_u8(src, offset)?;
            Ok(TypeIdentifier::WStringSmall { bound })
        }
        // sec. 7.3.4.4: `case TI_STRING16_LARGE: StringLTypeDefn { LBound bound; };`
        TI_STRING16_LARGE => {
            let bound = decode_u32(src, offset)?;
            Ok(TypeIdentifier::WStringLarge { bound })
        }
        // sec. 7.3.4.4: `case TI_PLAIN_SEQUENCE_SMALL: PlainSequenceSElemDefn seq_sdefn;`
        TI_PLAIN_SEQUENCE_SMALL => {
            let header = decode_plain_collection_header(src, offset)?;
            let bound = decode_u8(src, offset)?;
            let element_identifier =
                Box::new(decode_type_identifier_with_depth(src, offset, depth + 1)?);
            Ok(TypeIdentifier::PlainSequenceSmall(PlainSequenceSElemDefn {
                header,
                bound,
                element_identifier,
            }))
        }
        // sec. 7.3.4.4: `case TI_PLAIN_SEQUENCE_LARGE: PlainSequenceLElemDefn seq_ldefn;`
        TI_PLAIN_SEQUENCE_LARGE => {
            let header = decode_plain_collection_header(src, offset)?;
            let bound = decode_u32(src, offset)?;
            let element_identifier =
                Box::new(decode_type_identifier_with_depth(src, offset, depth + 1)?);
            Ok(TypeIdentifier::PlainSequenceLarge(PlainSequenceLElemDefn {
                header,
                bound,
                element_identifier,
            }))
        }
        // sec. 7.3.4.4: `case TI_PLAIN_ARRAY_SMALL: PlainArraySElemDefn array_sdefn;`
        TI_PLAIN_ARRAY_SMALL => {
            let header = decode_plain_collection_header(src, offset)?;
            let array_bound_seq = decode_sbound_seq(src, offset)?;
            let element_identifier =
                Box::new(decode_type_identifier_with_depth(src, offset, depth + 1)?);
            Ok(TypeIdentifier::PlainArraySmall(PlainArraySElemDefn {
                header,
                array_bound_seq,
                element_identifier,
            }))
        }
        // sec. 7.3.4.4: `case TI_PLAIN_ARRAY_LARGE: PlainArrayLElemDefn array_ldefn;`
        TI_PLAIN_ARRAY_LARGE => {
            let header = decode_plain_collection_header(src, offset)?;
            let array_bound_seq = decode_lbound_seq(src, offset)?;
            let element_identifier =
                Box::new(decode_type_identifier_with_depth(src, offset, depth + 1)?);
            Ok(TypeIdentifier::PlainArrayLarge(PlainArrayLElemDefn {
                header,
                array_bound_seq,
                element_identifier,
            }))
        }
        // sec. 7.3.4.4: `case TI_PLAIN_MAP_SMALL: PlainMapSTypeDefn map_sdefn;`
        TI_PLAIN_MAP_SMALL => {
            let header = decode_plain_collection_header(src, offset)?;
            let bound = decode_u8(src, offset)?;
            let element_identifier =
                Box::new(decode_type_identifier_with_depth(src, offset, depth + 1)?);
            let key_flags = CollectionElementFlag(decode_u16(src, offset)?);
            let key_identifier =
                Box::new(decode_type_identifier_with_depth(src, offset, depth + 1)?);
            Ok(TypeIdentifier::PlainMapSmall(PlainMapSTypeDefn {
                header,
                bound,
                element_identifier,
                key_flags,
                key_identifier,
            }))
        }
        // sec. 7.3.4.4: `case TI_PLAIN_MAP_LARGE: PlainMapLTypeDefn map_ldefn;`
        TI_PLAIN_MAP_LARGE => {
            let header = decode_plain_collection_header(src, offset)?;
            let bound = decode_u32(src, offset)?;
            let element_identifier =
                Box::new(decode_type_identifier_with_depth(src, offset, depth + 1)?);
            let key_flags = CollectionElementFlag(decode_u16(src, offset)?);
            let key_identifier =
                Box::new(decode_type_identifier_with_depth(src, offset, depth + 1)?);
            Ok(TypeIdentifier::PlainMapLarge(PlainMapLTypeDefn {
                header,
                bound,
                element_identifier,
                key_flags,
                key_identifier,
            }))
        }
        // sec. 7.3.4.4: `case TI_STRONGLY_CONNECTED_COMPONENT:
        //               StronglyConnectedComponentId sc_component_id;`
        // Symmetric with the encoder: outer DHEADER (per XTypes v1.3 rule
        // (30), added in 1.6.10i) wraps the body, and the inner
        // `TypeObjectHashId` union (XTypes v1.3 sec. 7.3.4.6.5 / sec. 7.3.4.6.6
        // + IDL annex) prefixes the 14-byte hash with a 1-byte octet
        // discriminator (EK_MINIMAL = 0xF1, EK_COMPLETE = 0xF2).
        TI_STRONGLY_CONNECTED_COMPONENT => decode_dheader_at(src, offset, |src, offset| {
            let inner_disc = decode_u8(src, offset)?;
            let kind = match inner_disc {
                EK_MINIMAL => crate::xtypes::EquivalenceKind::Minimal,
                EK_COMPLETE => crate::xtypes::EquivalenceKind::Complete,
                other => {
                    return Err(CdrError::Other(format!(
                        "TypeObjectHashId inner discriminator must be EK_MINIMAL (0xF1) \
                         or EK_COMPLETE (0xF2), got 0x{:02X}",
                        other
                    )));
                }
            };
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
                    kind,
                    sc_component_id: hash_bytes.into(),
                    scc_length,
                    scc_index,
                },
            ))
        }),
        // sec. 7.3.4.4: `case EK_MINIMAL: EquivalenceHash equivalence_hash;`
        EK_MINIMAL => {
            if *offset + 14 > src.len() {
                return Err(CdrError::UnexpectedEof);
            }
            let hash_bytes: [u8; 14] = src[*offset..*offset + 14]
                .try_into()
                .map_err(|_| CdrError::UnexpectedEof)?;
            *offset += 14;
            Ok(TypeIdentifier::Minimal(hash_bytes.into()))
        }
        // sec. 7.3.4.4: `case EK_COMPLETE: EquivalenceHash equivalence_hash;`
        EK_COMPLETE => {
            if *offset + 14 > src.len() {
                return Err(CdrError::UnexpectedEof);
            }
            let hash_bytes: [u8; 14] = src[*offset..*offset + 14]
                .try_into()
                .map_err(|_| CdrError::UnexpectedEof)?;
            *offset += 14;
            Ok(TypeIdentifier::Complete(hash_bytes.into()))
        }
        // sec. 7.3.4.4 reserves `EK_BOTH` (0xF3) as a forward-compat marker
        // for types whose Minimal and Complete `TypeObject`s share a
        // hash. HDDS does not currently emit this value; reject it
        // explicitly rather than silently picking one of the equivalent
        // interpretations.
        _ => Err(CdrError::Other(format!(
            "Invalid TypeIdentifier discriminator: 0x{:02X}",
            discriminator
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xtypes::EquivalenceHash;

    /// Every `TypeIdentifier` constant the crate exposes must survive its own
    /// encoder and decoder.
    ///
    /// This is the test whose absence let a broken constant live: nothing else
    /// in the suite encodes a member `TypeIdentifier` and reads it back, so an
    /// identifier that encodes to a byte our own decoder refuses stayed
    /// invisible in-tree and only surfaced against a real consumer.
    /// `TK_STRING8` was exactly that: `Primitive(TypeKind::TK_STRING8)` encodes
    /// as a bare 0x20 through the primitive arm, and 0x20 is neither an
    /// accepted primitive discriminator here nor legal as a `TypeIdentifier`
    /// discriminator at all (DDS-XTypes v1.3 7.3.4.4 puts a string at
    /// `TI_STRING8_SMALL` plus a bound). The crate already said so elsewhere:
    /// `type_kind.rs` asserts `!TypeKind::TK_STRING8.is_primitive()`.
    #[test]
    fn every_exposed_type_identifier_constant_survives_a_round_trip() {
        // The two string constants are NOT in this list, and that is the
        // point: they are held inert at the non-spec primitive discriminator
        // (see the guardrail on `TypeIdentifier::TK_STRING8`), because arming
        // them to the legal form makes our CompleteTypeObject parse for a
        // foreign peer that then rejects us on a hash HDDS cannot yet produce
        // exactly, which breaks matching with that peer. The exception is
        // asserted explicitly below rather than hidden by omission, together
        // with the legal forms every real caller gets.
        let constants: [(&str, TypeIdentifier); 14] = [
            ("TK_BOOLEAN", TypeIdentifier::TK_BOOLEAN),
            ("TK_BYTE", TypeIdentifier::TK_BYTE),
            ("TK_INT8", TypeIdentifier::TK_INT8),
            ("TK_INT16", TypeIdentifier::TK_INT16),
            ("TK_INT32", TypeIdentifier::TK_INT32),
            ("TK_INT64", TypeIdentifier::TK_INT64),
            ("TK_UINT8", TypeIdentifier::TK_UINT8),
            ("TK_UINT16", TypeIdentifier::TK_UINT16),
            ("TK_UINT32", TypeIdentifier::TK_UINT32),
            ("TK_UINT64", TypeIdentifier::TK_UINT64),
            ("TK_FLOAT32", TypeIdentifier::TK_FLOAT32),
            ("TK_FLOAT64", TypeIdentifier::TK_FLOAT64),
            ("TK_CHAR8", TypeIdentifier::TK_CHAR8),
            ("TK_CHAR16", TypeIdentifier::TK_CHAR16),
        ];

        for (name, id) in constants {
            let mut buf = [0u8; 64];
            let written = id
                .encode_cdr2_le(&mut buf)
                .unwrap_or_else(|e| panic!("{name} must encode: {e:?}"));
            let mut offset = 0usize;
            let decoded = TypeIdentifier::decode_cdr2_le_at(&buf[..written], &mut offset)
                .unwrap_or_else(|e| {
                    panic!(
                        "{name} encodes to 0x{:02X} and our own decoder refuses it: {e:?}",
                        buf[0]
                    )
                });
            assert_eq!(
                decoded, id,
                "{name} must decode back to itself, not to a different identifier"
            );
            assert_eq!(
                offset, written,
                "{name} must consume exactly the bytes it produced"
            );
        }

        // The two documented exceptions, asserted out loud. They must stay
        // inert AND stay the ONLY exceptions: if a third constant ever fails
        // to round-trip, it belongs in the loop above, not here.
        for (name, inert) in [
            ("TK_STRING8", TypeIdentifier::TK_STRING8),
            ("TK_STRING16", TypeIdentifier::TK_STRING16),
        ] {
            let mut buf = [0u8; 64];
            let written = inert
                .encode_cdr2_le(&mut buf)
                .unwrap_or_else(|e| panic!("{name} must still encode: {e:?}"));
            let mut offset = 0usize;
            assert!(
                TypeIdentifier::decode_cdr2_le_at(&buf[..written], &mut offset).is_err(),
                "{name} now round-trips. If the hash-exact TypeObject work has landed and this \
                 was armed deliberately, re-run the interoperability tests before removing \
                 this assertion: arming it alone breaks matching with peers that check the \
                 TypeObject hash."
            );
        }

        // What a real caller gets instead: the spec-legal forms, which do
        // round-trip. Nothing about the guardrail makes an unbounded string
        // unrepresentable.
        for (name, legal) in [
            ("string(0)", TypeIdentifier::string(0)),
            ("wstring(0)", TypeIdentifier::wstring(0)),
        ] {
            let mut buf = [0u8; 64];
            let written = legal
                .encode_cdr2_le(&mut buf)
                .unwrap_or_else(|e| panic!("{name} must encode: {e:?}"));
            let mut offset = 0usize;
            let decoded = TypeIdentifier::decode_cdr2_le_at(&buf[..written], &mut offset)
                .unwrap_or_else(|e| panic!("{name} must decode: {e:?}"));
            assert_eq!(decoded, legal, "{name} must decode back to itself");
            assert_eq!(offset, written, "{name} must consume what it produced");
        }
    }

    /// A bounded string keeps its bound across the round trip, in both the
    /// small and the large form. The bound is what a peer needs in order to
    /// run assignability, so losing it is not a cosmetic difference.
    #[test]
    fn a_bounded_string_identifier_keeps_its_bound_across_a_round_trip() {
        let cases = [
            TypeIdentifier::StringSmall { bound: 32 },
            TypeIdentifier::StringSmall { bound: 0 },
            TypeIdentifier::StringLarge { bound: 100_000 },
            TypeIdentifier::WStringSmall { bound: 128 },
            TypeIdentifier::WStringLarge { bound: 70_000 },
        ];

        for id in cases {
            let mut buf = [0u8; 64];
            let written = id.encode_cdr2_le(&mut buf).expect("bounded string encodes");
            let mut offset = 0usize;
            let decoded = TypeIdentifier::decode_cdr2_le_at(&buf[..written], &mut offset)
                .expect("bounded string decodes");
            assert_eq!(decoded, id, "the bound must survive the round trip");
            assert_eq!(
                offset, written,
                "decode must consume exactly what was written"
            );
        }
    }

    /// `TypeIdentifier::Minimal` must encode the spec EK_MINIMAL discriminator
    /// (0xF1 per DDS-XTypes v1.3 sec. 7.3.4.4 IDL), not the in-memory
    /// `EquivalenceKind::Minimal` value (0x10) which is unrelated to the wire.
    #[test]
    fn typeid_minimal_writes_ek_minimal_spec_byte() {
        let id = TypeIdentifier::Minimal(EquivalenceHash::from_bytes([0xAA; 14]));
        let mut buf = [0u8; 32];
        let written = id.encode_cdr2_le(&mut buf).expect("encode succeeds");
        assert_eq!(buf[0], 0xF1);
        assert_eq!(written, 15);
        assert_eq!(&buf[1..15], &[0xAA; 14]);
    }

    /// `TypeIdentifier::Complete` must encode the spec EK_COMPLETE
    /// discriminator (0xF2 per DDS-XTypes v1.3 sec. 7.3.4.4 IDL).
    #[test]
    fn typeid_complete_writes_ek_complete_spec_byte() {
        let id = TypeIdentifier::Complete(EquivalenceHash::from_bytes([0xBB; 14]));
        let mut buf = [0u8; 32];
        let written = id.encode_cdr2_le(&mut buf).expect("encode succeeds");
        assert_eq!(buf[0], 0xF2);
        assert_eq!(written, 15);
        assert_eq!(&buf[1..15], &[0xBB; 14]);
    }

    /// Per DDS-XTypes v1.3 sec. 7.3.4.4, primitive `TypeIdentifier`s are encoded
    /// as a single `TypeKind` octet. This test pins the wire size at 1 byte
    /// to lock against re-introducing the legacy 2-byte `[0x01, kind]`
    /// wrapper that diverged from spec.
    #[test]
    fn typeid_primitive_encodes_as_typekind_octet_only() {
        let id = TypeIdentifier::Primitive(TypeKind::TK_FLOAT32);
        let mut buf = [0u8; 32];
        let written = id.encode_cdr2_le(&mut buf).expect("encode succeeds");
        assert_eq!(written, 1, "primitive must emit 1 byte total");
        assert_eq!(buf[0], 0x09, "TK_FLOAT32 octet per sec. 7.3.4.4");
    }

    /// `TypeIdentifier::StringSmall` -> TI_STRING8_SMALL (0x70) +
    /// `StringSTypeDefn { SBound bound }` per sec. 7.3.4.4.
    #[test]
    fn typeid_string_small_writes_ti_string8_small() {
        let id = TypeIdentifier::StringSmall { bound: 0x42 };
        let mut buf = [0u8; 32];
        let written = id.encode_cdr2_le(&mut buf).expect("encode succeeds");
        assert_eq!(buf[0], 0x70);
        assert_eq!(buf[1], 0x42);
        assert_eq!(written, 2);
    }

    /// `TypeIdentifier::WStringLarge` -> TI_STRING16_LARGE (0x73) +
    /// `StringLTypeDefn { LBound bound }` per sec. 7.3.4.4. The LBound is a
    /// 4-byte CDR2-aligned u32, so the discriminator octet is followed by
    /// 3 padding bytes before the bound payload.
    #[test]
    fn typeid_wstring_large_writes_ti_string16_large_aligned() {
        let id = TypeIdentifier::WStringLarge { bound: 1024 };
        let mut buf = [0u8; 32];
        let written = id.encode_cdr2_le(&mut buf).expect("encode succeeds");
        assert_eq!(buf[0], 0x73);
        assert_eq!(written, 8);
        assert_eq!(u32::from_le_bytes(buf[4..8].try_into().unwrap()), 1024);
    }

    /// `TypeIdentifier::StronglyConnected` -> TI_STRONGLY_CONNECTED_COMPONENT
    /// (0xB0) per sec. 7.3.4.4. Wire size locked at **32 bytes** post-1.7g:
    /// - offset 0: 1 octet outer discriminator (0xB0)
    /// - offset 1..4: 3 padding bytes for 4-byte alignment of DHEADER (UInt32)
    /// - offset 4..8: 4-byte DHEADER (payload size = 24)
    /// - offset 8: 1 octet inner `TypeObjectHashId` discriminator
    ///   (`EK_MINIMAL = 0xF1` or `EK_COMPLETE = 0xF2`) per XTypes v1.3
    ///   sec. 7.3.4.6.5 / sec. 7.3.4.6.6 + IDL annex
    /// - offset 9..23: 14-byte EquivalenceHash
    /// - offset 23..24: 1 padding byte for 4-byte alignment of i32 `scc_length`
    /// - offset 24..28: 4-byte `scc_length`
    /// - offset 28..32: 4-byte `scc_index`
    ///
    /// The DHEADER is there because `StronglyConnectedComponentId`
    /// is `@extensibility(APPENDABLE)` per XTypes v1.3 spec line 12466. The
    /// inner `TypeObjectHashId` union discriminator is part of the wire
    /// form: the one byte that would otherwise be i32-alignment padding is the
    /// inner discriminator, so the total wire size is unchanged.
    #[test]
    fn typeid_strongly_connected_writes_ti_scc_discriminator() {
        let id = TypeIdentifier::StronglyConnected(
            crate::xtypes::type_id::StronglyConnectedComponentId {
                kind: crate::xtypes::EquivalenceKind::Minimal,
                sc_component_id: EquivalenceHash::from_bytes([0xCC; 14]),
                scc_length: 3,
                scc_index: 1,
            },
        );
        let mut buf = [0u8; 64];
        let written = id.encode_cdr2_le(&mut buf).expect("encode succeeds");
        assert_eq!(buf[0], 0xB0);
        assert_eq!(
            written, 32,
            "SCC wire size must be exactly 32 bytes (1 outer disc + 3 pad + 4 DHEADER + 1 inner disc + 14 hash + 1 pad + 2*4 i32)"
        );
        // DHEADER value = payload bytes (1 inner disc + 14 hash + 1 pad + 8 i32 = 24)
        assert_eq!(u32::from_le_bytes(buf[4..8].try_into().unwrap()), 24);
        assert_eq!(
            buf[8], 0xF1,
            "inner TypeObjectHashId discriminator = EK_MINIMAL"
        );
        assert_eq!(&buf[9..23], &[0xCC; 14], "14-byte hash follows inner disc");
    }

    /// Sanity: every spec discriminator that the encoder emits is a valid
    /// `TypeIdentifier` discriminator per sec. 7.3.4.4 IDL. Catches accidental
    /// import of an `EquivalenceKind` variant cast as `u8`, which would
    /// produce a stray 0x10 / 0x20 byte rather than 0xF1 / 0xF2.
    #[test]
    fn typeid_encoder_uses_only_spec_discriminator_octets() {
        let cases: [(TypeIdentifier, u8); 7] = [
            (
                TypeIdentifier::Primitive(TypeKind::TK_BOOLEAN),
                TypeKind::TK_BOOLEAN.to_u8(),
            ),
            (TypeIdentifier::StringSmall { bound: 1 }, 0x70),
            (TypeIdentifier::StringLarge { bound: 256 }, 0x71),
            (TypeIdentifier::WStringSmall { bound: 1 }, 0x72),
            (TypeIdentifier::WStringLarge { bound: 256 }, 0x73),
            (TypeIdentifier::Minimal(EquivalenceHash::zero()), 0xF1),
            (TypeIdentifier::Complete(EquivalenceHash::zero()), 0xF2),
        ];
        for (id, expected) in cases {
            let mut buf = [0u8; 32];
            id.encode_cdr2_le(&mut buf).expect("encode succeeds");
            assert_eq!(buf[0], expected, "discriminator mismatch for {:?}", id);
        }
    }

    /// Pre-migration HDDS used `0x06` as the discriminator for hash-based
    /// `Minimal` `TypeIdentifier`s, with a 14-byte payload. Per OMG
    /// DDS-XTypes v1.3 sec. 7.3.4.4, byte `0x06` is `TK_UINT16`, a primitive
    /// `TypeIdentifier` with no payload. This test locks the spec
    /// reinterpretation: a buffer that a legacy decoder would read as
    /// `Minimal(hash)` must produce `Primitive(TK_UINT16)` consuming
    /// only one byte. It guards against accidental re-introduction of the
    /// legacy hash branch.
    #[test]
    fn typeid_decoder_rejects_legacy_byte_06_as_minimal() {
        // 1 discriminator + 14 fake-hash bytes (legacy layout).
        let mut buf = [0u8; 15];
        buf[0] = 0x06;
        for byte in buf.iter_mut().take(15).skip(1) {
            *byte = 0xAA;
        }
        let (decoded, consumed) =
            TypeIdentifier::decode_cdr2_le(&buf).expect("primitive decode succeeds");
        match decoded {
            TypeIdentifier::Primitive(TypeKind::TK_UINT16) => {}
            other => panic!(
                "expected Primitive(TK_UINT16) for byte 0x06, got {:?}",
                other
            ),
        }
        assert_eq!(consumed, 1, "primitive must consume exactly 1 byte");
    }

    /// Pre-migration HDDS used `0x09` as the discriminator for the
    /// HDDS-only `Inline` variant. Per sec. 7.3.4.4, byte `0x09` is
    /// `TK_FLOAT32`. Locks the spec reinterpretation and guards against
    /// the legacy branch being restored.
    #[test]
    fn typeid_decoder_rejects_legacy_byte_09_as_inline() {
        let buf = [0x09u8];
        let (decoded, consumed) =
            TypeIdentifier::decode_cdr2_le(&buf).expect("primitive decode succeeds");
        match decoded {
            TypeIdentifier::Primitive(TypeKind::TK_FLOAT32) => {}
            other => panic!(
                "expected Primitive(TK_FLOAT32) for byte 0x09, got {:?}",
                other
            ),
        }
        assert_eq!(consumed, 1, "primitive must consume exactly 1 byte");
    }

    /// Bytes outside the spec discriminator set (primitives 0x00..0x11,
    /// TI_STRING* 0x70..0x73, TI_SCC 0xB0, EK_MINIMAL/EK_COMPLETE 0xF1/0xF2)
    /// must surface as `CdrError::Other`. `0x50` falls in the spec gap
    /// between `TK_CHAR16` (0x11) and the `TI_STRING8_*` block (0x70).
    #[test]
    fn typeid_decoder_rejects_spec_gap_byte() {
        let buf = [0x50u8, 0x00, 0x00, 0x00];
        match TypeIdentifier::decode_cdr2_le(&buf) {
            Err(CdrError::Other(msg)) => assert!(
                msg.contains("0x50"),
                "expected error to mention discriminator 0x50, got: {msg}"
            ),
            other => panic!("expected CdrError::Other for byte 0x50, got {:?}", other),
        }
    }

    /// `EK_BOTH` (0xF3) is a forward-compat marker per sec. 7.3.4.4 IDL.
    /// HDDS does not currently emit it; the decoder must reject it
    /// rather than silently aliasing to `Minimal` or `Complete`.
    #[test]
    fn typeid_decoder_rejects_ek_both_forward_compat() {
        let mut buf = [0u8; 15];
        buf[0] = 0xF3;
        match TypeIdentifier::decode_cdr2_le(&buf) {
            Err(CdrError::Other(msg)) => assert!(
                msg.contains("0xF3"),
                "expected error to mention EK_BOTH (0xF3), got: {msg}"
            ),
            other => panic!("expected CdrError::Other for EK_BOTH, got {:?}", other),
        }
    }

    /// Symmetric round-trip: encoder emits 0xF1 + 14-byte hash, decoder
    /// consumes the same bytes and reconstructs the `Minimal` variant.
    /// Guards against asymmetric drift between the two halves.
    #[test]
    fn typeid_minimal_encode_decode_round_trip_uses_spec_byte() {
        let original = TypeIdentifier::Minimal(EquivalenceHash::from_bytes([0x55; 14]));
        let mut buf = [0u8; 32];
        let written = original.encode_cdr2_le(&mut buf).expect("encode succeeds");
        assert_eq!(buf[0], 0xF1, "encoder must emit EK_MINIMAL discriminator");

        let (decoded, consumed) =
            TypeIdentifier::decode_cdr2_le(&buf[..written]).expect("decode succeeds");
        assert_eq!(consumed, written);
        assert_eq!(decoded, original);
    }

    /// Symmetric round-trip for `TI_STRONGLY_CONNECTED_COMPONENT` (0xB0):
    /// encoder writes the inner `TypeObjectHashId` discriminator + 14-byte
    /// hash + 1 padding byte + two `i32`s (24 bytes body inside the
    /// DHEADER). Decoder consumes the same bytes and reconstructs the same
    /// `StronglyConnectedComponentId`, including the `kind` field that
    /// carries the inner discriminator. Guards against asymmetric drift on
    /// the SCC payload between the two halves.
    #[test]
    fn typeid_strongly_connected_round_trip() {
        for kind in [
            crate::xtypes::EquivalenceKind::Minimal,
            crate::xtypes::EquivalenceKind::Complete,
        ] {
            let original = TypeIdentifier::StronglyConnected(
                crate::xtypes::type_id::StronglyConnectedComponentId {
                    kind,
                    sc_component_id: EquivalenceHash::from_bytes([0xCC; 14]),
                    scc_length: 7,
                    scc_index: 3,
                },
            );
            let mut buf = [0u8; 32];
            let written = original.encode_cdr2_le(&mut buf).expect("encode succeeds");
            assert_eq!(buf[0], 0xB0);

            let (decoded, consumed) =
                TypeIdentifier::decode_cdr2_le(&buf[..written]).expect("decode succeeds");
            assert_eq!(consumed, written);
            assert_eq!(decoded, original, "round-trip preserves kind = {:?}", kind);
        }
    }

    /// The decoder must reject inner `TypeObjectHashId` discriminator values
    /// that are not `EK_MINIMAL` (0xF1) or `EK_COMPLETE` (0xF2). Locks the
    /// behaviour added in 1.7g against silent acceptance of stray bytes.
    #[test]
    fn typeid_strongly_connected_rejects_invalid_inner_discriminator() {
        // Build a valid SCC frame then corrupt the inner discriminator byte.
        let original = TypeIdentifier::StronglyConnected(
            crate::xtypes::type_id::StronglyConnectedComponentId {
                kind: crate::xtypes::EquivalenceKind::Minimal,
                sc_component_id: EquivalenceHash::from_bytes([0xCC; 14]),
                scc_length: 1,
                scc_index: 0,
            },
        );
        let mut buf = [0u8; 32];
        let written = original.encode_cdr2_le(&mut buf).expect("encode succeeds");
        buf[8] = 0xAB; // stray byte where the inner discriminator lives
        match TypeIdentifier::decode_cdr2_le(&buf[..written]) {
            Err(CdrError::Other(msg)) => assert!(
                msg.contains("0xAB"),
                "error should mention the bad inner discriminator byte 0xAB, got: {msg}"
            ),
            other => panic!(
                "expected CdrError::Other for stray inner discriminator, got {:?}",
                other
            ),
        }
    }

    /// Per OMG DDS-XTypes v1.3 sec. 7.3.4 IDL TypeKinds block, the
    /// primitive-range bytes `0x0E` and `0x0F` are gaps (TK_UINT8 ends
    /// at 0x0D, TK_CHAR8 starts at 0x10). The decoder must reject them
    /// rather than silently widening the accepted set if a future
    /// `TypeKind` variant is added in that range without coordination
    /// with this match arm.
    #[test]
    fn typeid_decoder_rejects_undefined_primitive_bytes() {
        for byte in [0x0E_u8, 0x0F] {
            let buf = [byte];
            let result = TypeIdentifier::decode_cdr2_le(&buf);
            assert!(
                matches!(result, Err(CdrError::Other(_))),
                "byte 0x{:02X} must be rejected (undefined primitive TypeKind), got {:?}",
                byte,
                result
            );
        }
    }

    /// Build a representative `PlainCollectionHeader` for the tests below.
    fn sample_header() -> PlainCollectionHeader {
        PlainCollectionHeader {
            equiv_kind: EquivalenceKind::Minimal,
            element_flags: CollectionElementFlag(0x0040),
        }
    }

    #[test]
    fn typeid_plain_sequence_small_writes_disc_0x80_and_round_trips() {
        let id = TypeIdentifier::PlainSequenceSmall(PlainSequenceSElemDefn {
            header: sample_header(),
            bound: 32,
            element_identifier: Box::new(TypeIdentifier::Primitive(TypeKind::TK_INT32)),
        });
        let mut buf = [0u8; 64];
        let written = id.encode_cdr2_le(&mut buf).expect("encode succeeds");
        assert_eq!(buf[0], 0x80);
        let (decoded, consumed) = TypeIdentifier::decode_cdr2_le(&buf[..written]).expect("decode");
        assert_eq!(consumed, written);
        assert_eq!(decoded, id);
    }

    #[test]
    fn typeid_plain_sequence_large_writes_disc_0x81_and_round_trips() {
        let id = TypeIdentifier::PlainSequenceLarge(PlainSequenceLElemDefn {
            header: sample_header(),
            bound: 0, // unbounded
            element_identifier: Box::new(TypeIdentifier::Primitive(TypeKind::TK_FLOAT64)),
        });
        let mut buf = [0u8; 64];
        let written = id.encode_cdr2_le(&mut buf).expect("encode succeeds");
        assert_eq!(buf[0], 0x81);
        let (decoded, consumed) = TypeIdentifier::decode_cdr2_le(&buf[..written]).expect("decode");
        assert_eq!(consumed, written);
        assert_eq!(decoded, id);
    }

    #[test]
    fn typeid_plain_array_small_writes_disc_0x90_and_round_trips() {
        let id = TypeIdentifier::PlainArraySmall(PlainArraySElemDefn {
            header: sample_header(),
            array_bound_seq: vec![3, 4, 5],
            element_identifier: Box::new(TypeIdentifier::Primitive(TypeKind::TK_INT16)),
        });
        let mut buf = [0u8; 64];
        let written = id.encode_cdr2_le(&mut buf).expect("encode succeeds");
        assert_eq!(buf[0], 0x90);
        let (decoded, consumed) = TypeIdentifier::decode_cdr2_le(&buf[..written]).expect("decode");
        assert_eq!(consumed, written);
        assert_eq!(decoded, id);
    }

    #[test]
    fn typeid_plain_array_large_writes_disc_0x91_and_round_trips() {
        let id = TypeIdentifier::PlainArrayLarge(PlainArrayLElemDefn {
            header: sample_header(),
            array_bound_seq: vec![1024, 2048],
            element_identifier: Box::new(TypeIdentifier::Primitive(TypeKind::TK_UINT64)),
        });
        let mut buf = [0u8; 64];
        let written = id.encode_cdr2_le(&mut buf).expect("encode succeeds");
        assert_eq!(buf[0], 0x91);
        let (decoded, consumed) = TypeIdentifier::decode_cdr2_le(&buf[..written]).expect("decode");
        assert_eq!(consumed, written);
        assert_eq!(decoded, id);
    }

    #[test]
    fn typeid_plain_map_small_writes_disc_0xa0_and_round_trips() {
        let id = TypeIdentifier::PlainMapSmall(PlainMapSTypeDefn {
            header: sample_header(),
            bound: 16,
            element_identifier: Box::new(TypeIdentifier::Primitive(TypeKind::TK_INT32)),
            key_flags: CollectionElementFlag(0x0040),
            key_identifier: Box::new(TypeIdentifier::StringSmall { bound: 32 }),
        });
        let mut buf = [0u8; 64];
        let written = id.encode_cdr2_le(&mut buf).expect("encode succeeds");
        assert_eq!(buf[0], 0xA0);
        let (decoded, consumed) = TypeIdentifier::decode_cdr2_le(&buf[..written]).expect("decode");
        assert_eq!(consumed, written);
        assert_eq!(decoded, id);
    }

    #[test]
    fn typeid_plain_map_large_writes_disc_0xa1_and_round_trips() {
        let id = TypeIdentifier::PlainMapLarge(PlainMapLTypeDefn {
            header: sample_header(),
            bound: 4096,
            element_identifier: Box::new(TypeIdentifier::Primitive(TypeKind::TK_FLOAT32)),
            key_flags: CollectionElementFlag(0x0040),
            key_identifier: Box::new(TypeIdentifier::StringLarge { bound: 4096 }),
        });
        let mut buf = [0u8; 64];
        let written = id.encode_cdr2_le(&mut buf).expect("encode succeeds");
        assert_eq!(buf[0], 0xA1);
        let (decoded, consumed) = TypeIdentifier::decode_cdr2_le(&buf[..written]).expect("decode");
        assert_eq!(consumed, written);
        assert_eq!(decoded, id);
    }

    /// Recursive plain TypeIdentifier -- `sequence<sequence<int32, 16>, 32>`.
    /// Exercises the nested `encode_cdr2_le_at` / `decode_cdr2_le_at` path
    /// on the `Box<TypeIdentifier>` element fields.
    #[test]
    fn typeid_plain_sequence_of_sequence_round_trips() {
        let inner = TypeIdentifier::PlainSequenceSmall(PlainSequenceSElemDefn {
            header: sample_header(),
            bound: 16,
            element_identifier: Box::new(TypeIdentifier::Primitive(TypeKind::TK_INT32)),
        });
        let outer = TypeIdentifier::PlainSequenceSmall(PlainSequenceSElemDefn {
            header: sample_header(),
            bound: 32,
            element_identifier: Box::new(inner),
        });
        let mut buf = [0u8; 64];
        let written = outer.encode_cdr2_le(&mut buf).expect("encode succeeds");
        let (decoded, consumed) = TypeIdentifier::decode_cdr2_le(&buf[..written]).expect("decode");
        assert_eq!(consumed, written);
        assert_eq!(decoded, outer);
    }

    /// The decoder must reject `PlainCollectionHeader.equiv_kind` bytes that
    /// are not `EK_MINIMAL` (0xF1) or `EK_COMPLETE` (0xF2) per XTypes v1.3
    /// sec. 7.3.4.4 IDL (`typedef octet EquivalenceKind;`). The error message
    /// carries the offending byte for debugging.
    #[test]
    fn typeid_plain_sequence_rejects_invalid_equiv_kind() {
        // Encode a valid PlainSequenceSmall then corrupt the equiv_kind byte
        // (offset 1, right after the TI discriminator).
        let id = TypeIdentifier::PlainSequenceSmall(PlainSequenceSElemDefn {
            header: sample_header(),
            bound: 8,
            element_identifier: Box::new(TypeIdentifier::Primitive(TypeKind::TK_INT32)),
        });
        let mut buf = [0u8; 32];
        let written = id.encode_cdr2_le(&mut buf).expect("encode succeeds");
        // Sanity-check that the encoder emits the spec EK_MINIMAL byte
        // (0xF1), not the in-memory EquivalenceKind::Minimal value (0x10).
        assert_eq!(buf[1], 0xF1, "equiv_kind must be EK_MINIMAL (0xF1)");
        buf[1] = 0xAB; // stray equiv_kind byte
        match TypeIdentifier::decode_cdr2_le(&buf[..written]) {
            Err(CdrError::Other(msg)) => assert!(
                msg.contains("0xAB"),
                "error should mention the bad equiv_kind byte 0xAB, got: {msg}"
            ),
            other => panic!(
                "expected CdrError::Other for stray equiv_kind, got {:?}",
                other
            ),
        }
    }

    /// Build a payload nesting `PlainSequenceSmall` `depth` levels deep
    /// over a primitive leaf, used to exercise the recursion-depth guard.
    fn build_nested_plain_sequence(depth: usize) -> TypeIdentifier {
        let mut current = TypeIdentifier::Primitive(TypeKind::TK_INT32);
        for _ in 0..depth {
            current = TypeIdentifier::PlainSequenceSmall(PlainSequenceSElemDefn {
                header: sample_header(),
                bound: 1,
                element_identifier: Box::new(current),
            });
        }
        current
    }

    /// The decoder must reject crafted payloads that nest more than
    /// `MAX_TYPE_IDENTIFIER_DEPTH` levels of `PlainSequence` (or other
    /// recursive Plain* variants) to prevent stack-overflow DoS via
    /// unbounded recursion.
    #[test]
    fn typeid_decoder_rejects_recursion_bomb() {
        let bomb = build_nested_plain_sequence(MAX_TYPE_IDENTIFIER_DEPTH + 1);
        let mut buf = vec![0u8; 4096];
        let written = bomb
            .encode_cdr2_le(&mut buf)
            .expect("deep nesting still encodable");
        match TypeIdentifier::decode_cdr2_le(&buf[..written]) {
            Err(CdrError::Other(msg)) => assert!(
                msg.contains("depth") || msg.contains("MAX_TYPE_IDENTIFIER_DEPTH"),
                "depth-limit error should mention 'depth', got: {msg}"
            ),
            other => panic!(
                "expected CdrError::Other (depth limit) on recursion bomb, got {:?}",
                other
            ),
        }
    }

    /// Nesting exactly at `MAX_TYPE_IDENTIFIER_DEPTH - 1` must still
    /// round-trip cleanly so the guard does not impose an over-tight
    /// limit on legitimate but deeply nested types.
    #[test]
    fn typeid_decoder_accepts_max_depth_minus_one() {
        let deep = build_nested_plain_sequence(MAX_TYPE_IDENTIFIER_DEPTH - 1);
        let mut buf = vec![0u8; 4096];
        let written = deep.encode_cdr2_le(&mut buf).expect("encode");
        let (decoded, consumed) =
            TypeIdentifier::decode_cdr2_le(&buf[..written]).expect("decode within limit");
        assert_eq!(consumed, written);
        assert_eq!(decoded, deep);
    }

    /// A crafted `TI_PLAIN_ARRAY_LARGE` payload that declares a
    /// `LBoundSeq.length` far exceeding the available bytes must be
    /// rejected before the decoder tries to pre-allocate a multi-GB
    /// `Vec<u32>`.
    #[test]
    fn typeid_plain_array_large_rejects_bogus_lbound_seq_length() {
        let mut buf = vec![0u8; 32];
        let mut offset = 0;
        encode_u8(TI_PLAIN_ARRAY_LARGE, &mut buf, &mut offset).unwrap();
        encode_u8(EK_MINIMAL, &mut buf, &mut offset).unwrap();
        encode_u16(0x0040, &mut buf, &mut offset).unwrap();
        // Declare a billion-element bound seq with no elements actually present.
        encode_u32(1_000_000_000, &mut buf, &mut offset).unwrap();
        let written = offset;
        match TypeIdentifier::decode_cdr2_le(&buf[..written]) {
            Err(CdrError::UnexpectedEof) => {}
            other => panic!(
                "expected UnexpectedEof for bogus LBoundSeq length, got {:?}",
                other
            ),
        }
    }
}
