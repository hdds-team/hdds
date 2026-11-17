// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Union type definitions
//!
//! Complete and Minimal union types, headers, and members.
//!
//! # References
//! - XTypes v1.3 Spec: Section 7.3.4.8.2 (Union Types)

use super::dheader::{decode_dheader_at, encode_dheader_at};
use super::members::{decode_complete_union_member_internal, decode_minimal_union_member_internal};
use super::primitives::{decode_u16, encode_bool, encode_u16, encode_vec};
use super::type_identifier::decode_type_identifier_internal;
use crate::core::ser::traits::{Cdr2Decode, Cdr2Encode, CdrError};
use crate::xtypes::TypeIdentifier;

#[allow(clippy::wildcard_imports)]
use crate::xtypes::type_object::*;

// ============================================================================
// UnionHeader CDR2 Encoding/Decoding
// ============================================================================

impl Cdr2Encode for CompleteUnionHeader {
    fn max_cdr2_size(&self) -> usize {
        // DHEADER (4 bytes + up to 3 pad) + payload (detail only; the
        // discriminator is a separate member per XTypes v1.3 sec. 7.3.4.6).
        4 + 3 + self.detail.max_cdr2_size()
    }

    /// `@extensibility(APPENDABLE)` per XTypes v1.3 Sec.7.4.3.4 rule (30).
    ///
    /// Per XTypes v1.3 sec. 7.3.4.6 `CompleteUnionHeader` carries ONLY the
    /// `CompleteTypeDetail`. The discriminator type is serialised separately
    /// as the `CompleteDiscriminatorMember` that follows the header inside
    /// `CompleteUnionType` (see [`CompleteUnionType::encode_cdr2_le_at`]).
    fn encode_cdr2_le_at(&self, dst: &mut [u8], offset: &mut usize) -> Result<(), CdrError> {
        encode_dheader_at(dst, offset, |dst, offset| {
            self.detail.encode_cdr2_le_at(dst, offset)?;
            Ok(())
        })
    }
}

impl Cdr2Decode for CompleteUnionHeader {
    fn decode_cdr2_le_at(src: &[u8], offset: &mut usize) -> Result<Self, CdrError> {
        decode_complete_union_header_internal(src, offset)
    }
}

/// Internal helper that tracks offset for CompleteUnionHeader decoding.
/// `@extensibility(APPENDABLE)` per XTypes v1.3 Sec.7.4.3.4 rule (30).
///
/// The decoded header's `discriminator` field is left as a `TK_NONE`
/// placeholder; the real discriminator type is filled in by
/// [`CompleteUnionType::decode_cdr2_le_at`] from the trailing
/// `CompleteDiscriminatorMember` (XTypes v1.3 sec. 7.3.4.6).
pub(super) fn decode_complete_union_header_internal(
    src: &[u8],
    offset: &mut usize,
) -> Result<CompleteUnionHeader, CdrError> {
    decode_dheader_at(src, offset, |src, offset| {
        let detail =
            super::helpers::decode_detail_with_reencoding::<CompleteTypeDetail>(src, offset)?;
        Ok(CompleteUnionHeader {
            discriminator: TypeIdentifier::primitive(crate::xtypes::TypeKind::TK_NONE),
            discriminator_flags: MemberFlag::empty(),
            detail,
        })
    })
}

impl Cdr2Encode for MinimalUnionHeader {
    fn max_cdr2_size(&self) -> usize {
        // DHEADER (4 bytes + up to 3 pad) + payload (detail only; the
        // discriminator is a separate member per XTypes v1.3 sec. 7.3.4.6).
        4 + 3 + self.detail.max_cdr2_size()
    }

    /// `@extensibility(APPENDABLE)` per XTypes v1.3 Sec.7.4.3.4 rule (30).
    ///
    /// Per XTypes v1.3 sec. 7.3.4.6 `MinimalUnionHeader` carries ONLY the
    /// (empty) `MinimalTypeDetail`. The discriminator type is serialised
    /// separately as the `MinimalDiscriminatorMember` that follows the header
    /// inside `MinimalUnionType` (see [`MinimalUnionType::encode_cdr2_le_at`]).
    fn encode_cdr2_le_at(&self, dst: &mut [u8], offset: &mut usize) -> Result<(), CdrError> {
        encode_dheader_at(dst, offset, |dst, offset| {
            self.detail.encode_cdr2_le_at(dst, offset)?;
            Ok(())
        })
    }
}

impl Cdr2Decode for MinimalUnionHeader {
    fn decode_cdr2_le_at(src: &[u8], offset: &mut usize) -> Result<Self, CdrError> {
        decode_minimal_union_header_internal(src, offset)
    }
}

/// Internal helper that tracks offset for MinimalUnionHeader decoding.
/// `@extensibility(APPENDABLE)` per XTypes v1.3 Sec.7.4.3.4 rule (30).
///
/// The decoded header's `discriminator` field is left as a `TK_NONE`
/// placeholder; the real discriminator type is filled in by
/// [`MinimalUnionType::decode_cdr2_le_at`] from the trailing
/// `MinimalDiscriminatorMember` (XTypes v1.3 sec. 7.3.4.6).
pub(super) fn decode_minimal_union_header_internal(
    src: &[u8],
    offset: &mut usize,
) -> Result<MinimalUnionHeader, CdrError> {
    decode_dheader_at(src, offset, |src, offset| {
        // MinimalTypeDetail is empty (encodes as 0 bytes)
        let detail =
            super::helpers::decode_detail_with_reencoding::<MinimalTypeDetail>(src, offset)?;
        Ok(MinimalUnionHeader {
            discriminator: TypeIdentifier::primitive(crate::xtypes::TypeKind::TK_NONE),
            discriminator_flags: MemberFlag::empty(),
            detail,
        })
    })
}

// ============================================================================
// DiscriminatorMember CDR2 Encoding/Decoding
// ============================================================================
//
// Per XTypes v1.3 sec. 7.3.4.6 the union discriminator is serialised as a distinct
// member that follows the union header, NOT folded into the header. HDDS keeps
// the discriminator `TypeIdentifier` inside its `*UnionHeader` data model for
// ergonomic access, but emits/parses it here at the spec-mandated wire position.
//
//   @extensibility(FINAL)     struct CommonDiscriminatorMember { UnionDiscriminatorFlag member_flags; TypeIdentifier type_id; };
//   @extensibility(APPENDABLE) struct CompleteDiscriminatorMember { CommonDiscriminatorMember common; @optional ...annotations; };
//   @extensibility(APPENDABLE) struct MinimalDiscriminatorMember  { CommonDiscriminatorMember common; };
//
// With no annotations present the Complete and Minimal discriminator members are
// byte-identical, so a single encode/decode pair serves both.

/// Compute the `UnionDiscriminatorFlag` (member_flags) emitted for a union's
/// discriminator member.
///
/// Per XTypes v1.3 sec. 7.2.2.4.4.4.6 the discriminator member flags carry the
/// `TryConstructKind` (default `DISCARD`, encoded as `TRY_CONSTRUCT1`), the
/// `IS_MUST_UNDERSTAND` bit (the spec mandates: "In a union type, the
/// discriminator member shall always have the must understand attribute set
/// to true"), and the `IS_KEY` bit when the discriminator is a key.
///
/// The TryConstruct bits come from `header_flags`
/// ([`CompleteUnionHeader::discriminator_flags`], threaded from the
/// descriptor's `discriminator_try_construct`); when the header carries no
/// TryConstruct bits the spec default `DISCARD` (TRY_CONSTRUCT1) applies.
///
/// Keyness: HDDS internally marks a key discriminator by setting `IS_KEY` on
/// the union members at conversion time (`descriptor_union_to_xtypes`) --
/// that is the convention the matcher's key-agreement rule inspects. On the
/// WIRE keyness lives on
/// the discriminator member flags ONLY and branch members stay unflagged, so
/// the key state is folded in here (from either the header flags or the
/// members) and stripped from the members at encode time
/// (`CommonUnionMember::encode_cdr2_le_at`).
fn discriminator_member_flags(header_flags: MemberFlag, any_member_is_key: bool) -> u16 {
    let tc_bits = header_flags.0 & (MemberFlag::TRY_CONSTRUCT1.0 | MemberFlag::TRY_CONSTRUCT2.0);
    let tc_bits = if tc_bits == 0 {
        MemberFlag::TRY_CONSTRUCT1.0 // spec default = DISCARD
    } else {
        tc_bits
    };
    let mut flags = tc_bits | MemberFlag::IS_MUST_UNDERSTAND.0;
    if any_member_is_key || header_flags.contains(MemberFlag::IS_KEY) {
        flags |= MemberFlag::IS_KEY.0;
    }
    flags
}

/// Encode a `{Complete,Minimal}DiscriminatorMember` (APPENDABLE) per
/// XTypes v1.3 sec. 7.3.4.6: `DHEADER + CommonDiscriminatorMember{ member_flags:u16,
/// type_id }`. Annotations are never emitted (HDDS does not model discriminator
/// annotations), so this is identical for the Complete and Minimal forms.
fn encode_discriminator_member(
    discriminator: &TypeIdentifier,
    member_flags: u16,
    is_complete: bool,
    dst: &mut [u8],
    offset: &mut usize,
) -> Result<(), CdrError> {
    // Per XTypes v1.3 sec. 7.3.4.6 the discriminator member is APPENDABLE, so it is
    // DHEADER-delimited. Its `common` (CommonDiscriminatorMember, FINAL) is just
    // `member_flags` (u16) + `type_id`. The Complete form additionally carries
    // the two `@optional` annotation fields (`ann_builtin`, `ann_custom`); the
    // Minimal form does not (MinimalDiscriminatorMember = common only).
    encode_dheader_at(dst, offset, |dst, offset| {
        encode_u16(member_flags, dst, offset)?;
        discriminator.encode_cdr2_le_at(dst, offset)?;
        if is_complete {
            // @optional ann_builtin + @optional ann_custom, both absent (false).
            encode_bool(false, dst, offset)?;
            encode_bool(false, dst, offset)?;
        }
        Ok(())
    })
}

/// Decode a `{Complete,Minimal}DiscriminatorMember` (APPENDABLE), returning
/// the discriminator member flags and `TypeIdentifier`. The flags are
/// retained in the union header (`discriminator_flags`) so the descriptor
/// bridge can recover the discriminator's TryConstruct policy and `@key`
/// status from a remote TypeObject.
fn decode_discriminator_member(
    src: &[u8],
    offset: &mut usize,
) -> Result<(MemberFlag, TypeIdentifier), CdrError> {
    decode_dheader_at(src, offset, |src, offset| {
        let member_flags = MemberFlag(decode_u16(src, offset)?);
        let type_id = decode_type_identifier_internal(src, offset)?;
        // Trailing @optional annotation fields (Complete form only) are inside
        // the DHEADER-bounded region; decode_dheader_at skips any remainder.
        Ok((member_flags, type_id))
    })
}

/// Upper bound on the encoded size of a discriminator member plus the
/// member-sequence DHEADER: DHEADER (4 + up to 3 pad) + member_flags (2) +
/// TypeIdentifier (<=32) + 2 `@optional` annotation bytes (Complete) + the
/// member_seq DHEADER (4 + up to 3 pad).
const DISCRIMINATOR_MEMBER_MAX: usize = 4 + 3 + 2 + 32 + 2 + 4 + 3;

// ============================================================================
// CompleteUnionType / MinimalUnionType CDR2 Encoding/Decoding
// ============================================================================

impl Cdr2Encode for CompleteUnionType {
    fn max_cdr2_size(&self) -> usize {
        super::helpers::max_size_type_with_members(&self.header, &self.member_seq)
            + DISCRIMINATOR_MEMBER_MAX
    }

    /// XTypes v1.3 sec. 7.3.4.6 `CompleteUnionType` (FINAL):
    /// `union_flags`, `CompleteUnionHeader`, `CompleteDiscriminatorMember`,
    /// then `CompleteUnionMemberSeq`.
    fn encode_cdr2_le_at(&self, dst: &mut [u8], offset: &mut usize) -> Result<(), CdrError> {
        encode_u16(self.union_flags.0, dst, offset)?;
        self.header.encode_cdr2_le_at(dst, offset)?;
        // Discriminator member (spec-mandated position, after the header).
        let any_key = self
            .member_seq
            .iter()
            .any(|m| m.common.member_flags.contains(MemberFlag::IS_KEY));
        encode_discriminator_member(
            &self.header.discriminator,
            discriminator_member_flags(self.header.discriminator_flags, any_key),
            true,
            dst,
            offset,
        )?;
        // XTypes v1.3 sec. 7.4.3.5.3: the member sequence of a constructed type is
        // DHEADER-delimited (same framing as CompleteStructType::member_seq).
        // The spec TypeObject IDL annotates CompleteUnionMemberSeq
        // "Ordered by member_index", i.e. declaration order -- NOT sorted by
        // member_id (mirrors CompleteStructType::member_seq). The member_seq
        // is already in declaration order from the builder.
        encode_dheader_at(dst, offset, |dst, offset| {
            encode_vec(&self.member_seq, dst, offset, |member, dst, offset| {
                member.encode_cdr2_le_at(dst, offset)
            })
        })?;
        Ok(())
    }
}

impl Cdr2Decode for CompleteUnionType {
    fn decode_cdr2_le_at(src: &[u8], offset: &mut usize) -> Result<Self, CdrError> {
        let union_flags = UnionTypeFlag(decode_u16(src, offset)?);

        // Decode header (detail only; discriminator placeholder filled below).
        let mut header = decode_complete_union_header_internal(src, offset)?;

        // Discriminator member follows the header (XTypes v1.3 sec. 7.3.4.6).
        let (disc_flags, disc_type) = decode_discriminator_member(src, offset)?;
        header.discriminator = disc_type;
        header.discriminator_flags = disc_flags;

        // Member sequence is DHEADER-delimited (XTypes v1.3 sec. 7.4.3.5.3).
        let mut member_seq = decode_dheader_at(src, offset, |src, offset| {
            super::helpers::decode_member_sequence(
                src,
                offset,
                decode_complete_union_member_internal,
            )
        })?;

        // Wire convention: a @key discriminator is flagged
        // on the discriminator member only. Re-establish the HDDS-internal
        // convention (IS_KEY mirrored onto every member, which the matcher's
        // key-agreement rule inspects) so encode/decode round-trips and local
        // vs remote comparisons stay symmetric.
        if disc_flags.contains(MemberFlag::IS_KEY) {
            for m in &mut member_seq {
                m.common.member_flags = MemberFlag(m.common.member_flags.0 | MemberFlag::IS_KEY.0);
            }
        }

        Ok(CompleteUnionType {
            union_flags,
            header,
            member_seq,
        })
    }
}

impl Cdr2Encode for MinimalUnionType {
    fn max_cdr2_size(&self) -> usize {
        super::helpers::max_size_type_with_members(&self.header, &self.member_seq)
            + DISCRIMINATOR_MEMBER_MAX
    }

    /// XTypes v1.3 sec. 7.3.4.6 `MinimalUnionType` (FINAL):
    /// `union_flags`, `MinimalUnionHeader`, `MinimalDiscriminatorMember`,
    /// then `MinimalUnionMemberSeq`.
    fn encode_cdr2_le_at(&self, dst: &mut [u8], offset: &mut usize) -> Result<(), CdrError> {
        encode_u16(self.union_flags.0, dst, offset)?;
        self.header.encode_cdr2_le_at(dst, offset)?;
        // Discriminator member (spec-mandated position, after the header).
        let any_key = self
            .member_seq
            .iter()
            .any(|m| m.common.member_flags.contains(MemberFlag::IS_KEY));
        encode_discriminator_member(
            &self.header.discriminator,
            discriminator_member_flags(self.header.discriminator_flags, any_key),
            false,
            dst,
            offset,
        )?;
        // XTypes v1.3 sec. 7.4.3.5.3: DHEADER-delimited member sequence (matches
        // MinimalStructType::member_seq framing). Declaration-order emission:
        // NOTE the spec TypeObject IDL comment for MinimalUnionMemberSeq says
        // "Ordered by MinimalUnionMember.common.member_id", but HDDS emits
        // declaration order, the order the EquivalenceHash of conformant
        // peers is computed over (same choice as MinimalStructType).
        encode_dheader_at(dst, offset, |dst, offset| {
            encode_vec(&self.member_seq, dst, offset, |member, dst, offset| {
                member.encode_cdr2_le_at(dst, offset)
            })
        })?;
        Ok(())
    }
}

impl Cdr2Decode for MinimalUnionType {
    fn decode_cdr2_le_at(src: &[u8], offset: &mut usize) -> Result<Self, CdrError> {
        let union_flags = UnionTypeFlag(decode_u16(src, offset)?);

        // Decode header (detail only; discriminator placeholder filled below).
        let mut header = decode_minimal_union_header_internal(src, offset)?;

        // Discriminator member follows the header (XTypes v1.3 sec. 7.3.4.6).
        let (disc_flags, disc_type) = decode_discriminator_member(src, offset)?;
        header.discriminator = disc_type;
        header.discriminator_flags = disc_flags;

        // Member sequence is DHEADER-delimited (XTypes v1.3 sec. 7.4.3.5.3).
        let mut member_seq = decode_dheader_at(src, offset, |src, offset| {
            super::helpers::decode_member_sequence(
                src,
                offset,
                decode_minimal_union_member_internal,
            )
        })?;

        // Mirror wire-level discriminator keyness onto the members (see the
        // CompleteUnionType decoder above for the rationale).
        if disc_flags.contains(MemberFlag::IS_KEY) {
            for m in &mut member_seq {
                m.common.member_flags = MemberFlag(m.common.member_flags.0 | MemberFlag::IS_KEY.0);
            }
        }

        Ok(MinimalUnionType {
            union_flags,
            header,
            member_seq,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xtypes::{MemberFlag, TypeIdentifier, TypeKind, UnionTypeFlag};

    fn make_minimal_member(member_id: u32, label: i32, name_hash: u32) -> MinimalUnionMember {
        MinimalUnionMember {
            common: CommonUnionMember {
                member_id,
                member_flags: MemberFlag::empty(),
                member_type_id: TypeIdentifier::primitive(TypeKind::TK_INT32),
                label_seq: vec![label],
            },
            detail: MinimalMemberDetail { name_hash },
        }
    }

    fn minimal_header() -> MinimalUnionHeader {
        MinimalUnionHeader {
            discriminator: TypeIdentifier::primitive(TypeKind::TK_INT32),
            discriminator_flags: MemberFlag::empty(),
            detail: MinimalTypeDetail::new(),
        }
    }

    /// MinimalUnionMemberSeq is emitted in DECLARATION order: the input Vec
    /// order is preserved on the wire and a shuffled input must NOT be
    /// re-sorted by member_id; see the encoder comment in
    /// `MinimalUnionType::encode_cdr2_le_at`.
    #[test]
    fn minimal_union_members_emit_in_declaration_order() {
        let header = minimal_header();

        let shuffled = MinimalUnionType {
            union_flags: UnionTypeFlag(0),
            header: header.clone(),
            member_seq: vec![
                make_minimal_member(4, 40, 0x44),
                make_minimal_member(1, 10, 0x11),
                make_minimal_member(3, 30, 0x33),
            ],
        };
        let sorted = MinimalUnionType {
            union_flags: UnionTypeFlag(0),
            header,
            member_seq: vec![
                make_minimal_member(1, 10, 0x11),
                make_minimal_member(3, 30, 0x33),
                make_minimal_member(4, 40, 0x44),
            ],
        };

        let mut buf_shuffled = vec![0u8; shuffled.max_cdr2_size()];
        let len_shuffled = shuffled
            .encode_cdr2_le(&mut buf_shuffled)
            .expect("encode shuffled");
        let mut buf_sorted = vec![0u8; sorted.max_cdr2_size()];
        let len_sorted = sorted
            .encode_cdr2_le(&mut buf_sorted)
            .expect("encode sorted");

        assert_ne!(
            &buf_shuffled[..len_shuffled],
            &buf_sorted[..len_sorted],
            "differently-ordered inputs must produce different bytes \
             (declaration order preserved, no re-sort)"
        );

        // Round-trip: decode the shuffled-input bytes and confirm the wire
        // preserved the declaration order with labels intact.
        let (decoded, used) = MinimalUnionType::decode_cdr2_le(&buf_shuffled[..len_shuffled])
            .expect("decode round-trip");
        assert_eq!(used, len_shuffled, "decoder consumes full input");
        let ids: Vec<u32> = decoded
            .member_seq
            .iter()
            .map(|m| m.common.member_id)
            .collect();
        assert_eq!(
            ids,
            vec![4, 1, 3],
            "decoded member_ids preserve declaration order"
        );
        let labels: Vec<i32> = decoded
            .member_seq
            .iter()
            .map(|m| m.common.label_seq[0])
            .collect();
        assert_eq!(
            labels,
            vec![40, 10, 30],
            "labels follow their owning member in declaration order"
        );
    }

    /// Same guarantee for CompleteUnionType: the spec TypeObject IDL
    /// annotates CompleteUnionMemberSeq "Ordered by member_index"
    /// (declaration order), so the input order is preserved on the wire.
    #[test]
    fn complete_union_members_emit_in_declaration_order() {
        let header = CompleteUnionHeader {
            discriminator: TypeIdentifier::primitive(TypeKind::TK_INT32),
            discriminator_flags: MemberFlag::empty(),
            detail: CompleteTypeDetail {
                type_name: "Choice".to_string(),
                ann_builtin: None,
                ann_custom: None,
            },
        };

        let make = |member_id: u32, name: &str| CompleteUnionMember {
            common: CommonUnionMember {
                member_id,
                member_flags: MemberFlag::empty(),
                member_type_id: TypeIdentifier::primitive(TypeKind::TK_INT32),
                label_seq: vec![member_id as i32],
            },
            detail: CompleteMemberDetail {
                name: name.to_string(),
                ann_builtin: None,
                ann_custom: None,
            },
        };

        let shuffled = CompleteUnionType {
            union_flags: UnionTypeFlag(0),
            header: header.clone(),
            member_seq: vec![make(5, "e"), make(0, "a"), make(2, "c")],
        };
        let sorted = CompleteUnionType {
            union_flags: UnionTypeFlag(0),
            header,
            member_seq: vec![make(0, "a"), make(2, "c"), make(5, "e")],
        };

        let mut buf_shuffled = vec![0u8; shuffled.max_cdr2_size()];
        let len_shuffled = shuffled
            .encode_cdr2_le(&mut buf_shuffled)
            .expect("encode shuffled");
        let mut buf_sorted = vec![0u8; sorted.max_cdr2_size()];
        let len_sorted = sorted
            .encode_cdr2_le(&mut buf_sorted)
            .expect("encode sorted");

        assert_ne!(
            &buf_shuffled[..len_shuffled],
            &buf_sorted[..len_sorted],
            "differently-ordered inputs must produce different bytes \
             (declaration order preserved, no re-sort)"
        );

        // Round-trip: the shuffled input order survives encode+decode.
        let (decoded, used) = CompleteUnionType::decode_cdr2_le(&buf_shuffled[..len_shuffled])
            .expect("decode round-trip");
        assert_eq!(used, len_shuffled, "decoder consumes full input");
        let ids: Vec<u32> = decoded
            .member_seq
            .iter()
            .map(|m| m.common.member_id)
            .collect();
        assert_eq!(
            ids,
            vec![5, 0, 2],
            "decoded member_ids preserve declaration order"
        );
    }
}
