// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! CDR encoding/decoding for DynamicData.

use crate::dds::CdrVersion;
use crate::dynamic::{
    DynamicData, DynamicValue, Extensibility, FieldDescriptor, PrimitiveKind, TryConstructKind,
    TypeDescriptor, TypeKind,
};
use std::fmt;
use std::sync::Arc;

/// Maximum primitive alignment under XCDR2 (DDS-XTypes v1.3 Table 5 /
/// section 7.4.3.3): 8- and 16-byte primitives align to 4, not to their
/// natural size. XCDR1 keeps natural alignment (8 for 64-bit, up to 16 for
/// long double).
const XCDR2_MAX_ALIGN: usize = 4;

/// XCDR1 PL_CDR parameter list reserved ids (DDS-XTypes v1.3 section
/// 7.4.1.2.1, Table 34), as 14-bit values: `PID_EXTENDED` switches to the
/// extended header form (u32 member header + u32 length), `PID_LIST_END`
/// terminates the list.
const PID_EXTENDED: u16 = 0x3F01;
const PID_LIST_END: u16 = 0x3F02;
/// FLAG_MUST_UNDERSTAND of a 16-bit parameterId (section 7.4.1.2.1).
/// HDDS writes a mutable union's discriminator as parameterId 0x4000 =
/// member id 0 | this flag.
const PID_FLAG_MUST_UNDERSTAND: u16 = 0x4000;
/// Table 34 marks PID_EXTENDED and PID_LIST_END must-understand, so writers
/// emit them with the flag set: 0x7F01 and 0x7F02 (section 7.4.1.2.1, and
/// "The value of the PID_EXTENDED with the must understand flag set is
/// 0x7F01"). Readers accept them with or without it.
const PID_EXTENDED_WRITTEN: u16 = PID_EXTENDED | PID_FLAG_MUST_UNDERSTAND;
const PID_LIST_END_WRITTEN: u16 = PID_LIST_END | PID_FLAG_MUST_UNDERSTAND;
/// Largest member id the 16-bit parameterId represents (section 7.4.1.2.2:
/// "Member IDs from 0 to 16,128 (0x3F00) inclusive").
const PID_SHORT_MAX_MEMBER_ID: u32 = 0x3F00;
/// Flags of the extended parameter's 32-bit member header (eMemberHeader,
/// section 7.4.1.2.2): FLAG_1 = FLAG_IMPL_EXTENSION, FLAG_2 =
/// FLAG_MUST_UNDERSTAND of the member; the 16-bit PID_EXTENDED word's own
/// flags never apply to the member.
const EXT_FLAG_IMPL_EXTENSION: u32 = 0x8000_0000;
const EXT_FLAG_MUST_UNDERSTAND: u32 = 0x4000_0000;
/// The member id: low 28 bits of an XCDR1 extended member header and of an
/// XCDR2 EMHEADER1 (sections 7.4.1.2.2, 7.4.3.4.2).
const MEMBER_ID_MASK: u32 = super::xtypes_bridge::MAX_MEMBER_ID;
/// M_FLAG of an XCDR2 EMHEADER1, bit 31 (section 7.4.3.4.2).
const EMHEADER_FLAG_MUST_UNDERSTAND: u32 = 0x8000_0000;

/// One XCDR1 parameter header, as read: the end of the list, or a parameter
/// with its member id (`None` for a parameter that names no member of a
/// user type: an implementation extension or a reserved id), its
/// must-understand flag (always false for a Table 34 reserved id) and its
/// exact value length.
enum PlCdr1Header {
    ListEnd,
    Param {
        member_id: Option<u32>,
        must_understand: bool,
        len: usize,
    },
}

fn primitive_alignment(natural: usize, version: CdrVersion) -> usize {
    match version {
        CdrVersion::Xcdr1 => natural,
        CdrVersion::Xcdr2 => natural.min(XCDR2_MAX_ALIGN),
    }
}

/// Whether an XCDR2 collection (sequence/array) of this element type is
/// DELIMITED, i.e. serialized with a 4-byte DHEADER before its body
/// (DDS-XTypes v1.3 section 7.4.2: collections of non-primitive element
/// type). True primitives (integers, floats, bool, byte, char) are exempt;
/// strings and enums are not primitive element types here, so
/// sequence<string> and sequence<enum> both carry a DHEADER while
/// sequence<int32> does not.
fn collection_element_needs_dheader(kind: &TypeKind) -> bool {
    match kind {
        TypeKind::Primitive(p) => matches!(
            p,
            PrimitiveKind::String { .. } | PrimitiveKind::WString { .. }
        ),
        _ => true,
    }
}

/// Errors for dynamic CDR operations.
#[derive(Debug)]
pub enum DynamicCdrError {
    BufferTooSmall {
        need: usize,
        have: usize,
    },
    InvalidData(String),
    UnsupportedType(String),
    Utf8Error(std::string::FromUtf8Error),
    TypeMismatch {
        expected: String,
        found: String,
    },
    /// A length (element count, byte count, DHEADER, NEXTINT) does not fit
    /// the 32-bit word CDR gives it. `what` names the field.
    LengthOverflow {
        what: &'static str,
        len: usize,
    },
}

impl fmt::Display for DynamicCdrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BufferTooSmall { need, have } => {
                write!(f, "Buffer too small: need {} bytes, have {}", need, have)
            }
            Self::InvalidData(msg) => write!(f, "Invalid data: {}", msg),
            Self::UnsupportedType(t) => write!(f, "Unsupported type: {}", t),
            Self::Utf8Error(e) => write!(f, "UTF-8 error: {}", e),
            Self::TypeMismatch { expected, found } => {
                write!(f, "Type mismatch: expected {}, found {}", expected, found)
            }
            Self::LengthOverflow { what, len } => {
                write!(
                    f,
                    "{} of {} does not fit the u32 CDR length word",
                    what, len
                )
            }
        }
    }
}

/// Narrow a length to the u32 word CDR serializes it in, naming the field on
/// failure. Every length word the encoder writes goes through here so a body
/// or count too large for the format is an error, never a wrapped value.
fn cdr_u32_len(what: &'static str, len: usize) -> Result<u32, DynamicCdrError> {
    u32::try_from(len).map_err(|_| DynamicCdrError::LengthOverflow { what, len })
}

impl std::error::Error for DynamicCdrError {}

impl From<super::xtypes_bridge::MemberIdTooWide> for DynamicCdrError {
    fn from(e: super::xtypes_bridge::MemberIdTooWide) -> Self {
        Self::InvalidData(e.to_string())
    }
}

impl From<std::string::FromUtf8Error> for DynamicCdrError {
    fn from(e: std::string::FromUtf8Error) -> Self {
        Self::Utf8Error(e)
    }
}

// ---------------------------------------------------------------------------
// Discriminator conversion helpers
// ---------------------------------------------------------------------------

/// Convert an i64 discriminator value to the `DynamicValue` variant that
/// matches the declared discriminator type. Union cases store the discriminator
/// as i64 internally; the encoder needs the correctly-typed variant so
/// `encode_value` does not hit the TypeMismatch arm.
///
/// An enum discriminator (DDS-XTypes sec. 7.5.2.11, nonBasic discriminator in IDL)
/// must become `DynamicValue::Enum` so the Enum arm in `encode_value` is
/// reached. The variant name is resolved from the descriptor when present;
/// an empty string is used as a fallback (the name is display-only and does
/// not affect CDR encoding).
fn discriminator_i64_to_dv(disc: i64, kind: &TypeKind) -> DynamicValue {
    match kind {
        TypeKind::Primitive(pk) => match pk {
            PrimitiveKind::Bool => DynamicValue::Bool(disc != 0),
            PrimitiveKind::Byte | PrimitiveKind::U8 => {
                DynamicValue::U8(u8::try_from(disc.clamp(0, i64::from(u8::MAX))).unwrap_or(0))
            }
            PrimitiveKind::U16 => {
                DynamicValue::U16(u16::try_from(disc.clamp(0, i64::from(u16::MAX))).unwrap_or(0))
            }
            PrimitiveKind::U32 => {
                DynamicValue::U32(u32::try_from(disc.clamp(0, i64::from(u32::MAX))).unwrap_or(0))
            }
            PrimitiveKind::U64 => DynamicValue::U64(u64::try_from(disc.max(0)).unwrap_or(0)),
            PrimitiveKind::I8 => DynamicValue::I8(
                i8::try_from(disc.clamp(i64::from(i8::MIN), i64::from(i8::MAX))).unwrap_or(0),
            ),
            PrimitiveKind::I16 => DynamicValue::I16(
                i16::try_from(disc.clamp(i64::from(i16::MIN), i64::from(i16::MAX))).unwrap_or(0),
            ),
            PrimitiveKind::I32 => DynamicValue::I32(
                i32::try_from(disc.clamp(i64::from(i32::MIN), i64::from(i32::MAX))).unwrap_or(0),
            ),
            PrimitiveKind::I64 => DynamicValue::I64(disc),
            _ => DynamicValue::I32(
                i32::try_from(disc.clamp(i64::from(i32::MIN), i64::from(i32::MAX))).unwrap_or(0),
            ),
        },
        TypeKind::Enum(e) => {
            // Enum discriminator: resolve the variant name for the display
            // field; the value is what the encoder serializes.
            let name = e
                .variants
                .iter()
                .find(|v| v.value == disc)
                .map(|v| v.name.clone())
                .unwrap_or_default();
            DynamicValue::Enum(disc, name)
        }
        _ => DynamicValue::I32(
            i32::try_from(disc.clamp(i64::from(i32::MIN), i64::from(i32::MAX))).unwrap_or(0),
        ),
    }
}

/// Extract an i64 discriminator from any decoded `DynamicValue` integer or
/// enum variant. Covers all integer widths and enum discriminators so case
/// lookup never silently returns 0 for U8/U16 or enum discriminator types.
fn dv_to_discriminator_i64(dv: &DynamicValue) -> i64 {
    match dv {
        DynamicValue::Bool(v) => *v as i64,
        DynamicValue::U8(v) => *v as i64,
        DynamicValue::U16(v) => *v as i64,
        DynamicValue::U32(v) => *v as i64,
        DynamicValue::U64(v) => *v as i64,
        DynamicValue::I8(v) => *v as i64,
        DynamicValue::I16(v) => *v as i64,
        DynamicValue::I32(v) => *v as i64,
        DynamicValue::I64(v) => *v,
        // Enum discriminator (nonBasic discriminator in IDL).
        DynamicValue::Enum(v, _) => *v,
        _ => 0,
    }
}

/// Produce the zero/empty default value for a type kind.
///
/// Used for XCDR1 appendable widening: when a cleanly truncated sample runs
/// out before the reader's trailing members, those members take their
/// defaults (numeric 0, false, empty string/sequence, recursive member
/// defaults for composites). Total over `TypeKind`: every kind yields its
/// closest empty representation, no error path.
fn default_value_for_kind(kind: &TypeKind) -> DynamicValue {
    match kind {
        TypeKind::Primitive(p) => match p {
            PrimitiveKind::Bool => DynamicValue::Bool(false),
            PrimitiveKind::Byte | PrimitiveKind::U8 => DynamicValue::U8(0),
            PrimitiveKind::U16 => DynamicValue::U16(0),
            PrimitiveKind::U32 => DynamicValue::U32(0),
            PrimitiveKind::U64 => DynamicValue::U64(0),
            PrimitiveKind::I8 => DynamicValue::I8(0),
            PrimitiveKind::I16 => DynamicValue::I16(0),
            PrimitiveKind::I32 => DynamicValue::I32(0),
            PrimitiveKind::I64 => DynamicValue::I64(0),
            PrimitiveKind::F32 => DynamicValue::F32(0.0),
            PrimitiveKind::F64 => DynamicValue::F64(0.0),
            PrimitiveKind::LongDouble => {
                DynamicValue::LongDouble([0u8; crate::dynamic::LONG_DOUBLE_SIZE])
            }
            PrimitiveKind::Char => DynamicValue::Char('\0'),
            PrimitiveKind::String { .. } => DynamicValue::String(String::new()),
            PrimitiveKind::WString { .. } => DynamicValue::WString(String::new()),
        },
        TypeKind::Struct(fields) => DynamicValue::Struct(
            fields
                .iter()
                .map(|f| (f.name.clone(), default_value_for_kind(&f.type_desc.kind)))
                .collect(),
        ),
        TypeKind::Sequence(_) => DynamicValue::Sequence(Vec::new()),
        TypeKind::Array(arr) => DynamicValue::Array(
            (0..arr.length)
                .map(|_| default_value_for_kind(&arr.element_type.kind))
                .collect(),
        ),
        TypeKind::Enum(e) => {
            // Default literal (defaultLiteral="true" or the first variant),
            // mirroring the try-construct UseDefault path in decoding.
            let (dv, dn) = e
                .default_variant()
                .map(|v| (v.value, v.name.clone()))
                .unwrap_or((0, String::new()));
            DynamicValue::Enum(dv, dn)
        }
        TypeKind::Union(u) => {
            // Default-constructed union: default discriminator, plus the
            // matching branch default when a case (or default case) covers
            // it; otherwise discriminator only, same no-case representation
            // the decoder uses for an unmatched discriminator.
            let disc = dv_to_discriminator_i64(&default_value_for_kind(&u.discriminator.kind));
            match u.case_by_discriminator(disc) {
                Some(case) => DynamicValue::Union(
                    disc,
                    case.name.clone(),
                    Box::new(default_value_for_kind(&case.type_desc.kind)),
                ),
                None => DynamicValue::Union(disc, String::new(), Box::new(DynamicValue::Null)),
            }
        }
        TypeKind::Nested(inner) => default_value_for_kind(&inner.kind),
    }
}

/// Select the union case matching `disc` and its wire member id.
///
/// Case selection mirrors `UnionDescriptor::case_by_discriminator` (labeled
/// cases first, then the default case). The wire member id is the one the
/// TypeObject emission in `descriptor_union_to_xtypes` assigns, from the same
/// `union_cases_with_ids`: explicit `@id`/XML id when present, else the
/// previous member's id plus one, the discriminator being member id 0
/// (DDS-XTypes v1.3 7.2.2.4.4.3, 7.3.1.2.1.1). DATA member ids MUST match the
/// TypeObject ids or mutable-union readers cannot locate the branch.
fn union_select_case(
    u: &crate::dynamic::UnionDescriptor,
    disc: i64,
) -> Result<Option<(&crate::dynamic::UnionCase, u32)>, DynamicCdrError> {
    let cases = super::xtypes_bridge::union_cases_with_ids(u)?;
    Ok(cases
        .iter()
        .find(|(c, is_default, _)| !is_default && c.labels.contains(&disc))
        .or_else(|| cases.iter().find(|(_, is_default, _)| *is_default))
        .map(|(c, _, id)| (*c, *id)))
}

/// Extent of one mutable-encoding member on the wire: member id, its
/// must-understand flag, and the byte range of its serialized value in the
/// enclosing buffer.
struct MutableMemberEntry {
    id: u32,
    must_understand: bool,
    start: usize,
    end: usize,
}

/// DDS-XTypes 1.3 7.2.2.4.4.4.6: a consumer that does not recognize a
/// member whose must-understand flag is set "must discard the entire data
/// sample" (and 7.4.1.2.1 for XCDR1). The flag of a member the reader knows
/// changes nothing: readers are robust to any setting of it.
/// `member_id` is `None` for an XCDR1 parameter that names no member (an
/// implementation extension).
fn refuse_unknown_must_understand(member_id: Option<u32>) -> DynamicCdrError {
    let what = match member_id {
        Some(id) => format!("unknown member id {id:#x}"),
        None => "unrecognized parameter".to_string(),
    };
    DynamicCdrError::InvalidData(format!("{what} marked must-understand: sample discarded"))
}

/// Encode DynamicData to CDR bytes.
///
/// For struct types the framing follows the type's extensibility and the
/// active CDR version (DDS-XTypes v1.3 section 7.4.2 / 7.4.3.2):
///   - `Final`      -> members written back-to-back with alignment padding only.
///   - `Appendable` -> XCDR1: plain CDR, identical to Final; XCDR2: 4-byte
///     DHEADER (body length LE u32) preceding the members.
///   - `Mutable`    -> XCDR1: PL_CDR parameter list terminated by
///     PID_LIST_END; XCDR2: DHEADER + EMHEADER per member.
pub fn encode_dynamic(data: &DynamicData) -> Result<Vec<u8>, DynamicCdrError> {
    // Historical default: XCDR1 primitive alignment (64/128-bit on 8/16).
    // Callers on an XCDR2 wire path (encapsulation CDR2/D_CDR2/PL_CDR2) must
    // use encode_dynamic_with_version(.., CdrVersion::Xcdr2) so 64/128-bit
    // primitives align on 4 per DDS-XTypes v1.3 section 7.4.3.3.
    encode_dynamic_with_version(data, CdrVersion::Xcdr1)
}

/// Encode DynamicData to CDR bytes with an explicit CDR encoding version.
///
/// The version governs primitive alignment: XCDR2 caps alignment at 4 bytes
/// (i64/u64/f64/long double align on 4), XCDR1 uses natural alignment.
/// Struct framing (DHEADER/EMHEADER) follows the type's extensibility in
/// both modes.
pub fn encode_dynamic_with_version(
    data: &DynamicData,
    version: CdrVersion,
) -> Result<Vec<u8>, DynamicCdrError> {
    let mut encoder = CdrEncoder::new(version);
    encoder.encode_value_ext(data.value(), data.descriptor())?;
    Ok(encoder.into_bytes())
}

/// Decode CDR bytes to DynamicData.
///
/// For struct types the decoder peels off the framing that matches the type's
/// extensibility and the active CDR version (DDS-XTypes v1.3 section 7.4.2 /
/// 7.4.3.2):
///   - `Final`      -> members read back-to-back with alignment realignment only.
///   - `Appendable` -> XCDR1: plain CDR, identical to Final; XCDR2: consumes
///     the 4-byte DHEADER then reads members.
///   - `Mutable`    -> XCDR1: walks the PL_CDR parameter list to PID_LIST_END;
///     XCDR2: reads EMHEADERs bounded by the DHEADER.
pub fn decode_dynamic(
    bytes: &[u8],
    descriptor: &Arc<TypeDescriptor>,
) -> Result<DynamicData, DynamicCdrError> {
    // Historical default: XCDR1 primitive alignment. See encode_dynamic.
    decode_dynamic_with_version(bytes, descriptor, CdrVersion::Xcdr1)
}

/// Decode CDR bytes to DynamicData with an explicit CDR encoding version.
///
/// The version governs primitive alignment: XCDR2 caps alignment at 4 bytes
/// (i64/u64/f64/long double align on 4), XCDR1 uses natural alignment.
pub fn decode_dynamic_with_version(
    bytes: &[u8],
    descriptor: &Arc<TypeDescriptor>,
    version: CdrVersion,
) -> Result<DynamicData, DynamicCdrError> {
    let mut decoder = CdrDecoder::new(bytes, version);
    let value = decoder.decode_value_ext(descriptor)?;
    DynamicData::from_value(descriptor, value)
        .map_err(|e| DynamicCdrError::InvalidData(e.to_string()))
}

/// CDR Encoder for dynamic types.
struct CdrEncoder {
    buffer: Vec<u8>,
    version: CdrVersion,
}

impl CdrEncoder {
    fn new(version: CdrVersion) -> Self {
        Self {
            buffer: Vec::new(),
            version,
        }
    }

    fn into_bytes(self) -> Vec<u8> {
        self.buffer
    }

    fn align(&mut self, alignment: usize) {
        let padding = (alignment - (self.buffer.len() % alignment)) % alignment;
        self.buffer.extend(std::iter::repeat_n(0, padding));
    }

    /// Alignment for a primitive of `natural` size under the active CDR
    /// version (XCDR2 caps at 4, DDS-XTypes v1.3 section 7.4.3.3).
    fn prim_align(&self, natural: usize) -> usize {
        primitive_alignment(natural, self.version)
    }

    /// Encode a value with explicit extensibility context for the top-level type.
    ///
    /// For `TypeKind::Struct` the extensibility and the active CDR version
    /// govern the framing (see `encode_struct`). For all other kinds `ext`
    /// is unused -- only struct extensibility matters for framing.
    fn encode_value_ext(
        &mut self,
        value: &DynamicValue,
        desc: &TypeDescriptor,
    ) -> Result<(), DynamicCdrError> {
        let ext = desc.extensibility;
        match &desc.kind {
            TypeKind::Struct(fields) => self.encode_struct(value, fields, ext, desc.autoid_hash),
            TypeKind::Union(u) => self.encode_union(value, u, ext),
            TypeKind::Nested(inner) => {
                // Nested types carry their own TypeDescriptor with extensibility.
                self.encode_value_ext(value, inner)
            }
            other => self.encode_value(value, other),
        }
    }

    fn encode_value(
        &mut self,
        value: &DynamicValue,
        kind: &TypeKind,
    ) -> Result<(), DynamicCdrError> {
        match kind {
            TypeKind::Primitive(p) => self.encode_primitive(value, *p),
            TypeKind::Struct(fields) => {
                self.encode_struct(value, fields, Extensibility::Final, false)
            }
            TypeKind::Sequence(seq) => {
                if let DynamicValue::Sequence(vec) = value {
                    // XCDR2: collections of non-primitive elements are
                    // DELIMITED - a 4-byte DHEADER (byte count of everything
                    // after it, including the length word) precedes the body.
                    let dheader_pos = if self.version == CdrVersion::Xcdr2
                        && collection_element_needs_dheader(&seq.element_type.kind)
                    {
                        self.align(4);
                        let pos = self.buffer.len();
                        self.buffer.extend(&0u32.to_le_bytes());
                        Some(pos)
                    } else {
                        None
                    };
                    let body_start = self.buffer.len();
                    // Write length
                    self.align(4);
                    let count = cdr_u32_len("sequence length", vec.len())?;
                    self.buffer.extend(&count.to_le_bytes());
                    // Write elements
                    for elem in vec {
                        self.encode_value(elem, &seq.element_type.kind)?;
                    }
                    if let Some(pos) = dheader_pos {
                        let body_len =
                            cdr_u32_len("sequence DHEADER", self.buffer.len() - body_start)?;
                        self.buffer[pos..pos + 4].copy_from_slice(&body_len.to_le_bytes());
                    }
                    Ok(())
                } else {
                    Err(DynamicCdrError::TypeMismatch {
                        expected: "sequence".into(),
                        found: format!("{:?}", value),
                    })
                }
            }
            TypeKind::Array(arr) => {
                if let DynamicValue::Array(vec) = value {
                    if vec.len() != arr.length {
                        return Err(DynamicCdrError::InvalidData(format!(
                            "Array length mismatch: expected {}, got {}",
                            arr.length,
                            vec.len()
                        )));
                    }
                    // XCDR2 delimited rule, same as Sequence (arrays carry
                    // no length word - DHEADER + elements only).
                    let dheader_pos = if self.version == CdrVersion::Xcdr2
                        && collection_element_needs_dheader(&arr.element_type.kind)
                    {
                        self.align(4);
                        let pos = self.buffer.len();
                        self.buffer.extend(&0u32.to_le_bytes());
                        Some(pos)
                    } else {
                        None
                    };
                    let body_start = self.buffer.len();
                    for elem in vec {
                        self.encode_value(elem, &arr.element_type.kind)?;
                    }
                    if let Some(pos) = dheader_pos {
                        let body_len =
                            cdr_u32_len("array DHEADER", self.buffer.len() - body_start)?;
                        self.buffer[pos..pos + 4].copy_from_slice(&body_len.to_le_bytes());
                    }
                    Ok(())
                } else {
                    Err(DynamicCdrError::TypeMismatch {
                        expected: "array".into(),
                        found: format!("{:?}", value),
                    })
                }
            }
            TypeKind::Enum(e) => {
                if let DynamicValue::Enum(val, _) = value {
                    // A value sits in its holder type (XTypes 1.3 7.4.3.5.3
                    // rules 5 and 6, Table 40): Int8/16/32 for an enum,
                    // UInt8 to UInt64 for a bitmask, by @bit_bound. The value
                    // is held as i64: the decoder widens a 32-bit word
                    // unsigned, IDL @value may be negative, so both readings
                    // are accepted and anything wider than the holder is an
                    // error rather than a wrapped literal.
                    let width = e.holder_size();
                    let overflow = || {
                        DynamicCdrError::InvalidData(format!(
                            "enum value {} does not fit a {}-byte holder",
                            val, width
                        ))
                    };
                    self.align(self.prim_align(width));
                    match width {
                        1 => {
                            let b = u8::try_from(*val)
                                .or_else(|_| i8::try_from(*val).map(|x| x.to_le_bytes()[0]))
                                .map_err(|_| overflow())?;
                            self.buffer.push(b);
                        }
                        2 => {
                            let h = u16::try_from(*val)
                                .or_else(|_| {
                                    i16::try_from(*val).map(|x| u16::from_le_bytes(x.to_le_bytes()))
                                })
                                .map_err(|_| overflow())?;
                            self.buffer.extend(&h.to_le_bytes());
                        }
                        8 => self.buffer.extend(&val.to_le_bytes()),
                        _ => {
                            let word = u32::try_from(*val)
                                .or_else(|_| {
                                    i32::try_from(*val).map(|x| u32::from_le_bytes(x.to_le_bytes()))
                                })
                                .map_err(|_| overflow())?;
                            self.buffer.extend(&word.to_le_bytes());
                        }
                    }
                    Ok(())
                } else {
                    Err(DynamicCdrError::TypeMismatch {
                        expected: "enum".into(),
                        found: format!("{:?}", value),
                    })
                }
            }
            TypeKind::Union(u) => {
                // No extensibility context here (bare TypeKind without a
                // TypeDescriptor): keep the historical FINAL framing so the
                // legacy version-less callers (ROS2 rmw, FFI) stay
                // byte-identical. Descriptor-aware callers reach unions via
                // encode_value_ext / the Nested arm which carry the ext.
                self.encode_union(value, u, Extensibility::Final)
            }
            TypeKind::Nested(inner) => {
                // Propagate the nested descriptor's extensibility.
                self.encode_value_ext(value, inner)
            }
        }
    }

    /// Encode a struct value applying the framing indicated by `ext` and the
    /// active CDR version.
    ///
    /// - `Final`      -> members written back-to-back (no framing header).
    /// - `Appendable` -> XCDR1: plain CDR, identical to Final (DDS-XTypes
    ///   v1.3 section 7.4.2); XCDR2: a 4-byte DHEADER (body length as LE
    ///   u32) then members (section 7.4.3.2 delimited encoding).
    /// - `Mutable`    -> XCDR1: PL_CDR parameter list (see
    ///   `encode_struct_mutable_plcdr1`); XCDR2: each member preceded by a
    ///   4-byte EMHEADER encoding `(M=0 | LC | member_id)` per section 7.4.3.4.2
    ///   Table 12, the list bounded by a DHEADER.
    fn encode_struct(
        &mut self,
        value: &DynamicValue,
        fields: &[FieldDescriptor],
        ext: Extensibility,
        autoid_hash: bool,
    ) -> Result<(), DynamicCdrError> {
        let map = if let DynamicValue::Struct(m) = value {
            m
        } else {
            return Err(DynamicCdrError::TypeMismatch {
                expected: "struct".into(),
                found: format!("{:?}", value),
            });
        };

        match ext {
            Extensibility::Final => {
                for field in fields {
                    let field_value = map.get(&field.name).ok_or_else(|| {
                        DynamicCdrError::InvalidData(format!("Missing field: {}", field.name))
                    })?;
                    self.encode_value_ext(field_value, &field.type_desc)?;
                }
                Ok(())
            }

            Extensibility::Appendable => {
                // XCDR1 appendable is PLAIN CDR (DDS-XTypes v1.3 section
                // 7.4.2): no DHEADER, members are encoded sequentially
                // exactly like Final. Only XCDR2 uses delimited encoding.
                if self.version == CdrVersion::Xcdr1 {
                    for field in fields {
                        let field_value = map.get(&field.name).ok_or_else(|| {
                            DynamicCdrError::InvalidData(format!("Missing field: {}", field.name))
                        })?;
                        self.encode_value_ext(field_value, &field.type_desc)?;
                    }
                    return Ok(());
                }
                // XCDR2 DHEADER: 4-byte LE u32 = length of the body following
                // the DHEADER. Write a placeholder at the current position,
                // encode members, then patch the placeholder with
                // (end_pos - body_start).
                self.align(4);
                let dheader_pos = self.buffer.len();
                // Placeholder; will be overwritten after members are encoded.
                self.buffer.extend(&0u32.to_le_bytes());
                let body_start = self.buffer.len();

                for field in fields {
                    let field_value = map.get(&field.name).ok_or_else(|| {
                        DynamicCdrError::InvalidData(format!("Missing field: {}", field.name))
                    })?;
                    self.encode_value_ext(field_value, &field.type_desc)?;
                }

                let body_len = cdr_u32_len("struct DHEADER", self.buffer.len() - body_start)?;
                // Patch DHEADER placeholder with the actual body length.
                self.buffer[dheader_pos..dheader_pos + 4].copy_from_slice(&body_len.to_le_bytes());
                Ok(())
            }

            Extensibility::Mutable => {
                // EMHEADER format per DDS-XTypes v1.3 sec. 7.4.3.4.2 Table 12 (LE):
                //
                //   Bit  [31]:    M (must-understand): set for a key member,
                //                 which always is (7.2.2.4.4.4.8), and for an
                //                 @must_understand one; 0 otherwise.
                //   Bits [30:28]: LC (length code):
                //     LC=0 -> 1-byte value  (no NEXTINT)
                //     LC=1 -> 2-byte value  (no NEXTINT)
                //     LC=2 -> 4-byte value  (no NEXTINT)
                //     LC=3 -> 8-byte value  (no NEXTINT)
                //     LC=4 -> explicit NEXTINT u32 follows with byte count
                //   Bits [27:0]:  member_id
                //
                // XCDR1 mutable is PL_CDR (DDS-XTypes v1.3 section 7.4.2):
                // a classic parameter list terminated by PID_LIST_END, not
                // the XCDR2 EMHEADER encoding below.
                if self.version == CdrVersion::Xcdr1 {
                    return self.encode_struct_mutable_plcdr1(map, fields, autoid_hash);
                }

                // XCDR2 mutable is DELIMITED (sec. 7.4.3.4): a 4-byte DHEADER
                // precedes the EMHEADER list and terminates it (no sentinel).
                self.align(4);
                let dheader_pos = self.buffer.len();
                self.buffer.extend(&0u32.to_le_bytes());
                let body_start = self.buffer.len();

                // Member ids (explicit @id, else previous + 1, or the name
                // hash) from the same function as descriptor_struct_to_xtypes,
                // so a remote decoder using the TypeObject can locate the
                // field; an id wider than 28 bits is refused there.
                let member_ids = super::xtypes_bridge::struct_member_ids(autoid_hash, fields)?;
                for (field, member_id) in fields.iter().zip(member_ids) {
                    let field_value = map.get(&field.name).ok_or_else(|| {
                        DynamicCdrError::InvalidData(format!("Missing field: {}", field.name))
                    })?;

                    // Encode the member to a temporary buffer to know its size.
                    let mut member_enc = CdrEncoder::new(self.version);
                    member_enc.encode_value_ext(field_value, &field.type_desc)?;
                    let member_bytes = member_enc.into_bytes();
                    let must_understand = field.is_key || field.is_must_understand;
                    self.emit_emheader_member(member_id, must_understand, &member_bytes)?;
                }

                // XCDR2: patch the DHEADER with the body length; the
                // DHEADER range is the terminator (no sentinel).
                let body_len = cdr_u32_len("struct DHEADER", self.buffer.len() - body_start)?;
                self.buffer[dheader_pos..dheader_pos + 4].copy_from_slice(&body_len.to_le_bytes());
                Ok(())
            }
        }
    }

    /// Encode a mutable struct as an XCDR1 PL_CDR parameter list
    /// (DDS-XTypes v1.3 section 7.4.1.2, rules (23)-(25) of section
    /// 7.4.3.5.3).
    ///
    /// Each member goes through `emit_plcdr1_member` (short or extended
    /// header, exact length, value padded so the next header is 4-aligned)
    /// with FLAG_MUST_UNDERSTAND set if and only if the member is
    /// must-understand: an `@must_understand` member, or a key member,
    /// which always is (section 7.2.2.4.4.4.8 "Key members ... shall always
    /// have their must understand attribute set to true"). PID_LIST_END
    /// terminates the list.
    ///
    /// Members are serialized into a temporary buffer first: the value
    /// always starts 4-aligned in the main stream (headers are 4-aligned),
    /// which matches the temporary buffer's offset 0, so stream-relative
    /// alignment inside the member is preserved (same technique as the
    /// XCDR2 EMHEADER branch).
    fn encode_struct_mutable_plcdr1(
        &mut self,
        map: &std::collections::HashMap<String, DynamicValue>,
        fields: &[FieldDescriptor],
        autoid_hash: bool,
    ) -> Result<(), DynamicCdrError> {
        // Same member-id mapping as the XCDR2 branch: explicit @id, else the
        // previous member's id plus one (or the name hash under
        // @autoid(HASH)).
        let member_ids = super::xtypes_bridge::struct_member_ids(autoid_hash, fields)?;
        for (field, member_id) in fields.iter().zip(member_ids) {
            let field_value = map.get(&field.name).ok_or_else(|| {
                DynamicCdrError::InvalidData(format!("Missing field: {}", field.name))
            })?;

            let mut member_enc = CdrEncoder::new(self.version);
            member_enc.encode_value_ext(field_value, &field.type_desc)?;
            let member_bytes = member_enc.into_bytes();
            let must_understand = field.is_key || field.is_must_understand;
            self.emit_plcdr1_member(member_id, must_understand, &member_bytes)?;
        }
        self.emit_plcdr1_list_end();
        Ok(())
    }

    /// Emit one XCDR1 parameter header and its serialized member (struct
    /// and union mutable paths, DDS-XTypes v1.3 section 7.4.1.2).
    ///
    /// - Short form (rule (24)) when the member id is at most 0x3F00
    ///   (section 7.4.1.2.2) and the length fits the u16 parameterLength:
    ///   parameterId = FLAG_MUST_UNDERSTAND if `must_understand` | member id.
    /// - Otherwise the extended form (rule (25), Figure 24): parameterId
    ///   PID_EXTENDED written with its own must-understand flag (0x7F01,
    ///   Table 34), slength 8, the 32-bit member header carrying the
    ///   member's FLAG_MUST_UNDERSTAND (FLAG_2, 0x4000_0000) and its 28-bit
    ///   id, then llength.
    ///
    /// Both lengths are the EXACT member length, padding excluded (section
    /// 7.4.1.2 "Unlike it is stated in [RTPS] ... the value of the
    /// parameter length is the exact length of the serialized member");
    /// the stream is then padded so the next header starts 4-aligned. A
    /// member longer than u32::MAX bytes has no PL_CDR1 representation and
    /// is refused, never truncated; member ids arrive bounded to 28 bits
    /// (`struct_member_ids`, `union_cases_with_ids`).
    fn emit_plcdr1_member(
        &mut self,
        member_id: u32,
        must_understand: bool,
        member_bytes: &[u8],
    ) -> Result<(), DynamicCdrError> {
        let len = member_bytes.len();
        let padded_len = (len + 3) & !3usize;
        self.align(4);
        // The two conversions are the short-form decision itself.
        let short_form = if member_id <= PID_SHORT_MAX_MEMBER_ID {
            u16::try_from(member_id).ok().zip(u16::try_from(len).ok())
        } else {
            None
        };
        if let Some((id_u16, len_u16)) = short_form {
            let pid = if must_understand {
                id_u16 | PID_FLAG_MUST_UNDERSTAND
            } else {
                id_u16
            };
            self.buffer.extend(&pid.to_le_bytes());
            self.buffer.extend(&len_u16.to_le_bytes());
        } else {
            let len_u32 = cdr_u32_len("PL_CDR1 member length", len)?;
            let header = if must_understand {
                member_id | EXT_FLAG_MUST_UNDERSTAND
            } else {
                member_id
            };
            self.buffer.extend(&PID_EXTENDED_WRITTEN.to_le_bytes());
            self.buffer.extend(&8u16.to_le_bytes());
            self.buffer.extend(&header.to_le_bytes());
            self.buffer.extend(&len_u32.to_le_bytes());
        }
        self.buffer.extend_from_slice(member_bytes);
        self.buffer
            .extend(std::iter::repeat_n(0u8, padded_len - len));
        Ok(())
    }

    /// Terminate an XCDR1 parameter list: PID_LIST_END written with its
    /// must-understand flag (0x7F02, Table 34), length 0.
    fn emit_plcdr1_list_end(&mut self) {
        self.align(4);
        self.buffer.extend(&PID_LIST_END_WRITTEN.to_le_bytes());
        self.buffer.extend(&0u16.to_le_bytes());
    }

    /// Encode a union value applying the framing indicated by `ext` and the
    /// active CDR version:
    ///
    /// - `Final`      -> discriminator then selected branch, no framing
    ///   (historical encoding, shared with the version-less legacy callers).
    /// - `Appendable` -> XCDR1: plain CDR, identical to Final; XCDR2: 4-byte
    ///   DHEADER (body byte count LE u32) then the Final-style body
    ///   (D_CDR2_LE: DHEADER=2 for a uint8 disc + char8 branch).
    /// - `Mutable`    -> XCDR1: PL_CDR parameter list -- discriminator as
    ///   parameterId 0x4000 (member id 0 | FLAG_MUST_UNDERSTAND), branch under
    ///   its 1-based member id, PID_LIST_END terminator; XCDR2: DHEADER +
    ///   EMHEADER list -- discriminator EMHEADER 0x8000_0000|LC (id 0, M=1),
    ///   branch EMHEADER with M=0 and its 1-based member id.
    fn encode_union(
        &mut self,
        value: &DynamicValue,
        u: &crate::dynamic::UnionDescriptor,
        ext: Extensibility,
    ) -> Result<(), DynamicCdrError> {
        let (disc, inner) = if let DynamicValue::Union(disc, _, inner) = value {
            (*disc, inner.as_ref())
        } else {
            return Err(DynamicCdrError::TypeMismatch {
                expected: "union".into(),
                found: format!("{:?}", value),
            });
        };

        match ext {
            Extensibility::Final => self.encode_union_body(disc, inner, u),
            Extensibility::Appendable => {
                // XCDR1 appendable is PLAIN CDR: identical to Final.
                if self.version == CdrVersion::Xcdr1 {
                    return self.encode_union_body(disc, inner, u);
                }
                // XCDR2 DHEADER wrap, same shape as appendable structs.
                self.align(4);
                let dheader_pos = self.buffer.len();
                self.buffer.extend(&0u32.to_le_bytes());
                let body_start = self.buffer.len();
                self.encode_union_body(disc, inner, u)?;
                let body_len = cdr_u32_len("union DHEADER", self.buffer.len() - body_start)?;
                self.buffer[dheader_pos..dheader_pos + 4].copy_from_slice(&body_len.to_le_bytes());
                Ok(())
            }
            Extensibility::Mutable => {
                if self.version == CdrVersion::Xcdr1 {
                    self.encode_union_mutable_plcdr1(disc, inner, u)
                } else {
                    self.encode_union_mutable_xcdr2(disc, inner, u)
                }
            }
        }
    }

    /// Final-style union body: discriminator then the selected branch value,
    /// no member framing. This is the historical encoding; it must stay
    /// byte-identical (legacy version-less callers and XCDR1
    /// final/appendable unions depend on it).
    fn encode_union_body(
        &mut self,
        disc: i64,
        inner: &DynamicValue,
        u: &crate::dynamic::UnionDescriptor,
    ) -> Result<(), DynamicCdrError> {
        // Convert the i64 discriminator to the DynamicValue variant
        // that matches the declared discriminator primitive kind.
        // Passing DynamicValue::I64 for a U8/U32 discriminator kind
        // hits the TypeMismatch arm in encode_primitive.
        let disc_dv = discriminator_i64_to_dv(disc, &u.discriminator.kind);
        self.encode_value(&disc_dv, &u.discriminator.kind)?;
        // Find case and write value
        if let Some(case) = u.case_by_discriminator(disc) {
            self.encode_value(inner, &case.type_desc.kind)?;
        }
        Ok(())
    }

    /// XCDR2 mutable union: DHEADER + EMHEADER parameter list.
    ///
    /// Example (disc uint32=3, branch x3 int64=123): DHEADER 0x14, EMHEADER
    /// 0xA000_0000 (M=1, LC=2, id 0) + disc, EMHEADER 0x3000_0003 (M=0,
    /// LC=3, id 3) + branch. The discriminator is member id 0 with
    /// must-understand SET; HDDS writes the branch with M=0, the layout
    /// the other XCDR2 implementations it interoperates with accept.
    fn encode_union_mutable_xcdr2(
        &mut self,
        disc: i64,
        inner: &DynamicValue,
        u: &crate::dynamic::UnionDescriptor,
    ) -> Result<(), DynamicCdrError> {
        self.align(4);
        let dheader_pos = self.buffer.len();
        self.buffer.extend(&0u32.to_le_bytes());
        let body_start = self.buffer.len();

        // Discriminator: member id 0, must-understand.
        let disc_dv = discriminator_i64_to_dv(disc, &u.discriminator.kind);
        let mut disc_enc = CdrEncoder::new(self.version);
        disc_enc.encode_value(&disc_dv, &u.discriminator.kind)?;
        let disc_bytes = disc_enc.into_bytes();
        self.emit_emheader_member(0, true, &disc_bytes)?;

        // Selected branch under its wire member id, M=0.
        if let Some((case, wire_id)) = union_select_case(u, disc)? {
            let mut member_enc = CdrEncoder::new(self.version);
            member_enc.encode_value(inner, &case.type_desc.kind)?;
            let member_bytes = member_enc.into_bytes();
            self.emit_emheader_member(wire_id, false, &member_bytes)?;
        }

        let body_len = cdr_u32_len("union DHEADER", self.buffer.len() - body_start)?;
        self.buffer[dheader_pos..dheader_pos + 4].copy_from_slice(&body_len.to_le_bytes());
        Ok(())
    }

    /// Emit one EMHEADER1 (+ NEXTINT) and the serialized member, struct and
    /// union mutable XCDR2 paths (section 7.4.3.4.2): M in bit 31, LC in
    /// bits 30-28 (0-3 for a 1/2/4/8-byte member, else 4 with NEXTINT =
    /// byte count), member id in bits 27-0. Member ids arrive bounded to 28
    /// bits (`struct_member_ids`, `union_cases_with_ids`).
    fn emit_emheader_member(
        &mut self,
        member_id: u32,
        must_understand: bool,
        member_bytes: &[u8],
    ) -> Result<(), DynamicCdrError> {
        let member_len = member_bytes.len();
        let (lc, needs_nextint) = match member_len {
            1 => (0u32, false),
            2 => (1u32, false),
            4 => (2u32, false),
            8 => (3u32, false),
            _ => (4u32, true),
        };
        self.align(4);
        let m_bit = if must_understand { 1u32 << 31 } else { 0 };
        let emheader = m_bit | (lc << 28) | member_id;
        self.buffer.extend(&emheader.to_le_bytes());
        if needs_nextint {
            let nextint = cdr_u32_len("member NEXTINT", member_len)?;
            self.buffer.extend(&nextint.to_le_bytes());
        }
        self.buffer.extend_from_slice(member_bytes);
        Ok(())
    }

    /// XCDR1 mutable union: PL_CDR parameter list.
    ///
    /// Example (uint8 disc=5, char8 branch 'A'): parameterId 0x4000
    /// (member id 0 | FLAG_MUST_UNDERSTAND) length 1 value 0x05 padded to
    /// 4; parameterId 0x0005 length 1 value 0x41 padded to 4; then
    /// PID_LIST_END with its must-understand flag, 0x7F02 (Table 34). A
    /// reader also accepts 0x3F02 (the flag is ignored on read).
    /// The declared parameterLength is the exact value size (1 for a
    /// uint8, 8 for an int64, section 7.4.1.2) while the stream itself is
    /// padded to the next 4-byte boundary. The discriminator is
    /// must-understand (section 7.2.2.4.4.4.6), the branch is written
    /// without the flag.
    ///
    /// The encapsulation id (CDR_LE 0x0001 or PL_CDR_LE 0x0003) is owned by
    /// the engine (encap_kind_for_version), and readers key the body layout
    /// off the local type extensibility, so the body here is what matters.
    fn encode_union_mutable_plcdr1(
        &mut self,
        disc: i64,
        inner: &DynamicValue,
        u: &crate::dynamic::UnionDescriptor,
    ) -> Result<(), DynamicCdrError> {
        // Discriminator: member id 0 with the must-understand flag.
        let disc_dv = discriminator_i64_to_dv(disc, &u.discriminator.kind);
        let mut disc_enc = CdrEncoder::new(self.version);
        disc_enc.encode_value(&disc_dv, &u.discriminator.kind)?;
        let disc_bytes = disc_enc.into_bytes();
        self.emit_plcdr1_member(0, true, &disc_bytes)?;

        // Selected branch under its wire member id, no flag.
        if let Some((case, wire_id)) = union_select_case(u, disc)? {
            let mut member_enc = CdrEncoder::new(self.version);
            member_enc.encode_value(inner, &case.type_desc.kind)?;
            let member_bytes = member_enc.into_bytes();
            self.emit_plcdr1_member(wire_id, false, &member_bytes)?;
        }

        self.emit_plcdr1_list_end();
        Ok(())
    }

    fn encode_primitive(
        &mut self,
        value: &DynamicValue,
        kind: PrimitiveKind,
    ) -> Result<(), DynamicCdrError> {
        match (value, kind) {
            (DynamicValue::Bool(v), PrimitiveKind::Bool) => {
                self.buffer.push(if *v { 1 } else { 0 });
            }
            // Byte (TK_BYTE) and U8 (TK_UINT8) share identical CDR encoding: 1 byte,
            // no alignment. The distinction is semantic only (type compatibility).
            (DynamicValue::U8(v), PrimitiveKind::Byte | PrimitiveKind::U8) => {
                self.buffer.push(*v);
            }
            (DynamicValue::U16(v), PrimitiveKind::U16) => {
                self.align(2);
                self.buffer.extend(&v.to_le_bytes());
            }
            (DynamicValue::U32(v), PrimitiveKind::U32) => {
                self.align(4);
                self.buffer.extend(&v.to_le_bytes());
            }
            (DynamicValue::U64(v), PrimitiveKind::U64) => {
                self.align(self.prim_align(8));
                self.buffer.extend(&v.to_le_bytes());
            }
            (DynamicValue::I8(v), PrimitiveKind::I8) => {
                self.buffer.push(*v as u8);
            }
            (DynamicValue::I16(v), PrimitiveKind::I16) => {
                self.align(2);
                self.buffer.extend(&v.to_le_bytes());
            }
            (DynamicValue::I32(v), PrimitiveKind::I32) => {
                self.align(4);
                self.buffer.extend(&v.to_le_bytes());
            }
            (DynamicValue::I64(v), PrimitiveKind::I64) => {
                self.align(self.prim_align(8));
                self.buffer.extend(&v.to_le_bytes());
            }
            (DynamicValue::F32(v), PrimitiveKind::F32) => {
                self.align(4);
                self.buffer.extend(&v.to_le_bytes());
            }
            (DynamicValue::F64(v), PrimitiveKind::F64) => {
                self.align(self.prim_align(8));
                self.buffer.extend(&v.to_le_bytes());
            }
            (DynamicValue::LongDouble(v), PrimitiveKind::LongDouble) => {
                self.align(self.prim_align(crate::dynamic::LONG_DOUBLE_ALIGN));
                self.buffer.extend(v);
            }
            (DynamicValue::Char(v), PrimitiveKind::Char) => {
                self.buffer.push(*v as u8);
            }
            (DynamicValue::String(s), PrimitiveKind::String { max_length }) => {
                if let Some(max) = max_length {
                    if s.len() > max {
                        return Err(DynamicCdrError::InvalidData("string exceeds bound".into()));
                    }
                }
                self.align(4);
                let bytes = s.as_bytes();
                // Length includes null terminator
                let len = cdr_u32_len("string length", bytes.len() + 1)?;
                self.buffer.extend(&len.to_le_bytes());
                self.buffer.extend(bytes);
                self.buffer.push(0); // Null terminator
            }
            (DynamicValue::WString(s), PrimitiveKind::WString { max_length }) => {
                if let Some(max) = max_length {
                    if s.encode_utf16().count() > max {
                        return Err(DynamicCdrError::InvalidData("wstring exceeds bound".into()));
                    }
                }
                self.align(4);
                let chars: Vec<u16> = s.encode_utf16().collect();
                // XTypes 1.3 (7.4.1.1.2): wstring length prefix counts BYTES
                // of UTF-16 payload. No trailing NUL unit, no BOM.
                let byte_len = u32::try_from(chars.len() * 2).map_err(|_| {
                    DynamicCdrError::InvalidData("wstring byte length exceeds u32".into())
                })?;
                self.buffer.extend(&byte_len.to_le_bytes());
                for c in chars {
                    self.buffer.extend(&c.to_le_bytes());
                }
            }
            _ => {
                return Err(DynamicCdrError::TypeMismatch {
                    expected: format!("{:?}", kind),
                    found: format!("{:?}", value),
                });
            }
        }
        Ok(())
    }
}

/// CDR Decoder for dynamic types.
struct CdrDecoder<'a> {
    buffer: &'a [u8],
    offset: usize,
    version: CdrVersion,
    /// Decoding a key member, or a value nested inside one. Every bound or
    /// literal violation then refuses the sample, whatever TryConstruct the
    /// member declares: DDS-XTypes v1.3 Sec.7.2.4.4.8 Table 19's Note asks
    /// that "the key of T2 can be transformed faithfully into the key of T1
    /// without aliasing or loss of information", and a key trimmed or set to
    /// its default would name another instance. With `ignore_string_bounds`
    /// / `ignore_sequence_bounds` TRUE (the default, Sec.7.6.3.4.1) a writer
    /// whose key bound exceeds the reader's matches, so this is where a
    /// longer key is refused.
    in_key: bool,
}

impl<'a> CdrDecoder<'a> {
    fn new(buffer: &'a [u8], version: CdrVersion) -> Self {
        Self {
            buffer,
            offset: 0,
            version,
            in_key: false,
        }
    }

    /// Decode one struct member. A key member is decoded with `in_key` set,
    /// so nothing inside it is trimmed nor defaulted.
    fn decode_member(&mut self, field: &FieldDescriptor) -> Result<DynamicValue, DynamicCdrError> {
        let outer = self.in_key;
        self.in_key = outer || field.is_key;
        let value = match &field.type_desc.kind {
            TypeKind::Struct(inner_fields) => self.decode_struct(
                inner_fields,
                field.type_desc.extensibility,
                field.type_desc.autoid_hash,
            ),
            other => self.decode_value_with_policy(other, field.try_construct),
        };
        self.in_key = outer;
        value
    }

    /// Decode a union discriminator under its own TryConstruct, as a key when
    /// the union is keyed by it.
    fn decode_discriminator(
        &mut self,
        u: &crate::dynamic::UnionDescriptor,
    ) -> Result<DynamicValue, DynamicCdrError> {
        let outer = self.in_key;
        self.in_key = outer || u.discriminator_is_key;
        let value =
            self.decode_value_with_policy(&u.discriminator.kind, u.discriminator_try_construct);
        self.in_key = outer;
        value
    }

    /// The TryConstruct behaviour in effect: DISCARD inside a key.
    fn effective_policy(&self, declared: TryConstructKind) -> TryConstructKind {
        if self.in_key {
            TryConstructKind::Discard
        } else {
            declared
        }
    }

    fn remaining(&self) -> usize {
        self.buffer.len().saturating_sub(self.offset)
    }

    fn align(&mut self, alignment: usize) {
        self.offset = (self.offset + alignment - 1) & !(alignment - 1);
    }

    /// Alignment for a primitive of `natural` size under the active CDR
    /// version (XCDR2 caps at 4, DDS-XTypes v1.3 section 7.4.3.3).
    fn prim_align(&self, natural: usize) -> usize {
        primitive_alignment(natural, self.version)
    }

    /// Read one XCDR1 parameter header (DDS-XTypes v1.3 section 7.4.1.2),
    /// 4-aligned. The one reader of the format: the struct, union and skip
    /// walks all go through it.
    ///
    /// - FLAG_MUST_UNDERSTAND (0x4000) does not change what the id is: "readers ... shall be robust to any
    ///   setting of the FLAG_MUST_UNDERSTAND bit and accept the parameter
    ///   nevertheless". So 0x3F02 and 0x7F02 both end the list, 0x3F01 and
    ///   0x7F01 both open an extended header (HDDS 1.4.x wrote the former,
    ///   the specification prescribes the latter).
    /// - Extended header: the member's id is the low 28 bits of the 32-bit
    ///   member header, whose FLAG_2 (must-understand) and unspecified flags
    ///   are ignored; FLAG_1 (implementation extension) names no member.
    ///   The member starts right after llength; slength is not consulted.
    /// - Any other value above 0x3F00 once 0x4000 is cleared names no
    ///   member: the reserved ids (0x3F03 PID_IGNORE, 0x3F04-0x3FFF), whose
    ///   must-understand flag is reported false, and every parameter with
    ///   FLAG_IMPL_EXTENSION (0x8000), which is not a Table 34 value and
    ///   never a member of a user type (sections 7.4.1.2.1, 7.4.1.2.2),
    ///   whose flag is reported as read.
    /// - The member's must-understand flag is returned (0x4000 of the short
    ///   form, FLAG_2 of the extended member header) so that the caller can
    ///   refuse an unknown must-understand member (7.2.2.4.4.4.6).
    fn read_plcdr1_header(&mut self) -> Result<PlCdr1Header, DynamicCdrError> {
        self.align(4);
        let hdr = self.read_bytes(4)?;
        let raw = u16::from_le_bytes([hdr[0], hdr[1]]);
        let plen = usize::from(u16::from_le_bytes([hdr[2], hdr[3]]));
        let pid = raw & !PID_FLAG_MUST_UNDERSTAND;
        if pid == PID_LIST_END {
            return Ok(PlCdr1Header::ListEnd);
        }
        if pid == PID_EXTENDED {
            let ext = self.read_bytes(8)?;
            let header = u32::from_le_bytes([ext[0], ext[1], ext[2], ext[3]]);
            let llength = u32::from_le_bytes([ext[4], ext[5], ext[6], ext[7]]);
            let member_id =
                (header & EXT_FLAG_IMPL_EXTENSION == 0).then_some(header & MEMBER_ID_MASK);
            let len = usize::try_from(llength).map_err(|_| {
                DynamicCdrError::InvalidData("PL_CDR1 llength exceeds usize".into())
            })?;
            return Ok(PlCdr1Header::Param {
                member_id,
                must_understand: header & EXT_FLAG_MUST_UNDERSTAND != 0,
                len,
            });
        }
        let id = u32::from(pid);
        // A Table 34 reserved id (0x3F03 PID_IGNORE, 0x3F04-0x3FFF) is
        // skipped whatever its flag says; any other unrecognized parameter
        // (an implementation extension included) keeps its flag. A flagged
        // reserved id (0x7F03, 0x7F04-0x7FFF) is skipped too: PID_IGNORE
        // "shall" be ignored by all consumers, and readers "shall be robust
        // to any setting of the FLAG_MUST_UNDERSTAND bit" (DDS-XTypes 1.3
        // Table 34 and the paragraph after it, section 7.4.1.2.1).
        let reserved = (u32::from(PID_LIST_END) + 1..=0x3FFF).contains(&id);
        Ok(PlCdr1Header::Param {
            member_id: (id <= PID_SHORT_MAX_MEMBER_ID).then_some(id),
            must_understand: !reserved && raw & PID_FLAG_MUST_UNDERSTAND != 0,
            len: plen,
        })
    }

    fn read_bytes(&mut self, count: usize) -> Result<&'a [u8], DynamicCdrError> {
        if self.offset + count > self.buffer.len() {
            return Err(DynamicCdrError::BufferTooSmall {
                need: count,
                have: self.remaining(),
            });
        }
        let slice = &self.buffer[self.offset..self.offset + count];
        self.offset += count;
        Ok(slice)
    }

    fn decode_value(&mut self, kind: &TypeKind) -> Result<DynamicValue, DynamicCdrError> {
        self.decode_value_with_policy(kind, TryConstructKind::UseDefault)
    }

    /// Decode a value with explicit extensibility context for the top-level type.
    ///
    /// Mirrors `encode_value_ext`: for structs, applies the version-appropriate
    /// framing based on `ext`; for nested types, reads the extensibility from
    /// the descriptor.
    fn decode_value_ext(&mut self, desc: &TypeDescriptor) -> Result<DynamicValue, DynamicCdrError> {
        let ext = desc.extensibility;
        match &desc.kind {
            TypeKind::Struct(fields) => self.decode_struct(fields, ext, desc.autoid_hash),
            TypeKind::Union(u) => self.decode_union(u, ext),
            TypeKind::Nested(inner) => self.decode_value_ext(inner),
            other => self.decode_value(other),
        }
    }

    /// Decode a struct, applying the framing indicated by `ext` and the
    /// active CDR version.
    ///
    /// - `Final`      -> reads members back-to-back with alignment only.
    /// - `Appendable` -> XCDR1: plain CDR, identical to Final; XCDR2: reads
    ///   the 4-byte DHEADER (body length), then members, advancing exactly
    ///   past the body (forward-compatibility: any unknown trailing bytes
    ///   within the DHEADER range are skipped after the known fields are
    ///   consumed).
    /// - `Mutable`    -> XCDR1: walks the PL_CDR parameter list, skipping
    ///   unknown parameter ids, until PID_LIST_END; XCDR2: reads EMHEADERs
    ///   in order, skipping unknown member IDs, bounded by the DHEADER.
    fn decode_struct(
        &mut self,
        fields: &[FieldDescriptor],
        ext: Extensibility,
        autoid_hash: bool,
    ) -> Result<DynamicValue, DynamicCdrError> {
        let mut map = std::collections::HashMap::new();

        match ext {
            Extensibility::Final => {
                for field in fields {
                    // Preserve field.try_construct for collection bound enforcement.
                    // For struct-typed fields (non-Nested) propagate the field's
                    // own extensibility so that an APPENDABLE/MUTABLE nested struct
                    // is decoded with the framing its extensibility and the active
                    // CDR version require, even inside a FINAL outer struct.
                    let value = self.decode_member(field)?;
                    map.insert(field.name.clone(), value);
                }
            }

            Extensibility::Appendable => {
                // XCDR1 appendable is PLAIN CDR: no DHEADER, members are
                // read sequentially exactly like Final.
                if self.version == CdrVersion::Xcdr1 {
                    for field in fields {
                        // Widening: without a DHEADER, a sample from a writer
                        // whose type had fewer trailing members simply runs
                        // out; the remaining members take their defaults.
                        // Checked BEFORE alignment (a cleanly truncated
                        // sample ends without the padding of the never-
                        // written next member) and only on exact exhaustion,
                        // so a nested appendable mid-stream never triggers
                        // it. A mid-member truncation still surfaces as
                        // BufferTooSmall from the member decode below.
                        if self.offset >= self.buffer.len() {
                            map.insert(
                                field.name.clone(),
                                default_value_for_kind(&field.type_desc.kind),
                            );
                            continue;
                        }
                        let value = self.decode_member(field)?;
                        map.insert(field.name.clone(), value);
                    }
                    return Ok(DynamicValue::Struct(map));
                }

                // XCDR2: read DHEADER, a 4-byte LE u32 = body byte count
                // after the header.
                self.align(4);
                let hdr_bytes = self.read_bytes(4)?;
                let body_len =
                    u32::from_le_bytes([hdr_bytes[0], hdr_bytes[1], hdr_bytes[2], hdr_bytes[3]])
                        as usize;
                let body_start = self.offset;

                for field in fields {
                    // Stop early if the buffer is exhausted within the DHEADER range
                    // (e.g., publisher used an older type with fewer members).
                    if self.offset >= body_start + body_len {
                        break;
                    }
                    // For struct-typed fields (non-Nested) propagate the field's
                    // own extensibility so that an APPENDABLE/MUTABLE nested struct
                    // is decoded with its version-appropriate framing rather than
                    // raw Final.
                    let value = self.decode_member(field)?;
                    map.insert(field.name.clone(), value);
                }

                // Skip any trailing bytes the sender appended (forward compat).
                let body_end = body_start + body_len;
                if self.offset < body_end {
                    if body_end > self.buffer.len() {
                        return Err(DynamicCdrError::BufferTooSmall {
                            need: body_end,
                            have: self.buffer.len(),
                        });
                    }
                    self.offset = body_end;
                }
            }

            Extensibility::Mutable => {
                // Build a lookup from member_id -> FieldDescriptor index for O(1)
                // dispatch. Fields with no explicit @id take the previous
                // member's id plus one, the ids descriptor_struct_to_xtypes
                // and the encoder above assign. Unknown member IDs from the
                // wire are skipped.
                let id_map: std::collections::HashMap<u32, usize> =
                    super::xtypes_bridge::struct_member_ids(autoid_hash, fields)?
                        .into_iter()
                        .zip(0usize..)
                        .collect();

                // XCDR1 mutable is PL_CDR (section 7.4.2): a classic
                // parameter list terminated by PID_LIST_END, not the XCDR2
                // EMHEADER encoding below.
                if self.version == CdrVersion::Xcdr1 {
                    self.decode_struct_mutable_plcdr1(fields, &id_map, &mut map)?;
                    return Ok(DynamicValue::Struct(map));
                }

                // XCDR2 mutable is DELIMITED (sec. 7.4.3.4): a DHEADER bounds the
                // EMHEADER list; there is no sentinel. 0x8000_0000 is a legal
                // EMHEADER1 (M=1, LC=0, member id 0: a 1-byte key at id 0)
                // and 0x3FFF_FFFF one too (LC=3, member id 0x0FFF_FFFF).
                let body_end: Option<usize> = {
                    self.align(4);
                    let hdr = self.read_bytes(4)?;
                    let body_len = u32::from_le_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]) as usize;
                    Some(self.offset.saturating_add(body_len))
                };

                loop {
                    self.align(4);
                    if let Some(end) = body_end {
                        if self.offset + 4 > end {
                            break;
                        }
                    }
                    if self.offset + 4 > self.buffer.len() {
                        break;
                    }
                    let entry = self.read_emheader_member()?;
                    match id_map.get(&entry.id) {
                        Some(field_idx) => {
                            let field = &fields[*field_idx];
                            // All members are decoded via a sub-slice decoder
                            // so that internal alignment is relative to the
                            // start of the member blob (offset 0), not to the
                            // enclosing buffer. This matches the encode path
                            // where each member is serialised in a fresh
                            // CdrEncoder.
                            let member_slice = &self.buffer[entry.start..entry.end];
                            let mut sub = CdrDecoder {
                                buffer: member_slice,
                                offset: 0,
                                version: self.version,
                                in_key: self.in_key,
                            };
                            let value = sub.decode_member(field)?;
                            map.insert(field.name.clone(), value);
                        }
                        None if entry.must_understand => {
                            return Err(refuse_unknown_must_understand(Some(entry.id)));
                        }
                        // Unknown member without M: skipped.
                        None => {}
                    }
                    self.offset = entry.end;
                }

                // Forward compat: skip any trailing bytes within the DHEADER
                // range that the loop did not consume.
                if let Some(end) = body_end {
                    if self.offset < end {
                        if end > self.buffer.len() {
                            return Err(DynamicCdrError::BufferTooSmall {
                                need: end,
                                have: self.buffer.len(),
                            });
                        }
                        self.offset = end;
                    }
                }
            }
        }

        Ok(DynamicValue::Struct(map))
    }

    /// Decode an XCDR1 PL_CDR parameter list (mutable struct) into `map`.
    ///
    /// Walks 4-aligned parameter headers (u16 parameterId LE + u16
    /// parameterLength LE, or the extended header) until PID_LIST_END,
    /// through `read_plcdr1_header`, which ignores every must-understand
    /// flag. Unknown member ids are skipped by their declared
    /// length; after a known member is decoded the offset is resynced to
    /// (value start + declared length) rather than trusting the field
    /// decoder's end position (mirrors the XCDR2 EMHEADER extent handling).
    fn decode_struct_mutable_plcdr1(
        &mut self,
        fields: &[FieldDescriptor],
        id_map: &std::collections::HashMap<u32, usize>,
        map: &mut std::collections::HashMap<String, DynamicValue>,
    ) -> Result<(), DynamicCdrError> {
        loop {
            let PlCdr1Header::Param {
                member_id,
                must_understand,
                len: value_len,
            } = self.read_plcdr1_header()?
            else {
                break;
            };

            let value_start = self.offset;
            let end = value_start.saturating_add(value_len);
            if end > self.buffer.len() {
                return Err(DynamicCdrError::BufferTooSmall {
                    need: end,
                    have: self.buffer.len(),
                });
            }

            if let Some(field_idx) = member_id.and_then(|id| id_map.get(&id)) {
                let field = &fields[*field_idx];
                // Sub-slice decoder: alignment inside the member is relative
                // to the member start, which is always 4-aligned in the main
                // stream (matches the encoder's temp-buffer serialization).
                let member_slice = &self.buffer[value_start..end];
                let mut sub = CdrDecoder {
                    buffer: member_slice,
                    offset: 0,
                    version: self.version,
                    in_key: self.in_key,
                };
                let value = sub.decode_member(field)?;
                map.insert(field.name.clone(), value);
            } else if must_understand {
                return Err(refuse_unknown_must_understand(member_id));
            }
            // Known member, or unknown one without the flag: advance past the
            // declared extent.
            self.offset = end;
        }
        Ok(())
    }

    /// Decode a union applying the framing indicated by `ext` and the active
    /// CDR version (wire shapes: see `encode_union`).
    ///
    /// - `Final`      -> discriminator then branch, no framing (historical).
    /// - `Appendable` -> XCDR1: plain CDR identical to Final; XCDR2: DHEADER
    ///   bounds the body, trailing unknown bytes are skipped (widening).
    /// - `Mutable`    -> XCDR1: PL_CDR parameter list to PID_LIST_END;
    ///   XCDR2: DHEADER-bounded EMHEADER list. Entries are collected first
    ///   and matched by member id (discriminator = id 0, branch = the id the
    ///   local TypeObject emission assigns), so member order on the wire
    ///   does not matter. An unknown member id is skipped when its
    ///   must-understand flag is clear and discards the sample when it is
    ///   set (DDS-XTypes v1.3 7.2.2.4.4.4.6; "robust to any setting" in
    ///   7.4.1.2.1 concerns the flag of a parameter the reader recognizes).
    fn decode_union(
        &mut self,
        u: &crate::dynamic::UnionDescriptor,
        ext: Extensibility,
    ) -> Result<DynamicValue, DynamicCdrError> {
        match ext {
            Extensibility::Final => self.decode_union_body(u, None),
            Extensibility::Appendable => {
                // XCDR1 appendable is PLAIN CDR: identical to Final.
                if self.version == CdrVersion::Xcdr1 {
                    return self.decode_union_body(u, None);
                }
                // XCDR2: DHEADER bounds the body.
                self.align(4);
                let hdr = self.read_bytes(4)?;
                let body_len = u32::from_le_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]) as usize;
                let body_end = self.offset.saturating_add(body_len);
                if body_end > self.buffer.len() {
                    return Err(DynamicCdrError::BufferTooSmall {
                        need: body_end,
                        have: self.buffer.len(),
                    });
                }
                let value = self.decode_union_body(u, Some(body_end))?;
                // Forward compat: skip trailing bytes a wider writer appended.
                if self.offset < body_end {
                    self.offset = body_end;
                }
                Ok(value)
            }
            Extensibility::Mutable => {
                let entries = if self.version == CdrVersion::Xcdr1 {
                    self.collect_plcdr1_member_entries()?
                } else {
                    self.collect_emheader_member_entries()?
                };
                self.decode_union_from_entries(u, &entries)
            }
        }
    }

    /// Final-style union body: discriminator then the selected branch.
    ///
    /// `body_end` (XCDR2 appendable) marks the end of the DHEADER range: a
    /// body that ends cleanly after the discriminator (writer had no branch
    /// to send) yields the matched case's default value instead of reading
    /// past the body. `None` reproduces the historical unbounded behavior
    /// byte-for-byte.
    fn decode_union_body(
        &mut self,
        u: &crate::dynamic::UnionDescriptor,
        body_end: Option<usize>,
    ) -> Result<DynamicValue, DynamicCdrError> {
        // Decode discriminator, applying its own try_construct policy for
        // unknown enum values (DDS-XTypes v1.3 sec. 7.5.1.4 discriminator
        // try_construct on the <discriminator> element).
        let disc_value = self.decode_discriminator(u)?;
        let disc = dv_to_discriminator_i64(&disc_value);

        // Find case and decode value, applying the case's try_construct.
        if let Some(case) = u.case_by_discriminator(disc) {
            if let Some(end) = body_end {
                if self.offset >= end {
                    return Ok(DynamicValue::Union(
                        disc,
                        case.name.clone(),
                        Box::new(default_value_for_kind(&case.type_desc.kind)),
                    ));
                }
            }
            let inner = self.decode_value_with_policy(&case.type_desc.kind, case.try_construct)?;
            Ok(DynamicValue::Union(
                disc,
                case.name.clone(),
                Box::new(inner),
            ))
        } else {
            // No labeled case matched the discriminator value and there is
            // no default case. This is legal for extensible unions -- the
            // subscriber simply holds the discriminator with no payload.
            Ok(DynamicValue::Union(
                disc,
                String::new(),
                Box::new(DynamicValue::Null),
            ))
        }
    }

    /// Collect the member extents of an XCDR1 PL_CDR parameter list, walking
    /// 4-aligned headers until PID_LIST_END (same wire walk as
    /// `decode_struct_mutable_plcdr1`, collected instead of dispatched so
    /// union entries can be matched by id in any order).
    fn collect_plcdr1_member_entries(
        &mut self,
    ) -> Result<Vec<MutableMemberEntry>, DynamicCdrError> {
        let mut entries = Vec::new();
        loop {
            let PlCdr1Header::Param {
                member_id,
                must_understand,
                len: value_len,
            } = self.read_plcdr1_header()?
            else {
                break;
            };
            let start = self.offset;
            let end = start.saturating_add(value_len);
            if end > self.buffer.len() {
                return Err(DynamicCdrError::BufferTooSmall {
                    need: end,
                    have: self.buffer.len(),
                });
            }
            // A parameter that names no member (implementation extension,
            // reserved id) is skipped like an unknown member, unless it
            // carries the must-understand flag (a reserved id never does).
            match member_id {
                Some(id) => entries.push(MutableMemberEntry {
                    id,
                    must_understand,
                    start,
                    end,
                }),
                None if must_understand => {
                    return Err(refuse_unknown_must_understand(None));
                }
                None => {}
            }
            // The next header re-aligns to 4 at the loop top, so an unpadded
            // declared length (exact value size, unpadded) resyncs correctly.
            self.offset = end;
        }
        Ok(entries)
    }

    /// Read one EMHEADER1 (+ NEXTINT) at the current, 4-aligned offset and
    /// return the member's extent (DDS-XTypes 1.3 section 7.4.3.4.2): the
    /// one reader of the header for the struct and union XCDR2 walks.
    ///
    /// LC 0-3: implied byte count 1/2/4/8, value follows. LC 4: NEXTINT =
    /// byte count, value follows NEXTINT. LC 5-7: NEXTINT doubles as the
    /// member's leading collection-length word; the member starts AT the
    /// NEXTINT and spans 4 + NEXTINT * 1/4/8 bytes. The offset is left
    /// where the value starts; the caller moves it to `end`.
    ///
    /// The LC table itself is
    /// `core::ser::pl_cdr2::emheader_member_extent`, shared with
    /// `decode_pl_cdr2_struct` so the rule has one copy; this method's own
    /// job is reading NEXTINT off `self` (bounds-checked, LE) and turning
    /// the extent into a `MutableMemberEntry`.
    fn read_emheader_member(&mut self) -> Result<MutableMemberEntry, DynamicCdrError> {
        let hdr_bytes = self.read_bytes(4)?;
        let emheader = u32::from_le_bytes([hdr_bytes[0], hdr_bytes[1], hdr_bytes[2], hdr_bytes[3]]);
        let must_understand = emheader & EMHEADER_FLAG_MUST_UNDERSTAND != 0;
        let lc = (emheader >> 28) & 0x07;
        let id = emheader & MEMBER_ID_MASK;
        let header_end = self.offset;

        // LC 0..=3 need no NEXTINT; LC 4..=7 do, read here (bounds-checked)
        // and handed to the shared extent function as a plain value --
        // its own `read_u32_le` callback exists for a caller indexing a
        // raw slice (`decode_pl_cdr2_struct`), not one that already has
        // the word in hand.
        let nextint = if lc >= 4 {
            let next = self.read_bytes(4)?;
            u32::from_le_bytes([next[0], next[1], next[2], next[3]])
        } else {
            0
        };
        let (start, byte_count) =
            crate::core::ser::pl_cdr2::emheader_member_extent(lc, header_end, |_| nextint);

        let end = start.saturating_add(byte_count);
        if end > self.buffer.len() {
            return Err(DynamicCdrError::BufferTooSmall {
                need: end,
                have: self.buffer.len(),
            });
        }
        Ok(MutableMemberEntry {
            id,
            must_understand,
            start,
            end,
        })
    }

    /// Collect the member extents of an XCDR2 DHEADER-bounded EMHEADER list
    /// (same extent rules as the struct mutable decoder: LC 0-3 implied
    /// sizes, LC 4 NEXTINT byte count, LC 5-7 NEXTINT doubling as the
    /// member's collection length word).
    fn collect_emheader_member_entries(
        &mut self,
    ) -> Result<Vec<MutableMemberEntry>, DynamicCdrError> {
        self.align(4);
        let hdr = self.read_bytes(4)?;
        let body_len = u32::from_le_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]) as usize;
        let body_end = self.offset.saturating_add(body_len);
        if body_end > self.buffer.len() {
            return Err(DynamicCdrError::BufferTooSmall {
                need: body_end,
                have: self.buffer.len(),
            });
        }

        let mut entries = Vec::new();
        loop {
            self.align(4);
            if self.offset + 4 > body_end {
                break;
            }
            // NO sentinel check here: the DHEADER alone bounds an XCDR2
            // parameter list, and 0x8000_0000 is EXACTLY the discriminator
            // EMHEADER of a mutable union with a 1-byte discriminator
            // (M=1, LC=0, member id 0), as encode_union_mutable_xcdr2
            // writes it.
            let entry = self.read_emheader_member()?;
            self.offset = entry.end;
            entries.push(entry);
        }

        // Snap to the DHEADER boundary (trailing unknown bytes are legal).
        if self.offset < body_end {
            self.offset = body_end;
        }
        Ok(entries)
    }

    /// Assemble a union value from collected mutable-encoding entries.
    ///
    /// The discriminator is member id 0 (must-understand on the wire, id
    /// already flag-stripped here). The branch is located by the wire member
    /// id the local type assigns to the case the discriminator selects;
    /// entries with other ids of the type are ignored, entries with ids the
    /// type does not have are skipped unless they carry the must-understand
    /// flag, which discards the sample (7.2.2.4.4.4.6). A missing
    /// branch entry (id drift between writer and reader types) degrades to
    /// the case's default value, mirroring appendable widening.
    fn decode_union_from_entries(
        &mut self,
        u: &crate::dynamic::UnionDescriptor,
        entries: &[MutableMemberEntry],
    ) -> Result<DynamicValue, DynamicCdrError> {
        // An entry neither the discriminator (id 0) nor one of the cases is
        // unknown; carrying the must-understand flag, it discards the sample.
        let cases = super::xtypes_bridge::union_cases_with_ids(u)?;
        if let Some(unknown) = entries
            .iter()
            .find(|e| e.must_understand && e.id != 0 && !cases.iter().any(|(_, _, id)| *id == e.id))
        {
            return Err(refuse_unknown_must_understand(Some(unknown.id)));
        }
        let disc_entry = entries.iter().find(|e| e.id == 0).ok_or_else(|| {
            DynamicCdrError::InvalidData("mutable union missing discriminator (member id 0)".into())
        })?;
        let mut sub = CdrDecoder {
            buffer: &self.buffer[disc_entry.start..disc_entry.end],
            offset: 0,
            version: self.version,
            in_key: self.in_key,
        };
        let disc_value = sub.decode_discriminator(u)?;
        let disc = dv_to_discriminator_i64(&disc_value);

        match union_select_case(u, disc)? {
            Some((case, wire_id)) => {
                match entries.iter().find(|e| e.id == wire_id) {
                    Some(branch) => {
                        // Sub-slice decoder: alignment inside the member is
                        // relative to the member start (matches the
                        // encoder's fresh-buffer serialization).
                        let mut sub = CdrDecoder {
                            buffer: &self.buffer[branch.start..branch.end],
                            offset: 0,
                            version: self.version,
                            in_key: self.in_key,
                        };
                        let inner =
                            sub.decode_value_with_policy(&case.type_desc.kind, case.try_construct)?;
                        Ok(DynamicValue::Union(
                            disc,
                            case.name.clone(),
                            Box::new(inner),
                        ))
                    }
                    None => Ok(DynamicValue::Union(
                        disc,
                        case.name.clone(),
                        Box::new(default_value_for_kind(&case.type_desc.kind)),
                    )),
                }
            }
            None => Ok(DynamicValue::Union(
                disc,
                String::new(),
                Box::new(DynamicValue::Null),
            )),
        }
    }

    /// Decode a value, applying `policy` when a bound violation occurs.
    ///
    /// `policy` is the try-construct annotation on the *enclosing member*
    /// (struct field or union case), not on the type itself.  It governs what
    /// to do when the incoming sequence length or string length exceeds the
    /// local bound:
    ///   - `Discard`    -> propagate an error so the whole sample is dropped.
    ///   - `Trim`       -> truncate to the local bound, accept the sample.
    ///   - `UseDefault` -> ignore the content and return an empty default value.
    ///
    /// For all other violation kinds (e.g., unknown enum value) the policy
    /// governs the same way: Discard -> error, others -> return default.
    fn decode_value_with_policy(
        &mut self,
        kind: &TypeKind,
        policy: TryConstructKind,
    ) -> Result<DynamicValue, DynamicCdrError> {
        let policy = self.effective_policy(policy);
        match kind {
            TypeKind::Primitive(p) => self.decode_primitive_with_policy(*p, policy),
            TypeKind::Struct(fields) => {
                // decode_value_with_policy is called for embedded struct fields.
                // The extensibility context is not available here so default to
                // Final (no framing header). Callers that have extensibility
                // context should use decode_value_ext instead.
                self.decode_struct(fields, Extensibility::Final, false)
            }
            TypeKind::Sequence(seq) => {
                // XCDR2 delimited collections: consume the DHEADER and use it
                // to bound the body (robust skip for Trim/UseDefault).
                let body_end: Option<usize> = if self.version == CdrVersion::Xcdr2
                    && collection_element_needs_dheader(&seq.element_type.kind)
                {
                    self.align(4);
                    let hdr = self.read_bytes(4)?;
                    let body_len = u32::from_le_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]) as usize;
                    let end = self.offset.saturating_add(body_len);
                    if end > self.buffer.len() {
                        return Err(DynamicCdrError::BufferTooSmall {
                            need: end,
                            have: self.buffer.len(),
                        });
                    }
                    Some(end)
                } else {
                    None
                };

                self.align(4);
                let bytes = self.read_bytes(4)?;
                let wire_len =
                    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;

                // A primitive element consumes at least its value width (or
                // the four-byte length for a string). Check the wire payload
                // before reserving storage from an untrusted element count.
                if let TypeKind::Primitive(element) = &seq.element_type.kind {
                    let minimum = element.size().unwrap_or(4);
                    let available = body_end
                        .unwrap_or(self.buffer.len())
                        .saturating_sub(self.offset);
                    if wire_len > available / minimum {
                        return Err(DynamicCdrError::BufferTooSmall {
                            need: wire_len.saturating_mul(minimum),
                            have: available,
                        });
                    }
                }

                // Enforce the local bound when one is present.
                let effective_len = if let Some(max) = seq.max_length {
                    if wire_len > max {
                        match policy {
                            TryConstructKind::Discard => {
                                return Err(DynamicCdrError::InvalidData(format!(
                                    "sequence length {} exceeds bound {} (tryConstruct=discard)",
                                    wire_len, max
                                )));
                            }
                            TryConstructKind::Trim => {
                                // Read and keep only `max` elements; skip the rest.
                                let mut vec = Vec::with_capacity(max);
                                for _ in 0..max {
                                    vec.push(self.decode_value(&seq.element_type.kind)?);
                                }
                                // Skip remaining elements that exceed the bound.
                                match body_end {
                                    Some(end) => self.offset = end,
                                    None => {
                                        for _ in max..wire_len {
                                            self.skip_value(&seq.element_type.kind)?;
                                        }
                                    }
                                }
                                return Ok(DynamicValue::Sequence(vec));
                            }
                            TryConstructKind::UseDefault => {
                                // Skip all incoming elements; return empty sequence.
                                match body_end {
                                    Some(end) => self.offset = end,
                                    None => {
                                        for _ in 0..wire_len {
                                            self.skip_value(&seq.element_type.kind)?;
                                        }
                                    }
                                }
                                return Ok(DynamicValue::Sequence(Vec::new()));
                            }
                        }
                    }
                    wire_len
                } else {
                    wire_len
                };

                let mut vec = Vec::with_capacity(effective_len);
                for _ in 0..effective_len {
                    vec.push(self.decode_value(&seq.element_type.kind)?);
                }
                // Forward compat: snap past any trailing bytes within the
                // DHEADER range the loop did not consume.
                if let Some(end) = body_end {
                    if self.offset < end {
                        self.offset = end;
                    }
                }
                Ok(DynamicValue::Sequence(vec))
            }
            TypeKind::Array(arr) => {
                let body_end: Option<usize> = if self.version == CdrVersion::Xcdr2
                    && collection_element_needs_dheader(&arr.element_type.kind)
                {
                    self.align(4);
                    let hdr = self.read_bytes(4)?;
                    let body_len = u32::from_le_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]) as usize;
                    let end = self.offset.saturating_add(body_len);
                    if end > self.buffer.len() {
                        return Err(DynamicCdrError::BufferTooSmall {
                            need: end,
                            have: self.buffer.len(),
                        });
                    }
                    Some(end)
                } else {
                    None
                };
                let mut vec = Vec::with_capacity(arr.length);
                for _ in 0..arr.length {
                    vec.push(self.decode_value(&arr.element_type.kind)?);
                }
                if let Some(end) = body_end {
                    if self.offset < end {
                        self.offset = end;
                    }
                }
                Ok(DynamicValue::Array(vec))
            }
            TypeKind::Enum(e) => {
                // The holder type (see the encoder): a 32-bit word reads
                // unsigned as it always has; an 8 or 16-bit enum holder is
                // signed (Int8/Int16), a bitmask holder unsigned.
                let width = e.holder_size();
                self.align(self.prim_align(width));
                let bytes = self.read_bytes(width)?;
                let val = match width {
                    1 if e.is_bitmask => i64::from(bytes[0]),
                    1 => i64::from(i8::from_le_bytes([bytes[0]])),
                    2 if e.is_bitmask => i64::from(u16::from_le_bytes([bytes[0], bytes[1]])),
                    2 => i64::from(i16::from_le_bytes([bytes[0], bytes[1]])),
                    8 => i64::from_le_bytes([
                        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6],
                        bytes[7],
                    ]),
                    _ => i64::from(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])),
                };
                if let Some(variant) = e.variant_by_value(val) {
                    Ok(DynamicValue::Enum(val, variant.name.clone()))
                } else {
                    // Incoming enum value is not present in the local type.
                    // Apply try_construct policy.
                    match policy {
                        TryConstructKind::Discard => Err(DynamicCdrError::InvalidData(format!(
                            "enum value {} not in local type (tryConstruct=discard)",
                            val
                        ))),
                        TryConstructKind::Trim | TryConstructKind::UseDefault => {
                            // Return the default literal variant (the one with
                            // defaultLiteral="true", or the first variant).
                            let (dv, dn) = e
                                .default_variant()
                                .map(|v| (v.value, v.name.clone()))
                                .unwrap_or((0, String::new()));
                            Ok(DynamicValue::Enum(dv, dn))
                        }
                    }
                }
            }
            TypeKind::Union(u) => {
                // No extensibility context here (bare TypeKind without a
                // TypeDescriptor): keep the historical FINAL framing so the
                // legacy version-less callers stay byte-identical.
                // Descriptor-aware callers reach unions via decode_value_ext /
                // the Nested arm which carry the ext.
                self.decode_union(u, Extensibility::Final)
            }
            // A named type (typedef, enum, struct or union declared apart):
            // the member's TryConstruct still governs a bounded string, a
            // sequence or an enum reached through the name. Only a
            // structure or a union needs the descriptor's extensibility.
            TypeKind::Nested(inner) => match &inner.kind {
                TypeKind::Struct(_) | TypeKind::Union(_) => self.decode_value_ext(inner),
                other => self.decode_value_with_policy(other, policy),
            },
        }
    }

    #[allow(dead_code)]
    fn decode_primitive(&mut self, kind: PrimitiveKind) -> Result<DynamicValue, DynamicCdrError> {
        self.decode_primitive_with_policy(kind, TryConstructKind::UseDefault)
    }

    /// Decode a primitive, applying `policy` for string/wstring bound violations.
    fn decode_primitive_with_policy(
        &mut self,
        kind: PrimitiveKind,
        policy: TryConstructKind,
    ) -> Result<DynamicValue, DynamicCdrError> {
        match kind {
            PrimitiveKind::Bool => {
                let bytes = self.read_bytes(1)?;
                Ok(DynamicValue::Bool(bytes[0] != 0))
            }
            // Byte (TK_BYTE) shares the same CDR encoding as U8 (TK_UINT8): a single
            // unaligned octet. Both decode to DynamicValue::U8; type compatibility is
            // enforced at the TypeIdentifier level before decoding, not here.
            PrimitiveKind::Byte | PrimitiveKind::U8 => {
                let bytes = self.read_bytes(1)?;
                Ok(DynamicValue::U8(bytes[0]))
            }
            PrimitiveKind::U16 => {
                self.align(2);
                let bytes = self.read_bytes(2)?;
                Ok(DynamicValue::U16(u16::from_le_bytes([bytes[0], bytes[1]])))
            }
            PrimitiveKind::U32 => {
                self.align(4);
                let bytes = self.read_bytes(4)?;
                Ok(DynamicValue::U32(u32::from_le_bytes([
                    bytes[0], bytes[1], bytes[2], bytes[3],
                ])))
            }
            PrimitiveKind::U64 => {
                self.align(self.prim_align(8));
                let bytes = self.read_bytes(8)?;
                Ok(DynamicValue::U64(u64::from_le_bytes([
                    bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
                ])))
            }
            PrimitiveKind::I8 => {
                let bytes = self.read_bytes(1)?;
                Ok(DynamicValue::I8(bytes[0] as i8))
            }
            PrimitiveKind::I16 => {
                self.align(2);
                let bytes = self.read_bytes(2)?;
                Ok(DynamicValue::I16(i16::from_le_bytes([bytes[0], bytes[1]])))
            }
            PrimitiveKind::I32 => {
                self.align(4);
                let bytes = self.read_bytes(4)?;
                Ok(DynamicValue::I32(i32::from_le_bytes([
                    bytes[0], bytes[1], bytes[2], bytes[3],
                ])))
            }
            PrimitiveKind::I64 => {
                self.align(self.prim_align(8));
                let bytes = self.read_bytes(8)?;
                Ok(DynamicValue::I64(i64::from_le_bytes([
                    bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
                ])))
            }
            PrimitiveKind::F32 => {
                self.align(4);
                let bytes = self.read_bytes(4)?;
                Ok(DynamicValue::F32(f32::from_le_bytes([
                    bytes[0], bytes[1], bytes[2], bytes[3],
                ])))
            }
            PrimitiveKind::F64 => {
                self.align(self.prim_align(8));
                let bytes = self.read_bytes(8)?;
                Ok(DynamicValue::F64(f64::from_le_bytes([
                    bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
                ])))
            }
            PrimitiveKind::LongDouble => {
                self.align(self.prim_align(crate::dynamic::LONG_DOUBLE_ALIGN));
                let bytes = self.read_bytes(crate::dynamic::LONG_DOUBLE_SIZE)?;
                let mut storage = [0u8; crate::dynamic::LONG_DOUBLE_SIZE];
                storage.copy_from_slice(bytes);
                Ok(DynamicValue::LongDouble(storage))
            }
            PrimitiveKind::Char => {
                let bytes = self.read_bytes(1)?;
                Ok(DynamicValue::Char(bytes[0] as char))
            }
            PrimitiveKind::String { max_length } => {
                self.align(4);
                let len_bytes = self.read_bytes(4)?;
                // wire_len includes the null terminator byte.
                let wire_len =
                    u32::from_le_bytes([len_bytes[0], len_bytes[1], len_bytes[2], len_bytes[3]])
                        as usize;

                if let Some(max) = max_length {
                    // max is in characters (not including null terminator).
                    // wire_len > max + 1 means content exceeds the local bound.
                    if wire_len > 0 && wire_len - 1 > max {
                        match policy {
                            TryConstructKind::Discard => {
                                // Read and discard the string bytes to keep the
                                // stream aligned, then propagate the error.
                                if wire_len > 0 {
                                    self.read_bytes(wire_len)?;
                                }
                                return Err(DynamicCdrError::InvalidData(format!(
                                    "string length {} exceeds bound {} (tryConstruct=discard)",
                                    wire_len - 1,
                                    max
                                )));
                            }
                            TryConstructKind::Trim => {
                                // Read the full wire content, then truncate to bound.
                                if wire_len == 0 {
                                    return Ok(DynamicValue::String(String::new()));
                                }
                                let str_bytes = self.read_bytes(wire_len)?;
                                // Strip null terminator if present.
                                let content_len = if str_bytes.last() == Some(&0) {
                                    wire_len - 1
                                } else {
                                    wire_len
                                };
                                // Trim UTF-8 content to `max` bytes (char boundary safe).
                                let s =
                                    String::from_utf8_lossy(&str_bytes[..content_len]).into_owned();
                                let trimmed = truncate_str_to_chars(&s, max);
                                return Ok(DynamicValue::String(trimmed));
                            }
                            TryConstructKind::UseDefault => {
                                // Discard the wire string, return empty.
                                if wire_len > 0 {
                                    self.read_bytes(wire_len)?;
                                }
                                return Ok(DynamicValue::String(String::new()));
                            }
                        }
                    }
                }

                if wire_len == 0 {
                    return Ok(DynamicValue::String(String::new()));
                }
                let str_bytes = self.read_bytes(wire_len)?;
                // Remove null terminator
                let actual_len = if wire_len > 0 && str_bytes[wire_len - 1] == 0 {
                    wire_len - 1
                } else {
                    wire_len
                };
                let s = String::from_utf8(str_bytes[..actual_len].to_vec())?;
                Ok(DynamicValue::String(s))
            }
            PrimitiveKind::WString { max_length } => {
                self.align(4);
                let len_bytes = self.read_bytes(4)?;
                // XTypes 1.3 (7.4.1.1.2): wstring length prefix counts BYTES
                // of UTF-16 payload (no trailing NUL unit, no BOM).
                let wire_len =
                    u32::from_le_bytes([len_bytes[0], len_bytes[1], len_bytes[2], len_bytes[3]])
                        as usize;
                // Tolerate odd byte lengths by flooring to whole UTF-16 code
                // units; the stray trailing byte is still consumed below.
                let unit_count = wire_len / 2;

                if let Some(max) = max_length {
                    if unit_count > max {
                        match policy {
                            TryConstructKind::Discard => {
                                self.read_bytes(wire_len)?;
                                return Err(DynamicCdrError::InvalidData(format!(
                                    "wstring length {} exceeds bound {} (tryConstruct=discard)",
                                    unit_count, max
                                )));
                            }
                            TryConstructKind::Trim => {
                                let payload = self.read_bytes(wire_len)?;
                                let mut chars: Vec<u16> = payload[..unit_count * 2]
                                    .chunks_exact(2)
                                    .map(|cb| u16::from_le_bytes([cb[0], cb[1]]))
                                    .collect();
                                if chars.last() == Some(&0) {
                                    chars.pop();
                                }
                                chars.truncate(max);
                                let s = String::from_utf16(&chars).map_err(|_| {
                                    DynamicCdrError::InvalidData("Invalid UTF-16".into())
                                })?;
                                return Ok(DynamicValue::WString(s));
                            }
                            TryConstructKind::UseDefault => {
                                self.read_bytes(wire_len)?;
                                return Ok(DynamicValue::WString(String::new()));
                            }
                        }
                    }
                }

                if wire_len == 0 {
                    return Ok(DynamicValue::WString(String::new()));
                }
                let payload = self.read_bytes(wire_len)?;
                let mut chars: Vec<u16> = payload[..unit_count * 2]
                    .chunks_exact(2)
                    .map(|cb| u16::from_le_bytes([cb[0], cb[1]]))
                    .collect();
                // Defensive: some legacy peers append a NUL code unit even
                // though spec senders never do. Strip at most one.
                if chars.last() == Some(&0) {
                    chars.pop();
                }
                let s = String::from_utf16(&chars)
                    .map_err(|_| DynamicCdrError::InvalidData("Invalid UTF-16".into()))?;
                Ok(DynamicValue::WString(s))
            }
        }
    }

    /// Skip a value of the given type without storing it.
    ///
    /// Used when discarding excess sequence elements during Trim processing.
    fn skip_value(&mut self, kind: &TypeKind) -> Result<(), DynamicCdrError> {
        match kind {
            TypeKind::Primitive(p) => self.skip_primitive(*p),
            TypeKind::Struct(fields) => {
                // Plain struct arm: Final extensibility assumed (no descriptor context).
                for field in fields {
                    self.skip_value(&field.type_desc.kind)?;
                }
                Ok(())
            }
            TypeKind::Sequence(seq) => {
                // XCDR2 delimited collections skip wholesale via the DHEADER.
                if self.version == CdrVersion::Xcdr2
                    && collection_element_needs_dheader(&seq.element_type.kind)
                {
                    self.align(4);
                    let hdr = self.read_bytes(4)?;
                    let body_len = u32::from_le_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]) as usize;
                    if self.offset + body_len > self.buffer.len() {
                        return Err(DynamicCdrError::BufferTooSmall {
                            need: self.offset + body_len,
                            have: self.buffer.len(),
                        });
                    }
                    self.offset += body_len;
                    return Ok(());
                }
                self.align(4);
                let bytes = self.read_bytes(4)?;
                let len = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
                for _ in 0..len {
                    self.skip_value(&seq.element_type.kind)?;
                }
                Ok(())
            }
            TypeKind::Array(arr) => {
                if self.version == CdrVersion::Xcdr2
                    && collection_element_needs_dheader(&arr.element_type.kind)
                {
                    self.align(4);
                    let hdr = self.read_bytes(4)?;
                    let body_len = u32::from_le_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]) as usize;
                    if self.offset + body_len > self.buffer.len() {
                        return Err(DynamicCdrError::BufferTooSmall {
                            need: self.offset + body_len,
                            have: self.buffer.len(),
                        });
                    }
                    self.offset += body_len;
                    return Ok(());
                }
                for _ in 0..arr.length {
                    self.skip_value(&arr.element_type.kind)?;
                }
                Ok(())
            }
            TypeKind::Enum(e) => {
                let width = e.holder_size();
                self.align(self.prim_align(width));
                self.read_bytes(width)?;
                Ok(())
            }
            TypeKind::Union(u) => {
                // Final-framing skip (discriminator + branch). Appendable and
                // mutable unions always sit behind a TypeDescriptor and are
                // skipped wholesale by the Nested arm below (DHEADER extent /
                // PL_CDR sentinel walk), which never descends here; a bare
                // TypeKind::Union without descriptor context is Final by
                // construction (legacy callers).
                let disc_value = self.decode_value(&u.discriminator.kind)?;
                let disc = dv_to_discriminator_i64(&disc_value);
                if let Some(case) = u.case_by_discriminator(disc) {
                    self.skip_value(&case.type_desc.kind)?;
                }
                Ok(())
            }
            TypeKind::Nested(inner) => {
                // For appendable nested types, the DHEADER tells us the body size:
                // use it to skip efficiently without field-by-field traversal.
                match inner.extensibility {
                    Extensibility::Final => self.skip_value(&inner.kind),
                    Extensibility::Appendable => {
                        // XCDR1 appendable is plain CDR: skip members
                        // field-by-field exactly like Final.
                        if self.version == CdrVersion::Xcdr1 {
                            return self.skip_value(&inner.kind);
                        }
                        self.align(4);
                        let hdr = self.read_bytes(4)?;
                        let body_len =
                            u32::from_le_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]) as usize;
                        if self.offset + body_len > self.buffer.len() {
                            return Err(DynamicCdrError::BufferTooSmall {
                                need: self.offset + body_len,
                                have: self.buffer.len(),
                            });
                        }
                        self.offset += body_len;
                        Ok(())
                    }
                    Extensibility::Mutable => {
                        if self.version == CdrVersion::Xcdr2 {
                            // XCDR2 mutable is delimited: the DHEADER gives the
                            // exact body size, skip it wholesale.
                            self.align(4);
                            let hdr = self.read_bytes(4)?;
                            let body_len =
                                u32::from_le_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]) as usize;
                            if self.offset + body_len > self.buffer.len() {
                                return Err(DynamicCdrError::BufferTooSmall {
                                    need: self.offset + body_len,
                                    have: self.buffer.len(),
                                });
                            }
                            self.offset += body_len;
                            return Ok(());
                        }
                        // XCDR1 PL_CDR: walk parameter headers to
                        // PID_LIST_END. A declared length is exact (padding
                        // excluded); the next header re-aligns to 4.
                        while let PlCdr1Header::Param { len: skip_len, .. } =
                            self.read_plcdr1_header()?
                        {
                            let end = self.offset.saturating_add(skip_len);
                            if end > self.buffer.len() {
                                return Err(DynamicCdrError::BufferTooSmall {
                                    need: end,
                                    have: self.buffer.len(),
                                });
                            }
                            self.offset = end;
                        }
                        Ok(())
                    }
                }
            }
        }
    }

    /// Skip a primitive value without storing it.
    fn skip_primitive(&mut self, kind: PrimitiveKind) -> Result<(), DynamicCdrError> {
        match kind {
            PrimitiveKind::Bool
            | PrimitiveKind::Byte
            | PrimitiveKind::U8
            | PrimitiveKind::I8
            | PrimitiveKind::Char => {
                self.read_bytes(1)?;
            }
            PrimitiveKind::U16 | PrimitiveKind::I16 => {
                self.align(2);
                self.read_bytes(2)?;
            }
            PrimitiveKind::U32 | PrimitiveKind::I32 | PrimitiveKind::F32 => {
                self.align(4);
                self.read_bytes(4)?;
            }
            PrimitiveKind::String { .. } => {
                // CDR string: 4-byte length (includes null terminator) + bytes.
                self.align(4);
                let len_bytes = self.read_bytes(4)?;
                let len =
                    u32::from_le_bytes([len_bytes[0], len_bytes[1], len_bytes[2], len_bytes[3]])
                        as usize;
                self.read_bytes(len)?;
            }
            PrimitiveKind::WString { .. } => {
                // XTypes 1.3 wstring: 4-byte BYTE length (no trailing NUL,
                // no BOM) + that many bytes of UTF-16 payload.
                self.align(4);
                let len_bytes = self.read_bytes(4)?;
                let len =
                    u32::from_le_bytes([len_bytes[0], len_bytes[1], len_bytes[2], len_bytes[3]])
                        as usize;
                self.read_bytes(len)?;
            }
            PrimitiveKind::U64 | PrimitiveKind::I64 | PrimitiveKind::F64 => {
                self.align(self.prim_align(8));
                self.read_bytes(8)?;
            }
            PrimitiveKind::LongDouble => {
                self.align(self.prim_align(crate::dynamic::LONG_DOUBLE_ALIGN));
                self.read_bytes(crate::dynamic::LONG_DOUBLE_SIZE)?;
            }
        }
        Ok(())
    }
}

/// Truncate a UTF-8 string to at most `max` Unicode scalar values.
///
/// The boundary is always on a valid UTF-8 character boundary.
fn truncate_str_to_chars(s: &str, max: usize) -> String {
    s.char_indices()
        .nth(max)
        .map(|(byte_pos, _)| s[..byte_pos].to_string())
        .unwrap_or_else(|| s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn primitive_sequence_count_cannot_exceed_wire_payload() {
        let descriptor = Arc::new(
            crate::dynamic::TypeDescriptorBuilder::new("Sequence")
                .sequence_field("values", PrimitiveKind::U8)
                .build()
                .with_extensibility(Extensibility::Final),
        );
        for version in [CdrVersion::Xcdr1, CdrVersion::Xcdr2] {
            assert!(matches!(
                decode_dynamic_with_version(&[0xff; 4], &descriptor, version),
                Err(DynamicCdrError::BufferTooSmall { .. })
            ));
            let bytes = [2, 0, 0, 0, 10, 20];
            let decoded = decode_dynamic_with_version(&bytes, &descriptor, version).unwrap();
            assert_eq!(
                encode_dynamic_with_version(&decoded, version).unwrap(),
                bytes
            );
        }
    }
    use crate::dynamic::TypeDescriptorBuilder;

    #[test]
    fn test_encode_decode_primitives() {
        let desc = Arc::new(
            TypeDescriptorBuilder::new("Primitives")
                .field("b", PrimitiveKind::Bool)
                .field("u8", PrimitiveKind::U8)
                .field("u32", PrimitiveKind::U32)
                .field("f64", PrimitiveKind::F64)
                .build(),
        );

        let mut data = DynamicData::new(&desc);
        data.set("b", true).unwrap();
        data.set("u8", 42u8).unwrap();
        data.set("u32", 12345u32).unwrap();
        data.set("f64", std::f64::consts::E).unwrap();

        let encoded = encode_dynamic(&data).expect("encode");
        let decoded = decode_dynamic(&encoded, &desc).expect("decode");

        assert!(decoded.get::<bool>("b").unwrap());
        assert_eq!(decoded.get::<u8>("u8").unwrap(), 42);
        assert_eq!(decoded.get::<u32>("u32").unwrap(), 12345);
        assert!((decoded.get::<f64>("f64").unwrap() - std::f64::consts::E).abs() < 1e-10);
    }

    #[test]
    fn test_encode_decode_string() {
        let desc = Arc::new(
            TypeDescriptorBuilder::new("Message")
                .string_field("text")
                .build(),
        );

        let mut data = DynamicData::new(&desc);
        data.set("text", "Hello, DDS!").unwrap();

        let encoded = encode_dynamic(&data).expect("encode");
        let decoded = decode_dynamic(&encoded, &desc).expect("decode");

        assert_eq!(decoded.get::<String>("text").unwrap(), "Hello, DDS!");
    }

    #[test]
    fn test_encode_decode_sequence() {
        let desc = Arc::new(
            TypeDescriptorBuilder::new("DataPacket")
                .field("id", PrimitiveKind::U32)
                .sequence_field("data", PrimitiveKind::U8)
                .build(),
        );

        let mut data = DynamicData::new(&desc);
        data.set("id", 100u32).unwrap();

        // Set sequence manually
        if let DynamicValue::Struct(ref mut fields) = data.value_mut() {
            fields.insert(
                "data".to_string(),
                DynamicValue::Sequence(vec![
                    DynamicValue::U8(1),
                    DynamicValue::U8(2),
                    DynamicValue::U8(3),
                    DynamicValue::U8(4),
                ]),
            );
        }

        let encoded = encode_dynamic(&data).expect("encode");
        let decoded = decode_dynamic(&encoded, &desc).expect("decode");

        assert_eq!(decoded.get::<u32>("id").unwrap(), 100);
        let seq = decoded.get_field("data").unwrap();
        assert_eq!(seq.as_sequence().unwrap().len(), 4);
    }

    #[test]
    fn test_encode_decode_nested() {
        let point_desc = Arc::new(
            TypeDescriptorBuilder::new("Point")
                .field("x", PrimitiveKind::I32)
                .field("y", PrimitiveKind::I32)
                .build(),
        );

        let rect_desc = Arc::new(
            TypeDescriptorBuilder::new("Rectangle")
                .nested_field("origin", point_desc.clone())
                .field("width", PrimitiveKind::U32)
                .field("height", PrimitiveKind::U32)
                .build(),
        );

        let mut data = DynamicData::new(&rect_desc);
        data.set("width", 100u32).unwrap();
        data.set("height", 50u32).unwrap();

        // Set nested struct
        if let DynamicValue::Struct(ref mut fields) = data.value_mut() {
            let mut origin = std::collections::HashMap::new();
            origin.insert("x".to_string(), DynamicValue::I32(10));
            origin.insert("y".to_string(), DynamicValue::I32(20));
            fields.insert("origin".to_string(), DynamicValue::Struct(origin));
        }

        let encoded = encode_dynamic(&data).expect("encode");
        let decoded = decode_dynamic(&encoded, &rect_desc).expect("decode");

        assert_eq!(decoded.get::<u32>("width").unwrap(), 100);
        assert_eq!(decoded.get::<u32>("height").unwrap(), 50);

        let origin = decoded.get_field("origin").unwrap();
        assert_eq!(origin.get_field("x").and_then(|v| v.as_i32()), Some(10));
        assert_eq!(origin.get_field("y").and_then(|v| v.as_i32()), Some(20));
    }

    // -----------------------------------------------------------------------
    // XCDR2 framing tests: DHEADER (appendable) and EMHEADER (mutable)
    // -----------------------------------------------------------------------

    /// Build an appendable struct descriptor with two i32 fields.
    fn make_appendable_desc() -> Arc<TypeDescriptor> {
        Arc::new(
            TypeDescriptor::struct_type(
                "AppendablePoint",
                vec![
                    FieldDescriptor::new(
                        "x",
                        Arc::new(TypeDescriptor::primitive("", PrimitiveKind::I32)),
                    ),
                    FieldDescriptor::new(
                        "y",
                        Arc::new(TypeDescriptor::primitive("", PrimitiveKind::I32)),
                    ),
                ],
            )
            .with_extensibility(Extensibility::Appendable),
        )
    }

    /// Build a mutable struct descriptor with two i32 fields carrying member IDs.
    fn make_mutable_desc() -> Arc<TypeDescriptor> {
        Arc::new(
            TypeDescriptor::struct_type(
                "MutablePoint",
                vec![
                    FieldDescriptor::new(
                        "x",
                        Arc::new(TypeDescriptor::primitive("", PrimitiveKind::I32)),
                    )
                    .with_id(1),
                    FieldDescriptor::new(
                        "y",
                        Arc::new(TypeDescriptor::primitive("", PrimitiveKind::I32)),
                    )
                    .with_id(2),
                ],
            )
            .with_extensibility(Extensibility::Mutable),
        )
    }

    #[test]
    fn test_encode_appendable_struct_emits_dheader() {
        // DHEADER framing for appendable is an XCDR2 behavior; XCDR1
        // appendable is plain CDR (test_xcdr1_appendable_has_no_dheader).
        let desc = make_appendable_desc();
        let mut data = DynamicData::new(&desc);
        data.set("x", 10i32).unwrap();
        data.set("y", 20i32).unwrap();

        let encoded = encode_dynamic_with_version(&data, CdrVersion::Xcdr2).expect("encode");

        // Wire layout: [DHEADER u32 LE = 8] [x i32 LE = 10] [y i32 LE = 20]
        // Total: 12 bytes.
        assert_eq!(
            encoded.len(),
            12,
            "appendable struct must have 4-byte DHEADER + 2 * 4-byte members"
        );

        // DHEADER = body length = 8 (two i32 members, no padding between them).
        let dheader = u32::from_le_bytes(encoded[0..4].try_into().unwrap());
        assert_eq!(
            dheader, 8,
            "DHEADER must equal body length (8 bytes for two i32 members)"
        );

        // Members follow the DHEADER.
        let x = i32::from_le_bytes(encoded[4..8].try_into().unwrap());
        let y = i32::from_le_bytes(encoded[8..12].try_into().unwrap());
        assert_eq!(x, 10);
        assert_eq!(y, 20);
    }

    #[test]
    fn test_decode_appendable_struct_consumes_dheader() {
        // XCDR2 wire (XCDR1 appendable has no DHEADER).
        let desc = make_appendable_desc();

        // Construct wire bytes manually: DHEADER=8, x=42, y=-7.
        let mut wire: Vec<u8> = Vec::new();
        wire.extend(&8u32.to_le_bytes()); // DHEADER
        wire.extend(&42i32.to_le_bytes()); // x
        wire.extend(&(-7i32).to_le_bytes()); // y

        let decoded = decode_dynamic_with_version(&wire, &desc, CdrVersion::Xcdr2).expect("decode");
        assert_eq!(decoded.get::<i32>("x").unwrap(), 42);
        assert_eq!(decoded.get::<i32>("y").unwrap(), -7);

        // Round-trip: encode then decode.
        let mut data = DynamicData::new(&desc);
        data.set("x", 99i32).unwrap();
        data.set("y", -1i32).unwrap();
        let encoded = encode_dynamic_with_version(&data, CdrVersion::Xcdr2).expect("encode");
        let rt =
            decode_dynamic_with_version(&encoded, &desc, CdrVersion::Xcdr2).expect("roundtrip");
        assert_eq!(rt.get::<i32>("x").unwrap(), 99);
        assert_eq!(rt.get::<i32>("y").unwrap(), -1);
    }

    #[test]
    fn test_encode_mutable_struct_xcdr1_emits_pl_cdr1_param_list() {
        // XCDR1 mutable = PL_CDR parameter list (DDS-XTypes v1.3 section
        // 7.4.2): u16 parameterId + u16 parameterLength per member, then
        // the value padded to 4; PID_LIST_END written with its
        // must-understand flag (0x7F02, Table 34, length 0) terminates.
        let desc = make_mutable_desc();
        let mut data = DynamicData::new(&desc);
        data.set("x", 5i32).unwrap();
        data.set("y", 7i32).unwrap();

        let encoded = encode_dynamic(&data).expect("encode");

        // Wire layout for two i32 members + sentinel:
        //   [pid=1 u16][len=4 u16][x i32]
        //   [pid=2 u16][len=4 u16][y i32]
        //   [pid=0x7F02 u16][len=0 u16]
        // Total: 2 * (4 + 4) + 4 = 20 bytes.
        assert_eq!(
            encoded.len(),
            20,
            "mutable struct must emit 2 param headers + 2 members + sentinel"
        );

        assert_eq!(u16::from_le_bytes(encoded[0..2].try_into().unwrap()), 1);
        assert_eq!(u16::from_le_bytes(encoded[2..4].try_into().unwrap()), 4);
        assert_eq!(i32::from_le_bytes(encoded[4..8].try_into().unwrap()), 5);

        assert_eq!(u16::from_le_bytes(encoded[8..10].try_into().unwrap()), 2);
        assert_eq!(u16::from_le_bytes(encoded[10..12].try_into().unwrap()), 4);
        assert_eq!(i32::from_le_bytes(encoded[12..16].try_into().unwrap()), 7);

        assert_eq!(
            u16::from_le_bytes(encoded[16..18].try_into().unwrap()),
            0x7F02,
            "list must terminate with PID_LIST_END | FLAG_MUST_UNDERSTAND"
        );
        assert_eq!(u16::from_le_bytes(encoded[18..20].try_into().unwrap()), 0);
    }

    #[test]
    fn test_decode_mutable_struct_xcdr1_consumes_pl_cdr1_params() {
        let desc = make_mutable_desc();

        // Construct PL_CDR1 wire bytes manually.
        let mut wire: Vec<u8> = Vec::new();
        wire.extend(&1u16.to_le_bytes()); // pid x
        wire.extend(&4u16.to_le_bytes()); // len
        wire.extend(&11i32.to_le_bytes()); // x
        wire.extend(&2u16.to_le_bytes()); // pid y
        wire.extend(&4u16.to_le_bytes()); // len
        wire.extend(&22i32.to_le_bytes()); // y
        wire.extend(&0x3F02u16.to_le_bytes()); // PID_LIST_END as HDDS 1.4.x wrote it
        wire.extend(&0u16.to_le_bytes());

        let decoded = decode_dynamic(&wire, &desc).expect("decode");
        assert_eq!(decoded.get::<i32>("x").unwrap(), 11);
        assert_eq!(decoded.get::<i32>("y").unwrap(), 22);

        // Round-trip: encode then decode.
        let mut data = DynamicData::new(&desc);
        data.set("x", 100i32).unwrap();
        data.set("y", 200i32).unwrap();
        let encoded = encode_dynamic(&data).expect("encode");
        let rt = decode_dynamic(&encoded, &desc).expect("decode roundtrip");
        assert_eq!(rt.get::<i32>("x").unwrap(), 100);
        assert_eq!(rt.get::<i32>("y").unwrap(), 200);
    }

    // -----------------------------------------------------------------------
    // XCDR2 primitive alignment tests (DDS-XTypes v1.3 section 7.4.3.3):
    // 8- and 16-byte primitives align on 4 under XCDR2, natural under XCDR1.
    // -----------------------------------------------------------------------

    /// Final struct { u8 b; f64 v; } -- the alignment of v differs per version.
    fn make_byte_then_f64_desc() -> Arc<TypeDescriptor> {
        Arc::new(
            TypeDescriptor::struct_type(
                "ByteThenF64",
                vec![
                    FieldDescriptor::new(
                        "b",
                        Arc::new(TypeDescriptor::primitive("", PrimitiveKind::U8)),
                    ),
                    FieldDescriptor::new(
                        "v",
                        Arc::new(TypeDescriptor::primitive("", PrimitiveKind::F64)),
                    ),
                ],
            )
            .with_extensibility(Extensibility::Final),
        )
    }

    #[test]
    fn test_xcdr2_f64_aligns_on_4() {
        let desc = make_byte_then_f64_desc();
        let mut data = DynamicData::new(&desc);
        data.set("b", 1u8).unwrap();
        data.set("v", 1.5f64).unwrap();

        // XCDR2: b at 0, 3 pad bytes, v at offset 4 -> 12 bytes total.
        let x2 = encode_dynamic_with_version(&data, CdrVersion::Xcdr2).expect("encode xcdr2");
        assert_eq!(x2.len(), 12, "XCDR2 must align f64 on 4 (1 + 3 pad + 8)");
        let v = f64::from_le_bytes(x2[4..12].try_into().unwrap());
        assert_eq!(v, 1.5);

        // XCDR1: b at 0, 7 pad bytes, v at offset 8 -> 16 bytes total.
        let x1 = encode_dynamic_with_version(&data, CdrVersion::Xcdr1).expect("encode xcdr1");
        assert_eq!(x1.len(), 16, "XCDR1 must align f64 on 8 (1 + 7 pad + 8)");
        let v1 = f64::from_le_bytes(x1[8..16].try_into().unwrap());
        assert_eq!(v1, 1.5);

        // Round-trips at matching versions.
        let rt2 = decode_dynamic_with_version(&x2, &desc, CdrVersion::Xcdr2).expect("decode");
        assert_eq!(rt2.get::<f64>("v").unwrap(), 1.5);
        let rt1 = decode_dynamic_with_version(&x1, &desc, CdrVersion::Xcdr1).expect("decode");
        assert_eq!(rt1.get::<f64>("v").unwrap(), 1.5);
    }

    #[test]
    fn test_xcdr2_i64_u64_longdouble_align_on_4() {
        let desc = Arc::new(
            TypeDescriptor::struct_type(
                "Wide",
                vec![
                    FieldDescriptor::new(
                        "b",
                        Arc::new(TypeDescriptor::primitive("", PrimitiveKind::U8)),
                    ),
                    FieldDescriptor::new(
                        "i",
                        Arc::new(TypeDescriptor::primitive("", PrimitiveKind::I64)),
                    ),
                    FieldDescriptor::new(
                        "u",
                        Arc::new(TypeDescriptor::primitive("", PrimitiveKind::U64)),
                    ),
                    FieldDescriptor::new(
                        "c",
                        Arc::new(TypeDescriptor::primitive("", PrimitiveKind::Char)),
                    ),
                    FieldDescriptor::new(
                        "ld",
                        Arc::new(TypeDescriptor::primitive("", PrimitiveKind::LongDouble)),
                    ),
                ],
            )
            .with_extensibility(Extensibility::Final),
        );

        let mut data = DynamicData::new(&desc);
        data.set("b", 7u8).unwrap();
        data.set("i", -5i64).unwrap();
        data.set("u", 9u64).unwrap();
        data.set("c", 'z').unwrap();
        if let DynamicValue::Struct(ref mut fields) = data.value_mut() {
            let mut ld = [0u8; crate::dynamic::LONG_DOUBLE_SIZE];
            ld[0] = 0xAB;
            fields.insert("ld".to_string(), DynamicValue::LongDouble(ld));
        }

        // XCDR2 layout: b@0, pad 3, i@4..12, u@12..20, c@20, pad 3, ld@24.
        let x2 = encode_dynamic_with_version(&data, CdrVersion::Xcdr2).expect("encode xcdr2");
        assert_eq!(x2.len(), 24 + crate::dynamic::LONG_DOUBLE_SIZE);
        assert_eq!(i64::from_le_bytes(x2[4..12].try_into().unwrap()), -5);
        assert_eq!(u64::from_le_bytes(x2[12..20].try_into().unwrap()), 9);
        assert_eq!(x2[20], b'z');
        assert_eq!(x2[24], 0xAB);

        // Round-trip at XCDR2.
        let rt = decode_dynamic_with_version(&x2, &desc, CdrVersion::Xcdr2).expect("decode");
        assert_eq!(rt.get::<i64>("i").unwrap(), -5);
        assert_eq!(rt.get::<u64>("u").unwrap(), 9);
    }

    /// Body bytes from a hex string, whitespace ignored.
    fn hex_body(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
            .collect()
    }

    fn prim(kind: PrimitiveKind) -> Arc<TypeDescriptor> {
        Arc::new(TypeDescriptor::primitive("", kind))
    }

    fn seq_of_i64() -> Arc<TypeDescriptor> {
        Arc::new(TypeDescriptor::new(
            "",
            TypeKind::Sequence(crate::dynamic::SequenceDescriptor::unbounded(prim(
                PrimitiveKind::I64,
            ))),
        ))
    }

    /// Encodes `value` of `desc` at both versions, compares each body with the
    /// one Eclipse Cyclone DDS 0.11.0 serializes for the same @final IDL type
    /// and value (`ddsi_serdata_to_ser` on a writer whose DataRepresentation is
    /// XCDR1 or XCDR2, encapsulation header and trailing alignment padding
    /// removed; Cyclone's XCDR1 alignment gaps are zero in these three types),
    /// and reads each back.
    fn pin_both_versions(
        desc: &Arc<TypeDescriptor>,
        value: DynamicValue,
        xcdr2: &str,
        xcdr1: &str,
    ) {
        let data = DynamicData::from_value(desc, value).expect("value fits type");
        for (version, expected) in [(CdrVersion::Xcdr2, xcdr2), (CdrVersion::Xcdr1, xcdr1)] {
            let expected = hex_body(expected);
            let wire = encode_dynamic_with_version(&data, version).expect("encode");
            assert_eq!(wire, expected, "{version:?} body of {}", desc.name);
            let back = decode_dynamic_with_version(&wire, desc, version).expect("decode");
            assert_eq!(
                encode_dynamic_with_version(&back, version).expect("re-encode"),
                expected,
                "{version:?} round trip of {}",
                desc.name
            );
        }
    }

    /// `@final struct Inner { octet t; long long v; };`
    /// `@final struct Nested { octet h; Inner in_; };`, h = 0x55, t = 0x66,
    /// v = 7. Cyclone: XCDR2 `0007 0000 556600000700000000000000`, XCDR1
    /// `0001 0000 55660000000000000700000000000000`. A nested @final struct
    /// carries no DHEADER; its i64 lands at 4 under XCDR2 and 8 under XCDR1.
    #[test]
    fn nested_struct_i64_matches_a_foreign_toolchain_at_both_versions() {
        let inner = Arc::new(
            TypeDescriptor::struct_type(
                "Inner",
                vec![
                    FieldDescriptor::new("t", prim(PrimitiveKind::U8)),
                    FieldDescriptor::new("v", prim(PrimitiveKind::I64)),
                ],
            )
            .with_extensibility(Extensibility::Final),
        );
        let outer = Arc::new(
            TypeDescriptor::struct_type(
                "Nested",
                vec![
                    FieldDescriptor::new("h", prim(PrimitiveKind::U8)),
                    FieldDescriptor::new("in_", Arc::clone(&inner)),
                ],
            )
            .with_extensibility(Extensibility::Final),
        );
        let mut in_value = DynamicData::new(&inner);
        in_value.set("t", 0x66u8).unwrap();
        in_value.set("v", 7i64).unwrap();
        let mut value = DynamicData::new(&outer);
        value.set("h", 0x55u8).unwrap();
        if let DynamicValue::Struct(fields) = value.value_mut() {
            fields.insert("in_".to_string(), in_value.into_value());
        }
        pin_both_versions(
            &outer,
            value.into_value(),
            "5566 0000 0700000000000000",
            "5566 000000000000 0700000000000000",
        );
    }

    /// `@final struct SeqOnly { sequence<long long> v; };`, v = [1, -1].
    /// Cyclone: XCDR2 `0007 0000 02000000 0100000000000000 ffffffffffffffff`,
    /// XCDR1 `0001 0000 02000000 00000000 0100000000000000 ffffffffffffffff`.
    /// The elements follow the length at 4 under XCDR2 and at 8 under XCDR1.
    #[test]
    fn sequence_of_i64_matches_a_foreign_toolchain_at_both_versions() {
        let desc = Arc::new(
            TypeDescriptor::struct_type("SeqOnly", vec![FieldDescriptor::new("v", seq_of_i64())])
                .with_extensibility(Extensibility::Final),
        );
        let mut value = DynamicData::new(&desc);
        if let DynamicValue::Struct(fields) = value.value_mut() {
            fields.insert(
                "v".to_string(),
                DynamicValue::Sequence(vec![DynamicValue::I64(1), DynamicValue::I64(-1)]),
            );
        }
        pin_both_versions(
            &desc,
            value.into_value(),
            "02000000 0100000000000000 ffffffffffffffff",
            "02000000 00000000 0100000000000000 ffffffffffffffff",
        );
    }

    /// `@final struct SeqI64 { octet h; sequence<long long> v; };`, h = 0x77,
    /// v = [1, -1]. Cyclone, both versions: `77000000 02000000
    /// 0100000000000000 ffffffffffffffff` (the elements start at 8, aligned
    /// under either rule).
    #[test]
    fn sequence_of_i64_after_an_octet_matches_a_foreign_toolchain() {
        let desc = Arc::new(
            TypeDescriptor::struct_type(
                "SeqI64",
                vec![
                    FieldDescriptor::new("h", prim(PrimitiveKind::U8)),
                    FieldDescriptor::new("v", seq_of_i64()),
                ],
            )
            .with_extensibility(Extensibility::Final),
        );
        let mut value = DynamicData::new(&desc);
        value.set("h", 0x77u8).unwrap();
        if let DynamicValue::Struct(fields) = value.value_mut() {
            fields.insert(
                "v".to_string(),
                DynamicValue::Sequence(vec![DynamicValue::I64(1), DynamicValue::I64(-1)]),
            );
        }
        let body = "77000000 02000000 0100000000000000 ffffffffffffffff";
        pin_both_versions(&desc, value.into_value(), body, body);
    }

    // The pinned layout holds a 16-byte long double; on Windows it is 8 bytes
    // (LONG_DOUBLE_SIZE), so these bytes do not describe that target.
    #[cfg(not(target_os = "windows"))]
    #[test]
    fn test_xcdr2_primitives_struct_final_pins_x12_offset_and_bytes() {
        // Mirrors the OMG dds-xtypes suite layout byte-for-byte (types/idl/
        // primitives.idl struct_primitives_final, members x1..x12) to pin
        // the XCDR2 byte offset of the float128 member. This is a regression
        // guard for the connext DATA_NOT_CORRECT float128 divergence
        // (xtypes_v2_struct_test_suite_primitives_struct_{final,appendable,
        // mutable}, hdds-pub -> connext-sub): the actual bug was in the app
        // driver's decimal-literal-to-binary128 conversion (wrong VALUE),
        // not struct layout (x13/x14 already decoded correctly on the wire
        // capture, proving the codec's alignment was never at fault) -- this
        // test locks that side down too so a future alignment change cannot
        // silently reintroduce a placement bug alongside it.
        let desc = Arc::new(
            TypeDescriptor::struct_type(
                "PrimitivesStructFinalPrefix",
                vec![
                    FieldDescriptor::new(
                        "x1",
                        Arc::new(TypeDescriptor::primitive("", PrimitiveKind::U8)),
                    ),
                    FieldDescriptor::new(
                        "x2",
                        Arc::new(TypeDescriptor::primitive("", PrimitiveKind::U16)),
                    ),
                    FieldDescriptor::new(
                        "x3",
                        Arc::new(TypeDescriptor::primitive("", PrimitiveKind::U32)),
                    ),
                    FieldDescriptor::new(
                        "x4",
                        Arc::new(TypeDescriptor::primitive("", PrimitiveKind::U64)),
                    ),
                    FieldDescriptor::new(
                        "x5",
                        Arc::new(TypeDescriptor::primitive("", PrimitiveKind::I8)),
                    ),
                    FieldDescriptor::new(
                        "x6",
                        Arc::new(TypeDescriptor::primitive("", PrimitiveKind::I16)),
                    ),
                    FieldDescriptor::new(
                        "x7",
                        Arc::new(TypeDescriptor::primitive("", PrimitiveKind::I32)),
                    ),
                    FieldDescriptor::new(
                        "x8",
                        Arc::new(TypeDescriptor::primitive("", PrimitiveKind::I64)),
                    ),
                    FieldDescriptor::new(
                        "x9",
                        Arc::new(TypeDescriptor::primitive("", PrimitiveKind::Bool)),
                    ),
                    FieldDescriptor::new(
                        "x10",
                        Arc::new(TypeDescriptor::primitive("", PrimitiveKind::F32)),
                    ),
                    FieldDescriptor::new(
                        "x11",
                        Arc::new(TypeDescriptor::primitive("", PrimitiveKind::F64)),
                    ),
                    FieldDescriptor::new(
                        "x12",
                        Arc::new(TypeDescriptor::primitive("", PrimitiveKind::LongDouble)),
                    ),
                ],
            )
            .with_extensibility(Extensibility::Final),
        );

        let mut data = DynamicData::new(&desc);
        data.set("x1", 1u8).unwrap();
        data.set("x2", 2u16).unwrap();
        data.set("x3", 3u32).unwrap();
        data.set("x4", 4u64).unwrap();
        data.set("x5", 5i8).unwrap();
        data.set("x6", 6i16).unwrap();
        data.set("x7", 7i32).unwrap();
        data.set("x8", 8i64).unwrap();
        data.set("x9", true).unwrap();
        data.set("x10", 10.1f32).unwrap();
        data.set("x11", 11.2f64).unwrap();
        // Connext DATA_NOT_CORRECT ground truth for x12 = literal "12.300000"
        // (struct_primitives.xml): the correctly-rounded binary128 LE bytes,
        // byte-identical to data/json/struct_primitives.json's raw x12 hex.
        let x12_bytes: [u8; crate::dynamic::LONG_DOUBLE_SIZE] = [
            0x9a, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x89,
            0x02, 0x40,
        ];
        if let DynamicValue::Struct(ref mut fields) = data.value_mut() {
            fields.insert("x12".to_string(), DynamicValue::LongDouble(x12_bytes));
        }

        let x2 = encode_dynamic_with_version(&data, CdrVersion::Xcdr2).expect("encode xcdr2");
        // XCDR2 layout (max align capped at 4, FINAL struct: no DHEADER):
        // x1@0(u8,1) x2@2(u16,2) x3@4(u32,4) x4@8(u64,8,align cap4)
        // x5@16(i8,1) x6@18(i16,2) x7@20(i32,4) x8@24(i64,8,align cap4)
        // x9@32(bool,1) x10@36(f32,4) x11@40(f64,8,align cap4)
        // x12@48(float128,16,align cap4) .. 64.
        assert_eq!(x2.len(), 48 + crate::dynamic::LONG_DOUBLE_SIZE);
        assert_eq!(
            &x2[48..64],
            &x12_bytes[..],
            "x12 must land at byte offset 48"
        );

        let rt = decode_dynamic_with_version(&x2, &desc, CdrVersion::Xcdr2).expect("decode");
        assert_eq!(
            rt.get::<[u8; crate::dynamic::LONG_DOUBLE_SIZE]>("x12")
                .unwrap(),
            x12_bytes
        );
        assert_eq!(rt.get::<f64>("x11").unwrap(), 11.2);
        assert_eq!(rt.get::<f32>("x10").unwrap(), 10.1);
    }

    #[test]
    fn test_xcdr2_appendable_dheader_with_f64() {
        // Appendable struct { u8 b; f64 v; } under XCDR2:
        // DHEADER@0 (body=12), b@4, pad 3, v@8..16 -> total 16.
        let desc = Arc::new(
            TypeDescriptor::struct_type(
                "AppendableWide",
                vec![
                    FieldDescriptor::new(
                        "b",
                        Arc::new(TypeDescriptor::primitive("", PrimitiveKind::U8)),
                    ),
                    FieldDescriptor::new(
                        "v",
                        Arc::new(TypeDescriptor::primitive("", PrimitiveKind::F64)),
                    ),
                ],
            )
            .with_extensibility(Extensibility::Appendable),
        );
        let mut data = DynamicData::new(&desc);
        data.set("b", 2u8).unwrap();
        data.set("v", -0.25f64).unwrap();

        let x2 = encode_dynamic_with_version(&data, CdrVersion::Xcdr2).expect("encode");
        assert_eq!(x2.len(), 16);
        let dheader = u32::from_le_bytes(x2[0..4].try_into().unwrap());
        assert_eq!(dheader, 12, "body = 1 (b) + 3 pad + 8 (f64)");
        assert_eq!(f64::from_le_bytes(x2[8..16].try_into().unwrap()), -0.25);

        let rt = decode_dynamic_with_version(&x2, &desc, CdrVersion::Xcdr2).expect("decode");
        assert_eq!(rt.get::<f64>("v").unwrap(), -0.25);
    }

    #[test]
    fn test_xcdr2_mutable_struct_is_dheader_delimited_no_sentinel() {
        // XCDR2 mutable (PL_CDR2) per DDS-XTypes v1.3 section 7.4.3.4:
        // DHEADER first, EMHEADER list bounded by it, NO sentinel.
        let desc = make_mutable_desc();
        let mut data = DynamicData::new(&desc);
        data.set("x", 5i32).unwrap();
        data.set("y", 7i32).unwrap();

        let x2 = encode_dynamic_with_version(&data, CdrVersion::Xcdr2).expect("encode");
        // DHEADER(4) + EMH(4)+x(4) + EMH(4)+y(4) = 20 bytes, no sentinel.
        assert_eq!(x2.len(), 20);
        let dheader = u32::from_le_bytes(x2[0..4].try_into().unwrap());
        assert_eq!(dheader, 16, "DHEADER must cover the EMHEADER list only");
        assert_eq!(
            u32::from_le_bytes(x2[4..8].try_into().unwrap()),
            0x2000_0001
        );
        assert_eq!(i32::from_le_bytes(x2[8..12].try_into().unwrap()), 5);
        assert_eq!(
            u32::from_le_bytes(x2[12..16].try_into().unwrap()),
            0x2000_0002
        );
        assert_eq!(i32::from_le_bytes(x2[16..20].try_into().unwrap()), 7);

        let rt = decode_dynamic_with_version(&x2, &desc, CdrVersion::Xcdr2).expect("decode");
        assert_eq!(rt.get::<i32>("x").unwrap(), 5);
        assert_eq!(rt.get::<i32>("y").unwrap(), 7);
    }

    #[test]
    fn test_xcdr2_mutable_decode_unknown_member_and_lc5() {
        // Wire from a "newer" remote type: known member x (id=1, LC=2),
        // then an unknown string member (id=9, LC=5: NEXTINT doubles as the
        // string length word), then known y (id=2). The decoder must skip
        // the unknown member using the LC=5 extent rule and stay in sync.
        let desc = make_mutable_desc();
        let mut body: Vec<u8> = Vec::new();
        body.extend(&0x2000_0001u32.to_le_bytes()); // EMH x (LC=2, id=1)
        body.extend(&41i32.to_le_bytes());
        body.extend(&0x5000_0009u32.to_le_bytes()); // EMH unknown (LC=5, id=9)
        body.extend(&6u32.to_le_bytes()); // NEXTINT = string len word = 6
        body.extend(b"hello\0"); // 6 bytes content
        body.extend(&[0u8, 0]); // pad to 4 for next EMHEADER
        body.extend(&0x2000_0002u32.to_le_bytes()); // EMH y (LC=2, id=2)
        body.extend(&42i32.to_le_bytes());

        let mut wire: Vec<u8> = Vec::new();
        wire.extend(&(body.len() as u32).to_le_bytes()); // DHEADER
        wire.extend(&body);

        let decoded = decode_dynamic_with_version(&wire, &desc, CdrVersion::Xcdr2).expect("decode");
        assert_eq!(decoded.get::<i32>("x").unwrap(), 41);
        assert_eq!(decoded.get::<i32>("y").unwrap(), 42);
    }

    #[test]
    fn test_xcdr2_sequence_of_nonprimitive_is_delimited() {
        // XCDR2 (DDS-XTypes v1.3 section 7.4.2): sequence<string> =
        // DHEADER + count + elements; sequence<int32> has NO DHEADER
        // (primitive element).
        use crate::dynamic::SequenceDescriptor;

        // seq<string> with 2 elements "ab", "cd".
        let seq_str = TypeKind::Sequence(SequenceDescriptor {
            element_type: Arc::new(TypeDescriptor::primitive(
                "",
                PrimitiveKind::String { max_length: None },
            )),
            max_length: None,
        });
        let desc = Arc::new(
            TypeDescriptor::struct_type(
                "SeqStr",
                vec![FieldDescriptor::new(
                    "x1",
                    Arc::new(TypeDescriptor::new("", seq_str)),
                )],
            )
            .with_extensibility(Extensibility::Final),
        );
        let mut data = DynamicData::new(&desc);
        if let DynamicValue::Struct(ref mut fields) = data.value_mut() {
            fields.insert(
                "x1".to_string(),
                DynamicValue::Sequence(vec![
                    DynamicValue::String("ab".into()),
                    DynamicValue::String("cd".into()),
                ]),
            );
        }
        let x2 = encode_dynamic_with_version(&data, CdrVersion::Xcdr2).expect("encode");
        // DHEADER(4) + count(4) + [len 4 + "ab\0" 3 + pad 1] + [len 4 + "cd\0" 3]
        // = 4 + 4 + 8 + 7 = 23 bytes.
        assert_eq!(x2.len(), 23);
        let dheader = u32::from_le_bytes(x2[0..4].try_into().unwrap());
        assert_eq!(dheader, 19, "DHEADER covers count + elements (4+8+7)");
        assert_eq!(u32::from_le_bytes(x2[4..8].try_into().unwrap()), 2);

        let rt = decode_dynamic_with_version(&x2, &desc, CdrVersion::Xcdr2).expect("decode");
        let seq = rt.get_field("x1").unwrap();
        assert_eq!(seq.as_sequence().unwrap().len(), 2);

        // XCDR1 mode: no DHEADER, historical layout intact.
        let x1 = encode_dynamic_with_version(&data, CdrVersion::Xcdr1).expect("encode");
        assert_eq!(u32::from_le_bytes(x1[0..4].try_into().unwrap()), 2);
    }

    #[test]
    fn test_xcdr2_sequence_of_primitive_has_no_dheader() {
        use crate::dynamic::SequenceDescriptor;
        let seq_i32 = TypeKind::Sequence(SequenceDescriptor {
            element_type: Arc::new(TypeDescriptor::primitive("", PrimitiveKind::I32)),
            max_length: None,
        });
        let desc = Arc::new(
            TypeDescriptor::struct_type(
                "SeqI32",
                vec![FieldDescriptor::new(
                    "x1",
                    Arc::new(TypeDescriptor::new("", seq_i32)),
                )],
            )
            .with_extensibility(Extensibility::Final),
        );
        let mut data = DynamicData::new(&desc);
        if let DynamicValue::Struct(ref mut fields) = data.value_mut() {
            fields.insert(
                "x1".to_string(),
                DynamicValue::Sequence(vec![DynamicValue::I32(7), DynamicValue::I32(9)]),
            );
        }
        let x2 = encode_dynamic_with_version(&data, CdrVersion::Xcdr2).expect("encode");
        // count(4) + 2 * i32 = 12 bytes, first word IS the count (no DHEADER).
        assert_eq!(x2.len(), 12);
        assert_eq!(u32::from_le_bytes(x2[0..4].try_into().unwrap()), 2);
        let rt = decode_dynamic_with_version(&x2, &desc, CdrVersion::Xcdr2).expect("decode");
        assert_eq!(rt.get_field("x1").unwrap().as_sequence().unwrap().len(), 2);
    }

    #[test]
    fn test_xcdr2_sequence_of_enum_is_delimited_cyclone_layout() {
        // A sequence of 10 enum values, all VAL1, is a delimited collection:
        // DHEADER = 44 (count 4 + 10 * 4), then count = 10, then values.
        use crate::dynamic::{EnumDescriptor, EnumVariant, SequenceDescriptor};
        let e = EnumDescriptor::new(vec![
            EnumVariant::new("VAL0", 0),
            EnumVariant::new("VAL1", 1),
            EnumVariant::new("VAL2", 2),
        ]);
        let seq_enum = TypeKind::Sequence(SequenceDescriptor {
            element_type: Arc::new(TypeDescriptor::new("E1", TypeKind::Enum(e))),
            max_length: None,
        });
        let desc = Arc::new(
            TypeDescriptor::struct_type(
                "enum1",
                vec![FieldDescriptor::new(
                    "x1",
                    Arc::new(TypeDescriptor::new("", seq_enum)),
                )],
            )
            .with_extensibility(Extensibility::Final),
        );
        let mut data = DynamicData::new(&desc);
        if let DynamicValue::Struct(ref mut fields) = data.value_mut() {
            fields.insert(
                "x1".to_string(),
                DynamicValue::Sequence(
                    (0..10)
                        .map(|_| DynamicValue::Enum(1, "VAL1".into()))
                        .collect(),
                ),
            );
        }
        let x2 = encode_dynamic_with_version(&data, CdrVersion::Xcdr2).expect("encode");
        assert_eq!(x2.len(), 48);
        assert_eq!(
            u32::from_le_bytes(x2[0..4].try_into().unwrap()),
            44,
            "sequence<enum> must be delimited: DHEADER 0x2c"
        );
        assert_eq!(u32::from_le_bytes(x2[4..8].try_into().unwrap()), 10);
        let rt = decode_dynamic_with_version(&x2, &desc, CdrVersion::Xcdr2).expect("decode");
        assert_eq!(rt.get_field("x1").unwrap().as_sequence().unwrap().len(), 10);
    }

    #[test]
    fn test_default_entry_points_keep_xcdr1_alignment() {
        // Legacy callers (ROS2 rmw path) rely on the version-less entry points
        // keeping natural (XCDR1) alignment: byte-identical to the historical
        // wire format.
        let desc = make_byte_then_f64_desc();
        let mut data = DynamicData::new(&desc);
        data.set("b", 1u8).unwrap();
        data.set("v", 2.0f64).unwrap();

        let legacy = encode_dynamic(&data).expect("encode");
        let x1 = encode_dynamic_with_version(&data, CdrVersion::Xcdr1).expect("encode");
        assert_eq!(legacy, x1, "default entry point must stay XCDR1-aligned");
    }

    // -----------------------------------------------------------------------
    // XCDR1 framing tests (DDS-XTypes v1.3 section 7.4.2):
    // appendable = plain CDR (no DHEADER), mutable = PL_CDR parameter list.
    // -----------------------------------------------------------------------

    #[test]
    fn test_xcdr1_appendable_has_no_dheader() {
        // Appendable struct { u16 a; f64 b; } under XCDR1 is PLAIN CDR:
        // a@0..2, 6 pad bytes (natural 8-alignment), b@8..16 -> 16 bytes,
        // no leading DHEADER.
        let desc = Arc::new(
            TypeDescriptor::struct_type(
                "AppendableU16F64",
                vec![
                    FieldDescriptor::new(
                        "a",
                        Arc::new(TypeDescriptor::primitive("", PrimitiveKind::U16)),
                    ),
                    FieldDescriptor::new(
                        "b",
                        Arc::new(TypeDescriptor::primitive("", PrimitiveKind::F64)),
                    ),
                ],
            )
            .with_extensibility(Extensibility::Appendable),
        );
        let mut data = DynamicData::new(&desc);
        data.set("a", 0x1234u16).unwrap();
        data.set("b", 2.5f64).unwrap();

        let x1 = encode_dynamic_with_version(&data, CdrVersion::Xcdr1).expect("encode");
        assert_eq!(x1.len(), 16, "XCDR1 appendable must be DHEADER-free");
        assert_eq!(u16::from_le_bytes(x1[0..2].try_into().unwrap()), 0x1234);
        assert_eq!(&x1[2..8], &[0u8; 6], "6 pad bytes to natural 8-alignment");
        assert_eq!(f64::from_le_bytes(x1[8..16].try_into().unwrap()), 2.5);

        let rt = decode_dynamic_with_version(&x1, &desc, CdrVersion::Xcdr1).expect("decode");
        assert_eq!(rt.get::<u16>("a").unwrap(), 0x1234);
        assert_eq!(rt.get::<f64>("b").unwrap(), 2.5);
    }

    #[test]
    fn test_xcdr1_mutable_is_pl_cdr1_param_list() {
        // Mixed-size members: the string value (7 bytes on the wire) is
        // padded to 8 in the stream but parameterLength declares the
        // UNPADDED size (7); the sentinel header stays 4-aligned via the
        // stream padding.
        let desc = Arc::new(
            TypeDescriptor::struct_type(
                "MutableMixed",
                vec![
                    FieldDescriptor::new(
                        "n",
                        Arc::new(TypeDescriptor::primitive("", PrimitiveKind::I32)),
                    )
                    .with_id(1),
                    FieldDescriptor::new(
                        "s",
                        Arc::new(TypeDescriptor::primitive(
                            "",
                            PrimitiveKind::String { max_length: None },
                        )),
                    )
                    .with_id(2),
                ],
            )
            .with_extensibility(Extensibility::Mutable),
        );
        let mut data = DynamicData::new(&desc);
        data.set("n", -3i32).unwrap();
        data.set("s", "hi").unwrap();

        let x1 = encode_dynamic_with_version(&data, CdrVersion::Xcdr1).expect("encode");
        // [pid=1][len=4][i32] [pid=2][len=7][u32 strlen=3]["hi\0"][pad]
        // [pid=0x7F02][len=0] = header(4)+4 + header(4)+7+1pad + 4 = 24.
        assert_eq!(x1.len(), 24);
        assert_eq!(u16::from_le_bytes(x1[0..2].try_into().unwrap()), 1);
        assert_eq!(u16::from_le_bytes(x1[2..4].try_into().unwrap()), 4);
        assert_eq!(i32::from_le_bytes(x1[4..8].try_into().unwrap()), -3);
        assert_eq!(u16::from_le_bytes(x1[8..10].try_into().unwrap()), 2);
        assert_eq!(
            u16::from_le_bytes(x1[10..12].try_into().unwrap()),
            7,
            "string value is 7 bytes; declared length is unpadded (stream pads to 8)"
        );
        assert_eq!(
            u32::from_le_bytes(x1[12..16].try_into().unwrap()),
            3,
            "string length word includes the NUL terminator"
        );
        assert_eq!(&x1[16..19], b"hi\0");
        assert_eq!(x1[19], 0, "pad byte to 4-align the next header");
        assert_eq!(u16::from_le_bytes(x1[20..22].try_into().unwrap()), 0x7F02);
        assert_eq!(u16::from_le_bytes(x1[22..24].try_into().unwrap()), 0);

        let rt = decode_dynamic_with_version(&x1, &desc, CdrVersion::Xcdr1).expect("decode");
        assert_eq!(rt.get::<i32>("n").unwrap(), -3);
        assert_eq!(rt.get::<String>("s").unwrap(), "hi");
    }

    #[test]
    fn test_xcdr1_mutable_decode_skips_unknown_pid() {
        // Wire from a "newer" remote type: an unknown pid before the known
        // members must be skipped by its declared length. The known x header
        // carries the must-understand flag (0x4000): matching must mask it.
        let desc = make_mutable_desc();
        let mut wire: Vec<u8> = Vec::new();
        wire.extend(&9u16.to_le_bytes()); // unknown pid 9
        wire.extend(&8u16.to_le_bytes()); // length 8
        wire.extend(&[0xAAu8; 8]); // opaque payload
        wire.extend(&0x4001u16.to_le_bytes()); // pid x (id=1) + must-understand
        wire.extend(&4u16.to_le_bytes());
        wire.extend(&33i32.to_le_bytes());
        wire.extend(&2u16.to_le_bytes()); // pid y
        wire.extend(&4u16.to_le_bytes());
        wire.extend(&44i32.to_le_bytes());
        wire.extend(&0x3F02u16.to_le_bytes()); // PID_LIST_END as HDDS 1.4.x wrote it
        wire.extend(&0u16.to_le_bytes());

        let decoded = decode_dynamic_with_version(&wire, &desc, CdrVersion::Xcdr1).expect("decode");
        assert_eq!(decoded.get::<i32>("x").unwrap(), 33);
        assert_eq!(decoded.get::<i32>("y").unwrap(), 44);
    }

    #[test]
    fn test_xcdr1_mutable_extended_pid_roundtrip() {
        // Member id >= 0x3F00 cannot use the short parameterId form: the
        // encoder must emit PID_EXTENDED with its must-understand flag
        // (0x7F01, length 8) followed by the u32 member header (no FLAG_2:
        // the member is not must-understand) + u32 member length.
        let desc = Arc::new(
            TypeDescriptor::struct_type(
                "MutableBigId",
                vec![FieldDescriptor::new(
                    "v",
                    Arc::new(TypeDescriptor::primitive("", PrimitiveKind::I32)),
                )
                .with_id(0x0004_1234)],
            )
            .with_extensibility(Extensibility::Mutable),
        );
        let mut data = DynamicData::new(&desc);
        data.set("v", 77i32).unwrap();

        let x1 = encode_dynamic_with_version(&data, CdrVersion::Xcdr1).expect("encode");
        // [0x7F01][8][u32 id][u32 len=4][i32 v][0x7F02][0] = 20 bytes.
        assert_eq!(x1.len(), 20);
        assert_eq!(u16::from_le_bytes(x1[0..2].try_into().unwrap()), 0x7F01);
        assert_eq!(u16::from_le_bytes(x1[2..4].try_into().unwrap()), 8);
        assert_eq!(
            u32::from_le_bytes(x1[4..8].try_into().unwrap()),
            0x0004_1234
        );
        assert_eq!(u32::from_le_bytes(x1[8..12].try_into().unwrap()), 4);
        assert_eq!(i32::from_le_bytes(x1[12..16].try_into().unwrap()), 77);
        assert_eq!(u16::from_le_bytes(x1[16..18].try_into().unwrap()), 0x7F02);
        assert_eq!(u16::from_le_bytes(x1[18..20].try_into().unwrap()), 0);

        let rt = decode_dynamic_with_version(&x1, &desc, CdrVersion::Xcdr1).expect("decode");
        assert_eq!(rt.get::<i32>("v").unwrap(), 77);
    }

    #[test]
    fn test_xcdr1_nested_mutable_inside_final_and_appendable_skip() {
        // A mutable struct nested (via Nested descriptor) inside a Final
        // outer struct must use PL_CDR1 framing under XCDR1 on both encode
        // and decode; a trailing member after it proves the parameter list
        // consumes exactly its own extent.
        let inner_desc = make_mutable_desc();
        let outer_desc = Arc::new(TypeDescriptor::struct_type(
            "Outer",
            vec![
                FieldDescriptor::new("m", inner_desc.clone()),
                FieldDescriptor::new(
                    "tail",
                    Arc::new(TypeDescriptor::primitive("", PrimitiveKind::U32)),
                ),
            ],
        ));
        let mut data = DynamicData::new(&outer_desc);
        data.set("tail", 0xDEADu32).unwrap();
        if let DynamicValue::Struct(ref mut fields) = data.value_mut() {
            let mut m = std::collections::HashMap::new();
            m.insert("x".to_string(), DynamicValue::I32(1));
            m.insert("y".to_string(), DynamicValue::I32(2));
            fields.insert("m".to_string(), DynamicValue::Struct(m));
        }

        let x1 = encode_dynamic_with_version(&data, CdrVersion::Xcdr1).expect("encode");
        // Nested PL list = 20 bytes (see the PL_CDR1 encode test) + u32 tail.
        assert_eq!(x1.len(), 24);
        assert_eq!(u16::from_le_bytes(x1[16..18].try_into().unwrap()), 0x7F02);
        assert_eq!(
            u32::from_le_bytes(x1[20..24].try_into().unwrap()),
            0xDEAD,
            "tail member must start right after the sentinel"
        );

        let rt = decode_dynamic_with_version(&x1, &outer_desc, CdrVersion::Xcdr1).expect("decode");
        assert_eq!(rt.get::<u32>("tail").unwrap(), 0xDEAD);
        let m = rt.get_field("m").unwrap();
        assert_eq!(m.get_field("x").and_then(|v| v.as_i32()), Some(1));
        assert_eq!(m.get_field("y").and_then(|v| v.as_i32()), Some(2));
    }

    #[test]
    fn test_xcdr1_appendable_widening_truncated_sample_defaults() {
        // Writer type {u32 x1} appendable vs reader type {u32 x1, i32 x2,
        // string s} appendable: XCDR1 has no DHEADER, so the reader sees the
        // sample cleanly run out after x1 and must default-fill x2 and s
        // (OMG interop ext_appendable_struct_2 widening semantics).
        let writer_desc = Arc::new(
            TypeDescriptor::struct_type(
                "A1",
                vec![FieldDescriptor::new(
                    "x1",
                    Arc::new(TypeDescriptor::primitive("", PrimitiveKind::U32)),
                )],
            )
            .with_extensibility(Extensibility::Appendable),
        );
        let reader_desc = Arc::new(
            TypeDescriptor::struct_type(
                "A2",
                vec![
                    FieldDescriptor::new(
                        "x1",
                        Arc::new(TypeDescriptor::primitive("", PrimitiveKind::U32)),
                    ),
                    FieldDescriptor::new(
                        "x2",
                        Arc::new(TypeDescriptor::primitive("", PrimitiveKind::I32)),
                    ),
                    FieldDescriptor::new(
                        "s",
                        Arc::new(TypeDescriptor::primitive(
                            "",
                            PrimitiveKind::String { max_length: None },
                        )),
                    ),
                ],
            )
            .with_extensibility(Extensibility::Appendable),
        );

        let mut data = DynamicData::new(&writer_desc);
        data.set("x1", 0xC0FFEEu32).unwrap();
        let wire = encode_dynamic_with_version(&data, CdrVersion::Xcdr1).expect("encode");
        assert_eq!(wire.len(), 4, "writer sample is just the u32, no DHEADER");

        let decoded =
            decode_dynamic_with_version(&wire, &reader_desc, CdrVersion::Xcdr1).expect("decode");
        assert_eq!(decoded.get::<u32>("x1").unwrap(), 0xC0FFEE);
        assert_eq!(decoded.get::<i32>("x2").unwrap(), 0, "missing member -> 0");
        assert_eq!(
            decoded.get::<String>("s").unwrap(),
            "",
            "missing member -> empty string"
        );
    }

    #[test]
    fn test_xcdr1_appendable_midmember_truncation_is_error() {
        // Truncation INSIDE a member is corruption, not widening: the
        // decoder must keep returning BufferTooSmall, not default-fill.
        let desc = Arc::new(
            TypeDescriptor::struct_type(
                "A",
                vec![
                    FieldDescriptor::new(
                        "a",
                        Arc::new(TypeDescriptor::primitive("", PrimitiveKind::U32)),
                    ),
                    FieldDescriptor::new(
                        "b",
                        Arc::new(TypeDescriptor::primitive("", PrimitiveKind::U32)),
                    ),
                ],
            )
            .with_extensibility(Extensibility::Appendable),
        );
        let mut data = DynamicData::new(&desc);
        data.set("a", 1u32).unwrap();
        data.set("b", 2u32).unwrap();
        let wire = encode_dynamic_with_version(&data, CdrVersion::Xcdr1).expect("encode");
        assert_eq!(wire.len(), 8);

        // Cut inside b's 4 bytes.
        let truncated = &wire[..wire.len() - 2];
        let result = decode_dynamic_with_version(truncated, &desc, CdrVersion::Xcdr1);
        assert!(
            matches!(result, Err(DynamicCdrError::BufferTooSmall { .. })),
            "mid-member truncation must stay an error, got {:?}",
            result.map(|d| d.value().clone())
        );
    }

    // ---------------------------------------------------------------
    // wstring wire format (XTypes 1.3 section 7.4.1.1.2): the length
    // prefix counts BYTES of UTF-16 payload, with NO trailing NUL code
    // unit and NO BOM (a 12-char string -> len 0x18 + 24 bytes, nothing
    // else).
    // ---------------------------------------------------------------

    fn wstring_struct_desc(max_length: Option<usize>, tc: TryConstructKind) -> Arc<TypeDescriptor> {
        Arc::new(TypeDescriptor::struct_type(
            "WS",
            vec![FieldDescriptor::new(
                "w",
                Arc::new(TypeDescriptor::primitive(
                    "wstring",
                    PrimitiveKind::WString { max_length },
                )),
            )
            .with_try_construct(tc)],
        ))
    }

    fn wstring_tail_struct_desc(
        max_length: Option<usize>,
        tc: TryConstructKind,
    ) -> Arc<TypeDescriptor> {
        Arc::new(TypeDescriptor::struct_type(
            "WST",
            vec![
                FieldDescriptor::new(
                    "w",
                    Arc::new(TypeDescriptor::primitive(
                        "wstring",
                        PrimitiveKind::WString { max_length },
                    )),
                )
                .with_try_construct(tc),
                FieldDescriptor::new(
                    "tail",
                    Arc::new(TypeDescriptor::primitive("", PrimitiveKind::U32)),
                ),
            ],
        ))
    }

    fn make_wstring_data(desc: &Arc<TypeDescriptor>, s: &str) -> DynamicData {
        let mut data = DynamicData::new(desc);
        if let DynamicValue::Struct(ref mut fields) = data.value_mut() {
            fields.insert("w".to_string(), DynamicValue::WString(s.to_string()));
        }
        data
    }

    /// UTF-16LE bytes of a &str (no BOM, no NUL).
    fn utf16le(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()
    }

    #[test]
    fn test_wstring_encode_wire_exact_bytes_no_nul() {
        // "hello" = 5 UTF-16 units = 10 bytes payload; length prefix 10.
        let desc = wstring_struct_desc(None, TryConstructKind::Discard);
        let data = make_wstring_data(&desc, "hello");
        let wire = encode_dynamic(&data).expect("encode");

        let mut expected = vec![0x0au8, 0, 0, 0];
        expected.extend(utf16le("hello"));
        assert_eq!(
            wire, expected,
            "wstring wire must be byte-length + UTF-16LE, no NUL"
        );

        // 12-char reference form from vendor captures: len 0x18 + 24 bytes.
        let data12 = make_wstring_data(&desc, "Hello world!");
        let wire12 = encode_dynamic(&data12).expect("encode");
        assert_eq!(wire12.len(), 4 + 24);
        assert_eq!(&wire12[..4], &[0x18, 0, 0, 0]);
        assert_eq!(&wire12[4..], utf16le("Hello world!").as_slice());
    }

    #[test]
    fn test_wstring_encode_bmp_wire_exact() {
        // BMP non-ASCII: e-acute (U+00E9), euro (U+20AC), CJK (U+4E2D)
        // = 3 UTF-16 units = 6 bytes.
        let desc = wstring_struct_desc(None, TryConstructKind::Discard);
        let data = make_wstring_data(&desc, "\u{00e9}\u{20ac}\u{4e2d}");
        let wire = encode_dynamic(&data).expect("encode");
        assert_eq!(
            wire,
            vec![0x06, 0, 0, 0, 0xe9, 0x00, 0xac, 0x20, 0x2d, 0x4e]
        );
    }

    #[test]
    fn test_wstring_decode_reference_bytes() {
        // Exact vendor reference form: 24-byte length + 24 UTF-16LE bytes,
        // no trailing NUL. Must decode to the 12 original chars.
        let desc = wstring_struct_desc(None, TryConstructKind::Discard);
        let mut wire = vec![0x18u8, 0, 0, 0];
        wire.extend(utf16le("Hello world!"));
        let decoded = decode_dynamic(&wire, &desc).expect("decode");
        assert_eq!(decoded.get::<String>("w").unwrap(), "Hello world!");
    }

    #[test]
    fn test_wstring_roundtrip() {
        // Mixed content incl. a surrogate pair (U+1D11E = 2 units).
        let desc = wstring_struct_desc(None, TryConstructKind::Discard);
        for s in [
            "",
            "hello",
            "Hello world!",
            "\u{00e9}\u{20ac}\u{4e2d}\u{1d11e}",
        ] {
            let data = make_wstring_data(&desc, s);
            let wire = encode_dynamic(&data).expect("encode");
            let decoded = decode_dynamic(&wire, &desc).expect("decode");
            assert_eq!(decoded.get::<String>("w").unwrap(), s, "roundtrip of {s:?}");
        }
        // Empty wstring is exactly a zero length prefix.
        let empty = make_wstring_data(&desc, "");
        assert_eq!(encode_dynamic(&empty).expect("encode"), vec![0, 0, 0, 0]);
    }

    #[test]
    fn test_wstring_decode_odd_length_tolerated() {
        // Odd byte length: floor to whole units, but still consume the
        // stray byte so the stream stays aligned for the next member.
        let desc = wstring_tail_struct_desc(None, TryConstructKind::Discard);
        let mut wire = vec![0x0bu8, 0, 0, 0]; // 11 bytes = 5 units + stray
        wire.extend(utf16le("hello")); // offsets 4..14
        wire.push(0xAA); // stray payload byte, offset 14
        wire.push(0x00); // alignment pad to 16 for the u32
        wire.extend(&0xDEAD_BEEFu32.to_le_bytes());
        let decoded = decode_dynamic(&wire, &desc).expect("decode");
        assert_eq!(decoded.get::<String>("w").unwrap(), "hello");
        assert_eq!(decoded.get::<u32>("tail").unwrap(), 0xDEAD_BEEF);
    }

    #[test]
    fn test_wstring_decode_trailing_nul_legacy_tolerated() {
        // Legacy peers may append one NUL unit inside the counted bytes;
        // spec senders never do. Strip it defensively.
        let desc = wstring_struct_desc(None, TryConstructKind::Discard);
        let mut wire = vec![0x0cu8, 0, 0, 0]; // 12 bytes = 6 units
        wire.extend(utf16le("hello"));
        wire.extend(&[0u8, 0u8]); // trailing NUL unit
        let decoded = decode_dynamic(&wire, &desc).expect("decode");
        assert_eq!(decoded.get::<String>("w").unwrap(), "hello");
    }

    #[test]
    fn test_wstring_bound_check_uses_unit_count() {
        // 6 units (12 bytes) against bound 6 must PASS: the bound counts
        // UTF-16 units, not wire bytes (old code compared bytes-1 > max).
        let desc = wstring_struct_desc(Some(6), TryConstructKind::Discard);
        let mut wire = vec![0x0cu8, 0, 0, 0];
        wire.extend(utf16le("worlds"));
        let decoded = decode_dynamic(&wire, &desc).expect("decode");
        assert_eq!(decoded.get::<String>("w").unwrap(), "worlds");

        // 6 units against bound 5 must trip the policy (Discard -> error).
        let desc5 = wstring_struct_desc(Some(5), TryConstructKind::Discard);
        let result = decode_dynamic(&wire, &desc5);
        assert!(
            matches!(result, Err(DynamicCdrError::InvalidData(_))),
            "6 units vs bound 5 must discard, got {:?}",
            result.map(|d| d.value().clone())
        );
    }

    #[test]
    fn test_wstring_bound_trim_consumes_exact_bytes() {
        // Trim to bound AND keep the stream position exact (consume
        // wire_len BYTES, not wire_len*2), proven by the tail member.
        let desc = wstring_tail_struct_desc(Some(3), TryConstructKind::Trim);
        let mut wire = vec![0x0au8, 0, 0, 0]; // "hello" = 10 bytes
        wire.extend(utf16le("hello")); // offsets 4..14
        wire.extend(&[0u8, 0u8]); // alignment pad to 16
        wire.extend(&0xCAFE_F00Du32.to_le_bytes());
        let decoded = decode_dynamic(&wire, &desc).expect("decode");
        assert_eq!(decoded.get::<String>("w").unwrap(), "hel");
        assert_eq!(decoded.get::<u32>("tail").unwrap(), 0xCAFE_F00D);
    }

    #[test]
    fn test_wstring_bound_usedefault_consumes_exact_bytes() {
        let desc = wstring_tail_struct_desc(Some(2), TryConstructKind::UseDefault);
        let mut wire = vec![0x0au8, 0, 0, 0];
        wire.extend(utf16le("hello"));
        wire.extend(&[0u8, 0u8]); // alignment pad to 16
        wire.extend(&0x1234_5678u32.to_le_bytes());
        let decoded = decode_dynamic(&wire, &desc).expect("decode");
        assert_eq!(decoded.get::<String>("w").unwrap(), "");
        assert_eq!(decoded.get::<u32>("tail").unwrap(), 0x1234_5678);
    }

    #[test]
    fn test_wstring_encode_rejects_over_bound() {
        // Publisher-side guard unchanged: bound counts UTF-16 units.
        let desc = wstring_struct_desc(Some(4), TryConstructKind::Discard);
        let data = make_wstring_data(&desc, "hello");
        assert!(encode_dynamic(&data).is_err());
        let ok = make_wstring_data(&desc, "hell");
        assert!(encode_dynamic(&ok).is_ok());
    }

    // ---------------------------------------------------------------
    // A key is never trimmed nor defaulted (DDS-XTypes v1.3 Sec.7.2.4.4.8
    // Table 19, Note: "the key of T2 can be transformed faithfully into the
    // key of T1 without aliasing or loss of information"). Under the default
    // ignore_string_bounds a writer key string<20> matches a reader key
    // string<10>; a 15-character key must then be refused, never turned
    // into the 10-character key of another instance.
    // ---------------------------------------------------------------

    const SHORT_KEY: &str = "abcdefghij";
    const LONG_KEY: &str = "abcdefghijKLMNO";

    fn bounded_string(bound: Option<usize>) -> Arc<TypeDescriptor> {
        Arc::new(TypeDescriptor::primitive(
            "string",
            PrimitiveKind::String { max_length: bound },
        ))
    }

    /// `struct K { [@key] <name_type> name; int32 v; }` with `ext`.
    fn keyed_struct(
        name_type: Arc<TypeDescriptor>,
        tc: TryConstructKind,
        key: bool,
        ext: Extensibility,
    ) -> Arc<TypeDescriptor> {
        let name = FieldDescriptor::new("name", name_type).with_try_construct(tc);
        let name = if key { name.with_key() } else { name };
        Arc::new(
            TypeDescriptor::struct_type(
                "K",
                vec![
                    name,
                    FieldDescriptor::new(
                        "v",
                        Arc::new(TypeDescriptor::primitive("int32", PrimitiveKind::I32)),
                    ),
                ],
            )
            .with_extensibility(ext),
        )
    }

    /// The writer's sample: an unbounded `name` and `v = 7`.
    fn written(name: &str, ext: Extensibility, version: CdrVersion) -> Vec<u8> {
        let desc = keyed_struct(bounded_string(None), TryConstructKind::Discard, true, ext);
        let mut data = DynamicData::new(&desc);
        if let DynamicValue::Struct(ref mut fields) = data.value_mut() {
            fields.insert("name".into(), DynamicValue::String(name.into()));
            fields.insert("v".into(), DynamicValue::I32(7));
        }
        encode_dynamic_with_version(&data, version).expect("encode")
    }

    const EXTS: [Extensibility; 3] = [
        Extensibility::Final,
        Extensibility::Appendable,
        Extensibility::Mutable,
    ];
    const TCS: [TryConstructKind; 3] = [
        TryConstructKind::Discard,
        TryConstructKind::Trim,
        TryConstructKind::UseDefault,
    ];

    /// What the reader with a string<10> `name` reads from `name`.
    fn read_name(
        name_type: &Arc<TypeDescriptor>,
        tc: TryConstructKind,
        key: bool,
        ext: Extensibility,
        version: CdrVersion,
        name: &str,
    ) -> Option<String> {
        let reader = keyed_struct(name_type.clone(), tc, key, ext);
        decode_dynamic_with_version(&written(name, ext, version), &reader, version)
            .ok()
            .map(|d| d.get::<String>("name").expect("name"))
    }

    #[test]
    fn a_key_longer_than_the_reader_bound_is_refused_whatever_its_try_construct() {
        let bound10 = bounded_string(Some(10));
        let typedef10 = Arc::new(TypeDescriptor::new(
            "Name",
            TypeKind::Nested(bound10.clone()),
        ));
        for name_type in [&bound10, &typedef10] {
            for ext in EXTS {
                for version in [CdrVersion::Xcdr1, CdrVersion::Xcdr2] {
                    for tc in TCS {
                        let at = format!("{} {ext:?} {version:?} {tc:?}", name_type.name);
                        assert_eq!(
                            read_name(name_type, tc, true, ext, version, SHORT_KEY).as_deref(),
                            Some(SHORT_KEY),
                            "{at}"
                        );
                        assert_eq!(
                            read_name(name_type, tc, true, ext, version, LONG_KEY),
                            None,
                            "{at}: a 15-char key must be refused, not read as another key"
                        );
                    }
                }
            }
        }
    }

    /// The rule is the key's: a non-key member keeps the TryConstruct it
    /// declares (Table 11), through a typedef too.
    #[test]
    fn a_non_key_member_keeps_its_try_construct() {
        let bound10 = bounded_string(Some(10));
        let typedef10 = Arc::new(TypeDescriptor::new(
            "Name",
            TypeKind::Nested(bound10.clone()),
        ));
        for name_type in [&bound10, &typedef10] {
            for ext in EXTS {
                for version in [CdrVersion::Xcdr1, CdrVersion::Xcdr2] {
                    let at = format!("{} {ext:?} {version:?}", name_type.name);
                    let read = |tc| read_name(name_type, tc, false, ext, version, LONG_KEY);
                    assert_eq!(read(TryConstructKind::Discard), None, "{at}");
                    assert_eq!(
                        read(TryConstructKind::Trim).as_deref(),
                        Some(SHORT_KEY),
                        "{at}"
                    );
                    assert_eq!(
                        read(TryConstructKind::UseDefault).as_deref(),
                        Some(""),
                        "{at}"
                    );
                }
            }
        }
    }

    /// A key of structure type: nothing inside it is trimmed either, even a
    /// member that declares TRIM.
    #[test]
    fn nothing_inside_a_structure_key_is_trimmed() {
        for ext in EXTS {
            for version in [CdrVersion::Xcdr1, CdrVersion::Xcdr2] {
                structure_key_case(ext, version);
            }
        }
    }

    fn structure_key_case(ext: Extensibility, version: CdrVersion) {
        let at = format!("{ext:?} {version:?}");
        let holder = |bound| {
            Arc::new(
                TypeDescriptor::struct_type(
                    "Holder",
                    vec![FieldDescriptor::new("s", bounded_string(bound))
                        .with_try_construct(TryConstructKind::Trim)],
                )
                .with_extensibility(ext),
            )
        };
        let outer = |bound, key: bool| {
            let k = FieldDescriptor::new("k", holder(bound));
            Arc::new(
                TypeDescriptor::struct_type("Outer", vec![if key { k.with_key() } else { k }])
                    .with_extensibility(ext),
            )
        };
        let mut data = DynamicData::new(&outer(None, true));
        if let DynamicValue::Struct(ref mut fields) = data.value_mut() {
            let inner = std::collections::HashMap::from([(
                "s".to_string(),
                DynamicValue::String(LONG_KEY.into()),
            )]);
            fields.insert("k".into(), DynamicValue::Struct(inner));
        }
        let wire = encode_dynamic_with_version(&data, version).expect("encode");
        assert!(
            decode_dynamic_with_version(&wire, &outer(Some(10), true), version).is_err(),
            "{at}"
        );
        let trimmed = decode_dynamic_with_version(&wire, &outer(Some(10), false), version)
            .expect("non-key trims");
        let DynamicValue::Struct(fields) = trimmed.value() else {
            panic!("Outer decodes to a struct");
        };
        match fields.get("k") {
            Some(DynamicValue::Struct(inner)) => assert_eq!(
                inner.get("s"),
                Some(&DynamicValue::String(SHORT_KEY.into())),
                "{at}"
            ),
            other => panic!("{at} k: {other:?}"),
        }
    }

    /// A union keyed by its discriminator: a discriminator value the reader's
    /// enumeration lacks is refused even under USE_DEFAULT, which would map
    /// it onto the default literal, another instance.
    #[test]
    fn a_key_discriminator_is_never_defaulted() {
        use crate::dynamic::{EnumDescriptor, EnumVariant, UnionCase, UnionDescriptor};
        let union = |key: bool| {
            let disc = Arc::new(TypeDescriptor::new(
                "E",
                TypeKind::Enum(EnumDescriptor::new(vec![
                    EnumVariant::new("A", 0),
                    EnumVariant::new("B", 1),
                ])),
            ));
            let int32 = Arc::new(TypeDescriptor::primitive("int32", PrimitiveKind::I32));
            let u = UnionDescriptor::new(disc, vec![UnionCase::new("a", vec![0], int32)])
                .with_discriminator_try_construct(TryConstructKind::UseDefault);
            let u = if key { u.with_discriminator_key() } else { u };
            Arc::new(TypeDescriptor::new("U", TypeKind::Union(u)))
        };
        // A writer whose enumeration has C = 2, selecting a case `c` = 7.
        let wire = [2u8, 0, 0, 0, 7, 0, 0, 0];
        assert!(decode_dynamic(&wire, &union(true)).is_err());
        assert!(decode_dynamic(&wire, &union(false)).is_ok());
    }
}
