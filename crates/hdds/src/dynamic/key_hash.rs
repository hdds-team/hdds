// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! KeyHash of a [`DynamicData`] sample (RTPS 2.5 9.6.4.8), through the same
//! [`KeyHolderWriter`] generated code uses.
//!
//! The KeyHolder is read from the descriptor: a structure keeps its `is_key`
//! members, or all of them when it has none, in ascending member id, where the
//! member id is the one the TypeObject announces (explicit id, else the
//! `@autoid(HASH)` name hash, else the declaration index). A union keeps its
//! discriminator alone when the discriminator is a key, and is kept whole
//! otherwise. The rule is applied again inside every member that is a
//! structure or a union.
//!
//! Not covered, refused with an error rather than hashed by a guess: a key
//! holding a collection whose element type is not primitive (whether XCDR2's
//! DHEADER belongs in the KeyHash serialization is not established, see
//! [`crate::core::key_hash`]), and `long double`, whose dynamic representation
//! is a host-dependent byte array.

use super::dynamic_data::DynamicDataError;
use super::xtypes_bridge::struct_member_ids;
use super::{
    DynamicData, DynamicValue, EnumDescriptor, FieldDescriptor, PrimitiveKind, TypeDescriptor,
    TypeKind, UnionDescriptor,
};
use crate::core::key_hash::{KeyHolderWriter, KeyMaxSize};

impl DynamicData {
    /// The instance KeyHash of this sample (RTPS 2.5 9.6.4.8), or `None` when
    /// its type has no key: a structure with no `is_key` member, or a union
    /// whose discriminator is not a key.
    ///
    /// # Errors
    ///
    /// The value does not match its descriptor (a missing member, a value of
    /// another kind, a string or sequence beyond its bound), or the KeyHolder
    /// holds a type this walker does not cover (see the module docs).
    pub fn compute_key_hash(&self) -> Result<Option<[u8; 16]>, DynamicDataError> {
        let desc = resolve(self.descriptor());
        if !type_has_key(desc) {
            return Ok(None);
        }
        let mut w = KeyHolderWriter::new();
        write_value(&mut w, desc, self.value())?;
        let max = match max_end(desc, 0)? {
            Some(n) => KeyMaxSize::Bounded(n),
            None => KeyMaxSize::Unbounded,
        };
        Ok(Some(w.finish(max)))
    }
}

/// Follow `Nested` references to the descriptor that holds the type.
fn resolve(mut desc: &TypeDescriptor) -> &TypeDescriptor {
    while let TypeKind::Nested(inner) = &desc.kind {
        desc = inner;
    }
    desc
}

fn type_has_key(desc: &TypeDescriptor) -> bool {
    match &desc.kind {
        TypeKind::Struct(fields) => fields.iter().any(|f| f.is_key),
        TypeKind::Union(u) => u.discriminator_is_key,
        _ => false,
    }
}

fn unsupported(what: &str) -> DynamicDataError {
    DynamicDataError::InvalidOperation(format!("KeyHash of {what} is not supported"))
}

fn mismatch(expected: &str, got: &DynamicValue) -> DynamicDataError {
    DynamicDataError::TypeMismatch {
        expected: expected.to_string(),
        got: format!("{got:?}"),
    }
}

/// The KeyHolder members of a structure, in ascending member id; a member
/// id wider than 28 bits is refused (`struct_member_ids`).
fn holder_members<'a>(
    desc: &TypeDescriptor,
    fields: &'a [FieldDescriptor],
) -> Result<Vec<&'a FieldDescriptor>, DynamicDataError> {
    let any_key = fields.iter().any(|f| f.is_key);
    let mut members: Vec<(u32, &FieldDescriptor)> = struct_member_ids(desc.autoid_hash, fields)
        .map_err(|e| DynamicDataError::InvalidOperation(e.to_string()))?
        .into_iter()
        .zip(fields)
        .filter(|(_, f)| !any_key || f.is_key)
        .collect();
    members.sort_by_key(|(id, _)| *id);
    Ok(members.into_iter().map(|(_, f)| f).collect())
}

/// A collection element the KeyHash serialization covers: a primitive other
/// than a string or a `long double`.
fn plain_element(desc: &TypeDescriptor) -> Result<PrimitiveKind, DynamicDataError> {
    match &resolve(desc).kind {
        TypeKind::Primitive(p) => match p {
            PrimitiveKind::String { .. } | PrimitiveKind::WString { .. } => {
                Err(unsupported("a collection of strings"))
            }
            PrimitiveKind::LongDouble => Err(unsupported("long double")),
            other => Ok(*other),
        },
        _ => Err(unsupported("a collection of non-primitive elements")),
    }
}

fn write_value(
    w: &mut KeyHolderWriter,
    desc: &TypeDescriptor,
    value: &DynamicValue,
) -> Result<(), DynamicDataError> {
    let desc = resolve(desc);
    match &desc.kind {
        TypeKind::Primitive(p) => write_primitive(w, *p, value),
        TypeKind::Struct(fields) => {
            let DynamicValue::Struct(map) = value else {
                return Err(mismatch("struct", value));
            };
            for field in holder_members(desc, fields)? {
                let member = map
                    .get(&field.name)
                    .ok_or_else(|| DynamicDataError::FieldNotFound(field.name.clone()))?;
                if field.optional {
                    // XTypes 1.3 7.4.3.5.3 rule 20: PLAIN_CDR2 prefixes an
                    // optional member with its presence flag.
                    let present = !member.is_null();
                    w.write_bool(present);
                    if !present {
                        continue;
                    }
                }
                write_value(w, &field.type_desc, member)?;
            }
            Ok(())
        }
        TypeKind::Union(u) => {
            let DynamicValue::Union(disc, _, inner) = value else {
                return Err(mismatch("union", value));
            };
            write_discriminator(w, u, *disc)?;
            if !u.discriminator_is_key {
                if let Some(case) = u.case_by_discriminator(*disc) {
                    write_value(w, &case.type_desc, inner)?;
                }
            }
            Ok(())
        }
        TypeKind::Enum(e) => {
            let DynamicValue::Enum(v, _) = value else {
                return Err(mismatch("enum", value));
            };
            write_int(w, enum_width(e), *v)
        }
        TypeKind::Sequence(seq) => {
            let elem = plain_element(&seq.element_type)?;
            let DynamicValue::Sequence(items) = value else {
                return Err(mismatch("sequence", value));
            };
            if let Some(max) = seq.max_length {
                if items.len() > max {
                    return Err(DynamicDataError::SequenceTooLong {
                        length: items.len(),
                        max,
                    });
                }
            }
            let len = u32::try_from(items.len())
                .map_err(|_| DynamicDataError::InvalidOperation("sequence length".into()))?;
            w.write_u32(len);
            for item in items {
                write_primitive(w, elem, item)?;
            }
            Ok(())
        }
        TypeKind::Array(arr) => {
            let elem = plain_element(&arr.element_type)?;
            let DynamicValue::Array(items) = value else {
                return Err(mismatch("array", value));
            };
            if items.len() != arr.length {
                return Err(DynamicDataError::IndexOutOfBounds {
                    index: items.len(),
                    length: arr.length,
                });
            }
            for item in items {
                write_primitive(w, elem, item)?;
            }
            Ok(())
        }
        TypeKind::Nested(_) => Err(unsupported("an unresolved nested type")),
    }
}

/// Holder width in bytes of an enum or bitmask (XTypes 1.3 Table 40).
fn enum_width(e: &EnumDescriptor) -> usize {
    e.holder_size()
}

/// Write `v` on `width` bytes, accepting either its signed or its unsigned
/// reading, and refusing a value neither reading holds.
fn write_int(w: &mut KeyHolderWriter, width: usize, v: i64) -> Result<(), DynamicDataError> {
    let out_of_range =
        || DynamicDataError::InvalidOperation(format!("value {v} does not fit {width} byte(s)"));
    match width {
        1 => {
            let b = u8::try_from(v)
                .or_else(|_| i8::try_from(v).map(|x| x.to_be_bytes()[0]))
                .map_err(|_| out_of_range())?;
            w.write_u8(b);
        }
        2 => {
            let h = u16::try_from(v)
                .or_else(|_| i16::try_from(v).map(|x| u16::from_be_bytes(x.to_be_bytes())))
                .map_err(|_| out_of_range())?;
            w.write_u16(h);
        }
        4 => {
            let word = u32::try_from(v)
                .or_else(|_| i32::try_from(v).map(|x| u32::from_be_bytes(x.to_be_bytes())))
                .map_err(|_| out_of_range())?;
            w.write_u32(word);
        }
        _ => w.write_i64(v),
    }
    Ok(())
}

/// The discriminator, at the width its type declares.
fn write_discriminator(
    w: &mut KeyHolderWriter,
    u: &UnionDescriptor,
    disc: i64,
) -> Result<(), DynamicDataError> {
    match &resolve(&u.discriminator).kind {
        TypeKind::Enum(e) => write_int(w, enum_width(e), disc),
        TypeKind::Primitive(p) => match p {
            PrimitiveKind::Bool => {
                w.write_bool(disc != 0);
                Ok(())
            }
            PrimitiveKind::String { .. }
            | PrimitiveKind::WString { .. }
            | PrimitiveKind::F32
            | PrimitiveKind::F64
            | PrimitiveKind::LongDouble => Err(unsupported("this union discriminator type")),
            other => write_int(w, other.size().unwrap_or(4), disc),
        },
        _ => Err(unsupported("this union discriminator type")),
    }
}

fn write_primitive(
    w: &mut KeyHolderWriter,
    kind: PrimitiveKind,
    value: &DynamicValue,
) -> Result<(), DynamicDataError> {
    match (value, kind) {
        (DynamicValue::Bool(v), PrimitiveKind::Bool) => w.write_bool(*v),
        (DynamicValue::U8(v), PrimitiveKind::U8 | PrimitiveKind::Byte) => w.write_u8(*v),
        (DynamicValue::I8(v), PrimitiveKind::I8) => w.write_i8(*v),
        (DynamicValue::U16(v), PrimitiveKind::U16) => w.write_u16(*v),
        (DynamicValue::I16(v), PrimitiveKind::I16) => w.write_i16(*v),
        (DynamicValue::U32(v), PrimitiveKind::U32) => w.write_u32(*v),
        (DynamicValue::I32(v), PrimitiveKind::I32) => w.write_i32(*v),
        (DynamicValue::U64(v), PrimitiveKind::U64) => w.write_u64(*v),
        (DynamicValue::I64(v), PrimitiveKind::I64) => w.write_i64(*v),
        (DynamicValue::F32(v), PrimitiveKind::F32) => w.write_f32(*v),
        (DynamicValue::F64(v), PrimitiveKind::F64) => w.write_f64(*v),
        (DynamicValue::Char(c), PrimitiveKind::Char) => {
            let byte = u8::try_from(u32::from(*c)).map_err(|_| {
                DynamicDataError::InvalidOperation(format!("char {c:?} is not a char8"))
            })?;
            w.write_u8(byte);
        }
        (DynamicValue::String(s), PrimitiveKind::String { max_length }) => {
            if let Some(max) = max_length {
                if s.len() > max {
                    return Err(DynamicDataError::SequenceTooLong {
                        length: s.len(),
                        max,
                    });
                }
            }
            w.write_string(s);
        }
        (DynamicValue::WString(s), PrimitiveKind::WString { max_length }) => {
            if let Some(max) = max_length {
                let units = s.encode_utf16().count();
                if units > max {
                    return Err(DynamicDataError::SequenceTooLong { length: units, max });
                }
            }
            w.write_wstring(s);
        }
        (_, PrimitiveKind::LongDouble) => return Err(unsupported("long double")),
        _ => return Err(mismatch(&format!("{kind:?}"), value)),
    }
    Ok(())
}

/// Offset after `size` bytes aligned to `size` capped at 4, from `off`.
fn after_aligned(off: usize, align: usize, size: usize) -> usize {
    let align = align.clamp(1, 4);
    off.div_ceil(align)
        .saturating_mul(align)
        .saturating_add(size)
}

/// The largest end offset a value of `desc` can reach when serialized from
/// `off`, or `None` when it is unbounded. The maximum serialized size of the
/// KeyHolder is `max_end(desc, 0)` (RTPS 2.5 9.6.4.8 step 5).
fn max_end(desc: &TypeDescriptor, off: usize) -> Result<Option<usize>, DynamicDataError> {
    let desc = resolve(desc);
    match &desc.kind {
        TypeKind::Primitive(p) => Ok(primitive_max_end(*p, off)),
        TypeKind::Struct(fields) => {
            let mut end = off;
            for field in holder_members(desc, fields)? {
                if field.optional {
                    end = end.saturating_add(1);
                }
                match max_end(&field.type_desc, end)? {
                    Some(e) => end = e,
                    None => return Ok(None),
                }
            }
            Ok(Some(end))
        }
        TypeKind::Union(u) => {
            let Some(after_disc) = discriminator_max_end(u, off)? else {
                return Ok(None);
            };
            if u.discriminator_is_key {
                return Ok(Some(after_disc));
            }
            let mut end = after_disc;
            for case in u.cases.iter().chain(u.default_case.as_deref()) {
                match max_end(&case.type_desc, after_disc)? {
                    Some(e) => end = end.max(e),
                    None => return Ok(None),
                }
            }
            Ok(Some(end))
        }
        TypeKind::Enum(e) => {
            let width = enum_width(e);
            Ok(Some(after_aligned(off, width, width)))
        }
        TypeKind::Sequence(seq) => {
            let elem = plain_element(&seq.element_type)?;
            let Some(max) = seq.max_length else {
                return Ok(None);
            };
            let size = elem.size().unwrap_or(1);
            // The length word leaves the offset aligned at 4, which every
            // primitive element of size <= 4 or aligned at 4 keeps.
            Ok(Some(
                after_aligned(off, 4, 4).saturating_add(max.saturating_mul(size)),
            ))
        }
        TypeKind::Array(arr) => {
            let elem = plain_element(&arr.element_type)?;
            let size = elem.size().unwrap_or(1);
            Ok(Some(after_aligned(
                off,
                size,
                arr.length.saturating_mul(size),
            )))
        }
        TypeKind::Nested(_) => Err(unsupported("an unresolved nested type")),
    }
}

fn primitive_max_end(p: PrimitiveKind, off: usize) -> Option<usize> {
    match p {
        // Length word, bound in bytes, NUL.
        PrimitiveKind::String { max_length } => {
            max_length.map(|m| after_aligned(off, 4, 4).saturating_add(m.saturating_add(1)))
        }
        // Length word, two bytes per code unit, no NUL.
        PrimitiveKind::WString { max_length } => {
            max_length.map(|m| after_aligned(off, 4, 4).saturating_add(m.saturating_mul(2)))
        }
        other => {
            let size = other.size().unwrap_or(1);
            Some(after_aligned(off, size, size))
        }
    }
}

fn discriminator_max_end(
    u: &UnionDescriptor,
    off: usize,
) -> Result<Option<usize>, DynamicDataError> {
    match &resolve(&u.discriminator).kind {
        TypeKind::Enum(e) => {
            let width = enum_width(e);
            Ok(Some(after_aligned(off, width, width)))
        }
        TypeKind::Primitive(p) => Ok(primitive_max_end(*p, off)),
        _ => Err(unsupported("this union discriminator type")),
    }
}

#[cfg(test)]
mod tests;
