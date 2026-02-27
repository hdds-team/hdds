// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! CDR encoding/decoding for DynamicData.

use crate::dynamic::{DynamicData, DynamicValue, PrimitiveKind, TypeDescriptor, TypeKind};
use std::fmt;
use std::sync::Arc;

/// Errors for dynamic CDR operations.
#[derive(Debug)]
pub enum DynamicCdrError {
    BufferTooSmall { need: usize, have: usize },
    InvalidData(String),
    UnsupportedType(String),
    Utf8Error(std::string::FromUtf8Error),
    TypeMismatch { expected: String, found: String },
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
        }
    }
}

impl std::error::Error for DynamicCdrError {}

impl From<std::string::FromUtf8Error> for DynamicCdrError {
    fn from(e: std::string::FromUtf8Error) -> Self {
        Self::Utf8Error(e)
    }
}

/// Encode DynamicData to CDR bytes.
pub fn encode_dynamic(data: &DynamicData) -> Result<Vec<u8>, DynamicCdrError> {
    let mut encoder = CdrEncoder::new();
    encoder.encode_value(data.value(), &data.descriptor().kind)?;
    Ok(encoder.into_bytes())
}

/// Decode CDR bytes to DynamicData.
pub fn decode_dynamic(
    bytes: &[u8],
    descriptor: &Arc<TypeDescriptor>,
) -> Result<DynamicData, DynamicCdrError> {
    let mut decoder = CdrDecoder::new(bytes);
    let value = decoder.decode_value(&descriptor.kind)?;
    DynamicData::from_value(descriptor, value)
        .map_err(|e| DynamicCdrError::InvalidData(e.to_string()))
}

/// CDR Encoder for dynamic types.
struct CdrEncoder {
    buffer: Vec<u8>,
}

impl CdrEncoder {
    fn new() -> Self {
        Self { buffer: Vec::new() }
    }

    fn into_bytes(self) -> Vec<u8> {
        self.buffer
    }

    fn align(&mut self, alignment: usize) {
        let padding = (alignment - (self.buffer.len() % alignment)) % alignment;
        self.buffer.extend(std::iter::repeat_n(0, padding));
    }

    fn encode_value(
        &mut self,
        value: &DynamicValue,
        kind: &TypeKind,
    ) -> Result<(), DynamicCdrError> {
        match kind {
            TypeKind::Primitive(p) => self.encode_primitive(value, *p),
            TypeKind::Struct(fields) => {
                if let DynamicValue::Struct(map) = value {
                    for field in fields {
                        let field_value = map.get(&field.name).ok_or_else(|| {
                            DynamicCdrError::InvalidData(format!("Missing field: {}", field.name))
                        })?;
                        self.encode_value(field_value, &field.type_desc.kind)?;
                    }
                    Ok(())
                } else {
                    Err(DynamicCdrError::TypeMismatch {
                        expected: "struct".into(),
                        found: format!("{:?}", value),
                    })
                }
            }
            TypeKind::Sequence(seq) => {
                if let DynamicValue::Sequence(vec) = value {
                    // Write length
                    self.align(4);
                    self.buffer.extend(&(vec.len() as u32).to_le_bytes());
                    // Write elements
                    for elem in vec {
                        self.encode_value(elem, &seq.element_type.kind)?;
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
                    for elem in vec {
                        self.encode_value(elem, &arr.element_type.kind)?;
                    }
                    Ok(())
                } else {
                    Err(DynamicCdrError::TypeMismatch {
                        expected: "array".into(),
                        found: format!("{:?}", value),
                    })
                }
            }
            TypeKind::Enum(_e) => {
                if let DynamicValue::Enum(val, _) = value {
                    self.align(4);
                    self.buffer.extend(&(*val as u32).to_le_bytes());
                    Ok(())
                } else {
                    Err(DynamicCdrError::TypeMismatch {
                        expected: "enum".into(),
                        found: format!("{:?}", value),
                    })
                }
            }
            TypeKind::Union(u) => {
                if let DynamicValue::Union(disc, _, inner) = value {
                    // Write discriminator
                    self.encode_value(&DynamicValue::I64(*disc), &u.discriminator.kind)?;
                    // Find case and write value
                    if let Some(case) = u.case_by_discriminator(*disc) {
                        self.encode_value(inner, &case.type_desc.kind)?;
                    }
                    Ok(())
                } else {
                    Err(DynamicCdrError::TypeMismatch {
                        expected: "union".into(),
                        found: format!("{:?}", value),
                    })
                }
            }
            TypeKind::Nested(inner) => self.encode_value(value, &inner.kind),
        }
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
            (DynamicValue::U8(v), PrimitiveKind::U8) => {
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
                self.align(8);
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
                self.align(8);
                self.buffer.extend(&v.to_le_bytes());
            }
            (DynamicValue::F32(v), PrimitiveKind::F32) => {
                self.align(4);
                self.buffer.extend(&v.to_le_bytes());
            }
            (DynamicValue::F64(v), PrimitiveKind::F64) => {
                self.align(8);
                self.buffer.extend(&v.to_le_bytes());
            }
            (DynamicValue::LongDouble(v), PrimitiveKind::LongDouble) => {
                self.align(crate::dynamic::LONG_DOUBLE_ALIGN);
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
                self.buffer
                    .extend(&((bytes.len() + 1) as u32).to_le_bytes());
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
                self.buffer
                    .extend(&((chars.len() + 1) as u32).to_le_bytes());
                for c in chars {
                    self.buffer.extend(&c.to_le_bytes());
                }
                self.buffer.extend(&0u16.to_le_bytes()); // Null terminator
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
}

impl<'a> CdrDecoder<'a> {
    fn new(buffer: &'a [u8]) -> Self {
        Self { buffer, offset: 0 }
    }

    fn remaining(&self) -> usize {
        self.buffer.len().saturating_sub(self.offset)
    }

    fn align(&mut self, alignment: usize) {
        self.offset = (self.offset + alignment - 1) & !(alignment - 1);
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
        match kind {
            TypeKind::Primitive(p) => self.decode_primitive(*p),
            TypeKind::Struct(fields) => {
                let mut map = std::collections::HashMap::new();
                for field in fields {
                    let value = self.decode_value(&field.type_desc.kind)?;
                    map.insert(field.name.clone(), value);
                }
                Ok(DynamicValue::Struct(map))
            }
            TypeKind::Sequence(seq) => {
                self.align(4);
                let bytes = self.read_bytes(4)?;
                let len = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
                let mut vec = Vec::with_capacity(len);
                for _ in 0..len {
                    vec.push(self.decode_value(&seq.element_type.kind)?);
                }
                Ok(DynamicValue::Sequence(vec))
            }
            TypeKind::Array(arr) => {
                let mut vec = Vec::with_capacity(arr.length);
                for _ in 0..arr.length {
                    vec.push(self.decode_value(&arr.element_type.kind)?);
                }
                Ok(DynamicValue::Array(vec))
            }
            TypeKind::Enum(e) => {
                self.align(4);
                let bytes = self.read_bytes(4)?;
                let val = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as i64;
                let name = e
                    .variant_by_value(val)
                    .map(|v| v.name.clone())
                    .unwrap_or_default();
                Ok(DynamicValue::Enum(val, name))
            }
            TypeKind::Union(u) => {
                // Read discriminator
                let disc_value = self.decode_value(&u.discriminator.kind)?;
                let disc = match disc_value {
                    DynamicValue::I32(v) => v as i64,
                    DynamicValue::U32(v) => v as i64,
                    DynamicValue::I64(v) => v,
                    DynamicValue::U64(v) => v as i64,
                    _ => 0,
                };

                // Find case and decode value
                if let Some(case) = u.case_by_discriminator(disc) {
                    let inner = self.decode_value(&case.type_desc.kind)?;
                    Ok(DynamicValue::Union(
                        disc,
                        case.name.clone(),
                        Box::new(inner),
                    ))
                } else {
                    Ok(DynamicValue::Union(
                        disc,
                        String::new(),
                        Box::new(DynamicValue::Null),
                    ))
                }
            }
            TypeKind::Nested(inner) => self.decode_value(&inner.kind),
        }
    }

    fn decode_primitive(&mut self, kind: PrimitiveKind) -> Result<DynamicValue, DynamicCdrError> {
        match kind {
            PrimitiveKind::Bool => {
                let bytes = self.read_bytes(1)?;
                Ok(DynamicValue::Bool(bytes[0] != 0))
            }
            PrimitiveKind::U8 => {
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
                self.align(8);
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
                self.align(8);
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
                self.align(8);
                let bytes = self.read_bytes(8)?;
                Ok(DynamicValue::F64(f64::from_le_bytes([
                    bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
                ])))
            }
            PrimitiveKind::LongDouble => {
                self.align(crate::dynamic::LONG_DOUBLE_ALIGN);
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
                let len =
                    u32::from_le_bytes([len_bytes[0], len_bytes[1], len_bytes[2], len_bytes[3]])
                        as usize;
                if let Some(max) = max_length {
                    if len > max + 1 {
                        return Err(DynamicCdrError::InvalidData("string exceeds bound".into()));
                    }
                }
                if len == 0 {
                    return Ok(DynamicValue::String(String::new()));
                }
                let str_bytes = self.read_bytes(len)?;
                // Remove null terminator
                let actual_len = if len > 0 && str_bytes[len - 1] == 0 {
                    len - 1
                } else {
                    len
                };
                let s = String::from_utf8(str_bytes[..actual_len].to_vec())?;
                Ok(DynamicValue::String(s))
            }
            PrimitiveKind::WString { max_length } => {
                self.align(4);
                let len_bytes = self.read_bytes(4)?;
                let len =
                    u32::from_le_bytes([len_bytes[0], len_bytes[1], len_bytes[2], len_bytes[3]])
                        as usize;
                if let Some(max) = max_length {
                    if len > max + 1 {
                        return Err(DynamicCdrError::InvalidData("wstring exceeds bound".into()));
                    }
                }
                if len == 0 {
                    return Ok(DynamicValue::WString(String::new()));
                }
                let mut chars = Vec::with_capacity(len);
                for _ in 0..len {
                    let char_bytes = self.read_bytes(2)?;
                    chars.push(u16::from_le_bytes([char_bytes[0], char_bytes[1]]));
                }
                // Remove null terminator
                if chars.last() == Some(&0) {
                    chars.pop();
                }
                let s = String::from_utf16(&chars)
                    .map_err(|_| DynamicCdrError::InvalidData("Invalid UTF-16".into()))?;
                Ok(DynamicValue::WString(s))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
}
