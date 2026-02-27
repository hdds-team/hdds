// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Dynamic value types.

use std::collections::HashMap;

/// A dynamic value that can hold any DDS type.
#[derive(Debug, Clone, PartialEq)]
pub enum DynamicValue {
    // Primitives
    Bool(bool),
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    I8(i8),
    I16(i16),
    I32(i32),
    I64(i64),
    F32(f32),
    F64(f64),
    LongDouble([u8; crate::dynamic::LONG_DOUBLE_SIZE]),
    Char(char),
    String(String),
    WString(String),

    // Composites
    Struct(HashMap<String, DynamicValue>),
    Sequence(Vec<DynamicValue>),
    Array(Vec<DynamicValue>),
    Enum(i64, String),                     // (value, variant_name)
    Union(i64, String, Box<DynamicValue>), // (discriminator, case_name, value)

    // Special
    Null,
}

impl DynamicValue {
    /// Check if value is null.
    pub fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }

    /// Try to get as bool.
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(v) => Some(*v),
            _ => None,
        }
    }

    /// Try to get as u8.
    pub fn as_u8(&self) -> Option<u8> {
        match self {
            Self::U8(v) => Some(*v),
            _ => None,
        }
    }

    /// Try to get as u16.
    pub fn as_u16(&self) -> Option<u16> {
        match self {
            Self::U16(v) => Some(*v),
            _ => None,
        }
    }

    /// Try to get as u32.
    pub fn as_u32(&self) -> Option<u32> {
        match self {
            Self::U32(v) => Some(*v),
            _ => None,
        }
    }

    /// Try to get as u64.
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Self::U64(v) => Some(*v),
            _ => None,
        }
    }

    /// Try to get as i8.
    pub fn as_i8(&self) -> Option<i8> {
        match self {
            Self::I8(v) => Some(*v),
            _ => None,
        }
    }

    /// Try to get as i16.
    pub fn as_i16(&self) -> Option<i16> {
        match self {
            Self::I16(v) => Some(*v),
            _ => None,
        }
    }

    /// Try to get as i32.
    pub fn as_i32(&self) -> Option<i32> {
        match self {
            Self::I32(v) => Some(*v),
            _ => None,
        }
    }

    /// Try to get as i64.
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Self::I64(v) => Some(*v),
            _ => None,
        }
    }

    /// Try to get as f32.
    pub fn as_f32(&self) -> Option<f32> {
        match self {
            Self::F32(v) => Some(*v),
            _ => None,
        }
    }

    /// Try to get as f64.
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Self::F64(v) => Some(*v),
            _ => None,
        }
    }

    /// Try to get as string.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(v) | Self::WString(v) => Some(v),
            _ => None,
        }
    }

    /// Try to get as sequence.
    pub fn as_sequence(&self) -> Option<&[DynamicValue]> {
        match self {
            Self::Sequence(v) | Self::Array(v) => Some(v),
            _ => None,
        }
    }

    /// Try to get struct field.
    pub fn get_field(&self, name: &str) -> Option<&DynamicValue> {
        match self {
            Self::Struct(fields) => fields.get(name),
            _ => None,
        }
    }

    /// Try to get mutable struct field.
    pub fn get_field_mut(&mut self, name: &str) -> Option<&mut DynamicValue> {
        match self {
            Self::Struct(fields) => fields.get_mut(name),
            _ => None,
        }
    }

    /// Set struct field.
    pub fn set_field(&mut self, name: impl Into<String>, value: DynamicValue) -> bool {
        match self {
            Self::Struct(fields) => {
                fields.insert(name.into(), value);
                true
            }
            _ => false,
        }
    }

    /// Get enum variant name.
    pub fn enum_variant(&self) -> Option<&str> {
        match self {
            Self::Enum(_, name) => Some(name),
            _ => None,
        }
    }

    /// Get enum value.
    pub fn enum_value(&self) -> Option<i64> {
        match self {
            Self::Enum(val, _) => Some(*val),
            _ => None,
        }
    }

    /// Get union discriminator.
    pub fn union_discriminator(&self) -> Option<i64> {
        match self {
            Self::Union(disc, _, _) => Some(*disc),
            _ => None,
        }
    }

    /// Get union value.
    pub fn union_value(&self) -> Option<&DynamicValue> {
        match self {
            Self::Union(_, _, val) => Some(val),
            _ => None,
        }
    }
}

// Conversion traits
impl From<bool> for DynamicValue {
    fn from(v: bool) -> Self {
        Self::Bool(v)
    }
}

impl From<u8> for DynamicValue {
    fn from(v: u8) -> Self {
        Self::U8(v)
    }
}

impl From<u16> for DynamicValue {
    fn from(v: u16) -> Self {
        Self::U16(v)
    }
}

impl From<u32> for DynamicValue {
    fn from(v: u32) -> Self {
        Self::U32(v)
    }
}

impl From<u64> for DynamicValue {
    fn from(v: u64) -> Self {
        Self::U64(v)
    }
}

impl From<i8> for DynamicValue {
    fn from(v: i8) -> Self {
        Self::I8(v)
    }
}

impl From<i16> for DynamicValue {
    fn from(v: i16) -> Self {
        Self::I16(v)
    }
}

impl From<i32> for DynamicValue {
    fn from(v: i32) -> Self {
        Self::I32(v)
    }
}

impl From<i64> for DynamicValue {
    fn from(v: i64) -> Self {
        Self::I64(v)
    }
}

impl From<f32> for DynamicValue {
    fn from(v: f32) -> Self {
        Self::F32(v)
    }
}

impl From<f64> for DynamicValue {
    fn from(v: f64) -> Self {
        Self::F64(v)
    }
}

impl From<char> for DynamicValue {
    fn from(v: char) -> Self {
        Self::Char(v)
    }
}

impl From<String> for DynamicValue {
    fn from(v: String) -> Self {
        Self::String(v)
    }
}

impl From<&str> for DynamicValue {
    fn from(v: &str) -> Self {
        Self::String(v.to_string())
    }
}

impl<T: Into<DynamicValue>> From<Vec<T>> for DynamicValue {
    fn from(v: Vec<T>) -> Self {
        Self::Sequence(v.into_iter().map(Into::into).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_primitive_values() {
        let v = DynamicValue::from(42u32);
        assert_eq!(v.as_u32(), Some(42));
        assert_eq!(v.as_i32(), None);

        let v = DynamicValue::from(std::f64::consts::PI);
        assert_eq!(v.as_f64(), Some(std::f64::consts::PI));

        let v = DynamicValue::from("hello");
        assert_eq!(v.as_str(), Some("hello"));
    }

    #[test]
    fn test_struct_value() {
        let mut v = DynamicValue::Struct(HashMap::new());
        v.set_field("x", 10i32.into());
        v.set_field("y", 20i32.into());

        assert_eq!(v.get_field("x").and_then(|f| f.as_i32()), Some(10));
        assert_eq!(v.get_field("y").and_then(|f| f.as_i32()), Some(20));
        assert!(v.get_field("z").is_none());
    }

    #[test]
    fn test_sequence_value() {
        let v = DynamicValue::from(vec![1u32, 2, 3, 4, 5]);
        let seq = v.as_sequence().expect("sequence");
        assert_eq!(seq.len(), 5);
        assert_eq!(seq[2].as_u32(), Some(3));
    }

    #[test]
    fn test_enum_value() {
        let v = DynamicValue::Enum(1, "GREEN".to_string());
        assert_eq!(v.enum_variant(), Some("GREEN"));
        assert_eq!(v.enum_value(), Some(1));
    }

    #[test]
    fn test_union_value() {
        let inner = DynamicValue::from(42i32);
        let v = DynamicValue::Union(1, "int_val".to_string(), Box::new(inner));
        assert_eq!(v.union_discriminator(), Some(1));
        assert_eq!(v.union_value().and_then(|v| v.as_i32()), Some(42));
    }
}
