// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! DynamicData container for runtime data manipulation.

use crate::dynamic::{DynamicValue, PrimitiveKind, TypeDescriptor, TypeKind};
use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

/// Errors for DynamicData operations.
#[derive(Debug)]
pub enum DynamicDataError {
    FieldNotFound(String),
    TypeMismatch { expected: String, got: String },
    InvalidOperation(String),
    IndexOutOfBounds { index: usize, length: usize },
    SequenceTooLong { length: usize, max: usize },
}

impl fmt::Display for DynamicDataError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FieldNotFound(name) => write!(f, "Field not found: {}", name),
            Self::TypeMismatch { expected, got } => {
                write!(f, "Type mismatch: expected {}, got {}", expected, got)
            }
            Self::InvalidOperation(msg) => write!(f, "Invalid operation for type: {}", msg),
            Self::IndexOutOfBounds { index, length } => {
                write!(f, "Index out of bounds: {} >= {}", index, length)
            }
            Self::SequenceTooLong { length, max } => {
                write!(f, "Sequence length exceeds maximum: {} > {}", length, max)
            }
        }
    }
}

impl std::error::Error for DynamicDataError {}

/// Dynamic data container with runtime type checking.
#[derive(Debug, Clone)]
pub struct DynamicData {
    /// Type descriptor.
    descriptor: Arc<TypeDescriptor>,
    /// Actual value.
    value: DynamicValue,
}

impl DynamicData {
    /// Create new DynamicData with default values.
    pub fn new(descriptor: &Arc<TypeDescriptor>) -> Self {
        let value = Self::default_value(&descriptor.kind);
        Self {
            descriptor: descriptor.clone(),
            value,
        }
    }

    /// Create from existing value (with validation).
    pub fn from_value(
        descriptor: &Arc<TypeDescriptor>,
        value: DynamicValue,
    ) -> Result<Self, DynamicDataError> {
        let data = Self {
            descriptor: descriptor.clone(),
            value,
        };
        // Could add validation here
        Ok(data)
    }

    /// Get the type descriptor.
    pub fn descriptor(&self) -> &Arc<TypeDescriptor> {
        &self.descriptor
    }

    /// Get the type name.
    pub fn type_name(&self) -> &str {
        &self.descriptor.name
    }

    /// Get the underlying value.
    pub fn value(&self) -> &DynamicValue {
        &self.value
    }

    /// Get mutable reference to value.
    pub fn value_mut(&mut self) -> &mut DynamicValue {
        &mut self.value
    }

    /// Into inner value.
    pub fn into_value(self) -> DynamicValue {
        self.value
    }

    /// Get a field value by name.
    pub fn get<T: FromDynamicValue>(&self, name: &str) -> Result<T, DynamicDataError> {
        let field_value = self.get_field(name)?;
        T::from_dynamic(field_value)
    }

    /// Set a field value by name.
    pub fn set<T: IntoDynamicValue>(
        &mut self,
        name: &str,
        value: T,
    ) -> Result<(), DynamicDataError> {
        // Verify field exists
        let _field = self
            .descriptor
            .field(name)
            .ok_or_else(|| DynamicDataError::FieldNotFound(name.to_string()))?;

        let dyn_value = value.into_dynamic();

        match &mut self.value {
            DynamicValue::Struct(fields) => {
                fields.insert(name.to_string(), dyn_value);
                Ok(())
            }
            _ => Err(DynamicDataError::InvalidOperation(
                "set requires struct type".into(),
            )),
        }
    }

    /// Get field by name.
    pub fn get_field(&self, name: &str) -> Result<&DynamicValue, DynamicDataError> {
        // Verify field exists in descriptor
        if self.descriptor.field(name).is_none() {
            return Err(DynamicDataError::FieldNotFound(name.to_string()));
        }

        match &self.value {
            DynamicValue::Struct(fields) => fields
                .get(name)
                .ok_or_else(|| DynamicDataError::FieldNotFound(name.to_string())),
            _ => Err(DynamicDataError::InvalidOperation(
                "get_field requires struct type".into(),
            )),
        }
    }

    /// Get mutable field by name.
    pub fn get_field_mut(&mut self, name: &str) -> Result<&mut DynamicValue, DynamicDataError> {
        // Verify field exists in descriptor
        if self.descriptor.field(name).is_none() {
            return Err(DynamicDataError::FieldNotFound(name.to_string()));
        }

        match &mut self.value {
            DynamicValue::Struct(fields) => fields
                .get_mut(name)
                .ok_or_else(|| DynamicDataError::FieldNotFound(name.to_string())),
            _ => Err(DynamicDataError::InvalidOperation(
                "get_field_mut requires struct type".into(),
            )),
        }
    }

    /// Get sequence element by index.
    pub fn get_element(&self, index: usize) -> Result<&DynamicValue, DynamicDataError> {
        match &self.value {
            DynamicValue::Sequence(seq) | DynamicValue::Array(seq) => {
                seq.get(index).ok_or(DynamicDataError::IndexOutOfBounds {
                    index,
                    length: seq.len(),
                })
            }
            _ => Err(DynamicDataError::InvalidOperation(
                "get_element requires sequence/array type".into(),
            )),
        }
    }

    /// Set sequence element by index.
    pub fn set_element(
        &mut self,
        index: usize,
        value: DynamicValue,
    ) -> Result<(), DynamicDataError> {
        match &mut self.value {
            DynamicValue::Sequence(seq) | DynamicValue::Array(seq) => {
                if index >= seq.len() {
                    return Err(DynamicDataError::IndexOutOfBounds {
                        index,
                        length: seq.len(),
                    });
                }
                seq[index] = value;
                Ok(())
            }
            _ => Err(DynamicDataError::InvalidOperation(
                "set_element requires sequence/array type".into(),
            )),
        }
    }

    /// Push element to sequence.
    pub fn push_element(&mut self, value: DynamicValue) -> Result<(), DynamicDataError> {
        match &mut self.value {
            DynamicValue::Sequence(seq) => {
                // Check max length if bounded
                if let TypeKind::Sequence(desc) = &self.descriptor.kind {
                    if let Some(max) = desc.max_length {
                        if seq.len() >= max {
                            return Err(DynamicDataError::SequenceTooLong {
                                length: seq.len() + 1,
                                max,
                            });
                        }
                    }
                }
                seq.push(value);
                Ok(())
            }
            _ => Err(DynamicDataError::InvalidOperation(
                "push_element requires sequence type".into(),
            )),
        }
    }

    /// Get sequence/array length.
    pub fn len(&self) -> Result<usize, DynamicDataError> {
        match &self.value {
            DynamicValue::Sequence(seq) | DynamicValue::Array(seq) => Ok(seq.len()),
            _ => Err(DynamicDataError::InvalidOperation(
                "len requires sequence/array type".into(),
            )),
        }
    }

    /// Check if sequence/array is empty.
    pub fn is_empty(&self) -> Result<bool, DynamicDataError> {
        self.len().map(|l| l == 0)
    }

    /// Iterate over fields (for structs).
    pub fn fields(&self) -> impl Iterator<Item = (&str, &DynamicValue)> {
        match &self.value {
            DynamicValue::Struct(fields) => {
                Box::new(fields.iter().map(|(k, v)| (k.as_str(), v))) as Box<dyn Iterator<Item = _>>
            }
            _ => Box::new(std::iter::empty()),
        }
    }

    /// Iterate over elements (for sequences/arrays).
    pub fn elements(&self) -> impl Iterator<Item = &DynamicValue> {
        match &self.value {
            DynamicValue::Sequence(seq) | DynamicValue::Array(seq) => {
                Box::new(seq.iter()) as Box<dyn Iterator<Item = _>>
            }
            _ => Box::new(std::iter::empty()),
        }
    }

    /// Create default value for a type kind.
    fn default_value(kind: &TypeKind) -> DynamicValue {
        match kind {
            TypeKind::Primitive(p) => Self::default_primitive(*p),
            TypeKind::Struct(fields) => {
                let mut map = HashMap::new();
                for field in fields {
                    map.insert(
                        field.name.clone(),
                        Self::default_value(&field.type_desc.kind),
                    );
                }
                DynamicValue::Struct(map)
            }
            TypeKind::Sequence(_) => DynamicValue::Sequence(Vec::new()),
            TypeKind::Array(arr) => {
                let elem_default = Self::default_value(&arr.element_type.kind);
                DynamicValue::Array(vec![elem_default; arr.length])
            }
            TypeKind::Enum(e) => {
                let first = e.variants.first();
                match first {
                    Some(v) => DynamicValue::Enum(v.value, v.name.clone()),
                    None => DynamicValue::Enum(0, String::new()),
                }
            }
            TypeKind::Union(u) => {
                let first_case = u.cases.first().or(u.default_case.as_deref());
                match first_case {
                    Some(c) => {
                        let disc = c.labels.first().copied().unwrap_or(0);
                        let inner = Self::default_value(&c.type_desc.kind);
                        DynamicValue::Union(disc, c.name.clone(), Box::new(inner))
                    }
                    None => DynamicValue::Union(0, String::new(), Box::new(DynamicValue::Null)),
                }
            }
            TypeKind::Nested(inner) => Self::default_value(&inner.kind),
        }
    }

    /// Create default value for a primitive.
    // @audit-ok: Simple pattern matching (cyclo 16, cogni 1) - default value dispatch table
    fn default_primitive(kind: PrimitiveKind) -> DynamicValue {
        match kind {
            PrimitiveKind::Bool => DynamicValue::Bool(false),
            PrimitiveKind::U8 => DynamicValue::U8(0),
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
        }
    }
}

impl PartialEq for DynamicData {
    fn eq(&self, other: &Self) -> bool {
        self.descriptor.name == other.descriptor.name && self.value == other.value
    }
}

/// Trait for converting from DynamicValue.
pub trait FromDynamicValue: Sized {
    fn from_dynamic(value: &DynamicValue) -> Result<Self, DynamicDataError>;
}

/// Trait for converting to DynamicValue.
pub trait IntoDynamicValue {
    fn into_dynamic(self) -> DynamicValue;
}

// Implement FromDynamicValue for primitives
macro_rules! impl_from_dynamic {
    ($ty:ty, $variant:ident, $name:expr) => {
        impl FromDynamicValue for $ty {
            fn from_dynamic(value: &DynamicValue) -> Result<Self, DynamicDataError> {
                match value {
                    DynamicValue::$variant(v) => Ok(*v),
                    other => Err(DynamicDataError::TypeMismatch {
                        expected: $name.to_string(),
                        got: format!("{:?}", other),
                    }),
                }
            }
        }
    };
}

impl_from_dynamic!(bool, Bool, "bool");
impl_from_dynamic!(u8, U8, "u8");
impl_from_dynamic!(u16, U16, "u16");
impl_from_dynamic!(u32, U32, "u32");
impl_from_dynamic!(u64, U64, "u64");
impl_from_dynamic!(i8, I8, "i8");
impl_from_dynamic!(i16, I16, "i16");
impl_from_dynamic!(i32, I32, "i32");
impl_from_dynamic!(i64, I64, "i64");
impl_from_dynamic!(f32, F32, "f32");
impl_from_dynamic!(f64, F64, "f64");
impl_from_dynamic!(char, Char, "char");

impl FromDynamicValue for [u8; crate::dynamic::LONG_DOUBLE_SIZE] {
    fn from_dynamic(value: &DynamicValue) -> Result<Self, DynamicDataError> {
        match value {
            DynamicValue::LongDouble(v) => Ok(*v),
            other => Err(DynamicDataError::TypeMismatch {
                expected: "long_double".to_string(),
                got: format!("{:?}", other),
            }),
        }
    }
}

impl FromDynamicValue for String {
    fn from_dynamic(value: &DynamicValue) -> Result<Self, DynamicDataError> {
        match value {
            DynamicValue::String(s) | DynamicValue::WString(s) => Ok(s.clone()),
            other => Err(DynamicDataError::TypeMismatch {
                expected: "string".to_string(),
                got: format!("{:?}", other),
            }),
        }
    }
}

// Implement IntoDynamicValue for primitives
macro_rules! impl_into_dynamic {
    ($ty:ty, $variant:ident) => {
        impl IntoDynamicValue for $ty {
            fn into_dynamic(self) -> DynamicValue {
                DynamicValue::$variant(self)
            }
        }
    };
}

impl_into_dynamic!(bool, Bool);
impl_into_dynamic!(u8, U8);
impl_into_dynamic!(u16, U16);
impl_into_dynamic!(u32, U32);
impl_into_dynamic!(u64, U64);
impl_into_dynamic!(i8, I8);
impl_into_dynamic!(i16, I16);
impl_into_dynamic!(i32, I32);
impl_into_dynamic!(i64, I64);
impl_into_dynamic!(f32, F32);
impl_into_dynamic!(f64, F64);
impl_into_dynamic!(char, Char);

impl IntoDynamicValue for [u8; crate::dynamic::LONG_DOUBLE_SIZE] {
    fn into_dynamic(self) -> DynamicValue {
        DynamicValue::LongDouble(self)
    }
}

impl IntoDynamicValue for String {
    fn into_dynamic(self) -> DynamicValue {
        DynamicValue::String(self)
    }
}

impl IntoDynamicValue for &str {
    fn into_dynamic(self) -> DynamicValue {
        DynamicValue::String(self.to_string())
    }
}

impl IntoDynamicValue for DynamicValue {
    fn into_dynamic(self) -> DynamicValue {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dynamic::TypeDescriptorBuilder;

    #[test]
    fn test_dynamic_data_struct() {
        let desc = Arc::new(
            TypeDescriptorBuilder::new("TestStruct")
                .field("x", PrimitiveKind::I32)
                .field("y", PrimitiveKind::F64)
                .field("name", PrimitiveKind::String { max_length: None })
                .build(),
        );

        let mut data = DynamicData::new(&desc);

        // Set fields
        data.set("x", 42i32).expect("set x");
        data.set("y", std::f64::consts::PI).expect("set y");
        data.set("name", "test").expect("set name");

        // Get fields
        assert_eq!(data.get::<i32>("x").expect("get x"), 42);
        assert_eq!(data.get::<f64>("y").expect("get y"), std::f64::consts::PI);
        assert_eq!(data.get::<String>("name").expect("get name"), "test");

        // Non-existent field
        assert!(data.get::<i32>("z").is_err());
    }

    #[test]
    fn test_dynamic_data_iteration() {
        let desc = Arc::new(
            TypeDescriptorBuilder::new("Point")
                .field("x", PrimitiveKind::I32)
                .field("y", PrimitiveKind::I32)
                .build(),
        );

        let mut data = DynamicData::new(&desc);
        data.set("x", 10i32).expect("set x");
        data.set("y", 20i32).expect("set y");

        let fields: Vec<_> = data.fields().collect();
        assert_eq!(fields.len(), 2);
    }
}
