// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Type descriptors for runtime type information.

use crate::dynamic::{LONG_DOUBLE_ALIGN, LONG_DOUBLE_SIZE};
use std::sync::Arc;

/// Primitive type kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PrimitiveKind {
    Bool,
    U8,
    U16,
    U32,
    U64,
    I8,
    I16,
    I32,
    I64,
    F32,
    F64,
    LongDouble,
    Char,
    String { max_length: Option<usize> },
    WString { max_length: Option<usize> },
}

impl PrimitiveKind {
    /// Get the size in bytes (None for strings).
    pub fn size(&self) -> Option<usize> {
        match self {
            Self::Bool | Self::U8 | Self::I8 | Self::Char => Some(1),
            Self::U16 | Self::I16 => Some(2),
            Self::U32 | Self::I32 | Self::F32 => Some(4),
            Self::U64 | Self::I64 | Self::F64 => Some(8),
            Self::LongDouble => Some(LONG_DOUBLE_SIZE),
            Self::String { .. } | Self::WString { .. } => None,
        }
    }

    /// Get CDR alignment requirement.
    pub fn alignment(&self) -> usize {
        match self {
            Self::Bool | Self::U8 | Self::I8 | Self::Char => 1,
            Self::U16 | Self::I16 => 2,
            Self::U32 | Self::I32 | Self::F32 | Self::String { .. } | Self::WString { .. } => 4,
            Self::U64 | Self::I64 | Self::F64 => 8,
            Self::LongDouble => LONG_DOUBLE_ALIGN,
        }
    }
}

/// Type kind enumeration.
#[derive(Debug, Clone, PartialEq)]
pub enum TypeKind {
    /// Primitive type.
    Primitive(PrimitiveKind),
    /// Struct with named fields.
    Struct(Vec<FieldDescriptor>),
    /// Sequence (dynamic length).
    Sequence(SequenceDescriptor),
    /// Array (fixed length).
    Array(ArrayDescriptor),
    /// Enumeration.
    Enum(EnumDescriptor),
    /// Union with discriminator.
    Union(UnionDescriptor),
    /// Nested type reference.
    Nested(Arc<TypeDescriptor>),
}

/// A complete type descriptor.
#[derive(Debug, Clone, PartialEq)]
pub struct TypeDescriptor {
    /// Type name.
    pub name: String,
    /// Type kind.
    pub kind: TypeKind,
}

impl TypeDescriptor {
    /// Create a new type descriptor.
    pub fn new(name: impl Into<String>, kind: TypeKind) -> Self {
        Self {
            name: name.into(),
            kind,
        }
    }

    /// Create a primitive type descriptor.
    pub fn primitive(name: impl Into<String>, kind: PrimitiveKind) -> Self {
        Self::new(name, TypeKind::Primitive(kind))
    }

    /// Create a struct type descriptor.
    pub fn struct_type(name: impl Into<String>, fields: Vec<FieldDescriptor>) -> Self {
        Self::new(name, TypeKind::Struct(fields))
    }

    /// Check if this is a primitive type.
    pub fn is_primitive(&self) -> bool {
        matches!(self.kind, TypeKind::Primitive(_))
    }

    /// Check if this is a struct type.
    pub fn is_struct(&self) -> bool {
        matches!(self.kind, TypeKind::Struct(_))
    }

    /// Get fields if this is a struct.
    pub fn fields(&self) -> Option<&[FieldDescriptor]> {
        match &self.kind {
            TypeKind::Struct(fields) => Some(fields),
            _ => None,
        }
    }

    /// Get field by name.
    pub fn field(&self, name: &str) -> Option<&FieldDescriptor> {
        self.fields()?.iter().find(|f| f.name == name)
    }

    /// Get field index by name.
    pub fn field_index(&self, name: &str) -> Option<usize> {
        self.fields()?.iter().position(|f| f.name == name)
    }

    /// Calculate minimum CDR size (without strings/sequences).
    pub fn min_size(&self) -> usize {
        match &self.kind {
            TypeKind::Primitive(p) => p.size().unwrap_or(4), // String: 4 bytes for length
            TypeKind::Struct(fields) => {
                let mut size = 0;
                for field in fields {
                    // Align
                    let align = field.type_desc.alignment();
                    size = (size + align - 1) & !(align - 1);
                    size += field.type_desc.min_size();
                }
                size
            }
            TypeKind::Sequence(_) => 4, // Just the length
            TypeKind::Array(arr) => arr.element_type.min_size() * arr.length,
            TypeKind::Enum(_) => 4,
            TypeKind::Union(u) => {
                4 + u
                    .cases
                    .iter()
                    .map(|c| c.type_desc.min_size())
                    .max()
                    .unwrap_or(0)
            }
            TypeKind::Nested(inner) => inner.min_size(),
        }
    }

    /// Get alignment requirement.
    pub fn alignment(&self) -> usize {
        match &self.kind {
            TypeKind::Primitive(p) => p.alignment(),
            TypeKind::Struct(fields) => fields
                .iter()
                .map(|f| f.type_desc.alignment())
                .max()
                .unwrap_or(1),
            TypeKind::Sequence(seq) => seq.element_type.alignment().max(4),
            TypeKind::Array(arr) => arr.element_type.alignment(),
            TypeKind::Enum(_) => 4,
            TypeKind::Union(u) => u.discriminator.alignment().max(
                u.cases
                    .iter()
                    .map(|c| c.type_desc.alignment())
                    .max()
                    .unwrap_or(1),
            ),
            TypeKind::Nested(inner) => inner.alignment(),
        }
    }
}

/// Field descriptor for struct members.
#[derive(Debug, Clone, PartialEq)]
pub struct FieldDescriptor {
    /// Field name.
    pub name: String,
    /// Field type.
    pub type_desc: Arc<TypeDescriptor>,
    /// Field ID (for extensible types).
    pub id: Option<u32>,
    /// Is optional (@optional annotation).
    pub optional: bool,
    /// Default value (if any).
    pub default: Option<String>,
}

impl FieldDescriptor {
    /// Create a new field descriptor.
    pub fn new(name: impl Into<String>, type_desc: Arc<TypeDescriptor>) -> Self {
        Self {
            name: name.into(),
            type_desc,
            id: None,
            optional: false,
            default: None,
        }
    }

    /// Set field ID.
    pub fn with_id(mut self, id: u32) -> Self {
        self.id = Some(id);
        self
    }

    /// Mark as optional.
    pub fn optional(mut self) -> Self {
        self.optional = true;
        self
    }

    /// Set default value.
    pub fn with_default(mut self, default: impl Into<String>) -> Self {
        self.default = Some(default.into());
        self
    }
}

/// Sequence type descriptor.
#[derive(Debug, Clone, PartialEq)]
pub struct SequenceDescriptor {
    /// Element type.
    pub element_type: Arc<TypeDescriptor>,
    /// Maximum length (None = unbounded).
    pub max_length: Option<usize>,
}

impl SequenceDescriptor {
    /// Create unbounded sequence.
    pub fn unbounded(element_type: Arc<TypeDescriptor>) -> Self {
        Self {
            element_type,
            max_length: None,
        }
    }

    /// Create bounded sequence.
    pub fn bounded(element_type: Arc<TypeDescriptor>, max_length: usize) -> Self {
        Self {
            element_type,
            max_length: Some(max_length),
        }
    }
}

/// Array type descriptor.
#[derive(Debug, Clone, PartialEq)]
pub struct ArrayDescriptor {
    /// Element type.
    pub element_type: Arc<TypeDescriptor>,
    /// Fixed length.
    pub length: usize,
}

impl ArrayDescriptor {
    /// Create array descriptor.
    pub fn new(element_type: Arc<TypeDescriptor>, length: usize) -> Self {
        Self {
            element_type,
            length,
        }
    }
}

/// Enumeration type descriptor.
#[derive(Debug, Clone, PartialEq)]
pub struct EnumDescriptor {
    /// Enum variants.
    pub variants: Vec<EnumVariant>,
    /// Underlying type (default u32).
    pub underlying: PrimitiveKind,
}

impl EnumDescriptor {
    /// Create enum descriptor.
    pub fn new(variants: Vec<EnumVariant>) -> Self {
        Self {
            variants,
            underlying: PrimitiveKind::U32,
        }
    }

    /// Create with specific underlying type.
    pub fn with_underlying(mut self, underlying: PrimitiveKind) -> Self {
        self.underlying = underlying;
        self
    }

    /// Get variant by name.
    pub fn variant(&self, name: &str) -> Option<&EnumVariant> {
        self.variants.iter().find(|v| v.name == name)
    }

    /// Get variant by value.
    pub fn variant_by_value(&self, value: i64) -> Option<&EnumVariant> {
        self.variants.iter().find(|v| v.value == value)
    }
}

/// Enum variant.
#[derive(Debug, Clone, PartialEq)]
pub struct EnumVariant {
    /// Variant name.
    pub name: String,
    /// Variant value.
    pub value: i64,
}

impl EnumVariant {
    /// Create enum variant.
    pub fn new(name: impl Into<String>, value: i64) -> Self {
        Self {
            name: name.into(),
            value,
        }
    }
}

/// Union type descriptor.
#[derive(Debug, Clone, PartialEq)]
pub struct UnionDescriptor {
    /// Discriminator type.
    pub discriminator: Arc<TypeDescriptor>,
    /// Union cases.
    pub cases: Vec<UnionCase>,
    /// Default case (if any).
    pub default_case: Option<Box<UnionCase>>,
}

impl UnionDescriptor {
    /// Create union descriptor.
    pub fn new(discriminator: Arc<TypeDescriptor>, cases: Vec<UnionCase>) -> Self {
        Self {
            discriminator,
            cases,
            default_case: None,
        }
    }

    /// Set default case.
    pub fn with_default(mut self, case: UnionCase) -> Self {
        self.default_case = Some(Box::new(case));
        self
    }

    /// Get case by discriminator value.
    pub fn case_by_discriminator(&self, value: i64) -> Option<&UnionCase> {
        self.cases
            .iter()
            .find(|c| c.labels.contains(&value))
            .or(self.default_case.as_deref())
    }
}

/// Union case.
#[derive(Debug, Clone, PartialEq)]
pub struct UnionCase {
    /// Case name.
    pub name: String,
    /// Discriminator labels for this case.
    pub labels: Vec<i64>,
    /// Case type.
    pub type_desc: Arc<TypeDescriptor>,
}

impl UnionCase {
    /// Create union case.
    pub fn new(name: impl Into<String>, labels: Vec<i64>, type_desc: Arc<TypeDescriptor>) -> Self {
        Self {
            name: name.into(),
            labels,
            type_desc,
        }
    }

    /// Create single-label case.
    pub fn single(name: impl Into<String>, label: i64, type_desc: Arc<TypeDescriptor>) -> Self {
        Self::new(name, vec![label], type_desc)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_primitive_size() {
        assert_eq!(PrimitiveKind::Bool.size(), Some(1));
        assert_eq!(PrimitiveKind::U32.size(), Some(4));
        assert_eq!(PrimitiveKind::F64.size(), Some(8));
        assert_eq!(PrimitiveKind::String { max_length: None }.size(), None);
    }

    #[test]
    fn test_primitive_alignment() {
        assert_eq!(PrimitiveKind::U8.alignment(), 1);
        assert_eq!(PrimitiveKind::U16.alignment(), 2);
        assert_eq!(PrimitiveKind::U32.alignment(), 4);
        assert_eq!(PrimitiveKind::F64.alignment(), 8);
    }

    #[test]
    fn test_type_descriptor_struct() {
        let u32_type = Arc::new(TypeDescriptor::primitive("uint32", PrimitiveKind::U32));
        let f64_type = Arc::new(TypeDescriptor::primitive("float64", PrimitiveKind::F64));

        let fields = vec![
            FieldDescriptor::new("x", u32_type.clone()),
            FieldDescriptor::new("y", f64_type.clone()),
        ];

        let desc = TypeDescriptor::struct_type("Point", fields);
        assert!(desc.is_struct());
        assert_eq!(desc.fields().map(|f| f.len()), Some(2));
        assert!(desc.field("x").is_some());
        assert!(desc.field("z").is_none());
    }

    #[test]
    fn test_enum_descriptor() {
        let variants = vec![
            EnumVariant::new("RED", 0),
            EnumVariant::new("GREEN", 1),
            EnumVariant::new("BLUE", 2),
        ];
        let enum_desc = EnumDescriptor::new(variants);

        assert_eq!(enum_desc.variant("GREEN").map(|v| v.value), Some(1));
        assert_eq!(
            enum_desc.variant_by_value(2).map(|v| &v.name as &str),
            Some("BLUE")
        );
    }

    #[test]
    fn test_sequence_descriptor() {
        let u8_type = Arc::new(TypeDescriptor::primitive("uint8", PrimitiveKind::U8));

        let unbounded = SequenceDescriptor::unbounded(u8_type.clone());
        assert!(unbounded.max_length.is_none());

        let bounded = SequenceDescriptor::bounded(u8_type, 100);
        assert_eq!(bounded.max_length, Some(100));
    }
}
