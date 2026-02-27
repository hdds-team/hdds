// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Fluent builder API for TypeDescriptor.

use crate::dynamic::{
    ArrayDescriptor, FieldDescriptor, PrimitiveKind, SequenceDescriptor, TypeDescriptor, TypeKind,
};
#[cfg(feature = "dynamic-types")]
use crate::dynamic::{EnumDescriptor, EnumVariant, UnionCase, UnionDescriptor};
use std::sync::Arc;

/// Builder for creating TypeDescriptor instances.
#[derive(Debug)]
pub struct TypeDescriptorBuilder {
    name: String,
    fields: Vec<FieldDescriptor>,
}

impl TypeDescriptorBuilder {
    /// Create a new builder for a struct type.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            fields: Vec::new(),
        }
    }

    /// Add a primitive field.
    pub fn field(mut self, name: impl Into<String>, kind: PrimitiveKind) -> Self {
        let type_desc = Arc::new(TypeDescriptor::primitive("", kind));
        self.fields.push(FieldDescriptor::new(name, type_desc));
        self
    }

    /// Add a field with a type descriptor.
    pub fn field_with_type(
        mut self,
        name: impl Into<String>,
        type_desc: Arc<TypeDescriptor>,
    ) -> Self {
        self.fields.push(FieldDescriptor::new(name, type_desc));
        self
    }

    /// Add an optional field.
    pub fn optional_field(mut self, name: impl Into<String>, kind: PrimitiveKind) -> Self {
        let type_desc = Arc::new(TypeDescriptor::primitive("", kind));
        self.fields
            .push(FieldDescriptor::new(name, type_desc).optional());
        self
    }

    /// Add a field with ID (for extensible types).
    pub fn field_with_id(mut self, name: impl Into<String>, kind: PrimitiveKind, id: u32) -> Self {
        let type_desc = Arc::new(TypeDescriptor::primitive("", kind));
        self.fields
            .push(FieldDescriptor::new(name, type_desc).with_id(id));
        self
    }

    /// Add a string field.
    pub fn string_field(self, name: impl Into<String>) -> Self {
        self.field(name, PrimitiveKind::String { max_length: None })
    }

    pub fn bounded_string_field(self, name: impl Into<String>, max_length: usize) -> Self {
        self.field(
            name,
            PrimitiveKind::String {
                max_length: Some(max_length),
            },
        )
    }

    /// Add a sequence field.
    pub fn sequence_field(mut self, name: impl Into<String>, element_kind: PrimitiveKind) -> Self {
        let element_type = Arc::new(TypeDescriptor::primitive("", element_kind));
        let seq_desc = SequenceDescriptor::unbounded(element_type);
        let type_desc = Arc::new(TypeDescriptor::new("", TypeKind::Sequence(seq_desc)));
        self.fields.push(FieldDescriptor::new(name, type_desc));
        self
    }

    /// Add a bounded sequence field.
    pub fn bounded_sequence_field(
        mut self,
        name: impl Into<String>,
        element_kind: PrimitiveKind,
        max_length: usize,
    ) -> Self {
        let element_type = Arc::new(TypeDescriptor::primitive("", element_kind));
        let seq_desc = SequenceDescriptor::bounded(element_type, max_length);
        let type_desc = Arc::new(TypeDescriptor::new("", TypeKind::Sequence(seq_desc)));
        self.fields.push(FieldDescriptor::new(name, type_desc));
        self
    }

    /// Add an array field.
    pub fn array_field(
        mut self,
        name: impl Into<String>,
        element_kind: PrimitiveKind,
        length: usize,
    ) -> Self {
        let element_type = Arc::new(TypeDescriptor::primitive("", element_kind));
        let arr_desc = ArrayDescriptor::new(element_type, length);
        let type_desc = Arc::new(TypeDescriptor::new("", TypeKind::Array(arr_desc)));
        self.fields.push(FieldDescriptor::new(name, type_desc));
        self
    }

    /// Add a nested struct field.
    pub fn nested_field(mut self, name: impl Into<String>, nested: Arc<TypeDescriptor>) -> Self {
        let type_desc = Arc::new(TypeDescriptor::new("", TypeKind::Nested(nested)));
        self.fields.push(FieldDescriptor::new(name, type_desc));
        self
    }

    /// Build the TypeDescriptor.
    pub fn build(self) -> TypeDescriptor {
        TypeDescriptor::struct_type(self.name, self.fields)
    }
}

/// Builder for enum types.
#[cfg(feature = "dynamic-types")]
#[derive(Debug)]
#[allow(dead_code)]
pub struct EnumBuilder {
    name: String,
    variants: Vec<EnumVariant>,
    next_value: i64,
    underlying: PrimitiveKind,
}

#[cfg(feature = "dynamic-types")]
#[allow(dead_code)]
impl EnumBuilder {
    /// Create a new enum builder.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            variants: Vec::new(),
            next_value: 0,
            underlying: PrimitiveKind::U32,
        }
    }

    /// Add a variant with auto-incrementing value.
    pub fn variant(mut self, name: impl Into<String>) -> Self {
        self.variants.push(EnumVariant::new(name, self.next_value));
        self.next_value += 1;
        self
    }

    /// Add a variant with explicit value.
    pub fn variant_value(mut self, name: impl Into<String>, value: i64) -> Self {
        self.variants.push(EnumVariant::new(name, value));
        self.next_value = value + 1;
        self
    }

    /// Set underlying type.
    pub fn underlying(mut self, kind: PrimitiveKind) -> Self {
        self.underlying = kind;
        self
    }

    /// Build the TypeDescriptor.
    pub fn build(self) -> TypeDescriptor {
        let enum_desc = EnumDescriptor::new(self.variants).with_underlying(self.underlying);
        TypeDescriptor::new(self.name, TypeKind::Enum(enum_desc))
    }
}

/// Builder for union types.
#[cfg(feature = "dynamic-types")]
#[derive(Debug)]
#[allow(dead_code)]
pub struct UnionBuilder {
    name: String,
    discriminator: Arc<TypeDescriptor>,
    cases: Vec<UnionCase>,
    default_case: Option<UnionCase>,
}

#[cfg(feature = "dynamic-types")]
#[allow(dead_code)]
impl UnionBuilder {
    /// Create a new union builder with discriminator type.
    pub fn new(name: impl Into<String>, discriminator: Arc<TypeDescriptor>) -> Self {
        Self {
            name: name.into(),
            discriminator,
            cases: Vec::new(),
            default_case: None,
        }
    }

    /// Create with u32 discriminator.
    pub fn with_u32_discriminator(name: impl Into<String>) -> Self {
        let disc = Arc::new(TypeDescriptor::primitive("", PrimitiveKind::U32));
        Self::new(name, disc)
    }

    /// Add a case with single label.
    pub fn case(
        mut self,
        name: impl Into<String>,
        label: i64,
        type_desc: Arc<TypeDescriptor>,
    ) -> Self {
        self.cases.push(UnionCase::single(name, label, type_desc));
        self
    }

    /// Add a case with multiple labels.
    pub fn case_labels(
        mut self,
        name: impl Into<String>,
        labels: Vec<i64>,
        type_desc: Arc<TypeDescriptor>,
    ) -> Self {
        self.cases.push(UnionCase::new(name, labels, type_desc));
        self
    }

    /// Add a primitive case.
    pub fn primitive_case(self, name: impl Into<String>, label: i64, kind: PrimitiveKind) -> Self {
        let type_desc = Arc::new(TypeDescriptor::primitive("", kind));
        self.case(name, label, type_desc)
    }

    /// Set default case.
    pub fn default_case(mut self, name: impl Into<String>, type_desc: Arc<TypeDescriptor>) -> Self {
        self.default_case = Some(UnionCase::new(name, vec![], type_desc));
        self
    }

    /// Build the TypeDescriptor.
    pub fn build(self) -> TypeDescriptor {
        let mut union_desc = UnionDescriptor::new(self.discriminator, self.cases);
        if let Some(default) = self.default_case {
            union_desc = union_desc.with_default(default);
        }
        TypeDescriptor::new(self.name, TypeKind::Union(union_desc))
    }
}

/// Builder for sequence types.
#[cfg(feature = "dynamic-types")]
#[allow(dead_code)]
pub struct SequenceBuilder {
    name: String,
    element_type: Arc<TypeDescriptor>,
    max_length: Option<usize>,
}

#[cfg(feature = "dynamic-types")]
#[allow(dead_code)]
impl SequenceBuilder {
    /// Create unbounded sequence of primitives.
    pub fn of_primitive(name: impl Into<String>, kind: PrimitiveKind) -> Self {
        Self {
            name: name.into(),
            element_type: Arc::new(TypeDescriptor::primitive("", kind)),
            max_length: None,
        }
    }

    /// Create sequence of custom type.
    pub fn of_type(name: impl Into<String>, element_type: Arc<TypeDescriptor>) -> Self {
        Self {
            name: name.into(),
            element_type,
            max_length: None,
        }
    }

    /// Set maximum length.
    pub fn max_length(mut self, max: usize) -> Self {
        self.max_length = Some(max);
        self
    }

    /// Build the TypeDescriptor.
    pub fn build(self) -> TypeDescriptor {
        let seq_desc = match self.max_length {
            Some(max) => SequenceDescriptor::bounded(self.element_type, max),
            None => SequenceDescriptor::unbounded(self.element_type),
        };
        TypeDescriptor::new(self.name, TypeKind::Sequence(seq_desc))
    }
}

/// Builder for array types.
#[cfg(feature = "dynamic-types")]
#[allow(dead_code)]
pub struct ArrayBuilder {
    name: String,
    element_type: Arc<TypeDescriptor>,
    length: usize,
}

#[cfg(feature = "dynamic-types")]
#[allow(dead_code)]
impl ArrayBuilder {
    /// Create array of primitives.
    pub fn of_primitive(name: impl Into<String>, kind: PrimitiveKind, length: usize) -> Self {
        Self {
            name: name.into(),
            element_type: Arc::new(TypeDescriptor::primitive("", kind)),
            length,
        }
    }

    /// Create array of custom type.
    pub fn of_type(
        name: impl Into<String>,
        element_type: Arc<TypeDescriptor>,
        length: usize,
    ) -> Self {
        Self {
            name: name.into(),
            element_type,
            length,
        }
    }

    /// Build the TypeDescriptor.
    pub fn build(self) -> TypeDescriptor {
        let arr_desc = ArrayDescriptor::new(self.element_type, self.length);
        TypeDescriptor::new(self.name, TypeKind::Array(arr_desc))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_struct_builder() {
        let desc = TypeDescriptorBuilder::new("Point3D")
            .field("x", PrimitiveKind::F64)
            .field("y", PrimitiveKind::F64)
            .field("z", PrimitiveKind::F64)
            .build();

        assert_eq!(desc.name, "Point3D");
        assert!(desc.is_struct());
        assert_eq!(desc.fields().map(|f| f.len()), Some(3));
    }

    #[test]
    fn test_struct_with_sequences() {
        let desc = TypeDescriptorBuilder::new("DataPacket")
            .field("id", PrimitiveKind::U32)
            .sequence_field("data", PrimitiveKind::U8)
            .string_field("label")
            .build();

        assert_eq!(desc.fields().map(|f| f.len()), Some(3));
    }

    #[test]
    fn test_struct_with_arrays() {
        let desc = TypeDescriptorBuilder::new("Matrix3x3")
            .array_field("values", PrimitiveKind::F64, 9)
            .build();

        let field = desc.field("values").expect("field");
        match &field.type_desc.kind {
            TypeKind::Array(arr) => assert_eq!(arr.length, 9),
            _ => panic!("Expected array"),
        }
    }

    #[test]
    #[cfg(feature = "dynamic-types")]
    fn test_enum_builder() {
        let desc = EnumBuilder::new("Color")
            .variant("RED")
            .variant("GREEN")
            .variant("BLUE")
            .build();

        match &desc.kind {
            TypeKind::Enum(e) => {
                assert_eq!(e.variants.len(), 3);
                assert_eq!(e.variant("GREEN").map(|v| v.value), Some(1));
            }
            _ => panic!("Expected enum"),
        }
    }

    #[test]
    #[cfg(feature = "dynamic-types")]
    fn test_enum_explicit_values() {
        let desc = EnumBuilder::new("HttpStatus")
            .variant_value("OK", 200)
            .variant_value("NOT_FOUND", 404)
            .variant_value("SERVER_ERROR", 500)
            .build();

        match &desc.kind {
            TypeKind::Enum(e) => {
                assert_eq!(e.variant("NOT_FOUND").map(|v| v.value), Some(404));
            }
            _ => panic!("Expected enum"),
        }
    }

    #[test]
    #[cfg(feature = "dynamic-types")]
    fn test_union_builder() {
        let desc = UnionBuilder::with_u32_discriminator("Value")
            .primitive_case("int_val", 0, PrimitiveKind::I32)
            .primitive_case("float_val", 1, PrimitiveKind::F64)
            .primitive_case("str_val", 2, PrimitiveKind::String { max_length: None })
            .build();

        match &desc.kind {
            TypeKind::Union(u) => {
                assert_eq!(u.cases.len(), 3);
                assert!(u.case_by_discriminator(1).is_some());
            }
            _ => panic!("Expected union"),
        }
    }

    #[test]
    fn test_nested_struct() {
        let point = Arc::new(
            TypeDescriptorBuilder::new("Point")
                .field("x", PrimitiveKind::F64)
                .field("y", PrimitiveKind::F64)
                .build(),
        );

        let rect = TypeDescriptorBuilder::new("Rectangle")
            .nested_field("top_left", point.clone())
            .nested_field("bottom_right", point)
            .build();

        assert_eq!(rect.fields().map(|f| f.len()), Some(2));
    }

    #[test]
    #[cfg(feature = "dynamic-types")]
    fn test_sequence_builder() {
        let desc = SequenceBuilder::of_primitive("ByteArray", PrimitiveKind::U8)
            .max_length(1024)
            .build();

        match &desc.kind {
            TypeKind::Sequence(s) => {
                assert_eq!(s.max_length, Some(1024));
            }
            _ => panic!("Expected sequence"),
        }
    }

    #[test]
    #[cfg(feature = "dynamic-types")]
    fn test_array_builder() {
        let desc = ArrayBuilder::of_primitive("Vector3", PrimitiveKind::F32, 3).build();

        match &desc.kind {
            TypeKind::Array(a) => {
                assert_eq!(a.length, 3);
            }
            _ => panic!("Expected array"),
        }
    }
}
