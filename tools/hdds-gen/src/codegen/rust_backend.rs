// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use crate::codegen::type_hash::compute_type_id;

#[derive(Debug, Clone)]
pub struct StructSpec {
    pub namespace: Vec<String>,
    pub name: String,
    pub size: u32,
    pub alignment: u8,
    pub fields: Vec<FieldSpec>,
}

impl StructSpec {
    pub fn new(namespace: Vec<String>, name: impl Into<String>) -> Self {
        Self {
            namespace,
            name: name.into(),
            size: 0,
            alignment: 1,
            fields: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_layout(mut self, size: u32, alignment: u8) -> Self {
        self.size = size;
        self.alignment = alignment;
        self
    }

    #[must_use]
    pub fn with_fields(mut self, fields: Vec<FieldSpec>) -> Self {
        self.fields = fields;
        self
    }

    fn fully_qualified_name(&self) -> String {
        if self.namespace.is_empty() {
            self.name.clone()
        } else {
            format!("{}::{}", self.namespace.join("::"), self.name)
        }
    }

    fn type_path(&self) -> String {
        self.fully_qualified_name()
    }

    fn is_variable(&self) -> bool {
        self.fields.iter().any(|f| f.kind.is_dynamic())
    }
}

#[derive(Debug, Clone)]
pub struct FieldSpec {
    pub name: String,
    pub offset: u32,
    pub size: u32,
    pub alignment: u8,
    pub kind: FieldKind,
    pub element_type: Option<String>,
}

impl FieldSpec {
    pub fn new(
        name: impl Into<String>,
        offset: u32,
        size: u32,
        alignment: u8,
        kind: FieldKind,
    ) -> Self {
        Self {
            name: name.into(),
            offset,
            size,
            alignment,
            kind,
            element_type: None,
        }
    }

    #[must_use]
    pub fn with_element_type(mut self, path: impl Into<String>) -> Self {
        self.element_type = Some(path.into());
        self
    }

    fn size_literal(&self) -> String {
        if self.kind.is_dynamic() {
            "0xFFFF_FFFF".to_string()
        } else {
            self.size.to_string()
        }
    }

    fn element_expr(&self) -> String {
        match (&self.element_type, &self.kind) {
            (Some(path), _) => format!("Some({path}::type_descriptor())"),
            (None, FieldKind::Struct { type_path }) => {
                format!("Some({type_path}::type_descriptor())")
            }
            _ => "None".to_string(),
        }
    }

    fn render(&self) -> String {
        format!(
            "::hdds::core::types::FieldLayout {{\n                    name: \"{}\",\n                    offset_bytes: {},\n                    field_type: {},\n                    alignment: {},\n                    size_bytes: {},\n                    element_type: {},\n                }}",
            self.name,
            self.offset,
            self.kind.field_type_expr(),
            self.alignment,
            self.size_literal(),
            self.element_expr()
        )
    }
}

#[derive(Debug, Clone)]
pub enum FieldKind {
    Primitive(PrimitiveType),
    Sequence,
    Array,
    Struct { type_path: String },
    String,
}

impl FieldKind {
    fn field_type_expr(&self) -> String {
        match self {
            FieldKind::Primitive(p) => format!(
                "::hdds::core::types::FieldType::Primitive({})",
                p.primitive_expr()
            ),
            FieldKind::Sequence => "::hdds::core::types::FieldType::Sequence".to_string(),
            FieldKind::Array => "::hdds::core::types::FieldType::Array".to_string(),
            FieldKind::Struct { .. } => "::hdds::core::types::FieldType::Struct".to_string(),
            FieldKind::String => "::hdds::core::types::FieldType::String".to_string(),
        }
    }

    fn is_dynamic(&self) -> bool {
        matches!(self, FieldKind::Sequence | FieldKind::String)
    }
}

#[derive(Debug, Clone)]
pub enum PrimitiveType {
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
    Bool,
}

impl PrimitiveType {
    // @audit-ok: Simple pattern matching (cyclo 12, cogni 1) - type to string literal mapping
    fn primitive_expr(&self) -> &'static str {
        match self {
            PrimitiveType::U8 => "::hdds::core::types::PrimitiveKind::U8",
            PrimitiveType::U16 => "::hdds::core::types::PrimitiveKind::U16",
            PrimitiveType::U32 => "::hdds::core::types::PrimitiveKind::U32",
            PrimitiveType::U64 => "::hdds::core::types::PrimitiveKind::U64",
            PrimitiveType::I8 => "::hdds::core::types::PrimitiveKind::I8",
            PrimitiveType::I16 => "::hdds::core::types::PrimitiveKind::I16",
            PrimitiveType::I32 => "::hdds::core::types::PrimitiveKind::I32",
            PrimitiveType::I64 => "::hdds::core::types::PrimitiveKind::I64",
            PrimitiveType::F32 => "::hdds::core::types::PrimitiveKind::F32",
            PrimitiveType::F64 => "::hdds::core::types::PrimitiveKind::F64",
            PrimitiveType::Bool => "::hdds::core::types::PrimitiveKind::Bool",
        }
    }
}

/// Emit Rust code that registers a `TypeDescriptor` for the provided structure.
pub fn emit_type_descriptor(spec: &StructSpec) -> String {
    let fq_name = spec.fully_qualified_name();
    let type_path = spec.type_path();
    let type_id = compute_type_id(&fq_name);
    let type_id_literal = format!("0x{type_id:08X}");
    let is_variable = spec.is_variable();
    let size_literal = if is_variable {
        "0xFFFF_FFFF".to_string()
    } else {
        spec.size.to_string()
    };

    let fields: Vec<String> = spec.fields.iter().map(FieldSpec::render).collect();
    let fields_block = if fields.is_empty() {
        "                ".to_string()
    } else {
        fields
            .into_iter()
            .map(|f| format!("                {f},"))
            .collect::<Vec<_>>()
            .join("\n")
    };

    format!(
        "impl ::hdds::api::DDS for {type_path} {{\n    fn type_descriptor() -> &'static ::hdds::core::types::TypeDescriptor {{\n        static DESC: ::hdds::core::types::TypeDescriptor = ::hdds::core::types::TypeDescriptor {{\n            type_id: {type_id_literal},\n            type_name: \"{fq_name}\",\n            size_bytes: {size_literal},\n            alignment: {alignment},\n            is_variable_size: {is_variable},\n            fields: &[\n{fields_block}\n            ],\n        }};\n        &DESC\n    }}\n}}",
        type_path = type_path,
        type_id_literal = type_id_literal,
        fq_name = fq_name,
        size_literal = size_literal,
        alignment = spec.alignment,
        is_variable = if is_variable { "true" } else { "false" },
        fields_block = fields_block,
    )
}
