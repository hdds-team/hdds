// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Fuzz target for hdds-gen codegen pipeline
//!
//! Since hdds-gen does not yet have an IDL parser, this fuzzer exercises the
//! code generation entry points with arbitrary inputs:
//! - `compute_type_id`: FNV-1a hash on arbitrary strings (must not panic)
//! - `emit_type_descriptor`: Rust code emission from arbitrary StructSpec (must not panic)

#![no_main]

use libfuzzer_sys::fuzz_target;
use hdds_gen::codegen::{
    compute_type_id, emit_type_descriptor, FieldKind, FieldSpec, PrimitiveType, StructSpec,
};

/// Map a byte to one of the primitive types
// @audit-ok: Simple pattern matching (cyclo 12, cogni 1) - fuzzing byte to type dispatch table
fn byte_to_primitive(b: u8) -> PrimitiveType {
    match b % 11 {
        0 => PrimitiveType::U8,
        1 => PrimitiveType::U16,
        2 => PrimitiveType::U32,
        3 => PrimitiveType::U64,
        4 => PrimitiveType::I8,
        5 => PrimitiveType::I16,
        6 => PrimitiveType::I32,
        7 => PrimitiveType::I64,
        8 => PrimitiveType::F32,
        9 => PrimitiveType::F64,
        _ => PrimitiveType::Bool,
    }
}

/// Map a byte to a field kind
fn byte_to_field_kind(b: u8) -> FieldKind {
    match b % 5 {
        0 => FieldKind::Primitive(byte_to_primitive(b.wrapping_add(1))),
        1 => FieldKind::Sequence,
        2 => FieldKind::Array,
        3 => FieldKind::Struct { type_path: "Nested".to_string() },
        _ => FieldKind::String,
    }
}

fuzz_target!(|data: &[u8]| {
    // Phase 1: Fuzz compute_type_id with arbitrary bytes as UTF-8 string
    if let Ok(input) = std::str::from_utf8(data) {
        let _ = compute_type_id(input);
    }

    // Phase 2: Fuzz emit_type_descriptor with struct specs derived from fuzz input
    // Need at least 4 bytes: 1 for name_len, 1 for num_fields, 1 for size, 1 for alignment
    if data.len() >= 4 {
        let name_len = (data[0] as usize % 32).max(1);
        let num_fields = data[1] as usize % 8;
        let size = u32::from(data[2]);
        let alignment = (data[3] % 8).max(1);

        // Build a type name from available bytes
        let name: String = data.iter()
            .skip(4)
            .take(name_len)
            .map(|b| char::from(b'A' + (b % 26)))
            .collect();

        let name = if name.is_empty() { "T".to_string() } else { name };

        // Build namespace
        let namespace = if data.len() > 4 + name_len && data[4 + name_len.min(data.len() - 5)] % 2 == 0 {
            vec!["ns".to_string()]
        } else {
            vec![]
        };

        // Build fields from remaining bytes
        let fields_data = &data[4..];
        let mut fields = Vec::new();
        for i in 0..num_fields {
            if i * 3 + 2 < fields_data.len() {
                let field_name = format!("f{}", i);
                let offset = u32::from(fields_data[i * 3]);
                let kind = byte_to_field_kind(fields_data[i * 3 + 1]);
                let field_alignment = (fields_data[i * 3 + 2] % 8).max(1);
                let field_size = match &kind {
                    FieldKind::Primitive(PrimitiveType::U8) | FieldKind::Primitive(PrimitiveType::I8) | FieldKind::Primitive(PrimitiveType::Bool) => 1,
                    FieldKind::Primitive(PrimitiveType::U16) | FieldKind::Primitive(PrimitiveType::I16) => 2,
                    FieldKind::Primitive(PrimitiveType::U32) | FieldKind::Primitive(PrimitiveType::I32) | FieldKind::Primitive(PrimitiveType::F32) => 4,
                    FieldKind::Primitive(PrimitiveType::U64) | FieldKind::Primitive(PrimitiveType::I64) | FieldKind::Primitive(PrimitiveType::F64) => 8,
                    _ => 0,
                };
                fields.push(FieldSpec::new(field_name, offset, field_size, field_alignment, kind));
            }
        }

        let spec = StructSpec::new(namespace, name)
            .with_layout(size, alignment)
            .with_fields(fields);

        // Must not panic
        let _code = emit_type_descriptor(&spec);
    }
});
