// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use hdds_gen::codegen::{
    compute_type_id, emit_type_descriptor, FieldKind, FieldSpec, PrimitiveType, StructSpec,
};

#[test]
fn test_type_id_deterministic() {
    let a = compute_type_id("geometry::Point");
    let b = compute_type_id("geometry::Point");
    assert_eq!(a, b);
}

#[test]
fn test_type_descriptor_primitive_struct() {
    let spec = StructSpec::new(vec!["geometry".to_string()], "Point")
        .with_layout(8, 4)
        .with_fields(vec![
            FieldSpec::new("x", 0, 4, 4, FieldKind::Primitive(PrimitiveType::F32)),
            FieldSpec::new("y", 4, 4, 4, FieldKind::Primitive(PrimitiveType::F32)),
        ]);

    let code = emit_type_descriptor(&spec);
    assert!(code.contains("type_name: \"geometry::Point\""));
    assert!(code.contains("PrimitiveKind::F32"));
    assert!(code.contains("size_bytes: 8"));
    assert!(code.contains("is_variable_size: false"));
}

#[test]
fn test_type_descriptor_with_string_field() {
    let spec = StructSpec::new(vec!["sensor".to_string()], "LabelledValue")
        .with_layout(24, 8)
        .with_fields(vec![
            FieldSpec::new("value", 0, 8, 8, FieldKind::Primitive(PrimitiveType::F64)),
            FieldSpec::new("label", 8, 0, 1, FieldKind::String),
        ]);

    let code = emit_type_descriptor(&spec);
    assert!(code.contains("is_variable_size: true"));
    assert!(code.contains("FieldType::String"));
    assert!(code.contains("size_bytes: 0xFFFF_FFFF"));
}
